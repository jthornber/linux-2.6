/*
 * Copyright (C) 2010 Red Hat GmbH. All rights reserved.
 *
 * This file is released under the GPL.
 *
 * Thin provisioning target.
 *
 * Features:
 * o manages a storage pool of free blocks to allocate to a device
 * o data block size selectable (2^^N)
 * o low water mark in thinp ctr line and status
 *   - status <low mark> <chunks free> <chunks used>
 *   - userland to kernel message just be a single resume (no prior suspend)
 *   - status provide meatdata stats, userland resizes via same
 *     mechanism as data extend
 *
 * FIXME:
 * o add policies for metadata device full:
 *   - error bio (imlemented)
 *   - postpone bio and wait on userspace to grow the data/metadata device
 * o support DISCARD requests to free unused blocks
 * o support relocation of blocks to allow for hot spot removal
 *   and shrinking of the data device.
 * o eventually drop metadata store creation once userspace does it
 *
 */

static const char version[] = "1.0";

#include "dm.h"
#include "multisnap-metadata.h"
#include "persistent-data/transaction-manager.h"

#include <linux/blkdev.h>
#include <linux/dm-io.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

/*----------------------------------------------------------------*/

#define	DM_MSG_PREFIX	"dm-thin-prov"
#define	DAEMON		DM_MSG_PREFIX	"d"

/*----------------------------------------------------------------*/

/* A little global cache of multisnap metadata devs */
struct multisnap_metadata;

/* FIXME: add a spin lock round the table */
#define MMD_TABLE_SIZE 1024
static struct hlist_head mmd_table_[MMD_TABLE_SIZE];

static void
mmd_table_init(void)
{
	unsigned i;
	for (i = 0; i < MMD_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(mmd_table_ + i);
}

static unsigned
hash_bdev(struct block_device *bdev)
{
	/* FIXME: finish */
	/* bdev -> dev_t -> unsigned */
	return 0;
}

static void
mmd_table_insert(struct multisnap_metadata *mmd)
{
	unsigned bucket = hash_bdev(mmd->bdev);
	hlist_add_head(&mmd->hash, mmd_table_ + bucket);
}

static void
mmd_table_remove(struct multisnap_metadata *mmd)
{
	hlist_del(&mmd->hash);
}

static struct multisnap_metadata *
mmd_table_lookup(struct block_device *bdev)
{
	unsigned bucket = hash_bdev(bdev);
	struct multisnap_metadata *mmd;
	struct hlist_node *n;

	hlist_for_each_entry (mmd, n, mmd_table_ + bucket, hash)
		if (mmd->bdev == bdev)
			return mmd;

	return NULL;
}

/*----------------------------------------------------------------*/

/* Minimum data device block size in sectors. */
#define	DATA_DEV_BLOCK_SIZE_MIN	8
#define	LLU	long long unsigned

/* Thin provisioning context. */
struct multisnap_c {
	struct dm_target *ti;
	struct dm_dev *pool_dev;
	struct ms_device *msd;

	sector_t block_size;
	sector_t offset_mask;	/* mask to give the offset of a sector within a block */
	unsigned int block_shift; /* Quick sector -> block mapping. */

	spinlock_t lock;	/* Protects central input list below. */
	struct bio_list in;	/* Bio input queue. */

	spinlock_t no_space_lock;
	struct bio_list no_space; /* Bios w/o data space. */

	struct work_struct ws;		/* IO work. */

	spinlock_t provisioned_lock; /* protects next 4 fields */
	block_t data_size;	/* Size of data device in blocks. */
	int inserts_since_last_commit; /* this is now a flag */
	int triggered;	/* 'Flag' for one shot table events. */

	int bounce_mode;
};

/* Return size of device in sectors. */
static sector_t get_dev_size(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

/* Return data device block size in sectors. */
static sector_t data_dev_block_size(struct multisnap_c *tc)
{
	sector_t size;
	return multisnap_metadata_get_data_block_size(tc->msd, &size) ? 0 : size;
}

/* Derive offset within block from b */
static sector_t _sector_to_block(struct multisnap_c *tc, sector_t sector)
{
	return sector >> tc->block_shift;
}

static void wake_worker(struct multisnap_c *tc)
{
	if (!work_pending(&tc->ws))
		queue_work(multisnap_metadata_get_workqueue(tc->msd), &tc->ws);
}

static struct block_device *_remap_dev(struct multisnap_c *tc)
{
       return tc->pool_dev->bdev;
}

static sector_t _remap_sector(struct multisnap_c *tc, sector_t sector, block_t block)
{
	return (block << tc->block_shift) + (sector & tc->offset_mask);
}

static void remap_bio(struct multisnap_c *tc, struct bio *bio, block_t block)
{
	bio->bi_sector = _remap_sector(tc, bio->bi_sector, block);
	bio->bi_bdev = _remap_dev(tc);
}

static void requeue_bios(struct multisnap_c *tc, struct bio_list *bl, spinlock_t *lock)
{
	struct bio *bio;
	struct bio_list bios;

	bio_list_init(&bios);
	spin_lock(lock);
	bio_list_merge(&bios, bl);
	bio_list_init(bl);
	spin_unlock(lock);

	while ((bio = bio_list_pop(&bios)))
		bio_endio(bio, DM_ENDIO_REQUEUE);
}

static void requeue_all_bios(struct multisnap_c *tc)
{
	requeue_bios(tc, &tc->in, &tc->lock);
	requeue_bios(tc, &tc->no_space, &tc->no_space_lock);
}

/* Thin provision congested function. */
static int tc_congested(void *congested_data, int bdi_bits)
{
	int r;
	struct multisnap_c *tc = congested_data;

	spin_lock(&tc->no_space_lock);
	r = !bio_list_empty(&tc->no_space);
	spin_unlock(&tc->no_space_lock);

	if (!r) {
		struct request_queue *q = bdev_get_queue(tc->pool_dev->bdev);
		r = bdi_congested(&q->backing_dev_info, bdi_bits);
	}

	return r;
}

/* Set congested function. */
static void tc_set_congested_fn(struct multisnap_c *tc)
{
	struct mapped_device *md = dm_table_get_md(tc->ti->table);
	struct backing_dev_info *bdi = &dm_disk(md)->queue->backing_dev_info;

	/* Set congested function and data. */
	bdi->congested_fn = tc_congested;
	bdi->congested_data = tc;
}

static void inc_inserts(struct multisnap_c *tc)
{
	spin_lock(&tc->provisioned_lock);
	tc->inserts_since_last_commit = 1; /* FIXME: make an atomic flag */
	spin_unlock(&tc->provisioned_lock);
}

static int commit(struct multisnap_c *tc)
{
	int r = 0;
	block_t inserts;

	spin_lock(&tc->provisioned_lock);
	inserts = tc->inserts_since_last_commit;
	spin_unlock(&tc->provisioned_lock);

	if (inserts) {
		r = multisnap_metadata_commit(tc->mmd);
		if (r == 0) {
			spin_lock(&tc->provisioned_lock);
			tc->inserts_since_last_commit = 0;
			spin_unlock(&tc->provisioned_lock);
		}
	}

	return r;
}

static void do_bios(struct multisnap_c *tc, struct bio_list *bios)
{
	int r;
	struct bio *bio;
	block_t thinp_block, pool_block;

	while ((bio = bio_list_pop(bios))) {
		thinp_block = _sector_to_block(tc, bio->bi_sector);
		r = multisnap_metadata_map(tc->msd, thinp_block,
					   bio->bi_rw | WRITE ? WRITE : READ,
					   1, &pool_block);
		if (r == -ENODATA) {
			/* don't create a new mapping for a read */
			if (bio_data_dir(bio) == READ) {
				zero_fill_bio(bio);
				bio_endio(bio, 0);
				continue;
			}

			/* new mapping */
			r = multisnap_metadata_insert(tc->mmd, tc->thinp_id, thinp_block, &pool_block);
			if (!r)
				inc_inserts(tc);

			else if (r == -ENOSPC) {
				/*
				 * No data space, so we postpone the bio
				 * until more space added by userland.
				 */
				spin_lock(&tc->no_space_lock);
				bio_list_add(&tc->no_space, bio);
				spin_unlock(&tc->no_space_lock);
				continue;
			}
		}

		if (r)
			bio_io_error(bio);
		else {
			/*
			 * REQ_FUA should only trigger a commit() if it's
			 * to a block that is pending.  I'm not sure
			 * whether the overhead of tracking pending blocks
			 * is worth it though.
			 */
			if ((bio->bi_rw & (REQ_FUA | REQ_FLUSH))) {
				r = commit(tc);
				if (r < 0) {
					bio_io_error(bio);
					continue;
				}
			}

			remap_bio(tc, bio, pool_block);
			generic_make_request(bio);
		}
	}
}

static void do_work(struct work_struct *ws)
{
	int bounce_mode;
	struct multisnap_c *tc = container_of(ws, struct multisnap_c, ws);
	struct bio_list bios;
	bio_list_init(&bios);

	spin_lock(&tc->lock);
	bio_list_merge(&bios, &tc->in);
	bio_list_init(&tc->in);
	bounce_mode = tc->bounce_mode;
	spin_unlock(&tc->lock);

	if (tc->bounce_mode) {
		struct bio *bio;
		while ((bio = bio_list_pop(&bios)))
			bio_endio(bio, DM_ENDIO_REQUEUE);
	} else
		do_bios(tc, &bios);
}

static void thin_flush(struct dm_target *ti)
{
	struct multisnap_c *tc = ti->private;

	/* Wait until all io has been processed. */

	/* FIXME: other thinp devs will still be working, so we can't
	 * flush, should instead keep a count of how many our jobs are
	 * pending. */
	flush_workqueue(multisnap_metadata_get_workqueue(tc->mmd));
	if (commit(tc) < 0) {
		printk(KERN_ALERT "thinp metadata write failed.");
		/* FIXME: invalidate device? error the next FUA or FLUSH bio ?*/
	}
}

/* Destroy a thinp device mapping. */
static void thin_dtr(struct dm_target *ti)
{
	struct multisnap_c *tc = ti->private;

	/* Close thinp metadata handler. */
	if (tc->mmd) {
		multisnap_metadata_unprepare_device(tc->mmd, tc->thinp_id);
		multisnap_metadata_close(tc->mmd);
	}

	/* Release reference on data device. */
	if (tc->data_dev)
		dm_put_device(ti, tc->data_dev);

	/* Release reference on metadata device. */
	if (tc->meta_dev)
		dm_put_device(ti, tc->meta_dev);

	kfree(tc);
}

/* Parse constructor arguments. */
static int _parse_args(struct dm_target *ti, unsigned argc, char **argv,
		       multisnap_dev_t *thinp_id,
		       sector_t *block_size,
		       block_t *low_water_mark)
{
	unsigned long long tmp;

	if (argc != 5) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	if (sscanf(argv[2], "%llu", &tmp) != 1) {
		ti->error = "Invalid thinp device identifier";
		return -EINVAL;
	}
	*thinp_id = tmp;

	if (sscanf(argv[3], "%llu", &tmp) != 1 ||
	    tmp < DATA_DEV_BLOCK_SIZE_MIN ||
	    !is_power_of_2(tmp)) {
		ti->error = "Invalid data block size argument";
		return -EINVAL;
	}
	*block_size = tmp;

	if (sscanf(argv[4], "%llu", &tmp) != 1) {
		ti->error = "Invalid low water mark argument";
		return -EINVAL;
	}

	*low_water_mark = tmp;
	return 0;
}

static int _get_devices(struct multisnap_c *tc, char **argv)
{
	int r = dm_get_device(tc->ti, argv[0], FMODE_READ | FMODE_WRITE, &tc->data_dev);
	if (r) {
		tc->ti->error = "Error opening data device";
		return r;
	}

	r = dm_get_device(tc->ti, argv[1], FMODE_READ | FMODE_WRITE, &tc->meta_dev);
	if (r) {
		dm_put_device(tc->ti, tc->data_dev);
		tc->ti->error = "Error opening metadata device";
		return r;
	}

	return 0;
}

static int create_mmd(struct multisnap_c *tc)
{
	int r;

	tc->mmd = multisnap_metadata_open(tc->meta_dev->bdev,
					  tc->block_size,
					  tc->data_size);
	if (!tc->mmd) {
		DMINFO("%s couldn't open thin-prov metadata object", __func__);
		return -ENOMEM;
	} else
		DMINFO("%s thin-prov metadata dev opened", __func__);

	r = multisnap_metadata_prepare_device(tc->mmd, tc->thinp_id);
	if (r) {
		DMERR("couldn't prepare thinp-metadata object");
		multisnap_metadata_close(tc->mmd);
		tc->mmd = NULL;
		return r;
	}

	return r;
}

/*
 * Construct a thin provisioned device mapping:
 *
 * <start> <length> thin-prov <data_dev> <meta_dev> <thinp_id> <data_block_size> <low_water_mark>
 *
 * dev_id: the thinp device identifier (just an opaque identifier, nothing to do with dev_t)
 * data_dev: device holding thin provisioned data blocks
 * meta_dev: device keeping track of provisioned blocks
 * data_block_size: provisioning unit size in sectors
 * low_water_mark: low water mark to throw a dm event for uspace to resize
 *
 */
static int
thin_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	sector_t block_size = 0, data_sectors;
	block_t low_water_mark = 0;
	multisnap_dev_t thinp_id;
	struct multisnap_c *tc;

	r = _parse_args(ti, argc, argv, &thinp_id, &block_size, &low_water_mark);
	if (r)
		return r;

	tc = ti->private = kzalloc(sizeof(*tc), GFP_KERNEL);
	if (!tc) {
		ti->error = "Error allocating thinp context";
		return -ENOMEM;
	}

	tc->ti = ti;
	tc->block_size = block_size;
	tc->block_shift = ffs(block_size) - 1;
	tc->low_water_mark = low_water_mark;
	tc_set_congested_fn(tc);

	spin_lock_init(&tc->lock);
	bio_list_init(&tc->in);
	spin_lock_init(&tc->no_space_lock);
	bio_list_init(&tc->no_space);

	tc->thinp_id = thinp_id;
	r = _get_devices(tc, argv);
	if (r)
		goto err;

	data_sectors = get_dev_size(tc->data_dev);
	tc->data_size = _sector_to_block(tc, data_sectors);
	INIT_WORK(&tc->ws, do_work);
	ti->split_io = tc->block_size;

	/* Set masks/shift for fast bio -> block mapping. */
	tc->offset_mask = ti->split_io - 1;

	spin_lock_init(&tc->provisioned_lock);
	tc->inserts_since_last_commit = 0;
	tc->triggered = 0;
	tc->bounce_mode = 0;

	smp_wmb();
	return 0;

err:
	multisnap_dtr(ti);
	return r;
}

/* Map a thin provisioned device  */
static int
thin_map(struct dm_target *ti, struct bio *bio,
	 union map_info *map_context)
{
	int r;
	struct multisnap_c *tc = ti->private;
	block_t thinp_block, pool_block;

	/* Remap sector to target begin. */
	bio->bi_sector -= ti->begin;

	if (!(bio->bi_rw & (REQ_FLUSH | REQ_FUA))) {
		thinp_block = _sector_to_block(tc, bio->bi_sector);
		r = multisnap_metadata_lookup(tc->mmd, tc->thinp_id, thinp_block, 0, &pool_block);
		if (r == 0) {
			remap_bio(tc, bio, pool_block);
			return DM_MAPIO_REMAPPED;
		}

		if (bio_data_dir(bio) == READ && r != -EWOULDBLOCK) {
			zero_fill_bio(bio);
			bio_endio(bio, 0);
			return DM_MAPIO_SUBMITTED;
		}
	}

	/* Don't bother the worker thread with read ahead io */
	if (bio_rw(bio) == READA)
		return -EIO;

	spin_lock(&tc->lock);
	bio_list_add(&tc->in, bio);
	spin_unlock(&tc->lock);

	wake_worker(tc);
	return DM_MAPIO_SUBMITTED;
}

static void
thin_presuspend(struct dm_target *ti)
{
	struct multisnap_c *tc = ti->private;

	spin_lock(&tc->lock);
	tc->bounce_mode = 1;
	spin_unlock(&tc->lock);

	multisnap_flush(ti);
	requeue_all_bios(tc);
}

static void
thin_postsuspend(struct dm_target *ti)
{
	struct multisnap_c *tc = ti->private;

	multisnap_metadata_close(tc->mmd);
	tc->mmd = NULL;
}

/*
 * Retrieves the number of blocks of the data device from
 * the superblock and compares it to the actual device size,
 * thus resizing the data device in case it has grown.
 *
 * This both copes with opening preallocated data devices in the ctr
 * being followed by a resume
 * -and-
 * calling the resume method individually after userpace has
 * grown the data device in reaction to a table event.
 */
static int
thin_preresume(struct dm_target *ti)
{
	int r;
	block_t data_size, sb_data_size;
	struct multisnap_c *tc = ti->private;

	spin_lock(&tc->lock);
	tc->bounce_mode = 0;
	spin_unlock(&tc->lock);

	if (!tc->mmd) {
		r = create_mmd(tc);
		if (r) {
			DMERR("couldn't create thinp-metadata object");
			return r;
		}
	}

	data_size = _sector_to_block(tc, get_dev_size(tc->data_dev));
	r = multisnap_metadata_get_data_dev_size(tc->mmd, tc->thinp_id, &sb_data_size);
	if (r) {
		DMERR("failed to retrieve data device size");
		return r;
	}

	/* Nothing to resize. */
	if (data_size == sb_data_size)
		return 0;

	if (data_size < sb_data_size) /* FIXME: weird */
		DMWARN("new data device size smaller than actual one");
	else {
		r = multisnap_metadata_resize_data_dev(tc->mmd, tc->thinp_id, data_size);
		if (r)
			DMERR("failed to resize data device");
		else {
			spin_lock(&tc->provisioned_lock);
			tc->data_size = data_size;
			tc->triggered = 0;
			spin_unlock(&tc->provisioned_lock);
			wake_worker(tc);
		}
	}

	return 0;
}

/* Thinp device status output method. */
static int
thin_status(struct dm_target *ti, status_type_t type,
	    char *result, unsigned maxlen)
{
	int r;
	ssize_t sz = 0;
	block_t provisioned, low_water_mark, data_size;
	char buf[BDEVNAME_SIZE], buf1[BDEVNAME_SIZE];
	struct multisnap_c *tc = ti->private;

#if 0
	r = multisnap_metadata_get_provisioned_blocks(tc->mmd, tc->thinp_id, &provisioned);
	if (r)
		return r;
#else
	provisioned = 0;
#endif

	spin_lock(&tc->provisioned_lock);
	low_water_mark = tc->low_water_mark;
	data_size = tc->data_size;
	spin_unlock(&tc->provisioned_lock);

	switch (type) {
	case STATUSTYPE_INFO:
		/*   <low mark> <chunks free> <chunks used> */
		DMEMIT("%llu %llu",
		       (LLU) data_size - provisioned, /* FIXME: wrong */
		       (LLU) provisioned);
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%s %s %llu %llu",
		       format_dev_t(buf1, tc->data_dev->bdev->bd_dev),
		       format_dev_t(buf, tc->meta_dev->bdev->bd_dev),
		       (LLU) tc->block_size,
		       (LLU) low_water_mark);
	}

	return 0;
}

/* bvec merge method. */
static int
thin_bvec_merge(struct dm_target *ti,
		struct bvec_merge_data *bvm,
		struct bio_vec *biovec, int max_size)
{
	struct multisnap_c *tc = ti->private;
	struct request_queue *q = bdev_get_queue(_remap_dev(tc));
	block_t thinp_block, pool_block;

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = _remap_dev(tc);
	bvm->bi_sector -= ti->begin;
	thinp_block = _sector_to_block(tc, bvm->bi_sector);
	if (multisnap_metadata_lookup(tc->mmd, tc->thinp_id, thinp_block, 0, &pool_block) < 0)
		return 0;

	bvm->bi_sector = _remap_sector(tc, bvm->bi_sector, pool_block);
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

/* Provide io hints. */
static void
thin_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct multisnap_c *tc = ti->private;

	blk_limits_io_min(limits, 0);
	blk_limits_io_opt(limits, data_dev_block_size(tc));
}

/* Thinp device target interface. */
static struct target_type thin_target = {
	.name =        "multisnap-thin",
	.version =     {1, 0, 0},
	.module =      THIS_MODULE,
	.ctr =	       thin_ctr,
	.dtr =	       thin_dtr,
	.flush =       thin_flush,
	.map =	       thin_map,
	.presuspend =  thin_presuspend,
	.postsuspend = thin_postsuspend,
	.preresume =   thin_preresume,
	.status =      thin_status,
	.merge =       thin_bvec_merge,
	.io_hints =    thin_io_hints,
};

/*----------------------------------------------------------------*/

struct pool_context {
	struct dm_dev *metadata_dev;
	struct dm_dev *data_dev;

	struct multisnap_metadata *mmd;
};

/*
 * multisnap-pool <metadata dev>
 *                <data dev>
 *                <data block size in sectors>
 *                <data dev size in blocks>
 */
static int pool_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	long long unsigned block_size;
	block_t data_size;
	struct pool_context *md;
	struct multisnap_metadata *mmd;
	struct dm_dev *metadata_dev, *data_dev;

	if (argc != 4) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	r = dm_get_device(ti, argv[0], FMODE_READ | FMODE_WRITE, &metadata_dev);
	if (r) {
		ti->error = "Error getting metadata device";
		return r;
	}

	r = dm_get_device(ti, argv[1], FMODE_READ | FMODE_WRITE, &data_dev);
	if (r) {
		ti->error = "Error getting data device";
		dm_put_device(ti, metadata_dev);
		return r;
	}

	if (sscanf(argv[2], "%llu", &block_size) != 1) {
		ti->error = "Invalid block size";
		dm_put_device(ti, metadata_dev);
		dm_put_device(ti, data_dev);
		return -EINVAL;
	}
	// FIXME: any extra validation here ? Check it's a power of 2

	if (sscanf(argv[3], "%llu", &data_size) != 1) {
		ti->error = "Invalid data size";
		dm_put_device(ti, metadata_dev);
		dm_put_device(ti, data_dev);
		return -EINVAL;
	}
	// FIXME: any extra validation here ?

	mmd = multisnap_metadata_open(metadata_dev->bdev, block_size, data_size);
	if (!mmd) {
		ti->error = "Error opening metadata device";
		dm_put_device(ti, metadata_dev);
		dm_put_device(ti, data_dev);
		return -ENOMEM;
	}

	md = kmalloc(sizeof(*md), GFP_KERNEL);
	if (!md) {
		ti->error = "Error allocating memory";
		multisnap_metadata_close(mmd);
		dm_put_device(ti, metadata_dev);
		dm_put_device(ti, data_dev);
		return -ENOMEM;
	}
	md->metadata_dev = metadata_dev;
	md->data_dev = data_dev;
	md->mmd = mmd;

	ti->private = md;
	return 0;
}

static void pool_dtr(struct dm_target *ti)
{
	struct pool_context *md = ti->private;

	multisnap_metadata_close(md->mmd);
	dm_put_device(ti, md->metadata_dev);
	dm_put_device(ti, md->data_dev);
	kfree(md);
}

static int pool_map(struct dm_target *ti, struct bio *bio,
		    union map_info *map_context)
{
	struct pool_context *md = ti->private;
	bio->bi_bdev = md->data_dev->bdev;
	return DM_MAPIO_REMAPPED;
}

/*
 * Messages supported:
 * new-thin <dev id> <dev size>
 * new-snap <dev id> <origin id>
 * del      <dev id>
 */
static int pool_message(struct dm_target *ti, unsigned argc, char **argv)
{
	/* ti->error doesn't have a const qualifier :( */
	char *invalid_args = "Incorrect number of arguments";

	int r;
	struct pool_context *md = ti->private;
	multisnap_dev_t dev_id;

	if (argc < 2) {
		ti->error = invalid_args;
		return -EINVAL;
	}

	if (sscanf(argv[1], "%llu", &dev_id) != 1) {
		ti->error = "Invalid dev id";
		return -EINVAL;
	}

	if (!strcmp(argv[0], "new-thin")) {
		block_t dev_size;

		if (argc != 3) {
			ti->error = invalid_args;
			return -EINVAL;
		}

		if (sscanf(argv[2], "%llu", &dev_size) != 1) {
			ti->error = "Invalid dev size";
			return -EINVAL;
		}

		r = multisnap_metadata_create_thin(md->mmd, dev_id, dev_size);
		if (r) {
			ti->error = "Creation of thin provisioned device failed";
			return r;
		}

	} else if (!strcmp(argv[0], "new-snap")) {
		multisnap_dev_t origin_id;

		if (argc != 3) {
			ti->error = invalid_args;
			return -EINVAL;
		}

		if (sscanf(argv[2], "%llu", &origin_id) != 1) {
			ti->error = "Invalid origin id";
			return -EINVAL;
		}

		r = multisnap_metadata_create_snap(md->mmd, dev_id, origin_id);
		if (r) {
			ti->error = "Creation of snapshot failed";
			return r;
		}

	} else if (!strcmp(argv[0], "del")) {
		if (argc != 2) {
			ti->error = invalid_args;
			return -EINVAL;
		}

		r = multisnap_metadata_delete(md->mmd, dev_id);

	} else
		return -EINVAL;

	return 0;
}

static struct target_type pool_target = {
	.name =    "multisnap-pool",
	.version = {1, 0, 0},
	.module =  THIS_MODULE,
	.ctr =	   pool_ctr,
	.dtr =	   pool_dtr,
	.map =	   pool_map,
	.message = pool_message,
};

/*----------------------------------------------------------------*/

static int __init dm_multisnap_init(void)
{
	int r = dm_register_target(&thin_target);
	if (r)
		return r;

	r = dm_register_target(&pool_target);
	if (r)
		dm_unregister_target(&thin_target);

	return r;
}

static void dm_multisnap_exit(void)
{
	dm_unregister_target(&thin_target);
	dm_unregister_target(&pool_target);
}

module_init(dm_multisnap_init);
module_exit(dm_multisnap_exit);

MODULE_DESCRIPTION(DM_NAME "device-mapper multisnap/thin provisioning target");
MODULE_AUTHOR("Joe Thornber <thornber@redhat.com>");
MODULE_LICENSE("GPL");

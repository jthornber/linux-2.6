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
#include "thinp-metadata.h"
#include "persistent-data/transaction-manager.h"

#include <linux/blkdev.h>
#include <linux/dm-io.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

/*----------------------------------------------------------------*/

#define	DM_MSG_PREFIX	"dm-thin-prov"
#define	DAEMON		DM_MSG_PREFIX	"d"

/* Minimum data device block size in sectors. */
#define	DATA_DEV_BLOCK_SIZE_MIN	8
#define	LLU	long long unsigned

/* Thin provisioning context. */
struct thinp_c {
	struct dm_target *ti;
	struct thinp_metadata *tpm;

	struct dm_dev *data_dev;
	struct dm_dev *meta_dev;

	sector_t block_size;
	sector_t offset_mask;	/* mask to give the offset of a sector within a block */
	unsigned int block_shift; /* Quick sector -> block mapping. */

	spinlock_t lock;	/* Protects central input list below. */
	struct bio_list in;	/* Bio input queue. */

	spinlock_t no_space_lock;
	struct bio_list no_space; /* Bios w/o data space. */

	struct workqueue_struct *wq;	/* Work queue. */
	struct work_struct ws;		/* IO work. */

	block_t low_water_mark;

	spinlock_t provisioned_lock; /* protects next 4 fields */
	block_t data_size;	/* Size of data device in blocks. */
	block_t provisioned_count;
	block_t inserts_since_last_commit;
	int triggered;	/* 'Flag' for one shot table events. */

	int bounce_mode;
};

/* Return size of device in sectors. */
static sector_t get_dev_size(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

/* Return data device block size in sectors. */
sector_t data_dev_block_size(struct thinp_c *tc)
{
	sector_t size;
	return thinp_metadata_get_data_block_size(tc->tpm, &size) ? 0 : size;
}

/* Derive offset within block from b */
static sector_t _sector_to_block(struct thinp_c *tc, sector_t sector)
{
	return sector >> tc->block_shift;
}

static void wake_do_thinp(struct thinp_c *tc)
{
	if (!work_pending(&tc->ws))
		queue_work(tc->wq, &tc->ws);
}

static struct block_device *_remap_dev(struct thinp_c *tc)
{
       return tc->data_dev->bdev;
}

static sector_t _remap_sector(struct thinp_c *tc, sector_t sector, block_t block)
{
	return (block << tc->block_shift) + (sector & tc->offset_mask);
}

static void remap_bio(struct thinp_c *tc, struct bio *bio, block_t block)
{
	bio->bi_sector = _remap_sector(tc, bio->bi_sector, block);
	bio->bi_bdev = _remap_dev(tc);
}

static void requeue_bios(struct thinp_c *tc, struct bio_list *bl, spinlock_t *lock)
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

static void requeue_all_bios(struct thinp_c *tc)
{
	requeue_bios(tc, &tc->in, &tc->lock);
	requeue_bios(tc, &tc->no_space, &tc->no_space_lock);
}

/* Return number of allocated blocks. */

static block_t allocated_count(struct thinp_c *tc)
{
	return tc->inserts_since_last_commit + tc->provisioned_count;
}

/* Thin provision congested function. */
static int tc_congested(void *congested_data, int bdi_bits)
{
	int r;
	struct thinp_c *tc = congested_data;

	spin_lock(&tc->no_space_lock);
	r = !bio_list_empty(&tc->no_space);
	spin_unlock(&tc->no_space_lock);

	if (!r) {
		struct request_queue *q = bdev_get_queue(tc->data_dev->bdev);

		r = bdi_congested(&q->backing_dev_info, bdi_bits);
		if (!r) {
			q = bdev_get_queue(tc->meta_dev->bdev);
			r = bdi_congested(&q->backing_dev_info, bdi_bits);
		}
	}

	return r;
}

/* Set congested function. */
static void tc_set_congested_fn(struct thinp_c *tc)
{
	struct mapped_device *md = dm_table_get_md(tc->ti->table);
	struct backing_dev_info *bdi = &dm_disk(md)->queue->backing_dev_info;

	/* Set congested function and data. */
	bdi->congested_fn = tc_congested;
	bdi->congested_data = tc;
}

static void inc_inserts(struct thinp_c *tc)
{
	int do_event = 0;

	spin_lock(&tc->provisioned_lock);
	tc->inserts_since_last_commit++;
	if (!tc->triggered) {
		if (tc->data_size - allocated_count(tc) <= tc->low_water_mark) {
			do_event = 1;
			tc->triggered = 1;
		}
	}
	spin_unlock(&tc->provisioned_lock);

	if (do_event)
		dm_table_event(tc->ti->table);
}

static int commit(struct thinp_c *tc)
{
	int r = 0;
	block_t inserts;

	spin_lock(&tc->provisioned_lock);
	inserts = tc->inserts_since_last_commit;
	spin_unlock(&tc->provisioned_lock);

	if (inserts) {
		r = thinp_metadata_commit(tc->tpm);
		if (r == 0) {
			spin_lock(&tc->provisioned_lock);
			tc->provisioned_count += inserts;
			tc->inserts_since_last_commit = 0;
			spin_unlock(&tc->provisioned_lock);
		}
	}

	return r;
}

static void do_bios(struct thinp_c *tc, struct bio_list *bios)
{
	int r;
	struct bio *bio;
	block_t thinp_block, pool_block;

	while ((bio = bio_list_pop(bios))) {
		thinp_block = _sector_to_block(tc, bio->bi_sector);
		r = thinp_metadata_lookup(tc->tpm, thinp_block, 1, &pool_block);
		if (r == -ENODATA) {
			/* new mapping */
			r = thinp_metadata_insert(tc->tpm, thinp_block, &pool_block);
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

static void do_thinp(struct work_struct *ws)
{
	int bounce_mode;
	struct thinp_c *tc = container_of(ws, struct thinp_c, ws);
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

static void thinp_flush(struct dm_target *ti)
{
	struct thinp_c *tc = ti->private;

	/* Wait until all io has been processed. */
	flush_workqueue(tc->wq);
	if (commit(tc) < 0) {
		printk(KERN_ALERT "thinp metadata write failed.");
		/* FIXME: invalidate device? error the next FUA or FLUSH bio ?*/
	}
}

/* Destroy a thinp device mapping. */
static void thinp_dtr(struct dm_target *ti)
{
	struct thinp_c *tc = ti->private;

	if (tc->wq)
		destroy_workqueue(tc->wq);

	/* Close thinp metadata handler. */
	if (tc->tpm)
		thinp_metadata_close(tc->tpm);

	/* Release reference on data device. */
	if (tc->data_dev)
		dm_put_device(ti, tc->data_dev);

	/* Release reference on metadata device. */
	if (tc->meta_dev)
		dm_put_device(ti, tc->meta_dev);

	kfree(tc);
}

/* Parse constructor arguments. */
static int _parse_args(struct dm_target *ti, unsigned argc, char **argv, sector_t *block_size, block_t *low_water_mark)
{
	unsigned long long tmp;

	if (argc != 4) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	if (sscanf(argv[2], "%llu", &tmp) != 1 ||
	    tmp < DATA_DEV_BLOCK_SIZE_MIN ||
	    !is_power_of_2(tmp)) {
		ti->error = "Invalid data block size argument";
		return -EINVAL;
	}

	*block_size = tmp;

	if (sscanf(argv[3], "%llu", &tmp) != 1) {
		ti->error = "Invalid low water mark argument";
		return -EINVAL;
	}

	*low_water_mark = tmp;
	return 0;
}

static int _get_devices(struct thinp_c *tc, char **argv)
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

static int create_tpm(struct thinp_c *tc)
{
	block_t meta_sectors = get_dev_size(tc->meta_dev);

	tc->tpm = thinp_metadata_open(tc->meta_dev->bdev, meta_sectors);
	if (!tc->tpm) {
		tc->tpm = thinp_metadata_create(tc->meta_dev->bdev,
						meta_sectors,
						tc->block_size, tc->data_size);
		if (!tc->tpm)
			return -ENOMEM;
	} else
		DMINFO("%s thin-prov metadata dev opened", __func__);

	/* Get already provisioned blocks. */
	return thinp_metadata_get_provisioned_blocks(tc->tpm,
						     &tc->provisioned_count);
}

/*
 * Construct a thin provisioned device mapping:
 *
 * <start> <length> thin-prov <data_dev> <meta_dev> <data_block_size> <low_water_mark>
 *
 * data_dev: device holding thin provisioned data blocks
 * meta_dev: device keeping track of provisioned blocks
 * data_block_size: provisioning unit size in sectors
 * low_water_mark: low water mark to throw a dm event for uspace to resize
 *
 */
static int thinp_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	sector_t block_size = 0, data_sectors;
	block_t low_water_mark = 0;
	struct thinp_c *tc;

	r = _parse_args(ti, argc, argv, &block_size, &low_water_mark);
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

	r = _get_devices(tc, argv);
	if (r)
		goto err;

	data_sectors = get_dev_size(tc->data_dev);

	/* FIXME: superfluous conditional once userspace creates the store. */
	tc->data_size = _sector_to_block(tc, data_sectors);

	/* Create singlethreaded workqueue for this thinp device. */
	INIT_WORK(&tc->ws, do_thinp);
	tc->wq = alloc_ordered_workqueue(DAEMON, WQ_MEM_RECLAIM);
	if (!tc->wq) {
		ti->error = "Failure creating thinp pool io work queue";
		r = -ENOMEM;
		goto err;
	}

	ti->split_io = tc->block_size;
	ti->num_flush_requests = 1;

	/* Set masks/shift for fast bio -> block mapping. */
	tc->offset_mask = ti->split_io - 1;

	spin_lock_init(&tc->provisioned_lock);
	tc->inserts_since_last_commit = 0;
	tc->triggered = 0;
	tc->bounce_mode = 0;
	smp_wmb();
	return 0;

err:
	thinp_dtr(ti);
	return r;
}

/* Map a thin provisioned device  */
static int thinp_map(struct dm_target *ti, struct bio *bio,
		     union map_info *map_context)
{
	int r;
	struct thinp_c *tc = ti->private;
	block_t thinp_block, pool_block;

	/* Remap sector to target begin. */
	bio->bi_sector -= ti->begin;

	if (!(bio->bi_rw & (REQ_FLUSH | REQ_FUA))) {
		thinp_block = _sector_to_block(tc, bio->bi_sector);
		r = thinp_metadata_lookup(tc->tpm, thinp_block, 0, &pool_block);
		if (r == 0) {
			remap_bio(tc, bio, pool_block);
			return DM_MAPIO_REMAPPED;
		}
	}

	/* Don't bother the worker thread with read ahead io */
	if (bio_rw(bio) == READA)
		return -EIO;

	spin_lock(&tc->lock);
	bio_list_add(&tc->in, bio);
	spin_unlock(&tc->lock);

	wake_do_thinp(tc);
	return DM_MAPIO_SUBMITTED;
}

static void thinp_presuspend(struct dm_target *ti)
{
	struct thinp_c *tc = ti->private;

	spin_lock(&tc->lock);
	tc->bounce_mode = 1;
	spin_unlock(&tc->lock);

	thinp_flush(ti);
	requeue_all_bios(tc);
}

static void thinp_postsuspend(struct dm_target *ti)
{
	struct thinp_c *tc = ti->private;

	thinp_metadata_close(tc->tpm);
	tc->tpm = NULL;
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
static int thinp_preresume(struct dm_target *ti)
{
	int r;
	block_t data_size, sb_data_size;
	struct thinp_c *tc = ti->private;

	spin_lock(&tc->lock);
	tc->bounce_mode = 0;
	spin_unlock(&tc->lock);

	if (!tc->tpm) {
		r = create_tpm(tc);
		if (r) {
			DMERR("couldn't create thinp-metadata object");
			return r;
		}
	}

	data_size = _sector_to_block(tc, get_dev_size(tc->data_dev));
	r = thinp_metadata_get_data_dev_size(tc->tpm, &sb_data_size);
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
		r = thinp_metadata_resize_data_dev(tc->tpm, data_size);
		if (r)
			DMERR("failed to resize data device");
		else {
			spin_lock(&tc->provisioned_lock);
			tc->data_size = data_size;
			tc->triggered = 0;
			spin_unlock(&tc->provisioned_lock);
			wake_do_thinp(tc);
		}
	}

	return 0;
}

/* Thinp device status output method. */
static int thinp_status(struct dm_target *ti, status_type_t type,
			char *result, unsigned maxlen)
{
	ssize_t sz = 0;
	block_t provisioned, low_water_mark, data_size;
	char buf[BDEVNAME_SIZE], buf1[BDEVNAME_SIZE];
	struct thinp_c *tc = ti->private;

	spin_lock(&tc->provisioned_lock);
	provisioned = allocated_count(tc);
	low_water_mark = tc->low_water_mark;
	data_size = tc->data_size;
	spin_unlock(&tc->provisioned_lock);

	switch (type) {
	case STATUSTYPE_INFO:
		/*   <low mark> <chunks free> <chunks used> */
		DMEMIT("%llu %llu",
		       (LLU) data_size - provisioned,
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
static int thinp_bvec_merge(struct dm_target *ti,
			    struct bvec_merge_data *bvm,
			    struct bio_vec *biovec, int max_size)
{
	struct thinp_c *tc = ti->private;
	struct request_queue *q = bdev_get_queue(_remap_dev(tc));
	block_t thinp_block, pool_block;

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = _remap_dev(tc);
	bvm->bi_sector -= ti->begin;
	thinp_block = _sector_to_block(tc, bvm->bi_sector);
	if (thinp_metadata_lookup(tc->tpm, thinp_block, 0, &pool_block) < 0)
		return 0;

	bvm->bi_sector = _remap_sector(tc, bvm->bi_sector, pool_block);
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

/* Provide io hints. */
static void
thinp_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct thinp_c *tc = ti->private;

	blk_limits_io_min(limits, 0);
	blk_limits_io_opt(limits, data_dev_block_size(tc));
}

/* Thinp pool control target interface. */
static struct target_type thinp_target = {
	.name = "thin-prov",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = thinp_ctr,
	.dtr = thinp_dtr,
	.flush = thinp_flush,
	.map = thinp_map,
	.presuspend = thinp_presuspend,
	.postsuspend = thinp_postsuspend,
	.preresume = thinp_preresume,
	.status = thinp_status,
	.merge = thinp_bvec_merge,
	.io_hints = thinp_io_hints,
};

static int __init dm_thinp_init(void)
{
	return dm_register_target(&thinp_target);
}

static void dm_thinp_exit(void)
{
	dm_unregister_target(&thinp_target);
}

/* Module hooks */
module_init(dm_thinp_init);
module_exit(dm_thinp_exit);

MODULE_DESCRIPTION(DM_NAME "device-mapper thin provisioning target");
MODULE_AUTHOR("Heinz Mauelshagen <heinzm@redhat.com>");
MODULE_LICENSE("GPL");

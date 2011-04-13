/*
 * Copyright (C) 2010 Red Hat UK.  All rights reserved.
 *
 * This file is released under the GPL.
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

#define	DM_MSG_PREFIX	"multisnap"

/*----------------------------------------------------------------*/

/*
 * A pool device ties together a metadata device and a data device.  It
 * also provides the interface for creating and destroying internal
 * devices.
 */
struct pool_c {
	struct dm_dev *metadata_dev;
	struct dm_dev *data_dev;
	struct multisnap_metadata *mmd;
};

/*----------------------------------------------------------------*/

/*
 * Sadly we need a global table mapping bdevs to pool objects.
 */
struct multisnap_metadata *mmd_;

/*----------------------------------------------------------------*/

/*
 * multisnap-pool <metadata dev>
 *                <data dev>
 *                <data block size in sectors>
 *                <data dev size in blocks>
 * FIXME: add low water mark
 */
static int pool_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	long long unsigned block_size;
	block_t data_size;
	struct pool_c *md;
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

	if (sscanf(argv[3], "%llu", &data_size) != 1) {
		ti->error = "Invalid data size";
		dm_put_device(ti, metadata_dev);
		dm_put_device(ti, data_dev);
		return -EINVAL;
	}

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
	mmd_ = mmd;		/* FIXME: remove */

	ti->private = md;
	return 0;
}

static void pool_dtr(struct dm_target *ti)
{
	struct pool_c *md = ti->private;

	multisnap_metadata_close(md->mmd);
	dm_put_device(ti, md->metadata_dev);
	dm_put_device(ti, md->data_dev);
	kfree(md);
}

static int pool_map(struct dm_target *ti, struct bio *bio,
		    union map_info *map_context)
{
	struct pool_c *md = ti->private;
	bio->bi_bdev = md->data_dev->bdev;
	return DM_MAPIO_REMAPPED;
}

/*
 * Messages supported:
 *   new-thin <dev id> <dev size>
 *   new-snap <dev id> <origin id>
 *   del      <dev id>
 */
static int pool_message(struct dm_target *ti, unsigned argc, char **argv)
{
	/* ti->error doesn't have a const qualifier :( */
	char *invalid_args = "Incorrect number of arguments";

	int r;
	struct pool_c *md = ti->private;
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

/* Somehow we need to get from a pool device to the mmd for the pool. */
static struct multisnap_metadata *pool_to_mmd(struct block_device *bdev)
{
	return mmd_;
}

/*----------------------------------------------------------------*/

struct multisnap_c {
	struct dm_target *ti;
	struct dm_dev *pool_dev;
	struct multisnap_metadata *mmd;
	struct ms_device *msd;
	multisnap_dev_t dev_id;

	/* Data block size. */
	sector_t block_size;

	/* Quick sector -> block mapping. */
	unsigned int block_shift;

	/* Mask to give the offset of a sector within a block. */
	sector_t offset_mask;

	/*
	 * All blocking operations are deferred to a worker, eg. inserting
	 * a new mapping, looking up a mapping that isn't in the block
	 * manager cache.  Bios are passed via the |in| list.
	 */
	spinlock_t lock;
	struct bio_list work;
	struct work_struct ws;

	/*
	 * If the pool is out of space, then we must wait until it is
	 * extended.  The |no_space| list holds these deferred bios
	 */
	spinlock_t no_space_lock;
	struct bio_list no_space; /* Bios w/o data space. */

	/*
	 * If bounce mode is in effect all incoming bios are errored with
	 * DM_ENDIO_REQUEUE.
	 */
	int bounce_mode;
};

/* Derive offset within block from b */
static sector_t _sector_to_block(struct multisnap_c *mc, sector_t sector)
{
	return sector >> mc->block_shift;
}

static void wake_worker(struct multisnap_c *mc)
{
	if (!work_pending(&mc->ws))
		queue_work(multisnap_metadata_get_workqueue(mc->msd), &mc->ws);
}

static struct block_device *_remap_dev(struct multisnap_c *mc)
{
       return mc->pool_dev->bdev;
}

static sector_t _remap_sector(struct multisnap_c *mc, sector_t sector, block_t block)
{
	return (block << mc->block_shift) + (sector & mc->offset_mask);
}

static void remap_bio(struct multisnap_c *mc, struct bio *bio, block_t block)
{
	bio->bi_sector = _remap_sector(mc, bio->bi_sector, block);
	bio->bi_bdev = _remap_dev(mc);
}

static void requeue_bios(struct multisnap_c *mc, struct bio_list *bl, spinlock_t *lock)
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

static void requeue_all_bios(struct multisnap_c *mc)
{
	requeue_bios(mc, &mc->work, &mc->lock);
	requeue_bios(mc, &mc->no_space, &mc->no_space_lock);
}

static int is_congested(void *congested_data, int bdi_bits)
{
	int r;
	struct multisnap_c *mc = congested_data;

	spin_lock(&mc->no_space_lock);
	r = !bio_list_empty(&mc->no_space);
	spin_unlock(&mc->no_space_lock);

	if (!r) {
		struct request_queue *q = bdev_get_queue(mc->pool_dev->bdev);
		r = bdi_congested(&q->backing_dev_info, bdi_bits);
	}

	return r;
}

static void set_congestion_fn(struct multisnap_c *mc)
{
	struct mapped_device *md = dm_table_get_md(mc->ti->table);
	struct backing_dev_info *bdi = &dm_disk(md)->queue->backing_dev_info;

	/* Set congested function and data. */
	bdi->congested_fn = is_congested;
	bdi->congested_data = mc;
}
#if 0
static int copy_complete(int err, void *context1, void *context2)
{
	/* FIXME: what do we do if there's an io error? */
	
}

static int do_copy_on_write(struct multisnap_c *mc,
			    struct multisnap_map_result *mapping,
			    struct bio *remapped_bio)
{
	/*
	 * There's two approaches to this:
	 *
	 * i) copy the parts of the block before and after the bio.  Hook
	 * the bio, and tell the metadata that the copying is complete when
	 * all three components have completed.
	 *
	 * ii) Copy the complete block, when this is done tell the metadata
	 * that the copying is complete and submit the bio.
	 *
	 * (i) incurs less latency, but is more complicated to code, so
	 * we're sticking with the simpler (ii) here.  Experiments with (i)
	 * can be done later to show that the improvement is worth the
	 * additional code complexity.
	 */
	copy_block(mapping->origin, mapping->dest, copy_complete, mc, remapped_bio);
}
#endif
static void do_bios(struct multisnap_c *mc, struct bio_list *bios)
{
	int r;
	struct bio *bio;
	block_t block;
	struct multisnap_map_result mapping;

	while ((bio = bio_list_pop(bios))) {
		block = _sector_to_block(mc, bio->bi_sector);
		r = multisnap_metadata_map(mc->msd, block, bio_data_dir(bio),
					   1, &mapping);
		if (r == -ENODATA) {
			/* don't create a new mapping for a read */
			if (bio_data_dir(bio) == READ) {
				zero_fill_bio(bio);
				bio_endio(bio, 0);
				continue;
			}

			/* can't get here if it's a write */
			BUG_ON(bio_data_dir(bio) == WRITE);

		} else if (r == -ENOSPC) {
			/*
			 * No data space, so we postpone the bio
			 * until more space added by userland.
			 */
			spin_lock(&mc->no_space_lock);
			bio_list_add(&mc->no_space, bio);
			spin_unlock(&mc->no_space_lock);
			continue;
		}

		if (r)
			bio_io_error(bio);
		else {
#if 0
			/*
			 * Copying io must be issued before commit.  The
			 * commit will wait for it to complete.
			 */
			r = issue_copy_io(mc, &mapping, bio);
			if (r < 0) {
				/* FIXME: we need to unpick the mapping */
				bio_io_error(bio);
				continue;
			}
#endif

			/*
			 * REQ_FUA should only trigger a commit() if it's
			 * to a block that is pending.  I'm not sure
			 * whether the overhead of tracking pending blocks
			 * is worth it though.
			 */
			if ((bio->bi_rw & (REQ_FUA | REQ_FLUSH))) {
				r = multisnap_metadata_commit(mc->mmd);
				if (r < 0) {
					bio_io_error(bio);
					continue;
				}
			}

			remap_bio(mc, bio, mapping.dest);
			generic_make_request(bio);
		}
	}
}

static void do_work(struct work_struct *ws)
{
	int bounce_mode;
	struct multisnap_c *mc = container_of(ws, struct multisnap_c, ws);
	struct bio_list bios;
	bio_list_init(&bios);

	spin_lock(&mc->lock);
	bio_list_merge(&bios, &mc->work);
	bio_list_init(&mc->work);
	bounce_mode = mc->bounce_mode;
	spin_unlock(&mc->lock);

	if (bounce_mode) {
		struct bio *bio;
		while ((bio = bio_list_pop(&bios)))
			bio_endio(bio, DM_ENDIO_REQUEUE);
	} else
		do_bios(mc, &bios);
}

static void multisnap_flush(struct dm_target *ti)
{
	struct multisnap_c *mc = ti->private;

	/* Wait until all io has been processed. */

	/* FIXME: other multisnaps will still be working, so we can't
	 * flush, should instead keep a count of how many our jobs are
	 * pending. */
	flush_workqueue(multisnap_metadata_get_workqueue(mc->msd));
	if (multisnap_metadata_commit(mc->mmd) < 0) {
		printk(KERN_ALERT "multisnap metadata write failed.");
		/* FIXME: invalidate device? error the next FUA or FLUSH bio ?*/
	}
}

static void multisnap_dtr(struct dm_target *ti)
{
	struct multisnap_c *mc = ti->private;

	if (mc->msd) {
		multisnap_metadata_close_device(mc->msd);
		printk(KERN_ALERT "msd closed");
	}

	if (mc->pool_dev)
		dm_put_device(ti, mc->pool_dev);
	kfree(mc);
}

/*
 * Construct a multisnap device:
 *
 * <start> <length> multisnap <dev id> <pool_dev>
 *
 * dev_id: the internal device identifier
 * pool_dev: The multisnap-pool device
 *
 */
static int
multisnap_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	unsigned long dev_id;
	struct multisnap_c *mc;

	if (argc != 2) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	mc = ti->private = kzalloc(sizeof(*mc), GFP_KERNEL);
	if (!mc) {
		ti->error = "Out of memory";
		return -ENOMEM;
	}

	r = dm_get_device(ti, argv[0], FMODE_READ | FMODE_WRITE, &mc->pool_dev);
	if (r) {
		ti->error = "Error getting pool device";
		multisnap_dtr(ti);
		return r;
	}

	if (sscanf(argv[1], "%lu", &dev_id) != 1) {
		ti->error = "Invalid device id";
		multisnap_dtr(ti);
		return -EINVAL;
	}
	mc->dev_id = dev_id;

	mc->ti = ti;
	mc->mmd = pool_to_mmd(mc->pool_dev->bdev);
	if (!mc->mmd) {
		ti->error = "Couldn't get metadata object from pool device";
		multisnap_dtr(ti);
		return -EINVAL;
	}

	r = multisnap_metadata_open_device(mc->mmd, dev_id, &mc->msd);
	printk(KERN_ALERT "opened msd");
	if (r) {
		ti->error = "Couldn't open multisnap internal device";
		multisnap_dtr(ti);
		return r;
	}

	r = multisnap_metadata_get_data_block_size(mc->mmd, &mc->block_size);
	if (r) {
		ti->error = "Couldn't get data block size";
		multisnap_dtr(ti);
		return r;
	}

	ti->split_io = mc->block_size;
	mc->offset_mask = ti->split_io - 1;
	mc->block_shift = ffs(mc->block_size) - 1;

	spin_lock_init(&mc->lock);
	bio_list_init(&mc->work);
	INIT_WORK(&mc->ws, do_work);

	spin_lock_init(&mc->no_space_lock);
	bio_list_init(&mc->no_space);

	mc->bounce_mode = 0;
	set_congestion_fn(mc);

	smp_wmb();
	return 0;
}

static int
multisnap_map(struct dm_target *ti, struct bio *bio,
	      union map_info *map_context)
{
	int r;
	struct multisnap_c *mc = ti->private;
	block_t block;
	struct multisnap_map_result mapping;

	/* Remap sector to target begin. */
	bio->bi_sector -= ti->begin;

	if (!(bio->bi_rw & (REQ_FLUSH | REQ_FUA))) {
		block = _sector_to_block(mc, bio->bi_sector);
		r = multisnap_metadata_map(mc->msd, block,
					   bio_data_dir(bio), 0, &mapping);
		if (r == 0) {
			/*
			 * Because the non-blocking flag wasn't set we know
			 * no copying is necc.
			 */
			remap_bio(mc, bio, mapping.dest);
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

	spin_lock(&mc->lock);
	bio_list_add(&mc->work, bio);
	spin_unlock(&mc->lock);

	wake_worker(mc);
	return DM_MAPIO_SUBMITTED;
}

static void
multisnap_presuspend(struct dm_target *ti)
{
	struct multisnap_c *mc = ti->private;

	spin_lock(&mc->lock);
	mc->bounce_mode = 1;
	spin_unlock(&mc->lock);

	multisnap_flush(ti);
	requeue_all_bios(mc);
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
multisnap_preresume(struct dm_target *ti)
{
	struct multisnap_c *mc = ti->private;

	spin_lock(&mc->lock);
	mc->bounce_mode = 0;
	spin_unlock(&mc->lock);

	return 0;
}

static int
multisnap_status(struct dm_target *ti, status_type_t type,
		 char *result, unsigned maxlen)
{
	int r;
	ssize_t sz = 0;
	block_t mapped;
	char buf[BDEVNAME_SIZE];
	struct multisnap_c *mc = ti->private;
	unsigned long dev_id;

	r = multisnap_metadata_get_mapped_count(mc->msd, &mapped);
	if (r)
		return r;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%llu", mapped);
		break;

	case STATUSTYPE_TABLE:
		dev_id = mc->dev_id;
		DMEMIT("%s %lu",
		       format_dev_t(buf, mc->pool_dev->bdev->bd_dev),
		       dev_id);
	}

	return 0;
}

/* bvec merge method. */
static int
multisnap_bvec_merge(struct dm_target *ti,
		     struct bvec_merge_data *bvm,
		     struct bio_vec *biovec, int max_size)
{
	struct multisnap_c *mc = ti->private;
	struct request_queue *q = bdev_get_queue(_remap_dev(mc));
	block_t block;
	struct multisnap_map_result mapping;

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = _remap_dev(mc);
	bvm->bi_sector -= ti->begin;
	block = _sector_to_block(mc, bvm->bi_sector);

	/*
	 * We look this up as a WRITE in case the bio is going to cause a
	 * new mapping.  Because we've selected non-blocking we know no
	 * mapping will be inserted.
	 */
	if (multisnap_metadata_map(mc->msd, block, WRITE, 0, &mapping) < 0)
		return 0;

	bvm->bi_sector = _remap_sector(mc, bvm->bi_sector, mapping.dest);
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

/* Provide io hints. */
static void
multisnap_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	int r;
	sector_t block_size;
	struct multisnap_c *mc = ti->private;

	blk_limits_io_min(limits, 0);

	r = multisnap_metadata_get_data_block_size(mc->mmd, &block_size);
	if (r)
		printk(KERN_ALERT "mmd_get_data_block_size() failed");
	blk_limits_io_opt(limits, r ? 0 : block_size);
}

static struct target_type multisnap_target = {
	.name =        "multisnap",
	.version =     {1, 0, 0},
	.module =      THIS_MODULE,
	.ctr =	       multisnap_ctr,
	.dtr =	       multisnap_dtr,
	.flush =       multisnap_flush,
	.map =	       multisnap_map,
	.presuspend =  multisnap_presuspend,
	.preresume =   multisnap_preresume,
	.status =      multisnap_status,
	.merge =       multisnap_bvec_merge,
	.io_hints =    multisnap_io_hints,
};

/*----------------------------------------------------------------*/

static int __init dm_multisnap_init(void)
{
	int r = dm_register_target(&multisnap_target);
	if (r)
		return r;

	r = dm_register_target(&pool_target);
	if (r)
		dm_unregister_target(&multisnap_target);

	return r;
}

static void dm_multisnap_exit(void)
{
	dm_unregister_target(&multisnap_target);
	dm_unregister_target(&pool_target);
}

module_init(dm_multisnap_init);
module_exit(dm_multisnap_exit);

MODULE_DESCRIPTION(DM_NAME "device-mapper multisnap target");
MODULE_AUTHOR("Joe Thornber <thornber@redhat.com>");
MODULE_LICENSE("GPL");

/*----------------------------------------------------------------*/



#if 0
#define TABLE_SIZE 1024
static spinlock_t table_lock_;
static struct hlist_head table_[TABLE_SIZE];

static void
table_init(void)
{
	unsigned i;
	spinlock_init(&table_lock_);
	for (i = 0; i < TABLE_SIZE; i++)
		INIT_HLIST_HEAD(table_ + i);
}

static unsigned
hash_bdev(struct block_device *bdev)
{
	/* FIXME: finish */
	/* bdev -> dev_t -> unsigned */
	return 0;
}

static void
table_insert(struct block_device *bdev, struct pool_c *p)
{
	unsigned bucket = hash_bdev(bdev);
	hlist_add_head(hash, table_ + bucket);
}

static void
table_remove(struct hash_node *hash)
{
	hlist_del(hash);
}

static struct pool_c *
table_lookup(struct block_device *bdev)
{
	unsigned bucket = hash_bdev(bdev);
	struct multisnap_metadata *mmd;
	struct hlist_node *n;

	hlist_for_each_entry (mmd, n, mmd_table_ + bucket, hash)
		if (mmd->bdev == bdev)
			return mmd;

	return NULL;
}

{
	struct multisnap_metadata *mmd;

	mmd = mmd_table_lookup(bdev);
	if (mmd)
		atomic_inc(&mmd->ref_count);
	else {
		mmd = multisnap_metadata_open_(bdev, data_block_size, data_dev_size);
		if (!mmd) {
			printk(KERN_ALERT "couldn't open new multisnap metadata device");
			return NULL;
		}

		atomic_set(&mmd->ref_count, 1);
		mmd_table_insert(mmd);
	}

	BUG_ON(!mmd->sblock);
	return mmd;
}
#endif

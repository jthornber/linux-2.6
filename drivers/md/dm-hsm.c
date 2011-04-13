/*
 * Copyright (C) 2011 Red Hat GmbH. All rights reserved.
 *
 * This file is released under the GPL.
 *
 * Hierarchical Storage Management target.
 *
 * Features:
 * o manages a storage pool of blocks on a fast cache block device
 *   to allocate from in order to cache blocks of a slower cached device
 * o data block size selectable (2^^N)
 * o low water mark in hsm ctr line and status
 *   - status <chunks free> <chunks used>
 *   - userland to kernel message just be a single resume (no prior suspend)
 *   - status provide metadata stats, userland resizes via same
 *     mechanism as data extend
 *
 * FIXME:
 * o add policies for metadata device full:
 *   - error bio (implemented)
 *   - postpone bio and wait on userspace to grow the metadata device
 * o support DISCARD requests to free unused blocks
 * o support relocation of blocks to allow for hot spot removal
 *   and shrinking of the data device.
 * o eventually drop metadata store creation once userspace does it
 *
 */

static const char version[] = "1.0";

#include "dm.h"
#include "hsm-metadata.h"
#include "persistent-data/transaction-manager.h"

#include <asm/div64.h>

#include <linux/blkdev.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>

/*----------------------------------------------------------------*/

#define	DM_MSG_PREFIX	"dm-hsm"
#define	DAEMON		DM_MSG_PREFIX	"d"

/* Minimum data device block size in sectors. */
#define	DATA_DEV_BLOCK_SIZE_MIN	8
#define	LLU	long long unsigned

#define	MIN_IOS	32
#define	DM_KCOPYD_PAGES	64

/* Cache for block io housekeeping. */
static struct kmem_cache *block_cache;

/* Hierarchical storage context. */
struct hsm_c {
	struct dm_target *ti;
	struct hsm_metadata *hmd;

	struct dm_dev *cached_dev;
	struct dm_dev *data_dev;
	struct dm_dev *meta_dev;

	struct list_head hsm_blocks;
	struct list_head flush_blocks;
	struct list_head endio_blocks;
	spinlock_t endio_lock;

	mempool_t *block_pool;

	sector_t block_sectors;
	sector_t offset_mask;	/* mask for offset of a sector within a block */
	unsigned int block_shift; /* Quick sector -> block mapping. */

	spinlock_t lock;	/* Protects central input list below. */
	struct bio_list in;	/* Bio input queue. */
	struct dm_kcopyd_client *kcopyd_client; /* kcopyd data <-> cached dev.*/

	spinlock_t no_space_lock;
	struct bio_list no_space; /* Bios w/o metadata space. */

	struct work_struct ws;		/* IO work. */

	block_t low_water_mark;

	spinlock_t provisioned_lock; /* protects next 4 fields */
	sector_t data_sectors;	/* Size of data device in sectors. */
	block_t data_blocks;	/* Size of data device in blocks. */
	sector_t cached_sectors;/* Size of cached device in sectors. */
	block_t provisioned_count;
	block_t updates_since_last_commit;
	int triggered;	/* 'Flag' for one shot table events. */
	int bounce_mode;
};

struct hsm_block {
	struct hsm_c *hc;
	struct list_head list, flush_endio;
	struct bio_list delay;
	spinlock_t delay_lock;
	block_t cache_block, pool_block;
	unsigned long flags, error, timeout;
	void *bio_private;
	atomic_t ref;
};

enum block_flags {
	BLOCK_UPTODATE,
	BLOCK_DIRTY,
	BLOCK_FORCE_DIRTY,
	/* Only max 4 persistent flags valid with hsm-metadata.c! */

	/* non-persistent flags start here */
	BLOCK_ACTIVE = 31,
	BLOCK_ERROR = 32,
};

static void _get_block(struct hsm_block *b)
{
	atomic_inc(&b->ref);
}

static struct hsm_block *get_block(struct hsm_c *hc, block_t cache_block)
{
	struct hsm_block *b;

	/* FIXME: hash this! */
	list_for_each_entry(b, &hc->hsm_blocks, list) {
		if (b->cache_block == cache_block) {
			_get_block(b);
			goto out;
		}
	}

	b = mempool_alloc(hc->block_pool, GFP_NOIO);
	if (b) {
		memset(b, 0, sizeof(*b));
		b->hc = hc;
		INIT_LIST_HEAD(&b->flush_endio);
		bio_list_init(&b->delay);
		spin_lock_init(&b->delay_lock);
		b->cache_block = cache_block;
		atomic_set(&b->ref, 1);
		list_add(&b->list, &hc->hsm_blocks);
	}
out:
	return b;
}

static void put_block(struct hsm_block *b)
{
	if (atomic_dec_and_test(&b->ref)) {
		list_del(&b->list);
		mempool_free(b, b->hc->block_pool);
	}
}

/* Return size of device in sectors. */
static sector_t get_dev_size(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

/* Return data device block size in sectors. */
static sector_t data_dev_block_sectors(struct hsm_c *hc)
{
	sector_t size;
	return hsm_metadata_get_data_block_size(hc->hmd, 1, &size) ? 0 : size;
}

/* Derive offset within block from b */
static sector_t _sector_to_block(struct hsm_c *hc, sector_t sector)
{
	return sector >> hc->block_shift;
}

static void wake_do_hsm(struct hsm_c *hc)
{
	if (!work_pending(&hc->ws))
		queue_work(hsm_metadata_get_workqueue(hc->hmd), &hc->ws);
}

static struct block_device *_remap_dev(struct hsm_c *hc)
{
       return hc->data_dev->bdev;
}

static sector_t _remap_sector(struct hsm_c *hc, sector_t sector, block_t block)
{
	return (block << hc->block_shift) + (sector & hc->offset_mask);
}

static void remap_bio(struct hsm_c *hc, struct bio *bio, block_t block)
{
	bio->bi_sector = _remap_sector(hc, bio->bi_sector, block);
	bio->bi_bdev = _remap_dev(hc);
}

/* Block copy callback (dm-kcopyd). */
static void block_copy_endio(int read_err, unsigned long write_err,
                             void *context)
{
	struct hsm_block *b = context;

	if (read_err || write_err)
		set_bit(BLOCK_ERROR, &b->flags);
	else if (test_and_set_bit(BLOCK_UPTODATE, &b->flags))
		clear_bit(BLOCK_DIRTY, &b->flags);

	spin_lock(&b->hc->endio_lock);
	list_move(&b->flush_endio, &b->hc->endio_blocks);
	spin_unlock(&b->hc->endio_lock);

	wake_do_hsm(b->hc);
}

/* Copy blocks between cache and original (cached) device. */
static int block_copy(int rw, struct hsm_block *b)
{
	struct dm_io_region cache = {
		.bdev = b->hc->data_dev->bdev,
		.sector = _remap_sector(b->hc, 0, b->cache_block),
	}, orig = {
		.bdev = b->hc->cached_dev->bdev,
		.sector = _remap_sector(b->hc, 0, b->pool_block),
	}, *from, *to;

	if (test_and_set_bit(BLOCK_ACTIVE, (unsigned long*) &b->flags))
		return 0;

	/* Check for partial extent at origin device end. */
	cache.count = orig.count =
		min(b->hc->block_sectors, b->hc->data_sectors - orig.sector);

	/* Set source and destination. */
	rw == READ ? (from = &orig,  to = &cache) :
		     (from = &cache, to = &orig);
	return dm_kcopyd_copy(b->hc->kcopyd_client, from, 1, to, 0,
			      block_copy_endio, b);
}

static void requeue_bios(struct hsm_c *hc, struct bio_list *bl, spinlock_t *lock)
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

static void requeue_all_bios(struct hsm_c *hc)
{
	requeue_bios(hc, &hc->in, &hc->lock);
	requeue_bios(hc, &hc->no_space, &hc->no_space_lock);
}

/* Return number of allocated blocks. */

static block_t allocated_count(struct hsm_c *hc)
{
	return hc->updates_since_last_commit + hc->provisioned_count;
}

static int _congested(struct dm_dev *dev, int bdi_bits)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);

	return bdi_congested(&q->backing_dev_info, bdi_bits);
}

/* Hierachical storage congested function. */
static int hc_congested(void *congested_data, int bdi_bits)
{
	int r;
	struct hsm_c *hc = congested_data;

	spin_lock(&hc->no_space_lock);
	r = !bio_list_empty(&hc->no_space);
	spin_unlock(&hc->no_space_lock);

	if (!r) {
		r = _congested(hc->cached_dev, bdi_bits);
		if (!r) {
			r = _congested(hc->meta_dev, bdi_bits);
			if (!r)
				r = _congested(hc->data_dev, bdi_bits);
		}
	}

	return r;
}

/* Set congested function. */
static void hc_set_congested_fn(struct hsm_c *hc)
{
	struct mapped_device *md = dm_table_get_md(hc->ti->table);
	struct backing_dev_info *bdi = &dm_disk(md)->queue->backing_dev_info;

	/* Set congested function and data. */
	bdi->congested_fn = hc_congested;
	bdi->congested_data = hc;
}

static void inc_update(struct hsm_c *hc)
{
	int do_event = 0;

	spin_lock(&hc->provisioned_lock);
	hc->updates_since_last_commit++;
	if (!hc->triggered) {
		if (hc->data_blocks - allocated_count(hc) <=
		    hc->low_water_mark) {
			do_event = 1;
			hc->triggered = 1;
		}
	}

	spin_unlock(&hc->provisioned_lock);

	if (do_event)
		dm_table_event(hc->ti->table);
}

static int commit(struct hsm_c *hc)
{
	int r = 0;
	block_t updates;

	spin_lock(&hc->provisioned_lock);
	updates = hc->updates_since_last_commit;
	spin_unlock(&hc->provisioned_lock);

	if (updates) {
		r = hsm_metadata_commit(hc->hmd);
		if (!r) {
			spin_lock(&hc->provisioned_lock);
			hc->provisioned_count += updates;
			hc->updates_since_last_commit = 0;
			spin_unlock(&hc->provisioned_lock);
		}
	}

	return r;
}

/* Insert into flash list sorted by timeout. */
static void flush_add_sorted(struct hsm_block *b)
{
	struct hsm_block *b_cur;

	list_for_each_entry(b_cur, &b->hc->flush_blocks, flush_endio) {
		if (b->timeout < b_cur->timeout)
			break;
	}

	if (list_empty(&b->flush_endio)) {
		_get_block(b);
		list_add(&b->flush_endio, &b_cur->flush_endio);
	}
}

/* Process all endios on blocks. */
static void do_endios(struct hsm_c *hc)
{
	int err, r;
	struct hsm_block *b, *tmp;
	LIST_HEAD(endios);

	spin_lock(&hc->endio_lock);
	list_splice(&hc->endio_blocks, &endios);
	INIT_LIST_HEAD(&hc->endio_blocks);
	spin_unlock(&hc->endio_lock);

	list_for_each_entry(b, &endios, flush_endio) {
		BUG_ON(!test_bit(BLOCK_UPTODATE, &b->flags));

		/* Reforce write, because we've been written to again. */
		if (test_and_clear_bit(BLOCK_FORCE_DIRTY, &b->flags)) {
			set_bit(BLOCK_DIRTY, &b->flags);
			r = hsm_metadata_update(hc->hmd, 1, b->cache_block,
						b->flags);
			if (!r)
				inc_update(hc);
		}
	}

	/* If the commit fails, error all delayed bios below. */
	err = commit(hc) ? -EIO : 0;

	list_for_each_entry_safe(b, tmp, &endios, flush_endio) {
		struct bio *bio;
		struct bio_list bios;

		bio_list_init(&bios);
		list_del_init(&b->flush_endio);

		spin_lock(&b->delay_lock);
		bio_list_merge(&bios, &b->delay);
		bio_list_init(&b->delay);
		spin_unlock(&b->delay_lock);

		/* Reforce write, because we've been written to again. */
		if (test_bit(BLOCK_DIRTY, &b->flags)) {
			b->timeout = jiffies + 3 * HZ;
			flush_add_sorted(b);
		}

		while ((bio = bio_list_pop(&bios))) {
			bio_endio(bio, err);
			put_block(b);
		}

		clear_bit(BLOCK_ACTIVE, &b->flags);
		put_block(b); /* Release reference for block_copy(); */
	}
}

/* Process all bios. */
static void do_bios(struct hsm_c *hc, struct bio_list *bios)
{
	struct bio *bio;

	while ((bio = bio_list_pop(bios))) {
		int r, rw = bio_data_dir(bio);
		unsigned long flags;
		block_t cache_block, pool_block;
		struct hsm_block *b;

		cache_block = _sector_to_block(hc, bio->bi_sector);
		r = hsm_metadata_lookup(hc->hmd, 1, cache_block, 1,
					&pool_block, &flags);
		if (r == -ENODATA) {
			/* Don't create a new mapping for a read */
			if (rw == READ) {
				zero_fill_bio(bio);
				bio_endio(bio, 0);
				continue;
			}

			/* New mapping */
			r = hsm_metadata_insert(hc->hmd, 1, cache_block,
					        &pool_block, &flags);
			if (!r)
				inc_update(hc);
			else if (r == -ENOSPC) {
				/*
				 * No data space, so we postpone the bio
				 * until more space added by userland.
				 */
nospace:
				spin_lock(&hc->no_space_lock);
				bio_list_add(&hc->no_space, bio);
				spin_unlock(&hc->no_space_lock);
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
				r = commit(hc);
				if (r < 0) {
					bio_io_error(bio);
					continue;
				}
			}

			/* Get the block housekeeping object for the io. */
			b = get_block(hc, cache_block);
			if (!b)
				goto nospace;

			if (atomic_read(&b->ref) == 1) {
				b->pool_block = pool_block;
				b->flags = flags;
				b->bio_private = bio->bi_private;
			} else
				BUG_ON(b->bio_private != bio->bi_private);

			if (!test_bit(BLOCK_UPTODATE, &b->flags)) {
				/*
				 * Block isn't uptodate, so we postpone the
				 * bio until it got read into the cache.
				 */
				bio_list_add(&b->delay, bio);
				BUG_ON(block_copy(READ, b));
				continue;
			}

			if (rw == WRITE) {
				set_bit(test_bit(BLOCK_DIRTY, &b->flags) ? BLOCK_FORCE_DIRTY : BLOCK_DIRTY, &b->flags);
				r = hsm_metadata_update(hc->hmd, 1, cache_block,
							b->flags);
				if (r) { /* Fatal. */
					put_block(b);
					bio_io_error(bio);
					continue;
				} else if (list_empty(&b->flush_endio)) {
					b->timeout = jiffies + 3 * HZ;
					flush_add_sorted(b);
				}
			}

			bio->bi_private = b;
			remap_bio(hc, bio, b->pool_block);
			generic_make_request(bio);
		}
	}
}

/* Process any delayed block writes. */
static void do_block_copies(struct hsm_c *hc)
{
	struct hsm_block *b, *tmp;

	list_for_each_entry_safe(b, tmp, &hc->flush_blocks, list) {
		if (jiffies > b->timeout) {
			b->timeout = ~0;
			list_del_init(&b->flush_endio);
			/* flush_add_sorted took out a reference already. */
			BUG_ON(block_copy(WRITE, b));
		} else
			break; /* Bail out, flush list is sorted by timeout. */
	}
}

/* Check for block inactive, ie. no copy io or bios pending. */
static int block_inactive(struct hsm_c *hc,
			  block_t pool_block, block_t *cache_block)
{
	int r;
	struct hsm_block *b;

	/* Reverse lookup cache block by pool block. */
	r = hsm_metadata_lookup_reverse(hc->hmd, 1, pool_block, 0, cache_block);
	if (r)
		return r;

	b = get_block(hc, *cache_block);
	r = atomic_read(&b->ref);
	put_block(b);
	return r == 1;
}

/*
 * Free an allocated block.
 *
 * We presume that the cache is fully allocated,
 * thus we can free an idle block randomly.
 *
 * FIXME: need reverse lookup from pool_block -> cache_block to allow for this.
 * 	  See block_inactive().
 * 	  This may end up finding no inactive block even if there's some
 * 	  _because_ if its random pattern.
 */
static void do_block_free(struct hsm_c *hc)
{
	if (!bio_list_empty(&hc->no_space)) {
		block_t blocks_active = 0;

		while (blocks_active < hc->data_blocks) {
			int r;
			unsigned int rand = random32();
			block_t cache_block,
				pool_block = do_div(rand, hc->data_blocks);

			r = block_inactive(hc, pool_block, &cache_block);
			BUG_ON(r < 0);
			if (r) {
				r = hsm_metadata_remove(hc->hmd, 1,
							cache_block);
				break;
			} else
				blocks_active++;
		}
	}
}

/* Main worker function. */
static void do_hsm(struct work_struct *ws)
{
	int bounce_mode;
	struct hsm_c *hc = container_of(ws, struct hsm_c, ws);
	struct bio_list bios;

	bio_list_init(&bios);

	spin_lock(&hc->lock);
	bio_list_merge(&bios, &hc->in);
	bio_list_init(&hc->in);
	bounce_mode = hc->bounce_mode;
	spin_unlock(&hc->lock);

	do_endios(hc);

	if (bounce_mode) {
		struct bio *bio;

		while ((bio = bio_list_pop(&bios)))
			bio_endio(bio, DM_ENDIO_REQUEUE);
	} else
		do_bios(hc, &bios);

	do_block_copies(hc);
	do_block_free(hc);
}

static void hsm_flush(struct dm_target *ti)
{
	struct hsm_c *hc = ti->private;

	/* Wait until all io has been processed. */
	flush_workqueue(hsm_metadata_get_workqueue(hc->hmd));

	if (commit(hc) < 0) {
		printk(KERN_ALERT "hsm metadata write failed.");
		/* FIXME: invalidate device? error the next FUA or FLUSH bio ?*/
	}
}

/* Destroy a hsm device mapping. */
static void hsm_dtr(struct dm_target *ti)
{
	struct hsm_c *hc = ti->private;

	/* Destroy hsm block pool. */
	if (hc->block_pool)
		mempool_destroy(hc->block_pool);

	/* Destroy kcopyd client. */
	if (hc->kcopyd_client)
		dm_kcopyd_client_destroy(hc->kcopyd_client);

	/* Close hsm metadata handler. */
	if (hc->hmd)
		hsm_metadata_close(hc->hmd);

	/* Release reference on cached device. */
	if (hc->cached_dev)
		dm_put_device(ti, hc->cached_dev);

	/* Release reference on data device. */
	if (hc->data_dev)
		dm_put_device(ti, hc->data_dev);

	/* Release reference on metadata device. */
	if (hc->meta_dev)
		dm_put_device(ti, hc->meta_dev);

	kfree(hc);
}

/* Parse constructor arguments. */
static int _parse_args(struct dm_target *ti, unsigned argc, char **argv,
		       sector_t *block_sectors, block_t *low_water_mark)
{
	unsigned long long tmp;

	if (argc != 5) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	if (sscanf(argv[3], "%llu", &tmp) != 1 ||
	    tmp < DATA_DEV_BLOCK_SIZE_MIN ||
	    !is_power_of_2(tmp)) {
		ti->error = "Invalid data block size argument";
		return -EINVAL;
	}

	*block_sectors = tmp;

	if (sscanf(argv[4], "%llu", &tmp) != 1) {
		ti->error = "Invalid low water mark argument";
		return -EINVAL;
	}

	*low_water_mark = tmp;
	return 0;
}

static int __get_device(struct dm_target *ti, char *arg, struct dm_dev **dev,
			char *errstr)
{
	int r = dm_get_device(ti, arg, FMODE_READ | FMODE_WRITE, dev);

	if (r)
		ti->error = errstr;

	return r;
}

static int _get_devices(struct hsm_c *hc, char **argv)
{
	return (__get_device(hc->ti, argv[0], &hc->cached_dev,
			     "Error opening cached device") ||
		__get_device(hc->ti, argv[1], &hc->data_dev,
			     "Error opening data device") ||
		__get_device(hc->ti, argv[2], &hc->meta_dev,
			     "Error opening metadata device"));

}

static int create_hsd(struct hsm_c *hc)
{
	hc->hmd = hsm_metadata_open(hc->meta_dev->bdev, hc->block_sectors,
				    hc->data_blocks);
	if (!hc->hmd) {
		DMINFO("%s couldn't open hsm metadata object", __func__);
		return -ENOMEM;
	} else
		DMINFO("%s hsm metadata dev opened", __func__);

	/* Get already provisioned blocks. */
	return hsm_metadata_get_provisioned_blocks(hc->hmd, 1,
						   &hc->provisioned_count);
}

/*
 * Construct a hierarchical storage device mapping:
 *
 * <start> <length> hsm <cached_dev> <data_dev> <meta_dev> \
 * 			<data_block_size> <low_water_mark>
 *
 * cached_dev: slow cached device holding original data blocks;
 * 	       can be any preexisting slow device to be cached
 * data_dev: fast device holding cached data blocks
 * meta_dev: fast device keeping track of provisioned cached blocks
 * data_block_size: cache unit size in sectors
 * low_water_mark: low water mark to throw a dm event for uspace
 * 		   to decide to resize the (meta)data device
 *
 */
static int hsm_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	sector_t block_sectors = 0;
	block_t low_water_mark = 0;
	struct hsm_c *hc;

	r = _parse_args(ti, argc, argv, &block_sectors, &low_water_mark);
	if (r)
		return r;

	hc = ti->private = kzalloc(sizeof(*hc), GFP_KERNEL);
	if (!hc) {
		ti->error = "Error allocating hsm context";
		return -ENOMEM;
	}

	hc->ti = ti;
	INIT_LIST_HEAD(&hc->hsm_blocks);
	INIT_LIST_HEAD(&hc->flush_blocks);
	INIT_LIST_HEAD(&hc->endio_blocks);
	hc->block_sectors = block_sectors;
	hc->block_shift = ffs(block_sectors) - 1;
	hc->low_water_mark = low_water_mark;
	hc_set_congested_fn(hc);

	spin_lock_init(&hc->lock);
	spin_lock_init(&hc->endio_lock);
	bio_list_init(&hc->in);
	spin_lock_init(&hc->no_space_lock);
	bio_list_init(&hc->no_space);

	r = _get_devices(hc, argv);
	if (r)
		goto err;

	r = dm_kcopyd_client_create(DM_KCOPYD_PAGES, &hc->kcopyd_client);
	if (r) 
		goto err;

	hc->block_pool = mempool_create_slab_pool(MIN_IOS, block_cache);
        if (!hc->block_pool)
		goto err;

	hc->data_sectors = get_dev_size(hc->data_dev);
	hc->data_blocks = _sector_to_block(hc, hc->data_sectors);
	hc->cached_sectors = get_dev_size(hc->cached_dev);
	INIT_WORK(&hc->ws, do_hsm);
	ti->split_io = hc->block_sectors;

	/* Set masks/shift for fast bio -> block mapping. */
	hc->offset_mask = ti->split_io - 1;

	spin_lock_init(&hc->provisioned_lock);
	hc->updates_since_last_commit = 0;
	hc->triggered = 0;
	hc->bounce_mode = 0;
	smp_wmb();
	return 0;

err:
	hsm_dtr(ti);
	return r;
}

/* Map a hierarchical storage device  */
static int hsm_map(struct dm_target *ti, struct bio *bio,
		   union map_info *map_context)
{
	struct hsm_c *hc = ti->private;

	/* Don't bother the worker thread with read ahead io */
	if (bio_rw(bio) == READA)
		return -EIO;

	/* Remap sector to target begin. */
	bio->bi_sector -= ti->begin;

	spin_lock(&hc->lock);
	bio_list_add(&hc->in, bio);
	spin_unlock(&hc->lock);

	wake_do_hsm(hc);
	return DM_MAPIO_SUBMITTED;
}

/* End io process a bio. */
static int hsm_end_io(struct dm_target *ti, struct bio *bio,
		      int error, union map_info *map_context)
{
	struct hsm_block *b = bio->bi_private;

	/*
	 * Check for eventually delaying endio, because
	 * the metadata isn't written yet unless error.
	 */
	BUG_ON(!b);
	BUG_ON(!b->bio_private);
	bio->bi_private = b->bio_private;

	if (!error && test_bit(BLOCK_ACTIVE, &b->flags)) {
		spin_lock(&b->delay_lock);
		bio_list_add(&b->delay, bio);
		spin_unlock(&b->delay_lock);
		return DM_ENDIO_INCOMPLETE;
	} else
		put_block(b);

	return error;
}

static void hsm_presuspend(struct dm_target *ti)
{
	struct hsm_c *hc = ti->private;

	spin_lock(&hc->lock);
	hc->bounce_mode = 1;
	spin_unlock(&hc->lock);

	hsm_flush(ti);
	requeue_all_bios(hc);
}

static void hsm_postsuspend(struct dm_target *ti)
{
	struct hsm_c *hc = ti->private;

	hsm_metadata_close(hc->hmd);
	hc->hmd = NULL;
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
static int hsm_preresume(struct dm_target *ti)
{
	int r;
	sector_t data_sectors;
	block_t data_blocks, sb_data_blocks;
	struct hsm_c *hc = ti->private;

	spin_lock(&hc->lock);
	hc->bounce_mode = 0;
	spin_unlock(&hc->lock);

	if (!hc->hmd) {
		r = create_hsd(hc);
		if (r) {
			DMERR("couldn't create hsm-metadata object");
			return r;
		}
	}

	data_sectors = get_dev_size(hc->data_dev);
	data_blocks = _sector_to_block(hc, data_sectors);
	r = hsm_metadata_get_data_dev_size(hc->hmd, 1, &sb_data_blocks);
	if (r) {
		DMERR("failed to retrieve data device size");
		return r;
	}

	/* Nothing to resize. */
	if (data_blocks == sb_data_blocks)
		return 0;

	if (data_blocks < sb_data_blocks) /* FIXME: weird */
		DMWARN("new data device size smaller than actual one");
	else {
		r = hsm_metadata_resize_data_dev(hc->hmd, 1, data_blocks);
		if (r)
			DMERR("failed to resize data device");
		else {
			spin_lock(&hc->provisioned_lock);
			hc->data_sectors = data_sectors;
			hc->data_blocks = data_blocks;
			hc->triggered = 0;
			spin_unlock(&hc->provisioned_lock);
			wake_do_hsm(hc);
		}
	}

	return 0;
}

/* Thinp device status output method. */
static int hsm_status(struct dm_target *ti, status_type_t type,
			char *result, unsigned maxlen)
{
	ssize_t sz = 0;
	block_t provisioned, low_water_mark, data_blocks;
	char buf[BDEVNAME_SIZE], buf1[BDEVNAME_SIZE];
	struct hsm_c *hc = ti->private;

	spin_lock(&hc->provisioned_lock);
	provisioned = allocated_count(hc);
	low_water_mark = hc->low_water_mark;
	data_blocks = hc->data_blocks;
	spin_unlock(&hc->provisioned_lock);

	switch (type) {
	case STATUSTYPE_INFO:
		/*   <chunks free> <chunks used> */
		DMEMIT("%llu %llu",
		       (LLU) data_blocks - provisioned,
		       (LLU) provisioned);
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%s %s %s %llu %llu",
		       format_dev_t(buf1, hc->cached_dev->bdev->bd_dev),
		       format_dev_t(buf1, hc->data_dev->bdev->bd_dev),
		       format_dev_t(buf, hc->meta_dev->bdev->bd_dev),
		       (LLU) hc->block_sectors,
		       (LLU) low_water_mark);
	}

	return 0;
}

/* bvec merge method. */
static int hsm_bvec_merge(struct dm_target *ti,
			    struct bvec_merge_data *bvm,
			    struct bio_vec *biovec, int max_size)
{
	unsigned long flags;
	struct hsm_c *hc = ti->private;
	struct request_queue *q = bdev_get_queue(_remap_dev(hc));
	block_t hsm_block, pool_block;

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = _remap_dev(hc);
	bvm->bi_sector -= ti->begin;
	hsm_block = _sector_to_block(hc, bvm->bi_sector);
	if (hsm_metadata_lookup(hc->hmd, 1, hsm_block, 0,
				&pool_block, &flags) < 0)
		return 0;

	bvm->bi_sector = _remap_sector(hc, bvm->bi_sector, pool_block);
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

/* Provide io hints. */
static void
hsm_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct hsm_c *hc = ti->private;

	blk_limits_io_min(limits, 0);
	blk_limits_io_opt(limits, data_dev_block_sectors(hc));
}

/* Thinp device target interface. */
static struct target_type hsm_target = {
	.name = "hsm",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = hsm_ctr,
	.dtr = hsm_dtr,
	.flush = hsm_flush,
	.map = hsm_map,
	.end_io = hsm_end_io,
	.presuspend = hsm_presuspend,
	.postsuspend = hsm_postsuspend,
	.preresume = hsm_preresume,
	.status = hsm_status,
	.merge = hsm_bvec_merge,
	.io_hints = hsm_io_hints,
};

static int __init dm_hsm_init(void)
{
	block_cache = KMEM_CACHE(hsm_block, 0);
        if (!block_cache) {
                DMERR("Couldn't create block cache.");
                return -ENOMEM;
        }

	srandom32(jiffies);
	return dm_register_target(&hsm_target);
}

static void dm_hsm_exit(void)
{
	dm_unregister_target(&hsm_target);
	kmem_cache_destroy(block_cache);
}

/* Module hooks */
module_init(dm_hsm_init);
module_exit(dm_hsm_exit);

MODULE_DESCRIPTION(DM_NAME "device-mapper hierachical storage target");
MODULE_AUTHOR("Heinz Mauelshagen <heinzm@redhat.com>");
MODULE_LICENSE("GPL");

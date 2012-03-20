/*
 * Copyright (C) 2011 Red Hat GmbH. All rights reserved.
 *
 * This file is released under the GPL.
 *
 * Hierarchical Storage Management target.
 *
 * Features:
 * o manages a storage pool of blocks on a fast block device to
 *   allocate from in order to cache blocks of a slower cached device
 * o data block size selectable (2^^N)
 * o - status <chunks free> <chunks used>
 *   - userland to kernel message just be a single resume (no prior suspend)
 *   - status provide metadata stats, userland resizes via same
 *     mechanism as data extend
 *
 * FIXME:
 * o support DISCARD requests to free unused blocks
 * o support relocation of blocks to allow for hot spot removal
 *   and shrinking of the data device.
 * o writethrough
 * o eventually drop metadata store creation once userspace does it
 *
 */

const char version[] = "1.0.69";

#include "dm.h"
#include "dm-bio-prison.h"
#include "hsm-metadata.h"
#include "persistent-data/dm-transaction-manager.h"

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

#define BLOCK_SIZE_MIN 64
#define DM_MSG_PREFIX "cache"
#define DAEMON "cached"

struct cache_c;

struct migration {
	struct list_head list;
	int to_cache;
	dm_block_t origin_block;
	dm_block_t cache_block;
	struct cell *cell;
	int err;
	struct cache_c *cache;
};

struct policy {
	void (*destructor)(struct policy *p);
	void (*notify)(struct policy *p, struct bio *bio);

	/*
	 * This should return -ENODATA if there is no currently suggested
	 * migration.
	 */
	int (*suggest_migration)(struct policy *p, struct migration *result);
};

struct cache_c {
	struct dm_target *ti;
	struct cache_metadata *hmd;

	struct dm_dev *origin_dev;
	struct dm_dev *cache_dev;
	struct dm_dev *metadata_dev;

	sector_t origin_size;
	sector_t sectors_per_block;
	sector_t offset_mask;
	unsigned int block_shift;

	spinlock_t lock;
	struct bio_list deferred_bios;
	struct list_head unquiesced_migrations;
	struct list_head quiesced_migrations;
	struct list_head copied_migrations;

	struct dm_kcopyd_client *copier;
	struct deferred_set deferred_set;
	struct bio_prison prison;

	mempool_t *migration_pool;

	struct workqueue_struct *wq;
	struct work_struct worker;
};

/*----------------------------------------------------------------
 * Stochastic policy.  The simplest, and worst performing policy I can
 * think of.  If you can't write a better one than this then you're not
 * trying.
 *--------------------------------------------------------------*/
struct stochastic_policy {
	struct policy policy;

	/* every nth bio gets mapped into a random cache slot */
	spinlock_t lock;
	unsigned interval;
	unsigned n;
	int suggested_set;
	dm_block_t suggested_block;
};

static void stochastic_dtr(struct policy *p)
{
	struct stochastic_policy *sp = container_of(p, struct stochastic_policy, policy);
	kfree(sp);
}

static void stochastic_notify(struct policy *p, struct bio *bio)
{
	unsigned long flags;
	struct stochastic_policy *sp = container_of(p, struct stochastic_policy, policy);

	spin_lock_irqsave(&sp->lock, flags);
	if (sp->n++ >= sp->interval) {
		suggested_block = get_bio_block(cache, bio);
		suggested_set = 1;
		sp->n = 0;
	}
	spin_lock_irqrestore(&sp->lock, flags);
}

static int stochastic_migration(struct policy *p, struct migration *result)
{
	int r;
	unsigned long flags;
	struct stochastic_policy *sp = container_of(p, struct stochastic_policy, policy);

	spin_lock_irqsave(&sp->lock, flags);
	if (sp->suggested_block) {

		if (there_are_unused_cache_blocks(cache)) {
			result->to_cache = 1;
			result->origin_block = sp->suggested_block;
			result->cache_block = random_unused_block;

		} else if (there_are_clean_cache_blocks(cache)) {

			// demote a random cache entry

			// promote a random cache entry

		} else {

		}

		sp->suggested_set = 0;
	}
	spin_lock_irqrestore(&sp->lock, flags);

	return r;
}

static stochastic_create(unsigned interval)
{
	struct stochastic_policy *sp = kmalloc(sizeof(*sp), GFP_MALLOC);
	if (sp) {
		sp->policy.destructor = stochastic_dtr;
		sp->policy.notify = stochastic_notify;
		sp->policy.suggest_migration = stochastic_migration;
		sp->interval = interval;
	}

	return &sp->policy;
}

/*----------------------------------------------------------------
 * Tracking of in flight bios
 *--------------------------------------------------------------*/

static void track_bio(struct cache_c *cache, union map_info *info, struct bio *bio)
{
	info->ptr = ds_inc(&cache->deferred_set);
}

static int untrack_bio(struct cache_c *cache, union map_info *info, struct bio *bio)
{
	unsigned long flags;
	struct deferred_entry *de = info->ptr;
	struct list_head work;

	INIT_LIST_HEAD(&work);
	ds_dec(de, &work);

	if (!list_empty(&work)) {
		spin_lock_irqsave(&cache->lock, flags);
		list_splice(&work, &cache->quiesced_migrations);
		spin_unlock_irqrestore(&cache->lock, flags);
	}

	return 0;
}

/*----------------------------------------------------------------
 * Migration processing
 *--------------------------------------------------------------*/

static void process_unquiesced_migrations(struct cache_c *cache)
{
	unsigned long flags;
	struct migration *m, *tmp;
	struct list_head head;
	struct cell_key key;
	struct cell *cell;

	INIT_LIST_HEAD(&head);
	spin_lock_irqsave(&cache->lock, flags);
	list_splice_init(&cache->unquiesced_migrations, &head);
	spin_unlock_irqrestore(&cache->lock, flags);

	list_for_each_entry_safe (m, tmp, &head, list) {
		list_del(&m->list);

		/*
		 * We must create a cell here to prevent further io
		 * to this block.
		 */
		build_key(m->origin_block, &key);
		bio_detain(&cache->prison, &key, NULL, &cell);
		m->cell = cell;
		if (!ds_add_work(&cache->deferred_set, &m->list))
			list_add(&m->list, &cache->quiesced_migrations);
	}
}

static void copy_complete(int read_err, unsigned long write_err, void *context)
{
	unsigned long flags;
	struct migration *m = (struct migration *) context;

	m->err = read_err || write_err ? -EIO : 0;

	spin_lock_irqsave(&m->cache->lock, flags);
	list_add(&m->list, &m->cache->copied_migrations);
	spin_unlock_irqrestore(&m->cache->lock, flags);

	queue_work(m->cache->wq, &m->cache->worker);
}

static void process_quiesced_migrations(struct cache_c *cache)
{
	int r;
	unsigned long flags;
	struct migration *m, *tmp;
	struct list_head head;

	INIT_LIST_HEAD(&head);
	spin_lock_irqsave(&cache->lock, flags);
	list_splice_init(&cache->quiesced_migrations, &head);
	spin_unlock_irqrestore(&cache->lock, flags);

	list_for_each_entry_safe (m, tmp, &head, list) {
		struct dm_io_region origin, cache;

		origin.bdev = cache->origin_dev->bdev;
		origin.sector = m->origin_block * cache->sectors_per_block;
		origin.count = cache->sectors_per_block;

		cache.bdev = cache->cache_dev->bdev;
		cache.sector = m->cache_block * cache->sectors_per_block;
		cache.sector = cache->sectors_per_block;

		r = dm_kcopyd_copy(cache->copier,
				   m->to_cache ? &origin : &cache,
				   1,
				   m->to_cache ? &cache : &origin,
				   0, copy_complete, m);
		if (r < 0) {
			mempool_free(m, cache->migration_pool);
			printk(KERN_ALERT "dm_kcopyd_copy() failed");
		}
	}
}

static void process_copied_migrations(struct cache_c *cache)
{
	int r;
	unsigned long flags;
	struct migration *m, *tmp;
	struct list_head head;
	struct bio_list bios;
	struct bio *bio;

	INIT_LIST_HEAD(&head);
	spin_lock_irqsave(&cache->lock, flags);
	list_splice_init(&cache->copied_migrations, &head);
	spin_unlock_irqrestore(&cache->lock, flags);

	/* update the metadata */
	list_for_each_entry_safe (m, tmp, &head, list) {
		if (!m->err) {
			if (m->to_cache) {
				r = cache_metadata_insert(cache->hmd, m->origin_block, m->cache_block);
			} else
				r = cache_metadata_remove(cache->hmd, m->origin_block);
		}

		/*
		 * Even if there was an error we can release the bios from
		 * the cell and let them proceed using the old location.
		 */
		bio_list_init(&bios);
		cell_release(m->cell, &bios);
		spin_lock_irqsave(&cache->lock, flags);
		while ((bio = bio_list_pop(&bios)))
			bio_list_add(&cache->deferred_bios, bio);
		spin_unlock_irqrestore(&cache->lock, flags);

		mempool_free(m, cache->migration_pool);
	}
}

/*----------------------------------------------------------------
 * bio processing
 *--------------------------------------------------------------*/

static void build_key(dm_block_t block, struct cell_key *key)
{
	key->virtual = 0;
	key->dev = 0;
	key->block = block;
}

static void defer_bio(struct cache_c *cache, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_add(&cache->deferred_bios, bio);
	spin_unlock_irqrestore(&cache->lock, flags);
}

static void remap_to_origin(struct cache_c *cache, struct bio *bio)
{
	bio->bi_bdev = cache->origin_dev->bdev;
}

static void remap_to_cache(struct cache_c *cache, struct bio *bio, dm_block_t cache_block)
{
	bio->bi_bdev = cache->cache_dev->bdev;
	bio->bi_sector = (cache_block << cache->block_shift) +
		(bio->bi_sector & cache->offset_mask);
}

static dm_block_t get_bio_block(struct cache_c *cache, struct bio *bio)
{
	return bio->bi_sector >> cache->block_shift;
}

static void issue(struct cache_c *cache, struct bio *bio)
{
	if (bio->bi_rw & (REQ_FLUSH | REQ_FUA)) {
		int r = cache_metadata_commit(cache->hmd);
		if (r) {
			printk(KERN_ALERT "cache metadata commit failed");
			bio_io_error(bio);
			return;
		}
	}

	generic_make_request(bio);
}

static int map_bio(struct cache_c *cache, struct bio *bio)
{
	int r;
	dm_block_t block = get_bio_block(cache, bio), cache_block;
	struct cell_key key;
	struct cell *cell;

	/*
	 * Check to see if that block is currently migrating.
	 */
	build_key(block, &key);
	r = bio_detain_if_occupied(&cache->prison, &key, bio, &cell);
	if (r > 0)
		r = DM_MAPIO_SUBMITTED;

	else if (r == 0) {
		r = cache_metadata_lookup(cache->hmd, block, 0, &cache_block);
		switch (r) {
		case 0:
			if (bio_data_dir(bio) == WRITE) {
				r = cache_metadata_mark_dirty(cache->hmd, block);
				if (r) {
					printk(KERN_ALERT "cache_metadata_mark_dirty() failed");
				} else {
					remap_to_cache(cache, bio, cache_block);
					r = DM_MAPIO_REMAPPED;
				}
			} else {
				remap_to_cache(cache, bio, cache_block);
				r = DM_MAPIO_REMAPPED;
			}
			break;

		case -ENODATA:
			remap_to_origin(cache, bio);
			r = DM_MAPIO_REMAPPED;
			break;

		default:
			break;
		}
	}

	return r;
}

static void process_discard(struct cache_c *cache, struct bio *bio)
{
	/* FIXME: finish */
	bio_endio(bio, 0);
}

static void process_bio(struct cache_c *cache, struct bio *bio)
{
	int r = map_bio(cache, bio);
	switch (r) {
	case DM_MAPIO_REMAPPED:
		issue(cache, bio);
		break;

	case DM_MAPIO_SUBMITTED:
		break;

	default:
		bio_io_error(bio);
		break;
	}
}

static void process_bios(struct cache_c *cache)
{
	unsigned long flags;
	struct bio_list bios;
	struct bio *bio;

	bio_list_init(&bios);

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_merge(&bios, &cache->deferred_bios);
	bio_list_init(&cache->deferred_bios);
	spin_unlock_irqrestore(&cache->lock, flags);

	while ((bio = bio_list_pop(&bios))) {
		if (bio->bi_rw & REQ_DISCARD)
			process_discard(cache, bio);
		else
			process_bio(cache, bio);
	}
}

/*----------------------------------------------------------------
 * Main worker loop
 *--------------------------------------------------------------*/
static int more_work(struct cache_c *cache)
{
	return !bio_list_empty(&cache->deferred_bios) ||
		!list_empty(&cache->unquiesced_migrations) ||
		!list_empty(&cache->quiesced_migrations) ||
		!list_empty(&cache->copied_migrations);
}

static void do_work(struct work_struct *ws)
{
	struct cache_c *cache = container_of(ws, struct cache_c, worker);

	do {
		process_bios(cache);
		process_unquiesced_migrations(cache);
		process_quiesced_migrations(cache);
		process_copied_migrations(cache);

	} while (more_work(cache));
}

/*----------------------------------------------------------------*/

static int is_congested(struct dm_dev *dev, int bdi_bits)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);
	return bdi_congested(&q->backing_dev_info, bdi_bits);
}

static int congested(void *congested_data, int bdi_bits)
{
	struct cache_c *cache = congested_data;

	return is_congested(cache->origin_dev, bdi_bits) ||
		is_congested(cache->cache_dev, bdi_bits) ||
		is_congested(cache->metadata_dev, bdi_bits); /* FIXME: we don't know that there is a metadata dev */
}

static void set_congestion_fn(struct cache_c *cache)
{
	struct mapped_device *md = dm_table_get_md(cache->ti->table);
	struct backing_dev_info *bdi = &dm_disk(md)->queue->backing_dev_info;

	/* Set congested function and data. */
	bdi->congested_fn = congested;
	bdi->congested_data = cache;
}

/*----------------------------------------------------------------
 * Target methods
 *--------------------------------------------------------------*/

static void cache_dtr(struct dm_target *ti)
{
	struct cache_c *cache = ti->private;

	prison_destroy(&cache->prison);
	dm_kcopyd_client_destroy(cache->copier);
	dm_put_device(ti, cache->origin_dev);
	dm_put_device(ti, cache->cache_dev);
	dm_put_device(ti, cache->metadata_dev);
	cache_metadata_close(cache->hmd);
	destroy_workqueue(cache->wq);

	kfree(cache);
}

static int get_device_(struct dm_target *ti, char *arg, struct dm_dev **dev,
		 char *errstr)
{
	int r = dm_get_device(ti, arg, FMODE_READ | FMODE_WRITE, dev);
	if (r)
		ti->error = errstr;

	return r;
}

static sector_t get_dev_size(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

/*
 * Construct a hierarchical storage device mapping:
 *
 * hsm <origin dev>
 *     <data dev>
 *     <meta dev>
 *     <data block size>
 *
 * origin dev	   : slow device holding original data blocks
 * data dev	   : fast device holding cached data blocks
 * meta dev	   : fast device keeping track of provisioned cached blocks
 * data block size : cache unit size in sectors
 */
static int cache_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	sector_t block_size;
	struct cache_c *cache;
	char *end;

	if (argc != 4) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	block_size = simple_strtoul(argv[3], &end, 10);
	if (block_size < BLOCK_SIZE_MIN ||
	    !is_power_of_2(block_size) || *end) {
		ti->error = "Invalid data block size argument";
		return -EINVAL;
	}

	cache = ti->private = kzalloc(sizeof(*cache), GFP_KERNEL);
	if (!cache) {
		ti->error = "Error allocating cache context";
		return -ENOMEM;
	}

	cache->ti = ti;
	cache->sectors_per_block = block_size;
	cache->block_shift = ffs(block_size) - 1;

	spin_lock_init(&cache->lock);
	bio_list_init(&cache->deferred_bios);

	if (get_device_(cache->ti, argv[0], &cache->origin_dev,
			"Error opening origin device"))
		goto bad5;

	if (get_device_(cache->ti, argv[1], &cache->cache_dev,
			"Error opening data device"))
		goto bad4;

	if (get_device_(cache->ti, argv[2], &cache->metadata_dev,
			"Error opening metadata device"))
		goto bad3;

	cache->copier = dm_kcopyd_client_create();
	if (IS_ERR(cache->copier)) {
		ti->error = "Couldn't create kcopyd client";
		goto bad2;
	}

	cache->origin_size = get_dev_size(cache->origin_dev);
	if (ti->len > cache->origin_size) {
		ti->error = "Device size larger than cached device";
		goto bad1;
	}

	cache->wq = alloc_ordered_workqueue(DAEMON, WQ_MEM_RECLAIM);
	if (!cache->wq) {
		printk(KERN_ALERT "couldn't create workqueue for metadata object");
		goto bad1;
	}

	INIT_WORK(&cache->worker, do_work);
	ti->split_io = cache->sectors_per_block;
	ti->num_flush_requests = 1;
	ti->num_discard_requests = 1;
	set_congestion_fn(cache);

	/* Set masks/shift for fast bio -> block mapping. */
	cache->offset_mask = ti->split_io - 1;
	smp_wmb();
	return 0;

bad1:
	dm_kcopyd_client_destroy(cache->copier);
bad2:
	dm_put_device(ti, cache->metadata_dev);
bad3:
	dm_put_device(ti, cache->cache_dev);
bad4:
	dm_put_device(ti, cache->origin_dev);
bad5:
	kfree(cache);
	return -EINVAL;
}

static int cache_map(struct dm_target *ti, struct bio *bio,
		   union map_info *map_context)
{
	int r;
	struct cache_c *cache = ti->private;

	track_bio(cache, map_context, bio);

	/* These may block, so we defer */
	if (bio->bi_rw & (REQ_DISCARD | REQ_FLUSH | REQ_FUA)) {
		defer_bio(cache, bio);
		return DM_MAPIO_SUBMITTED;
	}

	r = map_bio(cache, bio);
	switch (r) {
	case DM_MAPIO_SUBMITTED:
	case DM_MAPIO_REMAPPED:
		break;

	case -EWOULDBLOCK:
		defer_bio(cache, bio);
		r = DM_MAPIO_SUBMITTED;
		break;

	default:
		bio_io_error(bio);
		r = DM_MAPIO_SUBMITTED;
		break;
	}

	return r;
}

static int cache_end_io(struct dm_target *ti, struct bio *bio,
		      int error, union map_info *map_context)
{
	struct cache_c *cache = ti->private;
	return untrack_bio(cache, map_context, bio);
}

static int cache_status(struct dm_target *ti, status_type_t type,
		      char *result, unsigned maxlen)
{
	ssize_t sz = 0;
	char buf[BDEVNAME_SIZE];
	struct cache_c *cache = ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		/*   <hits> <misses> */
		DMEMIT("%llu %llu", 0LL, 0LL);
		break;

	case STATUSTYPE_TABLE:
		format_dev_t(buf, cache->origin_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
		format_dev_t(buf, cache->cache_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
		format_dev_t(buf, cache->metadata_dev->bdev->bd_dev);
		DMEMIT("%s %llu", buf, (long long unsigned) cache->sectors_per_block);
	}

	return 0;
}

static int cache_iterate_devices(struct dm_target *ti,
			       iterate_devices_callout_fn fn, void *data)
{
	struct cache_c *cache = ti->private;

	return fn(ti, cache->origin_dev, 0, ti->len, data) ||
		fn(ti, cache->cache_dev, 0, cache->origin_size, data);
}

static int cache_bvec_merge(struct dm_target *ti,
			  struct bvec_merge_data *bvm,
			  struct bio_vec *biovec, int max_size)
{
	struct cache_c *cache = ti->private;
	struct request_queue *q = bdev_get_queue(cache->origin_dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = cache->origin_dev->bdev;
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static void cache_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct cache_c *cache = ti->private;

	blk_limits_io_min(limits, 0);
	blk_limits_io_opt(limits, cache->sectors_per_block << SECTOR_SHIFT);
}

/*----------------------------------------------------------------*/

static struct target_type cache_target = {
	.name = "cache",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = cache_ctr,
	.dtr = cache_dtr,
	.map = cache_map,
	.end_io = cache_end_io,
	.status = cache_status,
	.iterate_devices = cache_iterate_devices,
	.merge = cache_bvec_merge,
	.io_hints = cache_io_hints,
};

int __init dm_cache_init(void)
{
	int r;

	r = dm_register_target(&cache_target);
	if (r) {
		DMERR("Failed to register %s %s", DM_MSG_PREFIX, version);
	} else
		DMINFO("Registered %s %s", DM_MSG_PREFIX, version);

	return r;
}

void dm_cache_exit(void)
{
	dm_unregister_target(&cache_target);
}

/* Module hooks */
module_init(dm_cache_init);
module_exit(dm_cache_exit);

MODULE_DESCRIPTION(DM_NAME "device-mapper cache target");
MODULE_AUTHOR("Joe Thornber <ejt@redhat.com>");
MODULE_LICENSE("GPL");

/*----------------------------------------------------------------*/

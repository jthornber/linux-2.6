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
#define DM_MSG_PREFIX "hsm"
#define DAEMON "hsmd"

struct hsm_c;

struct migration {
	struct list_head list;
	int to_cache;
	dm_block_t origin_block;
	dm_block_t cache_block;
	struct cell *cell;
	int err;
	struct hsm_c *hsm;
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

struct hsm_c {
	struct dm_target *ti;
	struct hsm_metadata *hmd;

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
		suggested_block = get_bio_block(hsm, bio);
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

		if (there_are_unused_cache_blocks(hsm)) {
			result->to_cache = 1;
			result->origin_block = sp->suggested_block;
			result->cache_block = random_unused_block;

		} else if (there_are_clean_cache_blocks(hsm)) {

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

static void track_bio(struct hsm_c *hsm, union map_info *info, struct bio *bio)
{
	info->ptr = ds_inc(&hsm->deferred_set);
}

static int untrack_bio(struct hsm_c *hsm, union map_info *info, struct bio *bio)
{
	unsigned long flags;
	struct deferred_entry *de = info->ptr;
	struct list_head work;

	INIT_LIST_HEAD(&work);
	ds_dec(de, &work);

	if (!list_empty(&work)) {
		spin_lock_irqsave(&hsm->lock, flags);
		list_splice(&work, &hsm->quiesced_migrations);
		spin_unlock_irqrestore(&hsm->lock, flags);
	}

	return 0;
}

/*----------------------------------------------------------------
 * Migration processing
 *--------------------------------------------------------------*/

static void process_unquiesced_migrations(struct hsm_c *hsm)
{
	unsigned long flags;
	struct migration *m, *tmp;
	struct list_head head;
	struct cell_key key;
	struct cell *cell;

	INIT_LIST_HEAD(&head);
	spin_lock_irqsave(&hsm->lock, flags);
	list_splice_init(&hsm->unquiesced_migrations, &head);
	spin_unlock_irqrestore(&hsm->lock, flags);

	list_for_each_entry_safe (m, tmp, &head, list) {
		list_del(&m->list);

		/*
		 * We must create a cell here to prevent further io
		 * to this block.
		 */
		build_key(m->origin_block, &key);
		bio_detain(&hsm->prison, &key, NULL, &cell);
		m->cell = cell;
		if (!ds_add_work(&hsm->deferred_set, &m->list))
			list_add(&m->list, &hsm->quiesced_migrations);
	}
}

static void copy_complete(int read_err, unsigned long write_err, void *context)
{
	unsigned long flags;
	struct migration *m = (struct migration *) context;

	m->err = read_err || write_err ? -EIO : 0;

	spin_lock_irqsave(&m->hsm->lock, flags);
	list_add(&m->list, &m->hsm->copied_migrations);
	spin_unlock_irqrestore(&m->hsm->lock, flags);

	queue_work(m->hsm->wq, &m->hsm->worker);
}

static void process_quiesced_migrations(struct hsm_c *hsm)
{
	int r;
	unsigned long flags;
	struct migration *m, *tmp;
	struct list_head head;

	INIT_LIST_HEAD(&head);
	spin_lock_irqsave(&hsm->lock, flags);
	list_splice_init(&hsm->quiesced_migrations, &head);
	spin_unlock_irqrestore(&hsm->lock, flags);

	list_for_each_entry_safe (m, tmp, &head, list) {
		struct dm_io_region origin, cache;

		origin.bdev = hsm->origin_dev->bdev;
		origin.sector = m->origin_block * hsm->sectors_per_block;
		origin.count = hsm->sectors_per_block;

		cache.bdev = hsm->cache_dev->bdev;
		cache.sector = m->cache_block * hsm->sectors_per_block;
		cache.sector = hsm->sectors_per_block;

		r = dm_kcopyd_copy(hsm->copier,
				   m->to_cache ? &origin : &cache,
				   1,
				   m->to_cache ? &cache : &origin,
				   0, copy_complete, m);
		if (r < 0) {
			mempool_free(m, hsm->migration_pool);
			printk(KERN_ALERT "dm_kcopyd_copy() failed");
		}
	}
}

static void process_copied_migrations(struct hsm_c *hsm)
{
	int r;
	unsigned long flags;
	struct migration *m, *tmp;
	struct list_head head;
	struct bio_list bios;
	struct bio *bio;

	INIT_LIST_HEAD(&head);
	spin_lock_irqsave(&hsm->lock, flags);
	list_splice_init(&hsm->copied_migrations, &head);
	spin_unlock_irqrestore(&hsm->lock, flags);

	/* update the metadata */
	list_for_each_entry_safe (m, tmp, &head, list) {
		if (!m->err) {
			if (m->to_cache) {
				r = hsm_metadata_insert(hsm->hmd, m->origin_block, m->cache_block);
			} else
				r = hsm_metadata_remove(hsm->hmd, m->origin_block);
		}

		/*
		 * Even if there was an error we can release the bios from
		 * the cell and let them proceed using the old location.
		 */
		bio_list_init(&bios);
		cell_release(m->cell, &bios);
		spin_lock_irqsave(&hsm->lock, flags);
		while ((bio = bio_list_pop(&bios)))
			bio_list_add(&hsm->deferred_bios, bio);
		spin_unlock_irqrestore(&hsm->lock, flags);

		mempool_free(m, hsm->migration_pool);
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

static void defer_bio(struct hsm_c *hsm, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&hsm->lock, flags);
	bio_list_add(&hsm->deferred_bios, bio);
	spin_unlock_irqrestore(&hsm->lock, flags);
}

static void remap_to_origin(struct hsm_c *hsm, struct bio *bio)
{
	bio->bi_bdev = hsm->origin_dev->bdev;
}

static void remap_to_cache(struct hsm_c *hsm, struct bio *bio, dm_block_t cache_block)
{
	bio->bi_bdev = hsm->cache_dev->bdev;
	bio->bi_sector = (cache_block << hsm->block_shift) +
		(bio->bi_sector & hsm->offset_mask);
}

static dm_block_t get_bio_block(struct hsm_c *hsm, struct bio *bio)
{
	return bio->bi_sector >> hsm->block_shift;
}

static void issue(struct hsm_c *hsm, struct bio *bio)
{
	if (bio->bi_rw & (REQ_FLUSH | REQ_FUA)) {
		int r = hsm_metadata_commit(hsm->hmd);
		if (r) {
			printk(KERN_ALERT "hsm metadata commit failed");
			bio_io_error(bio);
			return;
		}
	}

	generic_make_request(bio);
}

static int map_bio(struct hsm_c *hsm, struct bio *bio)
{
	int r;
	dm_block_t block = get_bio_block(hsm, bio), cache_block;
	struct cell_key key;
	struct cell *cell;

	/*
	 * Check to see if that block is currently migrating.
	 */
	build_key(block, &key);
	r = bio_detain_if_occupied(&hsm->prison, &key, bio, &cell);
	if (r > 0)
		r = DM_MAPIO_SUBMITTED;

	else if (r == 0) {
		r = hsm_metadata_lookup(hsm->hmd, block, 0, &cache_block);
		switch (r) {
		case 0:
			if (bio_data_dir(bio) == WRITE) {
				r = hsm_metadata_mark_dirty(hsm->hmd, block);
				if (r) {
					printk(KERN_ALERT "hsm_metadata_mark_dirty() failed");
				} else {
					remap_to_cache(hsm, bio, cache_block);
					r = DM_MAPIO_REMAPPED;
				}
			} else {
				remap_to_cache(hsm, bio, cache_block);
				r = DM_MAPIO_REMAPPED;
			}
			break;

		case -ENODATA:
			remap_to_origin(hsm, bio);
			r = DM_MAPIO_REMAPPED;
			break;

		default:
			break;
		}
	}

	return r;
}

static void process_discard(struct hsm_c *hsm, struct bio *bio)
{
	/* FIXME: finish */
	bio_endio(bio, 0);
}

static void process_bio(struct hsm_c *hsm, struct bio *bio)
{
	int r = map_bio(hsm, bio);
	switch (r) {
	case DM_MAPIO_REMAPPED:
		issue(hsm, bio);
		break;

	case DM_MAPIO_SUBMITTED:
		break;

	default:
		bio_io_error(bio);
		break;
	}
}

static void process_bios(struct hsm_c *hsm)
{
	unsigned long flags;
	struct bio_list bios;
	struct bio *bio;

	bio_list_init(&bios);

	spin_lock_irqsave(&hsm->lock, flags);
	bio_list_merge(&bios, &hsm->deferred_bios);
	bio_list_init(&hsm->deferred_bios);
	spin_unlock_irqrestore(&hsm->lock, flags);

	while ((bio = bio_list_pop(&bios))) {
		if (bio->bi_rw & REQ_DISCARD)
			process_discard(hsm, bio);
		else
			process_bio(hsm, bio);
	}
}

/*----------------------------------------------------------------
 * Main worker loop
 *--------------------------------------------------------------*/
static int more_work(struct hsm_c *hsm)
{
	return !bio_list_empty(&hsm->deferred_bios) ||
		!list_empty(&hsm->unquiesced_migrations) ||
		!list_empty(&hsm->quiesced_migrations) ||
		!list_empty(&hsm->copied_migrations);
}

static void do_work(struct work_struct *ws)
{
	struct hsm_c *hsm = container_of(ws, struct hsm_c, worker);

	do {
		process_bios(hsm);
		process_unquiesced_migrations(hsm);
		process_quiesced_migrations(hsm);
		process_copied_migrations(hsm);

	} while (more_work(hsm));
}

/*----------------------------------------------------------------*/

static int is_congested(struct dm_dev *dev, int bdi_bits)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);
	return bdi_congested(&q->backing_dev_info, bdi_bits);
}

static int congested(void *congested_data, int bdi_bits)
{
	struct hsm_c *hsm = congested_data;

	return is_congested(hsm->origin_dev, bdi_bits) ||
		is_congested(hsm->cache_dev, bdi_bits) ||
		is_congested(hsm->metadata_dev, bdi_bits);
}

static void set_congestion_fn(struct hsm_c *hsm)
{
	struct mapped_device *md = dm_table_get_md(hsm->ti->table);
	struct backing_dev_info *bdi = &dm_disk(md)->queue->backing_dev_info;

	/* Set congested function and data. */
	bdi->congested_fn = congested;
	bdi->congested_data = hsm;
}

/*----------------------------------------------------------------
 * Target methods
 *--------------------------------------------------------------*/

static void hsm_dtr(struct dm_target *ti)
{
	struct hsm_c *hsm = ti->private;

	prison_destroy(&hsm->prison);
	dm_kcopyd_client_destroy(hsm->copier);
	dm_put_device(ti, hsm->origin_dev);
	dm_put_device(ti, hsm->cache_dev);
	dm_put_device(ti, hsm->metadata_dev);
	hsm_metadata_close(hsm->hmd);
	destroy_workqueue(hsm->wq);

	kfree(hsm);
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
static int hsm_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	sector_t block_size;
	struct hsm_c *hsm;
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

	hsm = ti->private = kzalloc(sizeof(*hsm), GFP_KERNEL);
	if (!hsm) {
		ti->error = "Error allocating hsm context";
		return -ENOMEM;
	}

	hsm->ti = ti;
	hsm->sectors_per_block = block_size;
	hsm->block_shift = ffs(block_size) - 1;

	spin_lock_init(&hsm->lock);
	bio_list_init(&hsm->deferred_bios);

	if (get_device_(hsm->ti, argv[0], &hsm->origin_dev,
			"Error opening origin device"))
		goto bad5;

	if (get_device_(hsm->ti, argv[1], &hsm->cache_dev,
			"Error opening data device"))
		goto bad4;

	if (get_device_(hsm->ti, argv[2], &hsm->metadata_dev,
			"Error opening metadata device"))
		goto bad3;

	hsm->copier = dm_kcopyd_client_create();
	if (IS_ERR(hsm->copier)) {
		ti->error = "Couldn't create kcopyd client";
		goto bad2;
	}

	hsm->origin_size = get_dev_size(hsm->origin_dev);
	if (ti->len > hsm->origin_size) {
		ti->error = "Device size larger than cached device";
		goto bad1;
	}

	hsm->wq = alloc_ordered_workqueue(DAEMON, WQ_MEM_RECLAIM);
	if (!hsm->wq) {
		printk(KERN_ALERT "couldn't create workqueue for metadata object");
		goto bad1;
	}

	INIT_WORK(&hsm->worker, do_work);
	ti->split_io = hsm->sectors_per_block;
	ti->num_flush_requests = 1;
	ti->num_discard_requests = 1;
	set_congestion_fn(hsm);

	/* Set masks/shift for fast bio -> block mapping. */
	hsm->offset_mask = ti->split_io - 1;
	smp_wmb();
	return 0;

bad1:
	dm_kcopyd_client_destroy(hsm->copier);
bad2:
	dm_put_device(ti, hsm->metadata_dev);
bad3:
	dm_put_device(ti, hsm->cache_dev);
bad4:
	dm_put_device(ti, hsm->origin_dev);
bad5:
	kfree(hsm);
	return -EINVAL;
}

static int hsm_map(struct dm_target *ti, struct bio *bio,
		   union map_info *map_context)
{
	int r;
	struct hsm_c *hsm = ti->private;

	track_bio(hsm, map_context, bio);

	/* These may block, so we defer */
	if (bio->bi_rw & (REQ_DISCARD | REQ_FLUSH | REQ_FUA)) {
		defer_bio(hsm, bio);
		return DM_MAPIO_SUBMITTED;
	}

	r = map_bio(hsm, bio);
	switch (r) {
	case DM_MAPIO_SUBMITTED:
	case DM_MAPIO_REMAPPED:
		break;

	case -EWOULDBLOCK:
		defer_bio(hsm, bio);
		r = DM_MAPIO_SUBMITTED;
		break;

	default:
		bio_io_error(bio);
		r = DM_MAPIO_SUBMITTED;
		break;
	}

	return r;
}

static int hsm_end_io(struct dm_target *ti, struct bio *bio,
		      int error, union map_info *map_context)
{
	struct hsm_c *hsm = ti->private;
	return untrack_bio(hsm, map_context, bio);
}

static int hsm_status(struct dm_target *ti, status_type_t type,
		      char *result, unsigned maxlen)
{
	ssize_t sz = 0;
	char buf[BDEVNAME_SIZE];
	struct hsm_c *hsm = ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		/*   <hits> <misses> */
		DMEMIT("%llu %llu", 0LL, 0LL);
		break;

	case STATUSTYPE_TABLE:
		format_dev_t(buf, hsm->origin_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
		format_dev_t(buf, hsm->cache_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
		format_dev_t(buf, hsm->metadata_dev->bdev->bd_dev);
		DMEMIT("%s %llu", buf, (long long unsigned) hsm->sectors_per_block);
	}

	return 0;
}

static int hsm_iterate_devices(struct dm_target *ti,
			       iterate_devices_callout_fn fn, void *data)
{
	struct hsm_c *hsm = ti->private;

	return fn(ti, hsm->origin_dev, 0, ti->len, data) ||
		fn(ti, hsm->cache_dev, 0, hsm->origin_size, data);
}

static int hsm_bvec_merge(struct dm_target *ti,
			  struct bvec_merge_data *bvm,
			  struct bio_vec *biovec, int max_size)
{
	struct hsm_c *hsm = ti->private;
	struct request_queue *q = bdev_get_queue(hsm->origin_dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = hsm->origin_dev->bdev;
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static void hsm_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct hsm_c *hsm = ti->private;

	blk_limits_io_min(limits, 0);
	blk_limits_io_opt(limits, hsm->sectors_per_block << SECTOR_SHIFT);
}

/*----------------------------------------------------------------*/

static struct target_type hsm_target = {
	.name = "hsm",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = hsm_ctr,
	.dtr = hsm_dtr,
	.map = hsm_map,
	.end_io = hsm_end_io,
	.status = hsm_status,
	.iterate_devices = hsm_iterate_devices,
	.merge = hsm_bvec_merge,
	.io_hints = hsm_io_hints,
};

int __init dm_hsm_init(void)
{
	int r;

	r = dm_register_target(&hsm_target);
	if (r) {
		DMERR("Failed to register %s %s", DM_MSG_PREFIX, version);
	} else
		DMINFO("Registered %s %s", DM_MSG_PREFIX, version);

	return r;
}

void dm_hsm_exit(void)
{
	dm_unregister_target(&hsm_target);
}

/* Module hooks */
module_init(dm_hsm_init);
module_exit(dm_hsm_exit);

MODULE_DESCRIPTION(DM_NAME "device-mapper hierachical storage target");
MODULE_AUTHOR("Heinz Mauelshagen <heinzm@redhat.com>");
MODULE_LICENSE("GPL");

/*----------------------------------------------------------------*/

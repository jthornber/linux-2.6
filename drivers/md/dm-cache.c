/*
 * Copyright (C) 2012 Red Hat GmbH. All rights reserved.
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

#include "dm.h"
#include "dm-bio-prison.h"
#include "dm-cache-metadata.h"

#include <asm/div64.h>

#include <linux/blkdev.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/rbtree.h>
#include <linux/slab.h>

/* FIXME: describe, mechanism/controller/metadata split */

/* FIXME: I think all the md_ functions will eventually be able to block,
 * once we allow for this we can drop the irq spin locking.
 */

#define debug(x...) pr_alert(x)
//#define debug(x...) ;

/*----------------------------------------------------------------*/

/* Mechanism */

#define BLOCK_SIZE_MIN 64
#define DM_MSG_PREFIX "cache"
#define DAEMON "cached"
#define PRISON_CELLS 1024
#define ENDIO_HOOK_POOL_SIZE 10240
#define MIGRATION_POOL_SIZE 128

/* FIXME: split target from mech */
struct cache_c {
	struct dm_target *ti;

	struct dm_dev *origin_dev;
	struct dm_dev *cache_dev;

	sector_t origin_size;
	sector_t sectors_per_block;
	sector_t offset_mask;
	unsigned int block_shift;

	spinlock_t lock;
	struct bio_list deferred_bios;

	/*
	 * We have a need to chain several ios, (eg, a read from the origin
	 * followed by a write to the cache).  An endio fn cannot call
	 * generic_make_request(), so we use the daemon to submit these.
	 */
	struct bio_list submit_bios;

	struct list_head quiesced_migrations;
	struct list_head copied_migrations;

	struct dm_kcopyd_client *copier;
	struct workqueue_struct *wq;
	struct work_struct worker;

	struct bio_prison *prison;
	struct deferred_set *all_io_ds;

	struct dm_cache_metadata *md;

	mempool_t *endio_hook_pool;
	mempool_t *migration_pool;

	unsigned suspending:1;

	atomic_t total;
	atomic_t read_hit;
	atomic_t read_miss;
	atomic_t read_union;
	atomic_t write_hit;
	atomic_t write_miss;
	atomic_t write_miss_partial;
	atomic_t writeback;
	atomic_t write_hit_new;

	/*
	 * Here are the fields I'm pulling out of the metadata object.
	 * They should probably go into the policy object eventually.
	 */
	struct list_head lru;
	wait_queue_head_t migrating_wq;
	atomic_t nr_migrating;
	struct list_head migrating;

};

// FIXME: this is getting far too big
struct endio_hook {
	struct list_head list;
	struct cache_c *cache;
	struct deferred_entry *all_io_entry;
	struct cell *cell;
	struct bio *dup;	/* FIXME: rename to bio */

	unsigned write_to_cache:1;
	struct mapping *m;
};

struct migration {
	struct list_head list;

	unsigned to_cache:1;
	unsigned free_mapping:1;

	struct bio *bio;
	struct mapping *m;
	uint64_t gen;
	struct cell *cell;
	int err;
	atomic_t kcopyd_jobs;

	struct cache_c *cache;

	bio_end_io_t *saved_end_io;
	void *saved_private;
};

static void build_key(dm_block_t block, struct cell_key *key)
{
	key->virtual = 0;
	key->dev = 0;
	key->block = block;
}

static void wake_worker(struct cache_c *cache)
{
	queue_work(cache->wq, &cache->worker);
}

/*----------------------------------------------------------------
 * Remapping
 *--------------------------------------------------------------*/

static void remap_to_origin(struct cache_c *cache, struct bio *bio)
{
	bio->bi_bdev = cache->origin_dev->bdev;
}

/* FIXME: the name doesn't really indicate there's a side effect */
/* FIXME: refactor these two fns */
static void __remap_to_cache(struct cache_c *cache, struct bio *bio, struct mapping *m)
{
	if (bio_data_dir(bio) == WRITE)
		cache->md->inc_cache_gen(cache->md, m);

	bio->bi_bdev = cache->cache_dev->bdev;
	bio->bi_sector = (m->cache << cache->block_shift) +
		(bio->bi_sector & cache->offset_mask);
}

static void remap_to_cache(struct cache_c *cache, struct bio *bio, struct mapping *m)
{
	struct endio_hook *h = dm_get_mapinfo(bio)->ptr;
	h->m = m;

	if (bio_data_dir(bio) == WRITE)
		cache->md->inc_cache_gen(cache->md, m);

	bio->bi_bdev = cache->cache_dev->bdev;
	bio->bi_sector = (m->cache << cache->block_shift) +
		(bio->bi_sector & cache->offset_mask);
}

static dm_block_t get_bio_block(struct cache_c *cache, struct bio *bio)
{
	return bio->bi_sector >> cache->block_shift;
}

/*----------------------------------------------------------------
 * Submitted bios
 *--------------------------------------------------------------*/
static void process_submit_bios(struct cache_c *cache)
{
	unsigned long flags;
	struct bio *bio;
	struct bio_list bios;

	bio_list_init(&bios);

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_merge(&bios, &cache->submit_bios);
	bio_list_init(&cache->submit_bios);
	spin_unlock_irqrestore(&cache->lock, flags);

	while ((bio = bio_list_pop(&bios)))
		generic_make_request(bio);
}

static void __submit_bio(struct cache_c *cache, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_add(&cache->submit_bios, bio);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}

/*----------------------------------------------------------------
 * Migration processing
 *--------------------------------------------------------------*/
static void set_migrating(struct cache_c *cache, struct mapping *m, unsigned n)
{
	unsigned long flags;

	spin_lock_irqsave(&m->lock, flags);
	list_move_tail(&m->list, n ? &cache->migrating : &cache->lru);
	spin_unlock_irqrestore(&m->lock, flags);

	if (n)
		atomic_sub(1, &cache->nr_migrating);
	else
		atomic_add(1, &cache->nr_migrating);

	wake_up(&cache->migrating_wq);
}

static void cell_defer(struct cache_c *cache, struct cell *cell, int holder)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	(holder ? cell_release : cell_release_no_holder)(cell, &cache->deferred_bios);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}

static void promote_read_endio(struct bio *bio, int err)
{
	struct migration *mg = bio->bi_private;
	struct bio *dup = mg->bio;

	debug("in promote_read_endio\n");
	bio->bi_end_io = mg->saved_end_io;
	bio->bi_private = mg->saved_private;
	mg->bio = bio;
	__submit_bio(mg->cache, dup);
}

static void promote_write_endio(struct bio *bio, int err)
{
	struct migration *mg = bio->bi_private;
	struct cache_c *cache = mg->cache;

	debug("in promote_write_endio\n");
	bio_put(bio);

	set_migrating(cache, mg->m, 0);

	cache->md->mark_valid_sectors(cache->md, mg->m, bio);
	bio_endio(mg->bio, 0);
	cell_defer(cache, mg->cell, 0);
	mempool_free(mg, cache->migration_pool);
}

static void copy_via_clone(struct cache_c *cache, struct migration *mg)
{
	struct bio *bio = mg->bio;
	struct bio *dup = bio_clone(bio, GFP_NOIO);

	BUG_ON(!bio);
	BUG_ON(!dup);

	remap_to_origin(cache, bio);
	mg->saved_end_io = bio->bi_end_io;
	mg->saved_private = bio->bi_private;
	bio->bi_end_io = promote_read_endio;
	bio->bi_private = mg;

	__remap_to_cache(cache, dup, mg->m);
	dup->bi_rw = WRITE;
	dup->bi_end_io = promote_write_endio;
	dup->bi_private = mg;
	mg->bio = dup;

	generic_make_request(bio);
}

static void copy_complete(int read_err, unsigned long write_err, void *context)
{
	unsigned long flags;
	struct migration *mg = (struct migration *) context;
	struct cache_c *cache = mg->cache;

	debug("in copy complete");

	if (!mg->err)
		mg->err = read_err || write_err ? -EIO : 0;

	if (atomic_dec_and_test(&mg->kcopyd_jobs)) {
		spin_lock_irqsave(&cache->lock, flags);
		list_add(&mg->list, &cache->copied_migrations);
		spin_unlock_irqrestore(&cache->lock, flags);

		wake_worker(cache);
	}
}

static void copy_via_kcopyd(struct cache_c *cache, struct migration *mg)
{
	int r;
	struct dm_io_region o_region, c_region;

	debug("in process_quiesced\n");
	BUG_ON(!cache);
	BUG_ON(!mg);
	BUG_ON(!mg->m);

	atomic_set(&mg->kcopyd_jobs, 0);
	o_region.bdev = cache->origin_dev->bdev;
	c_region.bdev = cache->cache_dev->bdev;

	// FIXME: refactor
	if (mg->to_cache) {
		debug("copying to cache\n");
		/*
		 * Copy the whole block.
		 */
		o_region.sector = mg->m->origin * cache->sectors_per_block;
		o_region.count = cache->sectors_per_block;

		c_region.sector = mg->m->cache * cache->sectors_per_block;
		c_region.count = cache->sectors_per_block;

		atomic_inc(&mg->kcopyd_jobs);
		r = dm_kcopyd_copy(cache->copier,
				   mg->to_cache ? &o_region : &c_region,
				   1,
				   mg->to_cache ? &c_region : &o_region,
				   0, copy_complete, mg);
	} else {
		/*
		 * copy all the valid regions in the cache.
		 */
		int submitted_something = 0;
		unsigned b = 0, e = 0;

		debug("copying to origin\n");
		while (e != cache->sectors_per_block) {
			b = e;

			while (b < cache->sectors_per_block && !test_bit(b, mg->m->valid_sectors))
				b++;

			if (b >= cache->sectors_per_block)
				break;

			e = b;

			while (e < cache->sectors_per_block && test_bit(e, mg->m->valid_sectors))
				e++;

			o_region.sector = mg->m->origin * cache->sectors_per_block + b;
			o_region.count = e - b;

			c_region.sector = mg->m->cache * cache->sectors_per_block + b;
			c_region.count = e - b;

			atomic_inc(&mg->kcopyd_jobs);

			debug("o_region.sector = %u, o_region.count = %u\n",
			      (unsigned) o_region.sector, (unsigned) o_region.count);
			debug("c_region.sector = %u, c_region.count = %u\n",
			      (unsigned) c_region.sector, (unsigned) c_region.count);

			r = dm_kcopyd_copy(cache->copier,
					   mg->to_cache ? &o_region : &c_region,
					   1,
					   mg->to_cache ? &c_region : &o_region,
					   0, copy_complete, mg);
			if (r) {
				debug("kcopyd call failed\n");
				break;
			}

			submitted_something = 1;
		}

		BUG_ON(!submitted_something);
	}

	if (r < 0) {
		if (mg->cell)
			cell_defer(cache, mg->cell, 1);
		mempool_free(mg, cache->migration_pool);
	}
}

static void process_quiesced(struct cache_c *cache, struct migration *mg)
{
	(mg->to_cache ? copy_via_clone : copy_via_kcopyd)(cache, mg);
}

static void process_copied(struct cache_c *cache, struct migration *mg)
{
	debug("in process_copied");
	set_migrating(cache, mg->m, 0);

	/* if the migration failed, we reinsert the old mapping. */
	if (!mg->err && !mg->to_cache)
		cache->md->set_origin_gen(cache->md, mg->m, mg->gen);

	/* FIXME: what's happening here? */
	if (!mg->err && mg->free_mapping)
		cache->md->remove_mapping(cache->md, mg->m);

	if (!mg->err && mg->to_cache)
		cache->md->set_valid_sectors(cache->md, mg->m);

	/*
	 * Even if there was an error we can release the bios from
	 * the cell and let them proceed using the old location.
	 */
	if (mg->cell)
		cell_defer(cache, mg->cell, 1);

	mempool_free(mg, cache->migration_pool);
}

static void process_migrations(struct cache_c *cache, struct list_head *head,
			       void (*fn)(struct cache_c *, struct migration *))
{
	unsigned long flags;
	struct list_head list;
	struct migration *mg, *tmp;

	INIT_LIST_HEAD(&list);
	spin_lock_irqsave(&cache->lock, flags);
	list_splice_init(head, &list);
	spin_unlock_irqrestore(&cache->lock, flags);

	list_for_each_entry_safe(mg, tmp, &list, list)
		fn(cache, mg);
}

// FIXME: these two are very similar
static void promote(struct cache_c *cache, struct mapping *m, struct bio *bio, struct cell *cell)
{
	struct migration *mg;

	mg = mempool_alloc(cache->migration_pool, GFP_NOIO);
	mg->to_cache = 1;
	mg->free_mapping = 0;
	mg->bio = bio;
	mg->m = m;
	mg->gen = cache->md->get_cache_gen(cache->md, m);
	mg->cell = cell;
	mg->err = 0;
	mg->cache = cache;
	if (!ds_add_work(cache->all_io_ds, &mg->list)) {
		list_add_tail(&mg->list, &cache->quiesced_migrations);
		wake_worker(cache);
	}
}

static void writeback(struct cache_c *cache, struct mapping *m, int free_mapping, struct cell *cell)
{
	struct migration *mg;

	set_migrating(cache, m, 1);
	mg = mempool_alloc(cache->migration_pool, GFP_NOIO);
	mg->to_cache = 0;
	mg->free_mapping = free_mapping;
	mg->m = m;
	mg->gen = cache->md->get_cache_gen(cache->md, m);
	mg->cell = cell;
	mg->err = 0;
	mg->cache = cache;
	if (!ds_add_work(cache->all_io_ds, &mg->list)) {
		list_add_tail(&mg->list, &cache->quiesced_migrations);
		wake_worker(cache);
	}
}

/*----------------------------------------------------------------
 * bio processing
 *--------------------------------------------------------------*/
#if 0
static int io_overlaps_block(struct cache_c *cache, struct bio *bio)
{
	return !(bio->bi_sector & cache->offset_mask) &&
		(bio->bi_size == (cache->sectors_per_block << SECTOR_SHIFT));

}
#endif
static void defer_bio(struct cache_c *cache, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_add(&cache->deferred_bios, bio);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}

static void issue(struct cache_c *cache, struct bio *bio)
{
	if (bio->bi_rw & (REQ_FLUSH | REQ_FUA)) {
#if 0
		int r = cache_metadata_commit(cache->hmd);
		if (r) {
			bio_io_error(bio);
			return;
		}
#endif
	}

	generic_make_request(bio);
}

/*----------------------------------------------------------------*/

/*
 * Controller.
 */
#define MAX_ACTIONS 4

enum action_cmd {
	REMAP_ORIGIN,
	REMAP_CACHE,
	REMAP_NEW_CACHE,
	REMAP_UNION,		/* some of the data is on the origin, some in the cache (eek!) */

	WRITEBACK,
	PROMOTE,
};

struct action {
	enum action_cmd cmd;
	struct mapping *m;
};

static void __push_action(enum action_cmd cmd, struct mapping *m,
			  struct action *actions, unsigned *count)
{
	actions[*count].cmd = cmd;
	actions[*count].m = m;
	(*count)++;
}

#define push_action(cmd, m) __push_action(cmd, m, actions, count)

/* FIXME: clean blocks should be chosen in preference? */
static struct mapping *idle_mapping(struct cache_c *cache)
{
	struct mapping *m = NULL;
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	if (!list_empty(&cache->lru))
		m = list_first_entry(&cache->lru, struct mapping, list);
	spin_unlock_irqrestore(&cache->lock, flags);

	return m;
}

/* FIXME: get rid of the cache arg */
static void get_actions(struct cache_c *cache,
			struct dm_cache_metadata *md,
			dm_block_t block,
			struct bio *bio,
			struct action *actions,
			unsigned *count)
{
	struct mapping *m;
	int is_write = bio_data_dir(bio) == WRITE;

	*count = 0;

	m = md->lookup_mapping(md, block);
	if (m) {
		list_move_tail(&m->list, &cache->lru);
		if (is_write || md->check_valid_sectors(md, m, bio))
			push_action(REMAP_CACHE, m);
		else
			push_action(REMAP_UNION, m);

	} else {
		/* FIXME: too nested, too opaque */
		if (is_write) {
			m = md->new_mapping(md);
			if (m)
				push_action(REMAP_NEW_CACHE, m);

			else {
				m = idle_mapping(cache);
				if (!m)
					push_action(REMAP_ORIGIN, NULL);

				else {
					if (md->is_clean(md, m))
						push_action(REMAP_NEW_CACHE, m);

					else {
						/* writeback this cache block so we can use it later */
						/* FIXME: how do we avoid multiple migrations? */
						push_action(WRITEBACK, m);
						push_action(REMAP_ORIGIN, NULL);
					}
				}
			}

		} else {
#if 1
			push_action(REMAP_ORIGIN, NULL);
#else
			// FIXME: duplicate code
			m = md->new_mapping(md);
			if (m)
				push_action(PROMOTE, m);
			else {
				m = idle_mapping(cache);
				if (!m)
					push_action(REMAP_ORIGIN, NULL);
				else {
					if (md->is_clean(md, m))
						push_action(PROMOTE, m);

					else {
						push_action(WRITEBACK, m);
						push_action(REMAP_ORIGIN, NULL);
					}
				}
			}
#endif
		}
	}
}

static void get_background_action(struct cache_c *cache,
				  struct dm_cache_metadata *md,
				  struct action *actions,
				  unsigned *count)
{
#if 0
	struct mapping *m;
	dm_block_t migrating_target = md->get_nr_cache_blocks(md) / 16;
#endif

	*count = 0;
#if 0
	if (atomic_read(&cache->nr_migrating) < migrating_target) {
		list_for_each_entry(m, &cache->lru, list) {
			if (!md->is_clean(md, m)) {
				push_action(WRITEBACK, m);
				return;
			}
		}
	}
#endif
}

/*----------------------------------------------------------------*/

static int map_bio(struct cache_c *cache, struct bio *bio)
{
	int r, i;
	dm_block_t block = get_bio_block(cache, bio);
	struct cell_key key;
	struct cell *cell;
	struct mapping *m;
	struct endio_hook *h = dm_get_mapinfo(bio)->ptr;
	int release_cell = 1;
	struct action actions[MAX_ACTIONS];
	unsigned count = 0;
	int is_write = bio_data_dir(bio) == WRITE;

	/* FIXME: paranoia */
	memset(actions, 0, sizeof(actions));

	/*
	 * Check to see if that block is currently migrating.
	 */
	build_key(block, &key);
	r = bio_detain(cache->prison, &key, bio, &cell);
	if (r > 0)
		return DM_MAPIO_SUBMITTED;

	get_actions(cache, cache->md, block, bio, actions, &count);
	atomic_inc(&cache->total);

	r = DM_MAPIO_REMAPPED;
	for (i = 0; i < count; i++) {
		m = actions[i].m;

		switch (actions[i].cmd) {
		case REMAP_ORIGIN:
			BUG_ON(m);
			debug("REMAP_ORIGIN\n");
			atomic_inc(is_write ? &cache->write_miss : &cache->read_miss);
			remap_to_origin(cache, bio);
			break;

		case REMAP_CACHE:
			BUG_ON(!m);
			debug("REMAP_CACHE\n");
			atomic_inc(is_write ? &cache->write_hit : &cache->read_hit);
			remap_to_cache(cache, bio, m);
			break;

		case REMAP_NEW_CACHE:
			BUG_ON(!m);
			debug("REMAP_NEW_CACHE\n");
			atomic_inc(&cache->write_hit_new);
			cache->md->remove_mapping(cache->md, m);
			m->origin = block;
			pr_alert("remapping cache(%u) -> origin(%u)\n",
				 (unsigned) m->cache,
				 (unsigned) m->origin);
			cache->md->insert_mapping(cache->md, m);
			list_move_tail(&m->list, &cache->lru);
			cache->md->clear_valid_sectors(cache->md, m);
			h->cell = cell;
			remap_to_cache(cache, bio, m);
			release_cell = 0;
			break;

		case WRITEBACK:
			BUG_ON(!m);
			debug("REMAP_WRITEBACK\n");
			atomic_inc(&cache->writeback);
			writeback(cache, m, 0, NULL);
			break;

		case PROMOTE:
#if 1
			BUG_ON(!m);
			debug("PROMOTE\n");
			cache->md->remove_mapping(cache->md, m);
			m->origin = block;
			set_migrating(cache, m, 1);
			cache->md->insert_mapping(cache->md, m);
			list_move_tail(&m->list, &cache->lru);
			promote(cache, m, bio, cell);
			release_cell = 0;
			r = DM_MAPIO_SUBMITTED;
#else
			remap_to_origin(cache, bio);
#endif

			break;

		case REMAP_UNION:
			BUG_ON(!m);
			debug("REMAP_UNION\n");
			atomic_inc(&cache->read_union);

			/* slow, but simple ... we writeback, drop the cache entry, then retry */
			writeback(cache, m, 1, cell);
			release_cell = 0;
			r = DM_MAPIO_SUBMITTED;
			break;

		default:
			BUG();
		}
		debug("done");
	}

	if (release_cell)
		cell_release_singleton(cell, bio);

	return r;
}

static void process_bio(struct cache_c *cache, struct bio *bio)
{
	struct endio_hook *h;

	switch (map_bio(cache, bio)) {
	case DM_MAPIO_REMAPPED:
		h = dm_get_mapinfo(bio)->ptr;
		h->all_io_entry = ds_inc(cache->all_io_ds);
		issue(cache, bio);
		break;

	case DM_MAPIO_SUBMITTED:
		// FIXME: all_io_entry not used?
		break;

	default:
		bio_io_error(bio);
		break;
	}
}

static void process_deferred_bios(struct cache_c *cache)
{
	unsigned long flags;
	struct bio_list bios;
	struct bio *bio;

	bio_list_init(&bios);

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_merge(&bios, &cache->deferred_bios);
	bio_list_init(&cache->deferred_bios);
	spin_unlock_irqrestore(&cache->lock, flags);

	while ((bio = bio_list_pop(&bios)))
		process_bio(cache, bio);
}

static void process_background_work(struct cache_c *cache)
{
	int i;
	struct mapping *m;
	struct action actions[MAX_ACTIONS];
	unsigned count = 0;

	/* FIXME: paranoia */
	memset(actions, 0, sizeof(actions));

	do {
		get_background_action(cache, cache->md, actions, &count);

		/* FIXME: duplicate code */
		for (i = 0; i < count; i++) {
			m = actions[i].m;

			switch (actions[i].cmd) {
			case WRITEBACK:
				BUG_ON(!m);
				debug("REMAP_WRITEBACK\n");
				atomic_inc(&cache->writeback);
				writeback(cache, m, 0, NULL);
				break;

			default:
				BUG();
			}
		}

	} while (count);
}

/*----------------------------------------------------------------
 * Main worker loop
 *--------------------------------------------------------------*/
static int more_work(struct cache_c *cache)
{
	return !bio_list_empty(&cache->deferred_bios) ||
		!bio_list_empty(&cache->submit_bios) ||
		!list_empty(&cache->quiesced_migrations) ||
		!list_empty(&cache->copied_migrations);
}

static void do_work(struct work_struct *ws)
{
	unsigned sus;
	unsigned long flags;
	struct cache_c *cache = container_of(ws, struct cache_c, worker);

	do {
		process_deferred_bios(cache);
		process_migrations(cache, &cache->quiesced_migrations, process_quiesced);
		process_migrations(cache, &cache->copied_migrations, process_copied);
		process_submit_bios(cache);

		spin_lock_irqsave(&cache->lock, flags);
		sus = cache->suspending;
		spin_unlock_irqrestore(&cache->lock, flags);

		if (!sus)
			process_background_work(cache);

	} while (more_work(cache));
}

/*----------------------------------------------------------------*/
#if 0
static int is_congested(struct dm_dev *dev, int bdi_bits)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);
	return bdi_congested(&q->backing_dev_info, bdi_bits);
}

static int congested(void *congested_data, int bdi_bits)
{
	struct cache_c *cache = congested_data;

	return is_congested(cache->origin_dev, bdi_bits) ||
		is_congested(cache->cache_dev, bdi_bits);
}

static void set_congestion_fn(struct cache_c *cache)
{
	struct mapped_device *md = dm_table_get_md(cache->ti->table);
	struct backing_dev_info *bdi = &dm_disk(md)->queue->backing_dev_info;

	/* Set congested function and data. */
	bdi->congested_fn = congested;
	bdi->congested_data = cache;
}
#endif
/*----------------------------------------------------------------
 * Target methods
 *--------------------------------------------------------------*/

static void cache_dtr(struct dm_target *ti)
{
	struct cache_c *cache = ti->private;

	pr_alert("dm-cache statistics:\n");
	pr_alert("total ios:\t%u\n", (unsigned) atomic_read(&cache->total));
	pr_alert("read hits:\t%u\n", (unsigned) atomic_read(&cache->read_hit));
	pr_alert("read misses:\t%u\n", (unsigned) atomic_read(&cache->read_miss));
	pr_alert("read union:\t%u\n", (unsigned) atomic_read(&cache->read_union));
	pr_alert("write hits:\t%u\n", (unsigned) atomic_read(&cache->write_hit));
	pr_alert("write misses:\t%u\n", (unsigned) atomic_read(&cache->write_miss));
	pr_alert("write misses due to partial block:\t%u\n", (unsigned) atomic_read(&cache->write_miss_partial));
	pr_alert("writebacks:\t%u\n", (unsigned) atomic_read(&cache->writeback));
	pr_alert("write hit new:\t%u\n", (unsigned) atomic_read(&cache->write_hit_new));

	mempool_destroy(cache->migration_pool);
	mempool_destroy(cache->endio_hook_pool);
	cache->md->destroy(cache->md);
	ds_destroy(cache->all_io_ds);
	prison_destroy(cache->prison);
	destroy_workqueue(cache->wq);
	dm_kcopyd_client_destroy(cache->copier);
	dm_put_device(ti, cache->origin_dev);
	dm_put_device(ti, cache->cache_dev);

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
 * cache <origin dev> <cache dev> <block size>
 *
 * origin dev	   : slow device holding original data blocks
 * cache dev	   : fast device holding cached data blocks
 * data block size : cache unit size in sectors
 */
static int cache_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	dm_block_t nr_cache_blocks;
	sector_t block_size;
	struct cache_c *cache;
	char *end;

	if (argc != 3) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	block_size = simple_strtoul(argv[2], &end, 10);
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

	if (get_device_(cache->ti, argv[0], &cache->origin_dev,
			"Error opening origin device"))
		goto bad1;

	if (get_device_(cache->ti, argv[1], &cache->cache_dev,
			"Error opening cache device"))
		goto bad2;

	cache->origin_size = get_dev_size(cache->origin_dev);
	if (ti->len > cache->origin_size) {
		ti->error = "Device size larger than cached device";
		goto bad3;
	}

	cache->sectors_per_block = block_size;
	cache->offset_mask = block_size - 1;
	cache->block_shift = ffs(block_size) - 1;

	spin_lock_init(&cache->lock);
	bio_list_init(&cache->deferred_bios);
	bio_list_init(&cache->submit_bios);

	INIT_LIST_HEAD(&cache->quiesced_migrations);
	INIT_LIST_HEAD(&cache->copied_migrations);

	cache->copier = dm_kcopyd_client_create();
	if (IS_ERR(cache->copier)) {
		ti->error = "Couldn't create kcopyd client";
		goto bad3;
	}

	cache->wq = alloc_ordered_workqueue(DAEMON, WQ_MEM_RECLAIM);
	if (!cache->wq) {
		ti->error = "couldn't create workqueue for metadata object";
		goto bad4;
	}
	INIT_WORK(&cache->worker, do_work);

	cache->prison = prison_create(PRISON_CELLS);
	if (!cache->prison) {
		ti->error = "couldn't create bio prison";
		goto bad5;
	}

	cache->all_io_ds = ds_create();
	if (!cache->all_io_ds) {
		ti->error = "couldn't create all_io deferred set";
		goto bad6;
	}

	nr_cache_blocks = get_dev_size(cache->cache_dev) >> cache->block_shift;
	cache->md = dm_cache_metadata_create(block_size, nr_cache_blocks);
	if (!cache->md) {
		ti->error = "couldn't create metadata";
		goto bad7;
	}

	cache->endio_hook_pool =
		mempool_create_kmalloc_pool(ENDIO_HOOK_POOL_SIZE, sizeof(struct endio_hook));
	if (!cache->endio_hook_pool) {
		ti->error = "Error creating cache's endio_hook mempool";
		goto bad8;
	}

	cache->migration_pool =
		mempool_create_kmalloc_pool(MIGRATION_POOL_SIZE, sizeof(struct migration));
	if (!cache->migration_pool) {
		ti->error = "Error creating cache's endio_hook mempool";
		goto bad9;
	}

	cache->suspending = 0;
	atomic_set(&cache->total, 0);
	atomic_set(&cache->read_hit, 0);
	atomic_set(&cache->read_miss, 0);
	atomic_set(&cache->read_union, 0);
	atomic_set(&cache->write_hit, 0);
	atomic_set(&cache->write_miss, 0);
	atomic_set(&cache->write_miss_partial, 0);
	atomic_set(&cache->writeback, 0);
	atomic_set(&cache->write_hit_new, 0);

	INIT_LIST_HEAD(&cache->lru);
	INIT_LIST_HEAD(&cache->migrating);
	init_waitqueue_head(&cache->migrating_wq);
	atomic_set(&cache->nr_migrating, 0);

	ti->split_io = cache->sectors_per_block;
	ti->num_flush_requests = 1;
	ti->num_discard_requests = 0;
	return 0;

bad9:
	mempool_destroy(cache->migration_pool);
bad8:
	cache->md->destroy(cache->md);
bad7:
	ds_destroy(cache->all_io_ds);
bad6:
	prison_destroy(cache->prison);
bad5:
	destroy_workqueue(cache->wq);
bad4:
	dm_kcopyd_client_destroy(cache->copier);
bad3:
	dm_put_device(ti, cache->cache_dev);
bad2:
	dm_put_device(ti, cache->origin_dev);
bad1:
	kfree(cache);
	return -EINVAL;
}

static int cache_map(struct dm_target *ti, struct bio *bio,
		   union map_info *map_context)
{
	struct cache_c *cache = ti->private;
	struct endio_hook *h = mempool_alloc(cache->endio_hook_pool, GFP_NOIO);

	h->cache = cache;
	h->all_io_entry = NULL;
	h->cell = NULL;
	map_context->ptr = h;

	/*
	 * Let's keep it simple to start with and defer everything.
	 */
	defer_bio(cache, bio);
	return DM_MAPIO_SUBMITTED;
}

static int cache_end_io(struct dm_target *ti, struct bio *bio,
			int error, union map_info *info)
{
	unsigned long flags;
	struct cache_c *cache = ti->private;
	struct list_head work;
	struct endio_hook *h = info->ptr;

	if (h->m && bio_data_dir(bio) == WRITE)
		cache->md->mark_valid_sectors(cache->md, h->m, bio);

	INIT_LIST_HEAD(&work);
	if (h->all_io_entry)
		ds_dec(h->all_io_entry, &work);

	if (!list_empty(&work)) {
		spin_lock_irqsave(&cache->lock, flags);
		list_splice(&work, &cache->quiesced_migrations);
		spin_unlock_irqrestore(&cache->lock, flags);
		wake_worker(cache);
	}

	if (h->cell)
		cell_defer(cache, h->cell, 0);

	mempool_free(h, cache->endio_hook_pool);
	return 0;
}

static void cache_postsuspend(struct dm_target *ti)
{
	struct cache_c *cache = ti->private;
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	cache->suspending = 1;
	spin_unlock_irqrestore(&cache->lock, flags);

	flush_workqueue(cache->wq);

	/*
	 * Wait for any background migrations to finish.
	 */
	wait_event(cache->migrating_wq, !atomic_read(&cache->nr_migrating));
}

static void cache_resume(struct dm_target *ti)
{
	struct cache_c *cache = ti->private;
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	cache->suspending = 0;
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
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
	}

	return 0;
}

static int cache_iterate_devices(struct dm_target *ti,
				 iterate_devices_callout_fn fn, void *data)
{
	struct cache_c *cache = ti->private;

	/*
	 * We don't include the cache device in the iteration since
	 * device_area_is_invalid checks that all iteratees are at least
	 * the size of the target.
	 */
	return fn(ti, cache->origin_dev, 0, ti->len, data);
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
	.postsuspend = cache_postsuspend,
	.resume = cache_resume,
	.status = cache_status,
	.iterate_devices = cache_iterate_devices,
	.merge = cache_bvec_merge,
	.io_hints = cache_io_hints,
};

static int __init dm_cache_init(void)
{
	int r;

	r = dm_register_target(&cache_target);
	if (r) {
		DMERR("Failed to register %s", DM_MSG_PREFIX);
	} else
		DMINFO("Registered %s", DM_MSG_PREFIX);

	return r;
}

static void dm_cache_exit(void)
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

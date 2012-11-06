/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "dm.h"
#include "dm-bio-prison.h"
#include "dm-cache-metadata.h"
#include "dm-cache-policy-internal.h"

#include <asm/div64.h>

#include <linux/blkdev.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/slab.h>

#define DM_MSG_PREFIX "cache"
#define DAEMON "cached"

/*----------------------------------------------------------------*/

/*
 * Glossary:
 *
 * oblock; index of an origin block
 * cblock; index of a cache block
 * migration; movement of a block between the origin and cache device, either direction
 * promotion; movement of a block from origin to cache
 * demotion; movement of a block from cache to origin
 */

/*----------------------------------------------------------------*/

static size_t bitset_size_in_bytes(unsigned nr_entries)
{
	return sizeof(unsigned long) * dm_div_up(nr_entries, BITS_PER_LONG);
}

static unsigned long *alloc_bitset(unsigned nr_entries)
{
	size_t s = bitset_size_in_bytes(nr_entries);
	return vzalloc(s);
}

static void clear_bitset(void *bitset, unsigned nr_entries)
{
	size_t s = bitset_size_in_bytes(nr_entries);
	memset(bitset, 0, s);
}

static void set_bitset(void *bitset, unsigned nr_entries)
{
	size_t s = bitset_size_in_bytes(nr_entries);
	memset(bitset, ~0, s);
}

static void free_bitset(unsigned long *bits)
{
	vfree(bits);
}

/*----------------------------------------------------------------*/

#define PRISON_CELLS 1024
#define ENDIO_HOOK_POOL_SIZE 1024
#define MIGRATION_POOL_SIZE 128
#define COMMIT_PERIOD HZ
#define MIGRATION_COUNT_WINDOW 10

/*
 * The block size of the device holding cache data must be >= 32KB
 */
#define DATA_DEV_BLOCK_SIZE_MIN_SECTORS (32 * 1024 >> SECTOR_SHIFT)

/*
 * FIXME: the cache is read/write for the time being.
 */
enum cache_mode {
	CM_WRITE,		/* metadata may be changed */
};

struct cache_features {
	enum cache_mode mode;

	bool ctr_set:1;	/* Constructor has set feature argument below. */

	bool write_through:1;
};

struct cache {
	struct dm_target *ti;
	struct dm_target_callbacks callbacks;

	/*
	 * Metadata is written to this device.
	 */
	struct dm_dev *metadata_dev;

	/*
	 * The slower of the two data devices.  Typically a spindle.
	 */
	struct dm_dev *origin_dev;

	/*
	 * The faster of the two data devices.  Typically an SSD.
	 */
	struct dm_dev *cache_dev;

	/*
	 * Cache features such as write-through.
	 */
	struct cache_features cf;

	/*
	 * Size of the origin device in _complete_ blocks and native sectors.
	 */
	dm_oblock_t origin_blocks;
	sector_t origin_sectors;

	/*
	 * Size of the cache device in blocks.
	 */
	dm_cblock_t cache_size;

	struct dm_cache_metadata *cmd;

	/*
	 * Fields for converting from sectors to blocks.
	 */
	sector_t sectors_per_block;
	int sectors_per_block_shift;

	spinlock_t lock;
	struct bio_list deferred_bios;
	struct bio_list deferred_flush_bios;
	struct list_head quiesced_migrations;
	struct list_head completed_migrations;
	struct list_head need_commit_migrations;
	sector_t migration_threshold;
	wait_queue_head_t migration_wait;
	atomic_t nr_migrations;

	/*
	 * cache_size entries, dirty if set
	 */
	dm_cblock_t nr_dirty;
	unsigned long *dirty_bitset;

	/*
	 * origin_blocks entries, discarded if set.
	 * FIXME: This is too big
	 */
	unsigned long *discard_bitset;

	struct dm_kcopyd_client *copier;
	struct workqueue_struct *wq;
	struct work_struct worker;

	struct delayed_work waker;
	unsigned long last_commit_jiffies;

	struct dm_bio_prison *prison;
	struct dm_deferred_set *all_io_ds;

	mempool_t *endio_hook_pool;
	mempool_t *migration_pool;
	struct dm_cache_migration *next_migration;

	struct dm_cache_policy *policy;
	unsigned policy_nr_args;

	bool need_tick_bio:1;

	bool quiescing:1;
	bool commit_requested:1;
	bool loaded_mappings:1;

	atomic_t read_hit;
	atomic_t read_miss;
	atomic_t write_hit;
	atomic_t write_miss;
	atomic_t demotion;
	atomic_t promotion;
	atomic_t copies_avoided;
	atomic_t cache_cell_clash;
	atomic_t commit_count;
};

struct dm_cache_endio_hook {
	bool tick:1;
	bool error:1;
	unsigned req_nr:2;
	struct dm_deferred_entry *all_io_entry;

	atomic_t nr_pending;
	bio_end_io_t *bi_endio;
	void *bi_private;
};

struct dm_cache_migration {
	bool err:1;
	bool demote:1;
	bool promote:1;

	struct list_head list;
	struct cache *cache;

	unsigned long start_jiffies;
	dm_oblock_t old_oblock;
	dm_oblock_t new_oblock;
	dm_cblock_t cblock;

	struct dm_bio_prison_cell *old_ocell;
	struct dm_bio_prison_cell *new_ocell;
};

/*
 * Processing a bio in the worker thread may require these memory
 * allocations.  We prealloc to avoid deadlocks (the same worker thread
 * frees them back to the mempool).
 */
struct prealloc {
	struct dm_cache_migration *mg;
	struct dm_bio_prison_cell *cell1;
	struct dm_bio_prison_cell *cell2;
};

static void wake_worker(struct cache *cache)
{
	queue_work(cache->wq, &cache->worker);
}

/*----------------------------------------------------------------*/

static int prealloc_data_structs(struct cache *cache, struct prealloc *p)
{
	// FIXME: given we're doing this, can we get rid of the mempools?

	if (!p->mg) {
		p->mg = mempool_alloc(cache->migration_pool, GFP_ATOMIC);
		if (!p->mg)
			return -ENOMEM;
	}

	if (!p->cell1) {
		p->cell1 = dm_bio_prison_alloc_cell(cache->prison, GFP_ATOMIC);
		if (!p->cell1)
			return -ENOMEM;
	}

	if (!p->cell2) {
		p->cell2 = dm_bio_prison_alloc_cell(cache->prison, GFP_ATOMIC);
		if (!p->cell2)
			return -ENOMEM;
	}

	return 0;
}

static void prealloc_free_structs(struct cache *cache, struct prealloc *p)
{
	if (p->cell2)
		dm_bio_prison_free_cell(cache->prison, p->cell2);

	if (p->cell1)
		dm_bio_prison_free_cell(cache->prison, p->cell1);

	if (p->mg)
		mempool_free(p->mg, cache->migration_pool);
}

static struct dm_cache_migration *prealloc_get_migration(struct prealloc *p)
{
	struct dm_cache_migration *mg = p->mg;

	BUG_ON(!mg);
	p->mg = NULL;

	return mg;
}

static struct dm_bio_prison_cell **prealloc_get_cell(struct prealloc *p)
{
	if (p->cell1)
		return &p->cell1;

	if (p->cell2)
		return &p->cell2;

	BUG();
	return NULL;
}

/*----------------------------------------------------------------*/

static void build_key(dm_oblock_t oblock, struct dm_cell_key *key)
{
	key->virtual = 0;
	key->dev = 0;
	key->block = from_oblock(oblock);
}

// FIXME: refactor these three
static int bio_detain_(struct cache *cache,
		       dm_oblock_t oblock, struct bio *bio,
		       gfp_t gfp,
		       struct dm_bio_prison_cell **result)
{
	int r;
	struct dm_cell_key key;
	struct dm_bio_prison_cell *cell;

	cell = dm_bio_prison_alloc_cell(cache->prison, gfp);

	build_key(oblock, &key);
	r = dm_bio_detain(cache->prison, &key, bio, cell, result);

	if (r)
		dm_bio_prison_free_cell(cache->prison, cell);

	return r;
}

static int bio_detain(struct cache *cache, struct prealloc *structs,
		      dm_oblock_t oblock, struct bio *bio,
		      struct dm_bio_prison_cell **result)
{
	int r;
	struct dm_cell_key key;
	struct dm_bio_prison_cell **cell;

	cell = prealloc_get_cell(structs);

	build_key(oblock, &key);
	r = dm_bio_detain(cache->prison, &key, bio, *cell, result);

	if (!r)
		/* cell was used */
		*cell = NULL;

	return r;
}

static int bio_detain_no_holder(struct cache *cache,
				struct prealloc *structs,
				dm_oblock_t oblock,
				struct dm_bio_prison_cell **result)
{
	int r;
	struct dm_cell_key key;
	struct dm_bio_prison_cell **cell;

	cell = prealloc_get_cell(structs);

	build_key(oblock, &key);
	r = dm_bio_detain_no_holder(cache->prison, &key, *cell, result);

	if (!r)
		*cell = NULL;

	return r;
}

/*----------------------------------------------------------------*/

static bool is_dirty(struct cache *cache, dm_cblock_t b)
{
	return test_bit(from_cblock(b), cache->dirty_bitset);
}

static void set_dirty(struct cache *cache, dm_oblock_t oblock, dm_cblock_t cblock)
{
	if (!test_and_set_bit(from_cblock(cblock), cache->dirty_bitset)) {
		cache->nr_dirty = to_cblock(from_cblock(cache->nr_dirty) + 1);
		policy_set_dirty(cache->policy, oblock);
	}
}

static void clear_dirty(struct cache *cache, dm_oblock_t oblock, dm_cblock_t cblock)
{
	if (test_and_clear_bit(from_cblock(cblock), cache->dirty_bitset)) {
		policy_clear_dirty(cache->policy, oblock);

		cache->nr_dirty = to_cblock(from_cblock(cache->nr_dirty) - 1);
		if (!from_cblock(cache->nr_dirty))
			dm_table_event(cache->ti->table);
	}
}

/*----------------------------------------------------------------*/

/*
 * The discard bitset is accessed from both the worker thread and the
 * cache_map function, we need to protect it.
 */
static void set_discard(struct cache *cache, dm_oblock_t b)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	set_bit(from_oblock(b), cache->discard_bitset);
	spin_unlock_irqrestore(&cache->lock, flags);
}

static void clear_discard(struct cache *cache, dm_oblock_t b)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	clear_bit(from_oblock(b), cache->discard_bitset);
	spin_unlock_irqrestore(&cache->lock, flags);
}

static bool is_discarded(struct cache *cache, dm_oblock_t b)
{
	int r;
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	r = test_bit(from_oblock(b), cache->discard_bitset);
	spin_unlock_irqrestore(&cache->lock, flags);

	return r;
}

/*----------------------------------------------------------------*/

static void load_stats(struct cache *cache)
{
	struct dm_cache_statistics stats;

	dm_cache_get_stats(cache->cmd, &stats);
	atomic_set(&cache->read_hit, stats.read_hits);
	atomic_set(&cache->read_miss, stats.read_misses);
	atomic_set(&cache->write_hit, stats.write_hits);
	atomic_set(&cache->write_miss, stats.write_misses);
}

static void save_stats(struct cache *cache)
{
	struct dm_cache_statistics stats;

	stats.read_hits = atomic_read(&cache->read_hit);
	stats.read_misses = atomic_read(&cache->read_miss);
	stats.write_hits = atomic_read(&cache->write_hit);
	stats.write_misses = atomic_read(&cache->write_miss);

	dm_cache_set_stats(cache->cmd, &stats);
}

/*----------------------------------------------------------------
 * Remapping
 *--------------------------------------------------------------*/
static bool block_size_is_power_of_two(struct cache *cache)
{
	return cache->sectors_per_block_shift >= 0;
}

static void remap_to_origin(struct cache *cache, struct bio *bio)
{
	bio->bi_bdev = cache->origin_dev->bdev;
}

static void remap_to_cache(struct cache *cache, struct bio *bio,
			   dm_cblock_t cblock)
{
	sector_t bi_sector = bio->bi_sector;

	bio->bi_bdev = cache->cache_dev->bdev;
	if (!block_size_is_power_of_two(cache))
		bio->bi_sector = (from_cblock(cblock) * cache->sectors_per_block) +
				sector_div(bi_sector, cache->sectors_per_block);
	else
		bio->bi_sector = (from_cblock(cblock) << cache->sectors_per_block_shift) |
				(bi_sector & (cache->sectors_per_block - 1));
}

static void check_if_tick_bio_needed(struct cache *cache, struct bio *bio)
{
	unsigned long flags;
	struct dm_cache_endio_hook *h = dm_get_mapinfo(bio)->ptr;

	spin_lock_irqsave(&cache->lock, flags);
	if (cache->need_tick_bio && !(bio->bi_rw & (REQ_FUA | REQ_FLUSH | REQ_DISCARD))) {
		h->tick = true;
		cache->need_tick_bio = false;
	}
	spin_unlock_irqrestore(&cache->lock, flags);
}

static void remap_to_origin_dirty(struct cache *cache, struct bio *bio, dm_oblock_t oblock)
{
	check_if_tick_bio_needed(cache, bio);
	remap_to_origin(cache, bio);
	if (bio_data_dir(bio) == WRITE)
		clear_discard(cache, oblock);
}

static void remap_to_cache_dirty(struct cache *cache, struct bio *bio,
				 dm_oblock_t oblock, dm_cblock_t cblock)
{
	remap_to_cache(cache, bio, cblock);
	if (bio_data_dir(bio) == WRITE) {
		set_dirty(cache, oblock, cblock);
		clear_discard(cache, oblock);
	}
}

static dm_oblock_t get_bio_block(struct cache *cache, struct bio *bio)
{
	sector_t block_nr = bio->bi_sector;

	if (!block_size_is_power_of_two(cache))
		(void) sector_div(block_nr, cache->sectors_per_block);
	else
		block_nr >>= cache->sectors_per_block_shift;

	return to_oblock(block_nr);
}

static int bio_triggers_commit(struct cache *cache, struct bio *bio)
{
	return (bio->bi_rw & (REQ_FLUSH | REQ_FUA)) &&
		dm_cache_changed_this_transaction(cache->cmd);
}

static void issue(struct cache *cache, struct bio *bio)
{
	unsigned long flags;

	if (bio_triggers_commit(cache, bio)) {
		spin_lock_irqsave(&cache->lock, flags);
		cache->commit_requested = true;
		bio_list_add(&cache->deferred_flush_bios, bio);
		spin_unlock_irqrestore(&cache->lock, flags);
	} else
		generic_make_request(bio);
}

/*----------------------------------------------------------------
 * Migration processing
 *
 * Migration covers moving data from the origin device to the cache, or
 * vice versa.
 *--------------------------------------------------------------*/
static void free_migration(struct dm_cache_migration *mg)
{
	mempool_free(mg, mg->cache->migration_pool);
}

static void inc_nr_migrations(struct cache *cache)
{
	atomic_inc(&cache->nr_migrations);
	wake_up(&cache->migration_wait); /* FIXME: why is there a wakeup here? */
}

static void dec_nr_migrations(struct cache *cache)
{
	atomic_dec(&cache->nr_migrations);
	wake_up(&cache->migration_wait);
}

static void __cell_defer(struct cache *cache, struct dm_bio_prison_cell *cell, bool holder)
{
	(holder ? dm_cell_release : dm_cell_release_no_holder)
		(cache->prison, cell, &cache->deferred_bios);
	dm_bio_prison_free_cell(cache->prison, cell);
}

static void cell_defer(struct cache *cache, struct dm_bio_prison_cell *cell, bool holder)
{
	if (cell) {
		unsigned long flags;

		spin_lock_irqsave(&cache->lock, flags);
		__cell_defer(cache, cell, holder);
		spin_unlock_irqrestore(&cache->lock, flags);

		wake_worker(cache);
	}
}

static void cleanup_migration(struct dm_cache_migration *mg)
{
	struct cache *cache = mg->cache;

	free_migration(mg);
	dec_nr_migrations(cache);
}

static void migration_failure(struct dm_cache_migration *mg)
{
	struct cache *cache = mg->cache;

	if (mg->demote) {
		DMWARN("demotion failed; couldn't copy block");
		policy_force_mapping(cache->policy, mg->new_oblock, mg->old_oblock);

		cell_defer(cache, mg->old_ocell, mg->promote ? 0 : 1);
		if (mg->promote)
			cell_defer(cache, mg->new_ocell, 1);
	} else {
		DMWARN("promotion failed; couldn't copy block");
		policy_remove_mapping(cache->policy, mg->new_oblock);
		cell_defer(cache, mg->new_ocell, 1);
	}

	cleanup_migration(mg);
}

static void migration_success_pre_commit(struct dm_cache_migration *mg)
{
	unsigned long flags;
	struct cache *cache = mg->cache;

	if (mg->demote) {
		if (dm_cache_remove_mapping(cache->cmd, mg->cblock)) {
			DMWARN("demotion failed; couldn't update on disk metadata");
			policy_force_mapping(cache->policy, mg->new_oblock, mg->old_oblock);
			if (mg->promote)
				cell_defer(cache, mg->new_ocell, 1);
			cleanup_migration(mg);
			return;
		}
	} else {
		if (dm_cache_insert_mapping(cache->cmd, mg->cblock, mg->new_oblock)) {
			DMWARN("promotion failed; couldn't update on disk metadata");
			policy_remove_mapping(cache->policy, mg->new_oblock);
			cleanup_migration(mg);
		}
	}

	spin_lock_irqsave(&cache->lock, flags);
	list_add_tail(&mg->list, &cache->need_commit_migrations);
	cache->commit_requested = true;
	spin_unlock_irqrestore(&cache->lock, flags);
}

static void migration_success_post_commit(struct dm_cache_migration *mg)
{
	unsigned long flags;
	struct cache *cache = mg->cache;

	if (mg->demote) {
		cell_defer(cache, mg->old_ocell, mg->promote ? 0 : 1);
		clear_dirty(cache, mg->old_oblock, mg->cblock);

		if (mg->promote) {
			mg->demote = false;

			spin_lock_irqsave(&cache->lock, flags);
			list_add_tail(&mg->list, &cache->quiesced_migrations);
			spin_unlock_irqrestore(&cache->lock, flags);
		} else
			cleanup_migration(mg);
	} else {
		cell_defer(cache, mg->new_ocell, 1);
		clear_dirty(cache, mg->new_oblock, mg->cblock);
		cleanup_migration(mg);
	}
}

static void copy_complete(int read_err, unsigned long write_err, void *context)
{
	unsigned long flags;
	struct dm_cache_migration *mg = (struct dm_cache_migration *) context;
	struct cache *cache = mg->cache;

	if (read_err || write_err)
		mg->err = true;

	spin_lock_irqsave(&cache->lock, flags);
	list_add_tail(&mg->list, &cache->completed_migrations);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}

static void issue_copy_real(struct dm_cache_migration *mg)
{
	int r;
	struct dm_io_region o_region, c_region;
	struct cache *cache = mg->cache;

	o_region.bdev = cache->origin_dev->bdev;
	o_region.count = cache->sectors_per_block;

	c_region.bdev = cache->cache_dev->bdev;
	c_region.sector = from_cblock(mg->cblock) * cache->sectors_per_block;
	c_region.count = cache->sectors_per_block;

	if (mg->demote) {
		/* demote */
		o_region.sector = from_oblock(mg->old_oblock) * cache->sectors_per_block;
		r = dm_kcopyd_copy(cache->copier, &c_region, 1, &o_region, 0, copy_complete, mg);
	} else {
		/* promote */
		o_region.sector = from_oblock(mg->new_oblock) * cache->sectors_per_block;
		r = dm_kcopyd_copy(cache->copier, &o_region, 1, &c_region, 0, copy_complete, mg);
	}

	if (r < 0)
		migration_failure(mg);
}

static void avoid_copy(struct dm_cache_migration *mg)
{
	atomic_inc(&mg->cache->copies_avoided);
	migration_success_pre_commit(mg);
}

static void issue_copy(struct dm_cache_migration *mg)
{
	bool avoid;
	struct cache *cache = mg->cache;

	if (mg->demote)
		avoid = !is_dirty(cache, mg->cblock) ||
			is_discarded(cache, mg->old_oblock);
	else
		avoid = is_discarded(cache, mg->new_oblock);

	avoid ? avoid_copy(mg) : issue_copy_real(mg);
}

static void complete_migration(struct dm_cache_migration *mg)
{
	if (mg->err)
		migration_failure(mg);
	else
		migration_success_pre_commit(mg);
}

static void process_migrations(struct cache *cache, struct list_head *head,
			       void (*fn)(struct dm_cache_migration *))
{
	unsigned long flags;
	struct list_head list;
	struct dm_cache_migration *mg, *tmp;

	INIT_LIST_HEAD(&list);
	spin_lock_irqsave(&cache->lock, flags);
	list_splice_init(head, &list);
	spin_unlock_irqrestore(&cache->lock, flags);

	list_for_each_entry_safe(mg, tmp, &list, list)
		fn(mg);
}

static void __queue_quiesced_migration(struct dm_cache_migration *mg)
{
	list_add_tail(&mg->list, &mg->cache->quiesced_migrations);
}

static void queue_quiesced_migration(struct dm_cache_migration *mg)
{
	unsigned long flags;
	struct cache *cache = mg->cache;

	spin_lock_irqsave(&cache->lock, flags);
	__queue_quiesced_migration(mg);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}

static void queue_quiesced_migrations(struct cache *cache, struct list_head *work)
{
	unsigned long flags;
	struct dm_cache_migration *mg, *tmp;

	spin_lock_irqsave(&cache->lock, flags);
	list_for_each_entry_safe(mg, tmp, work, list)
		__queue_quiesced_migration(mg);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}

static void check_for_quiesced_migrations(struct cache *cache,
					  struct dm_cache_endio_hook *h)
{
	struct list_head work;

	if (!h->all_io_entry)
		return;

	INIT_LIST_HEAD(&work);
	if (h->all_io_entry)
		dm_deferred_entry_dec(h->all_io_entry, &work);

	if (!list_empty(&work))
		queue_quiesced_migrations(cache, &work);
}

static void quiesce_migration(struct dm_cache_migration *mg)
{
	if (!dm_deferred_set_add_work(mg->cache->all_io_ds, &mg->list))
		queue_quiesced_migration(mg);
}

static void promote(struct cache *cache, struct prealloc *structs, dm_oblock_t oblock,
		    dm_cblock_t cblock, struct dm_bio_prison_cell *cell)
{
	struct dm_cache_migration *mg = prealloc_get_migration(structs);

	mg->err = false;
	mg->demote = false;
	mg->promote = true;
	mg->cache = cache;
	mg->new_oblock = oblock;
	mg->cblock = cblock;
	mg->old_ocell = NULL;
	mg->new_ocell = cell;
	mg->start_jiffies = jiffies;

	inc_nr_migrations(cache);
	quiesce_migration(mg);
}

static void demote(struct cache *cache, struct prealloc *structs, dm_oblock_t oblock,
		   dm_cblock_t cblock, struct dm_bio_prison_cell *cell)
{
	struct dm_cache_migration *mg = prealloc_get_migration(structs);

	mg->err = false;
	mg->demote = true;
	mg->promote = false;
	mg->cache = cache;
	mg->old_oblock = oblock;
	mg->cblock = cblock;
	mg->old_ocell = cell;
	mg->new_ocell = NULL;
	mg->start_jiffies = jiffies;

	inc_nr_migrations(cache);
	quiesce_migration(mg);
}

static void demote_then_promote(struct cache *cache,
				struct prealloc *structs,
				dm_oblock_t old_oblock,
				dm_oblock_t new_oblock,
				dm_cblock_t cblock,
				struct dm_bio_prison_cell *old_ocell,
				struct dm_bio_prison_cell *new_ocell)
{
	struct dm_cache_migration *mg = prealloc_get_migration(structs);

	mg->err = false;
	mg->demote = true;
	mg->promote = true;
	mg->cache = cache;
	mg->old_oblock = old_oblock;
	mg->new_oblock = new_oblock;
	mg->cblock = cblock;
	mg->old_ocell = old_ocell;
	mg->new_ocell = new_ocell;
	mg->start_jiffies = jiffies;

	inc_nr_migrations(cache);
	quiesce_migration(mg);
}

/*----------------------------------------------------------------
 * Write through
 *--------------------------------------------------------------*/
static void complete_writethrough(struct bio *bio, int error)
{
	struct dm_cache_endio_hook *h = bio->bi_private;

	if (error)
		h->error = true;

	if (atomic_dec_and_test(&h->nr_pending)) {
		bio->bi_end_io = h->bi_endio;
		bio->bi_private = h->bi_private;
		bio_endio(bio, h->error);
	}
}

static bool issue_writethrough(struct cache *cache, struct bio *bio,
			       dm_cblock_t cblock, gfp_t gfp_mask)
{
	struct dm_cache_endio_hook *h = dm_get_mapinfo(bio)->ptr;
	struct bio *clone = bio_clone(bio, gfp_mask);

	if (!clone)
		return false;

	h->error = 0;
	atomic_set(&h->nr_pending, 2);
	h->bi_endio = bio->bi_end_io;
	h->bi_private = bio->bi_private;

	bio->bi_end_io = clone->bi_end_io = complete_writethrough;
	bio->bi_private = clone->bi_private = h;

	/*
	 * No, need to use the dirty variants since the cache and origin
	 * are always in sync in writethrough mode.
	 */
	remap_to_cache(cache, bio, cblock);
	issue(cache, bio);

	remap_to_origin(cache, bio);
	issue(cache, bio);

	return true;
}

/*----------------------------------------------------------------
 * bio processing
 *--------------------------------------------------------------*/
static void defer_bio(struct cache *cache, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_add(&cache->deferred_bios, bio);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}

static void process_flush_bio(struct cache *cache, struct bio *bio)
{
	struct dm_cache_endio_hook *h = dm_get_mapinfo(bio)->ptr;

	BUG_ON(bio->bi_size);
	if (h->req_nr == 0)
		remap_to_origin(cache, bio);
	else
		remap_to_cache(cache, bio, 0);

	issue(cache, bio);
}

/*
 * People generally discard large parts of a device, eg, the whole device
 * when formatting.  Splitting these large discards up into cache block
 * sized ios and then quiescing (always neccessary for discard) takes too
 * long.
 *
 * We keep it simple, and allow any size of discard to come in, and just
 * mark off blocks on the discard bitset.  No passdown occurs!
 *
 * To implement passdown we need to change the bio_prison such that a cell
 * can have a key that spans many blocks.  This change is planned for
 * thin-provisioning.
 */
static void process_discard_bio(struct cache *cache, struct bio *bio)
{
	dm_block_t start_block = dm_sector_div_up(bio->bi_sector, cache->sectors_per_block);
	dm_block_t end_block = bio->bi_sector + bio_sectors(bio);
	dm_block_t b;

	do_div(end_block, cache->sectors_per_block);

	for (b = start_block; b < end_block; b++)
		set_discard(cache, to_oblock(b));

	bio_endio(bio, 0);
}

static bool may_migrate(struct cache *cache)
{
	sector_t current_volume = (atomic_read(&cache->nr_migrations) + 1) * cache->sectors_per_block;
	return current_volume < cache->migration_threshold;
}

static void process_bio(struct cache *cache, struct prealloc *structs, struct bio *bio)
{
	int r;
	int release_cell = 1;
	dm_oblock_t block = get_bio_block(cache, bio);
	struct dm_bio_prison_cell *old_ocell, *new_ocell;
	struct policy_result lookup_result;
	struct dm_cache_endio_hook *h = dm_get_mapinfo(bio)->ptr;
	bool discarded_block = is_discarded(cache, block);

	/*
	 * Check to see if that block is currently migrating.
	 */
	r = bio_detain(cache, structs, block, bio, &new_ocell);
	if (r > 0)
		return;

	policy_map(cache->policy, block, may_migrate(cache),
		   discarded_block, bio, &lookup_result);
	switch (lookup_result.op) {
	case POLICY_HIT:
		atomic_inc(bio_data_dir(bio) == READ ? &cache->read_hit : &cache->write_hit);
		h->all_io_entry = dm_deferred_entry_inc(cache->all_io_ds);

		if (cache->cf.write_through && !is_dirty(cache, lookup_result.cblock))
			issue_writethrough(cache, bio, lookup_result.cblock, GFP_KERNEL);
		else {
			remap_to_cache_dirty(cache, bio, block, lookup_result.cblock);
			issue(cache, bio);
		}
		break;

	case POLICY_MISS:
		atomic_inc(bio_data_dir(bio) == READ ? &cache->read_miss : &cache->write_miss);
		h->all_io_entry = dm_deferred_entry_inc(cache->all_io_ds);
		remap_to_origin_dirty(cache, bio, block);
		issue(cache, bio);
		break;

	case POLICY_NEW:
		atomic_inc(&cache->promotion);
		promote(cache, structs, block, lookup_result.cblock, new_ocell);
		release_cell = 0;
		break;

	case POLICY_REPLACE:
		r = bio_detain(cache, structs, lookup_result.old_oblock,
			       bio, &old_ocell);
		if (r > 0) {
			/*
			 * We have to be careful to avoid lock inversion of
			 * the cells.  So we back off, and wait for the
			 * old_ocell to become free.
			 */
			policy_force_mapping(cache->policy, block,
					     lookup_result.old_oblock);
			atomic_inc(&cache->cache_cell_clash);
			break;
		}
		atomic_inc(&cache->demotion);
		atomic_inc(&cache->promotion);

		demote_then_promote(cache, structs, lookup_result.old_oblock, block,
				    lookup_result.cblock, old_ocell, new_ocell);
		release_cell = 0;
		break;
	}

	if (release_cell)
		cell_defer(cache, new_ocell, 0);
}

static int need_commit_due_to_time(struct cache *cache)
{
	return jiffies < cache->last_commit_jiffies ||
	       jiffies > cache->last_commit_jiffies + COMMIT_PERIOD;
}

static int commit_if_needed(struct cache *cache)
{
	if (cache->commit_requested || need_commit_due_to_time(cache)) {
		atomic_inc(&cache->commit_count);
		cache->last_commit_jiffies = jiffies;
		cache->commit_requested = false;
		return dm_cache_commit(cache->cmd, false);
	}

	return 0;
}

static void process_deferred_bios(struct cache *cache)
{
	unsigned long flags;
	struct bio_list bios;
	struct bio *bio;
	struct prealloc structs;

	memset(&structs, 0, sizeof(structs));
	bio_list_init(&bios);

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_merge(&bios, &cache->deferred_bios);
	bio_list_init(&cache->deferred_bios);
	spin_unlock_irqrestore(&cache->lock, flags);

	while (!bio_list_empty(&bios)) {
		/*
		 * If we've got no free migration structs, and processing
		 * this bio might require one, we pause until there are some
		 * prepared mappings to process.
		 */
		if (prealloc_data_structs(cache, &structs)) {
			spin_lock_irqsave(&cache->lock, flags);
			bio_list_merge(&cache->deferred_bios, &bios);
			spin_unlock_irqrestore(&cache->lock, flags);
			break;
		}

		bio = bio_list_pop(&bios);

		if (bio->bi_rw & REQ_FLUSH)
			process_flush_bio(cache, bio);

		else if (bio->bi_rw & REQ_DISCARD)
			process_discard_bio(cache, bio);

		else
			process_bio(cache, &structs, bio);
	}

	prealloc_free_structs(cache, &structs);
}

static void process_deferred_flush_bios(struct cache *cache, bool submit_bios)
{
	unsigned long flags;
	struct bio_list bios;
	struct bio *bio;

	bio_list_init(&bios);

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_merge(&bios, &cache->deferred_flush_bios);
	bio_list_init(&cache->deferred_flush_bios);
	spin_unlock_irqrestore(&cache->lock, flags);

	while ((bio = bio_list_pop(&bios)))
		submit_bios ? generic_make_request(bio) : bio_io_error(bio);
}

static void writeback_all_dirty_blocks(struct cache *cache)
{
	int r = 0;
	dm_oblock_t oblock;
	dm_cblock_t cblock;
	struct prealloc structs;

	memset(&structs, 0, sizeof(structs));
	while (!r && may_migrate(cache)) {
		if (prealloc_data_structs(cache, &structs))
			break;

		r = policy_writeback_work(cache->policy, &oblock, &cblock);
		if (!r) {
			struct dm_bio_prison_cell *old_ocell;

			r = bio_detain_no_holder(cache, &structs, oblock, &old_ocell);
			if (r) {
				policy_set_dirty(cache->policy, oblock);
				break;
			}

			demote(cache, &structs, oblock, cblock, old_ocell);
		}
	}

	prealloc_free_structs(cache, &structs);
}

/*----------------------------------------------------------------
 * Main worker loop
 *--------------------------------------------------------------*/
static void start_quiescing(struct cache *cache)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	cache->quiescing = 1;
	spin_unlock_irqrestore(&cache->lock, flags);
}

static void stop_quiescing(struct cache *cache)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	cache->quiescing = 0;
	spin_unlock_irqrestore(&cache->lock, flags);
}

static bool is_quiescing(struct cache *cache)
{
	int r;
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	r = cache->quiescing;
	spin_unlock_irqrestore(&cache->lock, flags);

	return r;
}

static void wait_for_migrations(struct cache *cache)
{
	wait_event(cache->migration_wait, atomic_read(&cache->nr_migrations) == 0);
}

static void stop_worker(struct cache *cache)
{
	cancel_delayed_work(&cache->waker);
	flush_workqueue(cache->wq);
}

static void requeue_deferred_io(struct cache *cache)
{
	struct bio *bio;
	struct bio_list bios;

	bio_list_init(&bios);
	bio_list_merge(&bios, &cache->deferred_bios);
	bio_list_init(&cache->deferred_bios);

	while ((bio = bio_list_pop(&bios)))
		bio_endio(bio, DM_ENDIO_REQUEUE);
}

static int more_work(struct cache *cache)
{
	if (is_quiescing(cache))
		return !list_empty(&cache->quiesced_migrations) ||
			!list_empty(&cache->completed_migrations) ||
			!list_empty(&cache->need_commit_migrations);
	else
		return !bio_list_empty(&cache->deferred_bios) ||
			!bio_list_empty(&cache->deferred_flush_bios) ||
			!list_empty(&cache->quiesced_migrations) ||
			!list_empty(&cache->completed_migrations) ||
			!list_empty(&cache->need_commit_migrations);
}

static void do_worker(struct work_struct *ws)
{
	struct cache *cache = container_of(ws, struct cache, worker);

	// FIXME: get rid of this loop, and let wake_up do its thing.
	do {
		if (!is_quiescing(cache))
			process_deferred_bios(cache);

		process_migrations(cache, &cache->quiesced_migrations, issue_copy);
		process_migrations(cache, &cache->completed_migrations, complete_migration);

		writeback_all_dirty_blocks(cache);

		if (commit_if_needed(cache)) {
			process_deferred_flush_bios(cache, false);

			/*
			 * FIXME: rollback metadata or just go into a
			 * failure mode and error everything
			 */
		} else {
			process_deferred_flush_bios(cache, true);
			process_migrations(cache, &cache->need_commit_migrations,
					   migration_success_post_commit);
		}

	} while (more_work(cache));
}

/*
 * We want to commit periodically so that not too much
 * unwritten metadata builds up.
 */
static void do_waker(struct work_struct *ws)
{
	struct cache *cache = container_of(to_delayed_work(ws), struct cache, waker);
	wake_worker(cache);
	queue_delayed_work(cache->wq, &cache->waker, COMMIT_PERIOD);
}

/*----------------------------------------------------------------*/

static int is_congested(struct dm_dev *dev, int bdi_bits)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);
	return bdi_congested(&q->backing_dev_info, bdi_bits);
}

static int cache_is_congested(struct dm_target_callbacks *cb, int bdi_bits)
{
	struct cache *cache = container_of(cb, struct cache, callbacks);

	return is_congested(cache->origin_dev, bdi_bits) ||
	       is_congested(cache->cache_dev, bdi_bits);
}

/*----------------------------------------------------------------
 * Target methods
 *--------------------------------------------------------------*/

static void cache_dtr(struct dm_target *ti)
{
	struct cache *cache = ti->private;

	pr_alert("dm-cache statistics:\n");
	pr_alert("read hits:\t%u\n", (unsigned) atomic_read(&cache->read_hit));
	pr_alert("read misses:\t%u\n", (unsigned) atomic_read(&cache->read_miss));
	pr_alert("write hits:\t%u\n", (unsigned) atomic_read(&cache->write_hit));
	pr_alert("write misses:\t%u\n", (unsigned) atomic_read(&cache->write_miss));
	pr_alert("demotions:\t%u\n", (unsigned) atomic_read(&cache->demotion));
	pr_alert("promotions:\t%u\n", (unsigned) atomic_read(&cache->promotion));
	pr_alert("copies avoided:\t%u\n", (unsigned) atomic_read(&cache->copies_avoided));
	pr_alert("cache cell clashs:\t%u\n", (unsigned) atomic_read(&cache->cache_cell_clash));
	pr_alert("commits:\t\t%u\n", (unsigned) atomic_read(&cache->commit_count));

	if (cache->next_migration)
		mempool_free(cache->next_migration, cache->migration_pool);

	mempool_destroy(cache->migration_pool);
	mempool_destroy(cache->endio_hook_pool);
	dm_deferred_set_destroy(cache->all_io_ds);
	dm_bio_prison_destroy(cache->prison);
	destroy_workqueue(cache->wq);
	free_bitset(cache->dirty_bitset);
	free_bitset(cache->discard_bitset);
	dm_kcopyd_client_destroy(cache->copier);
	dm_cache_metadata_close(cache->cmd);
	dm_put_device(ti, cache->metadata_dev);
	dm_put_device(ti, cache->origin_dev);
	dm_put_device(ti, cache->cache_dev);
	dm_cache_policy_destroy(cache->policy);

	kfree(cache);
}

static sector_t get_dev_size(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

static int load_mapping(void *context, dm_oblock_t oblock, dm_cblock_t cblock, bool dirty,
			uint32_t hint, bool hint_valid)
{
	struct cache *cache = context;

	dirty ? set_dirty(cache, oblock, cblock) : clear_dirty(cache, oblock, cblock);
	return policy_load_mapping(cache->policy, oblock, cblock, hint, hint_valid);
}

static int create_cache_policy(struct cache *cache,
			       const char *policy_name, char **error,
			       struct dm_arg_set *as)
{
	cache->policy =
		dm_cache_policy_create(policy_name, cache->cache_size,
				       cache->origin_sectors,
				       cache->sectors_per_block,
				       as->argc, as->argv);
	if (!cache->policy) {
		*error = "Error creating cache's policy";
		return -ENOMEM;
	}

	return 0;
}

static struct kmem_cache *_migration_cache;
static struct kmem_cache *_endio_hook_cache;

static struct cache *cache_create(struct block_device *metadata_dev,
				  sector_t block_size, sector_t origin_sectors,
				  sector_t cache_sectors, const char *policy_name,
				  bool read_only, char **error)
{
	int r;
	void *err_p = ERR_PTR(-ENOMEM);
	struct cache *cache;
	struct dm_cache_metadata *cmd;
	bool format_device = read_only ? false : true;
	dm_block_t origin_blocks;

	cmd = dm_cache_metadata_open(metadata_dev, block_size, format_device);
	if (IS_ERR(cmd)) {
		*error = "Error creating metadata object";
		return (struct cache *)cmd;
	}

	cache = kzalloc(sizeof(*cache), GFP_KERNEL);
	if (!cache) {
		*error = "Error allocating memory for cache";
		goto bad_cache;
	}

	cache->cmd = cmd;

	origin_blocks = cache->origin_sectors = origin_sectors;
	do_div(origin_blocks, block_size);
	cache->origin_blocks = to_oblock(origin_blocks);
	cache->sectors_per_block = block_size;
	if (block_size & (block_size - 1)) {
		dm_block_t cache_size = cache_sectors;

		cache->sectors_per_block_shift = -1;
		(void) sector_div(cache_size, block_size);
		cache->cache_size = to_cblock(cache_size);
	} else {
		cache->sectors_per_block_shift = __ffs(block_size);
		cache->cache_size = to_cblock(cache_sectors >> cache->sectors_per_block_shift);
	}

	spin_lock_init(&cache->lock);
	bio_list_init(&cache->deferred_bios);
	bio_list_init(&cache->deferred_flush_bios);
	INIT_LIST_HEAD(&cache->quiesced_migrations);
	INIT_LIST_HEAD(&cache->completed_migrations);
	INIT_LIST_HEAD(&cache->need_commit_migrations);
	atomic_set(&cache->nr_migrations, 0);
	init_waitqueue_head(&cache->migration_wait);

	r = dm_cache_resize(cmd, cache->cache_size);
	if (r) {
		*error = "Couldn't resize cache metadata";
		err_p = ERR_PTR(r);
		goto bad_alloc_dirty_bitset;
	}

	cache->dirty_bitset = alloc_bitset(from_cblock(cache->cache_size));
	if (!cache->dirty_bitset) {
		*error = "Couldn't allocate dirty_bitset";
		goto bad_alloc_dirty_bitset;
	}
	set_bitset(cache->dirty_bitset, from_cblock(cache->cache_size));
	cache->nr_dirty = cache->cache_size;

	cache->discard_bitset = alloc_bitset(from_oblock(cache->origin_blocks));
	if (!cache->discard_bitset) {
		*error = "Couldn't allocate discard bitset";
		goto bad_alloc_discard_bitset;
	}
	clear_bitset(cache->discard_bitset, from_oblock(cache->origin_blocks));

	cache->copier = dm_kcopyd_client_create();
	if (IS_ERR(cache->copier)) {
		*error = "Couldn't create kcopyd client";
		err_p = cache->copier;
		goto bad_kcopyd_client;
	}

	cache->wq = alloc_ordered_workqueue(DAEMON, WQ_MEM_RECLAIM);
	if (!cache->wq) {
		*error = "Couldn't create workqueue for metadata object";
		goto bad_wq;
	}
	INIT_WORK(&cache->worker, do_worker);
	INIT_DELAYED_WORK(&cache->waker, do_waker);

	cache->prison = dm_bio_prison_create(PRISON_CELLS);
	if (!cache->prison) {
		*error = "Couldn't create bio prison";
		goto bad_prison;
	}

	cache->all_io_ds = dm_deferred_set_create();
	if (!cache->all_io_ds) {
		*error = "Couldn't create all_io deferred set";
		goto bad_deferred_set;
	}

	cache->endio_hook_pool = mempool_create_slab_pool(ENDIO_HOOK_POOL_SIZE,
							  _endio_hook_cache);
	if (!cache->endio_hook_pool) {
		*error = "Error creating cache's endio_hook mempool";
		goto bad_endio_hook_pool;
	}

	cache->migration_pool = mempool_create_slab_pool(MIGRATION_POOL_SIZE,
							 _migration_cache);
	if (!cache->migration_pool) {
		*error = "Error creating cache's endio_hook mempool";
		goto bad_migration_pool;
	}

	cache->quiescing = false;
	cache->commit_requested = false;
	cache->loaded_mappings = false;
	cache->last_commit_jiffies = jiffies;

	load_stats(cache);

	atomic_set(&cache->demotion, 0);
	atomic_set(&cache->promotion, 0);
	atomic_set(&cache->copies_avoided, 0);
	atomic_set(&cache->cache_cell_clash, 0);
	atomic_set(&cache->commit_count, 0);

	return cache;

bad_migration_pool:
	mempool_destroy(cache->endio_hook_pool);
bad_endio_hook_pool:
	dm_deferred_set_destroy(cache->all_io_ds);
bad_deferred_set:
	dm_bio_prison_destroy(cache->prison);
bad_prison:
	destroy_workqueue(cache->wq);
bad_wq:
	dm_kcopyd_client_destroy(cache->copier);
bad_kcopyd_client:
	free_bitset(cache->discard_bitset);
bad_alloc_discard_bitset:
	free_bitset(cache->dirty_bitset);
bad_alloc_dirty_bitset:
	kfree(cache);
bad_cache:
	dm_cache_metadata_close(cmd);

	return err_p;
}

/* Initialize cache features. */
static void cache_features_init(struct cache_features *cf)
{
	cf->mode = CM_WRITE;
	cf->ctr_set = false;
	cf->write_through = false;
}

static int parse_cache_features(struct dm_arg_set *as, struct cache_features *cf,
				struct dm_target *ti)
{
	int r;
	unsigned argc;
	const char *arg_name;

	static struct dm_arg _args[] = {
		{0, 1, "Invalid number of cache feature arguments"},
	};

	r = dm_read_arg_group(_args, as, &argc, &ti->error);
	if (r)
		return -EINVAL;

	while (argc && !r) {
		arg_name = dm_shift_arg(as);
		argc--;

		if (!strcasecmp(arg_name, "write-back")) {
			cf->write_through = false;
			cf->ctr_set = true;

		} else if (!strcasecmp(arg_name, "write-through")) {
			cf->write_through = true;
			cf->ctr_set = true;

		} else {
			ti->error = "Unrecognised pool feature requested";
			r = -EINVAL;
			break;
		}
	}

	return r;
}

/*
 * Construct a cache device mapping:
 *
 * cache <metadata dev> <cache dev> <origin dev> <block size> <#feature_args> [<arg>]* <policy> <#policy_args> [<arg>]*
 *
 * metadata dev		  : fast device holding the persistent metadata
 * cache dev		  : fast device holding cached data blocks
 * origin dev		  : slow device holding original data blocks
 * block size		  : cache unit size in sectors
 * #feature args [<arg>]* : number of feature arguments followed by optional arguments
 * policy		  : the replacement policy to use
 * #policy_args  [<arg>]* : number of policy arguments followed by optional arguments; see policy plugin for instances
 *			    (key value pairs count as 2; delimiter is space)
 *
 * Optional feature arguments are:
 *	     write-back: write back cache allowing cache block contents to differ from origin blocks for performance reasons
 *	     write-through: write through caching prohibiting cache block content from being distinct from origin block content
 */
static int cache_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r = -EINVAL;
	struct cache *cache;
	struct dm_arg_set as;
	sector_t block_size, origin_sectors, cache_sectors;
	struct dm_dev *metadata_dev, *origin_dev, *cache_dev;
	struct cache_features cf;
	sector_t metadata_dev_size;
	char b[BDEVNAME_SIZE];
	const char *policy_name, *policy_argc;
	unsigned long tmp;

	if (argc < 7) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}
	as.argc = argc;
	as.argv = argv;

	if (kstrtoul(argv[3], 10, &tmp) || !tmp ||
	    tmp < DATA_DEV_BLOCK_SIZE_MIN_SECTORS ||
	    tmp & (DATA_DEV_BLOCK_SIZE_MIN_SECTORS - 1)) {
		ti->error = "Invalid data block size";
		return -EINVAL;
	}
	block_size = tmp;

	cache_features_init(&cf);
	dm_consume_args(&as, 4);
	r = parse_cache_features(&as, &cf, ti);
	if (r)
		goto bad_features;

	r = dm_get_device(ti, argv[0], FMODE_READ | FMODE_WRITE, &metadata_dev);
	if (r) {
		ti->error = "Error opening metadata device";
		goto bad_metadata;
	}

	metadata_dev_size = get_dev_size(metadata_dev);
	if (metadata_dev_size > CACHE_METADATA_MAX_SECTORS_WARNING)
		DMWARN("Metadata device %s is larger than %u sectors: excess space will not be used.",
		       bdevname(metadata_dev->bdev, b), THIN_METADATA_MAX_SECTORS);

	r = dm_get_device(ti, argv[1], FMODE_READ | FMODE_WRITE, &cache_dev);
	if (r) {
		ti->error = "Error opening cache device";
		goto bad_cache;
	}
	cache_sectors = get_dev_size(cache_dev);

	r = dm_get_device(ti, argv[2], FMODE_READ | FMODE_WRITE, &origin_dev);
	if (r) {
		ti->error = "Error opening origin device";
		goto bad_origin;
	}

	origin_sectors = get_dev_size(origin_dev);
	if (ti->len > origin_sectors) {
		ti->error = "Device size larger than cached device";
		goto bad_target_length;
	}

	policy_name = dm_shift_arg(&as);
	policy_argc = dm_shift_arg(&as);

	if (kstrtoul(policy_argc, 10, &tmp) || tmp != as.argc) {
		ti->error = "Invalid policy argument count";
		goto bad_policy_argc;
	}

	cache = cache_create(metadata_dev->bdev, block_size,
			     origin_sectors, cache_sectors,
			     policy_name, false, &ti->error);
	if (IS_ERR(cache)) {
		r = PTR_ERR(cache);
		goto bad_cache_create;
	}

	cache->policy_nr_args = tmp;
	cache->cf = cf;

	if (dm_set_target_max_io_len(ti, cache->sectors_per_block))
		goto bad_max_io_len;

	r = create_cache_policy(cache, policy_name, &ti->error, &as);
	if (r)
		goto bad_max_io_len;

	cache->ti = ti;
	cache->metadata_dev = metadata_dev;
	cache->cache_dev = cache_dev;
	cache->origin_dev = origin_dev;

	ti->private = cache;

	ti->num_flush_requests = 2;
	ti->flush_supported = true;

	ti->num_discard_requests = 1;
	ti->discards_supported = true;
	ti->discard_zeroes_data_unsupported = true;

	cache->callbacks.congested_fn = cache_is_congested;
	dm_table_add_target_callbacks(ti->table, &cache->callbacks);

	return 0;

bad_max_io_len:
	kfree(cache);
bad_target_length:
bad_policy_argc:
bad_cache_create:
	dm_put_device(ti, origin_dev);
bad_origin:
	dm_put_device(ti, cache_dev);
bad_cache:
	dm_put_device(ti, metadata_dev);
bad_features:
bad_metadata:
	return r;
}

static struct dm_cache_endio_hook *hook_endio(struct cache *cache, struct bio *bio, unsigned req_nr)
{
	struct dm_cache_endio_hook *h = mempool_alloc(cache->endio_hook_pool, GFP_NOIO);

	h->tick = false;
	h->req_nr = req_nr;
	h->all_io_entry = NULL;

	return h;
}

static int cache_map(struct dm_target *ti, struct bio *bio,
		     union map_info *map_context)
{
	struct cache *cache = ti->private;

	int r;
	dm_oblock_t block = get_bio_block(cache, bio);
	bool can_migrate = false;
	bool discarded_block;
	struct dm_bio_prison_cell *cell;
	struct policy_result lookup_result;
	struct dm_cache_endio_hook *h;

	if (from_oblock(block) > from_oblock(cache->origin_blocks)) {
		/*
		 * This can only occur if the io goes to a partial block at
		 * the end of the origin device.  We don't cache these.
		 * Just remap to the origin and carry on.
		 */
		remap_to_origin(cache, bio);
		return DM_MAPIO_REMAPPED;
	}

	h = map_context->ptr = hook_endio(cache, bio, map_context->target_request_nr);

	if (bio->bi_rw & (REQ_FLUSH | REQ_FUA | REQ_DISCARD)) {
		defer_bio(cache, bio);
		return DM_MAPIO_SUBMITTED;
	}

	/*
	 * Check to see if that block is currently migrating.
	 */
	r = bio_detain_(cache, block, bio, GFP_ATOMIC, &cell);
	if (r) {
		if (r < 0)
			defer_bio(cache, bio);

		return DM_MAPIO_SUBMITTED;
	}

	discarded_block = is_discarded(cache, block);

	r = policy_map(cache->policy, block, can_migrate, discarded_block, bio, &lookup_result);
	if (r == -EWOULDBLOCK) {
		cell_defer(cache, cell, true);
		return DM_MAPIO_SUBMITTED;
	}

	if (r)
		BUG();

	switch (lookup_result.op) {
	case POLICY_HIT:
		atomic_inc(bio_data_dir(bio) == READ ? &cache->read_hit : &cache->write_hit);
		h->all_io_entry = dm_deferred_entry_inc(cache->all_io_ds);

		if (cache->cf.write_through && !is_dirty(cache, lookup_result.cblock) &&
		    !issue_writethrough(cache, bio, lookup_result.cblock, GFP_NOIO)) {
			cell_defer(cache, cell, true);
			return DM_MAPIO_SUBMITTED;
		} else {
			remap_to_cache_dirty(cache, bio, block, lookup_result.cblock);
			cell_defer(cache, cell, false);
		}
		break;

	case POLICY_MISS:
		atomic_inc(bio_data_dir(bio) == READ ? &cache->read_miss : &cache->write_miss);
		h->all_io_entry = dm_deferred_entry_inc(cache->all_io_ds);
		remap_to_origin_dirty(cache, bio, block);
		cell_defer(cache, cell, false);
		break;

	default:
		pr_alert("illegal value: %u\n", (unsigned) lookup_result.op);
		BUG();
	}

	return DM_MAPIO_REMAPPED;
}

static int cache_end_io(struct dm_target *ti, struct bio *bio,
			int error, union map_info *info)
{
	struct cache *cache = ti->private;
	unsigned long flags;
	struct dm_cache_endio_hook *h = info->ptr;

	if (h->tick) {
		policy_tick(cache->policy);

		spin_lock_irqsave(&cache->lock, flags);
		cache->need_tick_bio = true;
		spin_unlock_irqrestore(&cache->lock, flags);
	}

	check_for_quiesced_migrations(cache, h);
	mempool_free(h, cache->endio_hook_pool);
	return 0;
}

static int write_dirty_bitset(struct cache *cache)
{
	unsigned i, r;

	for (i = 0; i < from_cblock(cache->cache_size); i++) {
		r = dm_cache_set_dirty(cache->cmd, to_cblock(i),
				       is_dirty(cache, to_cblock(i)));
		if (r)
			return r;
	}

	return 0;
}

static int save_hint(void *context, dm_cblock_t cblock, dm_oblock_t oblock, uint32_t hint)
{
	struct cache *cache = context;
	return dm_cache_save_hint(cache->cmd, cblock, hint);
}

static int write_hints(struct cache *cache)
{
	int r;

	r = dm_cache_begin_hints(cache->cmd, dm_cache_policy_get_name(cache->policy));
	if (r) {
		DMERR("dm_cache_begin_hints failed");
		return r;
	}

	r = policy_walk_mappings(cache->policy, save_hint, cache);
	if (r)
		DMERR("policy_walk_mappings failed");

	return r;
}

/*
 * FIXME: also write the discard bitset.
 */
static int sync_metadata(struct cache *cache)
{
	int r1, r2, r3;

	r1 = write_dirty_bitset(cache);
	save_stats(cache);

	r2 = write_hints(cache);

	/*
	 * If writing the above metadata failed, we still commit, but don't
	 * set the clean shutdown flag.  This will effectively force every
	 * dirty bit to be set on reload.
	 */
	r3 = dm_cache_commit(cache->cmd, !r1 && !r2);
	return !r1 && !r2 && !r3;
}

static void cache_postsuspend(struct dm_target *ti)
{
	struct cache *cache = ti->private;

	start_quiescing(cache);
	wait_for_migrations(cache);
	stop_worker(cache);
	requeue_deferred_io(cache);
	stop_quiescing(cache);

	if (!sync_metadata(cache))
		DMERR("Couldn't write cache metadata.  Data loss may occur.");
}

static int cache_preresume(struct dm_target *ti)
{
	int r = 0;
	struct cache *cache = ti->private;

	if (!cache->loaded_mappings) {
		r = dm_cache_load_mappings(cache->cmd,
					   dm_cache_policy_get_name(cache->policy),
					   load_mapping, cache);
		if (r) {
			DMERR("couldn't load cache mappings");
			return r;
		}

		cache->loaded_mappings = true;
	}

	return r;
}

static void cache_resume(struct dm_target *ti)
{
	struct cache *cache = ti->private;

	cache->need_tick_bio = true;
	do_waker(&cache->waker.work);
}

static int cache_status(struct dm_target *ti, status_type_t type,
			unsigned status_flags, char *result, unsigned maxlen)
{
	int r = 0;
	ssize_t sz = 0;
	dm_block_t nr_free_blocks_metadata = 0;
	dm_block_t nr_blocks_metadata = 0;
	char buf[BDEVNAME_SIZE];
	struct cache *cache = ti->private;
	dm_cblock_t residency;

	switch (type) {
	case STATUSTYPE_INFO:
		/* Commit to ensure statistics aren't out-of-date */
		if (!(status_flags & DM_STATUS_NOFLUSH_FLAG) && !dm_suspended(ti)) {
			r = dm_cache_commit(cache->cmd, false);
			if (r)
				DMERR("could not commit metadata for accurate status");
		}

		r = dm_cache_get_free_metadata_block_count(cache->cmd, &nr_free_blocks_metadata);
		if (r)
			DMERR("could not get metadata free block count");

		r = dm_cache_get_metadata_dev_size(cache->cmd, &nr_blocks_metadata);
		if (r)
			DMERR("could not get metadata device size");

		residency = policy_residency(cache->policy);

		DMEMIT("%llu/%llu %u %u %u %u %u %u %llu %u",
		       (unsigned long long)(nr_blocks_metadata - nr_free_blocks_metadata),
		       (unsigned long long)nr_blocks_metadata,
		       (unsigned) atomic_read(&cache->read_hit),
		       (unsigned) atomic_read(&cache->read_miss),
		       (unsigned) atomic_read(&cache->write_hit),
		       (unsigned) atomic_read(&cache->write_miss),
		       (unsigned) atomic_read(&cache->demotion),
		       (unsigned) atomic_read(&cache->promotion),
		       (unsigned long long) from_cblock(residency),
		       cache->nr_dirty);
		break;

	case STATUSTYPE_TABLE:
		format_dev_t(buf, cache->metadata_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
		format_dev_t(buf, cache->cache_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
		format_dev_t(buf, cache->origin_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
		DMEMIT("%llu ", (unsigned long long) cache->sectors_per_block);

		if (cache->cf.ctr_set)
			DMEMIT("1 %s ", cache->cf.write_through ? "write-through" : "write-back");
		else
			DMEMIT("0 ");

		DMEMIT("%s %u ", dm_cache_policy_get_name(cache->policy), cache->policy_nr_args);
	}

	if (sz < maxlen)
		r = policy_status(cache->policy, type, status_flags, result + sz, maxlen - sz);

	return r;
}

static int process_config_option(struct cache *cache, char **argv)
{
	if (strcmp(argv[1], "migration_threshold")) {
		unsigned long tmp;

		if (kstrtoul(argv[2], 10, &tmp))
			return -EINVAL;

		cache->migration_threshold = tmp;

	} else
		return 1; /* Inform caller it's not our option. */

	return 0;
}

static int cache_message(struct dm_target *ti, unsigned argc, char **argv)
{
	int r = 0;
	struct cache *cache = ti->private;

	if (argc != 3)
		return -EINVAL;

	if (strcmp(argv[0], "set_config")) {
		r = process_config_option(cache, argv);
		if (r < 0)
			goto bad;
	}

	if (r)
		r = policy_message(cache->policy, argc, argv);

bad:
	return r;
}

static int cache_iterate_devices(struct dm_target *ti,
				 iterate_devices_callout_fn fn, void *data)
{
	int r = 0;
	struct cache *cache = ti->private;

	r = fn(ti, cache->cache_dev, 0, get_dev_size(cache->cache_dev), data);
	if (!r)
		r = fn(ti, cache->origin_dev, 0, ti->len, data);

	return r;
}

static int cache_bvec_merge(struct dm_target *ti,
			  struct bvec_merge_data *bvm,
			  struct bio_vec *biovec, int max_size)
{
	struct cache *cache = ti->private;
	struct request_queue *q = bdev_get_queue(cache->origin_dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = cache->origin_dev->bdev;
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static void set_discard_limits(struct cache *cache, struct queue_limits *limits)
{
	/*
	 * FIXME: these limits may be incompatible with the cache's data device
	 */
	limits->max_discard_sectors = cache->sectors_per_block * 1024;

	/*
	 * discard_granularity is just a hint, and not enforced.
	 */
	if (block_size_is_power_of_two(cache))
		limits->discard_granularity = cache->sectors_per_block << SECTOR_SHIFT;
	else
		/*
		 * Use largest power of 2 that is a factor of sectors_per_block
		 * but at least DATA_DEV_BLOCK_SIZE_MIN_SECTORS.
		 */
		limits->discard_granularity = max(1 << __ffs(cache->sectors_per_block),
						  DATA_DEV_BLOCK_SIZE_MIN_SECTORS) << SECTOR_SHIFT;
}

static void cache_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct cache *cache = ti->private;

	blk_limits_io_min(limits, 0);
	blk_limits_io_opt(limits, cache->sectors_per_block << SECTOR_SHIFT);
	set_discard_limits(cache, limits);
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
	.preresume = cache_preresume,
	.resume = cache_resume,
	.status = cache_status,
	.message = cache_message,
	.iterate_devices = cache_iterate_devices,
	.merge = cache_bvec_merge,
	.io_hints = cache_io_hints,
};

static int __init dm_cache_init(void)
{
	int r;

	r = dm_register_target(&cache_target);
	if (r)
		return r;

	r = -ENOMEM;

	_migration_cache = KMEM_CACHE(dm_cache_migration, 0);
	if (!_migration_cache)
		goto bad_migration_cache;

	_endio_hook_cache = KMEM_CACHE(dm_cache_endio_hook, 0);
	if (!_endio_hook_cache)
		goto bad_endio_hook_cache;

	return 0;

bad_endio_hook_cache:
	kmem_cache_destroy(_migration_cache);
bad_migration_cache:
	dm_unregister_target(&cache_target);

	return r;
}

static void dm_cache_exit(void)
{
	dm_unregister_target(&cache_target);

	kmem_cache_destroy(_migration_cache);
	kmem_cache_destroy(_endio_hook_cache);
}

module_init(dm_cache_init);
module_exit(dm_cache_exit);

MODULE_DESCRIPTION(DM_NAME " cache target");
MODULE_AUTHOR("Joe Thornber <ejt@redhat.com>");
MODULE_LICENSE("GPL");

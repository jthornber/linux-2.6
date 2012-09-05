/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "dm.h"
#include "dm-bio-prison.h"
#include "dm-cache-metadata.h"
#include "dm-cache-policy.h"

#include <asm/div64.h>

#include <linux/blkdev.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/slab.h>

//#define debug(x...) pr_alert(x)
#define debug(x...) ;

/*----------------------------------------------------------------*/

static unsigned long *alloc_bitset(unsigned nr_entries, bool set_to_ones)
{
	size_t s = sizeof(unsigned long) * dm_div_up(nr_entries, BITS_PER_LONG);
	unsigned long *r = vzalloc(s);
	if (r && set_to_ones)
		memset(r, ~0, s);

	return r;
}

static void free_bitset(unsigned long *bits)
{
	vfree(bits);
}

/*----------------------------------------------------------------*/

struct rolling_average {
	spinlock_t lock;
	unsigned window;
	unsigned nr_entries;
	unsigned slot;
	uint64_t total;
	struct {
		uint64_t sum;
		unsigned long start;
	} *values;
};

static int rolling_average_init(struct rolling_average *ra, unsigned window)
{
	spin_lock_init(&ra->lock);
	ra->window = window;
	ra->nr_entries = 0;
	ra->slot = 0;
	ra->total = 0;
	ra->values = vzalloc(sizeof(*ra->values) * window);
	ra->values[ra->slot].start = jiffies;

	return ra->values ? 0 : -ENOMEM;
}

static void rolling_average_exit(struct rolling_average *ra)
{
	vfree(ra->values);
}

static unsigned calc_next_slot(struct rolling_average *ra, unsigned s)
{
	s = ra->slot + 1;
	if (s == ra->window)
		s = 0;

	return s;
}

static void ra_next_slot(struct rolling_average *ra)
{
	spin_lock(&ra->lock);

	/* we only add complete values into the total */
	ra->total += ra->values[ra->slot].sum;
	ra->slot = calc_next_slot(ra, ra->slot);
	ra->total -= ra->values[ra->slot].sum;

	if (ra->nr_entries < ra->window)
		ra->nr_entries++;

	ra->values[ra->slot].sum = 0;
	ra->values[ra->slot].start = jiffies;

	spin_unlock(&ra->lock);
}

static void ra_add_to_slot(struct rolling_average *ra, uint64_t value)
{
	spin_lock(&ra->lock);
	ra->values[ra->slot].sum += value;
	spin_unlock(&ra->lock);
}

static uint64_t ra_total(struct rolling_average *ra)
{
	uint64_t r;

	spin_lock(&ra->lock);
	r = ra->total + ra->values[ra->slot].sum;
	spin_unlock(&ra->lock);

	return r;
}

static uint64_t __ra_average(struct rolling_average *ra)
{
	uint64_t total = ra->total + ra->values[ra->slot].sum;
	uint64_t nr = ra->nr_entries + 1;

	return total / nr;
}

static uint64_t ra_average(struct rolling_average *ra)
{
	uint64_t r;

	spin_lock(&ra->lock);
	r = __ra_average(ra);
	spin_unlock(&ra->lock);

	return r;
}

static unsigned long elapsed(unsigned long start, unsigned long end)
{
	if (end < start)
		return end + (ULONG_MAX - start);
	else
		return end - start;
}

static unsigned long __ra_duration(struct rolling_average *ra)
{
	unsigned start_slot;
	unsigned long start;

	if (ra->nr_entries == 0)
		return 0;

	if (ra->nr_entries < ra->window)
		start_slot = 0;
	else
		start_slot = calc_next_slot(ra, ra->slot);

	start = ra->values[start_slot].start;
	return elapsed(start, jiffies);
}

static unsigned long ra_duration(struct rolling_average *ra)
{
	unsigned long r;

	spin_lock(&ra->lock);
	r = __ra_duration(ra);
	spin_unlock(&ra->lock);

	return r;
}

static uint64_t ra_average_per_second(struct rolling_average *ra)
{
	spin_lock(&ra->lock);
	if (ra->nr_entries == 0) {
		spin_unlock(&ra->lock);
		return 0;
	}
	spin_unlock(&ra->lock);

	return (ra_total(ra) * HZ) / ra_duration(ra);
}

/*----------------------------------------------------------------*/

/* Mechanism */

#define BLOCK_SIZE_MIN 64
#define DM_MSG_PREFIX "cache"
#define DAEMON "cached"
#define PRISON_CELLS 1024
#define ENDIO_HOOK_POOL_SIZE 1024
#define MIGRATION_POOL_SIZE 128
#define COMMIT_PERIOD HZ
#define MIGRATION_COUNT_WINDOW 10

struct cache_c {
	struct dm_target *ti;

	struct dm_dev *metadata_dev;
	struct dm_dev *origin_dev;
	struct dm_dev *cache_dev;
	struct dm_target_callbacks callbacks;

	dm_block_t origin_blocks;
	dm_block_t cache_size;
	sector_t sectors_per_block;
	sector_t offset_mask;
	unsigned int block_shift;

	struct dm_cache_metadata *cmd;

	spinlock_t lock;
	struct bio_list deferred_bios;
	struct bio_list deferred_flush_bios;
	struct list_head quiesced_migrations;
	struct list_head completed_migrations;
	atomic_t nr_migrations;
	wait_queue_head_t migration_wait;

	struct rolling_average hit_volume;
	struct rolling_average miss_volume;
	struct rolling_average migration_time;
	struct rolling_average migration_count;

	unsigned long *discard_bitset; /* origin block has been discarded if set */

	struct dm_kcopyd_client *copier;
	struct workqueue_struct *wq;
	struct work_struct worker;

	struct delayed_work waker;
	unsigned long last_commit_jiffies;

	struct bio_prison *prison;
	struct deferred_set *all_io_ds;

	mempool_t *endio_hook_pool;
	mempool_t *migration_pool;
	struct dm_cache_migration *next_migration;

	bool need_tick_bio;

	struct dm_cache_policy *policy;
	bool quiescing;

	atomic_t read_hit;
	atomic_t read_miss;
	atomic_t write_hit;
	atomic_t write_miss;
	atomic_t demotion;
	atomic_t promotion;
	atomic_t copies_avoided;

	unsigned int seq_io_threshold;
};

/* FIXME: can we lose this? */
struct dm_cache_endio_hook {
	bool tick;
	unsigned req_nr;
	struct deferred_entry *all_io_entry;
};

struct dm_cache_migration {
	bool err:1;
	bool demote:1;
	bool promote:1;

	struct list_head list;
	struct cache_c *c;

	unsigned long start_jiffies;
	dm_block_t old_oblock;
	dm_block_t new_oblock;
	dm_block_t cblock;

	struct dm_bio_prison_cell *old_ocell;
	struct dm_bio_prison_cell *new_ocell;
};

static void build_key(dm_block_t block, struct cell_key *key)
{
	key->virtual = 0;
	key->dev = 0;
	key->block = block;
}

static void wake_worker(struct cache_c *c)
{
	queue_work(c->wq, &c->worker);
}

/*----------------------------------------------------------------
 * Remapping
 *--------------------------------------------------------------*/
static void remap_to_origin(struct cache_c *c, struct bio *bio)
{
	unsigned long flags;
	struct dm_cache_endio_hook *h = dm_get_mapinfo(bio)->ptr;

	// FIXME: I don't like this side effect here
	spin_lock_irqsave(&c->lock, flags);
	if (c->need_tick_bio && !(bio->bi_rw & (REQ_FUA | REQ_FLUSH | REQ_DISCARD))) {
		h->tick = true;
		c->need_tick_bio = false;
	}
	spin_unlock_irqrestore(&c->lock, flags);

	bio->bi_bdev = c->origin_dev->bdev;
}

static void remap_to_cache(struct cache_c *c, struct bio *bio,
			   dm_block_t cblock)
{
	bio->bi_bdev = c->cache_dev->bdev;
	bio->bi_sector = (cblock << c->block_shift) + (bio->bi_sector & c->offset_mask);
}

static void remap_to_origin_dirty(struct cache_c *c, struct bio *bio, dm_block_t oblock)
{
	ra_add_to_slot(&c->miss_volume, bio->bi_size);

	remap_to_origin(c, bio);
	if (bio_data_dir(bio) == WRITE)
		set_bit(oblock, c->discard_bitset);
}

static void remap_to_cache_dirty(struct cache_c *c, struct bio *bio,
				 dm_block_t oblock, dm_block_t cblock)
{
	ra_add_to_slot(&c->hit_volume, bio->bi_size);

	remap_to_cache(c, bio, cblock);
	if (bio_data_dir(bio) == WRITE)
		set_bit(oblock, c->discard_bitset);
}

static dm_block_t get_bio_block(struct cache_c *c, struct bio *bio)
{
	return bio->bi_sector >> c->block_shift;
}

static int bio_triggers_commit(struct cache_c *c, struct bio *bio)
{
	return (bio->bi_rw & (REQ_FLUSH | REQ_FUA)) &&
		dm_cache_changed_this_transaction(c->cmd);
}


static void issue(struct cache_c *c, struct bio *bio)
{
	unsigned long flags;

	if (bio_triggers_commit(c, bio)) {
		spin_lock_irqsave(&c->lock, flags);
		bio_list_add(&c->deferred_flush_bios, bio);
		spin_unlock_irqrestore(&c->lock, flags);
	} else
		generic_make_request(bio);
}

/*----------------------------------------------------------------
 * Migration processing
 *
 * Migration covers moving data from the origin device to the cache, or
 * vice versa.
 *--------------------------------------------------------------*/
#define MIGRATION_INC 1024
#define MIGRATION_FACTOR 1024

static int prealloc_migration(struct cache_c *c)
{
	if (c->next_migration)
		return 0;

	c->next_migration = mempool_alloc(c->migration_pool, GFP_ATOMIC);
	return c->next_migration ? 0 : -ENOMEM;
}

static struct dm_cache_migration *alloc_migration(struct cache_c *c)
{
	struct dm_cache_migration *r = c->next_migration;

	BUG_ON(!r);
	c->next_migration = NULL;

	return r;
}

static void free_migration(struct cache_c *c, struct dm_cache_migration *mg)
{
	mempool_free(mg, c->migration_pool);
}

static void inc_nr_migrations(struct cache_c *c)
{
	ra_add_to_slot(&c->migration_count, MIGRATION_INC);
#if 0
	pr_alert("migrations per second * 1024 = %llu, total_migrations * 1024 = %llu\n",
		 (unsigned long long) ra_average_per_second(&c->migration_count),
		 (unsigned long long) ra_total(&c->migration_count));
#endif
	atomic_inc(&c->nr_migrations);
	wake_up(&c->migration_wait);
}

static void dec_nr_migrations(struct cache_c *c)
{
	atomic_dec(&c->nr_migrations);
	wake_up(&c->migration_wait);
}

static void __cell_defer(struct cache_c *c, struct dm_bio_prison_cell *cell, bool holder)
{
	(holder ? cell_release : cell_release_no_holder)(cell, &c->deferred_bios);
}

static void cell_defer(struct cache_c *c, struct dm_bio_prison_cell *cell, bool holder)
{
	unsigned long flags;

	spin_lock_irqsave(&c->lock, flags);
	__cell_defer(c, cell, holder);
	spin_unlock_irqrestore(&c->lock, flags);

	wake_worker(c);
}

static void cleanup_migration(struct cache_c *c, struct dm_cache_migration *mg)
{
	unsigned long duration = elapsed(mg->start_jiffies, jiffies);

	free_migration(c, mg);
	dec_nr_migrations(c);

	ra_add_to_slot(&c->migration_time, duration);
	ra_next_slot(&c->migration_time);
}

static void migration_failure(struct cache_c *c, struct dm_cache_migration *mg)
{
	if (mg->demote) {
		DMWARN("demotion failed; couldn't copy block");
		policy_force_mapping(c->policy, mg->new_oblock, mg->old_oblock);

		cell_defer(c, mg->old_ocell, mg->promote ? 0 : 1);
		if (mg->promote)
			cell_defer(c, mg->new_ocell, 1);
	} else {
		DMWARN("promotion failed; couldn't copy block");
		policy_remove_mapping(c->policy, mg->new_oblock);
		cell_defer(c, mg->new_ocell, 1);
	}

	cleanup_migration(c, mg);
}

static void migration_success(struct cache_c *c, struct dm_cache_migration *mg)
{
	unsigned long flags;

	if (mg->demote) {
		cell_defer(c, mg->old_ocell, mg->promote ? 0 : 1);

		if (dm_cache_remove_mapping(c->cmd, mg->old_oblock)) {
			DMWARN("demotion failed; couldn't update on disk metadata");
			policy_force_mapping(c->policy, mg->new_oblock,	mg->old_oblock);
			if (mg->promote)
				cell_defer(c, mg->new_ocell, 1);
			cleanup_migration(c, mg);
			return;
		}

		if (mg->promote) {
			mg->demote = false;

			spin_lock_irqsave(&c->lock, flags);
			list_add(&mg->list, &c->quiesced_migrations);
			spin_unlock_irqrestore(&c->lock, flags);
		} else
			cleanup_migration(c, mg);

	} else {
		cell_defer(c, mg->new_ocell, 1);

		if (dm_cache_insert_mapping(c->cmd, mg->new_oblock, mg->cblock)) {
			DMWARN("promotion failed; couldn't update on disk metadata");
			policy_remove_mapping(c->policy, mg->new_oblock);
		}

		cleanup_migration(c, mg);
	}
}

static void copy_complete(int read_err, unsigned long write_err, void *context)
{
	unsigned long flags;
	struct dm_cache_migration *mg = (struct dm_cache_migration *) context;
	struct cache_c *c = mg->c;

	if (read_err || write_err)
		mg->err = true;

	spin_lock_irqsave(&c->lock, flags);
	list_add(&mg->list, &c->completed_migrations);
	spin_unlock_irqrestore(&c->lock, flags);

	wake_worker(c);
}

static void issue_copy_real(struct cache_c *c, struct dm_cache_migration *mg)
{
	int r;
	struct dm_io_region o_region, c_region;

	o_region.bdev = c->origin_dev->bdev;
	o_region.count = c->sectors_per_block;

	c_region.bdev = c->cache_dev->bdev;
	c_region.sector = mg->cblock * c->sectors_per_block;
	c_region.count = c->sectors_per_block;

	if (mg->demote) {
		/* demote */
		debug("issuing copy for demotion %lu\n", (unsigned long) mg->old_oblock);
		o_region.sector = mg->old_oblock * c->sectors_per_block;
		r = dm_kcopyd_copy(c->copier, &c_region, 1, &o_region, 0, copy_complete, mg);
	} else {
		/* promote */
		debug("issuing copy for promotion %lu\n", (unsigned long) mg->new_oblock);
		o_region.sector = mg->new_oblock * c->sectors_per_block;
		r = dm_kcopyd_copy(c->copier, &o_region, 1, &c_region, 0, copy_complete, mg);
	}

	if (r < 0)
		migration_failure(c, mg);
}

static void issue_copy_maybe(struct cache_c *c, struct dm_cache_migration *mg, dm_block_t bit)
{
	if (!test_bit(bit, c->discard_bitset)) {
		atomic_inc(&c->copies_avoided);
		migration_success(c, mg);
	} else
		issue_copy_real(c, mg);
}

static void issue_copy(struct cache_c *c, struct dm_cache_migration *mg)
{
	if (mg->demote)
		issue_copy_maybe(c, mg, mg->old_oblock);
	else
		issue_copy_maybe(c, mg, mg->new_oblock);
}

static void complete_migration(struct cache_c *c, struct dm_cache_migration *mg)
{
	if (mg->err)
		migration_failure(c, mg);
	else
		migration_success(c, mg);
}

static void process_migrations(struct cache_c *cache, struct list_head *head,
			       void (*fn)(struct cache_c *, struct dm_cache_migration *))
{
	unsigned long flags;
	struct list_head list;
	struct dm_cache_migration *mg, *tmp;

	INIT_LIST_HEAD(&list);
	spin_lock_irqsave(&cache->lock, flags);
	list_splice_init(head, &list);
	spin_unlock_irqrestore(&cache->lock, flags);

	list_for_each_entry_safe(mg, tmp, &list, list)
		fn(cache, mg);
}

static void __queue_quiesced_migration(struct cache_c *c, struct dm_cache_migration *mg)
{
	list_add_tail(&mg->list, &c->quiesced_migrations);
}

static void queue_quiesced_migration(struct cache_c *c, struct dm_cache_migration *mg)
{
	unsigned long flags;

	spin_lock_irqsave(&c->lock, flags);
	__queue_quiesced_migration(c, mg);
	spin_unlock_irqrestore(&c->lock, flags);

	wake_worker(c);
}

static void queue_quiesced_migrations(struct cache_c *c, struct list_head *work)
{
	unsigned long flags;
	struct dm_cache_migration *mg, *tmp;

	spin_lock_irqsave(&c->lock, flags);
	list_for_each_entry_safe(mg, tmp, work, list)
		__queue_quiesced_migration(c, mg);
	spin_unlock_irqrestore(&c->lock, flags);

	wake_worker(c);
}

static void check_for_quiesced_migrations(struct cache_c *c, struct dm_cache_endio_hook *h)
{
	struct list_head work;

	if (!h->all_io_entry)
		return;

	INIT_LIST_HEAD(&work);
	if (h->all_io_entry)
		ds_dec(h->all_io_entry, &work);

	if (!list_empty(&work))
		queue_quiesced_migrations(c, &work);
}

static void quiesce_migration(struct cache_c *c, struct dm_cache_migration *mg)
{
	if (!ds_add_work(c->all_io_ds, &mg->list))
		queue_quiesced_migration(c, mg);
}

static void promote(struct cache_c *c, dm_block_t oblock, dm_block_t cblock, struct dm_bio_prison_cell *cell)
{
	struct dm_cache_migration *mg = alloc_migration(c);

	mg->err = false;
	mg->demote = false;
	mg->promote = true;
	mg->c = c;
	mg->new_oblock = oblock;
	mg->cblock = cblock;
	mg->old_ocell = NULL;
	mg->new_ocell = cell;
	mg->start_jiffies = jiffies;

	inc_nr_migrations(c);
	quiesce_migration(c, mg);
}

static void writeback_then_promote(struct cache_c *c,
				   dm_block_t old_oblock,
				   dm_block_t new_oblock,
				   dm_block_t cblock,
				   struct dm_bio_prison_cell *old_ocell,
				   struct dm_bio_prison_cell *new_ocell)
{
	struct dm_cache_migration *mg = alloc_migration(c);

	mg->err = false;
	mg->demote = true;
	mg->promote = true;
	mg->c = c;
	mg->old_oblock = old_oblock;
	mg->new_oblock = new_oblock;
	mg->cblock = cblock;
	mg->old_ocell = old_ocell;
	mg->new_ocell = new_ocell;
	mg->start_jiffies = jiffies;

	inc_nr_migrations(c);
	quiesce_migration(c, mg);
}

/*----------------------------------------------------------------
 * bio processing
 *--------------------------------------------------------------*/
static void defer_bio(struct cache_c *cache, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_add(&cache->deferred_bios, bio);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}

static void process_flush_bio(struct cache_c *c, struct bio *bio)
{
	struct dm_cache_endio_hook *h = dm_get_mapinfo(bio)->ptr;

	BUG_ON(bio->bi_size);
	if (h->req_nr == 0)
		remap_to_origin(c, bio);
	else
		remap_to_cache(c, bio, 0);

	issue(c, bio);
}

#if 0
static bool covers_block(struct cache_c *c, struct bio *bio)
{
	return !(bio->bi_sector & c->offset_mask) &&
		(bio->bi_size == (c->sectors_per_block << SECTOR_SHIFT));
}
#endif

static void process_discard_bio(struct cache_c *c, struct bio *bio)
{
#if 0
	int r;
	struct cell_key key;
	struct policy_result lookup_result;
	dm_block_t block = get_bio_block(c, bio);
	struct endio_hook *h = dm_get_mapinfo(bio)->ptr;

	/*
	 * Check to see if that block is currently migrating.
	 */
	build_key(block, &key);
	r = bio_detain_if_occupied(c->prison, &key, bio);
	if (r > 0)
		return;

	policy_map(c->policy, block, bio_data_dir(bio), 0, 0, bio, &lookup_result);
	switch (lookup_result.op) {
	case POLICY_HIT:
		h->all_io_entry = ds_inc(c->all_io_ds);
		remap_to_cache(c, bio, lookup_result.cblock);
		issue(c, bio);
		break;

	case POLICY_MISS:
		h->all_io_entry = ds_inc(c->all_io_ds);
		remap_to_origin(c, bio);
		issue(c, bio);
		break;

	default:
		BUG();
	}

	if (covers_block(c, bio))
		clear_bit(block, c->discard_bitset);
#else
	/*
	 * No passdown.
	 */
	dm_block_t start_block = dm_div_up(bio->bi_sector, c->sectors_per_block);
	dm_block_t end_block = bio->bi_sector + bio_sectors(bio);
	dm_block_t b;

	do_div(end_block, c->sectors_per_block);

	for (b = start_block; b < end_block; b++) {
		//pr_alert("discarding block %lu\n", (unsigned long) b);
		clear_bit(b, c->discard_bitset);
	}

	bio_endio(bio, 0);
#endif
}

/*
 * FIXME: this is just thinking out loud, tidy up later.
 *
 * Migrating a block to the cache has various costs associated with it:
 *
 * i) A read to the origin, followed by a write to the cache.  Reducing the
 * bandwidth of each.
 *
 * ii) A latency hit, io to the old _and_ new oblock get stalled until the
 * migration is complete.
 *
 * iii) Hits to the old_oblock now go to the origin.
 *
 * The benefits:
 *
 * iv) Hits to the new_oblock now got to the cache
 *
 * [Ignoring the latency aspect]
 *
 * In practise, blocks are only temporarily resident on the cache, let's
 * call this period t_resident (on average).
 *
 * The policy decides whether another block would be better in the cache.
 * Here we're trying to decide if now would be a good moment to actually do
 * the migration.  We also throttle migrations at this point; the policy
 * assumes they're instant.
 *
 * Let's address the throttling issue first:
 *
 * [Assuming uniform io access pattern, address changing ones later]
 *
 * t_resident should be long enough to have a payoff.
 * t_resident >= migration_io / (hit_rate * io_per_second)
 * hit_rate needs to take into account the size of the bios.
 */
static bool migrations_allowed(struct cache_c *c)
{
#if 0
	uint64_t migration_io = c->sectors_per_block * 2;
	uint64_t expected_migrations = c->cache_size * migration_io *
		(ra_average(&c->hit_volume) + ra_average(&c->miss_volume)) /
		ra_average(&c->hit_volume);

	// uint64_t actual_migrations = ra_total(&c->migrations);

	pr_alert("hit_volume %llu, miss_volume %llu, expected_migrations = %llu\n",
		 (unsigned long long) ra_average(&c->hit_volume),
		 (unsigned long long) ra_average(&c->miss_volume),
		 (unsigned long long) expected_migrations);
	return true;
#else
	uint64_t target = MIGRATION_INC * c->cache_size / MIGRATION_FACTOR;
	uint64_t migrations_per_second = ra_average_per_second(&c->migration_count);

	if (target == 0)
		target = 1;

	return (atomic_read(&c->nr_migrations) < 30) && (migrations_per_second < target);
#endif
}

static void process_bio(struct cache_c *c, struct bio *bio)
{
	int r;
	int release_cell = 1;
	struct cell_key key;
	dm_block_t block = get_bio_block(c, bio);
	struct dm_bio_prison_cell *old_ocell, *new_ocell;
	struct policy_result lookup_result;
	struct dm_cache_endio_hook *h = dm_get_mapinfo(bio)->ptr;
	bool cheap_copy = !test_bit(block, c->discard_bitset);
	bool can_migrate = migrations_allowed(c);

	/*
	 * Check to see if that block is currently migrating.
	 */
	build_key(block, &key);
	r = bio_detain(c->prison, &key, bio, &new_ocell);
	if (r > 0)
		return;

	policy_map(c->policy, block, bio_data_dir(bio), can_migrate, cheap_copy, bio, &lookup_result);
	switch (lookup_result.op) {
	case POLICY_HIT:
		debug("hit %lu -> %lu (process_bio)\n",
		      (unsigned long) block,
		      (unsigned long) lookup_result.cblock);
		atomic_inc(bio_data_dir(bio) == READ ? &c->read_hit : &c->write_hit);
		h->all_io_entry = ds_inc(c->all_io_ds);
		remap_to_cache_dirty(c, bio, block, lookup_result.cblock);
		issue(c, bio);
		break;

	case POLICY_MISS:
		debug("miss %lu (process_bio)\n",
		      (unsigned long) block);
		atomic_inc(bio_data_dir(bio) == READ ? &c->read_miss : &c->write_miss);
		h->all_io_entry = ds_inc(c->all_io_ds);
		remap_to_origin_dirty(c, bio, block);
		issue(c, bio);
		break;

	case POLICY_NEW:
		debug("promote %lu -> %lu (process_bio)\n",
		      (unsigned long) block,
		      (unsigned long) lookup_result.cblock);
		atomic_inc(&c->promotion);
		promote(c, block, lookup_result.cblock, new_ocell);
		release_cell = 0;
		break;

	case POLICY_REPLACE:
		build_key(lookup_result.old_oblock, &key);
		r = bio_detain(c->prison, &key, bio, &old_ocell);
		if (r > 0) {
			/*
			 * We have to be careful to avoid lock inversion of
			 * the cells.  So we back off, and wait for the
			 * old_ocell to become free.
			 */
			policy_force_mapping(c->policy, block,
					     lookup_result.old_oblock);
			pr_alert("cache cell clash, backing off\n");
			break;
		}
		atomic_inc(&c->demotion);
		atomic_inc(&c->promotion);

		writeback_then_promote(c, lookup_result.old_oblock, block,
				       lookup_result.cblock,
				       old_ocell, new_ocell);
		release_cell = 0;
		break;
	}

	if (release_cell)
		cell_defer(c, new_ocell, 0);
}

static int need_commit_due_to_time(struct cache_c *c)
{
	return jiffies < c->last_commit_jiffies ||
	       jiffies > c->last_commit_jiffies + COMMIT_PERIOD;
}

static void process_deferred_bios(struct cache_c *c)
{
	unsigned long flags;
	struct bio_list bios;
	struct bio *bio;

	bio_list_init(&bios);

	spin_lock_irqsave(&c->lock, flags);
	bio_list_merge(&bios, &c->deferred_bios);
	bio_list_init(&c->deferred_bios);
	spin_unlock_irqrestore(&c->lock, flags);

	while ((bio = bio_list_pop(&bios))) {
		/*
		 * If we've got no free migration structs, and processing
		 * this bio might require one, we pause until there are some
		 * prepared mappings to process.
		 */
		if (prealloc_migration(c)) {
			spin_lock_irqsave(&c->lock, flags);
			bio_list_merge(&c->deferred_bios, &bios);
			spin_unlock_irqrestore(&c->lock, flags);

			break;
		}

		if (bio->bi_rw & REQ_FLUSH)
			process_flush_bio(c, bio);

		else if (bio->bi_rw & REQ_DISCARD)
			process_discard_bio(c, bio);

		else
			process_bio(c, bio);
	}
}

static void process_deferred_flush_bios(struct cache_c *c)
{
	unsigned long flags;
	struct bio_list bios;
	struct bio *bio;

	bio_list_init(&bios);

	spin_lock_irqsave(&c->lock, flags);
	bio_list_merge(&bios, &c->deferred_flush_bios);
	bio_list_init(&c->deferred_flush_bios);
	spin_unlock_irqrestore(&c->lock, flags);

	if (bio_list_empty(&bios) && !need_commit_due_to_time(c))
		return;

	if (dm_cache_commit(c->cmd)) {
		while ((bio = bio_list_pop(&bios)))
			bio_io_error(bio);
		return;
	}
	c->last_commit_jiffies = jiffies;

	while ((bio = bio_list_pop(&bios)))
		generic_make_request(bio);
}

/*----------------------------------------------------------------
 * Main worker loop
 *--------------------------------------------------------------*/
static void start_quiescing(struct cache_c *c)
{
	unsigned long flags;

	spin_lock_irqsave(&c->lock, flags);
	c->quiescing = 1;
	spin_unlock_irqrestore(&c->lock, flags);
}

static void stop_quiescing(struct cache_c *c)
{
	unsigned long flags;

	spin_lock_irqsave(&c->lock, flags);
	c->quiescing = 0;
	spin_unlock_irqrestore(&c->lock, flags);
}

static bool is_quiescing(struct cache_c *c)
{
	int r;
	unsigned long flags;

	spin_lock_irqsave(&c->lock, flags);
	r = c->quiescing;
	spin_unlock_irqrestore(&c->lock, flags);

	return r;
}

static void wait_for_migrations(struct cache_c *c)
{
	wait_event(c->migration_wait, atomic_read(&c->nr_migrations) == 0);
}

static void stop_worker(struct cache_c *c)
{
	cancel_delayed_work(&c->waker);
	flush_workqueue(c->wq);
}

static void requeue_deferred_io(struct cache_c *c)
{
	struct bio *bio;
	struct bio_list bios;

	bio_list_init(&bios);
	bio_list_merge(&bios, &c->deferred_bios);
	bio_list_init(&c->deferred_bios);

	while ((bio = bio_list_pop(&bios)))
		bio_endio(bio, DM_ENDIO_REQUEUE);
}

static int more_work(struct cache_c *c)
{
	if (is_quiescing(c))
		return !list_empty(&c->quiesced_migrations) ||
			!list_empty(&c->completed_migrations);
	else
		return !bio_list_empty(&c->deferred_bios) ||
			!bio_list_empty(&c->deferred_flush_bios) ||
			!list_empty(&c->quiesced_migrations) ||
			!list_empty(&c->completed_migrations);
}

static void do_work(struct work_struct *ws)
{
	struct cache_c *c = container_of(ws, struct cache_c, worker);

	do {
		if (is_quiescing(c)) {
			process_migrations(c, &c->quiesced_migrations, issue_copy);
			process_migrations(c, &c->completed_migrations, complete_migration);
		} else {
			process_deferred_bios(c);
			process_migrations(c, &c->quiesced_migrations, issue_copy);
			process_migrations(c, &c->completed_migrations, complete_migration);
			process_deferred_flush_bios(c);

			ra_next_slot(&c->hit_volume);
			ra_next_slot(&c->miss_volume);
		}

	} while (more_work(c));
}

/*
 * We want to commit periodically so that not too much
 * unwritten data builds up.
 */
static void do_waker(struct work_struct *ws)
{
	struct cache_c *c = container_of(to_delayed_work(ws), struct cache_c, waker);
	ra_next_slot(&c->migration_count);
	wake_worker(c);
	queue_delayed_work(c->wq, &c->waker, COMMIT_PERIOD);
}

/*----------------------------------------------------------------*/

static int is_congested(struct dm_dev *dev, int bdi_bits)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);
	return bdi_congested(&q->backing_dev_info, bdi_bits);
}

static int cache_is_congested(struct dm_target_callbacks *cb, int bdi_bits)
{
	struct cache_c *cache = container_of(cb, struct cache_c, callbacks);

	return is_congested(cache->origin_dev, bdi_bits) ||
		is_congested(cache->cache_dev, bdi_bits);
}

/*----------------------------------------------------------------
 * Target methods
 *--------------------------------------------------------------*/

static void cache_dtr(struct dm_target *ti)
{
	struct cache_c *c = ti->private;

	pr_alert("dm-cache statistics:\n");
	pr_alert("read hits:\t%u\n", (unsigned) atomic_read(&c->read_hit));
	pr_alert("read misses:\t%u\n", (unsigned) atomic_read(&c->read_miss));
	pr_alert("write hits:\t%u\n", (unsigned) atomic_read(&c->write_hit));
	pr_alert("write misses:\t%u\n", (unsigned) atomic_read(&c->write_miss));
	pr_alert("demotions:\t%u\n", (unsigned) atomic_read(&c->demotion));
	pr_alert("promotions:\t%u\n", (unsigned) atomic_read(&c->promotion));
	pr_alert("copies avoided:\t%u\n", (unsigned) atomic_read(&c->copies_avoided));

	if (c->next_migration)
		mempool_free(c->next_migration, c->migration_pool);

	mempool_destroy(c->migration_pool);
	mempool_destroy(c->endio_hook_pool);
	ds_destroy(c->all_io_ds);
	prison_destroy(c->prison);
	destroy_workqueue(c->wq);
	free_bitset(c->discard_bitset);
	rolling_average_exit(&c->hit_volume);
	rolling_average_exit(&c->miss_volume);
	rolling_average_exit(&c->migration_time);
	rolling_average_exit(&c->migration_count);
	dm_kcopyd_client_destroy(c->copier);
	dm_cache_metadata_close(c->cmd);
	dm_put_device(ti, c->metadata_dev);
	dm_put_device(ti, c->origin_dev);
	dm_put_device(ti, c->cache_dev);
	dm_cache_policy_destroy(c->policy);

	kfree(c);
}

static sector_t get_dev_size(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

static int load_mapping(void *context, dm_block_t oblock, dm_block_t cblock)
{
	struct cache_c *c = context;
	return policy_load_mapping(c->policy, oblock, cblock);
}

static int parse_features(struct dm_arg_set *as, struct cache_c *c,
			  struct dm_target *ti)
{
	int r;
	unsigned argc;
	const char *arg_name;

	static struct dm_arg _args[] = {
		{0, 2, "Invalid number of feature args"},
		{0, UINT_MAX, "Invalid sequential bio nr"},
	};

	/* No feature arguments supplied. */
	if (!as->argc)
		return 0;

	r = dm_read_arg_group(_args, as, &argc, &ti->error);
	if (r)
		return r;

	while (argc) {
		arg_name = dm_shift_arg(as);
		argc--;

		/*
		 * seq_io_threshold <nr-ios>
		 * Number of sequential IOs after which an IO stream is
		 * considered sequential and caching is skipped.
		 */
		if (!strcasecmp(arg_name, "seq_io_threshold")) {
			if (!argc) {
				ti->error = "Feature seq_io_threshold requires parameters";
				return -EINVAL;
			}

			r = dm_read_arg(_args + 1, as, &c->seq_io_threshold, &ti->error);
			if (r)
				return r;
			argc--;
			continue;
		}

		ti->error = "Unrecognised cache feature requested";
		return -EINVAL;
	}

	return 0;
}

static struct kmem_cache *_migration_cache;
static struct kmem_cache *_endio_hook_cache;

/*
 * Construct a hierarchical storage device mapping:
 *
 * cache <metadata dev> <origin dev> <cache dev> <block size> <policy>
 * 			[<#feature args> [<arg>]*]
 *
 * metadata dev    : fast device holding the persistent metadata
 * origin dev	   : slow device holding original data blocks
 * cache dev	   : fast device holding cached data blocks
 * data block size : cache unit size in sectors
 * policy          : the replacement policy to use
 *
 * Feature args:
 * seq_io_threshold <number of sequential IO seen before caching stops >
 */
static int cache_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	sector_t block_size, origin_size;
	struct cache_c *c;
	char *end;
	struct dm_arg_set as;

	if (argc < 5) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	as.argc = argc;
	as.argv = argv;

	block_size = simple_strtoul(argv[3], &end, 10);
	if (block_size < BLOCK_SIZE_MIN ||
	    !is_power_of_2(block_size) || *end) {
		ti->error = "Invalid data block size argument";
		return -EINVAL;
	}

	c = ti->private = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c) {
		ti->error = "Error allocating cache context";
		return -ENOMEM;
	}
	c->ti = ti;

	r = dm_get_device(c->ti, argv[0], FMODE_READ | FMODE_WRITE, &c->metadata_dev);
	if (r) {
		ti->error = "Error opening metadata device";
		goto bad_metadata;
	}

	r = dm_get_device(c->ti, argv[1], FMODE_READ | FMODE_WRITE, &c->origin_dev);
	if (r) {
		ti->error = "Error opening origin device";
		goto bad_origin;
	}

	r = dm_get_device(c->ti, argv[2], FMODE_READ | FMODE_WRITE, &c->cache_dev);
	if (r) {
		ti->error = "Error opening cache device";
		goto bad_cache;
	}

	origin_size = get_dev_size(c->origin_dev);
	if (ti->len > origin_size) {
		ti->error = "Device size larger than cached device";
		goto bad;
	}

	c->origin_blocks = origin_size / block_size; /* FIXME: 64bit divide */
	c->sectors_per_block = block_size;
	c->offset_mask = block_size - 1;
	c->block_shift = ffs(block_size) - 1;

	if (dm_set_target_max_io_len(ti, c->sectors_per_block))
		goto bad;

	c->cmd = dm_cache_metadata_open(c->metadata_dev->bdev, block_size, 1);
	if (!c->cmd) {
		ti->error = "couldn't create cache metadata object";
		goto bad;
	}

	spin_lock_init(&c->lock);
	bio_list_init(&c->deferred_bios);
	bio_list_init(&c->deferred_flush_bios);
	INIT_LIST_HEAD(&c->quiesced_migrations);
	INIT_LIST_HEAD(&c->completed_migrations);
	atomic_set(&c->nr_migrations, 0);
	init_waitqueue_head(&c->migration_wait);
	rolling_average_init(&c->hit_volume, 2048); /* FIXME: magic number */
	rolling_average_init(&c->miss_volume, 2048);
	rolling_average_init(&c->migration_time, 2048);
	rolling_average_init(&c->migration_count, MIGRATION_COUNT_WINDOW); /* one sample per second */

	c->callbacks.congested_fn = cache_is_congested;
	dm_table_add_target_callbacks(ti->table, &c->callbacks);

	c->discard_bitset = alloc_bitset(c->origin_blocks, 1);
	if (!c->discard_bitset) {
		ti->error = "Couldn't allocate discard bitset";
		goto bad_alloc_bitset;
	}

	c->copier = dm_kcopyd_client_create();
	if (IS_ERR(c->copier)) {
		ti->error = "Couldn't create kcopyd client";
		goto bad_kcopyd_client;
	}

	c->wq = alloc_ordered_workqueue(DAEMON, WQ_MEM_RECLAIM);
	if (!c->wq) {
		ti->error = "couldn't create workqueue for metadata object";
		goto bad_wq;
	}
	INIT_WORK(&c->worker, do_work);
	INIT_DELAYED_WORK(&c->waker, do_waker);

	c->prison = prison_create(PRISON_CELLS);
	if (!c->prison) {
		ti->error = "couldn't create bio prison";
		goto bad_prison;
	}

	c->all_io_ds = ds_create();
	if (!c->all_io_ds) {
		ti->error = "couldn't create all_io deferred set";
		goto bad_deferred_set;
	}

	c->endio_hook_pool = mempool_create_slab_pool(ENDIO_HOOK_POOL_SIZE,
						      _endio_hook_cache);
	if (!c->endio_hook_pool) {
		ti->error = "Error creating cache's endio_hook mempool";
		goto bad_endio_hook_pool;
	}

	c->migration_pool = mempool_create_slab_pool(MIGRATION_POOL_SIZE,
						     _migration_cache);
	if (!c->migration_pool) {
		ti->error = "Error creating cache's endio_hook mempool";
		goto bad_migration_pool;
	}

	c->cache_size = get_dev_size(c->cache_dev) >> c->block_shift;
	c->policy = dm_cache_policy_create(argv[4], c->cache_size);
	if (!c->policy) {
		ti->error = "Error creating cache's policy";
		goto bad_cache_policy;
	}

	dm_consume_args(&as, 5);

	c->seq_io_threshold = 512;
	parse_features(&as, c, ti);
	policy_set_seq_io_threshold(c->policy, c->seq_io_threshold);

	c->quiescing = 0;
	c->last_commit_jiffies = jiffies;

	atomic_set(&c->read_hit, 0);
	atomic_set(&c->read_miss, 0);
	atomic_set(&c->write_hit, 0);
	atomic_set(&c->write_miss, 0);
	atomic_set(&c->demotion, 0);
	atomic_set(&c->promotion, 0);
	atomic_set(&c->copies_avoided, 0);

	r = dm_cache_load_mappings(c->cmd, load_mapping, c);
	if (r) {
		ti->error = "couldn't load cache mappings";
		goto bad_load_mappings;
	}

	ti->num_flush_requests = 2;
	ti->flush_supported = true;

	ti->num_discard_requests = 1;
	ti->discards_supported = true;
	return 0;

bad_load_mappings:
	dm_cache_policy_destroy(c->policy);
bad_cache_policy:
	mempool_destroy(c->migration_pool);
bad_migration_pool:
	mempool_destroy(c->endio_hook_pool);
bad_endio_hook_pool:
	ds_destroy(c->all_io_ds);
bad_deferred_set:
	prison_destroy(c->prison);
bad_prison:
	destroy_workqueue(c->wq);
bad_wq:
	dm_kcopyd_client_destroy(c->copier);
bad_kcopyd_client:
	free_bitset(c->discard_bitset);
bad_alloc_bitset:
	dm_cache_metadata_close(c->cmd);
bad:
	dm_put_device(ti, c->cache_dev);
bad_cache:
	dm_put_device(ti, c->origin_dev);
bad_origin:
	dm_put_device(ti, c->metadata_dev);
bad_metadata:
	kfree(c);
	return -EINVAL;
}

static struct dm_cache_endio_hook *hook_endio(struct cache_c *c, struct bio *bio, unsigned req_nr)
{
	struct dm_cache_endio_hook *h = mempool_alloc(c->endio_hook_pool, GFP_NOIO);

	h->tick = false;
	h->req_nr = req_nr;
	h->all_io_entry = NULL;

	return h;
}

static int cache_map(struct dm_target *ti, struct bio *bio,
		   union map_info *map_context)
{
#if 0
	int need_defer;
	struct cell_key key;
	struct cache_c *c = ti->private;
	dm_block_t block = get_bio_block(c, bio);
	struct arc_result lookup_result;

	map_context->ptr = hook_endio(c, bio);

	build_key(block, &key);
	if (bio_detain_if_occupied(c->prison, &key, bio))
		/* This block is busy, data moving around */
		return DM_MAPIO_SUBMITTED;

	need_defer = arc_quick_map(c->policy, block, &lookup_result);
	if (need_defer) {
		defer_bio(c, bio);
		return DM_MAPIO_SUBMITTED;
	}

	switch (lookup_result.op) {
	case ARC_HIT:
		debug("hit (cache_map)\n");
		remap_to_cache(c, bio, lookup_result.cblock);
		break;

	case ARC_MISS:
		debug("miss (cache_map)\n");
		remap_to_origin(c, bio);
		break;

	default:
		BUG();
	}

	return DM_MAPIO_REMAPPED;
#else
	struct cache_c *c = ti->private;
	map_context->ptr = hook_endio(c, bio, map_context->target_request_nr);
	defer_bio(c, bio);
	return DM_MAPIO_SUBMITTED;
#endif
}

static int cache_end_io(struct dm_target *ti, struct bio *bio,
			int error, union map_info *info)
{
	struct cache_c *c = ti->private;
	unsigned long flags;
	struct dm_cache_endio_hook *h = info->ptr;

	if (h->tick) {
		policy_tick(c->policy);

		spin_lock_irqsave(&c->lock, flags);
		c->need_tick_bio = true;
		spin_unlock_irqrestore(&c->lock, flags);
	}

	check_for_quiesced_migrations(c, h);
	mempool_free(h, c->endio_hook_pool);
	return 0;
}

static void cache_postsuspend(struct dm_target *ti)
{
	struct cache_c *c = ti->private;

	start_quiescing(c);
	wait_for_migrations(c);
	stop_worker(c);
	requeue_deferred_io(c);
	stop_quiescing(c);
}

static void cache_resume(struct dm_target *ti)
{
	struct cache_c *c = ti->private;
	c->need_tick_bio = true;
	do_waker(&c->waker.work);
}

static int cache_status(struct dm_target *ti, status_type_t type,
			unsigned status_flags, char *result, unsigned maxlen)
{
	ssize_t sz = 0;
	char buf[BDEVNAME_SIZE];
	struct cache_c *c = ti->private;
	dm_block_t residency;

	switch (type) {
	case STATUSTYPE_INFO:
		residency = policy_residency(c->policy);

		DMEMIT("%u %u %u %u %u %u %llu",
		       (unsigned) atomic_read(&c->read_hit),
		       (unsigned) atomic_read(&c->read_miss),
		       (unsigned) atomic_read(&c->write_hit),
		       (unsigned) atomic_read(&c->write_miss),
		       (unsigned) atomic_read(&c->demotion),
		       (unsigned) atomic_read(&c->promotion),
		       (unsigned long long) residency);
		break;

	case STATUSTYPE_TABLE:
		format_dev_t(buf, c->metadata_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
		format_dev_t(buf, c->origin_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
		format_dev_t(buf, c->cache_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
		DMEMIT("%llu ", (unsigned long long) c->sectors_per_block);
		DMEMIT("%s", dm_cache_policy_get_name(c->policy));
	}

	return 0;
}

static int cache_iterate_devices(struct dm_target *ti,
				 iterate_devices_callout_fn fn, void *data)
{
	int r = 0;
	struct cache_c *c = ti->private;

	r = fn(ti, c->cache_dev, 0, get_dev_size(c->cache_dev), data);
	if (!r)
		r = fn(ti, c->origin_dev, 0, ti->len, data);

	return r;
}

static int cache_bvec_merge(struct dm_target *ti,
			  struct bvec_merge_data *bvm,
			  struct bio_vec *biovec, int max_size)
{
	struct cache_c *c = ti->private;
	struct request_queue *q = bdev_get_queue(c->origin_dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = c->origin_dev->bdev;
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static void set_discard_limits(struct cache_c *c, struct queue_limits *limits)
{
	/*
	 * FIXME: these limits may be incompatible with the cache's data device
	 */
	limits->max_discard_sectors = c->sectors_per_block * 1024;

	/*
	 * This is just a hint, and not enforced.  We have to cope with
	 * bios that cover a block partially.  A discard that spans a block
	 * boundary is not sent to this target.
	 */
	limits->discard_granularity = c->sectors_per_block << SECTOR_SHIFT;
	limits->discard_zeroes_data = 0;
}

static void cache_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct cache_c *c = ti->private;

	blk_limits_io_min(limits, 0);
	blk_limits_io_opt(limits, c->sectors_per_block << SECTOR_SHIFT);
	set_discard_limits(c, limits);
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

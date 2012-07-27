/*
 * Copyright (C) 2012 Red Hat GmbH. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "dm.h"
#include "dm-bio-prison.h"

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

//#define debug(x...) pr_alert(x)
#define debug(x...) ;

/*----------------------------------------------------------------*/

struct queue {
	unsigned size;
	struct list_head elts;
};

static void queue_init(struct queue *q)
{
	q->size = 0;
	INIT_LIST_HEAD(&q->elts);
}

static unsigned queue_size(struct queue *q)
{
	return q->size;
}

static bool queue_empty(struct queue *q)
{
	BUG_ON(q->size ? list_empty(&q->elts) : !list_empty(&q->elts));
	return !q->size;
}

static struct list_head *queue_pop(struct queue *q)
{
	struct list_head *r;

	BUG_ON(list_empty(&q->elts));
	r = q->elts.next;
	list_del(r);
	q->size--;

	return r;
}

static void queue_del(struct queue *q, struct list_head *elt)
{
	BUG_ON(!q->size);
	list_del(elt);
	q->size--;
}

static void queue_push(struct queue *q, struct list_head *elt)
{
	list_add_tail(elt, &q->elts);
	q->size++;
}

/*----------------------------------------------------------------*/

enum arc_state {
	ARC_B1,
	ARC_T1,
	ARC_B2,
	ARC_T2
};

struct arc_entry {
	enum arc_state state;
	struct hlist_node hlist;
	struct list_head list;
	dm_block_t oblock;
	dm_block_t cblock;
};

struct arc_policy {
	dm_block_t cache_size;

	spinlock_t lock;

	dm_block_t p;		/* the magic factor that balances lru vs lfu */
	struct queue b1, t1, b2, t2;

	/*
	 * We know exactly how many entries will be needed, so we can
	 * allocate them up front.
	 */
	struct arc_entry *entries;
	dm_block_t nr_allocated;

	unsigned nr_buckets;
	dm_block_t hash_mask;
	struct hlist_head *table;

	dm_block_t interesting_size;
	dm_block_t *interesting_blocks;
	dm_block_t last_lookup;
};

enum arc_operation {
	ARC_HIT,
	ARC_MISS,
	ARC_NEW,
	ARC_REPLACE
};

struct arc_result {
	enum arc_operation op;

	dm_block_t old_oblock;
	dm_block_t cblock;
};

static struct arc_policy *arc_create(dm_block_t cache_size)
{
	dm_block_t nr_buckets;
	struct arc_policy *a = kmalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return NULL;

	a->cache_size = cache_size;
	spin_lock_init(&a->lock);
	a->p = 0;

	queue_init(&a->b1);
	queue_init(&a->t1);
	queue_init(&a->b2);
	queue_init(&a->t2);

	a->entries = vmalloc(sizeof(*a->entries) * 2 * cache_size);
	if (!a->entries) {
		kfree(a);
		return NULL;
	}

	a->nr_allocated = 0;

	a->nr_buckets = cache_size / 8;
	nr_buckets = 16;
	while (nr_buckets < a->nr_buckets)
		nr_buckets <<= 1;
	a->nr_buckets = nr_buckets;

	a->hash_mask = a->nr_buckets - 1;
	a->table = kzalloc(sizeof(*a->table) * a->nr_buckets, GFP_KERNEL);
	if (!a->table) {
		vfree(a->entries);
		kfree(a);
		return NULL;
	}

	a->interesting_size = cache_size / 8;
	a->interesting_blocks = vzalloc(sizeof(*a->interesting_blocks) * a->interesting_size);
	if (!a->interesting_blocks) {
		kfree(a->table);
		vfree(a->entries);
		kfree(a);
	}

	return a;
}

static void arc_destroy(struct arc_policy *a)
{
	vfree(a->interesting_blocks);
	kfree(a->table);
	vfree(a->entries);
	kfree(a);
}

static unsigned hash(struct arc_policy *a, dm_block_t b)
{
	const dm_block_t BIG_PRIME = 4294967291UL;
	dm_block_t h = b * BIG_PRIME;

	return (uint32_t) (h & a->hash_mask);
}

static void __arc_insert(struct arc_policy *a, struct arc_entry *e)
{
	unsigned h = hash(a, e->oblock);
	hlist_add_head(&e->hlist, a->table + h);
}

static struct arc_entry *__arc_lookup(struct arc_policy *a, dm_block_t origin)
{
	unsigned h = hash(a, origin);
	struct hlist_head *bucket = a->table + h;
	struct hlist_node *tmp;
	struct arc_entry *e;

	hlist_for_each_entry(e, tmp, bucket, hlist)
		if (e->oblock == origin)
			return e;

	return NULL;
}

static void __arc_remove(struct arc_policy *a, struct arc_entry *e)
{
	hlist_del(&e->hlist);
}

/*
 * This sets up the e->cache field.
 */
static struct arc_entry *__arc_alloc_entry(struct arc_policy *a)
{
	struct arc_entry *e;

	BUG_ON(a->nr_allocated >= 2 * a->cache_size);
	e = a->entries + a->nr_allocated;
	INIT_LIST_HEAD(&e->list);
	INIT_HLIST_NODE(&e->hlist);
	e->cblock = a->nr_allocated++;
	return e;
}

static bool __free_entries(struct arc_policy *a)
{
	return a->nr_allocated < a->cache_size;
}

static void __arc_push(struct arc_policy *a,
		     enum arc_state s, struct arc_entry *e)
{
	e->state = s;

	switch (s) {
	case ARC_T1:
		queue_push(&a->t1, &e->list);
		__arc_insert(a, e);
		break;

	case ARC_T2:
		queue_push(&a->t2, &e->list);
		__arc_insert(a, e);
		break;

	case ARC_B1:
		queue_push(&a->b1, &e->list);
		break;

	case ARC_B2:
		queue_push(&a->b2, &e->list);
		break;
	}
}

static struct arc_entry *__arc_pop(struct arc_policy *a, enum arc_state s)
{
	struct arc_entry *e = NULL;

#define POP(x) container_of(queue_pop(x), struct arc_entry, list)

	switch (s) {
	case ARC_T1:
		BUG_ON(queue_empty(&a->t1));
		e = POP(&a->t1);
		__arc_remove(a, e);
		break;

	case ARC_T2:
		BUG_ON(queue_empty(&a->t2));
		e = POP(&a->t2);
		__arc_remove(a, e);
		break;

	case ARC_B1:
		BUG_ON(queue_empty(&a->b1));
		e = POP(&a->b1);
		break;

	case ARC_B2:
		BUG_ON(queue_empty(&a->b2));
		e = POP(&a->b2);
		break;
	}

#undef POP

	return e;
}

/*
 * fe may be NULL.
 */
/* FIXME: replace fe with a bool */
static dm_block_t __arc_demote(struct arc_policy *a, struct arc_entry *fe, struct arc_result *result)
{
	struct arc_entry *e;
	dm_block_t t1_size = queue_size(&a->t1);

	result->op = ARC_REPLACE;

	if (t1_size &&
	    ((t1_size > a->p) || (fe && (fe->state == ARC_B2) && (t1_size == a->p)))) {
		e = __arc_pop(a, ARC_T1);

		result->old_oblock = e->oblock;
		result->cblock = e->cblock;

		__arc_push(a, ARC_B1, e);
	} else {
		e = __arc_pop(a, ARC_T2);

		result->old_oblock = e->oblock;
		result->cblock = e->cblock;

		__arc_push(a, ARC_B2, e);
	}

	return e->cblock;
}

/*
 * FIXME: the size of the interesting blocks hash table seems to be
 * directly related to the eviction rate.  So maybe we should resize on the
 * fly to get to a target eviction rate?
 */
static int __arc_interesting_block(struct arc_policy *a, dm_block_t origin, int data_dir)
{
	const dm_block_t BIG_PRIME = 4294967291UL;
	unsigned h = ((unsigned) (origin * BIG_PRIME)) % a->interesting_size;

	if (origin == a->last_lookup)
		return 0;

	if (a->interesting_blocks[h] == origin)
		return 1;

	a->interesting_blocks[h] = origin;
	return 0;
}

static void __arc_map(struct arc_policy *a,
		      dm_block_t origin_block,
		      int data_dir,
		      bool can_migrate,
		      bool cheap_copy,
		      struct arc_result *result)
{
	dm_block_t new_cache;
	dm_block_t delta;
	dm_block_t b1_size = queue_size(&a->b1);
	dm_block_t b2_size = queue_size(&a->b2);
	dm_block_t l1_size, l2_size;

	struct arc_entry *e;

	e = __arc_lookup(a, origin_block);
	if (e) {
		bool do_push = 1;

		switch (e->state) {
		case ARC_T1:
			result->op = ARC_HIT;
			result->cblock = e->cblock;
			if (a->last_lookup != origin_block) {
				queue_del(&a->t1, &e->list);
				__arc_remove(a, e);
			} else
				do_push = 0;
			break;

		case ARC_T2:
			result->op = ARC_HIT;
			result->cblock = e->cblock;
			if (a->last_lookup != origin_block) {
				queue_del(&a->t2, &e->list);
				__arc_remove(a, e);
			} else
				do_push = 0;
			break;

		case ARC_B1:
			if (!can_migrate) {
				result->op = ARC_MISS;
				return;
			}

			delta = (b1_size > b2_size) ? 1 : max(b2_size / b1_size, 1ULL);
			a->p = min(a->p + delta, a->cache_size);
			new_cache = __arc_demote(a, e, result);

			queue_del(&a->b1, &e->list);

			e->oblock = origin_block;
			e->cblock = new_cache;
			break;

		case ARC_B2:
			if (!can_migrate) {
				result->op = ARC_MISS;
				return;
			}

			delta = b2_size >= b1_size ? 1 : max(b1_size / b2_size, 1ULL);
			a->p = max(a->p - delta, 0ULL);
			new_cache = __arc_demote(a, e, result);

			queue_del(&a->b2, &e->list);

			e->oblock = origin_block;
			e->cblock = new_cache;
			break;
		}

		if (do_push)
			__arc_push(a, ARC_T2, e);
		return;
	}

	/* FIXME: this is turning into a huge mess */
	cheap_copy = cheap_copy && __free_entries(a);
	if (cheap_copy || (can_migrate && __arc_interesting_block(a, origin_block, data_dir))) {
		/* carry on, perverse logic */
	} else {
		result->op = ARC_MISS;
		return;
	}

	l1_size = queue_size(&a->t1) + b1_size;
	l2_size = queue_size(&a->t2) + b2_size;
	if (l1_size == a->cache_size) {
		if (!can_migrate)  {
			result->op = ARC_MISS;
			return;
		}

		if (queue_size(&a->t1) < a->cache_size) {
			e = __arc_pop(a, ARC_B1);

			new_cache = __arc_demote(a, NULL, result);
			e->oblock = origin_block;
			e->cblock = new_cache;

		} else {
			e = __arc_pop(a, ARC_T1);

			result->op = ARC_REPLACE;
			result->old_oblock = e->oblock;
			e->oblock = origin_block;
			result->cblock = e->cblock;
		}

	} else if (l1_size < a->cache_size && (l1_size + l2_size >= a->cache_size)) {
		if (!can_migrate)  {
			result->op = ARC_MISS;
			return;
		}

		if (l1_size + l2_size == 2 * a->cache_size) {
			e = __arc_pop(a, ARC_B2);
			e->oblock = origin_block;
			e->cblock = __arc_demote(a, NULL, result);

		} else {
			e = __arc_alloc_entry(a);
			e->oblock = origin_block;
			e->cblock = __arc_demote(a, NULL, result);
		}

	} else {
		e = __arc_alloc_entry(a);

		result->op = ARC_NEW;
		result->cblock = e->cblock;
		e->oblock = origin_block;
	}

	__arc_push(a, ARC_T1, e);
}

static void arc_map(struct arc_policy *a, dm_block_t origin_block, int data_dir,
		    bool can_migrate, bool cheap_copy, struct arc_result *result)
{
	unsigned long flags;

	spin_lock_irqsave(&a->lock, flags);
	__arc_map(a, origin_block, data_dir, can_migrate, cheap_copy, result);
	a->last_lookup = origin_block;
	spin_unlock_irqrestore(&a->lock, flags);
}

/*----------------------------------------------------------------*/

#define NR_TIMES 10

struct times {
	unsigned nr_times;
	unsigned slot;
	unsigned long total_durations;
	unsigned long starts[NR_TIMES];
	unsigned long durations[NR_TIMES];
};

static void times_init(struct times *ts)
{
	ts->nr_times = 0;
	ts->slot = 0;
	ts->total_durations = 0;
}

static void times_start(struct times *ts)
{
	ts->starts[ts->slot] = jiffies;
}

static unsigned long elapsed(unsigned long start, unsigned long end)
{
	if (start < end)
		return end + (ULONG_MAX - start);
	else
		return end - start;
}

static unsigned next_slot(unsigned s)
{
	s++;
	if (s == NR_TIMES)
		s = 0;
	return s;
}

static void times_end(struct times *ts)
{
	ts->total_durations -= ts->durations[ts->slot];
	ts->durations[ts->slot] = elapsed(ts->starts[ts->slot], jiffies);
	ts->total_durations += ts->durations[ts->slot];

	if (ts->nr_times < NR_TIMES)
		ts->nr_times++;

	ts->slot = next_slot(ts->slot);
}

/*
 * This curious interface avoids floating point math.
 */
static bool times_below_percentage(struct times *ts, unsigned percentage)
{
	if (!ts->nr_times)
		return true;
	else {
		unsigned start_slot = ts->nr_times < NR_TIMES ? 0 : next_slot(ts->slot);
		unsigned long period = elapsed(ts->starts[start_slot], jiffies);
		return ts->total_durations < ((period / 100) * percentage);
	}
}

/*----------------------------------------------------------------*/

/* Mechanism */

#define BLOCK_SIZE_MIN 64
#define DM_MSG_PREFIX "cache"
#define DAEMON "cached"
#define PRISON_CELLS 1024
#define ENDIO_HOOK_POOL_SIZE 1024
#define MIGRATION_POOL_SIZE 128

struct cache_c {
	struct dm_target *ti;

	struct dm_dev *origin_dev;
	struct dm_dev *cache_dev;
	struct dm_target_callbacks callbacks;

	dm_block_t origin_blocks;
	dm_block_t cache_size;
	sector_t sectors_per_block;
	sector_t offset_mask;
	unsigned int block_shift;

	spinlock_t lock;
	struct bio_list deferred_bios;
	struct list_head quiesced_migrations;
	atomic_t nr_migrations;
	struct times migration_times;
	unsigned long *dirty_bitset;

	struct dm_kcopyd_client *copier;
	struct workqueue_struct *wq;
	struct work_struct worker;

	struct bio_prison *prison;
	struct deferred_set *all_io_ds;

	mempool_t *endio_hook_pool;
	mempool_t *migration_pool;

	struct arc_policy *policy;

	atomic_t read_hit;
	atomic_t read_miss;
	atomic_t write_hit;
	atomic_t write_miss;
	atomic_t demotion;
	atomic_t promotion;
	atomic_t no_copy_promotion;
};

/* FIXME: can we lose this? */
struct endio_hook {
	struct deferred_entry *all_io_entry;
};

struct migration {
	struct list_head list;
	struct cache_c *c;

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
static void remap_to_origin(struct cache_c *c, struct bio *bio, dm_block_t oblock)
{
	set_bit(oblock, c->dirty_bitset);
	bio->bi_bdev = c->origin_dev->bdev;
}

static void remap_to_cache(struct cache_c *c, struct bio *bio,
			   dm_block_t oblock, dm_block_t cblock)
{
	set_bit(oblock, c->dirty_bitset);
	bio->bi_bdev = c->cache_dev->bdev;
	bio->bi_sector = (cblock << c->block_shift) + (bio->bi_sector & c->offset_mask);
}

static dm_block_t get_bio_block(struct cache_c *c, struct bio *bio)
{
	return bio->bi_sector >> c->block_shift;
}

static void issue(struct cache_c *cache, struct bio *bio)
{
	generic_make_request(bio);
}

/*----------------------------------------------------------------
 * Migration processing
 *
 * Migration covers moving data from the origin device to the cache, or
 * vice versa.
 *--------------------------------------------------------------*/
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

static void error_migration(struct migration *mg)
{
	unsigned long flags;
	struct cache_c *c = mg->c;

	spin_lock_irqsave(&c->lock, flags);
	if (mg->old_ocell)
		__cell_defer(c, mg->old_ocell, 0);
	__cell_defer(c, mg->new_ocell, 1);
	spin_unlock_irqrestore(&c->lock, flags);

	atomic_dec(&c->nr_migrations);
	times_end(&c->migration_times);
	mempool_free(mg, c->migration_pool);
	wake_worker(c);
}

static void copy_complete(int read_err, unsigned long write_err, void *context)
{
	unsigned long flags;
	struct migration *mg = (struct migration *) context;
	struct cache_c *c = mg->c;

	if (read_err || write_err) {
		error_migration(mg);
		return;
	}

	spin_lock_irqsave(&c->lock, flags);

	if (mg->old_ocell) {
		debug("copy_complete c(%lu) -> o(%lu)\n",
		      (unsigned long) mg->cblock,
		      (unsigned long) mg->old_oblock);
		__cell_defer(c, mg->old_ocell, 0);
		mg->old_ocell = NULL;
		list_add(&mg->list, &c->quiesced_migrations);
	} else {
		debug("copy_complete o(%lu) -> c(%lu)\n",
		      (unsigned long) mg->new_oblock,
		      (unsigned long) mg->cblock);
		__cell_defer(c, mg->new_ocell, 1);
		mempool_free(mg, c->migration_pool);
		atomic_dec(&c->nr_migrations);
		times_end(&c->migration_times);
	}

	spin_unlock_irqrestore(&c->lock, flags);
	wake_worker(c);
}

static void issue_copy(struct cache_c *c, struct migration *mg)
{
	int r;
	struct dm_io_region o_region, c_region;

	o_region.bdev = c->origin_dev->bdev;
	o_region.count = c->sectors_per_block;

	c_region.bdev = c->cache_dev->bdev;
	c_region.sector = mg->cblock * c->sectors_per_block;
	c_region.count = c->sectors_per_block;

	if (mg->old_ocell) {
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
		error_migration(mg);
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

static void __queue_quiesced_migration(struct cache_c *c, struct migration *mg)
{
	list_add_tail(&mg->list, &c->quiesced_migrations);
}

static void queue_quiesced_migration(struct cache_c *c, struct migration *mg)
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
	struct migration *mg, *tmp;

	spin_lock_irqsave(&c->lock, flags);
	list_for_each_entry_safe(mg, tmp, work, list)
		__queue_quiesced_migration(c, mg);
	spin_unlock_irqrestore(&c->lock, flags);

	wake_worker(c);
}

static void check_for_quiesced_migrations(struct cache_c *c, struct endio_hook *h)
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

static void quiesce_migration(struct cache_c *c, struct migration *mg)
{
	if (!ds_add_work(c->all_io_ds, &mg->list))
		queue_quiesced_migration(c, mg);
}

/* FIXME: we can't just block here, need to ensure the migration is allocated before we start processing a bio */
static void promote(struct cache_c *c, dm_block_t oblock, dm_block_t cblock, struct dm_bio_prison_cell *cell)
{
	struct migration *mg = mempool_alloc(c->migration_pool, GFP_NOIO);

	mg->c = c;
	mg->new_oblock = oblock;
	mg->cblock = cblock;
	mg->old_ocell = NULL;
	mg->new_ocell = cell;

	times_start(&c->migration_times);
	quiesce_migration(c, mg);
}

static void writeback_then_promote(struct cache_c *c,
				   dm_block_t old_oblock,
				   dm_block_t new_oblock,
				   dm_block_t cblock,
				   struct dm_bio_prison_cell *old_ocell,
				   struct dm_bio_prison_cell *new_ocell)
{
	struct migration *mg = mempool_alloc(c->migration_pool, GFP_NOIO);

	mg->c = c;
	mg->old_oblock = old_oblock;
	mg->new_oblock = new_oblock;
	mg->cblock = cblock;
	mg->old_ocell = old_ocell;
	mg->new_ocell = new_ocell;

	times_start(&c->migration_times);
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

static void process_bio(struct cache_c *c, struct bio *bio)
{
	int r;
	int release_cell = 1;
	struct cell_key key;
	dm_block_t block = get_bio_block(c, bio);
	struct dm_bio_prison_cell *old_ocell, *new_ocell;
	struct arc_result lookup_result;
	struct endio_hook *h = dm_get_mapinfo(bio)->ptr;
#if 0
	/*
	 * Use this branch if you want the no copy optimisation.  atm this
	 * means your origin must initially contain junk.
	 */
	bool cheap_copy = !test_bit(block, c->dirty_bitset);
#else
	bool cheap_copy = 0;
#endif

	bool can_migrate = (atomic_read(&c->nr_migrations) == 0) &&
		times_below_percentage(&c->migration_times, 100); /* FIXME: hard coded value */

	/*
	 * Check to see if that block is currently migrating.
	 */
	build_key(block, &key);
	r = bio_detain(c->prison, &key, bio, &new_ocell);
	if (r > 0)
		return;

	arc_map(c->policy, block, bio_data_dir(bio), can_migrate, cheap_copy, &lookup_result);
	switch (lookup_result.op) {
	case ARC_HIT:
		debug("hit %lu -> %lu (process_bio)\n",
		      (unsigned long) block,
		      (unsigned long) lookup_result.cblock);
		atomic_inc(bio_data_dir(bio) == READ ? &c->read_hit : &c->write_hit);
		h->all_io_entry = ds_inc(c->all_io_ds);
		remap_to_cache(c, bio, block, lookup_result.cblock);
		issue(c, bio);
		break;

	case ARC_MISS:
		debug("miss %lu (process_bio)\n",
		      (unsigned long) block);
		atomic_inc(bio_data_dir(bio) == READ ? &c->read_miss : &c->write_miss);
		h->all_io_entry = ds_inc(c->all_io_ds);
		remap_to_origin(c, bio, block);
		issue(c, bio);
		break;

	case ARC_NEW:
		debug("promote %lu -> %lu (process_bio)\n",
		      (unsigned long) block,
		      (unsigned long) lookup_result.cblock);
		if (!cheap_copy) {
			atomic_inc(&c->nr_migrations);
			atomic_inc(&c->promotion);
			promote(c, block, lookup_result.cblock, new_ocell);
			release_cell = 0;
		} else {
			atomic_inc(&c->no_copy_promotion);
			h->all_io_entry = ds_inc(c->all_io_ds);
			remap_to_cache(c, bio, block, lookup_result.cblock);
			issue(c, bio);
		}
		break;

	case ARC_REPLACE:
		debug("demote/promote (process_bio)\n");
		atomic_inc(&c->nr_migrations);
		atomic_inc(&c->demotion);
		atomic_inc(&c->promotion);
		build_key(lookup_result.old_oblock, &key);
		r = bio_detain(c->prison, &key, bio, &old_ocell);
		if (r > 0) {
			/* hmm, awkward */
			pr_alert("demoting a migrating block :( old_oblock = %lu, new_oblock = %lu, cache = %lu, nr_migrating = %lu\n",
				 (unsigned long) lookup_result.old_oblock,
				 (unsigned long) block,
				 (unsigned long) lookup_result.cblock,
				 (unsigned long) atomic_read(&c->nr_migrations));
			BUG();
		} else {
			writeback_then_promote(c, lookup_result.old_oblock, block,
					       lookup_result.cblock,
					       old_ocell, new_ocell);
		}
		release_cell = 0;
		break;
	}

	if (release_cell)
		cell_defer(c, new_ocell, 0);
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

/*----------------------------------------------------------------
 * Main worker loop
 *--------------------------------------------------------------*/
static int more_work(struct cache_c *cache)
{
	return !bio_list_empty(&cache->deferred_bios) ||
		!list_empty(&cache->quiesced_migrations);
}

static void do_work(struct work_struct *ws)
{
	struct cache_c *cache = container_of(ws, struct cache_c, worker);

	do {
		process_deferred_bios(cache);
		process_migrations(cache, &cache->quiesced_migrations, issue_copy);

	} while (more_work(cache));
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
	pr_alert("no copy promotions:\t%u\n", (unsigned) atomic_read(&c->no_copy_promotion));

	mempool_destroy(c->migration_pool);
	mempool_destroy(c->endio_hook_pool);
	ds_destroy(c->all_io_ds);
	prison_destroy(c->prison);
	destroy_workqueue(c->wq);
	vfree(c->dirty_bitset);
	dm_kcopyd_client_destroy(c->copier);
	dm_put_device(ti, c->origin_dev);
	dm_put_device(ti, c->cache_dev);
	arc_destroy(c->policy);

	kfree(c);
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
	sector_t block_size, origin_size;
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

	origin_size = get_dev_size(cache->origin_dev);
	if (ti->len > origin_size) {
		ti->error = "Device size larger than cached device";
		goto bad3;
	}

	cache->origin_blocks = origin_size / block_size;
	cache->sectors_per_block = block_size;
	cache->offset_mask = block_size - 1;
	cache->block_shift = ffs(block_size) - 1;

	spin_lock_init(&cache->lock);
	bio_list_init(&cache->deferred_bios);
	INIT_LIST_HEAD(&cache->quiesced_migrations);
	atomic_set(&cache->nr_migrations, 0);
	times_init(&cache->migration_times);

	cache->callbacks.congested_fn = cache_is_congested;
	dm_table_add_target_callbacks(ti->table, &cache->callbacks);

	cache->dirty_bitset = vzalloc(sizeof(unsigned long) * dm_div_up(cache->origin_blocks, sizeof(unsigned long) * 8));
	if (!cache->dirty_bitset) {
		ti->error = "Couldn't allocate discard bitset";
		goto bad3;
	}

	cache->copier = dm_kcopyd_client_create();
	if (IS_ERR(cache->copier)) {
		ti->error = "Couldn't create kcopyd client";
		goto bad3_5;
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

	nr_cache_blocks = get_dev_size(cache->cache_dev) >> cache->block_shift;
	cache->policy = arc_create(nr_cache_blocks);
	if (!cache->policy) {
		ti->error = "Error creating cache's policy";
		goto bad10;
	}

	atomic_set(&cache->read_hit, 0);
	atomic_set(&cache->read_miss, 0);
	atomic_set(&cache->write_hit, 0);
	atomic_set(&cache->write_miss, 0);
	atomic_set(&cache->demotion, 0);
	atomic_set(&cache->promotion, 0);
	atomic_set(&cache->no_copy_promotion, 0);

	if (dm_set_target_max_io_len(ti, cache->sectors_per_block))
		goto bad11;

	ti->num_flush_requests = 1;
	ti->num_discard_requests = 0;
	return 0;

bad11:
	arc_destroy(cache->policy);
bad10:
	mempool_destroy(cache->migration_pool);
bad9:
	mempool_destroy(cache->endio_hook_pool);
bad8:
	ds_destroy(cache->all_io_ds);
bad6:
	prison_destroy(cache->prison);
bad5:
	destroy_workqueue(cache->wq);
bad4:
	dm_kcopyd_client_destroy(cache->copier);
bad3_5:
	vfree(cache->dirty_bitset);
bad3:
	dm_put_device(ti, cache->cache_dev);
bad2:
	dm_put_device(ti, cache->origin_dev);
bad1:
	kfree(cache);
	return -EINVAL;
}

static struct endio_hook *hook_endio(struct cache_c *c, struct bio *bio)
{
	struct endio_hook *h = mempool_alloc(c->endio_hook_pool, GFP_NOIO);
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
	map_context->ptr = hook_endio(c, bio);
	defer_bio(c, bio);
	return DM_MAPIO_SUBMITTED;
#endif
}

static int cache_end_io(struct dm_target *ti, struct bio *bio,
			int error, union map_info *info)
{
	struct cache_c *c = ti->private;
	struct endio_hook *h = info->ptr;

	check_for_quiesced_migrations(c, h);
	mempool_free(h, c->endio_hook_pool);
	return 0;
}

static void cache_postsuspend(struct dm_target *ti)
{
	struct cache_c *c = ti->private;
	flush_workqueue(c->wq);

	/* FIXME: wait for in flight migrations */
}

static void cache_resume(struct dm_target *ti)
{
	struct cache_c *c = ti->private;
	wake_worker(c);
}

static int cache_status(struct dm_target *ti, status_type_t type,
			unsigned status_flags, char *result, unsigned maxlen)
{
	ssize_t sz = 0;
	char buf[BDEVNAME_SIZE];
	struct cache_c *c = ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		/*   <hits> <misses> */
		DMEMIT("%llu %llu", 0LL, 0LL);
		break;

	case STATUSTYPE_TABLE:
		format_dev_t(buf, c->origin_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
		format_dev_t(buf, c->cache_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
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

static void cache_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct cache_c *c = ti->private;

	blk_limits_io_min(limits, 0);
	blk_limits_io_opt(limits, c->sectors_per_block << SECTOR_SHIFT);
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

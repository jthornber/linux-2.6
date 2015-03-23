/*
 * Copyright (C) 2015 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "dm-cache-policy.h"
#include "dm-cache-policy-internal.h"
#include "dm.h"

#include <linux/hash.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>

#define DM_MSG_PREFIX "cache-policy-mq"

/*----------------------------------------------------------------*/

#define NR_HIT_BITS 1

struct entry {
	unsigned hash_next:28;
	unsigned prev:28;
	unsigned next:28;
	unsigned level:7;
	unsigned hits:NR_HIT_BITS;
	bool dirty:1;
	bool allocated:1;
	bool hotspot:1;
	bool sentinel:1;

	dm_oblock_t oblock;
};

/*----------------------------------------------------------------*/

// FIXME: merge with the address_space/pool concept
#define INDEXER_NULL ((1u << 28u) - 1u)

/*
 * An entry_space manages a set of entries that we use for the queues.
 * The clean and dirty queues share entries, so this object is separate
 * from the queue itself.
 */
struct entry_space {
	struct entry *begin;
	struct entry *end;
};

static int space_init(struct entry_space *es, unsigned nr_entries)
{
	es->begin = vzalloc(sizeof(struct entry) * nr_entries);
	if (!es->begin)
		return -ENOMEM;

	es->end = es->begin + nr_entries;
	return 0;
}

static void space_exit(struct entry_space *es)
{
	vfree(es->begin);
}

static struct entry *__get_entry(struct entry_space *es, unsigned block)
{
	struct entry *e;

	e = es->begin + block;
	if (e >= es->end) {
		pr_alert("bad index: __get_entry(%u)\n", block);
		BUG();
	}

	return e;
}

static unsigned to_index(struct entry_space *es, struct entry *e)
{
	BUG_ON(e < es->begin || e >= es->end);
	return e - es->begin;
}

static struct entry *to_entry(struct entry_space *es, unsigned i)
{
	struct entry *e;

	if (i == INDEXER_NULL)
		return NULL;

	e = es->begin + i;

	if (e >= es->end) {
		pr_alert("index out of bounds %u\n", (unsigned) i);
		BUG();
	}

	return e;
}

/*----------------------------------------------------------------*/

struct ilist {
	unsigned nr_elts;
	unsigned head, tail;
};

static void l_init(struct ilist *l)
{
	l->nr_elts = 0;
	l->head = l->tail = INDEXER_NULL;
}

static struct entry *l_head(struct entry_space *es, struct ilist *l)
{
	return to_entry(es, l->head);
}

static struct entry *l_tail(struct entry_space *es, struct ilist *l)
{
	return to_entry(es, l->tail);
}

static struct entry *l_next(struct entry_space *es, struct entry *e)
{
	return to_entry(es, e->next);
}

static struct entry *l_prev(struct entry_space *es, struct entry *e)
{
	return to_entry(es, e->prev);
}

static bool l_empty(struct ilist *l)
{
	return l->head == INDEXER_NULL;
}

static void l_add_head(struct entry_space *es, struct ilist *l, struct entry *e)
{
	struct entry *head = l_head(es, l);

	e->next = l->head;
	e->prev = INDEXER_NULL;

	if (head)
		head->prev = l->head = to_index(es, e);
	else
		l->head = l->tail = to_index(es, e);

	if (!e->sentinel)
		l->nr_elts++;
}

static void l_add_tail(struct entry_space *es, struct ilist *l, struct entry *e)
{
	struct entry *tail = l_tail(es, l);

	e->next = INDEXER_NULL;
	e->prev = l->tail;

	if (tail)
		tail->next = l->tail = to_index(es, e);
	else
		l->head = l->tail = to_index(es, e);

	if (!e->sentinel)
		l->nr_elts++;
}

static void l_add_before(struct entry_space *es, struct ilist *l,
			 struct entry *old, struct entry *e)
{
	struct entry *prev = l_prev(es, old);

	if (!prev)
		l_add_head(es, l, e);

	else {
		e->prev = old->prev;
		e->next = to_index(es, old);
		prev->next = old->prev = to_index(es, e);

		if (!e->sentinel)
			l->nr_elts++;
	}
}

static void l_del(struct entry_space *es, struct ilist *l, struct entry *e)
{
	struct entry *prev = l_prev(es, e);
	struct entry *next = l_next(es, e);

	if (prev)
		prev->next = e->next;
	else
		l->head = e->next;

	if (next)
		next->prev = e->prev;
	else
		l->tail = e->prev;

	// FIXME: debug only
	e->next = e->prev = INDEXER_NULL;

	if (!e->sentinel)
		l->nr_elts--;
}

static struct entry *l_pop_tail(struct entry_space *es, struct ilist *l)
{
	struct entry *e;

	for (e = l_tail(es, l); e; e = l_prev(es, e))
		if (!e->sentinel) {
			l_del(es, l, e);
			return e;
		}

	return NULL;
}

/*
 * Iterates the list to perform a crude sanity check.
 */
static void l_check(struct entry_space *es, struct ilist *l, unsigned level)
{
#ifdef ILIST_DEBUG
	unsigned count = 0;
	struct entry *e;
	unsigned prev_index = INDEXER_NULL;

	for (e = l_head(es, l); e; e = l_next(es, e)) {
		BUG_ON(e->level != level);
		BUG_ON(e->prev != prev_index);
		prev_index = to_index(es, e);

		if (!e->sentinel)
			count++;
	}

	BUG_ON(l->tail != prev_index);
	BUG_ON(l->nr_elts != count);
#endif
}

static void l_check_not_present(struct entry_space *es, struct ilist *l, struct entry *sought)
{
#ifdef ILIST_DEBUG
	struct entry *e;

	for (e = l_head(es, l); e; e = l_next(es, e))
		BUG_ON(e == sought);

	for (e = l_tail(es, l); e; e = l_prev(es, e))
		BUG_ON(e == sought);
#endif
}

static void l_check_present(struct entry_space *es, struct ilist *l, struct entry *sought)
{
#ifdef ILIST_DEBUG
	struct entry *e;
	bool found;

	found = false;
	for (e = l_head(es, l); e; e = l_next(es, e))
		if (e == sought) {
			found = true;
			break;
		}

	BUG_ON(!found);

	found = false;
	for (e = l_tail(es, l); e; e = l_prev(es, e))
		if (e == sought) {
			found = true;
			break;
		}

	BUG_ON(!found);
#endif
}

/*----------------------------------------------------------------*/

/*
 * This queue is divided up into different levels.  Allowing us to push
 * entries to the back of any of the levels.  Think of it as a partially
 * sorted queue.
 */
#define NR_HOTSPOT_LEVELS 16u
#define NR_CACHE_LEVELS 64u
#define MAX_LEVELS 64u

/* two writeback sentinels per level per cache queue*/
#define NR_SENTINELS (NR_CACHE_LEVELS * 4u)

// FIXME: separate writeback period and demote period
#define WRITEBACK_PERIOD (2 * 60  * HZ)

// FIXME: why do we pass the es into the list functions, but store it in
// the queue?

struct queue {
	struct entry_space *es;

	unsigned nr_elts;
	unsigned nr_levels;
	struct ilist qs[MAX_LEVELS];

	unsigned generation_period;

	/*
	 * Used to autotune the generation period.
	 */
	unsigned hit_threshold_level;
	unsigned autotune_hits;
	unsigned autotune_misses;
	unsigned autotune_total_hits;
	unsigned autotune_total_misses;
};

static void q_init(struct queue *q, struct entry_space *es, unsigned nr_levels)
{
	unsigned i;

	q->es = es;
	q->nr_elts = 0;
	q->nr_levels = nr_levels;

	for (i = 0; i < q->nr_levels; i++)
		l_init(q->qs + i);

	q->generation_period = 8192u; /* FIXME: use #define */

	q->hit_threshold_level = (q->nr_levels * 7u) / 8u;
	q->autotune_hits = 0u;
	q->autotune_misses = 0u;
	q->autotune_total_hits = 0u;
	q->autotune_total_misses = 0u;
}

static unsigned q_size(struct queue *q)
{
	return q->nr_elts;
}

/*
 * Insert an entry to the back of the given level.
 */
static void q_push(struct queue *q, struct entry *e)
{
	if (!e->sentinel)
		q->nr_elts++;

	l_add_tail(q->es, q->qs + e->level, e);
}

static void q_push_before(struct queue *q, struct entry *old, struct entry *e)
{
	if (!e->sentinel)
		q->nr_elts++;

	l_add_before(q->es, q->qs + e->level, old, e);
}

static void q_del(struct queue *q, struct entry *e)
{
	l_del(q->es, q->qs + e->level, e);
	if (!e->sentinel)
		q->nr_elts--;
}

/*
 * Return the oldest entry of the lowest populated level.
 */
static struct entry *q_peek(struct queue *q, bool can_cross_sentinel)
{
	unsigned level;
	struct entry *e;

	for (level = 0; level < q->nr_levels; level++)
		for (e = l_head(q->es, q->qs + level); e; e = l_next(q->es, e)) {
			if (e->sentinel) {
				if (can_cross_sentinel)
					continue;
				else
					break;
			}

			return e;
		}

	return NULL;
}

static struct entry *q_pop(struct queue *q)
{
	struct entry *e = q_peek(q, true);

	if (e)
		q_del(q, e);

	return e;
}

/*
 * Pops an entry from a level that is not past a sentinel.
 */
static struct entry *q_pop_old(struct queue *q)
{
	struct entry *e = q_peek(q, false);

	if (e)
		q_del(q, e);

	return e;
}

/*
 * This function assumes there is a non-sentinel entry to pop.  It's only
 * used by redistribute, so we know this is true.  It also doesn't adjust
 * the q->nr_elts count.
 */
static struct entry *__redist_pop_from(struct queue *q, unsigned level)
{
	struct entry *e;

	for (; level < q->nr_levels; level++)
		for (e = l_head(q->es, q->qs + level); e; e = l_next(q->es, e))
			if (!e->sentinel) {
				l_del(q->es, q->qs + e->level, e);
				return e;
			}

	return NULL;
}

static void q_redistribute(struct queue *q)
{
	unsigned target, level;
	unsigned entries_per_level = q->nr_elts / q->nr_levels;
	unsigned remainder = q->nr_elts % q->nr_levels;
	struct ilist *l, *l_above;
	struct entry *e;

	for (level = 0u; level < q->nr_levels - 1; level++) {
		l = q->qs + level;
		l_above = q->qs + level + 1;

		l_check(q->es, l, level);
		l_check(q->es, l_above, level + 1);

		target = (level < remainder) ? entries_per_level + 1 : entries_per_level;

		/*
		 * Pull down some entries from the level above.
		 */
		while (l->nr_elts < target) {
			e = __redist_pop_from(q, level + 1);
			BUG_ON(!e);
			e->level = level;
			l_add_tail(q->es, l, e);
		}

		/*
		 * Push some entries up.
		 */
		while (l->nr_elts > target) {
			e = l_pop_tail(q->es, l);
			BUG_ON(!e);
			e->level = level + 1;
			l_add_head(q->es, l_above, e);
		}

		l_check(q->es, l, level);
		l_check(q->es, l_above, level + 1);
	}
}

/*
 * We use some fixed point math to calculate the autotune period.
 * Variables that contain a fixed point number are given the suffix _fp.
 */
#define FP_SHIFT 8

static unsigned ramp(unsigned low, unsigned high, unsigned alpha_fp)
{
	unsigned delta;

	if (alpha_fp > (1 << FP_SHIFT))
		return high;

	delta = high - low;
	return low + ((delta * alpha_fp) >> FP_SHIFT);
}

static unsigned q_autotune_period(struct queue *q)
{
	// FIXME: magic numbers
	unsigned min_period = max(q->nr_elts / 4u, 1024u);
	unsigned max_period = min(q->nr_elts, 8192u);

	unsigned low_hit_ratio = 1u << (FP_SHIFT - 3u); /* 0.125 */
	unsigned high_hit_ratio = 1u << (FP_SHIFT - 1u); /* 0.5 */

	unsigned hit_ratio, alpha_fp;

	if (!q->autotune_hits)
		return min_period;

	else {
		hit_ratio = (q->autotune_hits << FP_SHIFT) / (q->autotune_hits + q->autotune_misses);

		if (hit_ratio < low_hit_ratio)
			return min_period;

		alpha_fp = ((hit_ratio - low_hit_ratio) << FP_SHIFT) / (high_hit_ratio - low_hit_ratio);

		return ramp(min_period, max_period, alpha_fp);
	}
}

static void q_reset_autotune(struct queue *q)
{
	q->autotune_total_hits += q->autotune_hits;
	q->autotune_total_misses += q->autotune_misses;

	q->autotune_hits = 0;
	q->autotune_misses = 0;
}

static void q_adjust_period(struct queue *q)
{
	q->generation_period = q_autotune_period(q);

//	pr_alert("hits = %u, misses = %u, adjustment = %u\n",
//		 q->autotune_hits, q->autotune_misses, q->generation_period);

	q_reset_autotune(q);
}

static void q_update_autotune(struct queue *q, struct entry *e)
{
	if (e->level >= q->hit_threshold_level)
		q->autotune_hits++;
	else
		q->autotune_misses++;
}

static void q_requeue(struct queue *q, struct entry *e, bool up_level)
{
	struct entry *de;

	q_del(q, e);

	if (up_level && (e->level < q->nr_levels - 1u)) {
		for (de = l_head(q->es, q->qs + e->level + 1u); de; de = l_next(q->es, de)) {
			if (de->sentinel)
				continue;

			q_del(q, de);
			de->level--;
			q_push(q, de);
			break;
		}

		e->level++;
	}

	q_push(q, e);
}

// FIXME: refactor
static void q_requeue_before(struct queue *q, struct entry *dest, struct entry *e)
{
	struct entry *de;

	q_del(q, e);

	if (e->level < q->nr_levels - 1u) {
		for (de = l_head(q->es, q->qs + e->level + 1u); de; de = l_next(q->es, de)) {
			if (de->sentinel)
				continue;

			q_del(q, de);
			de->level--;
			q_push_before(q, dest, de);
			break;
		}

		e->level++;
	}

	q_push(q, e);
}

static bool q_period_complete(struct queue *q)
{
	// FIXME: what if q->nr_elts is *huge* ?
	return (q->autotune_hits + q->autotune_misses) > q->generation_period;
}

static void q_end_period(struct queue *q)
{
	q_redistribute(q);
	q_adjust_period(q);	/* FIXME: still needed? */
}

/*----------------------------------------------------------------*/

struct hash_table {
	struct entry_space *es;
	unsigned long long hash_bits;
	unsigned *buckets;
};

/*
 * All cache entries are stored in a chained hash table.  To save space we
 * use indexing again, and only store indexes to the next entry.
 */
static int h_init(struct hash_table *ht, struct entry_space *es, unsigned nr_entries)
{
	unsigned i, nr_buckets;

	ht->es = es;
	nr_buckets = roundup_pow_of_two(max(nr_entries / 2u, 16u));
	ht->hash_bits = ffs(nr_buckets) - 1;

	ht->buckets = vmalloc(sizeof(*ht->buckets) * nr_buckets);
	if (!ht->buckets)
		return -ENOMEM;

	for (i = 0; i < nr_buckets; i++)
		ht->buckets[i] = INDEXER_NULL;

	return 0;
}

static void h_exit(struct hash_table *ht)
{
	vfree(ht->buckets);
}

static struct entry *h_head(struct hash_table *ht, unsigned bucket)
{
	BUG_ON(!ht);
	BUG_ON(!ht->es);
	return to_entry(ht->es, ht->buckets[bucket]);
}

static struct entry *h_next(struct hash_table *ht, struct entry *e)
{
	return to_entry(ht->es, e->hash_next);
}

static void __h_insert(struct hash_table *ht, unsigned bucket, struct entry *e)
{
	e->hash_next = ht->buckets[bucket];
	ht->buckets[bucket] = to_index(ht->es, e);
}

static void h_insert(struct hash_table *ht, struct entry *e)
{
	unsigned h = hash_64(from_oblock(e->oblock), ht->hash_bits);
	__h_insert(ht, h, e);
}

static struct entry *__h_lookup(struct hash_table *ht, unsigned h, dm_oblock_t oblock,
				struct entry **prev)
{
	struct entry *e;

	*prev = NULL;
	for (e = h_head(ht, h); e; e = h_next(ht, e)) {
		if (e->oblock == oblock)
			return e;

		*prev = e;
	}

	return NULL;
}

static void __h_unlink(struct hash_table *ht, unsigned h,
		       struct entry *e, struct entry *prev)
{
	if (prev)
		prev->hash_next = e->hash_next;
	else
		ht->buckets[h] = e->hash_next;
}

/*
 * Also moves each entry to the front of the bucket.
 */
static struct entry *h_lookup(struct hash_table *ht, dm_oblock_t oblock)
{
	struct entry *e, *prev;
	unsigned h = hash_64(from_oblock(oblock), ht->hash_bits);

	e = __h_lookup(ht, h, oblock, &prev);
	if (e) {
		__h_unlink(ht, h, e, prev);
		__h_insert(ht, h, e);
		return e;
	}

	return e;
}

static void h_remove(struct hash_table *ht, struct entry *e)
{
	unsigned h = hash_64(from_oblock(e->oblock), ht->hash_bits);
	struct entry *prev;

	/*
	 * The down side of using a singly linked list is we have to
	 * iterate the bucket to remove an item.
	 */
	e = __h_lookup(ht, h, e->oblock, &prev);
	if (e)
		__h_unlink(ht, h, e, prev);
}

/*----------------------------------------------------------------*/

struct entry_alloc {
	struct entry_space *es;
	unsigned begin;

	unsigned nr_allocated;
	struct ilist free;
};

static void init_allocator(struct entry_alloc *ea, struct entry_space *es,
			   unsigned begin, unsigned end)
{
	unsigned i;

	ea->es = es;
	ea->nr_allocated = 0u;
	ea->begin = begin;

	l_init(&ea->free);
	for (i = begin; i != end; i++)
		l_add_tail(ea->es, &ea->free, __get_entry(ea->es, i));
}

static void init_entry(struct entry *e)
{
	/*
	 * We can't memset because that would clear the hotspot and
	 * sentinel bits which remain constant.
	 */
	e->hash_next = INDEXER_NULL;
	e->next = INDEXER_NULL;
	e->prev = INDEXER_NULL;
	e->level = 0u;
	e->hits = 0u;
	e->allocated = true;
}

static struct entry *alloc_entry(struct entry_alloc *ea)
{
	struct entry *e;

	if (l_empty(&ea->free))
		return NULL;

	e = l_pop_tail(ea->es, &ea->free);
	init_entry(e);
	ea->nr_allocated++;

	return e;
}

/*
 * This assumes the cblock hasn't already been allocated.
 */
static struct entry *alloc_particular_entry(struct entry_alloc *ea, unsigned i)
{
	struct entry *e = __get_entry(ea->es, ea->begin + i);

	BUG_ON(e->allocated);

	l_del(ea->es, &ea->free, e);
	init_entry(e);
	ea->nr_allocated++;

	return e;
}

static void free_entry(struct entry_alloc *ea, struct entry *e)
{
	BUG_ON(!ea->nr_allocated);
	BUG_ON(!e->allocated);

	ea->nr_allocated--;
	e->allocated = false;
	l_add_tail(ea->es, &ea->free, e);
}

static bool allocator_empty(struct entry_alloc *ea)
{
	return l_empty(&ea->free);
}

static unsigned get_index(struct entry_alloc *ea, struct entry *e)
{
	return to_index(ea->es, e) - ea->begin;
}

static struct entry *get_entry(struct entry_alloc *ea, unsigned index)
{
	return __get_entry(ea->es, ea->begin + index);
}

/*----------------------------------------------------------------*/

struct mq_policy {
	struct dm_cache_policy policy;

	/* protects everything */
	struct mutex lock;
	dm_cblock_t cache_size;
	sector_t cache_block_size;
	unsigned nr_hotspot_blocks;

	struct entry_space es;
	struct entry_alloc sentinel_alloc;
	struct entry_alloc hotspot_alloc;
	struct entry_alloc cache_alloc;

	unsigned long *hotspot_hit_bits;
	unsigned long *cache_hit_bits;

	/*
	 * We maintain three queues of entries.  The cache proper,
	 * consisting of a clean and dirty queue, contains the currently
	 * active mappings.  The hotspot queue uses a much larger block
	 * size to track blocks that are being hit frequently and potential
	 * candidates for promotion to the cache.
	 */
	struct queue hotspot;
	struct queue clean;
	struct queue dirty;

	/*
	 * Keeps track of time, incremented by the core.  We use this to
	 * avoid attributing multiple hits within the same tick.
	 *
	 * Access to tick_protected should be done with the spin lock held.
	 * It's copied to tick at the start of the map function (within the
	 * mutex).
	 */
	spinlock_t tick_lock;
	unsigned tick_protected;
	unsigned tick;

	/*
	 * A count of the number of times the map function has been called
	 * and found an entry in the pre_cache or cache.  Currently used to
	 * calculate the generation.
	 */
	unsigned hit_count;

	/*
	 * A generation is a longish period that is used to trigger some
	 * book keeping effects.  eg, decrementing hit counts on entries.
	 * This is needed to allow the cache to evolve as io patterns
	 * change.
	 */
	unsigned generation;
	unsigned generation_period; /* in lookups (will probably change) */

	unsigned discard_promote_adjustment;
	unsigned read_promote_adjustment;
	unsigned write_promote_adjustment;

	/*
	 * The hash table allows us to quickly find an entry by origin
	 * block.
	 */
	struct hash_table table;

	bool current_writeback_sentinels;
	unsigned long next_writeback;

	unsigned write_promote_level;
	unsigned read_promote_level;

	unsigned nr_demotions;
	unsigned nr_hit_demotions;

	unsigned long next_hotspot_period;
	unsigned long next_cache_period;
};

#define DEFAULT_DISCARD_PROMOTE_ADJUSTMENT 1
#define DEFAULT_READ_PROMOTE_ADJUSTMENT 4
#define DEFAULT_WRITE_PROMOTE_ADJUSTMENT 8
#define DISCOURAGE_DEMOTING_DIRTY_THRESHOLD 128

/*----------------------------------------------------------------*/

#if 0
static char density_char(unsigned n, unsigned maximum)
{
	static char density[] = ".:-=+*#%@";

	if (!n)
		return ' ';

	return density[(n * (sizeof(density) - 2)) / maximum];
}

#define HEATMAP_WIDTH 128
#define HEATMAP_ROWS 8

static void display_heatmap(struct mq_policy *mq)
{
	static char buffer[HEATMAP_WIDTH + 1];

	struct entry *e;
	unsigned blocks_per_char = mq->nr_hotspot_blocks / (HEATMAP_ROWS * HEATMAP_WIDTH);
	unsigned r, i, c, base, tot, m, count, thresh;

	pr_alert("~~~~~\n");

	for (r = 0; r < HEATMAP_ROWS; r++) {
		for (c = 0; c < HEATMAP_WIDTH; c++) {
			thresh = tot = m = count = 0;
			base = ((c * HEATMAP_ROWS) + r) * blocks_per_char;
			for (i = 0; i < blocks_per_char; i++) {
				if (base + i >= mq->nr_hotspot_blocks)
					break;

				e = get_entry(&mq->hotspot_allocator, base + i);
				m = max((unsigned) e->level, m);
				tot += e->level;
				thresh += (e->level >= mq->hotspot.hit_threshold_level) ? 1u : 0u;
				count++;
			}

			buffer[c] = density_char(thresh, count);
		}

		buffer[c] = '\0';
		pr_alert("%s\n", buffer);
	}
}
#endif

/*----------------------------------------------------------------*/

static struct entry *writeback_sentinel(struct mq_policy *mq, unsigned level, bool dirty)
{
	unsigned base = dirty ? NR_CACHE_LEVELS * 2 : 0;

	if (mq->current_writeback_sentinels)
		return get_entry(&mq->sentinel_alloc, base + level);
	else
		return get_entry(&mq->sentinel_alloc, base + NR_CACHE_LEVELS + level);
}

static void __update_writeback_sentinels(struct mq_policy *mq, struct queue *q, bool dirty)
{
	unsigned level;
	struct entry *sentinel;

	for (level = 0; level < q->nr_levels; level++) {
		sentinel = writeback_sentinel(mq, level, dirty);
		q_del(q, sentinel);
		q_push(q, sentinel);
	}
}

static void update_writeback_sentinels(struct mq_policy *mq)
{
	if (time_after(jiffies, mq->next_writeback)) {
		__update_writeback_sentinels(mq, &mq->dirty, true);
		__update_writeback_sentinels(mq, &mq->clean, false);

		mq->next_writeback = jiffies + WRITEBACK_PERIOD;
		mq->current_writeback_sentinels = !mq->current_writeback_sentinels;
	}
}

// FIXME: refactor
static void writeback_sentinels_init(struct mq_policy *mq)
{
	unsigned level;
	struct entry *sentinel;

	mq->current_writeback_sentinels = false;
	mq->next_writeback = jiffies + WRITEBACK_PERIOD;

	for (level = 0; level < NR_CACHE_LEVELS; level++) {
		sentinel = writeback_sentinel(mq, level, true);
		sentinel->level = level;
		q_push(&mq->dirty, sentinel);

		sentinel = writeback_sentinel(mq, level, false);
		sentinel->level = level;
		q_push(&mq->clean, sentinel);
	}

	mq->current_writeback_sentinels = !mq->current_writeback_sentinels;

	for (level = 0; level < NR_CACHE_LEVELS; level++) {
		sentinel = writeback_sentinel(mq, level, true);
		sentinel->level = level;
		q_push(&mq->dirty, sentinel);

		sentinel = writeback_sentinel(mq, level, false);
		sentinel->level = level;
		q_push(&mq->clean, sentinel);
	}
}

/*----------------------------------------------------------------*/

/*
 * Inserts the entry into the pre_cache or the cache.  Ensures the cache
 * block is marked as allocated if necc.  Inserts into the hash table.
 * Sets the tick which records when the entry was last moved about.
 */
static void push(struct mq_policy *mq, struct queue *q, struct entry *e)
{
	h_insert(&mq->table, e);
	q_push(q, e);
}

static void push_cache(struct mq_policy *mq, struct entry *e)
{
	push(mq, e->dirty ? &mq->dirty : &mq->clean, e);
}

static void push_temporary(struct mq_policy *mq, struct entry *e)
{
	struct queue * q = e->dirty ? &mq->dirty : &mq->clean;
	struct entry *sentinel;

	h_insert(&mq->table, e);

	/*
	 * Punch this into the queue just in front of the writeback
	 * sentinel, to ensure it's cleaned straight away.
	 */
	sentinel = writeback_sentinel(mq, 0, e->dirty);
	q_push_before(q, sentinel, e);
}

/*
 * Removes an entry from cache.  Removes from the hash table.
 */
static void del(struct mq_policy *mq, struct queue *q, struct entry *e)
{
	q_del(q, e);
	h_remove(&mq->table, e);
}

static void del_cache(struct mq_policy *mq, struct entry *e)
{
	del(mq, e->dirty ? &mq->dirty : &mq->clean, e);
}

/*
 * Like del, except it removes the first entry in the queue (ie. the least
 * recently used).
 */
static struct entry *pop(struct mq_policy *mq, struct queue *q)
{
	struct entry *e = q_pop(q);
	if (e)
		h_remove(&mq->table, e);
	return e;
}

static struct entry *pop_old(struct mq_policy *mq, struct queue *q)
{
	struct entry *e = q_pop_old(q);
	if (e)
		h_remove(&mq->table, e);
	return e;
}

static dm_cblock_t infer_cblock(struct mq_policy *mq, struct entry *e)
{
	return to_cblock(get_index(&mq->cache_alloc, e));
}

/*
 * Whenever we use an entry we bump up it's hit counter, and push it to the
 * back to it's current level.
 */
static void requeue(struct mq_policy *mq, struct entry *e)
{
	struct entry *sentinel;

	if (e->hits != ((1 << NR_HIT_BITS) - 1u))
		e->hits++;

	if (e->dirty) {
		q_update_autotune(&mq->dirty, e);

		// FIXME: refactor
		if (test_and_set_bit(from_cblock(infer_cblock(mq, e)), mq->cache_hit_bits))
			q_requeue(&mq->dirty, e, false);
		else {
			sentinel = writeback_sentinel(mq, e->level, true);
			q_requeue_before(&mq->dirty, sentinel, e);
		}
	} else {
		q_update_autotune(&mq->clean, e);
		if (test_and_set_bit(from_cblock(infer_cblock(mq, e)), mq->cache_hit_bits))
			q_requeue(&mq->clean, e, false);
		else {
			sentinel = writeback_sentinel(mq, e->level, false);
			q_requeue_before(&mq->clean, sentinel, e);
		}
	}
}

#define HOTSPOT_UPDATE_PERIOD (HZ)
#define CACHE_UPDATE_PERIOD (10u * HZ)

static void update_promote_levels(struct mq_policy *mq);

static void end_hotspot_period(struct mq_policy *mq)
{
	update_promote_levels(mq);
	clear_bitset(mq->hotspot_hit_bits, mq->nr_hotspot_blocks);
	q_end_period(&mq->hotspot);
	mq->next_hotspot_period = jiffies + HOTSPOT_UPDATE_PERIOD;
}

// FIXME: bad name
static void book_keeping(struct mq_policy *mq)
{
	if (time_after(jiffies, mq->next_cache_period)) {
		pr_alert("hit demotions %u/%u\n", mq->nr_hit_demotions, mq->nr_demotions);
		//mq->nr_hit_demotions = mq->nr_demotions = 0u;
		clear_bitset(mq->cache_hit_bits, from_cblock(mq->cache_size));

		q_end_period(&mq->dirty);
		q_end_period(&mq->clean);

		mq->next_cache_period = jiffies + CACHE_UPDATE_PERIOD;
		//display_heatmap(mq);
	}
}

static int demote_cblock(struct mq_policy *mq, dm_oblock_t *oblock)
{
	struct entry *demoted = pop_old(mq, &mq->clean);
	if (!demoted)
		/*
		 * We could get a block from mq->dirty, but that
		 * would add extra latency to the triggering bio as it
		 * waits for the writeback.  Better to not promote this
		 * time and hope there's a clean block next time this block
		 * is hit.
		 */
		return -ENOSPC;

	*oblock = demoted->oblock;
	mq->nr_demotions++;
	if (demoted->hits == ((1 << NR_HIT_BITS) - 1u))
		mq->nr_hit_demotions++;

	free_entry(&mq->cache_alloc, demoted);

	return 0;
}

enum promote_result {
	PROMOTE_NOT,
	PROMOTE_TEMPORARY,
	PROMOTE_PERMANENT
};

static enum promote_result maybe_promote(bool promote)
{
	return promote ? PROMOTE_PERMANENT : PROMOTE_NOT;
}

static enum promote_result should_promote(struct mq_policy *mq, struct entry *hs_e, struct bio *bio,
					  bool fast_promote)
{
	if (bio_data_dir(bio) == WRITE) {
		if (!allocator_empty(&mq->cache_alloc) && fast_promote)
			return PROMOTE_TEMPORARY;

		return maybe_promote(hs_e->level >= mq->write_promote_level);

	} else
		return maybe_promote(hs_e->level >= mq->read_promote_level);
}

static void insert_in_cache(struct mq_policy *mq, dm_oblock_t oblock,
			    struct policy_result *result, enum promote_result pr)
{
	int r;
	struct entry *e;

	if (allocator_empty(&mq->cache_alloc)) {
		result->op = POLICY_REPLACE;
		r = demote_cblock(mq, &result->old_oblock);
		if (unlikely(r)) {
			result->op = POLICY_MISS;
			return;
		}

	} else
		result->op = POLICY_NEW;

	e = alloc_entry(&mq->cache_alloc);
	BUG_ON(!e);
	e->oblock = oblock;

	if (pr == PROMOTE_TEMPORARY)
		push_temporary(mq, e);
	else
		push_cache(mq, e);

	result->cblock = infer_cblock(mq, e);
}

static void update_promote_levels(struct mq_policy *mq)
{
#if 0
	/*
	 * There are times when we don't have any confidence in the hotspot
	 * queue.  Such as when a fresh cache is created and the blocks
	 * have been spread out across the levels.  We detect this by
	 * seeing how often a lookup is in the top levels of the hotspot
	 * queue.
	 */
	unsigned confidence = (mq->hotspot.autotune_hits << FP_SHIFT) /
		(mq->hotspot.autotune_hits + mq->hotspot.autotune_misses);

	unsigned cache_blocks_per_hotspot = 1u; //  mq->hotspot_block_size / (unsigned) mq->cache_block_size;

	unsigned nr_hotspots = ((unsigned) from_cblock(mq->cache_size)) /
		cache_blocks_per_hotspot;

	unsigned hotspots_per_level, threshold_level;

	/*
	 * We add a little fudge factor because not all of a hotspot will
	 * be neccessarily be hot/promoted.
	 */
	// FIXME: fix comment
	nr_hotspots = nr_hotspots / 2u;

	hotspots_per_level = mq->hotspot.nr_elts / mq->hotspot.nr_levels;
	threshold_level = max(1u, nr_hotspots / hotspots_per_level);

	/*
	 * If there are unused cache entries then we want to be really
	 * eager to promote.
	 */
	if (!allocator_empty(&mq->cache_alloc))
		threshold_level = NR_HOTSPOT_LEVELS;

	else if (confidence < (1u << (FP_SHIFT - 3u))) /* 0.125 */
		threshold_level = 0u;

	else if (confidence < (1u << (FP_SHIFT - 2u))) /* 0.25 */
		threshold_level /= 2u;

	mq->read_promote_level = NR_HOTSPOT_LEVELS - threshold_level;
	mq->write_promote_level = mq->read_promote_level + 2u;
#else
	mq->read_promote_level = (NR_HOTSPOT_LEVELS * 1u) / 2u;
	mq->write_promote_level = mq->read_promote_level + 2u;
#endif
}

/*
 * Looks the oblock up in the hash table, then decides whether to put in
 * pre_cache, or cache etc.
 */
static int map(struct mq_policy *mq, struct bio *bio, dm_oblock_t oblock,
	       bool can_migrate, bool fast_promote,
	       struct policy_result *result)
{
	struct entry *e;
	enum promote_result pr;

	e = h_lookup(&mq->table, oblock);
	if (e) {
		if (e->hotspot) {
			q_update_autotune(&mq->hotspot, e);
			q_requeue(&mq->hotspot, e,
				  !test_and_set_bit(get_index(&mq->hotspot_alloc, e),
						    mq->hotspot_hit_bits));

			pr = should_promote(mq, e, bio, fast_promote);
			if (pr == PROMOTE_NOT) {
				result->op = POLICY_MISS;

			} else {
				if (!can_migrate) {
					result->op = POLICY_MISS;
					return -EWOULDBLOCK;
				}

				del(mq, &mq->hotspot, e);
				free_entry(&mq->hotspot_alloc, e);

				if (fast_promote)
					pr_alert("fast promoting %llu\n", (unsigned long long) oblock);
				else
					pr_alert("promoting %llu\n", (unsigned long long) oblock);

				insert_in_cache(mq, oblock, result, pr);
			}

		} else {
			requeue(mq, e);
			result->op = POLICY_HIT;
			result->cblock = infer_cblock(mq, e);
		}

	} else {
		if (allocator_empty(&mq->hotspot_alloc))
			e = pop(mq, &mq->hotspot);
		else
			e = alloc_entry(&mq->hotspot_alloc);

		init_entry(e);
		e->hotspot = true;
		e->oblock = oblock;
		push(mq, &mq->hotspot, e);
	}

	return 0;
}

/*----------------------------------------------------------------*/

/*
 * Public interface, via the policy struct.  See dm-cache-policy.h for a
 * description of these.
 */

static struct mq_policy *to_mq_policy(struct dm_cache_policy *p)
{
	return container_of(p, struct mq_policy, policy);
}

static void mq_destroy(struct dm_cache_policy *p)
{
	struct mq_policy *mq = to_mq_policy(p);

	pr_alert("hotspot hits = %u, misses = %u\n",
		 mq->hotspot.autotune_total_hits,
		 mq->hotspot.autotune_total_misses);

	h_exit(&mq->table);
	free_bitset(mq->hotspot_hit_bits);
	free_bitset(mq->cache_hit_bits);
	space_exit(&mq->es);
	kfree(mq);
}

static void copy_tick(struct mq_policy *mq)
{
	unsigned long flags, tick;

	spin_lock_irqsave(&mq->tick_lock, flags);
	tick = mq->tick_protected;
	if (tick != mq->tick) {
		update_writeback_sentinels(mq);
		end_hotspot_period(mq);
		mq->tick = tick;
	}
	book_keeping(mq);
	spin_unlock_irqrestore(&mq->tick_lock, flags);
}

static bool maybe_lock(struct mq_policy *mq, bool can_block)
{
	if (can_block) {
		mutex_lock(&mq->lock);
		return true;
	} else
		return mutex_trylock(&mq->lock);
}

static int mq_map(struct dm_cache_policy *p, dm_oblock_t oblock,
		  bool can_block, bool can_migrate, bool fast_promote,
		  struct bio *bio, struct policy_result *result)
{
	int r;
	struct mq_policy *mq = to_mq_policy(p);

	result->op = POLICY_MISS;

	if (!maybe_lock(mq, can_block))
		return -EWOULDBLOCK;

	copy_tick(mq);
	r = map(mq, bio, oblock, can_migrate, fast_promote, result);
	mutex_unlock(&mq->lock);

	return r;
}

static int mq_lookup(struct dm_cache_policy *p, dm_oblock_t oblock, dm_cblock_t *cblock)
{
	int r;
	struct mq_policy *mq = to_mq_policy(p);
	struct entry *e;

	if (!mutex_trylock(&mq->lock))
		return -EWOULDBLOCK;

	e = h_lookup(&mq->table, oblock);
	if (e) {
		*cblock = infer_cblock(mq, e);
		r = 0;
	} else
		r = -ENOENT;

	mutex_unlock(&mq->lock);

	return r;
}

static void __mq_set_clear_dirty(struct mq_policy *mq, dm_oblock_t oblock, bool set)
{
	struct entry *e;

	e = h_lookup(&mq->table, oblock);
	BUG_ON(!e);

	del_cache(mq, e);
	e->dirty = set;
	push_cache(mq, e);
}

static void mq_set_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	struct mq_policy *mq = to_mq_policy(p);

	mutex_lock(&mq->lock);
	__mq_set_clear_dirty(mq, oblock, true);
	mutex_unlock(&mq->lock);
}

static void mq_clear_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	struct mq_policy *mq = to_mq_policy(p);

	mutex_lock(&mq->lock);
	__mq_set_clear_dirty(mq, oblock, false);
	mutex_unlock(&mq->lock);
}

static int mq_load_mapping(struct dm_cache_policy *p,
			   dm_oblock_t oblock, dm_cblock_t cblock,
			   uint32_t hint, bool hint_valid)
{
	struct mq_policy *mq = to_mq_policy(p);
	struct entry *e;

	e = alloc_particular_entry(&mq->cache_alloc, from_cblock(cblock));
	e->oblock = oblock;
	e->dirty = false;	/* this gets corrected in a minute */
	e->level = hint_valid ? min(hint, NR_CACHE_LEVELS - 1) : 1;
	push_cache(mq, e);

	return 0;
}

static int mq_save_hints(struct mq_policy *mq, struct queue *q,
			 policy_walk_fn fn, void *context)
{
	int r;
	unsigned level;
	struct entry *e;

	for (level = 0; level < q->nr_levels; level++)
		for (e = l_head(q->es, q->qs + level); e; e = l_next(q->es, e)) {
			if (!e->sentinel) {
				r = fn(context, infer_cblock(mq, e),
				       e->oblock, e->level);
				if (r)
					return r;
			}
		}

	return 0;
}

static int mq_walk_mappings(struct dm_cache_policy *p, policy_walk_fn fn,
			    void *context)
{
	struct mq_policy *mq = to_mq_policy(p);
	int r = 0;

	mutex_lock(&mq->lock);

	r = mq_save_hints(mq, &mq->clean, fn, context);
	if (!r)
		r = mq_save_hints(mq, &mq->dirty, fn, context);

	mutex_unlock(&mq->lock);

	return r;
}

static void __remove_mapping(struct mq_policy *mq, dm_oblock_t oblock)
{
	struct entry *e;

	e = h_lookup(&mq->table, oblock);
	BUG_ON(!e);

	del_cache(mq, e);
	free_entry(&mq->cache_alloc, e);
}

static void mq_remove_mapping(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	struct mq_policy *mq = to_mq_policy(p);

	mutex_lock(&mq->lock);
	__remove_mapping(mq, oblock);
	mutex_unlock(&mq->lock);
}

static int __remove_cblock(struct mq_policy *mq, dm_cblock_t cblock)
{
	struct entry *e = get_entry(&mq->cache_alloc, from_cblock(cblock));

	if (!e || !e->allocated)
		return -ENODATA;

	del_cache(mq, e);
	free_entry(&mq->cache_alloc, e);

	return 0;
}

static int mq_remove_cblock(struct dm_cache_policy *p, dm_cblock_t cblock)
{
	int r;
	struct mq_policy *mq = to_mq_policy(p);

	mutex_lock(&mq->lock);
	r = __remove_cblock(mq, cblock);
	mutex_unlock(&mq->lock);

	return r;
}


/*
 * Percentages.
 */
#define CLEAN_TARGET_CRITICAL 5u
#define CLEAN_TARGET 25u

static bool clean_target_met(struct mq_policy *mq, bool critical)
{
	unsigned percentage = critical ? CLEAN_TARGET_CRITICAL : CLEAN_TARGET;

	/*
	 * Cache entries may not be populated.  So we're cannot rely on the
	 * size of the clean queue.
	 */
	unsigned nr_clean = from_cblock(mq->cache_size) - q_size(&mq->dirty);
	unsigned target = from_cblock(mq->cache_size) * percentage / 100u;

	return nr_clean >= target;
}

static int __mq_writeback_work(struct mq_policy *mq, dm_oblock_t *oblock,
			       dm_cblock_t *cblock, bool critical_only)
{
	struct entry *e;
	bool target_met = clean_target_met(mq, critical_only);

	if (critical_only && target_met)
		return -ENODATA;

	e = pop_old(mq, &mq->dirty);
	if (!e && !target_met)
		e = pop(mq, &mq->dirty);

	if (!e)
		return -ENODATA;

	*oblock = e->oblock;
	*cblock = infer_cblock(mq, e);
	e->dirty = false;
	push_cache(mq, e);

	return 0;
}

static int mq_writeback_work(struct dm_cache_policy *p, dm_oblock_t *oblock,
			     dm_cblock_t *cblock, bool critical_only)
{
	int r;
	struct mq_policy *mq = to_mq_policy(p);

	mutex_lock(&mq->lock);
	r = __mq_writeback_work(mq, oblock, cblock, critical_only);
	mutex_unlock(&mq->lock);

	return r;
}

static void __force_mapping(struct mq_policy *mq,
			    dm_oblock_t current_oblock, dm_oblock_t new_oblock)
{
	struct entry *e = h_lookup(&mq->table, current_oblock);

	if (e) {
		del_cache(mq, e);
		e->oblock = new_oblock;
		e->dirty = true;
		push_cache(mq, e);
	}
}

static void mq_force_mapping(struct dm_cache_policy *p,
			     dm_oblock_t current_oblock, dm_oblock_t new_oblock)
{
	struct mq_policy *mq = to_mq_policy(p);

	mutex_lock(&mq->lock);
	__force_mapping(mq, current_oblock, new_oblock);
	mutex_unlock(&mq->lock);
}

static dm_cblock_t mq_residency(struct dm_cache_policy *p)
{
	dm_cblock_t r;
	struct mq_policy *mq = to_mq_policy(p);

	mutex_lock(&mq->lock);
	r = to_cblock(mq->cache_alloc.nr_allocated);
	mutex_unlock(&mq->lock);

	return r;
}

static void mq_tick(struct dm_cache_policy *p)
{
	struct mq_policy *mq = to_mq_policy(p);
	unsigned long flags;

	spin_lock_irqsave(&mq->tick_lock, flags);
	mq->tick_protected++;
	spin_unlock_irqrestore(&mq->tick_lock, flags);
}

static int mq_set_config_value(struct dm_cache_policy *p,
			       const char *key, const char *value)
{
	struct mq_policy *mq = to_mq_policy(p);
	unsigned long tmp;

	if (kstrtoul(value, 10, &tmp))
		return -EINVAL;

	else if (!strcasecmp(key, "discard_promote_adjustment"))
		mq->discard_promote_adjustment = tmp;

	else if (!strcasecmp(key, "read_promote_adjustment"))
		mq->read_promote_adjustment = tmp;

	else if (!strcasecmp(key, "write_promote_adjustment"))
		mq->write_promote_adjustment = tmp;

	else
		return -EINVAL;

	return 0;
}

static int mq_emit_config_values(struct dm_cache_policy *p, char *result, unsigned maxlen)
{
	ssize_t sz = 0;
	struct mq_policy *mq = to_mq_policy(p);

	DMEMIT("6 discard_promote_adjustment %u "
	       "read_promote_adjustment %u "
	       "write_promote_adjustment %u",
	       mq->discard_promote_adjustment,
	       mq->read_promote_adjustment,
	       mq->write_promote_adjustment);

	return 0;
}

/* Init the policy plugin interface function pointers. */
static void init_policy_functions(struct mq_policy *mq)
{
	mq->policy.destroy = mq_destroy;
	mq->policy.map = mq_map;
	mq->policy.lookup = mq_lookup;
	mq->policy.set_dirty = mq_set_dirty;
	mq->policy.clear_dirty = mq_clear_dirty;
	mq->policy.load_mapping = mq_load_mapping;
	mq->policy.walk_mappings = mq_walk_mappings;
	mq->policy.remove_mapping = mq_remove_mapping;
	mq->policy.remove_cblock = mq_remove_cblock;
	mq->policy.writeback_work = mq_writeback_work;
	mq->policy.force_mapping = mq_force_mapping;
	mq->policy.residency = mq_residency;
	mq->policy.tick = mq_tick;
	mq->policy.emit_config_values = mq_emit_config_values;
	mq->policy.set_config_value = mq_set_config_value;
}

static struct dm_cache_policy *mq_create(dm_cblock_t cache_size,
					 sector_t origin_size,
					 sector_t cache_block_size)
{
	unsigned i;
	struct mq_policy *mq = kzalloc(sizeof(*mq), GFP_KERNEL);

	if (!mq)
		return NULL;

	init_policy_functions(mq);
	mq->cache_size = cache_size;
	mq->cache_block_size = cache_block_size;

	mq->nr_hotspot_blocks = from_cblock(cache_size);
	if (space_init(&mq->es, NR_SENTINELS + mq->nr_hotspot_blocks + from_cblock(cache_size))) {
		DMERR("couldn't initialize entry space");
		goto bad_pool_init;
	}

	init_allocator(&mq->sentinel_alloc, &mq->es, 0, NR_SENTINELS);
        for (i = 0; i < NR_SENTINELS; i++)
		get_entry(&mq->sentinel_alloc, i)->sentinel = true;

	init_allocator(&mq->hotspot_alloc, &mq->es, NR_SENTINELS,
		       NR_SENTINELS + mq->nr_hotspot_blocks);
	for (i = 0; i < mq->nr_hotspot_blocks; i++)
		get_entry(&mq->hotspot_alloc, i)->hotspot = true;

	init_allocator(&mq->cache_alloc, &mq->es,
		       NR_SENTINELS + mq->nr_hotspot_blocks,
		       NR_SENTINELS + mq->nr_hotspot_blocks + from_cblock(cache_size));

	mq->hotspot_hit_bits = alloc_bitset(mq->nr_hotspot_blocks);
	if (!mq->hotspot_hit_bits) {
		DMERR("couldn't allocate hotspot hit bitset");
		goto bad_hotspot_hit_bits;
	}
	clear_bitset(mq->hotspot_hit_bits, mq->nr_hotspot_blocks);

	mq->cache_hit_bits = alloc_bitset(from_cblock(cache_size));
	if (!mq->cache_hit_bits) {
		DMERR("couldn't allocate cache hit bitset");
		goto bad_cache_hit_bits;
	}
	clear_bitset(mq->cache_hit_bits, from_cblock(mq->cache_size));

	mq->tick_protected = 0;
	mq->tick = 0;
	mq->hit_count = 0;
	mq->generation = 0;
	mq->discard_promote_adjustment = DEFAULT_DISCARD_PROMOTE_ADJUSTMENT;
	mq->read_promote_adjustment = DEFAULT_READ_PROMOTE_ADJUSTMENT;
	mq->write_promote_adjustment = DEFAULT_WRITE_PROMOTE_ADJUSTMENT;
	mutex_init(&mq->lock);
	spin_lock_init(&mq->tick_lock);

	q_init(&mq->hotspot, &mq->es, NR_HOTSPOT_LEVELS);
	q_init(&mq->clean, &mq->es, NR_CACHE_LEVELS);
	q_init(&mq->dirty, &mq->es, NR_CACHE_LEVELS);

	mq->generation_period = max((unsigned) from_cblock(cache_size), 1024u);
	if (h_init(&mq->table, &mq->es, from_cblock(cache_size) + mq->nr_hotspot_blocks))
		goto bad_alloc_table;

	writeback_sentinels_init(mq);
	mq->write_promote_level = mq->read_promote_level = NR_HOTSPOT_LEVELS;

	return &mq->policy;

bad_alloc_table:
	free_bitset(mq->cache_hit_bits);
bad_cache_hit_bits:
	free_bitset(mq->hotspot_hit_bits);
bad_hotspot_hit_bits:
	space_exit(&mq->es);
bad_pool_init:
	kfree(mq);

	return NULL;
}

/*----------------------------------------------------------------*/

static struct dm_cache_policy_type smq_policy_type = {
	.name = "smq",
	.version = {1, 3, 0},
	.hint_size = 4,
	.owner = THIS_MODULE,
	.create = mq_create
};

static int __init mq_init(void)
{
	int r;

	r = dm_cache_policy_register(&smq_policy_type);
	if (r) {
		DMERR("register failed %d", r);
		return -ENOMEM;
	}

	return 0;
}

static void __exit mq_exit(void)
{
	dm_cache_policy_unregister(&smq_policy_type);
}

module_init(mq_init);
module_exit(mq_exit);

MODULE_AUTHOR("Joe Thornber <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("smq cache policy");

MODULE_ALIAS("dm-cache-default");

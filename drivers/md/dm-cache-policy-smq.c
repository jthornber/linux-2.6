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

#define NR_HIT_BITS 2

struct entry {
	unsigned hash_next:28;
	unsigned prev:28;
	unsigned next:28;
	unsigned level:7;
	unsigned hits:NR_HIT_BITS;
	bool dirty:1;
	bool allocated:1;

	dm_oblock_t oblock;
};

/*----------------------------------------------------------------*/

#define INDEXER_NULL ((1u << 28u) - 1u)

typedef uint32_t index_t;

struct indexer {
	size_t elt_size;
	unsigned nr_sentinels;
	unsigned char *base, *end;
};

static index_t to_index(struct indexer *ix, void *ptr)
{
	BUG_ON(ptr < (void *)ix->base || ptr >= (void *)ix->end);

	return ((unsigned char *)ptr - ix->base) / ix->elt_size;
}

static void *to_obj(struct indexer *ix, index_t i)
{
	void *ptr;

	if (i == INDEXER_NULL)
		return NULL;

	ptr = ix->base + (ix->elt_size * i);

	if (ptr >= (void *)ix->end) {
		pr_alert("index out of bounds %u\n", (unsigned) i);
		BUG();
	}

	return ptr;
}

static bool is_sentinel(struct indexer *ix, struct entry *elt)
{
	return to_index(ix, elt) < ix->nr_sentinels;
}

/*----------------------------------------------------------------*/

struct ilist {
	unsigned nr_elts;
	index_t head, tail;
};

static void init_ilist(struct ilist *l)
{
	l->nr_elts = 0;
	l->head = l->tail = INDEXER_NULL;
}

static struct entry *head_obj(struct indexer *ix, struct ilist *l)
{
	return to_obj(ix, l->head);
}

static struct entry *tail_obj(struct indexer *ix, struct ilist *l)
{
	return to_obj(ix, l->tail);
}

static struct entry *next_obj(struct indexer *ix, struct entry *elt)
{
	return to_obj(ix, elt->next);
}

static struct entry *prev_obj(struct indexer *ix, struct entry *elt)
{
	return to_obj(ix, elt->prev);
}

static bool ilist_empty(struct ilist *l)
{
	return l->head == INDEXER_NULL;
}

static void ilist_add_head(struct indexer *ix, struct ilist *l, struct entry *elt)
{
	struct entry *head = to_obj(ix, l->head);

	elt->next = l->head;
	elt->prev = INDEXER_NULL;

	if (head)
		head->prev = l->head = to_index(ix, elt);
	else
		l->head = l->tail = to_index(ix, elt);

	if (!is_sentinel(ix, elt))
		l->nr_elts++;
}

static void ilist_add_tail(struct indexer *ix, struct ilist *l, struct entry *elt)
{
	struct entry *tail = to_obj(ix, l->tail);

	elt->next = INDEXER_NULL;
	elt->prev = l->tail;

	if (tail)
		tail->next = l->tail = to_index(ix, elt);
	else
		l->head = l->tail = to_index(ix, elt);

	if (!is_sentinel(ix, elt))
		l->nr_elts++;
}

static void ilist_add_before(struct indexer *ix, struct ilist *l,
			     struct entry *old, struct entry *elt)
{
	struct entry *prev = prev_obj(ix, old);

	if (!prev)
		ilist_add_head(ix, l, elt);

	else {
		elt->prev = old->prev;
		elt->next = to_index(ix, old);
		prev->next = old->prev = to_index(ix, elt);

		if (!is_sentinel(ix, elt))
			l->nr_elts++;
	}
}

static void ilist_del(struct indexer *ix, struct ilist *l, struct entry *elt)
{
	struct entry *prev = prev_obj(ix, elt);
	struct entry *next = next_obj(ix, elt);

	if (prev)
		prev->next = elt->next;
	else
		l->head = elt->next;

	if (next)
		next->prev = elt->prev;
	else
		l->tail = elt->prev;

	// FIXME: debug only
	elt->next = elt->prev = INDEXER_NULL;

	if (!is_sentinel(ix, elt))
		l->nr_elts--;
}

static struct entry *ilist_pop_tail(struct indexer *ix, struct ilist *l)
{
	struct entry *e;

	for (e = tail_obj(ix, l); e; e = prev_obj(ix, e))
		if (!is_sentinel(ix, e)) {
			ilist_del(ix, l, e);
			return e;
		}

	return NULL;
}

/*
 * Iterates the list to perform a crude sanity check.
 */
static void ilist_check(struct indexer *ix, struct ilist *l, unsigned level)
{
#ifdef ILIST_DEBUG
	unsigned count = 0;
	struct entry *elt;
	index_t prev_index = INDEXER_NULL;

	for (elt = head_obj(ix, l); elt; elt = next_obj(ix, elt)) {
		BUG_ON(elt->level != level);
		BUG_ON(elt->prev != prev_index);
		prev_index = to_index(ix, elt);

		if (!is_sentinel(ix, elt))
			count++;
	}

	BUG_ON(l->tail != prev_index);
	BUG_ON(l->nr_elts != count);
#endif
}

static void ilist_check_not_present(struct indexer *ix, struct ilist *l, struct entry *e)
{
#ifdef ILIST_DEBUG
	struct entry *elt;

	for (elt = head_obj(ix, l); elt; elt = next_obj(ix, elt))
		BUG_ON(elt == e);

	for (elt = tail_obj(ix, l); elt; elt = prev_obj(ix, elt))
		BUG_ON(elt == e);
#endif
}

static void ilist_check_present(struct indexer *ix, struct ilist *l, struct entry *e)
{
#ifdef ILIST_DEBUG
	struct entry *elt;
	bool found;

	found = false;
	for (elt = head_obj(ix, l); elt; elt = next_obj(ix, elt))
		if (elt == e) {
			found = true;
			break;
		}

	BUG_ON(!found);

	found = false;
	for (elt = tail_obj(ix, l); elt; elt = prev_obj(ix, elt))
		if (elt == e) {
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
#define NR_HOTSPOT_LEVELS 64u
#define NR_CACHE_LEVELS 64u
#define MAX_LEVELS 64u

/* two writeback sentinels per level per cache queue*/
#define NR_SENTINELS (NR_CACHE_LEVELS * 4u)

// FIXME: separate writeback period and demote period?
#define WRITEBACK_PERIOD (2 * 60  * HZ)

struct queue {
	struct indexer *ix;

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

static void q_init(struct queue *q, struct indexer *ix, unsigned nr_levels)
{
	unsigned i;

	q->ix = ix;
	q->nr_elts = 0;
	q->nr_levels = nr_levels;

	for (i = 0; i < q->nr_levels; i++)
		init_ilist(q->qs + i);

	q->generation_period = 8192u; /* FIXME: use #define */

	q->hit_threshold_level = (q->nr_levels * 7) / 8u;
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
static void q_push(struct queue *q, struct entry *elt)
{
	if (!is_sentinel(q->ix, elt))
		q->nr_elts++;
	ilist_add_tail(q->ix, q->qs + elt->level, elt);
}

static void q_push_before(struct queue *q, struct entry *old, struct entry *elt)
{
	if (!is_sentinel(q->ix, elt))
		q->nr_elts++;

	ilist_add_before(q->ix, q->qs + elt->level, old, elt);
}

static void q_push_sentinel(struct queue *q, struct entry *elt)
{
	/*
	 * Sentinels don't count towards the q->nr_elts.
	 */
	ilist_add_tail(q->ix, q->qs + elt->level, elt);
}

static void q_del(struct queue *q, struct entry *elt)
{
	ilist_del(q->ix, q->qs + elt->level, elt);
	if (!is_sentinel(q->ix, elt))
		q->nr_elts--;
}

/*
 * Return the oldest entry of the lowest populated level.
 */
static struct entry *q_peek(struct queue *q, bool can_cross_sentinel)
{
	unsigned level;
	struct entry *elt;

	for (level = 0; level < q->nr_levels; level++)
		for (elt = head_obj(q->ix, q->qs + level); elt; elt = next_obj(q->ix, elt)) {
			if (is_sentinel(q->ix, elt)) {
				if (can_cross_sentinel)
					continue;
				else
					break;
			}

			return elt;
		}

	return NULL;
}

static struct entry *q_pop(struct queue *q)
{
	struct entry *elt = q_peek(q, true);

	if (elt)
		q_del(q, elt);

	return elt;
}

/*
 * Pops an entry from a level that is not past a sentinel.
 */
static struct entry *q_pop_old(struct queue *q)
{
	struct entry *elt = q_peek(q, false);

	if (elt)
		q_del(q, elt);

	return elt;
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
		for (e = head_obj(q->ix, q->qs + level); e; e = next_obj(q->ix, e))
			if (!is_sentinel(q->ix, e)) {
				ilist_del(q->ix, q->qs + e->level, e);
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

		ilist_check(q->ix, l, level);
		ilist_check(q->ix, l_above, level + 1);

		target = (level < remainder) ? entries_per_level + 1 : entries_per_level;

		/*
		 * Pull down some entries from the level above.
		 */
		while (l->nr_elts < target) {
			e = __redist_pop_from(q, level + 1);
			BUG_ON(!e);
			e->level = level;
			ilist_add_tail(q->ix, l, e);
		}

		/*
		 * Push some entries up.
		 */
		while (l->nr_elts > target) {
			e = ilist_pop_tail(q->ix, l);
			BUG_ON(!e);
			e->level = level + 1;
			ilist_add_head(q->ix, l_above, e);
		}

		ilist_check(q->ix, l, level);
		ilist_check(q->ix, l_above, level + 1);
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
	struct entry *demote_e;

	q_del(q, e);

	if (up_level && (e->level < q->nr_levels - 1u)) {
		for (demote_e = head_obj(q->ix, q->qs + e->level + 1u); demote_e;
		     demote_e = next_obj(q->ix, demote_e)) {
			if (is_sentinel(q->ix, demote_e))
				continue;

			q_del(q, demote_e);
			demote_e->level--;
			q_push(q, demote_e);
			break;
		}

		e->level++;
	}

	q_push(q, e);
}

// FIXME: refactor
static void q_requeue_before(struct queue *q, struct entry *demote_dest, struct entry *e)
{
	struct entry *demote_e;

	q_del(q, e);

	if (e->level < q->nr_levels - 1u) {
		for (demote_e = head_obj(q->ix, q->qs + e->level + 1u); demote_e;
		     demote_e = next_obj(q->ix, demote_e)) {
			if (is_sentinel(q->ix, demote_e))
				continue;

			q_del(q, demote_e);
			demote_e->level--;
			q_push_before(q, demote_dest, demote_e);
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

/*
 * cache entries, cache sentinel entries, hotspot entries and hotspot
 * sentinels all get allocated together in one big array.  We need to be
 * able to infer the cblock based on the entry position.
 *
 * | cache sentinels | hotspot sentinels | cache entries | hotspot entries |
 *
 * Free entries are linked together into a list.
 */
struct entry_pool {
	unsigned nr_cache_entries;
	unsigned nr_hotspot_entries;

	struct entry *entries, *entries_end;

	struct entry *cache_sentinels;
	struct entry *cache_entries;
	struct entry *hotspot_entries;

	/*
	 * Just the cache entries get linked onto the free list.
	 */
	unsigned nr_allocated;
	struct ilist free;

	struct indexer ix;
};

static int epool_init(struct entry_pool *ep, unsigned nr_cache_entries,
		      unsigned nr_hotspot_entries)
{
	unsigned i;
	unsigned nr_entries = nr_cache_entries + nr_hotspot_entries + NR_SENTINELS;

	pr_alert("size of entry = %lu\n", sizeof(struct entry));
	pr_alert("nr_cache_entries = %u, nr_hotspot_entries = %u, nr_entries = %u\n",
		 nr_cache_entries, nr_hotspot_entries, nr_entries);

	ep->nr_cache_entries = nr_cache_entries;
	ep->nr_hotspot_entries = nr_hotspot_entries;

	ep->entries = vzalloc(sizeof(struct entry) * nr_entries);
	if (!ep->entries)
		return -ENOMEM;

	pr_alert("ep->entries = %p, ep->entries_end = %p\n",
		 ep->entries, ep->entries + nr_entries);

	ep->entries_end = ep->entries + nr_entries;

	ep->cache_sentinels = ep->entries;
	ep->cache_entries = ep->entries + NR_SENTINELS;
	ep->hotspot_entries = ep->entries + NR_SENTINELS + nr_cache_entries;

	ep->nr_allocated = 0;
	init_ilist(&ep->free);

	ep->ix.elt_size = sizeof(struct entry);
	ep->ix.nr_sentinels = NR_SENTINELS;
	ep->ix.base = (char *)ep->entries;
	ep->ix.end = (char *)ep->entries_end;

	for (i = 0; i < nr_cache_entries; i++)
		ilist_add_tail(&ep->ix, &ep->free, ep->cache_entries + i);

	return 0;
}

static void epool_exit(struct entry_pool *ep)
{
	vfree(ep->entries);
}

static void init_entry(struct entry *e)
{
	memset(e, 0, sizeof(*e));
	e->hash_next = INDEXER_NULL;
	e->next = INDEXER_NULL;
	e->prev = INDEXER_NULL;
	e->allocated = true;
}

static struct entry *alloc_entry(struct entry_pool *ep)
{
	struct entry *e;

	if (ilist_empty(&ep->free))
		return NULL;

	e = ilist_pop_tail(&ep->ix, &ep->free);
	init_entry(e);
	ep->nr_allocated++;

	return e;
}

/*
 * This assumes the cblock hasn't already been allocated.
 */
static struct entry *alloc_particular_entry(struct entry_pool *ep, dm_cblock_t cblock)
{
	struct entry *e = ep->cache_entries + from_cblock(cblock);

	list_del_init((struct list_head *) e);
	init_entry(e);
	ep->nr_allocated++;

	return e;
}

static void free_entry(struct entry_pool *ep, struct entry *e)
{
	BUG_ON(!ep->nr_allocated);
	memset(e, 0, sizeof(*e));
	ep->nr_allocated--;
	e->hash_next = INDEXER_NULL;
	e->allocated = false;
	ilist_add_tail(&ep->ix, &ep->free, e);
}

/*
 * Returns NULL if the entry is free.
 */
static struct entry *epool_find(struct entry_pool *ep, dm_cblock_t cblock)
{
	struct entry *e = ep->cache_entries + from_cblock(cblock);
	return e->allocated ? e : NULL;
}

static bool epool_empty(struct entry_pool *ep)
{
	return ilist_empty(&ep->free);
}

static dm_cblock_t infer_cblock(struct entry_pool *ep, struct entry *e)
{
	return to_cblock(e - ep->cache_entries);
}

static struct entry *hotspot_entry(struct entry_pool *ep, unsigned hs_block)
{
	struct entry *e;

	BUG_ON(hs_block >= ep->nr_hotspot_entries);
	e = ep->hotspot_entries + hs_block;

	BUG_ON(e >= ep->entries_end);

	return e;
}

/*----------------------------------------------------------------*/

struct mq_policy {
	struct dm_cache_policy policy;

	/* protects everything */
	struct mutex lock;
	dm_cblock_t cache_size;
	sector_t cache_block_size;

	struct entry_pool pool;
	unsigned long *hotspot_hit_bits;
	unsigned long *cache_hit_bits;

	/*
	 * We maintain three queues of entries.  The cache proper,
	 * consisting of a clean and dirty queue, contains the currently
	 * active mappings.  The hotspot queue uses a much larger block
	 * size to track blocks that are being hit frequently and potential
	 * candidates for promotion to the cache.
	 */
	sector_t hotspot_block_size;
	unsigned nr_hotspot_blocks;
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
	unsigned nr_buckets;
	dm_block_t hash_bits;
	index_t *table;

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

static bool good_hotspot_block_size(sector_t origin_size, sector_t cache_block_size, sector_t bs)
{
	if (bs >= cache_block_size * 16u)
		return true;

	do_div(origin_size, bs);
	return origin_size <= 16384;
}

static void init_hotspot_fields(struct mq_policy *mq, sector_t origin_size, sector_t cache_block_size)
{
	sector_t bs = cache_block_size;

	while (!good_hotspot_block_size(origin_size, cache_block_size, bs))
		bs *= 2u;

	mq->hotspot_block_size = bs;
	mq->nr_hotspot_blocks = dm_div_up(origin_size, bs);
}

static void populate_hotspot_queue(struct mq_policy *mq)
{
	unsigned b;
	struct entry *e;

	for (b = 0; b < mq->nr_hotspot_blocks; b++) {
		e = hotspot_entry(&mq->pool, b);
		e->level = 0;
		q_push(&mq->hotspot, e);
	}
}

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

				e = hotspot_entry(&mq->pool, base + i);
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

/*----------------------------------------------------------------*/

/*
 * All cache entries are stored in a chained hash table.  To save space we
 * use indexing again, and only store indexes to the next entry.
 */
static index_t *hash_alloc_table(unsigned nr_buckets)
{
	unsigned i;
	index_t *r = vzalloc(sizeof(*r) * nr_buckets);

	if (r)
		for (i = 0; i < nr_buckets; i++)
			r[i] = INDEXER_NULL;

	return r;
}

static void hash_insert(struct mq_policy *mq, struct entry *e)
{
	unsigned h = hash_64(from_oblock(e->oblock), mq->hash_bits);

	e->hash_next = mq->table[h];
	mq->table[h] = to_index(&mq->pool.ix, e);
}

static struct entry *__hash_lookup(struct mq_policy *mq, unsigned h, dm_oblock_t oblock,
				   struct entry **prev)
{
	struct entry *e;

	*prev = NULL;
	for (e = to_obj(&mq->pool.ix, mq->table[h]); e; e = to_obj(&mq->pool.ix, e->hash_next)) {
		if (e->oblock == oblock)
			return e;

		*prev = e;
	}

	return NULL;
}

static void __hash_unlink(struct mq_policy *mq, unsigned h, struct entry *e, struct entry *prev)
{
	if (prev)
		prev->hash_next = e->hash_next;
	else
		mq->table[h] = e->hash_next;
}

/*
 * Also moves each entry to the front of the bucket.
 */
static struct entry *hash_lookup(struct mq_policy *mq, dm_oblock_t oblock)
{
	unsigned h = hash_64(from_oblock(oblock), mq->hash_bits);
	struct entry *e, *prev;

	e = __hash_lookup(mq, h, oblock, &prev);
	if (e) {
		__hash_unlink(mq, h, e, prev);
		e->hash_next = mq->table[h];
		mq->table[h] = to_index(&mq->pool.ix, e);
		return e;
	}

	return e;
}

static void hash_remove(struct mq_policy *mq, struct entry *e)
{
	unsigned h = hash_64(from_oblock(e->oblock), mq->hash_bits);
	struct entry *prev;

	e = __hash_lookup(mq, h, e->oblock, &prev);
	if (e)
		__hash_unlink(mq, h, e, prev);
}

/*----------------------------------------------------------------*/

static struct entry *writeback_sentinel(struct mq_policy *mq, unsigned level, bool dirty)
{
	unsigned base = dirty ? NR_CACHE_LEVELS * 2 : 0;

	if (mq->current_writeback_sentinels)
		return mq->pool.cache_sentinels + base + level;
	else
		return mq->pool.cache_sentinels + base + NR_CACHE_LEVELS + level;
}

static void __update_writeback_sentinels(struct mq_policy *mq, struct queue *q, bool dirty)
{
	unsigned level;
	struct entry *sentinel;

	for (level = 0; level < q->nr_levels; level++) {
		sentinel = writeback_sentinel(mq, level, dirty);
		q_del(q, sentinel);
		q_push_sentinel(q, sentinel);
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
		q_push_sentinel(&mq->dirty, sentinel);

		sentinel = writeback_sentinel(mq, level, false);
		sentinel->level = level;
		q_push_sentinel(&mq->clean, sentinel);
	}

	mq->current_writeback_sentinels = !mq->current_writeback_sentinels;

	for (level = 0; level < NR_CACHE_LEVELS; level++) {
		sentinel = writeback_sentinel(mq, level, true);
		sentinel->level = level;
		q_push_sentinel(&mq->dirty, sentinel);

		sentinel = writeback_sentinel(mq, level, false);
		sentinel->level = level;
		q_push_sentinel(&mq->clean, sentinel);
	}
}

/*----------------------------------------------------------------*/

/*
 * Inserts the entry into the pre_cache or the cache.  Ensures the cache
 * block is marked as allocated if necc.  Inserts into the hash table.
 * Sets the tick which records when the entry was last moved about.
 */
static void push(struct mq_policy *mq, struct entry *e)
{
	hash_insert(mq, e);
	q_push(e->dirty ? &mq->dirty : &mq->clean, e);
}

static void push_temporary(struct mq_policy *mq, struct entry *e)
{
	struct queue * q = e->dirty ? &mq->dirty : &mq->clean;
	struct entry *sentinel;

	hash_insert(mq, e);

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
static void del(struct mq_policy *mq, struct entry *e)
{
	q_del(e->dirty ? &mq->dirty : &mq->clean, e);
	hash_remove(mq, e);
}

/*
 * Like del, except it removes the first entry in the queue (ie. the least
 * recently used).
 */
static struct entry *pop(struct mq_policy *mq, struct queue *q)
{
	struct entry *e = q_pop(q);
	if (e)
		hash_remove(mq, e);
	return e;
}

static struct entry *pop_old(struct mq_policy *mq, struct queue *q)
{
	struct entry *e = q_pop_old(q);
	if (e)
		hash_remove(mq, e);
	return e;
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
		if (test_and_set_bit(from_cblock(infer_cblock(&mq->pool, e)),
				     mq->cache_hit_bits))
			q_requeue(&mq->dirty, e, false);
		else {
			sentinel = writeback_sentinel(mq, e->level, true);
			q_requeue_before(&mq->dirty, sentinel, e);
		}
	} else {
		q_update_autotune(&mq->clean, e);
		if (test_and_set_bit(from_cblock(infer_cblock(&mq->pool, e)),
				     mq->cache_hit_bits))
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
		display_heatmap(mq);
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

	free_entry(&mq->pool, demoted);

	return 0;
}

static unsigned to_hotspot_block(struct mq_policy *mq, sector_t s)
{
	do_div(s, mq->hotspot_block_size);
	return (unsigned) s;
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
		if (!epool_empty(&mq->pool) && fast_promote)
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

	if (epool_empty(&mq->pool)) {
		result->op = POLICY_REPLACE;
		r = demote_cblock(mq, &result->old_oblock);
		if (unlikely(r)) {
			result->op = POLICY_MISS;
			return;
		}

	} else
		result->op = POLICY_NEW;

	e = alloc_entry(&mq->pool);
	BUG_ON(!e);
	e->oblock = oblock;

	if (pr == PROMOTE_TEMPORARY)
		push_temporary(mq, e);
	else
		push(mq, e);

	result->cblock = infer_cblock(&mq->pool, e);
}

static void update_promote_levels(struct mq_policy *mq)
{
	/*
	 * There are times when we don't have any confidence in the hotspot
	 * queue.  Such as when a fresh cache is created and the blocks
	 * have been spread out across the levels.  We detect this by
	 * seeing how often a lookup is in the top levels of the hotspot
	 * queue.
	 */
	unsigned confidence = (mq->hotspot.autotune_hits << FP_SHIFT) /
		(mq->hotspot.autotune_hits + mq->hotspot.autotune_misses);

	unsigned cache_blocks_per_hotspot = mq->hotspot_block_size /
		(unsigned) mq->cache_block_size;

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
	if (!epool_empty(&mq->pool))
		threshold_level = NR_HOTSPOT_LEVELS;

	else if (confidence < (1u << (FP_SHIFT - 3u))) /* 0.125 */
		threshold_level = 0u;

	else if (confidence < (1u << (FP_SHIFT - 2u))) /* 0.25 */
		threshold_level /= 2u;

	mq->read_promote_level = NR_HOTSPOT_LEVELS - threshold_level;
	mq->write_promote_level = mq->read_promote_level + 2u;
}

/*
 * Looks the oblock up in the hash table, then decides whether to put in
 * pre_cache, or cache etc.
 */
static int map(struct mq_policy *mq, struct bio *bio, dm_oblock_t oblock,
	       bool can_migrate, bool fast_promote,
	       struct policy_result *result)
{
	struct entry *e, *hs_e;
	unsigned hs_block = to_hotspot_block(mq, bio->bi_iter.bi_sector);
	enum promote_result pr;

	hs_e = hotspot_entry(&mq->pool, hs_block);

	q_update_autotune(&mq->hotspot, hs_e);
	q_requeue(&mq->hotspot, hs_e,
		  !test_and_set_bit(hs_block, mq->hotspot_hit_bits));

	e = hash_lookup(mq, oblock);
	if (e) {
		requeue(mq, e);
		result->op = POLICY_HIT;
		result->cblock = infer_cblock(&mq->pool, e);
		return 0;
	}

	pr = should_promote(mq, hs_e, bio, fast_promote);
	if (pr == PROMOTE_NOT)
		result->op = POLICY_MISS;

	else {
		if (!can_migrate) {
			result->op = POLICY_MISS;
			return -EWOULDBLOCK;
		}

		insert_in_cache(mq, oblock, result, pr);
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

	vfree(mq->table);
	free_bitset(mq->hotspot_hit_bits);
	free_bitset(mq->cache_hit_bits);
	epool_exit(&mq->pool);
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

	e = hash_lookup(mq, oblock);
	if (e) {
		*cblock = infer_cblock(&mq->pool, e);
		r = 0;
	} else
		r = -ENOENT;

	mutex_unlock(&mq->lock);

	return r;
}

static void __mq_set_clear_dirty(struct mq_policy *mq, dm_oblock_t oblock, bool set)
{
	struct entry *e;

	e = hash_lookup(mq, oblock);
	BUG_ON(!e);

	del(mq, e);
	e->dirty = set;
	push(mq, e);
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

	e = alloc_particular_entry(&mq->pool, cblock);
	e->oblock = oblock;
	e->dirty = false;	/* this gets corrected in a minute */
	e->level = hint_valid ? min(hint, NR_CACHE_LEVELS - 1) : 1;
	push(mq, e);

	return 0;
}

static int mq_save_hints(struct mq_policy *mq, struct queue *q,
			 policy_walk_fn fn, void *context)
{
	int r;
	unsigned level;
	struct entry *e;

	for (level = 0; level < q->nr_levels; level++)
		for (e = head_obj(q->ix, q->qs + level); e; e = next_obj(q->ix, e)) {
			if (!is_sentinel(q->ix, e)) {
				r = fn(context, infer_cblock(&mq->pool, e),
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

	e = hash_lookup(mq, oblock);
	BUG_ON(!e);

	del(mq, e);
	free_entry(&mq->pool, e);
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
	struct entry *e = epool_find(&mq->pool, cblock);

	if (!e)
		return -ENODATA;

	del(mq, e);
	free_entry(&mq->pool, e);

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
	*cblock = infer_cblock(&mq->pool, e);
	e->dirty = false;
	push(mq, e);

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
	struct entry *e = hash_lookup(mq, current_oblock);

	if (e) {
		del(mq, e);
		e->oblock = new_oblock;
		e->dirty = true;
		push(mq, e);
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
	r = to_cblock(mq->pool.nr_allocated);
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
	struct mq_policy *mq = kzalloc(sizeof(*mq), GFP_KERNEL);

	if (!mq)
		return NULL;

	init_policy_functions(mq);
	mq->cache_size = cache_size;
	mq->cache_block_size = cache_block_size;

	init_hotspot_fields(mq, origin_size, cache_block_size);

	if (epool_init(&mq->pool, from_cblock(cache_size), mq->nr_hotspot_blocks)) {
		DMERR("couldn't initialize pool of cache entries");
		goto bad_pool_init;
	}

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

	q_init(&mq->hotspot, &mq->pool.ix, NR_HOTSPOT_LEVELS);

	populate_hotspot_queue(mq);

	q_init(&mq->clean, &mq->pool.ix, NR_CACHE_LEVELS);
	q_init(&mq->dirty, &mq->pool.ix, NR_CACHE_LEVELS);

	mq->generation_period = max((unsigned) from_cblock(cache_size), 1024u);

	mq->nr_buckets = roundup_pow_of_two(max(from_cblock(cache_size) / 2u, 16u));
	mq->hash_bits = ffs(mq->nr_buckets) - 1;
	mq->table = hash_alloc_table(mq->nr_buckets);
	if (!mq->table)
		goto bad_alloc_table;

	writeback_sentinels_init(mq);
	mq->write_promote_level = mq->read_promote_level = NR_HOTSPOT_LEVELS;

	return &mq->policy;

bad_alloc_table:
	free_bitset(mq->cache_hit_bits);
bad_cache_hit_bits:
	free_bitset(mq->hotspot_hit_bits);
bad_hotspot_hit_bits:
	epool_exit(&mq->pool);
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

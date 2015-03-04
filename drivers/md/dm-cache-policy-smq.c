/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "dm-cache-policy.h"
#include "dm.h"

#include <linux/hash.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#define DM_MSG_PREFIX "cache-policy-mq"

/*----------------------------------------------------------------*/

static unsigned next_power(unsigned n, unsigned min)
{
	return roundup_pow_of_two(max(n, min));
}

/*----------------------------------------------------------------*/

struct entry {
	unsigned prev:28;
	unsigned next:28;
	unsigned level:5;
	bool dirty:1;
	bool sentinel:1;

	struct hlist_node hlist; /* FIXME: replace with an index */
	dm_oblock_t oblock;
};

/*----------------------------------------------------------------*/

// FIXME: I hate this
#define INDEXER_NULL ((1u << 28u) - 1u)

typedef uint32_t index_t;

struct indexer {
	size_t elt_size;
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

static void ilist_add_head(struct indexer *ix, struct ilist *l, struct entry *elt)
{
	struct entry *head = to_obj(ix, l->head);

	elt->next = l->head;
	elt->prev = INDEXER_NULL;

	if (head)
		head->prev = l->head = to_index(ix, elt);
	else
		l->head = l->tail = to_index(ix, elt);

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

	l->nr_elts++;
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

	l->nr_elts--;
}

static void ilist_splice_head(struct indexer *ix, struct ilist *l1, struct ilist *l2)
{
	if (l1->head == INDEXER_NULL)
		memcpy(l1, l2, sizeof(*l1));

	else if (l2->head != INDEXER_NULL) {
		struct entry *head1 = to_obj(ix, l1->head);
		struct entry *tail2 = to_obj(ix, l2->tail);

		head1->prev = l2->tail;
		tail2->next = l1->head;
		l1->head = l2->head;

		l1->nr_elts += l2->nr_elts;
	}
}

static void ilist_splice_tail(struct indexer *ix, struct ilist *l1, struct ilist *l2)
{
	if (l1->head == INDEXER_NULL)
		memcpy(l1, l2, sizeof(*l1));

	else if (l2->head != INDEXER_NULL) {
		struct entry *head2 = head_obj(ix, l2);
		struct entry *tail1 = tail_obj(ix, l1);

		tail1->next = l2->head;
		head2->prev = l1->tail;
		l1->tail = l2->tail;
		l1->nr_elts += l2->nr_elts;
	}
}

/*
 * Iterates the list to perform a crude sanity check.
 */
static void ilist_check(struct indexer *ix, struct ilist *l, unsigned level)
{
	unsigned count = 0;
	struct entry *elt;
	index_t prev_index = INDEXER_NULL;

	for (elt = head_obj(ix, l); elt; elt = next_obj(ix, elt)) {
		// BUG_ON(elt->level != level);
		BUG_ON(elt->prev != prev_index);
		prev_index = to_index(ix, elt);
		count++;
	}
	BUG_ON(l->tail != prev_index);

	BUG_ON(l->nr_elts != count);
}

static void ilist_check_not_present(struct indexer *ix, struct ilist *l, struct entry *e)
{
	struct entry *elt;

	for (elt = head_obj(ix, l); elt; elt = next_obj(ix, elt))
		BUG_ON(elt == e);

	for (elt = tail_obj(ix, l); elt; elt = prev_obj(ix, elt))
		BUG_ON(elt == e);
}

/*----------------------------------------------------------------*/

/*
 * This queue is divided up into different levels.  Allowing us to push
 * entries to the back of any of the levels.  Think of it as a partially
 * sorted queue.
 */
#define NR_LEVELS 8u

/* two writeback sentinels */
#define NR_SENTINELS (NR_LEVELS * 2)
#define WRITEBACK_PERIOD HZ

struct queue {
	struct indexer *ix;

	unsigned nr_elts;
	struct ilist qs[NR_LEVELS];

	bool current_writeback_sentinels;

	/*
	 * Used to autotune the shuffle adjustment.
	 */
	unsigned hit_threshold_level;
	unsigned autotune_hits;
	unsigned autotune_misses;
	unsigned autotune_total_hits;
	unsigned autotune_total_misses;
};

static void queue_init(struct queue *q, struct indexer *ix)
{
	unsigned i;

	q->ix = ix;
	q->nr_elts = 0;

	for (i = 0; i < NR_LEVELS; i++)
		init_ilist(q->qs + i);

	q->current_writeback_sentinels = false;
	q->hit_threshold_level = (NR_LEVELS * 7) / 8u;
	q->autotune_hits = 0u;
	q->autotune_misses = 0u;
	q->autotune_total_hits = 0u;
	q->autotune_total_misses = 0u;
}

static unsigned queue_size(struct queue *q)
{
	return q->nr_elts;
}

/*
 * Insert an entry to the back of the given level.
 */
static void queue_push(struct queue *q, struct entry *elt)
{
	q->nr_elts++;
	ilist_add_tail(q->ix, q->qs + elt->level, elt);
}

static void queue_remove(struct queue *q, struct entry *elt)
{
	ilist_del(q->ix, q->qs + elt->level, elt);
	q->nr_elts--;
}

static bool is_sentinel(struct queue *q, struct entry *elt)
{
	return to_index(q->ix, elt) < (NR_SENTINELS * 2);
}

/*
 * Return the oldest entry of the lowest populated level.
 */
static struct entry *queue_peek(struct queue *q)
{
	unsigned level;
	struct entry *elt;

	for (level = 0; level < NR_LEVELS; level++)
		for (elt = head_obj(q->ix, q->qs + level); elt; elt = next_obj(q->ix, elt))
			if (!is_sentinel(q, elt))
				return elt;

	return NULL;
}

static struct entry *queue_pop(struct queue *q)
{
	unsigned level;
	struct entry *elt;

	for (level = 0; level < NR_LEVELS; level++)
		for (elt = head_obj(q->ix, q->qs + level); elt; elt = next_obj(q->ix, elt)) {
			if (is_sentinel(q, elt))
				continue;

			queue_remove(q, elt);
			return elt;
		}

	return NULL;
}

/*
 * Pops an entry from a level that is not past a sentinel.
 */
static struct entry *queue_pop_old(struct queue *q)
{
	unsigned level;
	struct entry *elt;

	for (level = 0; level < NR_LEVELS; level++)
		for (elt = head_obj(q->ix, q->qs + level); elt; elt = next_obj(q->ix, elt)) {
			if (is_sentinel(q, elt))
				break;

			queue_remove(q, elt);
			return elt;
		}

	return NULL;
}

static struct list_head *writeback_sentinel(struct queue *q, unsigned level)
{
#if 0
	if (q->current_writeback_sentinels)
		return q->sentinels + level;
	else
		return q->sentinels + NR_LEVELS + level;
#else
	return NULL;
#endif
}

/*
 * Sometimes we want to iterate through entries that have been pushed since
 * a certain event.  We use sentinel entries on the queues to delimit these
 * 'tick' events.
 */
static void queue_update_writeback_sentinels(struct queue *q)
{
#if 0
	unsigned level;
	struct entry *sentinel;

	if (time_after(jiffies, q->next_writeback)) {
		for (level = 0; level < NR_LEVELS; level++) {
			sentinel = writeback_sentinel(q, level);
			ilist_del(q->ix, q->qs + level, sentinel);
			ilist_add_tail(q->ix, q->qs + level, sentinel);
		}

		q->next_writeback = jiffies + WRITEBACK_PERIOD;
		q->current_writeback_sentinels = !q->current_writeback_sentinels;
	}
#endif
}

static bool within(unsigned n, unsigned target, unsigned variance)
{
	return ((n + variance) >= target) && (n <= (target + variance));
}

static bool need_redistribute(struct queue *q)
{
	unsigned level;
	unsigned target_per_level = q->nr_elts / NR_LEVELS;

	for (level = 0u; level < NR_LEVELS; level++)
		if (!within(q->qs[level].nr_elts, target_per_level, 4u))
			return true;

	return false;
}

// FIXME: slow
static void queue_redistribute(struct queue *q)
{
	unsigned level;
	struct ilist all;
	struct entry *elt;
	unsigned entries_per_level, remainder, count;

	if (!need_redistribute(q))
		return;

	pr_alert("redistributing\n");
	init_ilist(&all);
	for (level = 0u; level < NR_LEVELS; level++) {
		ilist_splice_tail(q->ix, &all, q->qs + level);
		init_ilist(q->qs + level);
	}
	BUG_ON(all.nr_elts != q->nr_elts);

	entries_per_level = all.nr_elts / NR_LEVELS;
        remainder = all.nr_elts % NR_LEVELS;
        for (level = 0u; level < NR_LEVELS; level++) {
                count = (level < remainder) ? entries_per_level + 1 : entries_per_level;
                while (count--) {
			elt = head_obj(q->ix, &all);

			if (!elt) {
				BUG();
			}

			ilist_del(q->ix, &all, elt);
			elt->level = level;
                        ilist_add_tail(q->ix, q->qs + level, elt);
                }
        }

	if (need_redistribute(q))
		pr_alert("redistribute didn't, %u\n", q->nr_elts);
}

// FIXME: slow
static void queue_shuffle(struct queue *q, unsigned adjustment)
{
	unsigned level, count, tweaked_adjustment;
	struct ilist promote[NR_LEVELS];
	struct ilist demote[NR_LEVELS];
	struct entry *e, *next, *prev;

	for (level = 0u; level < NR_LEVELS; level++) {
		init_ilist(promote + level);
		init_ilist(demote + level);
	}

	for (level = 0u; level < NR_LEVELS; level++) {
		ilist_check(q->ix, q->qs + level, level);
		tweaked_adjustment = min(adjustment, q->qs[level].nr_elts / 2);

		if (level < NR_LEVELS - 1) {
			for (count = 0, e = head_obj(q->ix, q->qs + level); e && count < tweaked_adjustment;) {
				next = next_obj(q->ix, e);

				if (!is_sentinel(q, e)) {
					ilist_del(q->ix, q->qs + level, e);
					e->level++;
					ilist_add_tail(q->ix, promote + level + 1, e);
					count++;
				} else
					BUG(); /* I'm not using sentinels yet */

				e = next;
			}
		}

		if (level > 0) {
			for (count = 0, e = tail_obj(q->ix, q->qs + level); e && count < tweaked_adjustment;) {
				prev = prev_obj(q->ix, e);

				if (!is_sentinel(q, e)) {
					ilist_del(q->ix, q->qs + level, e);
					e->level--;
					ilist_add_head(q->ix, demote + level - 1, e);
					count++;
				} else
					BUG();

				e = prev;
			}
		}
	}

	for (level = 0u; level < NR_LEVELS; level++) {
		ilist_splice_head(q->ix, q->qs + level, promote + level);
                ilist_splice_tail(q->ix, q->qs + level, demote + level);
		ilist_check(q->ix, q->qs + level, level);
        }

	if (need_redistribute(q)) {
		for (level = 0u; level < NR_LEVELS; level++)
			pr_alert("level %u: nr_elts = %u, promotes = %u, demotes = %u\n",
				 level, q->qs[level].nr_elts, promote[level].nr_elts, demote[level].nr_elts);
		BUG();
	}
}

/*
 * We use some fixed point math to calculate the autotune adjustment.
 */
#define FP_SHIFT 8

static unsigned queue_autotune_adjustment_(struct queue *q)
{
	unsigned max_adjustment = (q->nr_elts / NR_LEVELS) / 4u;

	if (!q->autotune_hits)
		return max_adjustment;

	else {
		unsigned miss_ratio = (q->autotune_misses << FP_SHIFT) / q->autotune_hits; /* it is correct to not shift q->autotune_hits */
		unsigned adjustment = ((miss_ratio - (1u << FP_SHIFT)) * 4u) + (1u << FP_SHIFT);

		adjustment = min(adjustment, max_adjustment << FP_SHIFT);
		adjustment = max(adjustment, 1u << FP_SHIFT);
		return adjustment >> FP_SHIFT;
	}
}

static unsigned queue_autotune_adjustment(struct queue *q)
{
	unsigned r = queue_autotune_adjustment_(q);
	pr_alert("hits = %u, misses = %u, adjustment = %u\n",
		 q->autotune_hits, q->autotune_misses, r);
	return r;
}

static void queue_reset_autotune(struct queue *q)
{
	q->autotune_total_hits += q->autotune_hits;
	q->autotune_total_misses += q->autotune_misses;

	q->autotune_hits = 0;
	q->autotune_misses = 0;
}

/*
 * Return true if the queue was shuffled.
 */
static bool queue_requeue(struct queue *q, struct entry *e)
{
	queue_remove(q, e);
	queue_push(q, e);

	if (e->level >= q->hit_threshold_level)
		q->autotune_hits++;
	else
		q->autotune_misses++;

	if ((q->autotune_hits + q->autotune_misses) > max(8192u, q->nr_elts)) {
		queue_redistribute(q);
		queue_shuffle(q, queue_autotune_adjustment(q));
		queue_reset_autotune(q);
		return true;
	}

	return false;
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
	struct entry *hotspot_sentinels;
	struct entry *cache_entries;
	struct entry *hotspot_entries;

	/*
	 * Just the cache entries get linked onto the free list.
	 */
	unsigned nr_allocated;
	struct list_head free;

	struct indexer ix;
};

static int epool_init(struct entry_pool *ep, unsigned nr_cache_entries,
		      unsigned nr_hotspot_entries)
{
	unsigned i;
	unsigned nr_entries = nr_cache_entries + nr_hotspot_entries + 2 * NR_SENTINELS;

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
	ep->hotspot_sentinels = ep->entries + NR_SENTINELS;
	ep->cache_entries = ep->entries + 2 * NR_SENTINELS;
	ep->hotspot_entries = ep->entries + 2 * NR_SENTINELS + nr_cache_entries;

	ep->nr_allocated = 0;
	INIT_LIST_HEAD(&ep->free);
	for (i = 0; i < nr_cache_entries; i++)
		list_add((struct list_head *) (ep->cache_entries + i), &ep->free);

	ep->ix.elt_size = sizeof(struct entry);
	ep->ix.base = (char *)ep->entries;
	ep->ix.end = (char *)ep->entries_end;

	return 0;
}

static void epool_exit(struct entry_pool *ep)
{
	vfree(ep->entries);
}

static void init_entry(struct entry *e)
{
	memset(e, 0, sizeof(*e));
	e->next = INDEXER_NULL;
	e->prev = INDEXER_NULL;
	INIT_HLIST_NODE(&e->hlist);
}

static struct list_head *list_pop(struct list_head *lh)
{
	struct list_head *r = lh->next;

	BUG_ON(!r);
	list_del_init(r);

	return r;
}

static struct entry *alloc_entry(struct entry_pool *ep)
{
	struct entry *e;

	if (list_empty(&ep->free)) {
		pr_alert("alloc_entry returning NULL\n");
		return NULL;
	}

	e = (struct entry *) list_pop(&ep->free);
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
	ep->nr_allocated--;
	INIT_HLIST_NODE(&e->hlist);
	list_add((struct list_head *) e, &ep->free);
}

/*
 * Returns NULL if the entry is free.
 */
static struct entry *epool_find(struct entry_pool *ep, dm_cblock_t cblock)
{
	struct entry *e = ep->cache_entries + from_cblock(cblock);
	return !hlist_unhashed(&e->hlist) ? e : NULL;
}

static bool epool_empty(struct entry_pool *ep)
{
	return list_empty(&ep->free);
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

	// FIXME: rename clean and dirty
	struct queue cache_clean;
	struct queue cache_dirty;

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
	struct hlist_head *table;
};

#define DEFAULT_DISCARD_PROMOTE_ADJUSTMENT 1
#define DEFAULT_READ_PROMOTE_ADJUSTMENT 4
#define DEFAULT_WRITE_PROMOTE_ADJUSTMENT 8
#define DISCOURAGE_DEMOTING_DIRTY_THRESHOLD 128

/*----------------------------------------------------------------*/

static bool good_hotspot_block_size(sector_t origin_size, sector_t bs)
{
	do_div(origin_size, bs);
	return origin_size <= 8192;
}

static void init_hotspot_fields(struct mq_policy *mq, sector_t origin_size, sector_t cache_block_size)
{
	sector_t bs = cache_block_size;

	while (!good_hotspot_block_size(origin_size, bs))
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
		queue_push(&mq->hotspot, e);
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
 * Simple hash table implementation.  Should replace with the standard hash
 * table that's making its way upstream.
 */
static void hash_insert(struct mq_policy *mq, struct entry *e)
{
	unsigned h = hash_64(from_oblock(e->oblock), mq->hash_bits);

	hlist_add_head(&e->hlist, mq->table + h);
}

static struct entry *hash_lookup(struct mq_policy *mq, dm_oblock_t oblock)
{
	unsigned h = hash_64(from_oblock(oblock), mq->hash_bits);
	struct hlist_head *bucket = mq->table + h;
	struct entry *e;

	hlist_for_each_entry(e, bucket, hlist)
		if (e->oblock == oblock)
			return e;

	return NULL;
}

static void hash_remove(struct entry *e)
{
	hlist_del(&e->hlist);
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
	queue_push(e->dirty ? &mq->cache_dirty : &mq->cache_clean, e);

	{
		struct entry *e2 = hash_lookup(mq, e->oblock);
		BUG_ON(!e2);
	}
}

/*
 * Removes an entry from cache.  Removes from the hash table.
 */
static void del(struct mq_policy *mq, struct entry *e)
{
	queue_remove(e->dirty ? &mq->cache_dirty : &mq->cache_clean, e);
	hash_remove(e);
}

/*
 * Like del, except it removes the first entry in the queue (ie. the least
 * recently used).
 */
static struct entry *pop(struct mq_policy *mq, struct queue *q)
{
	struct entry *e = queue_pop(q);
	if (e)
		hash_remove(e);
	return e;
}

static struct entry *pop_old(struct mq_policy *mq, struct queue *q)
{
	struct entry *e = queue_pop_old(q);
	if (e)
		hash_remove(e);
	return e;
}

/*
 * Whenever we use an entry we bump up it's hit counter, and push it to the
 * back to it's current level.
 */
static void requeue(struct mq_policy *mq, struct entry *e)
{
	queue_requeue(e->dirty ? &mq->cache_dirty : &mq->cache_clean, e);
}

static int demote_cblock(struct mq_policy *mq, dm_oblock_t *oblock)
{
	struct entry *demoted = pop(mq, &mq->cache_clean);
	if (!demoted)
		/*
		 * We could get a block from mq->cache_dirty, but that
		 * would add extra latency to the triggering bio as it
		 * waits for the writeback.  Better to not promote this
		 * time and hope there's a clean block next time this block
		 * is hit.
		 */
		return -ENOSPC;

	*oblock = demoted->oblock;
	free_entry(&mq->pool, demoted);

	return 0;
}

static unsigned to_hotspot_block(struct mq_policy *mq, sector_t s)
{
	do_div(s, mq->hotspot_block_size);
	return (unsigned) s;
}

static bool should_promote(struct mq_policy *mq, struct entry *hs_e, struct bio *bio,
			   bool fast_promote)
{
	if (bio_data_dir(bio) == WRITE && fast_promote && !epool_empty(&mq->pool))
		return true;

	return hs_e->level > ((3 * NR_LEVELS) / 4); /* FIXME: hard coded */
}

static void insert_in_cache(struct mq_policy *mq, dm_oblock_t oblock,
			    struct policy_result *result)
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
	push(mq, e);
	result->cblock = infer_cblock(&mq->pool, e);
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

	hs_e = hotspot_entry(&mq->pool,
			     to_hotspot_block(mq, bio->bi_iter.bi_sector));
	if (queue_requeue(&mq->hotspot, hs_e))
		display_heatmap(mq);

	e = hash_lookup(mq, oblock);
	if (e) {
		requeue(mq, e);
		result->op = POLICY_HIT;
		result->cblock = infer_cblock(&mq->pool, e);
		return 0;
	}

	if (should_promote(mq, hs_e, bio, fast_promote)) {
		if (!can_migrate) {
			result->op = POLICY_MISS;
			return -EWOULDBLOCK;
		}

		insert_in_cache(mq, oblock, result);

	} else
		result->op = POLICY_MISS;

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
	epool_exit(&mq->pool);
	kfree(mq);
}

static void update_cache_hits(struct list_head *h, void *context)
{
	struct mq_policy *mq = context;
	mq->hit_count++;
}

// FIXME: redundant?
static void copy_tick(struct mq_policy *mq)
{
	unsigned long flags, tick;

	spin_lock_irqsave(&mq->tick_lock, flags);
	tick = mq->tick_protected;
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
	e->level = hint_valid ? min(hint, NR_LEVELS - 1) : 1;
	push(mq, e);

	return 0;
}

static int mq_save_hints(struct mq_policy *mq, struct queue *q,
			 policy_walk_fn fn, void *context)
{
	int r;
	unsigned level;
	struct entry *e;

	for (level = 0; level < NR_LEVELS; level++)
		for (e = head_obj(q->ix, q->qs + level); e; e = next_obj(q->ix, e)) {
			if (!is_sentinel(q, e)) {
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

	r = mq_save_hints(mq, &mq->cache_clean, fn, context);
	if (!r)
		r = mq_save_hints(mq, &mq->cache_dirty, fn, context);

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

#define CLEAN_TARGET_PERCENTAGE 25

static bool clean_target_met(struct mq_policy *mq)
{
	/*
	 * Cache entries may not be populated.  So we're cannot rely on the
	 * size of the clean queue.
	 */
	unsigned nr_clean = from_cblock(mq->cache_size) - queue_size(&mq->cache_dirty);
	unsigned target = from_cblock(mq->cache_size) * CLEAN_TARGET_PERCENTAGE / 100;

	return nr_clean >= target;
}

static int __mq_writeback_work(struct mq_policy *mq, dm_oblock_t *oblock,
			      dm_cblock_t *cblock)
{
	struct entry *e = pop_old(mq, &mq->cache_dirty);

	if (!e && !clean_target_met(mq))
		e = pop(mq, &mq->cache_dirty);

	if (!e)
		return -ENODATA;

	*oblock = e->oblock;
	*cblock = infer_cblock(&mq->pool, e);
	e->dirty = false;
	push(mq, e);

	return 0;
}

static int mq_writeback_work(struct dm_cache_policy *p, dm_oblock_t *oblock,
			     dm_cblock_t *cblock)
{
	int r;
	struct mq_policy *mq = to_mq_policy(p);

	mutex_lock(&mq->lock);
	r = __mq_writeback_work(mq, oblock, cblock);
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

	pr_alert("mq_create 1\n");
	init_policy_functions(mq);
	mq->cache_size = cache_size;
	mq->cache_block_size = cache_block_size;

	pr_alert("mq_create 2\n");
	init_hotspot_fields(mq, origin_size, cache_block_size);

	pr_alert("mq_create 3\n");
	if (epool_init(&mq->pool, from_cblock(cache_size), mq->nr_hotspot_blocks)) {
		DMERR("couldn't initialize pool of cache entries");
		goto bad_pool_init;
	}

	pr_alert("mq_create 4\n");
	mq->tick_protected = 0;
	mq->tick = 0;
	mq->hit_count = 0;
	mq->generation = 0;
	mq->discard_promote_adjustment = DEFAULT_DISCARD_PROMOTE_ADJUSTMENT;
	mq->read_promote_adjustment = DEFAULT_READ_PROMOTE_ADJUSTMENT;
	mq->write_promote_adjustment = DEFAULT_WRITE_PROMOTE_ADJUSTMENT;
	mutex_init(&mq->lock);
	spin_lock_init(&mq->tick_lock);

	pr_alert("mq_create 5\n");
	queue_init(&mq->hotspot, &mq->pool.ix);

	pr_alert("mq_create 5.5\n");
	populate_hotspot_queue(mq);

	pr_alert("mq_create 6\n");
	queue_init(&mq->cache_clean, &mq->pool.ix);
	queue_init(&mq->cache_dirty, &mq->pool.ix);

	mq->generation_period = max((unsigned) from_cblock(cache_size), 1024U);

	mq->nr_buckets = next_power(from_cblock(cache_size) / 2, 16);
	mq->hash_bits = ffs(mq->nr_buckets) - 1;
	mq->table = vzalloc(sizeof(*mq->table) * mq->nr_buckets);
	if (!mq->table)
		goto bad_alloc_table;

	pr_alert("mq_create 7\n");
	return &mq->policy;

bad_alloc_table:
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

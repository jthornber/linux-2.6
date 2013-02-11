/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 *
 * A selection of cache replacement policies for the dm-cache target:
 *   basic
 *   dumb
 *   fifo
 *   filo
 *   lfu
 *   lfu_ws
 *   lru
 *   mfu
 *   mfu_ws
 *   mru
 *   multiqueue
 *   multiqueue_ws
 *   noop
 *   random
 *   q2
 *   twoqueue
 */

#include "dm-cache-policy.h"
#include "dm.h"

#include <linux/btree.h>
#include <linux/hash.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>

/* Cache input queue defines. */
#define	READ_PROMOTE_THRESHOLD	1U	/* Minimum read cache in queue promote per element threshold. */
#define	WRITE_PROMOTE_THRESHOLD	4U	/* Minimum write cache in queue promote per element threshold. */

/* Default "multiqueue" queue timeout. */
#define	MQ_QUEUE_TMO_DEFAULT	(5UL * HZ)	/* Default seconds queue maximum lifetime per entry. FIXME: dynamic? */

/*----------------------------------------------------------------------------*/
/*
 * Large, sequential ios are probably better left on the origin device since
 * spindles tend to have good bandwidth.
 *
 * The io_tracker tries to spot when the io is in
 * one of these sequential modes.
 *
 * Two thresholds to switch between random and sequential io mode are defaulting
 * as follows and can be adjusted via the constructor and message interfaces.
 */
#define RANDOM_THRESHOLD_DEFAULT 4
#define SEQUENTIAL_THRESHOLD_DEFAULT 512

static struct kmem_cache *basic_entry_cache;
static struct kmem_cache *track_entry_cache;

enum io_pattern {
	PATTERN_SEQUENTIAL,
	PATTERN_RANDOM
};

struct io_tracker {
	sector_t next_start_osector, nr_seq_sectors;

	unsigned nr_rand_samples;
	enum io_pattern pattern;

	unsigned long thresholds[2];
};

static void iot_init(struct io_tracker *t, int sequential_threshold, int random_threshold)
{
	t->pattern = PATTERN_RANDOM;
	t->nr_seq_sectors = t->nr_rand_samples = t->next_start_osector = 0;
	t->thresholds[PATTERN_SEQUENTIAL] = sequential_threshold < 0 ? SEQUENTIAL_THRESHOLD_DEFAULT : sequential_threshold;
	t->thresholds[PATTERN_RANDOM] = random_threshold < 0 ? RANDOM_THRESHOLD_DEFAULT : random_threshold;
}

static bool iot_sequential_pattern(struct io_tracker *t)
{
	return t->pattern == PATTERN_SEQUENTIAL;
}

static void iot_update_stats(struct io_tracker *t, struct bio *bio)
{
	sector_t sectors = bio_sectors(bio);

	if (bio->bi_sector == t->next_start_osector) {
		t->nr_seq_sectors += sectors;

	} else {
		/*
		 * Just one non-sequential IO is
		 * enough to reset the counters.
		 */
		if (t->nr_seq_sectors)
			t->nr_seq_sectors = t->nr_rand_samples = 0;

		t->nr_rand_samples++;
	}

	t->next_start_osector = bio->bi_sector + sectors;
}

static void iot_check_for_pattern_switch(struct io_tracker *t,
					 sector_t block_size)
{
	bool reset = iot_sequential_pattern(t) ? (t->nr_rand_samples >= t->thresholds[PATTERN_RANDOM]) :
						 (t->nr_seq_sectors >= t->thresholds[PATTERN_SEQUENTIAL] * block_size);
	if (reset)
		t->nr_seq_sectors = t->nr_rand_samples = 0;
}

/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------*/

/* The common cache entry part for all policies. */
struct common_entry {
	struct hlist_node hlist;
	struct list_head list;
	dm_oblock_t oblock;
	unsigned count[2][2];
};

/* Cache entry struct. */
struct basic_cache_entry {
	struct common_entry ce;
	struct list_head walk;

	dm_cblock_t cblock;
	unsigned long access, expire;
	unsigned saved;
};

/* Pre and post cache queue entry. */
struct track_queue_entry {
	struct common_entry ce;
};

enum policy_type {
	p_dumb,
	p_fifo,
	p_filo,
	p_lru,
	p_mru,
	p_lfu,
	p_lfu_ws,
	p_mfu,
	p_mfu_ws,
	p_multiqueue,
	p_multiqueue_ws,
	p_noop,
	p_random,
	p_q2,
	p_twoqueue,
	p_basic	/* The default selecting one of the above. */
};

struct policy;
typedef void (*queue_add_fn)(struct policy *, struct list_head *);
typedef void (*queue_del_fn)(struct policy *, struct list_head *);
typedef struct list_head * (*queue_evict_fn)(struct policy *);

struct queue_fns {
	queue_add_fn add;
	queue_del_fn del;
	queue_evict_fn evict;
};

static struct list_head *queue_evict_multiqueue(struct policy *);
static void queue_add_noop(struct policy *, struct list_head *);

#define	IS_FILO_MRU(p)			(p->queues.fns->add == &queue_add_filo_mru)
#define	IS_LFU(p)			(p->queues.fns->add == &queue_add_lfu)
#define	IS_MULTIQUEUE(p)		(p->queues.fns->evict == &queue_evict_multiqueue)
#define	IS_Q2(p)			(p->queues.fns->add == &queue_add_q2)
#define	IS_TWOQUEUE(p)			(p->queues.fns->add == &queue_add_twoqueue)
#define	IS_DUMB(p)			(p->queues.fns->add == &queue_add_dumb)
#define	IS_NOOP(p)			(p->queues.fns->add == &queue_add_noop)

#define	IS_FIFO_FILO(p)			(p->queues.fns->del == &queue_del_fifo_filo)
#define	IS_Q2_TWOQUEUE(p)		(p->queues.fns->evict == &queue_evict_q2_twoqueue)
#define	IS_MULTIQUEUE_Q2_TWOQUEUE(p)	(p->queues.fns->del == &queue_del_multiqueue)
#define	IS_LFU_MFU_WS(p)		(p->queues.fns->del == &queue_del_lfu_mfu)

static unsigned next_power(unsigned n, unsigned min)
{
	return roundup_pow_of_two(max(n, min));
}

struct hash {
	struct hlist_head *table;
	dm_block_t hash_bits;
	unsigned nr_buckets;
};

enum count_type {
	T_HITS,
	T_SECTORS
};
struct track_queue {
	struct hash hash;
	struct track_queue_entry *elts;
	struct list_head used, free;
	unsigned count[2][2], size, nr_elts;
};

struct policy {
	struct dm_cache_policy policy;
	struct mutex lock;

	struct io_tracker tracker;

	sector_t origin_size, block_size;
	unsigned block_shift, calc_threshold_hits, promote_threshold[2], hits;

	struct {
		/* add/del/evict entry abstractions. */
		struct queue_fns *fns;

		/* Multiqueue policies. */
		struct list_head *mq;
		unsigned long mq_tmo;

		/* Pre- and post-cache queues. */
		struct track_queue pre, post;
		enum count_type ctype;

		/*
		 * FIXME:
		 * mempool based kernel lib btree used for lfu,mfu,lfu_ws and mfu_ws
		 *
		 * Now preallocating all objects on creation in order to avoid OOM deadlock.
		 *
		 * Replace with priority heap.
		 */
		struct btree_head32 fu_head;
		mempool_t *fu_pool;

		unsigned nr_mqueues, twoqueue_q0_size, twoqueue_q0_max_elts;
		struct list_head free; /* Free cache entry list */
		struct list_head used; /* Used cache entry list */
		struct list_head walk; /* walk_mappings uses this list */
	} queues;

	/* MINORME: allocate only for multiqueue? */
	unsigned long jiffies;

	/*
	 * We know exactly how many cblocks will be needed, so we can
	 * allocate them up front.
	 */
	/* FIXME: unify with track_queue? */
	dm_cblock_t cache_size;
	unsigned find_free_nr_words;
	unsigned find_free_last_word;
	struct hash chash;
	unsigned cache_count[2][2];

	/* Cache entry allocation bitset. */
	unsigned long *allocation_bitset;
	dm_cblock_t nr_cblocks_allocated;

	struct basic_cache_entry **tmp_entries;

	int threshold_args[2];
	int mq_tmo_arg, ctype_arg;
};

/*----------------------------------------------------------------------------*/
/* Low-level functions. */
static struct policy *to_policy(struct dm_cache_policy *p)
{
	return container_of(p, struct policy, policy);
}

static int to_rw(struct bio *bio)
{
	return (bio_data_dir(bio) == WRITE) ? 1 : 0;
}

/*----------------------------------------------------------------------------*/
/* Low-level queue functions. */
static void queue_init(struct list_head *q)
{
	INIT_LIST_HEAD(q);
}

static bool queue_empty(struct list_head *q)
{
	return list_empty(q);
}

static void queue_add(struct list_head *q, struct list_head *elt)
{
	list_add(elt, q);
}

static void queue_add_tail(struct list_head *q, struct list_head *elt)
{
	list_add_tail(elt, q);
}

static void queue_del(struct list_head *elt)
{
	list_del(elt);
}

static struct list_head *queue_pop(struct list_head *q)
{
	struct list_head *r = q->next;

	BUG_ON(!r);
	list_del(r);

	return r;
}

static void queue_move_tail(struct list_head *q, struct list_head *elt)
{
	list_move_tail(elt, q);
}

/*----------------------------------------------------------------------------*/

/* Allocate/free various resources. */
static int alloc_hash(struct hash *hash, unsigned elts)
{
	hash->nr_buckets = next_power(elts >> 4, 16);
	hash->hash_bits = ffs(hash->nr_buckets) - 1;
	hash->table = vzalloc(sizeof(*hash->table) * hash->nr_buckets);

	return hash->table ? 0 : -ENOMEM;
}

static void free_hash(struct hash *hash)
{
	if (hash->table)
		vfree(hash->table);
}

/* Free/alloc basic cache entry structures. */
static void free_cache_entries(struct policy *p)
{
	struct basic_cache_entry *e, *tmp;

	list_for_each_entry_safe(e, tmp, &p->queues.free, ce.list)
		kmem_cache_free(basic_entry_cache, e);

	list_for_each_entry_safe(e, tmp, &p->queues.walk, walk)
		kmem_cache_free(basic_entry_cache, e);
}

static int alloc_cache_blocks_with_hash(struct policy *p, unsigned cache_size)
{
	int r = -ENOMEM;
	unsigned u = cache_size;

	p->nr_cblocks_allocated = to_cblock(0);

	while (u--) {
		struct basic_cache_entry *e = kmem_cache_zalloc(basic_entry_cache, GFP_KERNEL);

		if (!e)
			goto bad_cache_alloc;

		queue_add(&p->queues.free, &e->ce.list);
	}

	/* Cache entries hash. */
	r = alloc_hash(&p->chash, cache_size);
	if (!r)
		return 0;

bad_cache_alloc:
	free_cache_entries(p);

	return r;
}

static void free_cache_blocks_and_hash(struct policy *p)
{
	free_hash(&p->chash);
	free_cache_entries(p);
}

static void free_track_queue(struct track_queue *q)
{
	struct track_queue_entry *tqe, *tmp;

	free_hash(&q->hash);

	list_splice(&q->used, &q->free);
	list_for_each_entry_safe(tqe, tmp, &q->free, ce.list)
		kmem_cache_free(track_entry_cache, tqe);
}

static int alloc_track_queue_with_hash(struct track_queue *q, unsigned elts)
{
	int r = -ENOMEM;
	unsigned u = elts;

	while (u--) {
		struct track_queue_entry *tqe = kmem_cache_zalloc(track_entry_cache, GFP_KERNEL);

		if (!tqe)
			goto bad_tq_alloc;

		queue_add(&q->free, &tqe->ce.list);
	}


	r = alloc_hash(&q->hash, elts);
	if (!r)
		return 0;

bad_tq_alloc:
	free_track_queue(q);

	return r;
}

static int alloc_multiqueues(struct policy *p, unsigned mqueues)
{
	/* Multiqueue heads. */
	p->queues.nr_mqueues = mqueues;
	p->queues.mq = vzalloc(sizeof(*p->queues.mq) * mqueues);
	if (!p->queues.mq)
		return -ENOMEM;

	while (mqueues--)
		queue_init(&p->queues.mq[mqueues]);

	return 0;
}

static void free_multiqueues(struct policy *p)
{
	vfree(p->queues.mq);
}

static struct basic_cache_entry *alloc_cache_entry(struct policy *p)
{
	struct basic_cache_entry *e;

	BUG_ON(from_cblock(p->nr_cblocks_allocated) >= from_cblock(p->cache_size));

	e = list_entry(queue_pop(&p->queues.free), struct basic_cache_entry, ce.list);
	p->nr_cblocks_allocated = to_cblock(from_cblock(p->nr_cblocks_allocated) + 1);

	return e;
}

static void alloc_cblock(struct policy *p, dm_cblock_t cblock)
{
	BUG_ON(from_cblock(cblock) >= from_cblock(p->cache_size));
	BUG_ON(test_bit(from_cblock(cblock), p->allocation_bitset));
	set_bit(from_cblock(cblock), p->allocation_bitset);
}

static void free_cblock(struct policy *p, dm_cblock_t cblock)
{
	BUG_ON(from_cblock(cblock) >= from_cblock(p->cache_size));
	BUG_ON(!test_bit(from_cblock(cblock), p->allocation_bitset));
	clear_bit(from_cblock(cblock), p->allocation_bitset);
}

static void queue_add_twoqueue(struct policy *p, struct list_head *elt);
static bool any_free_cblocks(struct policy *p)
{
	if (IS_TWOQUEUE(p)) {
		/*
		 * Only allow a certain amount of the total cache size in queue 0
		 * (cblocks with hit count 1).
		 */
		if (p->queues.twoqueue_q0_size == p->queues.twoqueue_q0_max_elts)
			return false;
	}

	return !queue_empty(&p->queues.free);
}

/*----------------------------------------------------------------*/

static unsigned bit_set_nr_words(unsigned nr_cblocks)
{
	return dm_div_up(nr_cblocks, BITS_PER_LONG);
}

static unsigned long *alloc_bitset(unsigned nr_cblocks)
{
	return vzalloc(sizeof(unsigned long) * bit_set_nr_words(nr_cblocks));
}

static void free_bitset(unsigned long *bits)
{
	if (bits)
		vfree(bits);
}
/*----------------------------------------------------------------------------*/

/* Hash functions (lookup, insert, remove). */
static struct common_entry *__lookup_common_entry(struct hash *hash, dm_oblock_t oblock)
{
	unsigned h = hash_64(from_oblock(oblock), hash->hash_bits);
	struct common_entry *cur;
	struct hlist_node *tmp;
	struct hlist_head *bucket = &hash->table[h];

	hlist_for_each_entry(cur, tmp, bucket, hlist) {
		if (cur->oblock == oblock) {
			/* Move upfront bucket for faster access. */
			hlist_del(&cur->hlist);
			hlist_add_head(&cur->hlist, bucket);
			return cur;
		}
	}

	return NULL;
}

static struct basic_cache_entry *lookup_cache_entry(struct policy *p,
						    dm_oblock_t oblock)
{
	struct common_entry *ce = IS_NOOP(p) ? NULL :
		__lookup_common_entry(&p->chash, oblock);

	return ce ? container_of(ce, struct basic_cache_entry, ce) : NULL;
}

static void insert_cache_hash_entry(struct policy *p, struct basic_cache_entry *e)
{
	unsigned h = hash_64(from_oblock(e->ce.oblock), p->chash.hash_bits);

	hlist_add_head(&e->ce.hlist, &p->chash.table[h]);
}

static void remove_cache_hash_entry(struct policy *p, struct basic_cache_entry *e)
{
	hlist_del(&e->ce.hlist);
}

/* Cache track queue. */
static struct track_queue_entry *lookup_track_queue_entry(struct track_queue *q,
							  dm_oblock_t oblock)
{
	struct common_entry *ce = __lookup_common_entry(&q->hash, oblock);

	return ce ? container_of(ce, struct track_queue_entry, ce) : NULL;
}

static void insert_track_queue_hash_entry(struct track_queue *q,
					  struct track_queue_entry *tqe)
{
	unsigned h = hash_64(from_oblock(tqe->ce.oblock), q->hash.hash_bits);

	hlist_add_head(&tqe->ce.hlist, &q->hash.table[h]);
}

static void remove_track_queue_hash_entry(struct track_queue_entry *tqe)
{
	hlist_del(&tqe->ce.hlist);
}
/*----------------------------------------------------------------------------*/

/* Out of cache queue support functions. */
static struct track_queue_entry *pop_track_queue(struct track_queue *q)
{
	struct track_queue_entry *r;

	if (queue_empty(&q->free)) {
		unsigned t, u, end = ARRAY_SIZE(r->ce.count[T_HITS]);

		BUG_ON(queue_empty(&q->used));
		r = list_entry(queue_pop(&q->used), struct track_queue_entry, ce.list);
		remove_track_queue_hash_entry(r);
		q->size--;

		for (t = 0; t < end; t++)
			for (u = 0; u < end; u++)
				q->count[t][u] -= q->count[t][u];

		memset(r, 0, sizeof(*r));

	} else
		r = list_entry(queue_pop(&q->free), struct track_queue_entry, ce.list);

	return r;
}

/* Retrieve track entry from free list _or_ evict one from track queue. */
static struct track_queue_entry *
pop_add_and_insert_track_queue_entry(struct track_queue *q, dm_oblock_t oblock)
{
	struct track_queue_entry *r = pop_track_queue(q);

	r->ce.oblock = oblock;
	queue_add_tail(&q->used, &r->ce.list);
	insert_track_queue_hash_entry(q, r);
	q->size++;

	return r;
}

static unsigned ctype_threshold(struct policy *p, unsigned th)
{
	return th << (p->queues.ctype == T_HITS ? 0 : p->block_shift);
}

static void init_promote_threshold(struct policy *p, bool cache_full)
{
	p->promote_threshold[0] = ctype_threshold(p, READ_PROMOTE_THRESHOLD);
	p->promote_threshold[1] = ctype_threshold(p, WRITE_PROMOTE_THRESHOLD);

	if (cache_full) {
		p->promote_threshold[0] += ((p->cache_count[p->queues.ctype][0] * READ_PROMOTE_THRESHOLD) << 5) / from_cblock(p->cache_size);
		p->promote_threshold[1] += ((p->cache_count[p->queues.ctype][1] * WRITE_PROMOTE_THRESHOLD) << 6) / from_cblock(p->cache_size);
	}
}

static void calc_rw_threshold(struct policy *p)
{
	if (++p->hits > p->calc_threshold_hits && !any_free_cblocks(p)) {
		p->hits = 0;
		init_promote_threshold(p, true);

		pr_alert("promote thresholds = %u/%u queue stats = %u/%u\n",
			 p->promote_threshold[0], p->promote_threshold[1], p->queues.pre.size, p->queues.post.size);
	}
}

/* Add or update track queue entry. */
static struct track_queue_entry *
update_track_queue(struct policy *p, struct track_queue *q, dm_oblock_t oblock,
		   int rw, unsigned hits, sector_t sectors)
{
	struct track_queue_entry *r = lookup_track_queue_entry(q, oblock);

	if (r)
		queue_move_tail(&q->used, &r->ce.list);

	else {
		r = pop_add_and_insert_track_queue_entry(q, oblock);
		BUG_ON(!r);
	}

	r->ce.count[T_HITS][rw] += hits;
	r->ce.count[T_SECTORS][rw] += sectors;
	q->count[T_HITS][rw] += hits;
	q->count[T_SECTORS][rw] += sectors;

	return r;
}

/* Get hit/sector counts from track queue entry if exists and delete the entry. */
static void get_any_counts_from_track_queue(struct track_queue *q,
					    struct basic_cache_entry *e,
					    dm_oblock_t oblock)
{
	struct track_queue_entry *tqe = lookup_track_queue_entry(q, oblock);

	if (tqe) {
		/*
		 * On track queue -> retrieve memorized hit count and sectors
		 * in order to sort into appropriate queue on add_cache_entry().
		 */
		unsigned t, u, end = ARRAY_SIZE(e->ce.count[T_HITS]);

		remove_track_queue_hash_entry(tqe);

		for (t = 0; t < end; t++)
			for (u = 0; u < end; u++) {
				e->ce.count[t][u] += tqe->ce.count[t][u];
				q->count[t][u] -= tqe->ce.count[t][u];
		}

		memset(&tqe->ce.count, 0, sizeof(tqe->ce.count));
		queue_move_tail(&q->free, &tqe->ce.list);
		q->size--;
	}
}

static unsigned sum_count(struct policy *p, struct common_entry *ce, enum count_type t)
{
	return (ce->count[t][0] + ce->count[t][1]) >> (t == T_HITS ? 0 : p->block_shift);
}

/*----------------------------------------------------------------------------*/

/* queue_add_.*() functions. */
static void __queue_add_default(struct policy *p, struct list_head *elt,
				bool to_head)
{
	struct list_head *q = &p->queues.used;
	struct basic_cache_entry *e = list_entry(elt, struct basic_cache_entry, ce.list);

	to_head ? queue_add(q, elt) : queue_add_tail(q, elt);
	queue_add_tail(&p->queues.walk, &e->walk);
}

static void queue_add_default(struct policy *p, struct list_head *elt)
{
	__queue_add_default(p, elt, true);
}

static void queue_add_default_tail(struct policy *p, struct list_head *elt)
{
	__queue_add_default(p, elt, false);
}

static void queue_add_filo_mru(struct policy *p, struct list_head *elt)
{
	queue_add_default(p, elt);
}

static u32 __make_key(u32 k, bool is_lfu)
{
	/*
	 * Invert key in case of lfu to allow btree_last() to
	 * retrieve the minimum used list.
	 */
	return is_lfu ? ~k : k;
}

static void __queue_add_lfu_mfu(struct policy *p, struct list_head *elt,
				bool is_lfu, enum count_type ctype)
{
	struct list_head *head;
	struct basic_cache_entry *e = list_entry(elt, struct basic_cache_entry, ce.list);
	u32 key = __make_key(sum_count(p, &e->ce, ctype), is_lfu);

	/*
	 * Memorize key for deletion (e->ce.count[T_HITS]/e->ce.count[T_SECTORS]
	 * will have changed before)
	 */
	e->saved = key;

	/*
	 * Key is e->ce.count[T_HITS]/e->ce.count[T_SECTORS] for mfu or
	 * ~e->ce.count[T_HITS]/~e->ce.count[T_SECTORS] for lfu in order to
	 * allow for btree_last() to be able to retrieve the appropriate node.
	 *
	 * A list of cblocks sharing the same hit/sector count is hanging off that node.
	 *
	 * FIXME: replace with priority heap.
	 */
	head = btree_lookup32(&p->queues.fu_head, key);
	if (head) {
		/* Always add to the end where we'll pop cblocks off */
		list_add_tail(elt, head);

		if (is_lfu) {
			/*
			 * For lfu, point to added new head, so that
			 * the older entry will get popped first.
			 */
			int r = btree_update32(&p->queues.fu_head, key, (void *) elt);

			BUG_ON(r);
		}

	} else {
		/* New key, insert into tree. */
		int r = btree_insert32(&p->queues.fu_head, key, (void *) elt, GFP_KERNEL);

		BUG_ON(r);
		INIT_LIST_HEAD(elt);
	}

	queue_add_tail(&p->queues.walk, &e->walk);
}

static void queue_add_lfu(struct policy *p, struct list_head *elt)
{
	__queue_add_lfu_mfu(p, elt, true, T_HITS);
}

static void queue_add_mfu(struct policy *p, struct list_head *elt)
{
	__queue_add_lfu_mfu(p, elt, false, T_HITS);
}

static void queue_add_lfu_ws(struct policy *p, struct list_head *elt)
{
	__queue_add_lfu_mfu(p, elt, true, T_SECTORS);
}

static void queue_add_mfu_ws(struct policy *p, struct list_head *elt)
{
	__queue_add_lfu_mfu(p, elt, false, T_SECTORS);
}

static unsigned __select_multiqueue(struct policy *p, struct basic_cache_entry *e,
				    enum count_type ctype)
{
	return min((unsigned) ilog2(sum_count(p, &e->ce, ctype)), p->queues.nr_mqueues - 1U);
}

static unsigned __get_twoqueue(struct policy *p, struct basic_cache_entry *e)
{
	return sum_count(p, &e->ce, T_HITS) > 1 ? 1 : 0;
}

static unsigned long __queue_tmo_multiqueue(struct policy *p)
{
	return p->jiffies + p->queues.mq_tmo;
}

static void demote_multiqueues(struct policy *p)
{
	struct basic_cache_entry *e;
	struct list_head *cur = p->queues.mq, *end;

	if (!queue_empty(cur))
		return;

	/*
	 * Start with 2nd queue, because we conditionally move
	 * from queue to queue - 1
	 */
	end = cur + p->queues.nr_mqueues;
	while (++cur < end) {
		while (!queue_empty(cur)) {
			/* Reference head element. */
			e = list_first_entry(cur, struct basic_cache_entry, ce.list);

			/*
			 * If expired, move entry from head of higher prio
			 * queue to tail of lower prio one.
			 */
			if (time_after_eq(p->jiffies, e->expire)) {
				queue_move_tail(cur - 1, &e->ce.list);
				e->expire = __queue_tmo_multiqueue(p);

			} else
				break;
		}
	}
}

static void __queue_add_multiqueue(struct policy *p, struct list_head *elt,
				   enum count_type ctype)
{
	struct basic_cache_entry *e = list_entry(elt, struct basic_cache_entry, ce.list);
	unsigned queue = __select_multiqueue(p, e, ctype);

	e->expire = __queue_tmo_multiqueue(p);
	queue_add_tail(&p->queues.mq[queue], &e->ce.list);
	queue_add_tail(&p->queues.walk, &e->walk);
}

static void queue_add_multiqueue(struct policy *p, struct list_head *elt)
{
	__queue_add_multiqueue(p, elt, T_HITS);
}

static void queue_add_multiqueue_ws(struct policy *p, struct list_head *elt)
{
	__queue_add_multiqueue(p, elt, T_SECTORS);
}

static void queue_add_q2(struct policy *p, struct list_head *elt)
{
	struct basic_cache_entry *e = list_entry(elt, struct basic_cache_entry, ce.list);

	queue_add_tail(&p->queues.mq[0], &e->ce.list);
	queue_add_tail(&p->queues.walk, &e->walk);
}

static void queue_add_twoqueue(struct policy *p, struct list_head *elt)
{
	unsigned queue;
	struct basic_cache_entry *e = list_entry(elt, struct basic_cache_entry, ce.list);

	queue = e->saved = __get_twoqueue(p, e);
	if (!queue)
		p->queues.twoqueue_q0_size++;

	queue_add_tail(&p->queues.mq[queue], &e->ce.list);
	queue_add_tail(&p->queues.walk, &e->walk);
}

static void queue_add_dumb(struct policy *p, struct list_head *elt)
{
	queue_add_default_tail(p, elt);
}

static void queue_add_noop(struct policy *p, struct list_head *elt)
{
	queue_add_default_tail(p, elt); /* Never called. */
}
/*----------------------------------------------------------------------------*/

/* queue_del_.*() functions. */
static void queue_del_default(struct policy *p, struct list_head *elt)
{
	struct basic_cache_entry *e = list_entry(elt, struct basic_cache_entry, ce.list);

	queue_del(&e->ce.list);
	queue_del(&e->walk);
}

static void queue_del_fifo_filo(struct policy *p, struct list_head *elt)
{
	queue_del_default(p, elt);
}

static void queue_del_lfu_mfu(struct policy *p, struct list_head *elt)
{
	struct list_head *head;
	struct basic_cache_entry *e = list_entry(elt, struct basic_cache_entry, ce.list);
	/* Retrieve saved key which has been saved by queue_add_lfu_mfu(). */
	u32 key = e->saved;

	head = btree_lookup32(&p->queues.fu_head, key);
	BUG_ON(!head);
	if (head == elt) {
		/* Need to remove head, because it's the only element. */
		if (list_empty(head)) {
			struct list_head *h = btree_remove32(&p->queues.fu_head, key);

			BUG_ON(!h);

		} else {
			int r;

			/* Update node to point to next entry as new head. */
			head = head->next;
			list_del(elt);
			r = btree_update32(&p->queues.fu_head, key, (void *) head);
			BUG_ON(r);
		}

	} else
		/* If not head, we can simply remove the element from the list. */
		list_del(elt);

	queue_del(&e->walk);
}

static void queue_del_multiqueue(struct policy *p, struct list_head *elt)
{
	struct basic_cache_entry *e = list_entry(elt, struct basic_cache_entry, ce.list);

	if (IS_TWOQUEUE(p)) {
		unsigned queue = e->saved;

		if (!queue)
			p->queues.twoqueue_q0_size--;
	}

	queue_del(&e->ce.list);
	queue_del(&e->walk);
}
/*----------------------------------------------------------------------------*/

/* queue_evict_.*() functions. */
static struct list_head *queue_evict_default(struct policy *p)
{
	struct list_head *r = queue_pop(&p->queues.used);
	struct basic_cache_entry *e = list_entry(r, struct basic_cache_entry, ce.list);

	queue_del(&e->walk);

	return r;
}

static struct list_head *queue_evict_lfu_mfu(struct policy *p)
{
	u32 k;
	struct list_head *r;
	struct basic_cache_entry *e;

	/* This'll retrieve lfu/mfu entry because of __make_key(). */
	r = btree_last32(&p->queues.fu_head, &k);
	BUG_ON(!r);

	if (list_empty(r))
		r = btree_remove32(&p->queues.fu_head, k);

	else {
		/* Retrieve last element in order to minimize btree updates. */
		r = r->prev;
		BUG_ON(!r);
		list_del(r);
	}

	e = list_entry(r, struct basic_cache_entry, ce.list);
	e->saved = 0;
	queue_del(&e->walk);

	return r;
}

static struct list_head *queue_evict_random(struct policy *p)
{
	struct list_head *r = p->queues.used.next;
	struct basic_cache_entry *e;
	dm_block_t off = random32();

	BUG_ON(!r);

	/* FIXME: cblock_t is 32 bit for the time being. */
	/* Be prepared for large caches ;-) */
	if (from_cblock(p->cache_size) >= UINT_MAX)
		off |= ((dm_block_t) random32() << 32);

	/* FIXME: overhead walking list. */
	off = do_div(off, from_cblock(p->cache_size));
	while (off--)
		r = r->next;

	e = list_entry(r, struct basic_cache_entry, ce.list);
	queue_del(r);
	queue_del(&e->walk);

	return r;
}

static struct list_head *queue_evict_multiqueue(struct policy *p)
{
	struct list_head *cur = p->queues.mq - 1, /* -1 because of ++cur below. */
			 *end = p->queues.mq + p->queues.nr_mqueues;

	while (++cur < end) {
		if (!queue_empty(cur)) {
			struct basic_cache_entry *e;
			struct list_head *r;

			if (IS_TWOQUEUE(p) && cur == p->queues.mq)
				p->queues.twoqueue_q0_size--;

			r = queue_pop(cur);
			e = list_entry(r, struct basic_cache_entry, ce.list);
			queue_del(&e->walk);

			return r;
		}

		if (IS_MULTIQUEUE(p))
			break;
	}

	return NULL;
}

static struct list_head *queue_evict_q2_twoqueue(struct policy *p)
{
	return queue_evict_multiqueue(p);
}

/*----------------------------------------------------------------------------*/

/*
 * This doesn't allocate the block.
 */
static int __find_free_cblock(struct policy *p, unsigned begin, unsigned end,
			      dm_cblock_t *result, unsigned *last_word)
{
	int r = -ENOSPC;
	unsigned w;

	for (w = begin; w < end; w++) {
		/*
		 * ffz is undefined if no zero exists
		 */
		if (p->allocation_bitset[w] != ULONG_MAX) {
			*last_word = w;
			*result = to_cblock((w * BITS_PER_LONG) + ffz(p->allocation_bitset[w]));
			if (from_cblock(*result) < from_cblock(p->cache_size))
				r = 0;

			break;
		}
	}

	return r;
}

static int find_free_cblock(struct policy *p, dm_cblock_t *result)
{
	int r = __find_free_cblock(p, p->find_free_last_word, p->find_free_nr_words, result, &p->find_free_last_word);

	if (r == -ENOSPC && p->find_free_last_word)
		r = __find_free_cblock(p, 0, p->find_free_last_word, result, &p->find_free_last_word);

	return r;
}

static void alloc_cblock_insert_cache_and_count_entry(struct policy *p, struct basic_cache_entry *e)
{
	unsigned t, u, end = ARRAY_SIZE(e->ce.count[T_HITS]);

	alloc_cblock(p, e->cblock);
	insert_cache_hash_entry(p, e);

	if (IS_DUMB(p) || IS_NOOP(p))
		return;

	for (t = 0; t < end; t++)
		for (u = 0; u < end; u++)
			p->cache_count[t][u] += e->ce.count[t][u];
}

static void add_cache_entry(struct policy *p, struct basic_cache_entry *e)
{
	p->queues.fns->add(p, &e->ce.list);
	alloc_cblock_insert_cache_and_count_entry(p, e);
}

static void remove_cache_entry(struct policy *p, struct basic_cache_entry *e)
{
	unsigned t, u, end = ARRAY_SIZE(e->ce.count[T_HITS]);

	remove_cache_hash_entry(p, e);
	free_cblock(p, e->cblock);

	if (IS_DUMB(p) || IS_NOOP(p))
		return;

	for (t = 0; t < end; t++)
		for (u = 0; u < end; u++)
			p->cache_count[t][u] -= e->ce.count[t][u];
}

static struct basic_cache_entry *evict_cache_entry(struct policy *p)
{
	struct basic_cache_entry *r;
	struct list_head *elt = p->queues.fns->evict(p);

	if (elt) {
		r = list_entry(elt, struct basic_cache_entry, ce.list);
		remove_cache_entry(p, r);
	} else
		r = NULL;

	return r;
}

static void update_cache_entry(struct policy *p, struct basic_cache_entry *e,
			       struct bio *bio, struct policy_result *result)
{
	int rw;

	result->op = POLICY_HIT;
	result->cblock = e->cblock;

	if (IS_DUMB(p) || IS_NOOP(p))
		return;

	rw = to_rw(bio);

	e->ce.count[T_HITS][rw]++;
	e->ce.count[T_SECTORS][rw] += bio_sectors(bio);

	/*
	 * No queue deletion and reinsertion needed with fifo/filo; ie.
	 * avoid queue reordering for those.
	 */
	if (!IS_FIFO_FILO(p)) {
		p->queues.fns->del(p, &e->ce.list);
		p->queues.fns->add(p, &e->ce.list);
	}
}

static void get_cache_block(struct policy *p, dm_oblock_t oblock, struct bio *bio,
			    struct policy_result *result)
{
	int rw = to_rw(bio);
	struct basic_cache_entry *e;

	if (queue_empty(&p->queues.free)) {
		if (IS_MULTIQUEUE(p))
			demote_multiqueues(p);

		e = evict_cache_entry(p);
		if (!e)
			return;

		/* Memorize hits and sectors of just evicted entry on out queue. */
		if (!IS_DUMB(p)) {
			/* Reads. */
			update_track_queue(p, &p->queues.post, e->ce.oblock, 0,
					   e->ce.count[T_HITS][0],
					   e->ce.count[T_SECTORS][0]);
			/* Writes. */
			update_track_queue(p, &p->queues.post, e->ce.oblock, 1,
					   e->ce.count[T_HITS][1],
					   e->ce.count[T_SECTORS][1]);
		}

		result->old_oblock = e->ce.oblock;
		result->op = POLICY_REPLACE;

	} else {
		int r;

		e = alloc_cache_entry(p);
		r = find_free_cblock(p, &e->cblock);
		BUG_ON(r);

		result->op = POLICY_NEW;
	}

	/*
	 * If an entry for oblock exists on track queues ->
	 * retrieve hit counts and sectors from track queues and delete
	 * the respective tracking entries.
	 */
	if (!IS_DUMB(p)) {
		memset(&e->ce.count, 0, sizeof(e->ce.count));
		e->ce.count[T_HITS][rw] = 1;
		e->ce.count[T_SECTORS][rw] = bio_sectors(bio);
		get_any_counts_from_track_queue(&p->queues.pre, e, oblock);
		get_any_counts_from_track_queue(&p->queues.post, e, oblock);
	}

	result->cblock = e->cblock;
	e->ce.oblock = oblock;
	add_cache_entry(p, e);
}

static bool in_cache(struct policy *p, dm_oblock_t oblock, struct bio *bio, struct policy_result *result)
{
	struct basic_cache_entry *e = lookup_cache_entry(p, oblock);

	if (e) {
		/* Cache hit: update entry on queues, increment its hit count */
		update_cache_entry(p, e, bio, result);
		return true;
	}

	return false;
}

static bool should_promote(struct policy *p, struct track_queue_entry *tqe,
			   dm_oblock_t oblock, int rw, bool discarded_oblock,
			   struct policy_result *result)
{
	BUG_ON(!tqe);
	calc_rw_threshold(p);

	if (discarded_oblock && any_free_cblocks(p))
		/*
		 * We don't need to do any copying at all, so give this a
		 * very low threshold.  In practice this only triggers
		 * during initial population after a format.
		 */
		return true;

	return tqe->ce.count[p->queues.ctype][rw] >= p->promote_threshold[rw];
}

static void map_prerequisites(struct policy *p, struct bio *bio)
{
	/* Update io tracker. */
	iot_update_stats(&p->tracker, bio);
	iot_check_for_pattern_switch(&p->tracker, p->block_size);

	/* Get start jiffies needed for time based queue demotion. */
	if (IS_MULTIQUEUE(p))
		p->jiffies = get_jiffies_64();
}

static int map(struct policy *p, dm_oblock_t oblock,
	       bool can_block, bool can_migrate, bool discarded_oblock,
	       struct bio *bio, struct policy_result *result)
{
	int rw = to_rw(bio);
	struct track_queue_entry *tqe;

	if (IS_NOOP(p))
		return 0;

	if (in_cache(p, oblock, bio, result))
		return 0;

	if (!IS_DUMB(p))
		/* Record hits on pre cache track queue. */
		tqe = update_track_queue(p, &p->queues.pre, oblock, rw, 1, bio_sectors(bio));

	if (!can_migrate)
		return -EWOULDBLOCK;

	else if (!IS_DUMB(p) && iot_sequential_pattern(&p->tracker))
		;

	else if (IS_DUMB(p) || should_promote(p, tqe, oblock, rw, discarded_oblock, result))
		get_cache_block(p, oblock, bio, result);

	return 0;
}

/* Public interface (see dm-cache-policy.h */
static int basic_map(struct dm_cache_policy *pe, dm_oblock_t oblock,
		     bool can_block, bool can_migrate, bool discarded_oblock,
		     struct bio *bio, struct policy_result *result)
{
	int r;
	struct policy *p = to_policy(pe);

	result->op = POLICY_MISS;

	if (can_block)
		mutex_lock(&p->lock);

	else if (!mutex_trylock(&p->lock))
		return -EWOULDBLOCK;

	if (!IS_DUMB(p) && !IS_NOOP(p))
		map_prerequisites(p, bio);

	r = map(p, oblock, can_block, can_migrate, discarded_oblock, bio, result);

	mutex_unlock(&p->lock);

	return r;
}

static int basic_lookup(struct dm_cache_policy *pe, dm_oblock_t oblock, dm_cblock_t *cblock)
{
	int r;
	struct policy *p = to_policy(pe);
	struct basic_cache_entry *e;

	if (!mutex_trylock(&p->lock))
		return -EWOULDBLOCK;

	e = lookup_cache_entry(p, oblock);
	if (e) {
		*cblock = e->cblock;
		r = 0;

	} else
		r = -ENOENT;

	mutex_unlock(&p->lock);

	return r;
}

static void basic_destroy(struct dm_cache_policy *pe)
{
	struct policy *p = to_policy(pe);

	if (IS_LFU_MFU_WS(p))
		btree_destroy32(&p->queues.fu_head);

	else if (IS_MULTIQUEUE_Q2_TWOQUEUE(p))
		free_multiqueues(p);

	free_track_queue(&p->queues.post);
	free_track_queue(&p->queues.pre);
	free_bitset(p->allocation_bitset);
	free_cache_blocks_and_hash(p);
	kfree(p);
}

/* FIXME: converters can disappear in case of larger hint cast in metadata. */
static const uint16_t high_flag = 0x8000;
static const uint32_t hint_lmask = 0xFFFF;
static const uint32_t hint_hmask = 0xFFFF0000;
static uint16_t count_to_hint(unsigned val)
{
	uint16_t vh, vl;

	vl = val & hint_lmask;
	vh = (val & hint_hmask) >> 16;

	if (vh)
		return vh | high_flag;
	else
		return vl & ~high_flag;
}

static uint32_t counts_to_hint(unsigned read, unsigned write)
{
	return count_to_hint(read) & (count_to_hint(write) << 16);
}

static unsigned check_high(uint16_t v)
{
	unsigned r = v;

	if (r & high_flag)
		r = (r & ~high_flag) << 16;

	return r;
}

static void hint_to_counts(uint32_t val, unsigned *read, unsigned *write)
{
	*read  = check_high(val & hint_lmask);
	*write = check_high((val & hint_hmask) >> 16);

}

static void sort_in_cache_entry(struct policy *p, struct basic_cache_entry *e)
{
	struct list_head *elt;
	struct basic_cache_entry *cur;

	list_for_each(elt, &p->queues.used) {
		cur = list_entry(elt, struct basic_cache_entry, ce.list);
		if (e->ce.count[T_HITS][0] > cur->ce.count[T_HITS][0])
			break;
	}

	if (elt == &p->queues.used)
		list_add_tail(&e->ce.list, elt);
	else
		list_add(&e->ce.list, elt);

	queue_add_tail(&p->queues.walk, &e->walk);
}

static int basic_load_mapping(struct dm_cache_policy *pe,
			      dm_oblock_t oblock, dm_cblock_t cblock,
			      uint32_t hint, bool hint_valid)
{
	struct policy *p = to_policy(pe);
	struct basic_cache_entry *e;

	e = alloc_cache_entry(p);
	if (!e)
		return -ENOMEM;

	e->cblock = cblock;
	e->ce.oblock = oblock;

	if (hint_valid) {
		unsigned reads, writes;

		hint_to_counts(hint, &reads, &writes);
		e->ce.count[T_HITS][0] = reads;
		e->ce.count[T_HITS][1] = writes;

		if (IS_MULTIQUEUE(p) || IS_TWOQUEUE(p) || IS_LFU_MFU_WS(p)) {
			/* FIXME: store also in larger hints rather than making up. */
			e->ce.count[T_SECTORS][0] = reads << p->block_shift;
			e->ce.count[T_SECTORS][1] = writes << p->block_shift;
		}
	}

	if (IS_MULTIQUEUE(p) || IS_TWOQUEUE(p) || IS_LFU_MFU_WS(p))
		add_cache_entry(p, e);
	else {
		sort_in_cache_entry(p, e);
		alloc_cblock_insert_cache_and_count_entry(p, e);
	}

	return 0;
}

/* Walk mappings */
static int basic_walk_mappings(struct dm_cache_policy *pe, policy_walk_fn fn,
			       void *context)
{
	int r = 0;
	unsigned nr = 0;
	struct policy *p = to_policy(pe);
	struct basic_cache_entry *e;

	mutex_lock(&p->lock);

	list_for_each_entry(e, &p->queues.walk, walk) {
		unsigned reads, writes;

		if (IS_MULTIQUEUE_Q2_TWOQUEUE(p) || IS_LFU_MFU_WS(p)) {
			reads = e->ce.count[T_HITS][0];
			writes = e->ce.count[T_HITS][1];

		} else {
			reads = nr++;

			if (IS_FILO_MRU(p))
				reads = from_cblock(p->cache_size) - reads - 1;

			writes = 0;
		}

		r = fn(context, e->cblock, e->ce.oblock,
		       counts_to_hint(reads, writes));
		if (r)
			break;
	}

	mutex_unlock(&p->lock);
	return r;
}

static struct basic_cache_entry *__basic_force_remove_mapping(struct policy *p,
							      dm_oblock_t oblock)
{
	struct basic_cache_entry *r = lookup_cache_entry(p, oblock);

	BUG_ON(!r);

	p->queues.fns->del(p, &r->ce.list);
	remove_cache_entry(p, r);

	return r;
}

static void basic_remove_mapping(struct dm_cache_policy *pe, dm_oblock_t oblock)
{
	struct policy *p = to_policy(pe);
	struct basic_cache_entry *e;

	mutex_lock(&p->lock);
	e = __basic_force_remove_mapping(p, oblock);
	memset(&e->ce.count, 0, sizeof(e->ce.count));
	queue_add_tail(&p->queues.free, &e->ce.list);

	BUG_ON(!from_cblock(p->nr_cblocks_allocated));
	p->nr_cblocks_allocated = to_cblock(from_cblock(p->nr_cblocks_allocated) - 1);
	mutex_unlock(&p->lock);
}

static void basic_force_mapping(struct dm_cache_policy *pe,
				dm_oblock_t current_oblock, dm_oblock_t oblock)
{
	struct policy *p = to_policy(pe);
	struct basic_cache_entry *e;

	mutex_lock(&p->lock);
	e = __basic_force_remove_mapping(p, current_oblock);
	e->ce.oblock = oblock;
	add_cache_entry(p, e);
	mutex_unlock(&p->lock);
}

static dm_cblock_t basic_residency(struct dm_cache_policy *pe)
{
	/* FIXME: lock mutex, not sure we can block here. */
	return to_policy(pe)->nr_cblocks_allocated;
}

/* ctr/message optional argument parsing. */
static int process_threshold_option(struct policy *p, char **argv,
				    enum io_pattern pattern, bool set_ctr_arg)
{
	unsigned long tmp;

	if (kstrtoul(argv[1], 10, &tmp))
		return -EINVAL;

	if (set_ctr_arg) {
		if (p->threshold_args[pattern] > -1)
			return -EINVAL;

		p->threshold_args[pattern] = tmp;
	}

	p->tracker.thresholds[pattern] = tmp;

	return 0;
}

static int process_multiqueue_timeout_option(struct policy *p, char **argv, bool set_ctr_arg)
{
	unsigned long tmp;

	/* multiqueue timeout in milliseconds. */
	if (kstrtoul(argv[1], 10, &tmp) ||
	    tmp < 1 || tmp > 24*3600*1000) /* 1 day max :) */
		return -EINVAL;

	if (IS_MULTIQUEUE(p)) {
		unsigned long ticks = tmp * HZ / 1000;

		if (set_ctr_arg) {
			if (p->mq_tmo_arg > -1)
				return -EINVAL;

			p->mq_tmo_arg = tmp;
		}

		/* Ensure one tick timeout minimum. */
		p->queues.mq_tmo = ticks ? ticks : 1;

		return 0;
	}

	return -EINVAL;
}

static int process_hits_option(struct policy *p, char **argv, bool set_ctr_arg)
{
	unsigned long tmp;

	/* Only allow as ctr argument. */
	if (!set_ctr_arg)
		return -EINVAL;

	if (kstrtoul(argv[1], 10, &tmp) || tmp > 1)
		return -EINVAL;

	if (p->ctype_arg > -1)
		return -EINVAL;

	p->ctype_arg = tmp;
	p->queues.ctype = tmp ? T_HITS : T_SECTORS;

	return 0;
}

static int process_config_option(struct policy *p, char **argv, bool set_ctr_arg)
{
	if (!strcasecmp(argv[0], "sequential_threshold"))
		return process_threshold_option(p, argv, PATTERN_SEQUENTIAL, set_ctr_arg);

	else if (!strcasecmp(argv[0], "random_threshold"))
		return process_threshold_option(p, argv, PATTERN_RANDOM, set_ctr_arg);

	else if (!strcasecmp(argv[0], "multiqueue_timeout"))
		return process_multiqueue_timeout_option(p, argv, set_ctr_arg);

	else if (!strcasecmp(argv[0], "hits"))
		return process_hits_option(p, argv, set_ctr_arg);

	return -EINVAL;
}

static int basic_message(struct dm_cache_policy *pe, unsigned argc, char **argv)
{
	struct policy *p = to_policy(pe);

	if (argc != 3)
		return -EINVAL;

	if (!strcasecmp(argv[0], "set_config"))
		return process_config_option(p, argv + 1, false);

	return -EINVAL;
}

static int basic_status(struct dm_cache_policy *pe, status_type_t type,
			unsigned status_flags, char *result, unsigned maxlen)
{
	ssize_t sz = 0;
	struct policy *p = to_policy(pe);

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT(" %lu %lu %lu %u",
		       p->tracker.thresholds[PATTERN_SEQUENTIAL],
		       p->tracker.thresholds[PATTERN_RANDOM],
		       p->queues.mq_tmo * 1000 / HZ,
		       p->queues.ctype);
		break;

	case STATUSTYPE_TABLE:
		if (p->threshold_args[PATTERN_SEQUENTIAL] > -1)
			DMEMIT(" sequential_threshold %u", p->threshold_args[PATTERN_SEQUENTIAL]);

		if (p->threshold_args[PATTERN_RANDOM] > -1)
			DMEMIT(" random_threshold %u", p->threshold_args[PATTERN_RANDOM]);

		if (p->mq_tmo_arg > -1)
			DMEMIT(" multiqueue_timeout %d", p->mq_tmo_arg);

		if (p->ctype_arg > -1)
			DMEMIT(" hits %d", p->ctype_arg);
	}

	return 0;
}

static int process_policy_args(struct policy *p, int argc, char **argv)
{
	int r;
	unsigned u;

	p->threshold_args[0] = p->threshold_args[1] = p->mq_tmo_arg = p->ctype_arg = -1;

	if (!argc)
		return 0;

	if (argc != 2 && argc != 4 && argc != 6 && argc != 8)
		return -EINVAL;

	for (r = u = 0; u < argc && !r; u += 2)
		r = process_config_option(p, argv + u, true);

	return r;
}

/* Init the policy plugin interface function pointers. */
static void init_policy_functions(struct policy *p)
{
	p->policy.destroy = basic_destroy;
	p->policy.map = basic_map;
	p->policy.lookup = basic_lookup;
	p->policy.load_mapping = basic_load_mapping;
	p->policy.walk_mappings = basic_walk_mappings;
	p->policy.remove_mapping = basic_remove_mapping;
	p->policy.writeback_work = NULL;
	p->policy.force_mapping = basic_force_mapping;
	p->policy.residency = basic_residency;
	p->policy.tick = NULL;
	p->policy.status = basic_status;
	p->policy.message = basic_message;
}

static struct dm_cache_policy *basic_policy_create(dm_cblock_t cache_size,
						   sector_t origin_size,
						   sector_t block_size,
						   int argc, char **argv,
						   enum policy_type type)
{
	int r;
	unsigned mqueues = 0;
	static struct queue_fns queue_fns[] = {
		/* These have to be in 'enum policy_type' order! */
		{ &queue_add_dumb,	    &queue_del_default,		&queue_evict_default },		/* p_dumb */
		{ &queue_add_default_tail,  &queue_del_fifo_filo,	&queue_evict_default },		/* p_fifo */
		{ &queue_add_filo_mru,      &queue_del_fifo_filo,	&queue_evict_default },		/* p_filo */
		{ &queue_add_default_tail,  &queue_del_default,		&queue_evict_default },		/* p_lru */
		{ &queue_add_filo_mru,      &queue_del_default,		&queue_evict_default },		/* p_mru */
		{ &queue_add_lfu,	    &queue_del_lfu_mfu,		&queue_evict_lfu_mfu },		/* p_lfu */
		{ &queue_add_lfu_ws,	    &queue_del_lfu_mfu,		&queue_evict_lfu_mfu },		/* p_lfu_ws */
		{ &queue_add_mfu,	    &queue_del_lfu_mfu,		&queue_evict_lfu_mfu },		/* p_mfu */
		{ &queue_add_mfu_ws,	    &queue_del_lfu_mfu,		&queue_evict_lfu_mfu },		/* p_mfu_ws */
		{ &queue_add_multiqueue,    &queue_del_multiqueue,	&queue_evict_multiqueue },	/* p_multiqueue */
		{ &queue_add_multiqueue_ws, &queue_del_multiqueue,	&queue_evict_multiqueue },	/* p_multiqueue_ws */
		{ &queue_add_noop,	    NULL,			NULL },				/* p_noop */
		{ &queue_add_default_tail,  &queue_del_default,		&queue_evict_random },		/* p_random */
		{ &queue_add_q2,	    &queue_del_multiqueue,	&queue_evict_q2_twoqueue },	/* p_q2 */
		{ &queue_add_twoqueue,      &queue_del_multiqueue,	&queue_evict_q2_twoqueue },	/* p_twoqueue */
	};
	struct policy *p = kzalloc(sizeof(*p), GFP_KERNEL);

	if (!p)
		return NULL;

	/* Set default (aka basic) policy (doesn't need a queue_fns entry above). */
	if (type == p_basic)
		type = p_multiqueue_ws;

	/* Distinguish policies */
	p->queues.fns = queue_fns + type;

	init_policy_functions(p);

	/* Need to do that before iot_init(). */
	r = process_policy_args(p, argc, argv);
	if (r)
		goto bad_free_policy;

	iot_init(&p->tracker, p->threshold_args[PATTERN_SEQUENTIAL], p->threshold_args[PATTERN_RANDOM]);

	p->cache_size = cache_size;
	p->find_free_nr_words = bit_set_nr_words(from_cblock(cache_size));
	p->find_free_last_word = 0;
	p->block_size = block_size;
	p->block_shift = ffs(block_size);
	p->origin_size = origin_size;
	p->calc_threshold_hits = max(from_cblock(cache_size) >> 2, 128U);
	p->queues.ctype = p->ctype_arg < 0 ? T_HITS : p->queues.ctype;
	init_promote_threshold(p, false);
	mutex_init(&p->lock);
	queue_init(&p->queues.free);
	queue_init(&p->queues.used);
	queue_init(&p->queues.walk);
	queue_init(&p->queues.pre.free);
	queue_init(&p->queues.pre.used);
	queue_init(&p->queues.post.free);
	queue_init(&p->queues.post.used);

	if (IS_NOOP(p))
		goto out;

	/* Allocate cache entry structs and add them to free list. */
	r = alloc_cache_blocks_with_hash(p, from_cblock(cache_size));
	if (r)
		goto bad_free_policy;

	/* Cache allocation bitset. */
	p->allocation_bitset = alloc_bitset(from_cblock(cache_size));
	if (!p->allocation_bitset)
		goto bad_free_cache_blocks_and_hash;

	if (IS_DUMB(p))
		goto out;

	/*
	 * Create in queue to track entries waiting for the
	 * cache in order to stear their promotion.
	 */
	r = alloc_track_queue_with_hash(&p->queues.pre, max(from_cblock(cache_size), 128U));
	if (r)
		goto bad_free_allocation_bitset;

	/* Create cache_size queue to track evicted cache entries. */
	r = alloc_track_queue_with_hash(&p->queues.post, max(from_cblock(cache_size) >> 1, 128U));
	if (r)
		goto bad_free_track_queue_pre;

	if (IS_LFU_MFU_WS(p)) {
		/* FIXME: replace with priority heap. */
		p->queues.fu_pool = mempool_create(from_cblock(cache_size), btree_alloc, btree_free, NULL);
		if (!p->queues.fu_pool)
			goto bad_free_track_queue_post;

		btree_init_mempool32(&p->queues.fu_head, p->queues.fu_pool);

	} else if (IS_Q2(p))
		mqueues = 1; /* Not really multiple queues but code can be shared */

	else if (IS_TWOQUEUE(p)) {
		/*
		 * Just 2 prio queues.
		 *
		 * Only allow 25% of the total cache size maximum in queue 0 (hit count 1).
		 * Ie. 75% minimum is reserved for cblocks with multiple hits.
		 */
		mqueues = 2;
		p->queues.twoqueue_q0_max_elts =
			min(max(from_cblock(cache_size) >> 2, 16U), from_cblock(cache_size));

	} else if (IS_MULTIQUEUE(p)) {
		/* Multiple queues. */
		mqueues = min(max((unsigned) ilog2(block_size << 13), 8U), (unsigned) from_cblock(cache_size));
		p->jiffies = get_jiffies_64();
		p->queues.mq_tmo = p->mq_tmo_arg < 0 ? MQ_QUEUE_TMO_DEFAULT : p->queues.mq_tmo;
	}


	if (mqueues) {
		r = alloc_multiqueues(p, mqueues);
		if (r)
			goto bad_free_track_queue_post;

	}

out:
	return &p->policy;

bad_free_track_queue_post:
	free_track_queue(&p->queues.post);
bad_free_track_queue_pre:
	free_track_queue(&p->queues.pre);
bad_free_allocation_bitset:
	free_bitset(p->allocation_bitset);
bad_free_cache_blocks_and_hash:
	free_cache_blocks_and_hash(p);
bad_free_policy:
	kfree(p);

	return NULL;
}
/*----------------------------------------------------------------------------*/

/* Policy type creation magic. */
#define __CREATE_POLICY(policy) \
static struct dm_cache_policy *policy ## _create(dm_cblock_t cache_size, sector_t origin_size, \
						  sector_t block_size, int argc, char **argv) \
{ \
	return basic_policy_create(cache_size, origin_size, block_size, argc, argv, p_ ## policy); \
}

#define	__POLICY_TYPE(policy) \
static struct dm_cache_policy_type policy ## _policy_type = { \
	.name = #policy, \
	.hint_size = 0, \
	.owner = THIS_MODULE, \
	.create = policy ## _create \
};

#define	__CREATE_POLICY_TYPE(policy) \
	__CREATE_POLICY(policy); \
	__POLICY_TYPE(policy);

/*
 * Create all fifo_create,filo_create,lru_create,... functions and
 * declare and initialize all fifo_policy_type,filo_policy_type,... structures.
 */
__CREATE_POLICY_TYPE(basic);
__CREATE_POLICY_TYPE(dumb);
__CREATE_POLICY_TYPE(fifo);
__CREATE_POLICY_TYPE(filo);
__CREATE_POLICY_TYPE(lfu);
__CREATE_POLICY_TYPE(lfu_ws);
__CREATE_POLICY_TYPE(lru);
__CREATE_POLICY_TYPE(mfu);
__CREATE_POLICY_TYPE(mfu_ws);
__CREATE_POLICY_TYPE(mru);
__CREATE_POLICY_TYPE(multiqueue);
__CREATE_POLICY_TYPE(multiqueue_ws);
__CREATE_POLICY_TYPE(noop);
__CREATE_POLICY_TYPE(random);
__CREATE_POLICY_TYPE(q2);
__CREATE_POLICY_TYPE(twoqueue);

static struct dm_cache_policy_type *policy_types[] = {
	&basic_policy_type,
	&dumb_policy_type,
	&fifo_policy_type,
	&filo_policy_type,
	&lfu_policy_type,
	&lfu_ws_policy_type,
	&lru_policy_type,
	&mfu_policy_type,
	&mfu_ws_policy_type,
	&mru_policy_type,
	&multiqueue_policy_type,
	&multiqueue_ws_policy_type,
	&noop_policy_type,
	&random_policy_type,
	&q2_policy_type,
	&twoqueue_policy_type
};

static int __init basic_init(void)
{
	int i = ARRAY_SIZE(policy_types), r;

	basic_entry_cache = kmem_cache_create("dm_cache_basic_policy",
					      sizeof(struct basic_cache_entry),
					      __alignof__(struct basic_cache_entry),
					      0, NULL);
	if (!basic_entry_cache)
		goto bad_basic_entry_cache;

	track_entry_cache = kmem_cache_create("dm_cache_basic_policy_tq",
					      sizeof(struct track_queue_entry),
					      __alignof__(struct track_queue_entry),
					      0, NULL);
	if (!track_entry_cache)
		goto bad_track_entry_cache;

	while (i--) {
		r = dm_cache_policy_register(policy_types[i]);
		if (r)
			goto bad_policy;
	}

	return 0;

bad_policy:
	kmem_cache_destroy(track_entry_cache);
bad_track_entry_cache:
	kmem_cache_destroy(basic_entry_cache);
bad_basic_entry_cache:
	return -ENOMEM;
}

static void __exit basic_exit(void)
{
	int i = ARRAY_SIZE(policy_types);

	while (i--)
		dm_cache_policy_unregister(policy_types[i]);

	kmem_cache_destroy(track_entry_cache);
	kmem_cache_destroy(basic_entry_cache);
}

module_init(basic_init);
module_exit(basic_exit);

MODULE_AUTHOR("Joe Thornber/Heinz Mauelshagen <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("basic cache policies (fifo, lru, etc)");

MODULE_ALIAS("dm-cache-basic"); /* basic_policy_create() maps "basic" to one of the following: */
MODULE_ALIAS("dm-cache-dumb");
MODULE_ALIAS("dm-cache-fifo");
MODULE_ALIAS("dm-cache-filo");
MODULE_ALIAS("dm-cache-lfu");
MODULE_ALIAS("dm-cache-lfu_ws");
MODULE_ALIAS("dm-cache-lru");
MODULE_ALIAS("dm-cache-mfu");
MODULE_ALIAS("dm-cache-mfu_ws");
MODULE_ALIAS("dm-cache-mru");
MODULE_ALIAS("dm-cache-multiqueue");
MODULE_ALIAS("dm-cache-multiqueue_ws");
MODULE_ALIAS("dm-cache-noop");
MODULE_ALIAS("dm-cache-random");
MODULE_ALIAS("dm-cache-q2");
MODULE_ALIAS("dm-cache-twoqueue");

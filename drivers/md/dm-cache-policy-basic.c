/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * FIFO/FILO/LRU/MRU/LFU/MFU/RANDOM/MULTIQUEUE/Q2 cache replacement policies.
 *
 * This file is released under the GPL.
 */

#include "dm-cache-policy.h"
#include "dm.h"

#include <linux/btree.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>

/* MULTIQUEUE defines. */
#define	MQ_QUEUES_MAX	64LLU		/* Limit for calculated queues. */
#define	MQ_OUT_ELTS_MAX	65536LLU	/* Limit for calculated history queue elements. */
#define	MQ_QUEUE_TMO	(30UL * HZ)	/* 30 seconds queue maximum lifetime per entry. */
#define	MQ_DEMOTE_TMO	(1UL * HZ)	/* Run demotion cycle after 1 second (the earliest). */

//#define debug(x...) pr_alert(x)
#define debug(x...) ;

/*----------------------------------------------------------------*/

static unsigned next_power(unsigned n, unsigned min)
{
	return roundup_pow_of_two(max(n, min));
}

/*----------------------------------------------------------------*/

static unsigned long *alloc_bitset(unsigned nr_entries)
{
	return vzalloc(sizeof(*alloc_bitset) * dm_sector_div_up(nr_entries, BITS_PER_LONG));
}

static void free_bitset(unsigned long *bits)
{
	vfree(bits);
}

/*----------------------------------------------------------------*/

struct all_entry {
	struct hlist_node hlist;
	struct list_head list;

	dm_block_t oblock, cblock;
	struct {
		unsigned long expire; /* FIXME: avoid if not MULTIQUEUE/Q2? */
		unsigned tick;
	} time;

	unsigned used;
	unsigned queue; /* FIXME: avoid if not MULTIQUEUE/Q2? */
};

struct queue {
	struct list_head elts;
	unsigned size;
};

struct seen_block {
	dm_block_t oblock;
	unsigned tick;
};

struct multiqueue_out {
	struct list_head list;
	dm_block_t oblock;
	unsigned used;
};

enum queue_add_type {
	P_fifo,
	P_filo,
	P_lru,
	P_mru,
	P_lfu,
	P_mfu,
	P_random,
	P_multiqueue,
	P_q2
};
struct policy;
typedef void (*queue_add_fn)(struct policy *, struct list_head *);
typedef void (*queue_del_fn)(struct policy *, struct list_head *);
typedef struct list_head * (*queue_get_fn)(struct policy *, dm_block_t);
struct queue_fns {
	queue_add_fn add;
	queue_del_fn del;
	queue_get_fn get;
};
#define	IS_FIFO_FILO(a)		(a->queue->del == &queue_del_fifo_filo)
#define	IS_LFU(a)		(a->queue->add == &queue_add_lfu)
#define	IS_LFU_MFU(a)		(a->queue->del == &queue_del_lfu_mfu)
#define	IS_RANDOM(a)		(a->queue->get == &queue_get_random)
#define	IS_MULTIQUEUE(a)	(a->queue->add == &queue_add_multiqueue)
#define	IS_MULTIQUEUE_Q2(a)	(a->queue->del == &queue_del_multiqueue)
#define	IS_Q2(a)		(a->queue->add == &queue_add_q2)
struct policy {
	struct dm_cache_policy policy;

	struct mutex lock;

	dm_block_t cache_size;
	atomic_t tick_ext;
	unsigned tick;

	/* FIXME: allocate only for MULTIQUEUE? */
	unsigned long mq_demote_timeout, jiffies;

	struct {
		union {
			struct queue *mq;
			struct queue prio;
		} u;

		/* FIXME: allocate only for MULTIQUEUE? */
		struct multiqueue_out *mq_out_elts;
		struct queue mq_out, mq_out_free;
		unsigned mqueues;

		struct queue free;
	} queues;

	union {
		struct btree_head32 fu_head;	/* FIXME: allocate only with LFU/MFU? */
		struct btree_head64 mq_out_head;/* FIXME: allocate only with MULTIQUEUE? */
	} btree;

	struct queue_fns *queue;

	/*
	 * We know exactly how many entries will be needed, so we can
	 * allocate them up front.
	 */
	struct all_entry *entries;
	unsigned long *allocation_bitset;
	dm_block_t nr_allocated;

	unsigned nr_buckets;
	dm_block_t hash_mask;
	struct hlist_head *table;

	dm_block_t interesting_size;
	struct seen_block *interesting_array;

	/* Fields for tracking IO pattern */
	/* 0: IO stream is random. 1: IO stream is sequential */
	bool seq_stream;
	unsigned nr_seq_samples, nr_rand_samples, seq_io_threshold;
	dm_block_t next_start_oblock;

	/* Last looked up cached entry */
	struct all_entry *last_lookup;
};

static struct policy *to_policy(struct dm_cache_policy *p)
{
	return container_of(p, struct policy, policy);
}

static void queue_init(struct queue *q)
{
	INIT_LIST_HEAD(&q->elts);
	q->size = 0;
}

static bool queue_empty(struct queue *q)
{
	BUG_ON(q->size ? list_empty(&q->elts) : !list_empty(&q->elts));
	return !q->size;
}

static void queue_add(struct queue *q, struct list_head *elt)
{
	list_add(elt, &q->elts);
	q->size++;
}

static void queue_add_tail(struct queue *q, struct list_head *elt)
{
	list_add_tail(elt, &q->elts);
	q->size++;
}

static void queue_del(struct queue *q, struct list_head *elt)
{
	BUG_ON(queue_empty(q));
	list_del(elt);
	q->size--;
}

static struct list_head *queue_pop(struct queue *q)
{
	struct list_head *r = q->elts.next;

	queue_del(q, r);

	return r;
}

static void queue_move_tail(struct queue *to, struct queue *from, struct list_head *elt)
{
	queue_del(from, elt);
	queue_add_tail(to, elt);
}
/*----------------------------------------------------------------*/

/* queue_add_.*() functions. */
static void __queue_add_default(struct policy *a, struct list_head *elt, bool to_head)
{
	struct queue *q = &a->queues.u.prio;

	to_head ? queue_add(q, elt) : queue_add_tail(q, elt);
	BUG_ON(q->size > a->nr_allocated);
}

static void queue_add_default(struct policy *a, struct list_head *elt)
{
	__queue_add_default(a, elt, true);
}

static void queue_add_default_tail(struct policy *a, struct list_head *elt)
{
	__queue_add_default(a, elt, false);
}

static u32 __make_key(u32 k, bool is_lfu)
{
	/* Invert key in case of LFU to allow btree_last() to retrieve the minimum used list. */
	return is_lfu ? ~k : k;
}

static void __queue_add_lfu_mfu(struct policy *a, struct list_head *elt, bool is_lfu)
{
	struct list_head *head;
	struct queue *q = &a->queues.u.prio;
	struct all_entry *e = list_entry(elt, struct all_entry, list);
	u32 key = __make_key(++e->used, is_lfu);

	/*
	 * Key is e->used for MFU or ~e->used for LFU in order to allow for btree_last()
	 * to be able to retrieve the appropriate node.
	 *
	 * A list of entries sharing the same used count is hanging off that node.
	 */
	head = btree_lookup32(&a->btree.fu_head, key);
	if (head) {
		/* Always add to the end where we'll pop entries off */
		list_add_tail(elt, head);

		if (is_lfu)
			/* For LFU, point to added new head, so that the older entry will get popped first. */
			BUG_ON(btree_update32(&a->btree.fu_head, key, (void *) elt));
	} else {
		/* New key, insert into tree. */
		INIT_LIST_HEAD(elt);
		BUG_ON(btree_insert32(&a->btree.fu_head, key, (void *) elt, GFP_KERNEL));
	}

	q->size++;
	BUG_ON(q->size > a->nr_allocated);
}

static void queue_add_lfu(struct policy *a, struct list_head *elt)
{
	__queue_add_lfu_mfu(a, elt, true);
}

static void queue_add_mfu(struct policy *a, struct list_head *elt)
{
	__queue_add_lfu_mfu(a, elt, false);
}

static unsigned long __queue_tmo_multiqueue(struct policy *a)
{
	return a->jiffies + MQ_QUEUE_TMO;
}

static unsigned long __demote_tmo_multiqueue(struct policy *a)
{
	return a->jiffies + MQ_DEMOTE_TMO;
}

static unsigned __get_multiqueue(struct policy *a, struct all_entry *e)
{
	return a->queues.mqueues > 1 ? min((unsigned) ilog2(e->used), a->queues.mqueues - 1) : 0;
}

static void __queue_add_multiqueue(struct policy *a, struct all_entry *e, unsigned queue)
{
	BUG_ON(queue >= a->queues.mqueues);
	e->time.expire = __queue_tmo_multiqueue(a);
	e->queue = queue;
	queue_add_tail(&a->queues.u.mq[queue], &e->list);
}

static void __demote_multiqueues(struct policy *a)
{
	if (a->queues.mqueues > 1 && time_after(a->jiffies, a->mq_demote_timeout)) {
		struct queue *cur = a->queues.u.mq;

		/* Start qith 2nd queue, because we conditionally move from queue to queue-1 */
		while (++cur < a->queues.u.mq + a->queues.mqueues) {
			while (!queue_empty(cur)) {
				/* Reference head element. */
				struct all_entry *e = list_first_entry(&cur->elts, struct all_entry, list);

				/* If expired, pop from head of higher prio queue and add to tail of lower prio one. */
				if (time_after(a->jiffies, e->time.expire)) {
					queue_move_tail(cur - 1, cur, &e->list);
					e->queue--;
					BUG_ON(e->queue >= a->queues.mqueues);
					e->time.expire = __queue_tmo_multiqueue(a);
				} else
					break;
			}
		}

		a->mq_demote_timeout = __demote_tmo_multiqueue(a);
	}
}

static void queue_add_multiqueue(struct policy *a, struct list_head *elt)
{
	struct all_entry *e = list_entry(elt, struct all_entry, list);

	/*
	 *
 	 * If allocated anew or evicted and not in history queue (ie. not referenced) -> first (lowest priority) queue,
	 * else referenced as member of a queue or still found in history queue       -> move to appropriate queue.
	 *
	 * Demote any entries afterwards.
	 */
	e->used++;
	__queue_add_multiqueue(a, e, __get_multiqueue(a, e));
	__demote_multiqueues(a);
}

static void queue_add_q2(struct policy *a, struct list_head *elt)
{
	queue_add_multiqueue(a, elt);
}
/*----------------------------------------------------------------*/

/* queue_del_.*() functions. */
static void queue_del_default(struct policy *a, struct list_head *elt)
{
	queue_del(&a->queues.u.prio, elt);
}

static void queue_del_fifo_filo(struct policy *a, struct list_head *elt)
{
	queue_del(&a->queues.u.prio, elt);
}

static void queue_del_lfu_mfu(struct policy *a, struct list_head *elt)
{
	struct list_head *head;
	struct all_entry *e = list_entry(elt, struct all_entry, list);
	struct queue *q = &a->queues.u.prio;
	u32 key = __make_key(e->used, IS_LFU(a));

	/* Don't use queue_empty! We're only housekeeping q->size with LFU/MFU. */
	BUG_ON(!q->size);

	head = btree_lookup32(&a->btree.fu_head, key);
	BUG_ON(!head);
	if (head == elt) {
		/* Need to remove head, because it's the only element. */
		if (list_empty(head))
			BUG_ON(!btree_remove32(&a->btree.fu_head, key));

		else {
			/* Update node to point to next entry as new head. */
			head = head->next;
			list_del(elt);
			BUG_ON(btree_update32(&a->btree.fu_head, key, (void *) head));
		}
	} else
		list_del(elt);

	BUG_ON(!q->size);
	q->size--;
}

static void queue_del_multiqueue(struct policy *a, struct list_head *elt)
{
	struct all_entry *e = list_entry(elt, struct all_entry, list);

	BUG_ON(e->queue >= a->queues.mqueues);
	queue_del(&a->queues.u.mq[e->queue], elt);
}
/*----------------------------------------------------------------*/

/* queue_get_.*() functions. */
static struct list_head *queue_get_default(struct policy *a, dm_block_t new_oblock)
{
	return queue_pop(&a->queues.u.prio);
}

static struct list_head *queue_get_lfu_mfu(struct policy *a, dm_block_t new_oblock)
{
	u32 k;
	struct all_entry *e;
	struct list_head *r;
	struct queue *q = &a->queues.u.prio;

	/* Don't use queue_empty! We're only housekeeping q->size with LFU/MFU. */
	BUG_ON(!q->size);

	/* This'll retrieve LFU/MFU because of __make_key(). */
	r = btree_last32(&a->btree.fu_head, &k);
	BUG_ON(!r);

	if (list_empty(r))
		r = btree_remove32(&a->btree.fu_head, k);
	else {
		/* Retrieve last element in order to minimize btree remove/insert pairs. */
		BUG_ON(r == r->prev);
		r = r->prev;
		list_del(r);
	}

	BUG_ON(!r);
	q->size--;
	e = list_entry(r, struct all_entry, list);
	e->used = 0;

	return r;
}

static struct list_head *queue_get_random(struct policy *a, dm_block_t new_oblock)
{
	/* FIXME: nr_allocated > 2^32? Eg. 1TB at 512 sectors block size. */
	dm_block_t off = random32();
	struct all_entry *e = a->entries + do_div(off, a->nr_allocated);
	struct list_head *r = &e->list;

	queue_del(&a->queues.u.prio, r);

	return r;
}

static struct multiqueue_out *__remove_multiqueue_history(struct policy *a, dm_block_t oblock)
{
	struct multiqueue_out *r = btree_remove64(&a->btree.mq_out_head, oblock);

	if (r)
		queue_move_tail(&a->queues.mq_out_free, &a->queues.mq_out, &r->list);

	return r;
}

static void __update_multiqueue_history(struct policy *a, struct all_entry *e, dm_block_t new_oblock)
{
	struct multiqueue_out *o = btree_lookup64(&a->btree.mq_out_head, new_oblock);

	if (o) {
		/* On history queue -> retrieve memorized used count in order to sort into appropriate multiqueue on __all_add(). */
		e->used = o->used;
		BUG_ON(o != __remove_multiqueue_history(a, new_oblock));
	} else {
		/* Retrieve element from free list _or_ evict one from history queue and memorize oblck and used count. */
		o = list_entry(queue_pop(queue_empty(&a->queues.mq_out_free) ? &a->queues.mq_out : &a->queues.mq_out_free), struct multiqueue_out, list);
		o->oblock = e->oblock;
		o->used = e->used;
		e->used = 0;
		BUG_ON(btree_insert64(&a->btree.mq_out_head, e->oblock, (void *) o, GFP_KERNEL));
		queue_add_tail(&a->queues.mq_out, &o->list);
	}
}

static struct list_head *queue_get_multiqueue(struct policy *a, dm_block_t new_oblock)
{
	struct queue *cur = a->queues.u.mq - 1; /* -1 because of ++cur below. */

	while (++cur < a->queues.u.mq + a->queues.mqueues) {
		if (!queue_empty(cur)) {
			struct list_head *r = queue_pop(cur);

			/* Update entry on/from history queue. */
			__update_multiqueue_history(a, list_entry(r, struct all_entry, list), new_oblock);
			return r;
		}
	}

	BUG();
	return NULL;
}

/*----------------------------------------------------------------*/

static void all_destroy(struct dm_cache_policy *p)
{
	struct policy *a = to_policy(p);

	free_bitset(a->allocation_bitset);
	vfree(a->interesting_array);
	kfree(a->table);

	if (IS_LFU_MFU(a))
		btree_destroy32(&a->btree.fu_head);

	else if (IS_MULTIQUEUE_Q2(a)) {
		btree_destroy64(&a->btree.mq_out_head);
		vfree(a->queues.mq_out_elts);
		kfree(a->queues.u.mq);
	}

	vfree(a->entries);
	kfree(a);
}

static unsigned hash(struct policy *a, dm_block_t b)
{
	const dm_block_t BIG_PRIME = 4294967291UL;
	dm_block_t h = b * BIG_PRIME;

	return (uint32_t) (h & a->hash_mask);
}

static void __all_insert(struct policy *a, struct all_entry *e)
{
	unsigned h = hash(a, e->oblock);
	hlist_add_head(&e->hlist, a->table + h);
}

static struct all_entry *__all_lookup(struct policy *a, dm_block_t origin)
{
	struct hlist_head *bucket;
	struct hlist_node *tmp;
	struct all_entry *e;

	/* Check last lookup cache */
	if (a->last_lookup && a->last_lookup->oblock == origin)
		return a->last_lookup;

	bucket = a->table + hash(a, origin);
	hlist_for_each_entry(e, tmp, bucket, hlist) {
		if (e->oblock == origin) {
			a->last_lookup = e;
			return e;
		}
	}

	return NULL;
}

static void __all_remove(struct policy *a, struct all_entry *e)
{
	hlist_del(&e->hlist);
}

static struct all_entry *__all_alloc_entry(struct policy *a)
{
	struct all_entry *e;

	BUG_ON(a->nr_allocated >= a->cache_size);

	e = list_entry(queue_pop(&a->queues.free), struct all_entry, list);
	a->nr_allocated++;
	e->time.tick = a->tick;
	e->used = 0;

	return e;
}

static void __alloc_cblock(struct policy *a, dm_block_t cblock)
{
	BUG_ON(cblock > a->cache_size);
	BUG_ON(test_bit(cblock, a->allocation_bitset));
	set_bit(cblock, a->allocation_bitset);
}

static void __free_cblock(struct policy *a, dm_block_t cblock)
{
	BUG_ON(cblock > a->cache_size);
	BUG_ON(!test_bit(cblock, a->allocation_bitset));
	clear_bit(cblock, a->allocation_bitset);
}

/*
 * This doesn't allocate the block.
 */
static int __find_free_cblock(struct policy *a, dm_block_t *result)
{
	unsigned nr_words = dm_sector_div_up(a->cache_size, BITS_PER_LONG), w;

	for (w = 0; w < nr_words; w++) {
		/*
		 * ffz is undefined if no zero exists
		 */
		if (a->allocation_bitset[w] != ~0UL) {
			*result = (w * BITS_PER_LONG) + ffz(a->allocation_bitset[w]);

			return (*result < a->cache_size) ? 0 : -ENOSPC;
		}
	}

	return -ENOSPC;
}

static bool __any_free_entries(struct policy *a)
{
	return a->nr_allocated < a->cache_size;
}

static void __all_add(struct policy *a, struct all_entry *e)
{
	e->time.tick = a->tick;
	a->queue->add(a, &e->list);
	__alloc_cblock(a, e->cblock);
	__all_insert(a, e);
}

static struct all_entry *__all_pop(struct policy *a, dm_block_t oblock)
{
	struct all_entry *e = NULL;

	e = list_entry(a->queue->get(a, oblock), struct all_entry, list);
	__all_remove(a, e);
	__free_cblock(a, e->cblock);
	return e;
}

/*
 * FIXME: the size of the interesting blocks hash table seems to be
 * directly related to the eviction rate.  So maybe we should resize on the
 * fly to get to a target eviction rate?
 */
static int __all_interesting_block(struct policy *a, dm_block_t oblock, int data_dir)
{
	const dm_block_t BIG_PRIME = 4294967291UL;
	unsigned h = ((unsigned) (oblock * BIG_PRIME)) % a->interesting_size;
	struct seen_block *sb = a->interesting_array + h;

	if (sb->tick == a->tick)
		return 0;

	if (sb->oblock == oblock)
		return 1;

	sb->oblock = oblock;
	sb->tick = a->tick;

	return 0;
}

static bool updated_this_tick(struct policy *a, struct all_entry *e)
{
	return a->tick == e->time.tick;
}

static void __all_update_io_stream_data(struct policy *a, struct bio *bio)
{
	if (bio->bi_sector == a->next_start_oblock)
		/* Block sequential to last io (+= bio_sectors(bio) to recognize stream size?) */
		a->nr_seq_samples++;

	else {
		/* One non sequential IO resets the existing data */
		if (a->nr_seq_samples)
			a->nr_seq_samples = a->nr_rand_samples = 0;

		a->nr_rand_samples++;
	}

	a->next_start_oblock = bio->bi_sector + bio_sectors(bio);

	/*
	 * If current stream state is sequential and we see 4 random IO,
	 * change state. Otherwise if current state is random and we see
	 * seq_io_threshold sequential IO, change stream state to sequential.
	 */
	if (a->seq_stream) {
		if (a->nr_rand_samples >= 4) {
			a->seq_stream = false;
			a->nr_seq_samples = a->nr_rand_samples = 0;
		}
	} else if (a->seq_io_threshold && a->nr_seq_samples >= a->seq_io_threshold) {
		a->seq_stream = true;
		a->nr_seq_samples = a->nr_rand_samples = 0;
	}
}

static void __map_found(struct policy *a, struct all_entry *e, struct policy_result *result)
{
	result->op = POLICY_HIT;
	result->cblock = e->cblock;

	/* No queue deletion and reinsertion needed with fifo/filo. */
	if (!IS_FIFO_FILO(a) && !updated_this_tick(a, e)) {
		a->queue->del(a, &e->list);
		a->queue->add(a, &e->list);
		e->time.tick = a->tick;
	}
}

static bool __all_random_stream(struct policy *a)
{
	return !a->seq_stream;
}

static bool __definitely_a_miss(struct policy *a, dm_block_t origin_block, int data_dir, bool can_migrate, bool cheap_copy, struct policy_result *result)
{
	bool possible_migration = can_migrate && __all_interesting_block(a, origin_block, data_dir);
	bool possible_new = cheap_copy && __any_free_entries(a);
	bool maybe_a_hit = __all_random_stream(a) && (possible_new || possible_migration);

	return !maybe_a_hit;
}

static void __map_not_found(struct policy *a, dm_block_t origin_block, bool can_migrate, struct policy_result *result)
{
	struct all_entry *e;

	if (queue_empty(&a->queues.free)) {
		if (!can_migrate) {
			result->op = POLICY_MISS;
			return;
		}

		e = __all_pop(a, origin_block);
		result->old_oblock = e->oblock;
		result->op = POLICY_REPLACE;
	} else {
		e = __all_alloc_entry(a);
		BUG_ON(__find_free_cblock(a, &e->cblock));
		result->op = POLICY_NEW;
	}

	e->oblock = origin_block;
	result->cblock = e->cblock;
	__all_add(a, e);
}

static void __all_map(struct policy *a, dm_block_t origin_block, int data_dir,
		      bool can_migrate, bool cheap_copy, struct policy_result *result)
{
	struct all_entry *e = __all_lookup(a, origin_block);

	if (e) 
                __map_found(a, e, result);

        else if (__definitely_a_miss(a, origin_block, data_dir, can_migrate, cheap_copy, result))
                result->op = POLICY_MISS;

        else   
                __map_not_found(a, origin_block, can_migrate, result);
}

static void all_map(struct dm_cache_policy *p, dm_block_t origin_block, int data_dir,
		    bool can_migrate, bool cheap_copy, struct bio *bio,
		    struct policy_result *result)
{
	struct policy *a = to_policy(p);

	if (IS_MULTIQUEUE(a))
		a->jiffies = get_jiffies_64();

	a->tick = atomic_read(&a->tick_ext);

	mutex_lock(&a->lock);
	__all_update_io_stream_data(a, bio);
	__all_map(a, origin_block, data_dir, can_migrate, cheap_copy, result);
	mutex_unlock(&a->lock);
}

static int all_load_mapping(struct dm_cache_policy *p, dm_block_t oblock, dm_block_t cblock)
{
	int r;
	struct policy *a = to_policy(p);
	struct all_entry *e;

	debug("loading mapping %lu -> %lu\n",
	      (unsigned long) oblock,
	      (unsigned long) cblock);

	mutex_lock(&a->lock);
	e = __all_alloc_entry(a);
	if (e)
		r = 0;
	else {
		r = -ENOMEM;
		goto bad;
	}

	e->cblock = cblock;
	e->oblock = oblock;
	__all_add(a, e);
bad:
	mutex_unlock(&a->lock);

	return r;
}

static struct all_entry *__all_force_remove_mapping(struct policy *a, dm_block_t block)
{
	struct all_entry *e = __all_lookup(a, block);

	BUG_ON(!e);

	if (IS_MULTIQUEUE_Q2(a))
		__remove_multiqueue_history(a, e->oblock);

	__free_cblock(a, e->cblock);
	a->queue->del(a, &e->list);
	__all_remove(a, e);

	return e;
}

static void all_remove_mapping(struct dm_cache_policy *p, dm_block_t oblock)
{
	struct policy *a = to_policy(p);
	struct all_entry *e;

	mutex_lock(&a->lock);
	e = __all_force_remove_mapping(a, oblock);
	queue_add_tail(&a->queues.free, &e->list);

	BUG_ON(!a->nr_allocated);
	a->nr_allocated--;
	mutex_unlock(&a->lock);
}

static void all_force_mapping(struct dm_cache_policy *p,
			      dm_block_t current_oblock, dm_block_t new_oblock)
{
	struct policy *a = to_policy(p);
	struct all_entry *e;

	mutex_lock(&a->lock);
	e = __all_force_remove_mapping(a, current_oblock);
	e->oblock = new_oblock;
	__all_add(a, e);
	mutex_unlock(&a->lock);
}

static dm_block_t all_residency(struct dm_cache_policy *p)
{
	struct policy *a = to_policy(p);
	dm_block_t r;

	mutex_lock(&a->lock);
	r = a->nr_allocated;
	mutex_unlock(&a->lock);

	return r;
}

static void all_set_seq_io_threshold(struct dm_cache_policy *p,
				     unsigned int seq_io_thresh)
{
	struct policy *a = to_policy(p);

	mutex_lock(&a->lock);
	a->seq_io_threshold = seq_io_thresh;
	mutex_unlock(&a->lock);
}

static void all_tick(struct dm_cache_policy *p)
{
	atomic_inc(&to_policy(p)->tick_ext);
}

static struct dm_cache_policy *__create(dm_block_t cache_size,
					enum queue_add_type type)
{
	int r;
	unsigned i;
	static struct queue_fns queue_fns[] = {
		/* These have to be in 'enum queue_add_type' order! */
		{ &queue_add_default_tail, &queue_del_fifo_filo,  &queue_get_default }, 	/* P_fifo */
		{ &queue_add_default,      &queue_del_fifo_filo,  &queue_get_default },		/* P_filo */
		{ &queue_add_default_tail, &queue_del_default,    &queue_get_default },		/* P_lru */
		{ &queue_add_default,      &queue_del_default,    &queue_get_default },		/* P_mru */
		{ &queue_add_lfu,          &queue_del_lfu_mfu,    &queue_get_lfu_mfu },		/* P_lfu */
		{ &queue_add_mfu,          &queue_del_lfu_mfu,    &queue_get_lfu_mfu },		/* P_mfu */
		{ &queue_add_default_tail, &queue_del_default,    &queue_get_random },		/* P_random */
		{ &queue_add_multiqueue,   &queue_del_multiqueue, &queue_get_multiqueue },	/* P_multiqueue */
		{ &queue_add_q2,           &queue_del_multiqueue, &queue_get_multiqueue }	/* P_q2 */
	};
	struct policy *a = kzalloc(sizeof(*a), GFP_KERNEL);

	if (!a)
		return NULL;

	/* Distinguish policies */
	a->queue = queue_fns + type;

	a->policy.destroy = all_destroy;
	a->policy.map = all_map;
	a->policy.load_mapping = all_load_mapping;
	a->policy.remove_mapping = all_remove_mapping;
	a->policy.force_mapping = all_force_mapping;
	a->policy.residency = all_residency;
	a->policy.set_seq_io_threshold = all_set_seq_io_threshold;
	a->policy.tick = all_tick;

	a->cache_size = cache_size;
	a->tick = 0;
	atomic_set(&a->tick_ext, 0);
	mutex_init(&a->lock);

	queue_init(&a->queues.free);

	a->last_lookup = NULL;
	a->entries = vzalloc(sizeof(*a->entries) * cache_size);
	if (!a->entries)
		goto bad1;

	for (i = 0; i < cache_size; i++)
		queue_add_tail(&a->queues.free, &a->entries[i].list);

	a->nr_allocated = 0;
	a->nr_buckets = next_power(cache_size >> 2, 16);
	a->hash_mask = a->nr_buckets - 1;
	a->table = kzalloc(sizeof(*a->table) * a->nr_buckets, GFP_KERNEL);
	if (!a->table) 
		goto bad2;

	a->interesting_size = next_power(cache_size, 16);
	a->interesting_array = vzalloc(sizeof(*a->interesting_array) * a->interesting_size);
	if (!a->interesting_array)
		goto bad3;

	a->allocation_bitset = alloc_bitset(cache_size);
	if (!a->allocation_bitset)
		goto bad4;

	if (IS_LFU_MFU(a)) {
		r = btree_init32(&a->btree.fu_head);
		if (r)
			goto bad5;
	}

	if (IS_MULTIQUEUE_Q2(a)) {
		/* Queues. */
		a->queues.mqueues = i = IS_Q2(a) ? 1 : max(min(cache_size >> 9, MQ_QUEUES_MAX), (dm_block_t) 3);
		a->queues.u.mq = kzalloc(sizeof(*a->queues.u.mq) * i, GFP_KERNEL);
		if (!a->queues.u.mq)
			goto bad5;

		while (i--)
			queue_init(&a->queues.u.mq[i]);

		a->jiffies = get_jiffies_64();
		a->mq_demote_timeout = __demote_tmo_multiqueue(a);

		/* History queue. */
		queue_init(&a->queues.mq_out);
		queue_init(&a->queues.mq_out_free);

		i = max(min(cache_size >> 1, MQ_OUT_ELTS_MAX), (dm_block_t) 2);
		a->queues.mq_out_elts = vzalloc(sizeof(*a->queues.mq_out_elts) * i);
		if (!a->queues.mq_out_elts)
			goto bad6;

		while (i--)
			queue_add_tail(&a->queues.mq_out_free, &a->queues.mq_out_elts[i].list);

		r = btree_init64(&a->btree.mq_out_head);
		if (r)
			goto bad7;
	} else 
		queue_init(&a->queues.u.prio);
	
	return &a->policy;

bad7:
	vfree(a->queues.mq_out_elts);
bad6:
	kfree(a->queues.u.mq);
bad5:
	free_bitset(a->allocation_bitset);
bad4:
	vfree(a->interesting_array);
bad3:
	kfree(a->table);
bad2:
	vfree(a->entries);
bad1:
	kfree(a);

	return NULL;
}

#define __CREATE(policy) \
static struct dm_cache_policy * policy ## _create(dm_block_t cache_size) \
{ \
	return __create(cache_size, P_ ## policy); \
}

/*----------------------------------------------------------------*/

#define	__POLICY_TYPE(policy) \
static struct dm_cache_policy_type policy ## _policy_type = { \
	.name = #policy, \
	.owner = THIS_MODULE, \
        .create = policy ## _create \
};

#define	__CREATE_POLICY_TYPE(policy) \
	__CREATE(policy); \
	__POLICY_TYPE(policy);

/*
 * Create all fifo_create,filo_create,lru_create,... functions and
 * declare and initialize all fifo_policy_type,filo_policy_type,... structures.
 */
__CREATE_POLICY_TYPE(fifo);
__CREATE_POLICY_TYPE(filo);
__CREATE_POLICY_TYPE(lru);
__CREATE_POLICY_TYPE(mru);
__CREATE_POLICY_TYPE(lfu);
__CREATE_POLICY_TYPE(mfu);
__CREATE_POLICY_TYPE(random);
__CREATE_POLICY_TYPE(multiqueue);
__CREATE_POLICY_TYPE(q2);

static struct dm_cache_policy_type *policy_types[] = {
	&fifo_policy_type,
	&filo_policy_type,
	&lru_policy_type,
	&mru_policy_type,
	&lfu_policy_type,
	&mfu_policy_type,
	&random_policy_type,
	&multiqueue_policy_type,
	&q2_policy_type
};

static int __init all_init(void)
{
	int i = ARRAY_SIZE(policy_types), r;

	while (i--) {
		r = dm_cache_policy_register(policy_types[i]);
		if (r)
			break;
	}

	return r;
}

static void __exit all_exit(void)
{
	int i = ARRAY_SIZE(policy_types);

	while (i--)
		dm_cache_policy_unregister(policy_types[i]);
}

module_init(all_init);
module_exit(all_exit);

MODULE_AUTHOR("Joe Thornber/Heinz Mauelshagen");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("fifo/filo/lru/mru/lfu/mfu/random/multiqueue/q2 cache policies");

MODULE_ALIAS("dm-cache-fifo");
MODULE_ALIAS("dm-cache-filo");
MODULE_ALIAS("dm-cache-lru");
MODULE_ALIAS("dm-cache-mru");
MODULE_ALIAS("dm-cache-lfu");
MODULE_ALIAS("dm-cache-mfu");
MODULE_ALIAS("dm-cache-random");
MODULE_ALIAS("dm-cache-multiqueue");
MODULE_ALIAS("dm-cache-q2");

/*----------------------------------------------------------------*/

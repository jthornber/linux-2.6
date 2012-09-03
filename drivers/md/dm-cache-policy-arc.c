/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "dm-cache-policy.h"
#include "dm.h"

#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>

//#define debug(x...) pr_alert(x)
#define debug(x...) ;

/*----------------------------------------------------------------*/

static unsigned next_power(unsigned n, unsigned min)
{
	unsigned r = min;

	while (r < n)
		r <<= 1;

	return r;
}

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

static struct list_head *queue_head(struct queue *q)
{
	BUG_ON(list_empty(&q->elts));
	return q->elts.next;
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

#define ARC_NR_QUEUES 4

struct arc_entry {
	enum arc_state state;
	struct hlist_node hlist;
	struct list_head list;
	dm_block_t oblock;
	dm_block_t cblock;

	unsigned tick;
};

struct seen_block {
	dm_block_t oblock;
	unsigned tick;
};

struct arc_policy {
	struct dm_cache_policy policy;

	dm_block_t cache_size;
	unsigned tick;

	spinlock_t lock;

	dm_block_t p;		/* the magic factor that balances lru vs lfu */
	struct queue q[ARC_NR_QUEUES];

	/*
	 * We know exactly how many entries will be needed, so we can
	 * allocate them up front.
	 */
	struct arc_entry *entries;
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
	unsigned nr_seq_samples, nr_rand_samples;
	dm_block_t last_end_oblock;
	unsigned int seq_io_threshold;

	/* Last looked up cached entry */
	struct arc_entry *last_lookup;
};

static struct arc_policy *to_arc_policy(struct dm_cache_policy *p)
{
	return container_of(p, struct arc_policy, policy);
}

static void arc_destroy(struct dm_cache_policy *p)
{
	struct arc_policy *a = to_arc_policy(p);

	free_bitset(a->allocation_bitset);
	vfree(a->interesting_array);
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

	/* Check last lookup cache */
	if (a->last_lookup && a->last_lookup->oblock == origin)
		return a->last_lookup;

	hlist_for_each_entry(e, tmp, bucket, hlist)
		if (e->oblock == origin) {
			a->last_lookup = e;
			return e;
		}
	return NULL;
}

static void __arc_remove(struct arc_policy *a, struct arc_entry *e)
{
	hlist_del(&e->hlist);
}

static struct arc_entry *__arc_alloc_entry(struct arc_policy *a)
{
	struct arc_entry *e;

	BUG_ON(a->nr_allocated >= 2 * a->cache_size);
	e = a->entries + a->nr_allocated;
	INIT_LIST_HEAD(&e->list);
	INIT_HLIST_NODE(&e->hlist);
	a->nr_allocated++;
	e->tick = a->tick;

	return e;
}

static void __alloc_cblock(struct arc_policy *a, dm_block_t cblock)
{
	BUG_ON(cblock > a->cache_size);
	BUG_ON(test_bit(cblock, a->allocation_bitset));
	set_bit(cblock, a->allocation_bitset);
}

static void __free_cblock(struct arc_policy *a, dm_block_t cblock)
{
	BUG_ON(cblock > a->cache_size);
	BUG_ON(!test_bit(cblock, a->allocation_bitset));
	clear_bit(cblock, a->allocation_bitset);
}

/*
 * This doesn't allocate the block.
 */
static int __find_free_cblock(struct arc_policy *a, dm_block_t *result)
{
	int r = -ENOSPC;
	unsigned nr_words = dm_div_up(a->cache_size, BITS_PER_LONG);
	unsigned w, b;

	for (w = 0; w < nr_words; w++) {
		/*
		 * ffz is undefined if no zero exists
		 */
		if (a->allocation_bitset[w] != ~0UL) {
			b = ffz(a->allocation_bitset[w]);

			*result = (w * BITS_PER_LONG) + b;
			if (*result < a->cache_size)
				r = 0;

			break;
		}
	}

	return r;
}

static bool __any_free_entries(struct arc_policy *a)
{
	return a->nr_allocated < a->cache_size;
}

static void __arc_push(struct arc_policy *a,
		       enum arc_state s, struct arc_entry *e)
{
	e->state = s;
	e->tick = a->tick;

	if (e->state == ARC_T1 || e->state == ARC_T2) {
		__alloc_cblock(a, e->cblock);
		__arc_insert(a, e);
	}

	queue_push(&a->q[s], &e->list);
}

static struct arc_entry *__arc_pop(struct arc_policy *a, enum arc_state s)
{
	struct arc_entry *e = container_of(queue_pop(&a->q[s]), struct arc_entry, list);

	if (s == ARC_T1 || s == ARC_T2) {
		__arc_remove(a, e);
		__free_cblock(a, e->cblock);
	}

	return e;
}

static struct arc_entry *__arc_peek(struct arc_policy *a, enum arc_state s)
{
	return container_of(queue_head(&a->q[s]), struct arc_entry, list);
}

static bool __can_demote(struct arc_policy *a)
{
	struct arc_entry *e;
	dm_block_t t1_size = queue_size(&a->q[ARC_T1]);


	if (t1_size && ((t1_size > a->p) || (t1_size == a->p)))
		e = __arc_peek(a, ARC_T1);
	else
		e = __arc_peek(a, ARC_T2);

	return e->tick != a->tick;
}

static dm_block_t __arc_demote(struct arc_policy *a, bool is_arc_b2, struct policy_result *result)
{
	struct arc_entry *e;
	enum arc_state s1, s2;
	dm_block_t t1_size = queue_size(&a->q[ARC_T1]);

	result->op = POLICY_REPLACE;

	if (t1_size &&
	    ((t1_size > a->p) || (is_arc_b2 && (t1_size == a->p)))) {
		s1 = ARC_T1;
		s2 = ARC_B1;
	} else {
		s1 = ARC_T2;
		s2 = ARC_B2;
	}

	e = __arc_pop(a, s1);
	result->old_oblock = e->oblock;
	result->cblock = e->cblock;
	__arc_push(a, s2, e);

	return e->cblock;
}

/*
 * FIXME: the size of the interesting blocks hash table seems to be
 * directly related to the eviction rate.  So maybe we should resize on the
 * fly to get to a target eviction rate?
 */
static int __arc_interesting_block(struct arc_policy *a, dm_block_t oblock, int data_dir)
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

static bool arc_random_stream(struct arc_policy *a)
{
	return !a->seq_stream;
}

static void __arc_update_io_stream_data(struct arc_policy *a, struct bio *bio)
{
	if (bio->bi_sector == a->last_end_oblock + 1) {
		/* Block sequential to last io */
		a->nr_seq_samples++;
	} else {
		/* One non sequential IO resets the existing data */
		if (a->nr_seq_samples) {
			a->nr_seq_samples = 0;
			a->nr_rand_samples = 0;
		}
		a->nr_rand_samples++;
	}

	a->last_end_oblock = bio->bi_sector + bio_sectors(bio) - 1;

	/*
	 * If current stream state is sequential and we see 4 random IO,
	 * change state. Otherwise if current state is random and we see
	 * seq_io_threshold sequential IO, change stream state to sequential.
	 */

	if (a->seq_stream && a->nr_rand_samples >= 4) {
		a->seq_stream = false;
		debug("switched stream state to random. nr_rand=%u"
			" nr_seq=%u\n", a->nr_rand_samples, a->nr_seq_samples);
		a->nr_seq_samples = a->nr_rand_samples = 0;
	} else if (!a->seq_stream && a->seq_io_threshold &&
                   a->nr_seq_samples >= a->seq_io_threshold) {
		a->seq_stream = true;
		debug("switched stream state to sequential. nr_rand=%u"
			" nr_seq=%u\n", a->nr_rand_samples, a->nr_seq_samples);
		a->nr_seq_samples = a->nr_rand_samples = 0;
	}
}

static bool updated_this_tick(struct arc_policy *a, struct arc_entry *e)
{
	return a->tick == e->tick;
}

static void __arc_hit(struct arc_policy *a, struct arc_entry *e)
{
	BUG_ON(e->state != ARC_T1 && e->state != ARC_T2);

	if (updated_this_tick(a, e))
		return;

	__free_cblock(a, e->cblock);
	queue_del(&a->q[e->state], &e->list);
	__arc_remove(a, e);
	__arc_push(a, ARC_T2, e);
}

static void __arc_map_found(struct arc_policy *a,
			    struct arc_entry *e,
			    dm_block_t origin_block,
			    bool can_migrate,
			    struct policy_result *result)
{
	bool is_arc_b2 = false;
	dm_block_t delta;
	dm_block_t b1_size = queue_size(&a->q[ARC_B1]);
	dm_block_t b2_size = queue_size(&a->q[ARC_B2]);
	dm_block_t new_cache;

	if (e->state == ARC_T1 || e->state == ARC_T2) {
		result->op = POLICY_HIT;
		result->cblock = e->cblock;
		__arc_hit(a, e);
		return;
	}

	if (!can_migrate || updated_this_tick(a, e)) {
		result->op = POLICY_MISS;
		return;
	}

	if (e->state == ARC_B1) {
		delta = (b1_size > b2_size) ? 1 : max(b2_size / b1_size, 1ULL);
		a->p = min(a->p + delta, a->cache_size);

	} else { /* ARC_B2 */
		is_arc_b2 = true;
		delta = b2_size >= b1_size ? 1 : max(b1_size / b2_size, 1ULL);
		a->p = max(a->p - delta, 0ULL);
	}

	new_cache = __arc_demote(a, is_arc_b2, result);
	queue_del(&a->q[e->state], &e->list);
	e->oblock = origin_block;
	e->cblock = new_cache;
	__arc_push(a, ARC_T2, e);
}

static void __arc_map(struct arc_policy *a,
		      dm_block_t origin_block,
		      int data_dir,
		      bool can_migrate,
		      bool cheap_copy,
		      struct policy_result *result)
{
	int r;
	dm_block_t b1_size = queue_size(&a->q[ARC_B1]);
	dm_block_t b2_size = queue_size(&a->q[ARC_B2]);
	dm_block_t l1_size, l2_size;
	dm_block_t new_cache;
	struct arc_entry *e;

	e = __arc_lookup(a, origin_block);
	if (e) {
		__arc_map_found(a, e, origin_block, can_migrate, result);
		return;
	}

	/* FIXME: this is turning into a huge mess */
	cheap_copy = cheap_copy && __any_free_entries(a);
	if (arc_random_stream(a) && (cheap_copy || (can_migrate && __arc_interesting_block(a, origin_block, data_dir)))) {
		/* carry on, perverse logic */
	} else {
		result->op = POLICY_MISS;
		return;
	}

	l1_size = queue_size(&a->q[ARC_T1]) + b1_size;
	l2_size = queue_size(&a->q[ARC_T2]) + b2_size;
	if (l1_size == a->cache_size) {
		if (!can_migrate || !__can_demote(a))  {
			result->op = POLICY_MISS;
			return;
		}

		if (queue_size(&a->q[ARC_T1]) < a->cache_size) {
			e = __arc_pop(a, ARC_B1);

			new_cache = __arc_demote(a, 0, result);
			e->oblock = origin_block;
			e->cblock = new_cache;

		} else {
			e = __arc_pop(a, ARC_T1);

			result->op = POLICY_REPLACE;
			result->old_oblock = e->oblock;
			e->oblock = origin_block;
			result->cblock = e->cblock;
		}

	} else if (l1_size < a->cache_size && (l1_size + l2_size >= a->cache_size)) {
		if (!can_migrate || !__can_demote(a))  {
			result->op = POLICY_MISS;
			return;
		}

		if (l1_size + l2_size == 2 * a->cache_size) {
			e = __arc_pop(a, ARC_B2);
			e->oblock = origin_block;
			e->cblock = __arc_demote(a, 0, result);

		} else {
			e = __arc_alloc_entry(a);
			e->oblock = origin_block;
			e->cblock = __arc_demote(a, 0, result);
			//__alloc_cblock(a, e->cblock);
		}

	} else {
		e = __arc_alloc_entry(a);
		r = __find_free_cblock(a, &e->cblock);
		BUG_ON(r);

		result->op = POLICY_NEW;
		result->cblock = e->cblock;
		e->oblock = origin_block;
	}

	__arc_push(a, ARC_T1, e);
}

static void arc_map(struct dm_cache_policy *p, dm_block_t origin_block, int data_dir,
		    bool can_migrate, bool cheap_copy, struct bio *bio,
		    struct policy_result *result)
{
	unsigned long flags;
	struct arc_policy *a = to_arc_policy(p);

	spin_lock_irqsave(&a->lock, flags);
	__arc_update_io_stream_data(a, bio);
	__arc_map(a, origin_block, data_dir, can_migrate, cheap_copy, result);
	spin_unlock_irqrestore(&a->lock, flags);
}

static int arc_load_mapping(struct dm_cache_policy *p, dm_block_t oblock, dm_block_t cblock)
{
	struct arc_policy *a = to_arc_policy(p);
	struct arc_entry *e;

	debug("loading mapping %lu -> %lu\n",
	      (unsigned long) oblock,
	      (unsigned long) cblock);

	e = __arc_alloc_entry(a);
	if (!e)
		return -ENOMEM;

	e->cblock = cblock;
	e->oblock = oblock;
	__arc_push(a, ARC_T1, e);

	return 0;
}

static void arc_remove_mapping(struct dm_cache_policy *p, dm_block_t oblock)
{
	struct arc_policy *a = to_arc_policy(p);
	struct arc_entry *e = __arc_lookup(a, oblock);

	BUG_ON(!e || e->state == ARC_B1 || e->state == ARC_B2);

	__free_cblock(a, e->cblock);
	queue_del(e->state == ARC_T1 ? &a->q[ARC_T1] : &a->q[ARC_T2], &e->list);
	__arc_remove(a, e);
	__arc_push(a, ARC_B2, e);
}

static void arc_force_mapping(struct dm_cache_policy *p,
		dm_block_t current_oblock, dm_block_t new_oblock)
{
	struct arc_policy *a = to_arc_policy(p);
	struct arc_entry *e = __arc_lookup(a, current_oblock);

	BUG_ON(!e || e->state == ARC_B1 || e->state == ARC_B2);

	__free_cblock(a, e->cblock);
	queue_del(e->state == ARC_T1 ? &a->q[ARC_T1] : &a->q[ARC_T2], &e->list);
	__arc_remove(a, e);
	e->oblock = new_oblock;
	__arc_push(a, ARC_T1, e);
}

static dm_block_t arc_residency(struct dm_cache_policy *p)
{
	struct arc_policy *a = to_arc_policy(p);
	// FIXME: this may be wrong if arc_remove_mapping has been called
	return min(a->nr_allocated, a->cache_size);
}

static void arc_set_seq_io_threshold(struct dm_cache_policy *p,
			unsigned int seq_io_thresh)
{
	struct arc_policy *a = to_arc_policy(p);

	a->seq_io_threshold = seq_io_thresh;
}

static void arc_tick(struct dm_cache_policy *p)
{
	struct arc_policy *a = to_arc_policy(p);
	unsigned long flags;

	spin_lock_irqsave(&a->lock, flags);
	a->tick++;
	spin_unlock_irqrestore(&a->lock, flags);
}

static struct dm_cache_policy *arc_create(dm_block_t cache_size)
{
	int i;
	struct arc_policy *a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return NULL;

	a->policy.destroy = arc_destroy;
	a->policy.map = arc_map;
	a->policy.load_mapping = arc_load_mapping;
	a->policy.remove_mapping = arc_remove_mapping;
	a->policy.force_mapping = arc_force_mapping;
	a->policy.residency = arc_residency;
	a->policy.set_seq_io_threshold = arc_set_seq_io_threshold;
	a->policy.tick = arc_tick;

	a->cache_size = cache_size;
	a->tick = 0;
	spin_lock_init(&a->lock);
	a->p = 0;

	for (i = 0; i < ARC_NR_QUEUES; i++)
		queue_init(&a->q[i]);

	a->last_lookup = NULL;
	a->entries = vzalloc(sizeof(*a->entries) * 2 * cache_size);
	if (!a->entries) {
		kfree(a);
		return NULL;
	}

	a->nr_allocated = 0;

	a->nr_buckets = next_power(cache_size / 4, 16);
	a->hash_mask = a->nr_buckets - 1;
	a->table = kzalloc(sizeof(*a->table) * a->nr_buckets, GFP_KERNEL);
	if (!a->table) {
		vfree(a->entries);
		kfree(a);
		return NULL;
	}

	a->interesting_size = next_power(cache_size * 2, 16);
	a->interesting_array = vzalloc(sizeof(*a->interesting_array) * a->interesting_size);
	if (!a->interesting_array) {
		kfree(a->table);
		vfree(a->entries);
		kfree(a);
		return NULL;
	}

	a->allocation_bitset = alloc_bitset(cache_size, 0);
	if (!a->allocation_bitset) {
		vfree(a->interesting_array);
		kfree(a->table);
		vfree(a->entries);
		kfree(a);
		return NULL;
	}

	return &a->policy;
}

/*----------------------------------------------------------------*/

static struct dm_cache_policy_type arc_policy_type = {
	.name = "arc",
	.owner = THIS_MODULE,
        .create = arc_create
};

static int __init arc_init(void)
{
	return dm_cache_policy_register(&arc_policy_type);
}

static void __exit arc_exit(void)
{
	dm_cache_policy_unregister(&arc_policy_type);
}

module_init(arc_init);
module_exit(arc_exit);

MODULE_AUTHOR("Joe Thornber");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("arc+ cache policy");

/*----------------------------------------------------------------*/

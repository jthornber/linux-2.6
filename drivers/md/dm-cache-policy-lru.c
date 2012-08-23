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

struct lru_entry {
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

struct lru_policy {
	struct dm_cache_policy policy;

	dm_block_t cache_size;
	unsigned tick;

	spinlock_t lock;
	struct queue lru;
	struct queue free;

	/*
	 * We know exactly how many entries will be needed, so we can
	 * allocate them up front.
	 */
	struct lru_entry *entries;
	unsigned long *allocation_bitset;
	dm_block_t nr_allocated;

	unsigned nr_buckets;
	dm_block_t hash_mask;
	struct hlist_head *table;

	dm_block_t interesting_size;
	struct seen_block *interesting_array;

	/* Last looked up cached entry */
	struct lru_entry *last_lookup;
};

static struct lru_policy *to_lru_policy(struct dm_cache_policy *p)
{
	return container_of(p, struct lru_policy, policy);
}

static void lru_destroy(struct dm_cache_policy *p)
{
	struct lru_policy *l = to_lru_policy(p);

	free_bitset(l->allocation_bitset);
	vfree(l->interesting_array);
	kfree(l->table);
	vfree(l->entries);
	kfree(l);
}

static unsigned hash(struct lru_policy *a, dm_block_t b)
{
	const dm_block_t BIG_PRIME = 4294967291UL;
	dm_block_t h = b * BIG_PRIME;

	return (uint32_t) (h & a->hash_mask);
}

static void __lru_insert(struct lru_policy *a, struct lru_entry *e)
{
	unsigned h = hash(a, e->oblock);
	hlist_add_head(&e->hlist, a->table + h);
}

static struct lru_entry *__lru_lookup(struct lru_policy *l, dm_block_t origin)
{
	unsigned h = hash(l, origin);
	struct hlist_head *bucket = l->table + h;
	struct hlist_node *tmp;
	struct lru_entry *e;

	/* Check last lookup cache */
	if (l->last_lookup && l->last_lookup->oblock == origin)
		return l->last_lookup;

	hlist_for_each_entry(e, tmp, bucket, hlist)
		if (e->oblock == origin) {
			l->last_lookup = e;
			return e;
		}

	return NULL;
}

static void __lru_remove(struct lru_policy *l, struct lru_entry *e)
{
	hlist_del(&e->hlist);
}

static struct lru_entry *__lru_alloc_entry(struct lru_policy *l)
{
	struct lru_entry *e;

	BUG_ON(l->nr_allocated >= l->cache_size);

	e = container_of(queue_pop(&l->free), struct lru_entry, list);
	INIT_LIST_HEAD(&e->list);
	INIT_HLIST_NODE(&e->hlist);
	l->nr_allocated++;
	e->tick = l->tick;

	return e;
}

static void __alloc_cblock(struct lru_policy *l, dm_block_t cblock)
{
	BUG_ON(cblock > l->cache_size);
	BUG_ON(test_bit(cblock, l->allocation_bitset));
	set_bit(cblock, l->allocation_bitset);
}

static void __free_cblock(struct lru_policy *l, dm_block_t cblock)
{
	BUG_ON(cblock > l->cache_size);
	BUG_ON(!test_bit(cblock, l->allocation_bitset));
	clear_bit(cblock, l->allocation_bitset);
}

/*
 * This doesn't allocate the block.
 */
static int __find_free_cblock(struct lru_policy *l, dm_block_t *result)
{
	int r = -ENOSPC;
	unsigned nr_words = dm_div_up(l->cache_size, BITS_PER_LONG);
	unsigned w, b;

	for (w = 0; w < nr_words; w++) {
		/*
		 * ffz is undefined if no zero exists
		 */
		if (l->allocation_bitset[w] != ~0UL) {
			b = ffz(l->allocation_bitset[w]);

			*result = (w * BITS_PER_LONG) + b;
			if (*result < l->cache_size)
				r = 0;

			break;
		}
	}

	return r;
}

static bool __any_free_entries(struct lru_policy *l)
{
	return l->nr_allocated < l->cache_size;
}

static void __lru_push(struct lru_policy *l, struct lru_entry *e)
{
	e->tick = l->tick;
	queue_push(&l->lru, &e->list);
	__alloc_cblock(l, e->cblock);
	__lru_insert(l, e);
}

static struct lru_entry *__lru_pop(struct lru_policy *l)
{
	struct lru_entry *e = NULL;

	e = container_of(queue_pop(&l->lru), struct lru_entry, list);
	__lru_remove(l, e);
	__free_cblock(l, e->cblock);
	return e;
}

/*
 * FIXME: the size of the interesting blocks hash table seems to be
 * directly related to the eviction rate.  So maybe we should resize on the
 * fly to get to a target eviction rate?
 */
static int __lru_interesting_block(struct lru_policy *l, dm_block_t oblock, int data_dir)
{
	const dm_block_t BIG_PRIME = 4294967291UL;
	unsigned h = ((unsigned) (oblock * BIG_PRIME)) % l->interesting_size;
	struct seen_block *sb = l->interesting_array + h;

	if (sb->tick == l->tick)
		return 0;

	if (sb->oblock == oblock)
		return 1;

	sb->oblock = oblock;
	sb->tick = l->tick;

	return 0;
}

static bool updated_this_tick(struct lru_policy *l, struct lru_entry *e)
{
	return l->tick == e->tick;
}

static void __lru_map(struct lru_policy *l,
		      dm_block_t origin_block,
		      int data_dir,
		      bool can_migrate,
		      bool cheap_copy,
		      struct policy_result *result)
{
	int r;
	dm_block_t lru_size;
	struct lru_entry *e;

	e = __lru_lookup(l, origin_block);
	if (e) {
		result->op = POLICY_HIT;
		result->cblock = e->cblock;

		if (!updated_this_tick(l, e)) {
			__free_cblock(l, e->cblock);
			queue_del(&l->lru, &e->list);
			__lru_remove(l, e);
			__lru_push(l, e);
		}

		return;
	}

	/* FIXME: this is turning into a huge mess */
	cheap_copy = cheap_copy && __any_free_entries(l);
	if (cheap_copy || (can_migrate && __lru_interesting_block(l, origin_block, data_dir))) {
		/* carry on, perverse logic */
	} else {
		result->op = POLICY_MISS;
		return;
	}

	lru_size = queue_size(&l->lru);
	if (lru_size == l->cache_size) {
		if (!can_migrate) {
			result->op = POLICY_MISS;
			return;
		}

		e = __lru_pop(l);
		result->old_oblock = e->oblock;
		e->oblock = origin_block;
		result->op = POLICY_REPLACE;
		result->cblock = e->cblock;
	} else {
		e = __lru_alloc_entry(l);
		r = __find_free_cblock(l, &e->cblock);
		BUG_ON(r);

		result->op = POLICY_NEW;
		result->cblock = e->cblock;
		e->oblock = origin_block;
	}

	__lru_push(l, e);
}

static void lru_map(struct dm_cache_policy *p, dm_block_t origin_block, int data_dir,
		    bool can_migrate, bool cheap_copy, struct bio *bio,
		    struct policy_result *result)
{
	unsigned long flags;
	struct lru_policy *l = to_lru_policy(p);

	spin_lock_irqsave(&l->lock, flags);
	__lru_map(l, origin_block, data_dir, can_migrate, cheap_copy, result);
	spin_unlock_irqrestore(&l->lock, flags);
}

static int lru_load_mapping(struct dm_cache_policy *p, dm_block_t oblock, dm_block_t cblock)
{
	struct lru_policy *l = to_lru_policy(p);
	struct lru_entry *e;

	debug("loading mapping %lu -> %lu\n",
	      (unsigned long) oblock,
	      (unsigned long) cblock);

	e = __lru_alloc_entry(l);
	if (!e)
		return -ENOMEM;

	e->cblock = cblock;
	e->oblock = oblock;
	__lru_push(l, e);

	return 0;
}

static void lru_remove_mapping(struct dm_cache_policy *p, dm_block_t oblock)
{
	struct lru_policy *l = to_lru_policy(p);
	struct lru_entry *e = __lru_lookup(l, oblock);

	BUG_ON(!e);

	__free_cblock(l, e->cblock);
	queue_del(&l->lru, &e->list);
	__lru_remove(l, e);
	queue_push(&l->free, &e->list);
}

static void lru_force_mapping(struct dm_cache_policy *p,
		dm_block_t current_oblock, dm_block_t new_oblock)
{
	struct lru_policy *l = to_lru_policy(p);
	struct lru_entry *e = __lru_lookup(l, current_oblock);

	BUG_ON(!e);

	__free_cblock(l, e->cblock);
	queue_del(&l->lru, &e->list);
	__lru_remove(l, e);
	e->oblock = new_oblock;
	__lru_push(l, e);
}

static dm_block_t lru_residency(struct dm_cache_policy *p)
{
	struct lru_policy *l = to_lru_policy(p);
	return l->nr_allocated;
}

static void lru_set_seq_io_threshold(struct dm_cache_policy *p,
				     unsigned int seq_io_thresh)
{
}

static void lru_tick(struct dm_cache_policy *p)
{
	struct lru_policy *l = to_lru_policy(p);
	unsigned long flags;

	spin_lock_irqsave(&l->lock, flags);
	l->tick++;
	spin_unlock_irqrestore(&l->lock, flags);
}

static struct dm_cache_policy *lru_create(dm_block_t cache_size)
{
	int i;
	struct lru_policy *l = kzalloc(sizeof(*l), GFP_KERNEL);
	if (!l)
		return NULL;

	l->policy.destroy = lru_destroy;
	l->policy.map = lru_map;
	l->policy.load_mapping = lru_load_mapping;
	l->policy.remove_mapping = lru_remove_mapping;
	l->policy.force_mapping = lru_force_mapping;
	l->policy.residency = lru_residency;
	l->policy.set_seq_io_threshold = lru_set_seq_io_threshold;
	l->policy.tick = lru_tick;

	l->cache_size = cache_size;
	l->tick = 0;
	spin_lock_init(&l->lock);

	queue_init(&l->lru);
	queue_init(&l->free);

	l->last_lookup = NULL;
	l->entries = vzalloc(sizeof(*l->entries) * cache_size);
	if (!l->entries) {
		kfree(l);
		return NULL;
	}

	for (i = 0; i < cache_size; i++)
		queue_push(&l->free, &l->entries[i].list);

	l->nr_allocated = 0;
	l->nr_buckets = next_power(cache_size / 4, 16);
	l->hash_mask = l->nr_buckets - 1;
	l->table = kzalloc(sizeof(*l->table) * l->nr_buckets, GFP_KERNEL);
	if (!l->table) {
		vfree(l->entries);
		kfree(l);
		return NULL;
	}

	l->interesting_size = next_power(cache_size * 2, 16);
	l->interesting_array = vzalloc(sizeof(*l->interesting_array) * l->interesting_size);
	if (!l->interesting_array) {
		kfree(l->table);
		vfree(l->entries);
		kfree(l);
		return NULL;
	}

	l->allocation_bitset = alloc_bitset(cache_size, 0);
	if (!l->allocation_bitset) {
		vfree(l->interesting_array);
		kfree(l->table);
		vfree(l->entries);
		kfree(l);
		return NULL;
	}

	return &l->policy;
}

/*----------------------------------------------------------------*/

static struct dm_cache_policy_type lru_policy_type = {
	.name = "lru",
	.owner = THIS_MODULE,
        .create = lru_create
};

static int __init lru_init(void)
{
	return dm_cache_policy_register(&lru_policy_type);
}

static void __exit lru_exit(void)
{
	dm_cache_policy_unregister(&lru_policy_type);
}

module_init(lru_init);
module_exit(lru_exit);

MODULE_AUTHOR("Joe Thornber");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("lru cache policy");

/*----------------------------------------------------------------*/

/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * FIFO/LRU/MRU/LFU/MFU cache replacement policies.
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

struct all_entry {
	struct hlist_node hlist;
	struct list_head list;

	dm_block_t oblock, cblock;
	unsigned tick, used;
};

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

static void queue_add(struct queue *q, struct list_head *elt)
{
	list_add_tail(elt, &q->elts);
	q->size++;
}

static void queue_add_fifo(struct queue *q, struct list_head *elt)
{
	queue_add(q, elt);
}

static void queue_add_lru(struct queue *q, struct list_head *elt)
{
	queue_add(q, elt);
}

static void queue_add_mru(struct queue *q, struct list_head *elt)
{
	list_add(elt, &q->elts);
	q->size++;
}

enum queue_add_type { P_FIFO = 0, P_LRU, P_MRU, P_LFU, P_MFU };
static void _queue_add_lfu_mfu(struct queue *q, struct list_head *elt, enum queue_add_type type)
{
        if (!list_empty(&q->elts)) {
		int iterate = 1;
		struct all_entry *end       = list_entry(q->elts.prev, struct all_entry, list);
		struct all_entry *elt_entry = list_entry(elt, struct all_entry, list);

		/* Optimization to avoid loop if possible. */
		if (type == P_LFU) {
 			if (end->used <= elt_entry->used)
				iterate = 0;
		} else if (end->used >= elt_entry->used)
			iterate = 0;

		if (iterate) {
                	struct list_head *e;

	                list_for_each(e, &q->elts) {
				int r = (list_entry(e, struct all_entry, list))->used < elt_entry->used;

				if (type == P_LFU ? !r : r) {
	                                list_add_tail(elt, e);
	                                q->size++;
	                                return;
	                        }
	                }
                }
        }

        queue_add(q, elt);
}

static void queue_add_lfu(struct queue *q, struct list_head *elt)
{
        _queue_add_lfu_mfu(q, elt, P_LFU);
}

static void queue_add_mfu(struct queue *q, struct list_head *elt)
{
        _queue_add_lfu_mfu(q, elt, P_MFU);
}

/*----------------------------------------------------------------*/

struct seen_block {
	dm_block_t oblock;
	unsigned tick;
};

typedef void (*queue_add_fn)(struct queue*, struct list_head*);
struct policy {
	struct dm_cache_policy policy;

	dm_block_t cache_size;
	unsigned tick;

	spinlock_t lock;
	struct queue prio;
	struct queue free;
	queue_add_fn queue_add;
	enum queue_add_type type;

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

	/* Last looked up cached entry */
	struct all_entry *last_lookup;
};

static struct policy *to_policy(struct dm_cache_policy *p)
{
	return container_of(p, struct policy, policy);
}

static void all_destroy(struct dm_cache_policy *p)
{
	struct policy *l = to_policy(p);

	free_bitset(l->allocation_bitset);
	vfree(l->interesting_array);
	kfree(l->table);
	vfree(l->entries);
	kfree(l);
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

static struct all_entry *__all_lookup(struct policy *l, dm_block_t origin)
{
	unsigned h = hash(l, origin);
	struct hlist_head *bucket = l->table + h;
	struct hlist_node *tmp;
	struct all_entry *e;

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

static void __all_remove(struct policy *l, struct all_entry *e)
{
	hlist_del(&e->hlist);
}

static struct all_entry *__all_alloc_entry(struct policy *l)
{
	struct all_entry *e;

	BUG_ON(l->nr_allocated >= l->cache_size);

	e = list_entry(queue_pop(&l->free), struct all_entry, list);
	INIT_LIST_HEAD(&e->list);
	INIT_HLIST_NODE(&e->hlist);
	l->nr_allocated++;
	e->tick = l->tick;
	e->used = 0;

	return e;
}

static void __alloc_cblock(struct policy *l, dm_block_t cblock)
{
	BUG_ON(cblock > l->cache_size);
	BUG_ON(test_bit(cblock, l->allocation_bitset));
	set_bit(cblock, l->allocation_bitset);
}

static void __free_cblock(struct policy *l, dm_block_t cblock)
{
	BUG_ON(cblock > l->cache_size);
	BUG_ON(!test_bit(cblock, l->allocation_bitset));
	clear_bit(cblock, l->allocation_bitset);
}

/*
 * This doesn't allocate the block.
 */
static int __find_free_cblock(struct policy *l, dm_block_t *result)
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

static bool __any_free_entries(struct policy *l)
{
	return l->nr_allocated < l->cache_size;
}

static void __all_add(struct policy *l, struct all_entry *e)
{
	e->tick = l->tick;
	l->queue_add(&l->prio, &e->list);
	__alloc_cblock(l, e->cblock);
	__all_insert(l, e);
}

static struct all_entry *__all_pop(struct policy *l)
{
	struct all_entry *e = NULL;

	e = list_entry(queue_pop(&l->prio), struct all_entry, list);
	INIT_LIST_HEAD(&e->list);
	__all_remove(l, e);
	__free_cblock(l, e->cblock);
	e->used = 0;
	return e;
}

/*
 * FIXME: the size of the interesting blocks hash table seems to be
 * directly related to the eviction rate.  So maybe we should resize on the
 * fly to get to a target eviction rate?
 */
static int __all_interesting_block(struct policy *l, dm_block_t oblock, int data_dir)
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

static bool updated_this_tick(struct policy *l, struct all_entry *e)
{
	return l->tick == e->tick;
}

static void __all_map(struct policy *l,
		      dm_block_t origin_block,
		      int data_dir,
		      bool can_migrate,
		      bool cheap_copy,
		      struct policy_result *result)
{
	int r;
	dm_block_t all_size;
	struct all_entry *e;

	e = __all_lookup(l, origin_block);
	if (e) {
		result->op = POLICY_HIT;
		result->cblock = e->cblock;

		if (l->type == P_FIFO)
			return;

		e->used++;

		if (l->type == P_LFU || l->type == P_MFU || !updated_this_tick(l, e)) {
			struct list_head tmp;

			__free_cblock(l, e->cblock);
			/* Store start point in list for queue_add_[ml]fu, because list del will poison it. */
			tmp = e->list;
			queue_del(&l->prio, &e->list);
			__all_remove(l, e);
			e->list = tmp;
			__all_add(l, e);
		}

		return;
	}

	/* FIXME: this is turning into a huge mess */
	cheap_copy &= __any_free_entries(l);
	if (!(cheap_copy || (can_migrate && __all_interesting_block(l, origin_block, data_dir)))) {
		result->op = POLICY_MISS;
		return;
	}

	all_size = queue_size(&l->prio);
	if (all_size == l->cache_size) {
		if (!can_migrate) {
			result->op = POLICY_MISS;
			return;
		}

		e = __all_pop(l);
		result->old_oblock = e->oblock;
		e->oblock = origin_block;
		result->op = POLICY_REPLACE;
		result->cblock = e->cblock;
	} else {
		e = __all_alloc_entry(l);
		r = __find_free_cblock(l, &e->cblock);
		BUG_ON(r);

		result->op = POLICY_NEW;
		result->cblock = e->cblock;
		e->oblock = origin_block;
	}

	__all_add(l, e);
}

static void all_map(struct dm_cache_policy *p, dm_block_t origin_block, int data_dir,
		    bool can_migrate, bool cheap_copy, struct bio *bio,
		    struct policy_result *result)
{
	unsigned long flags;
	struct policy *l = to_policy(p);

	spin_lock_irqsave(&l->lock, flags);
	__all_map(l, origin_block, data_dir, can_migrate, cheap_copy, result);
	spin_unlock_irqrestore(&l->lock, flags);
}

static int all_load_mapping(struct dm_cache_policy *p, dm_block_t oblock, dm_block_t cblock)
{
	struct policy *l = to_policy(p);
	struct all_entry *e;

	debug("loading mapping %lu -> %lu\n",
	      (unsigned long) oblock,
	      (unsigned long) cblock);

	e = __all_alloc_entry(l);
	if (!e)
		return -ENOMEM;

	e->cblock = cblock;
	e->oblock = oblock;
	__all_add(l, e);

	return 0;
}

static void all_remove_mapping(struct dm_cache_policy *p, dm_block_t oblock)
{
	struct policy *l = to_policy(p);
	struct all_entry *e = __all_lookup(l, oblock);

	BUG_ON(!e);

	__free_cblock(l, e->cblock);
	queue_del(&l->prio, &e->list);
	__all_remove(l, e);
	queue_add(&l->free, &e->list);
// HM
	BUG_ON(!l->nr_allocated);
	l->nr_allocated--;
}

static void all_force_mapping(struct dm_cache_policy *p,
		dm_block_t current_oblock, dm_block_t new_oblock)
{
	struct policy *l = to_policy(p);
	struct all_entry *e = __all_lookup(l, current_oblock);

	BUG_ON(!e);

	__free_cblock(l, e->cblock);
	queue_del(&l->prio, &e->list);
	INIT_LIST_HEAD(&e->list);
	__all_remove(l, e);
	e->oblock = new_oblock;
	__all_add(l, e);
}

static dm_block_t all_residency(struct dm_cache_policy *p)
{
	struct policy *l = to_policy(p);
	return l->nr_allocated;
}

static void all_set_seq_io_threshold(struct dm_cache_policy *p,
				     unsigned int seq_io_thresh)
{
}

static void all_tick(struct dm_cache_policy *p)
{
	struct policy *l = to_policy(p);
	unsigned long flags;

	spin_lock_irqsave(&l->lock, flags);
	l->tick++;
	spin_unlock_irqrestore(&l->lock, flags);
}

static struct dm_cache_policy *__create(dm_block_t cache_size,
					enum queue_add_type type)
{
	int i;
	static queue_add_fn queue_add_fns[] = {
		/* Have to be sorted by queue_add_type enum! */
		&queue_add_fifo,
		&queue_add_lru,
		&queue_add_mru,
		&queue_add_lfu,
		&queue_add_mfu
	};
	struct policy *l = kzalloc(sizeof(*l), GFP_KERNEL);

	if (!l)
		return NULL;

	/* Distinguish FIFO/LRU/MRU/LFU/MFU policies */
	l->queue_add = queue_add_fns[type];
	l->type = type;

	l->policy.destroy = all_destroy;
	l->policy.map = all_map;
	l->policy.load_mapping = all_load_mapping;
	l->policy.remove_mapping = all_remove_mapping;
	l->policy.force_mapping = all_force_mapping;
	l->policy.residency = all_residency;
	l->policy.set_seq_io_threshold = all_set_seq_io_threshold;
	l->policy.tick = all_tick;

	l->cache_size = cache_size;
	l->tick = 0;
	spin_lock_init(&l->lock);

	queue_init(&l->prio);
	queue_init(&l->free);

	l->last_lookup = NULL;
	l->entries = vzalloc(sizeof(*l->entries) * cache_size);
	if (!l->entries) {
		kfree(l);
		return NULL;
	}

	for (i = 0; i < cache_size; i++)
		queue_add(&l->free, &l->entries[i].list);

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

static struct dm_cache_policy *fifo_create(dm_block_t cache_size)
{
	return __create(cache_size, P_FIFO);
}

static struct dm_cache_policy *lru_create(dm_block_t cache_size)
{
	return __create(cache_size, P_LRU);
}

static struct dm_cache_policy *mru_create(dm_block_t cache_size)
{
	return __create(cache_size, P_MRU);
}

static struct dm_cache_policy *lfu_create(dm_block_t cache_size)
{
	return __create(cache_size, P_LFU);
}

static struct dm_cache_policy *mfu_create(dm_block_t cache_size)
{
	return __create(cache_size, P_MFU);
}

/*----------------------------------------------------------------*/

static struct dm_cache_policy_type fifo_policy_type = {
	.name = "fifo",
	.owner = THIS_MODULE,
        .create = fifo_create
};

static struct dm_cache_policy_type lru_policy_type = {
	.name = "lru",
	.owner = THIS_MODULE,
        .create = lru_create
};

static struct dm_cache_policy_type mru_policy_type = {
	.name = "mru",
	.owner = THIS_MODULE,
        .create = mru_create
};

static struct dm_cache_policy_type lfu_policy_type = {
	.name = "lfu",
	.owner = THIS_MODULE,
        .create = lfu_create
};

static struct dm_cache_policy_type mfu_policy_type = {
	.name = "mfu",
	.owner = THIS_MODULE,
        .create = mfu_create
};

static int __init all_init(void)
{
	int r = dm_cache_policy_register(&fifo_policy_type);

	if (!r)
	       r = dm_cache_policy_register(&lru_policy_type);

	if (!r)
	       r = dm_cache_policy_register(&mru_policy_type);

	if (!r)
	       r = dm_cache_policy_register(&lfu_policy_type);

	if (!r)
	       r = dm_cache_policy_register(&mfu_policy_type);

	return r;
}

static void __exit all_exit(void)
{
	dm_cache_policy_unregister(&mfu_policy_type);
	dm_cache_policy_unregister(&lfu_policy_type);
	dm_cache_policy_unregister(&mru_policy_type);
	dm_cache_policy_unregister(&lru_policy_type);
	dm_cache_policy_unregister(&fifo_policy_type);
}

module_init(all_init);
module_exit(all_exit);

MODULE_AUTHOR("Joe Thornber/Heinz Mauelshagen");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("fifo/lru/mru/lfu/mfu cache policies");

MODULE_ALIAS("dm-cache-fifo");
MODULE_ALIAS("dm-cache-lru");
MODULE_ALIAS("dm-cache-mru");
MODULE_ALIAS("dm-cache-lfu");
MODULE_ALIAS("dm-cache-mfu");

/*----------------------------------------------------------------*/

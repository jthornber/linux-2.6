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

#define DM_MSG_PREFIX "cache-policy-arc"

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

/*
 * Multiqueue
 * FIXME: explain
 */
#define NR_MQ_LEVELS 16

typedef unsigned (*queue_level_fn)(void *context, struct list_head *entry, unsigned nr_levels);

struct multiqueue {
	queue_level_fn queue_level;
	void *context;

	struct list_head qs[NR_MQ_LEVELS];
};

static void mq_init(struct multiqueue *mq,
		    queue_level_fn queue_level,
		    void *context)
{
	unsigned i;

	mq->queue_level = queue_level;
	mq->context = context;

	for (i = 0; i < NR_MQ_LEVELS; i++)
		INIT_LIST_HEAD(mq->qs + i);
}

static struct list_head *mq_get_q(struct multiqueue *mq, struct list_head *elt)
{
	unsigned level = mq->queue_level(mq->context, elt, NR_MQ_LEVELS);
	BUG_ON(level >= NR_MQ_LEVELS);
	return mq->qs + level;
}

static void mq_push(struct multiqueue *mq, struct list_head *elt)
{
	list_add_tail(elt, mq_get_q(mq, elt));
}

static void mq_remove(struct list_head *elt)
{
	list_del(elt);
}

static void mq_shift_down(struct multiqueue *mq)
{
	unsigned level;

	for (level = 1; level < NR_MQ_LEVELS; level++)
		list_splice_init(mq->qs + level, mq->qs + level - 1);
}

/*
 * Gives us the oldest entry of the lowest level.
 */
static struct list_head *mq_pop(struct multiqueue *mq)
{
	unsigned i;
	struct list_head *r;

	for (i = 0; i < NR_MQ_LEVELS; i++)
		if (!list_empty(mq->qs + i)) {
			r = mq->qs[i].next;
			list_del(r);

			if (i == 0 && list_empty(mq->qs))
				mq_shift_down(mq);

			return r;
		}

	return NULL;
}

/*----------------------------------------------------------------*/

struct entry {
	struct hlist_node hlist;
	struct list_head list;
	dm_block_t oblock;
	dm_block_t cblock;

	bool in_cache:1;

	// FIXME: pack these better
	unsigned hit_count;
	unsigned generation;
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
	unsigned lookup_count;
	unsigned hit_count;
	unsigned promote_threshold;
	unsigned generation;
	unsigned generation_period;

	spinlock_t lock;

	struct multiqueue mq_pre_cache;
	struct multiqueue mq_cache;

	/*
	 * We know exactly how many entries will be needed, so we can
	 * allocate them up front.
	 */
	unsigned nr_entries;
	unsigned nr_allocated;
	struct entry *entries;

	unsigned long *allocation_bitset;
	unsigned nr_cblocks_allocated;

	unsigned nr_buckets;
	dm_block_t hash_mask;
	struct hlist_head *table;

	/* Fields for tracking IO pattern */
	/* 0: IO stream is random. 1: IO stream is sequential */
	bool seq_stream;
	unsigned nr_seq_samples, nr_rand_samples;
	dm_block_t last_end_oblock;
	unsigned int seq_io_threshold;

	/* Last looked up cached entry */
	struct entry *last_lookup;
};

#define NR_PRE_CACHE_LEVELS 4

static struct arc_policy *to_arc_policy(struct dm_cache_policy *p)
{
	return container_of(p, struct arc_policy, policy);
}

static void arc_destroy(struct dm_cache_policy *p)
{
	struct arc_policy *a = to_arc_policy(p);

	free_bitset(a->allocation_bitset);
	kfree(a->table);
	vfree(a->entries);
	kfree(a);
}

/*----------------------------------------------------------------*/

/* FIXME: replace with the new hash table stuff */

static unsigned hash(struct arc_policy *a, dm_block_t b)
{
	const dm_block_t BIG_PRIME = 4294967291UL;
	dm_block_t h = b * BIG_PRIME;

	return (uint32_t) (h & a->hash_mask);
}

static void __hash_insert(struct arc_policy *a, struct entry *e)
{
	unsigned h = hash(a, e->oblock);
	hlist_add_head(&e->hlist, a->table + h);
}

static struct entry *__hash_lookup(struct arc_policy *a, dm_block_t origin)
{
	unsigned h = hash(a, origin);
	struct hlist_head *bucket = a->table + h;
	struct hlist_node *tmp;
	struct entry *e;

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

static void __hash_remove(struct arc_policy *a, struct entry *e)
{
	hlist_del(&e->hlist);
}

/*----------------------------------------------------------------*/

static struct entry *__arc_alloc_entry(struct arc_policy *a)
{
	struct entry *e;

	if (a->nr_allocated >= a->nr_entries)
		return NULL;

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
	a->nr_cblocks_allocated++;
}

static void __free_cblock(struct arc_policy *a, dm_block_t cblock)
{
	BUG_ON(cblock > a->cache_size);
	BUG_ON(!test_bit(cblock, a->allocation_bitset));
	clear_bit(cblock, a->allocation_bitset);
	a->nr_cblocks_allocated--;
}

/*
 * This doesn't allocate the block.
 */
static int __find_free_cblock(struct arc_policy *a, dm_block_t *result)
{
	int r = -ENOSPC;
	unsigned nr_words = dm_div_up(a->cache_size, BITS_PER_LONG);
	unsigned w, b;

	if (a->nr_cblocks_allocated >= a->cache_size)
		return -ENOSPC;

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

static bool __any_free_cblocks(struct arc_policy *a)
{
	return a->nr_cblocks_allocated < a->cache_size;
}

/*----------------------------------------------------------------*/

static void __arc_push(struct arc_policy *a, struct entry *e)
{
	e->tick = a->tick;
	__hash_insert(a, e);

	if (e->in_cache) {
		__alloc_cblock(a, e->cblock);
		mq_push(&a->mq_cache, &e->list);
	} else
		mq_push(&a->mq_pre_cache, &e->list);
}


static void __arc_del(struct arc_policy *a, struct entry *e)
{
	mq_remove(&e->list);
	__hash_remove(a, e);
	if (e->in_cache)
		__free_cblock(a, e->cblock);
}

// FIXME: move up with the structs
enum queue_area {
	QA_PRE_CACHE,
	QA_CACHE
};

static struct entry *__arc_pop(struct arc_policy *a, enum queue_area area)
{
	struct entry *e;

	if (area == QA_PRE_CACHE)
		e = container_of(mq_pop(&a->mq_pre_cache), struct entry, list);
	else
		e = container_of(mq_pop(&a->mq_cache), struct entry, list);

	if (e) {
		__hash_remove(a, e);

		if (e->in_cache)
			__free_cblock(a, e->cblock);
	}

	return e;
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

static bool updated_this_tick(struct arc_policy *a, struct entry *e)
{
	return a->tick == e->tick;
}

// debug only
static unsigned list_stats(struct list_head *head, unsigned *counts)
{
	unsigned r = 0;
	struct list_head *tmp;

	memset(counts, 0, sizeof(*counts) * NR_MQ_LEVELS);

	list_for_each (tmp, head) {
		struct entry *e = container_of(tmp, struct entry, list);
		counts[min(ilog2(e->hit_count), NR_MQ_LEVELS)]++;
		r++;
	}

	return r;
}

static void mq_stats(struct multiqueue *mq)
{
	static char buffer[256];

	unsigned i, j, counts[NR_MQ_LEVELS];
	bool printing = false;

	for (i = NR_MQ_LEVELS; i; i--) {
		unsigned level = i - 1;
		unsigned total = list_stats(mq->qs + level, counts);

		if (printing || total) {
			unsigned written = 0;
			written += snprintf(buffer + written, sizeof(buffer) - written, "level %u:\t%u [", level, total);
			for (j = 0; j < NR_MQ_LEVELS; j++)
				written += snprintf(buffer + written, sizeof(buffer) - written, "%u, ", counts[j]);
			written += snprintf(buffer + written, sizeof(buffer) - written, "]\n");
			buffer[written] = '\0';
			pr_alert("%s", buffer);

			printing = true;
		}
	}
}

static void __arc_hit(struct arc_policy *a, struct entry *e)
{
	if (updated_this_tick(a, e))
		return;

	__arc_del(a, e);

	e->hit_count++;
	a->hit_count++;

	if ((a->lookup_count == a->generation_period) &&
	    (a->nr_cblocks_allocated == a->cache_size)) {
		unsigned total = 0, nr = 0;
		struct list_head *head;
		struct entry *e;

		pr_alert("----  pre cache stats\n");
		mq_stats(&a->mq_pre_cache);
		pr_alert("----  cache stats\n");
		mq_stats(&a->mq_cache);

		a->lookup_count = 0;
		a->generation++;

		head = a->mq_cache.qs + 1;
		if (list_empty(head))
			head = a->mq_cache.qs;

		// FIXME: just the first 20 or so should be enough
		list_for_each_entry (e, head, list) {
			nr++;
			total += e->hit_count;
		}

		a->promote_threshold = nr ? total / nr : 1;

		pr_alert("promote_threshold = %u\n", a->promote_threshold);
	}

	//e->hit_count -= min(e->hit_count - 1, a->generation - e->generation);
	e->generation = a->generation;

	__arc_push(a, e);
}

static dm_block_t demote_cblock(struct arc_policy *a, dm_block_t *oblock)
{
	dm_block_t result;
	struct entry *demoted = __arc_pop(a, QA_CACHE);

	BUG_ON(!demoted);
	result = demoted->cblock;
	*oblock = demoted->oblock;
	demoted->in_cache = false;
	__arc_push(a, demoted);

	return result;
}

#define DISCARDED_PROMOTE_THRESHOLD 1
#define READ_PROMOTE_THRESHOLD 1
#define WRITE_PROMOTE_THRESHOLD 5

static unsigned arc_queue_level(void *context, struct list_head *elt, unsigned nr_levels)
{
	struct entry *e = container_of(elt, struct entry, list);
	return min((unsigned) ilog2(e->hit_count), nr_levels - 1);
}

static bool should_promote(struct arc_policy *a,
			   struct entry *e,
			   bool can_migrate,
			   bool cheap_copy,
			   int data_dir)
{
	if (!arc_random_stream(a))
		return false;

	if (cheap_copy && __any_free_cblocks(a) &&
	    (e->hit_count >= a->promote_threshold + DISCARDED_PROMOTE_THRESHOLD))
		return true;

	return can_migrate &&
		(e->hit_count >= (data_dir == READ ?
				  (a->promote_threshold + READ_PROMOTE_THRESHOLD) :
				  (a->promote_threshold + WRITE_PROMOTE_THRESHOLD)));
}

// FIXME: rename origin_block to oblock
static int __arc_map_found(struct arc_policy *a,
			   struct entry *e,
			   dm_block_t origin_block,
			   bool can_migrate,
			   bool cheap_copy,
			   bool can_block,
			   int data_dir,
			   struct policy_result *result)
{
	dm_block_t cblock;
	bool updated = updated_this_tick(a, e); /* has to be done before __arc_hit */

	__arc_hit(a, e);

	if (e->in_cache) {
		result->op = POLICY_HIT;
		result->cblock = e->cblock;
		return 0;
	}

	if (updated || !arc_random_stream(a) || !should_promote(a, e, can_migrate, cheap_copy, data_dir)) {
		result->op = POLICY_MISS;
		return 0;
	}

	if (!can_block)
		return -EWOULDBLOCK;

	if (__find_free_cblock(a, &cblock) == -ENOSPC) {
		result->op = POLICY_REPLACE;
		cblock = demote_cblock(a, &result->old_oblock);
	} else
		result->op = POLICY_NEW;

	result->cblock = e->cblock = cblock;

	__arc_del(a, e);
	e->in_cache = true;
	__arc_push(a, e);

	return 0;
}

static void to_pre_cache(struct arc_policy *a,
			 dm_block_t oblock)
{
	struct entry *e = __arc_alloc_entry(a);

	if (!e)
		e = __arc_pop(a, QA_PRE_CACHE);

	if (unlikely(!e)) {
		DMWARN("couldn't pop from pre cache");
		return;
	}

	e->in_cache = false;
	e->oblock = oblock;
	e->hit_count = 1;
	e->generation = a->generation;
	__arc_push(a, e);
}

static void straight_to_cache(struct arc_policy *a,
			      dm_block_t oblock,
			      struct policy_result *result)
{
	struct entry *e = __arc_alloc_entry(a);

	if (unlikely(!e)) {
		result->op = POLICY_MISS;
		return;
	}

	e->oblock = oblock;
	e->hit_count = 1;
	e->generation = a->generation;

	if (__find_free_cblock(a, &e->cblock) == -ENOSPC) {
		DMWARN("straight_to_cache couldn't allocate cblock");
		result->op = POLICY_MISS;
		e->in_cache = false;
	} else {
		result->op = POLICY_NEW;
		result->cblock = e->cblock;
		e->in_cache = true;
	}

	__arc_push(a, e);
}

static int __arc_map(struct arc_policy *a,
		     dm_block_t oblock,
		     bool can_migrate,
		     bool cheap_copy,
		     bool can_block,
		     int data_dir,
		     struct policy_result *result)
{
	struct entry *e = __hash_lookup(a, oblock);
	if (e)
		return __arc_map_found(a, e, oblock, can_migrate, cheap_copy, can_block, data_dir, result);

	if (!arc_random_stream(a)) {
		result->op = POLICY_MISS;
		return 0;
	}

	if (cheap_copy && __any_free_cblocks(a)) {
		if (can_block) {
			straight_to_cache(a, oblock, result);
			return 0;
		} else
			return -EWOULDBLOCK;

	} else {
		to_pre_cache(a, oblock);
		result->op = POLICY_MISS;
		return 0;
	}
}

static int arc_map(struct dm_cache_policy *p, dm_block_t origin_block, int data_dir,
		   bool can_migrate, bool cheap_copy, bool can_block, struct bio *bio,
		   struct policy_result *result)
{
	int r;
	unsigned long flags;
	struct arc_policy *a = to_arc_policy(p);

	spin_lock_irqsave(&a->lock, flags);
	a->lookup_count++;
	__arc_update_io_stream_data(a, bio);
	r = __arc_map(a, origin_block, can_migrate, cheap_copy, can_block, bio_data_dir(bio), result);
	spin_unlock_irqrestore(&a->lock, flags);

	return r;
}

static int arc_load_mapping(struct dm_cache_policy *p, dm_block_t oblock, dm_block_t cblock)
{
	struct arc_policy *a = to_arc_policy(p);
	struct entry *e;

	debug("loading mapping %lu -> %lu\n",
	      (unsigned long) oblock,
	      (unsigned long) cblock);

	e = __arc_alloc_entry(a);
	if (!e)
		return -ENOMEM;

	e->cblock = cblock;
	e->oblock = oblock;
	e->in_cache = true;
	__arc_push(a, e);

	return 0;
}

static void arc_remove_mapping(struct dm_cache_policy *p, dm_block_t oblock)
{
	struct arc_policy *a = to_arc_policy(p);
	struct entry *e = __hash_lookup(a, oblock);

	BUG_ON(!e || e->in_cache);

	__arc_del(a, e);
	e->in_cache = false;
	__arc_push(a, e);
}

static void arc_force_mapping(struct dm_cache_policy *p,
			      dm_block_t current_oblock, dm_block_t new_oblock)
{
	struct arc_policy *a = to_arc_policy(p);
	struct entry *e = __hash_lookup(a, current_oblock);

	BUG_ON(!e);
	BUG_ON(!e->in_cache);

	__arc_del(a, e);
	e->oblock = new_oblock;
	__arc_push(a, e);
}

static dm_block_t arc_residency(struct dm_cache_policy *p)
{
	struct arc_policy *a = to_arc_policy(p);
	return a->nr_cblocks_allocated;
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
	a->lookup_count = 0;
	a->hit_count = 0;
	a->generation = 0;
	a->promote_threshold = 1;
	spin_lock_init(&a->lock);

	mq_init(&a->mq_pre_cache, arc_queue_level, a);
	mq_init(&a->mq_cache, arc_queue_level, a);
	a->generation_period = max((unsigned) cache_size, 1024U); /* FIXME: this should be related to the origin size I feel */

	a->last_lookup = NULL;

	a->nr_entries = 2 * cache_size;
	a->entries = vzalloc(sizeof(*a->entries) * a->nr_entries);
	if (!a->entries) {
		kfree(a);
		return NULL;
	}

	a->nr_allocated = 0;
	a->nr_cblocks_allocated = 0;

	a->nr_buckets = next_power(cache_size / 4, 16);
	a->hash_mask = a->nr_buckets - 1;
	a->table = kzalloc(sizeof(*a->table) * a->nr_buckets, GFP_KERNEL);
	if (!a->table) {
		vfree(a->entries);
		kfree(a);
		return NULL;
	}

	a->allocation_bitset = alloc_bitset(cache_size, 0);
	if (!a->allocation_bitset) {
		kfree(a->table);
		vfree(a->entries);
		kfree(a);
		return NULL;
	}

	return &a->policy;
}

/*----------------------------------------------------------------*/

// FIXME: register this under the 'default' policy name too

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

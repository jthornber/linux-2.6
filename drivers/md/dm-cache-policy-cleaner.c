/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * writeback cache policy supporting flushing out dirty cache blocks.
 *
 * This file is released under the GPL.
 */

#include "dm-cache-background-tracker.h"
#include "dm-cache-policy.h"
#include "dm.h"

#include <linux/hash.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

/*----------------------------------------------------------------*/

#define DM_MSG_PREFIX "cache cleaner"

/* Cache entry struct. */
struct wb_cache_entry {
	struct list_head list;
	struct hlist_node hlist;

	dm_oblock_t oblock;
	dm_cblock_t cblock;	/* FIXME: we can infer this from it's address */

	bool dirty:1;
	bool pending:1;
};

struct hash {
	struct hlist_head *table;
	dm_block_t hash_bits;
	unsigned nr_buckets;
};

struct policy {
	struct dm_cache_policy policy;
	spinlock_t lock;

	struct list_head free;
	struct list_head clean;
	struct list_head dirty;

	/*
	 * We know exactly how many cblocks will be needed,
	 * so we can allocate them up front.
	 */
	dm_cblock_t cache_size;
	dm_cblock_t nr_cblocks_allocated;
	struct wb_cache_entry *cblocks;
	struct hash chash;

	struct background_tracker *bg_work;
};

/*----------------------------------------------------------------------------*/

/*
 * Low-level functions.
 */
static unsigned next_power(unsigned n, unsigned min)
{
	return roundup_pow_of_two(max(n, min));
}

static struct policy *to_policy(struct dm_cache_policy *p)
{
	return container_of(p, struct policy, policy);
}

static struct list_head *list_pop(struct list_head *q)
{
	struct list_head *r = q->next;

	list_del(r);
	return r;
}

/*----------------------------------------------------------------------------*/

/* Allocate/free various resources. */
static int alloc_hash(struct hash *hash, unsigned elts)
{
	hash->nr_buckets = next_power(elts >> 4, 16);
	hash->hash_bits = __ffs(hash->nr_buckets);
	hash->table = vzalloc(sizeof(*hash->table) * hash->nr_buckets);

	return hash->table ? 0 : -ENOMEM;
}

static void free_hash(struct hash *hash)
{
	vfree(hash->table);
}

static int alloc_cache_blocks_with_hash(struct policy *p, dm_cblock_t cache_size)
{
	int r = -ENOMEM;

	p->cblocks = vzalloc(sizeof(*p->cblocks) * from_cblock(cache_size));
	if (p->cblocks) {
		unsigned u = from_cblock(cache_size);

		while (u--)
			list_add(&p->cblocks[u].list, &p->free);

		p->nr_cblocks_allocated = 0;

		/* Cache entries hash. */
		r = alloc_hash(&p->chash, from_cblock(cache_size));
		if (r)
			vfree(p->cblocks);
	}

	return r;
}

static void free_cache_blocks_and_hash(struct policy *p)
{
	free_hash(&p->chash);
	vfree(p->cblocks);
}

static struct wb_cache_entry *alloc_cache_entry(struct policy *p)
{
	struct wb_cache_entry *e;

	BUG_ON(from_cblock(p->nr_cblocks_allocated) >= from_cblock(p->cache_size));

	e = list_entry(list_pop(&p->free), struct wb_cache_entry, list);
	p->nr_cblocks_allocated = to_cblock(from_cblock(p->nr_cblocks_allocated) + 1);

	return e;
}

/* Hash functions (lookup, insert, remove). */
static struct wb_cache_entry *lookup_cache_entry(struct policy *p, dm_oblock_t oblock)
{
	struct hash *hash = &p->chash;
	unsigned h = hash_64(from_oblock(oblock), hash->hash_bits);
	struct wb_cache_entry *cur;
	struct hlist_head *bucket = &hash->table[h];

	hlist_for_each_entry(cur, bucket, hlist) {
		if (cur->oblock == oblock) {
			/* Move upfront bucket for faster access. */
			hlist_del(&cur->hlist);
			hlist_add_head(&cur->hlist, bucket);
			return cur;
		}
	}

	return NULL;
}

static void insert_cache_hash_entry(struct policy *p, struct wb_cache_entry *e)
{
	unsigned h = hash_64(from_oblock(e->oblock), p->chash.hash_bits);

	hlist_add_head(&e->hlist, &p->chash.table[h]);
}

/*----------------------------------------------------------------*/

static void wb_destroy(struct dm_cache_policy *pe)
{
	struct policy *p = to_policy(pe);

	btracker_destroy(p->bg_work);
	free_cache_blocks_and_hash(p);
	kfree(p);
}

static int wb_lookup(struct dm_cache_policy *pe, dm_oblock_t oblock, dm_cblock_t *cblock,
		     int data_dir, bool fast_copy, bool *background_queued)
{
	int r;
	struct policy *p = to_policy(pe);
	struct wb_cache_entry *e;
	unsigned long flags;

	*background_queued = false;

	spin_lock_irqsave(&p->lock, flags);

	e = lookup_cache_entry(p, oblock);
	if (e) {
		*cblock = e->cblock;
		r = 0;
	} else
		r = -ENOENT;

	spin_unlock_irqrestore(&p->lock, flags);

	return r;
}

static int wb_lookup_with_work(struct dm_cache_policy *pe,
				dm_oblock_t oblock, dm_cblock_t *cblock,
				int data_dir, bool fast_copy,
				struct policy_work **work)
{
	bool background_queued = false;
	*work = NULL;
	return wb_lookup(pe, oblock, cblock, data_dir, fast_copy, &background_queued);
}

static bool wb_has_background_work(struct dm_cache_policy *pe)
{
	struct policy *p = to_policy(pe);
	return btracker_any_queued(p->bg_work);
}

static void __queue_writeback(struct policy *p)
{
	int r;
	struct wb_cache_entry *e;
	struct policy_work work;

	if (list_empty(&p->dirty))
		return;

	e = container_of(list_pop(&p->dirty), struct wb_cache_entry, list);
	e->pending = true;

	work.op = POLICY_WRITEBACK;
	work.cblock = e->cblock;
	work.oblock = e->oblock;

	r = btracker_queue(p->bg_work, &work, NULL);
	if (r == -EINVAL) {
		/*
		 * The block has already been queued, so we just exit.
		 * I don't think this can happen.
		 */
	} else {
		/*
		 * We need to back out.
		 */
		e->pending = false;
		list_add(&e->list, &p->dirty);
	}
}

static int wb_get_background_work(struct dm_cache_policy *pe, bool idle,
				  struct policy_work **result)
{
	int r;
	unsigned long flags;
	struct policy *p = to_policy(pe);

	/* protected with it's own lock */
	r = btracker_issue(p->bg_work, result);
	if (r == -ENODATA) {
		/* find some writeback work to do */
		spin_lock_irqsave(&p->lock, flags);
		__queue_writeback(p);
		spin_unlock_irqrestore(&p->lock, flags);

		r = btracker_issue(p->bg_work, result);
	}

	return r;
}

static void __complete_background_work(struct policy *p,
				       struct policy_work *work,
				       bool success)
{
	struct wb_cache_entry *e;

	if (work->op != POLICY_WRITEBACK) {
		DMERR("internal error: unexpected background work op\n");
		BUG();
	}

	e = lookup_cache_entry(p, work->oblock);
	if (!e) {
		DMERR("internal error: asked to complete work for an unknown entry");
		BUG();
	}

	if (success) {
		e->dirty = false;
		list_add(&e->list, &p->clean);
	} else
		list_add(&e->list, &p->dirty);

	e->pending = false;
	btracker_complete(p->bg_work, work);
}

static void wb_complete_background_work(struct dm_cache_policy *pe,
					struct policy_work *work,
					bool success)
{
	unsigned long flags;
	struct policy *p = to_policy(pe);

	spin_lock_irqsave(&p->lock, flags);
	__complete_background_work(p, work, success);
	spin_unlock_irqrestore(&p->lock, flags);
}

static void __set_clear_dirty(struct dm_cache_policy *pe, dm_oblock_t oblock, bool set)
{
	struct policy *p = to_policy(pe);
	struct wb_cache_entry *e;

	e = lookup_cache_entry(p, oblock);
	BUG_ON(!e);

	if (set) {
		if (!e->dirty) {
			e->dirty = true;
			list_move(&e->list, &p->dirty);
		}

	} else {
		if (e->dirty) {
			e->pending = false;
			e->dirty = false;
			list_move(&e->list, &p->clean);
		}
	}
}

static void wb_set_dirty(struct dm_cache_policy *pe, dm_oblock_t oblock)
{
	struct policy *p = to_policy(pe);
	unsigned long flags;

	spin_lock_irqsave(&p->lock, flags);
	__set_clear_dirty(pe, oblock, true);
	spin_unlock_irqrestore(&p->lock, flags);
}

static void wb_clear_dirty(struct dm_cache_policy *pe, dm_oblock_t oblock)
{
	struct policy *p = to_policy(pe);
	unsigned long flags;

	spin_lock_irqsave(&p->lock, flags);
	__set_clear_dirty(pe, oblock, false);
	spin_unlock_irqrestore(&p->lock, flags);
}

static void add_cache_entry(struct policy *p, struct wb_cache_entry *e)
{
	insert_cache_hash_entry(p, e);
	if (e->dirty)
		list_add(&e->list, &p->dirty);
	else
		list_add(&e->list, &p->clean);
}

static int wb_load_mapping(struct dm_cache_policy *pe,
			   dm_oblock_t oblock, dm_cblock_t cblock,
			   uint32_t hint, bool hint_valid)
{
	int r;
	struct policy *p = to_policy(pe);
	struct wb_cache_entry *e = alloc_cache_entry(p);

	if (e) {
		e->cblock = cblock;
		e->oblock = oblock;
		e->dirty = false; /* blocks default to clean */
		add_cache_entry(p, e);
		r = 0;
	} else
		r = -ENOMEM;

	return r;
}

static dm_cblock_t wb_residency(struct dm_cache_policy *pe)
{
	return to_policy(pe)->nr_cblocks_allocated;
}

/* Init the policy plugin interface function pointers. */
static void init_policy_functions(struct policy *p)
{
	p->policy.destroy = wb_destroy;
	p->policy.lookup = wb_lookup;
	p->policy.lookup_with_work = wb_lookup_with_work;
	p->policy.has_background_work = wb_has_background_work;
	p->policy.get_background_work = wb_get_background_work;
	p->policy.complete_background_work = wb_complete_background_work;
	p->policy.set_dirty = wb_set_dirty;
	p->policy.clear_dirty = wb_clear_dirty;
	p->policy.load_mapping = wb_load_mapping;
	p->policy.get_hint = NULL;
	p->policy.residency = wb_residency;
	p->policy.tick = NULL;
}

static struct dm_cache_policy *wb_create(dm_cblock_t cache_size,
					 sector_t origin_size,
					 sector_t cache_block_size)
{
	int r;
	struct policy *p = kzalloc(sizeof(*p), GFP_KERNEL);

	if (!p)
		return NULL;

	init_policy_functions(p);
	INIT_LIST_HEAD(&p->free);
	INIT_LIST_HEAD(&p->clean);
	INIT_LIST_HEAD(&p->dirty);

	p->cache_size = cache_size;
	spin_lock_init(&p->lock);

	/* Allocate cache entry structs and add them to free list. */
	r = alloc_cache_blocks_with_hash(p, cache_size);
	if (r) {
		kfree(p);
		return NULL;
	}

	p->bg_work = btracker_create(10240); /* FIXME: hard coded */
	if (!p->bg_work) {
		free_cache_blocks_and_hash(p);
		kfree(p);
	}

	return &p->policy;
}

/*----------------------------------------------------------------------------*/

static struct dm_cache_policy_type wb_policy_type = {
	.name = "cleaner",
	.version = {2, 0, 0},
	.hint_size = 4,
	.owner = THIS_MODULE,
	.create = wb_create
};

static int __init wb_init(void)
{
	int r = dm_cache_policy_register(&wb_policy_type);

	if (r < 0)
		DMERR("register failed %d", r);
	else
		DMINFO("version %u.%u.%u loaded",
		       wb_policy_type.version[0],
		       wb_policy_type.version[1],
		       wb_policy_type.version[2]);

	return r;
}

static void __exit wb_exit(void)
{
	dm_cache_policy_unregister(&wb_policy_type);
}

module_init(wb_init);
module_exit(wb_exit);

MODULE_AUTHOR("Heinz Mauelshagen <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("cleaner cache policy");

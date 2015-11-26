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

#define DM_MSG_PREFIX "cache-policy-always-promote"

static struct kmem_cache *ap_entry_cache;

/*----------------------------------------------------------------*/

static unsigned next_power(unsigned n, unsigned min)
{
	return roundup_pow_of_two(max(n, min));
}

/*----------------------------------------------------------------*/

/*
 * Describes a cache entry.  Used in both the cache and the pre_cache.
 */
struct entry {
	struct hlist_node hlist;
	struct list_head list;
	dm_oblock_t oblock;
	bool dirty;
};

/*
 * Rather than storing the cblock in an entry, we allocate all entries in
 * an array, and infer the cblock from the entry position.
 *
 * Free entries are linked together into a list.
 */
struct entry_pool {
	struct entry *entries, *entries_end;
	struct list_head free;
	unsigned nr_allocated;
};

static int epool_init(struct entry_pool *ep, unsigned nr_entries)
{
	unsigned i;

	ep->entries = vzalloc(sizeof(struct entry) * nr_entries);
	if (!ep->entries)
		return -ENOMEM;

	ep->entries_end = ep->entries + nr_entries;

	INIT_LIST_HEAD(&ep->free);
	for (i = 0; i < nr_entries; i++)
		list_add(&ep->entries[i].list, &ep->free);

	ep->nr_allocated = 0;

	return 0;
}

static void epool_exit(struct entry_pool *ep)
{
	vfree(ep->entries);
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

	if (list_empty(&ep->free))
		return NULL;

	e = list_entry(list_pop(&ep->free), struct entry, list);
	INIT_LIST_HEAD(&e->list);
	INIT_HLIST_NODE(&e->hlist);
	ep->nr_allocated++;

	return e;
}

/*
 * This assumes the cblock hasn't already been allocated.
 */
static struct entry *alloc_particular_entry(struct entry_pool *ep, dm_cblock_t cblock)
{
	struct entry *e = ep->entries + from_cblock(cblock);

	list_del_init(&e->list);
	INIT_HLIST_NODE(&e->hlist);
	ep->nr_allocated++;

	return e;
}

static void free_entry(struct entry_pool *ep, struct entry *e)
{
	BUG_ON(!ep->nr_allocated);
	ep->nr_allocated--;
	INIT_HLIST_NODE(&e->hlist);
	list_add(&e->list, &ep->free);
}

/*
 * Returns NULL if the entry is free.
 */
static struct entry *epool_find(struct entry_pool *ep, dm_cblock_t cblock)
{
	struct entry *e = ep->entries + from_cblock(cblock);
	return !hlist_unhashed(&e->hlist) ? e : NULL;
}

static bool epool_empty(struct entry_pool *ep)
{
	return list_empty(&ep->free);
}

static bool in_pool(struct entry_pool *ep, struct entry *e)
{
	return e >= ep->entries && e < ep->entries_end;
}

static dm_cblock_t infer_cblock(struct entry_pool *ep, struct entry *e)
{
	return to_cblock(e - ep->entries);
}

/*----------------------------------------------------------------*/

#define WRITEBACK_PERIOD HZ

struct queue {
	unsigned nr_elts;
	unsigned long next_writeback;
	struct list_head lru;
};

static void queue_init(struct queue *q)
{
	q->nr_elts = 0;
	q->next_writeback = 0;
	INIT_LIST_HEAD(&q->lru);
}

/*
 * Insert an entry to the back of the given level.
 */
static void queue_push(struct queue *q, struct list_head *elt)
{
	q->nr_elts++;
	list_add_tail(elt, &q->lru);
}

static void queue_remove(struct queue *q, struct list_head *elt)
{
	q->nr_elts--;
	list_del(elt);
}

/*
 * Gives us the oldest entry of the lowest popoulated level.  If the first
 * level is emptied then we shift down one level.
 */
static struct list_head *queue_peek(struct queue *q)
{
	return list_empty(&q->lru) ? NULL : q->lru.next;
}

static struct list_head *queue_pop(struct queue *q)
{
	struct list_head *r = queue_peek(q);

	if (r) {
		q->nr_elts--;
		list_del(r);
	}

	return r;
}

/*----------------------------------------------------------------*/

struct always_promote_policy {
	struct dm_cache_policy policy;

	/* protects everything */
	struct mutex lock;
	dm_cblock_t cache_size;
	struct entry_pool cache_pool;

	struct queue cache_clean;
	struct queue cache_dirty;

	/*
	 * The hash table allows us to quickly find an entry by origin
	 * block.  Both pre_cache and cache entries are in here.
	 */
	unsigned nr_buckets;
	dm_block_t hash_bits;
	struct hlist_head *table;
};

/*----------------------------------------------------------------*/

/*
 * Simple hash table implementation.  Should replace with the standard hash
 * table that's making its way upstream.
 */
static void hash_insert(struct always_promote_policy *ap, struct entry *e)
{
	unsigned h = hash_64(from_oblock(e->oblock), ap->hash_bits);

	hlist_add_head(&e->hlist, ap->table + h);
}

static struct entry *hash_lookup(struct always_promote_policy *ap, dm_oblock_t oblock)
{
	unsigned h = hash_64(from_oblock(oblock), ap->hash_bits);
	struct hlist_head *bucket = ap->table + h;
	struct entry *e;

	hlist_for_each_entry(e, bucket, hlist)
		if (e->oblock == oblock) {
			hlist_del(&e->hlist);
			hlist_add_head(&e->hlist, bucket);
			return e;
		}

	return NULL;
}

static void hash_remove(struct entry *e)
{
	hlist_del(&e->hlist);
}

/*----------------------------------------------------------------*/

static bool in_cache(struct always_promote_policy *ap, struct entry *e)
{
	return in_pool(&ap->cache_pool, e);
}

/*
 * Inserts the entry into the pre_cache or the cache.  Ensures the cache
 * block is marked as allocated if necc.  Inserts into the hash table.
 * Sets the tick which records when the entry was last moved about.
 */
static void push(struct always_promote_policy *ap, struct entry *e)
{
	hash_insert(ap, e);
	queue_push(e->dirty ? &ap->cache_dirty : &ap->cache_clean,
		   &e->list);
}

/*
 * Removes an entry from pre_cache or cache.  Removes from the hash table.
 */
static void del(struct always_promote_policy *ap, struct entry *e)
{
	queue_remove(e->dirty ? &ap->cache_dirty : &ap->cache_clean, &e->list);
	hash_remove(e);
}

/*
 * Like del, except it removes the first entry in the queue (ie. the least
 * recently used).
 */
static struct entry *pop(struct always_promote_policy *ap, struct queue *q)
{
	struct entry *e;
	struct list_head *h = queue_pop(q);

	if (!h)
		return NULL;

	e = container_of(h, struct entry, list);
	hash_remove(e);

	return e;
}

static struct entry *peek(struct queue *q)
{
	struct list_head *h = queue_peek(q);
	return h ? container_of(h, struct entry, list) : NULL;
}

static void requeue(struct always_promote_policy *ap, struct entry *e)
{
	del(ap, e);
	push(ap, e);
}

static int demote_cblock(struct always_promote_policy *ap,
			 struct policy_locker *locker, dm_oblock_t *oblock)
{
	struct entry *demoted = peek(&ap->cache_clean);

	if (!demoted)
		/*
		 * We could get a block from ap->cache_dirty, but that
		 * would add extra latency to the triggering bio as it
		 * waits for the writeback.  Better to not promote this
		 * time and hope there's a clean block next time this block
		 * is hit.
		 */
		return -ENOSPC;

	if (locker->fn(locker, demoted->oblock))
		/*
		 * We couldn't lock the demoted block.
		 */
		return -EBUSY;

	del(ap, demoted);
	*oblock = demoted->oblock;
	free_entry(&ap->cache_pool, demoted);

	/*
	 * We used to put the demoted block into the pre-cache, but I think
	 * it's simpler to just let it work it's way up from zero again.
	 * Stops blocks flickering in and out of the cache.
	 */

	return 0;
}

static void cache_entry_found(struct always_promote_policy *ap,
			      struct entry *e,
			      struct policy_result *result)
{
	requeue(ap, e);
	result->op = POLICY_HIT;
	result->cblock = infer_cblock(&ap->cache_pool, e);
}

static void insert_in_cache(struct always_promote_policy *ap, dm_oblock_t oblock,
			    struct policy_locker *locker,
			    struct policy_result *result)
{
	int r;
	struct entry *e;

	if (epool_empty(&ap->cache_pool)) {
		result->op = POLICY_REPLACE;
		r = demote_cblock(ap, locker, &result->old_oblock);
		if (unlikely(r)) {
			result->op = POLICY_MISS;
			return;
		}

		/*
		 * This will always succeed, since we've just demoted.
		 */
		e = alloc_entry(&ap->cache_pool);
		BUG_ON(!e);

	} else {
		e = alloc_entry(&ap->cache_pool);
		result->op = POLICY_NEW;
	}

	e->oblock = oblock;
	e->dirty = false;
	push(ap, e);

	result->cblock = infer_cblock(&ap->cache_pool, e);
}

static int no_entry_found(struct always_promote_policy *ap, dm_oblock_t oblock,
			  bool can_migrate, bool discarded_oblock,
			  int data_dir, struct policy_locker *locker,
			  struct policy_result *result)
{
	if (can_migrate) {
		insert_in_cache(ap, oblock, locker, result);
		return 0;
	} else
		return -EWOULDBLOCK;
}

/*
 * Looks the oblock up in the hash table, then decides whether to put in
 * pre_cache, or cache etc.
 */
static int map(struct always_promote_policy *ap, dm_oblock_t oblock,
	       bool can_migrate, bool discarded_oblock,
	       int data_dir, struct policy_locker *locker,
	       struct policy_result *result)
{
	int r = 0;
	struct entry *e = hash_lookup(ap, oblock);

	if (e)
		cache_entry_found(ap, e, result);

	else
		r = no_entry_found(ap, oblock, can_migrate, discarded_oblock,
				   data_dir, locker, result);

	if (r == -EWOULDBLOCK)
		result->op = POLICY_MISS;

	return r;
}

/*----------------------------------------------------------------*/

/*
 * Public interface, via the policy struct.  See dm-cache-policy.h for a
 * description of these.
 */

static struct always_promote_policy *to_ap_policy(struct dm_cache_policy *p)
{
	return container_of(p, struct always_promote_policy, policy);
}

static void ap_destroy(struct dm_cache_policy *p)
{
	struct always_promote_policy *ap = to_ap_policy(p);

	vfree(ap->table);
	epool_exit(&ap->cache_pool);
	kfree(ap);
}

static int ap_map(struct dm_cache_policy *p, dm_oblock_t oblock,
		  bool can_block, bool can_migrate, bool discarded_oblock,
		  struct bio *bio, struct policy_locker *locker,
		  struct policy_result *result)
{
	int r;
	struct always_promote_policy *ap = to_ap_policy(p);

	result->op = POLICY_MISS;

	if (can_block)
		mutex_lock(&ap->lock);
	else if (!mutex_trylock(&ap->lock))
		return -EWOULDBLOCK;

	r = map(ap, oblock, can_migrate, discarded_oblock,
		bio_data_dir(bio), locker, result);

	mutex_unlock(&ap->lock);

	return r;
}

static int ap_lookup(struct dm_cache_policy *p, dm_oblock_t oblock, dm_cblock_t *cblock)
{
	int r;
	struct always_promote_policy *ap = to_ap_policy(p);
	struct entry *e;

	if (!mutex_trylock(&ap->lock))
		return -EWOULDBLOCK;

	e = hash_lookup(ap, oblock);
	if (e) {
		*cblock = infer_cblock(&ap->cache_pool, e);
		r = 0;
	} else
		r = -ENOENT;

	mutex_unlock(&ap->lock);

	return r;
}

static void __ap_set_clear_dirty(struct always_promote_policy *ap, dm_oblock_t oblock, bool set)
{
	struct entry *e;

	e = hash_lookup(ap, oblock);
	BUG_ON(!e);

	del(ap, e);
	e->dirty = set;
	push(ap, e);
}

static void ap_set_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	struct always_promote_policy *ap = to_ap_policy(p);

	mutex_lock(&ap->lock);
	__ap_set_clear_dirty(ap, oblock, true);
	mutex_unlock(&ap->lock);
}

static void ap_clear_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	struct always_promote_policy *ap = to_ap_policy(p);

	mutex_lock(&ap->lock);
	__ap_set_clear_dirty(ap, oblock, false);
	mutex_unlock(&ap->lock);
}

static int ap_load_mapping(struct dm_cache_policy *p,
			   dm_oblock_t oblock, dm_cblock_t cblock,
			   uint32_t hint, bool hint_valid)
{
	struct always_promote_policy *ap = to_ap_policy(p);
	struct entry *e;

	e = alloc_particular_entry(&ap->cache_pool, cblock);
	e->oblock = oblock;
	e->dirty = false;	/* this gets corrected in a minute */
	push(ap, e);

	return 0;
}

static int ap_save_hints(struct always_promote_policy *ap, struct queue *q,
			 policy_walk_fn fn, void *context)
{
	int r;
	struct list_head *h;
	struct entry *e;

	list_for_each(h, &q->lru) {
		e = container_of(h, struct entry, list);
		r = fn(context, infer_cblock(&ap->cache_pool, e),
		       e->oblock, 0);

		if (r)
			return r;
	}

	return 0;
}

static int ap_walk_mappings(struct dm_cache_policy *p, policy_walk_fn fn,
			    void *context)
{
	struct always_promote_policy *ap = to_ap_policy(p);
	int r = 0;

	mutex_lock(&ap->lock);

	r = ap_save_hints(ap, &ap->cache_clean, fn, context);
	if (!r)
		r = ap_save_hints(ap, &ap->cache_dirty, fn, context);

	mutex_unlock(&ap->lock);

	return r;
}

static void __remove_mapping(struct always_promote_policy *ap, dm_oblock_t oblock)
{
	struct entry *e;

	e = hash_lookup(ap, oblock);
	BUG_ON(!e);

	del(ap, e);
	free_entry(&ap->cache_pool, e);
}

static void ap_remove_mapping(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	struct always_promote_policy *ap = to_ap_policy(p);

	mutex_lock(&ap->lock);
	__remove_mapping(ap, oblock);
	mutex_unlock(&ap->lock);
}

static int __remove_cblock(struct always_promote_policy *ap, dm_cblock_t cblock)
{
	struct entry *e = epool_find(&ap->cache_pool, cblock);

	if (!e)
		return -ENODATA;

	del(ap, e);
	free_entry(&ap->cache_pool, e);

	return 0;
}

static int ap_remove_cblock(struct dm_cache_policy *p, dm_cblock_t cblock)
{
	int r;
	struct always_promote_policy *ap = to_ap_policy(p);

	mutex_lock(&ap->lock);
	r = __remove_cblock(ap, cblock);
	mutex_unlock(&ap->lock);

	return r;
}

static int __ap_writeback_work(struct always_promote_policy *ap, dm_oblock_t *oblock,
			      dm_cblock_t *cblock)
{
	struct entry *e = pop(ap, &ap->cache_dirty);
	if (!e)
		return -ENODATA;

	*oblock = e->oblock;
	*cblock = infer_cblock(&ap->cache_pool, e);
	e->dirty = false;
	push(ap, e);

	return 0;
}

static int ap_writeback_work(struct dm_cache_policy *p, dm_oblock_t *oblock,
			     dm_cblock_t *cblock, bool critical_only)
{
	int r;
	struct always_promote_policy *ap = to_ap_policy(p);

	mutex_lock(&ap->lock);
	r = __ap_writeback_work(ap, oblock, cblock);
	mutex_unlock(&ap->lock);

	return r;
}

static void __force_mapping(struct always_promote_policy *ap,
			    dm_oblock_t current_oblock, dm_oblock_t new_oblock)
{
	struct entry *e = hash_lookup(ap, current_oblock);

	if (e && in_cache(ap, e)) {
		del(ap, e);
		e->oblock = new_oblock;
		e->dirty = true;
		push(ap, e);
	}
}

static void ap_force_mapping(struct dm_cache_policy *p,
			     dm_oblock_t current_oblock, dm_oblock_t new_oblock)
{
	struct always_promote_policy *ap = to_ap_policy(p);

	mutex_lock(&ap->lock);
	__force_mapping(ap, current_oblock, new_oblock);
	mutex_unlock(&ap->lock);
}

static dm_cblock_t ap_residency(struct dm_cache_policy *p)
{
	dm_cblock_t r;
	struct always_promote_policy *ap = to_ap_policy(p);

	mutex_lock(&ap->lock);
	r = to_cblock(ap->cache_pool.nr_allocated);
	mutex_unlock(&ap->lock);

	return r;
}

static void ap_tick(struct dm_cache_policy *p, bool can_block)
{
}

static int ap_set_config_value(struct dm_cache_policy *p,
			       const char *key, const char *value)
{
	return -EINVAL;
}

static int ap_emit_config_values(struct dm_cache_policy *p, char *result,
				 unsigned maxlen, ssize_t *sz_ptr)
{
	ssize_t sz = *sz_ptr;

	DMEMIT("0 ");

	*sz_ptr = sz;
	return 0;
}

/* Init the policy plugin interface function pointers. */
static void init_policy_functions(struct always_promote_policy *ap)
{
	ap->policy.destroy = ap_destroy;
	ap->policy.map = ap_map;
	ap->policy.lookup = ap_lookup;
	ap->policy.set_dirty = ap_set_dirty;
	ap->policy.clear_dirty = ap_clear_dirty;
	ap->policy.load_mapping = ap_load_mapping;
	ap->policy.walk_mappings = ap_walk_mappings;
	ap->policy.remove_mapping = ap_remove_mapping;
	ap->policy.remove_cblock = ap_remove_cblock;
	ap->policy.writeback_work = ap_writeback_work;
	ap->policy.force_mapping = ap_force_mapping;
	ap->policy.residency = ap_residency;
	ap->policy.tick = ap_tick;
	ap->policy.emit_config_values = ap_emit_config_values;
	ap->policy.set_config_value = ap_set_config_value;
}

static struct dm_cache_policy *ap_create(dm_cblock_t cache_size,
					 sector_t origin_size,
					 sector_t cache_block_size)
{
	struct always_promote_policy *ap = kzalloc(sizeof(*ap), GFP_KERNEL);

	if (!ap)
		return NULL;

	init_policy_functions(ap);
	ap->cache_size = cache_size;

	if (epool_init(&ap->cache_pool, from_cblock(cache_size))) {
		DMERR("couldn't initialize pool of cache entries");
		goto bad_cache_init;
	}

	mutex_init(&ap->lock);
	queue_init(&ap->cache_clean);
	queue_init(&ap->cache_dirty);

	ap->nr_buckets = next_power(from_cblock(cache_size) / 2, 16);
	ap->hash_bits = ffs(ap->nr_buckets) - 1;
	ap->table = vzalloc(sizeof(*ap->table) * ap->nr_buckets);
	if (!ap->table)
		goto bad_alloc_table;

	return &ap->policy;

bad_alloc_table:
	epool_exit(&ap->cache_pool);
bad_cache_init:
	kfree(ap);

	return NULL;
}

/*----------------------------------------------------------------*/

static struct dm_cache_policy_type ap_policy_type = {
	.name = "always-promote",
	.version = {1, 4, 0},
	.hint_size = 4,
	.owner = THIS_MODULE,
	.create = ap_create
};

static int __init ap_init(void)
{
	int r;

	ap_entry_cache = kmem_cache_create("dm_ap_policy_cache_entry",
					   sizeof(struct entry),
					   __alignof__(struct entry),
					   0, NULL);
	if (!ap_entry_cache)
		return -ENOMEM;

	r = dm_cache_policy_register(&ap_policy_type);
	if (r) {
		DMERR("register failed %d", r);
		kmem_cache_destroy(ap_entry_cache);
		return -ENOMEM;
	}

	return 0;
}

static void __exit ap_exit(void)
{
	dm_cache_policy_unregister(&ap_policy_type);

	kmem_cache_destroy(ap_entry_cache);
}

module_init(ap_init);
module_exit(ap_exit);

MODULE_AUTHOR("Joe Thornber <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("always-promote cache policy");

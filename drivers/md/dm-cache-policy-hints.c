/*
 * Copyright (C) 2013 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 *
 * TESTING! NOT FOR PRODUCTION USE!
 *
 * "hints" policy to test variable hint size.
 */

#include "dm.h"
#include "dm-cache-policy.h"
#include "dm-cache-policy-internal.h"

#include <linux/hash.h>
#include <linux/list.h>
#include <linux/module.h>

#define DM_MSG_PREFIX "cache-policy-hints"

/*----------------------------------------------------------------*/

static struct kmem_cache *hints_entry_cache;

/*----------------------------------------------------------------*/

static unsigned next_power(unsigned n, unsigned min)
{
	return roundup_pow_of_two(max(n, min));
}

struct hash {
	struct hlist_head *table;
	dm_block_t hash_bits;
	unsigned nr_buckets;
};

struct entry {
	struct hlist_node hlist;
	struct list_head list;
	dm_oblock_t oblock;
	dm_cblock_t cblock;
};

#define	DEFAULT_HINT_SIZE DM_CACHE_POLICY_MAX_HINT_SIZE
struct policy {
	struct dm_cache_policy policy;
	struct mutex lock;

	sector_t origin_size, block_size;

	/* To optimize search in the allocation bitset */
	unsigned find_free_nr_words, find_free_last_word;
	unsigned long *allocation_bitset;

	dm_cblock_t nr_cblocks_allocated;
	dm_cblock_t cache_size;

	struct {
		struct list_head free; /* Free cache entry list */
		struct list_head used; /* Used cache entry list */
	} queues;

	/* The cache hash */
	struct hash chash;

	/* Flag to blog (re)setting hint_size via the message interface */
	bool hint_size_set;
};

/*----------------------------------------------------------------------------*/
/* Low-level queue function. */
static struct entry *queue_pop(struct list_head *q)
{
	struct list_head *elt;

	if (list_empty(q))
		return NULL;

	elt = q->next;
	list_del(elt);
	return list_entry(elt, struct entry, list);
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
static void __free_cache_entries(struct list_head *q) {
	struct entry *e;

	while ((e = queue_pop(q)))
		kmem_cache_free(hints_entry_cache, e);
}

static void free_cache_entries(struct policy *p)
{
	__free_cache_entries(&p->queues.free);
	__free_cache_entries(&p->queues.used);
}

static int alloc_cache_blocks_with_hash(struct policy *p, unsigned cache_size)
{
	int r = -ENOMEM;
	unsigned u = cache_size;

	p->nr_cblocks_allocated = to_cblock(0);

	while (u--) {
		struct entry *e = kmem_cache_zalloc(hints_entry_cache, GFP_KERNEL);

		if (!e)
			goto bad_cache_alloc;

		list_add(&e->list, &p->queues.free);
	}

	/* Cache entries hash. */
	r = alloc_hash(&p->chash, cache_size);
	if (r)
		goto bad_cache_alloc;

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

/*----------------------------------------------------------------------------*/
/* Low-level functions. */
static struct policy *to_policy(struct dm_cache_policy *p)
{
	return container_of(p, struct policy, policy);
}

/*----------------------------------------------------------------*/

static unsigned bit_set_nr_words(unsigned long nr_cblocks)
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
static struct entry *lookup_cache_entry(struct policy *p, dm_oblock_t oblock)
{
	struct hash *hash = &p->chash;
	unsigned h = hash_64(from_oblock(oblock), hash->hash_bits);
	struct entry *cur;
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

static void insert_cache_hash_entry(struct policy *p, struct entry *e)
{
	unsigned h = hash_64(from_oblock(e->oblock), p->chash.hash_bits);

	hlist_add_head(&e->hlist, &p->chash.table[h]);
}

static void remove_cache_hash_entry(struct policy *p, struct entry *e)
{
	hlist_del(&e->hlist);
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

static struct entry *alloc_cache_entry(struct policy *p)
{
	struct list_head *free = &p->queues.free;
	struct entry *e = queue_pop(free);

	if (e) {
		BUG_ON(from_cblock(p->nr_cblocks_allocated) >= from_cblock(p->cache_size));
		p->nr_cblocks_allocated = to_cblock(from_cblock(p->nr_cblocks_allocated) + 1);
	}

	return e;
}

static void alloc_cblock_and_insert_cache(struct policy *p, struct entry *e)
{
	alloc_cblock(p, e->cblock);
	insert_cache_hash_entry(p, e);
}

static void add_cache_entry(struct policy *p, struct entry *e)
{
	list_add_tail(&e->list, &p->queues.used);
	alloc_cblock_and_insert_cache(p, e);
}

static void remove_cache_entry(struct policy *p, struct entry *e)
{
	remove_cache_hash_entry(p, e);
	free_cblock(p, e->cblock);
}

static struct entry *evict_cache_entry(struct policy *p)
{
	struct entry *e = queue_pop(&p->queues.used);

	BUG_ON(!e);
	remove_cache_entry(p, e);

	return e;
}

static void get_cache_block(struct policy *p, dm_oblock_t oblock, struct bio *bio,
			    struct policy_result *result)
{
	struct entry *e = alloc_cache_entry(p);

	if (e) {
		BUG_ON(find_free_cblock(p, &e->cblock));
		result->op = POLICY_NEW;

	} else {
		e = evict_cache_entry(p);
		result->old_oblock = e->oblock;
		result->op = POLICY_REPLACE;
	}

	result->cblock = e->cblock;
	e->oblock = oblock;
	add_cache_entry(p, e);
}

static bool in_cache(struct policy *p, dm_oblock_t oblock, dm_cblock_t *cblock)
{
	struct entry *e = lookup_cache_entry(p, oblock);

	if (!e)
		return false;

	*cblock = e->cblock;
	return true;
}

/*----------------------------------------------------------------------------*/

/* Public interface (see dm-cache-policy.h */
static int hints_map(struct dm_cache_policy *pe, dm_oblock_t oblock,
		     bool can_block, bool can_migrate, bool discarded_oblock,
		     struct bio *bio, struct policy_result *result)
{
	int r = 0;
	struct policy *p = to_policy(pe);

	result->op = POLICY_MISS;

	if (can_block)
		mutex_lock(&p->lock);

	else if (!mutex_trylock(&p->lock))
		return -EWOULDBLOCK;


	if (in_cache(p, oblock, &result->cblock))
		result->op = POLICY_HIT;

	else if (!can_migrate)
		r = -EWOULDBLOCK;

	else
		get_cache_block(p, oblock, bio, result);

	mutex_unlock(&p->lock);

	return r;
}

static int hints_lookup(struct dm_cache_policy *pe, dm_oblock_t oblock, dm_cblock_t *cblock)
{
	int r;
	struct policy *p = to_policy(pe);

	if (!mutex_trylock(&p->lock))
		return -EWOULDBLOCK;

	if (!in_cache(p, oblock, cblock))
		r = -ENOENT;

	mutex_unlock(&p->lock);

	return r;
}

static void hints_destroy(struct dm_cache_policy *pe)
{
	struct policy *p = to_policy(pe);

	free_bitset(p->allocation_bitset);
	free_cache_blocks_and_hash(p);
	kfree(p);
}

static int hints_load_mapping(struct dm_cache_policy *pe,
			      dm_oblock_t oblock, dm_cblock_t cblock,
			      void *hint, bool hint_valid)
{
	struct policy *p = to_policy(pe);
	struct entry *e;
static unsigned c = 0;

	e = alloc_cache_entry(p);
	if (!e)
		return -ENOMEM;

	e->cblock = cblock;
	e->oblock = oblock;

#define	LLU long long unsigned
while (++c < 32)
	DMINFO("%s -- hint_valid=%u hint_size=%llu", __func__, hint_valid, (LLU) dm_cache_policy_get_hint_size(pe));

	if (hint_valid) {
		unsigned hint_size = dm_cache_policy_get_hint_size(pe) / 4;
		__le32 *le_hints = hint;
		uint32_t *ui_hints = hint;
DMINFO("%s -- hint_size=%u", __func__, hint_size);

		while (hint_size--) {
			ui_hints[hint_size] = le32_to_cpu(le_hints[hint_size]);
			WARN_ON(ui_hints[hint_size] != hint_size);
		}
	}

	alloc_cblock_and_insert_cache(p, e);

	return 0;
}

/* Walk mappings */
static int hints_walk_mappings(struct dm_cache_policy *pe, policy_walk_fn fn, void *context)
{
	int r = 0;
	unsigned hint_size = dm_cache_policy_get_hint_size(pe) / 4;
	__le32 hints[64];
	struct policy *p = to_policy(pe);
	struct entry *e;
static unsigned c = 0;

DMINFO_LIMIT("%s", __func__);
	while (hint_size--)
		hints[hint_size] = cpu_to_le32(hint_size + 1);

	mutex_lock(&p->lock);

	list_for_each_entry(e, &p->queues.used, list) {
while (++c < 32)
	DMINFO("%s -- cblock=%llu oblock=%llu", __func__, (LLU) from_cblock(e->cblock), (LLU) from_oblock(e->oblock));
		r = fn(context, e->cblock, e->oblock, (void*) &hints);
		if (r)
			break;
	}

	mutex_unlock(&p->lock);

	return r;
}

static struct entry *__hints_force_remove_mapping(struct policy *p,
							      dm_oblock_t oblock)
{
	struct entry *e = lookup_cache_entry(p, oblock);

	BUG_ON(!e);

	list_del(&e->list);
	remove_cache_entry(p, e);

	return e;
}

static void hints_remove_mapping(struct dm_cache_policy *pe, dm_oblock_t oblock)
{
	struct policy *p = to_policy(pe);
	struct entry *e;

	mutex_lock(&p->lock);
	e = __hints_force_remove_mapping(p, oblock);
	list_add_tail(&e->list, &p->queues.free);

	BUG_ON(!from_cblock(p->nr_cblocks_allocated));
	p->nr_cblocks_allocated = to_cblock(from_cblock(p->nr_cblocks_allocated) - 1);
	mutex_unlock(&p->lock);
}

static void hints_force_mapping(struct dm_cache_policy *pe,
				dm_oblock_t current_oblock, dm_oblock_t oblock)
{
	struct policy *p = to_policy(pe);
	struct entry *e;

	mutex_lock(&p->lock);

	e = __hints_force_remove_mapping(p, current_oblock);
	e->oblock = oblock;
	add_cache_entry(p, e);

	mutex_unlock(&p->lock);
}

static int hints_next_dirty_block(struct dm_cache_policy *pe, dm_oblock_t *oblock, dm_cblock_t *cblock)
{
	return -ENOENT;
}

static dm_cblock_t hints_residency(struct dm_cache_policy *pe)
{
	/* FIXME: lock mutex, not sure we can block here. */
	return to_policy(pe)->nr_cblocks_allocated;
}

static int hints_set_config_value(struct dm_cache_policy *pe,
				  const char *key, const char *value)
{
	if (!strcasecmp(key, "hint_size")) {
		struct policy *p = to_policy(pe);

		if (p->hint_size_set)
			return -EPERM;

		else {
			unsigned tmp;

			if (kstrtou32(value, 10, &tmp))
				return -EINVAL;

			else {
				int r = dm_cache_policy_set_hint_size(pe, tmp);

				if (!r)
					p->hint_size_set = true;
DMINFO("%s -- hint_size=%llu", __func__, (LLU) dm_cache_policy_get_hint_size(pe));
				return r;
			}
		}
	}

	return -EINVAL;
}

static int hints_emit_config_values(struct dm_cache_policy *pe, char *result, unsigned maxlen)
{
	ssize_t sz = 0;

	DMEMIT("hint_size %llu", (long long unsigned) dm_cache_policy_get_hint_size(pe));
	return 0;
}

/* Init the policy plugin interface function pointers. */
static void init_policy_functions(struct policy *p)
{
	p->policy.destroy = hints_destroy;
	p->policy.map = hints_map;
	p->policy.lookup = hints_lookup;
#if 0
	p->policy.set_dirty = NULL;
	p->policy.clear_dirty = NULL;
#endif
	p->policy.load_mapping = hints_load_mapping;
	p->policy.walk_mappings = hints_walk_mappings;
	p->policy.remove_mapping = hints_remove_mapping;
	p->policy.writeback_work = NULL;
	p->policy.next_dirty_block = hints_next_dirty_block;
	p->policy.force_mapping = hints_force_mapping;
	p->policy.residency = hints_residency;
	p->policy.tick = NULL;
	p->policy.emit_config_values = hints_emit_config_values;
	p->policy.set_config_value = hints_set_config_value;
}

static struct dm_cache_policy *hints_policy_create(dm_cblock_t cache_size,
						   sector_t origin_size,
						   sector_t block_size)
{
	int r;
	struct policy *p = kzalloc(sizeof(*p), GFP_KERNEL);

	if (!p)
		return NULL;

	init_policy_functions(p);

	p->cache_size = cache_size;
	p->find_free_nr_words = bit_set_nr_words(from_cblock(cache_size));
	p->find_free_last_word = 0;
	p->block_size = block_size;
	p->origin_size = origin_size;
	mutex_init(&p->lock);
	INIT_LIST_HEAD(&p->queues.free);
	INIT_LIST_HEAD(&p->queues.used);

	/* Allocate cache entry structs and add them to free list. */
	r = alloc_cache_blocks_with_hash(p, from_cblock(cache_size));
	if (r)
		goto bad_free_policy;

	/* Cache allocation bitset. */
	p->allocation_bitset = alloc_bitset(from_cblock(cache_size));
	if (!p->allocation_bitset)
		goto bad_free_cache_blocks_and_hash;

	p->hint_size_set = false;

	return &p->policy;

bad_free_cache_blocks_and_hash:
	free_cache_blocks_and_hash(p);
bad_free_policy:
	kfree(p);

	return NULL;
}

/*----------------------------------------------------------------------------*/
static struct dm_cache_policy_type hints_policy_type = {
	.name = "hints",
	.version = {1, 0, 0},
	.hint_size = 4, // DEFAULT_HINT_SIZE,
	.owner = THIS_MODULE,
	.create = hints_policy_create
};

static int __init hints_init(void)
{
	int r = -ENOMEM;

	hints_entry_cache = kmem_cache_create("dm_hints_policy_cache_entry",
					      sizeof(struct entry),
					      __alignof__(struct entry),
					      0, NULL);
	if (hints_entry_cache) {
		r = dm_cache_policy_register(&hints_policy_type);
		if (r)
			kmem_cache_destroy(hints_entry_cache);

		else {
			DMINFO("version %u.%u.%u loaded",
			       hints_policy_type.version[0],
			       hints_policy_type.version[1],
			       hints_policy_type.version[2]);
		}
	}

	return r;
}

static void __exit hints_exit(void)
{
	dm_cache_policy_unregister(&hints_policy_type);
	kmem_cache_destroy(hints_entry_cache);
}

module_init(hints_init);
module_exit(hints_exit);

MODULE_AUTHOR("Heinz Mauelshagen <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("hint size test cache policy");

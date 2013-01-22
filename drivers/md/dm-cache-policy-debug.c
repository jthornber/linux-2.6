/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * Debug module for cache replacement policies.
 *
 * Load with "{policy=$Name {verbose=N}". Name=mq, fifo, ... verbose=0..7
 * with flags 1: residency, 2: policy, 4: more policy
 *
 * This file is released under the GPL.
 */

#include "dm-cache-policy.h"
#include "dm-cache-policy-internal.h"
#include "dm.h"

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/hash.h>

#define	DM_MSG_PREFIX	"dm-cache-debug"

#define	LLU	long long unsigned

static struct kmem_cache *debug_block_cache;

/*----------------------------------------------------------------*/

/* Module parameters to select replacement policy to debug and verbosity. */
static struct {
	char *policy_name;
	unsigned verbose;
} modparms = {
	"basic",
	0
};

struct hash {
	struct hlist_head *table;
	dm_block_t hash_bits;
	unsigned nr_buckets;
};

struct debug_entry {
	struct hlist_node ohlist, chlist;
	struct list_head list;
	dm_oblock_t oblock;
	dm_cblock_t cblock;
	enum policy_operation op;
};

struct good_state_counts {
	unsigned hit, map_miss, miss, new, replace, op, cblock, load, remove, force, residency;
};

struct bad_state_counts {
	unsigned hit, map_miss, miss, new, replace, op, cblock, load, remove, force, residency_larger, residency_invalid;
};

struct policy {
	struct dm_cache_policy policy;
	struct mutex lock;

	struct dm_cache_policy *debug_policy;
	struct list_head free, used;
	struct hash ohash, chash;
	dm_oblock_t origin_blocks;
	dm_cblock_t cache_blocks;
	unsigned nr_dblocks_allocated, analysed, hit;
	struct good_state_counts good;
	struct bad_state_counts bad;
};

/*----------------------------------------------------------------------------*/
/* Low-level functions. */
static struct policy *to_policy(struct dm_cache_policy *pe)
{
	return container_of(pe, struct policy, policy);
}

static unsigned next_power(unsigned n, unsigned min)
{
	return roundup_pow_of_two(max(n, min));
}

static bool test_ok(struct policy *p)
{
	struct bad_state_counts *b = &p->bad;

	return b->hit + b->miss + b->new + b->replace + b->op + b->cblock + b->load + b->remove + b->force + b->residency_larger + b->residency_invalid > 0 ? false : true;
}

/*----------------------------------------------------------------------------*/

static struct list_head *list_pop(struct list_head *lh)
{
	struct list_head *r = lh->next;

	BUG_ON(!r);
	list_del_init(r);

	return r;
}

/*----------------------------------------------------------------------------*/

/* Hash functions (lookup, insert, remove). */

/* To create lookup_debug_entry_by_cache_block() and lookup_debug_entry_by_origin_block() */
#define LOOKUP(type, longtype) \
static struct debug_entry *lookup_debug_entry_by_ ## longtype ## _block(struct policy *p, dm_ ## type ## block_t type ## block) \
{ \
	unsigned h = hash_64(from_ ## type ## block(type ## block), p->type ## hash.hash_bits); \
	struct debug_entry *cur; \
	struct hlist_node *tmp; \
	struct hlist_head *bucket = p->type ## hash.table + h; \
\
	hlist_for_each_entry(cur, tmp, bucket, type ## hlist) { \
		if (cur->type ## block == type ## block) { \
			/* Move upfront bucket for faster access. */ \
			hlist_del(&cur->type ## hlist); \
			hlist_add_head(&cur->type ## hlist, bucket); \
			return cur; \
		} \
	} \
\
	return NULL; \
}

LOOKUP(o, origin);
LOOKUP(c, cache);
#undef LOOKUP

static void insert_origin_hash_entry(struct policy *p, struct debug_entry *e)
{
	unsigned h = hash_64(from_oblock(e->oblock), p->ohash.hash_bits);

	hlist_add_head(&e->ohlist, p->ohash.table + h);
}

static void insert_cache_hash_entry(struct policy *p, struct debug_entry *e)
{
	if (from_cblock(e->cblock) < from_cblock(p->cache_blocks)) {
		unsigned h = hash_64(from_cblock(e->cblock), p->chash.hash_bits);

		hlist_add_head(&e->chlist, p->chash.table + h);
	}
}

static void remove_origin_hash_entry(struct policy *p, struct debug_entry *e)
{
	hlist_del(&e->ohlist);
}

static void remove_cache_hash_entry(struct policy *p, struct debug_entry *e)
{
	if (from_cblock(e->cblock) < from_cblock(p->cache_blocks))
		hlist_del(&e->chlist);
}

/*----------------------------------------------------------------------------*/

/* Allocate/free hashs and debug blocks. */
static int alloc_hash(struct hash *hash, unsigned elts)
{
	hash->nr_buckets = next_power(elts >> 5, 16);
	hash->hash_bits = ffs(hash->nr_buckets) - 1;
	hash->table = vzalloc(sizeof(*hash->table) * hash->nr_buckets);

	return hash->table ? 0 : -ENOMEM;
}

static void free_hash(struct hash *hash)
{
	vfree(hash->table);
}

static void free_dblocks(struct policy *p)
{
	struct debug_entry *e, *tmp;

	list_splice_init(&p->used, &p->free);
	list_for_each_entry_safe(e, tmp, &p->free, list)
		kmem_cache_free(debug_block_cache, e);
}

static int alloc_debug_blocks_and_hashs(struct policy *p, dm_oblock_t origin_blocks, dm_cblock_t cache_blocks)
{
	int r = -ENOMEM;
	dm_block_t u;
	struct debug_entry *e;

	INIT_LIST_HEAD(&p->free);
	INIT_LIST_HEAD(&p->used);

	p->nr_dblocks_allocated = 0;

	/* FIXME: if we'ld avoid POLICY_MISS checks, we wouldn't need that many. */
	u = from_oblock(origin_blocks);
	while (u--) {
		/* FIXME: use slab. */
		e = kmem_cache_alloc(debug_block_cache, GFP_KERNEL);
		if (!e)
			goto bad_kmem_cache_alloc;

		list_add(&e->list, &p->free);
	}

	/* Cache entries by oblock hash. */
	r = alloc_hash(&p->ohash, from_oblock(origin_blocks));
	if (r)
		goto bad_alloc_origin_hash;

	/* Cache entries by cblock hash. */
	r = alloc_hash(&p->chash, from_cblock(cache_blocks));
	if (!r)
		return 0;

	free_hash(&p->ohash);
bad_alloc_origin_hash:
bad_kmem_cache_alloc:
	free_dblocks(p);

	return r;
}

static void free_debug_blocks_and_hashs(struct policy *p)
{
	free_hash(&p->chash);
	free_hash(&p->ohash);
	free_dblocks(p);
}

static void free_debug_entry(struct policy *p, struct debug_entry *e)
{
	BUG_ON(!e);
	remove_origin_hash_entry(p, e);
	remove_cache_hash_entry(p, e);
	e->oblock = 0;
	e->cblock = 0;
	e->op = 0;
	BUG_ON(list_empty(&e->list));
	list_move_tail(&e->list, &p->free);
	p->nr_dblocks_allocated--;
}

static struct debug_entry *alloc_and_add_debug_entry(struct policy *p, dm_oblock_t oblock, dm_cblock_t cblock)
{
	struct debug_entry *e = list_entry(list_pop(&p->free), struct debug_entry, list);

	e->oblock = oblock;
	e->cblock = cblock;
	e->op = 0;
	insert_origin_hash_entry(p, e);
	insert_cache_hash_entry(p, e);
	list_add(&e->list, &p->used);
	p->nr_dblocks_allocated++;

	return e;
}
/*----------------------------------------------------------------------------*/

static void check_op(char *name, enum policy_operation op)
{
	if (modparms.verbose & 0x4) {
		if (op == POLICY_HIT)
			DMWARN("%s: previous op POLICY_HIT invalid!", name);

		else if (op == POLICY_NEW)
			DMWARN("%s: previous op POLICY_NEW invalid!", name);

		else if (op == POLICY_REPLACE)
			DMWARN("%s: previous op POLICY_REPLACE invalid!", name);
	}
}

static struct debug_entry *analyse_map_result(struct policy *p, dm_oblock_t oblock,
					      int map_ret, struct policy_result *result)
{
	bool cblock_ok = true;
	struct debug_entry *ec = from_cblock(result->cblock) < from_cblock(p->cache_blocks) ?
		lookup_debug_entry_by_cache_block(p, result->cblock) : NULL;
	struct debug_entry *eo = lookup_debug_entry_by_origin_block(p, oblock);

	p->good.op++;

	/* target map thread caller may result in this. */
	if (map_ret == -EWOULDBLOCK) {
		if (result->op != POLICY_MISS) {
			if (modparms.verbose & 0x2)
				DMWARN("-EWOULDBLOCK: op=%u != POLICY_MISS invalid!", eo->op);

			p->bad.map_miss++;

		} else
			p->good.map_miss++;

		return NULL;
	}

	switch (result->op) {
	case POLICY_HIT:
		/* POLICY_HIT, POLICY_NEW, POLICY_REPLACE -> POLICY_HIT ok. */
		/* POLICY_MISS -> POLICY_HIT FALSE. */
		if (eo) {
			if (from_cblock(eo->cblock) != from_cblock(result->cblock)) {
				if (modparms.verbose & 0x2)
					DMWARN("POLICY_HIT: e->oblock=%llu e->cblock=%u != result->cblock=%u invalid!",
					       from_oblock(eo->oblock),
					       from_cblock(eo->cblock),
					       from_cblock(result->cblock));

				p->bad.cblock++;

			} else
				p->good.cblock++;

			if (eo->op == POLICY_MISS) {
				if (modparms.verbose & 0x2)
					DMWARN("POLICY_HIT: following POLICY_MISS invalid!");

				p->bad.hit++;

			} else
				p->good.hit++;
		}

		break;

	case POLICY_NEW:
		/* POLICY_MISS -> POLICY_NEW ok */
		/* POLICY_HIT, POLICY_NEW, POLICY_REPLACE -> POLICY_NEW FALSE. */
		if (ec) {
			if (modparms.verbose & 0x2)
				DMWARN("POLICY_NEW: oblock=%llu e->cblock=%u already existing invalid!", from_oblock(oblock), from_cblock(ec->cblock));

			check_op("POLICY_NEW", ec->op);
			free_debug_entry(p, ec);
			ec = eo = NULL;
			p->bad.new++;

		} else
			p->good.new++;


		if (eo) {
			free_debug_entry(p, eo);
			ec = eo = NULL;
		}

		break;

	case POLICY_REPLACE:
		/* POLICY_MISS -> POLICY_REPLACE ok */
		/* POLICY_HIT, POLICY_NEW, POLICY_REPLACE -> POLICY_REPLACE FALSE. */
		if (eo) {
			if (from_oblock(result->old_oblock) == from_oblock(oblock)) {
				if (modparms.verbose & 0x2)
					DMWARN("POLICY_REPLACE: e->cblock=%u e->oblock=%llu = result->old_block=%llu invalid!",
					       from_cblock(eo->cblock),
					       (LLU) from_oblock(eo->oblock),
					       (LLU) from_oblock(result->old_oblock));

				p->bad.replace++;

			} else
				p->good.replace++;

			check_op("POLICY_REPLACE", eo->op);
			free_debug_entry(p, eo);
			ec = eo = NULL;
		}

		break;

	case POLICY_MISS:
		/* POLICY_MISS -> POLICY_MISS ok. */
		/* POLICY_HIT, POLICY_NEW, POLICY_REPLACE -> POLICY_MISS FALSE. */
		if (eo) {
			check_op("POLICY_MISS", eo->op);

			if (eo->op != POLICY_MISS) {
				if (modparms.verbose & 0x2)
					DMWARN("POLICY_MISS: op=%u != POLICY_MISS invalid!", eo->op);

				p->bad.miss++;
			}

		} else
			p->good.miss++;

		cblock_ok = false;
		break;

	default:
		if (modparms.verbose > 1)
			DMWARN("Invalid op code %u", result->op);

		cblock_ok = false;
		p->good.op--;
		p->bad.op++;
	}

	eo = eo ? eo : alloc_and_add_debug_entry(p, oblock, cblock_ok ? result->cblock : p->cache_blocks);
	eo->op = result->op; /* Memorize op for next analysis cycle. */
	p->analysed++;

	return eo;
}

static void log_stats(struct policy *p)
{
	if (++p->hit > (from_cblock(p->cache_blocks) << 1)) {
		p->hit = 0;
		DMINFO("%s nr_dblocks_allocated/analysed = %u/%u good/bad hit=%u/%u,miss=%u/%u,map_miss=%u/%u,new=%u/%u,replace=%u/%u,op=%u/%u,"
		       "cblock=%u/%u,load=%u/%u,remove=%u/%u,force=%u/%u residency ok/larger/invalid=%u/%u/%u",
		       modparms.policy_name, p->nr_dblocks_allocated, p->analysed,
		       p->good.hit, p->bad.hit, p->good.miss, p->bad.miss, p->good.map_miss, p->bad.map_miss, p->good.new, p->bad.new,
		       p->good.replace, p->bad.replace, p->good.op, p->bad.op, p->good.cblock, p->bad.cblock,
		       p->good.load, p->bad.load, p->good.remove, p->bad.remove, p->good.force, p->bad.force,
		       p->good.residency, p->bad.residency_larger, p->bad.residency_invalid);
	}
}

/* Public interface (see dm-cache-policy.h */
static int debug_map(struct dm_cache_policy *pe, dm_oblock_t oblock,
		     bool can_block, bool can_migrate, bool discarded_oblock,
		     struct bio *bio, struct policy_result *result)
{
	int r;
	struct policy *p = to_policy(pe);
	struct debug_entry *e;

	result->op = POLICY_MISS;

	if (can_block)
		mutex_lock(&p->lock);

	else if (!mutex_trylock(&p->lock))
		return -EWOULDBLOCK;

	r = policy_map(p->debug_policy, oblock, can_block, can_migrate,
		       discarded_oblock, bio, result);
	e = analyse_map_result(p, oblock, r, result);
	log_stats(p);
	mutex_unlock(&p->lock);

	return r;
}

static int debug_lookup(struct dm_cache_policy *pe, dm_oblock_t oblock, dm_cblock_t *cblock)
{
	int r;
	struct policy *p = to_policy(pe);
	struct debug_entry *ec = NULL;

	if (!mutex_trylock(&p->lock))
		return -EWOULDBLOCK;

	r = policy_lookup(p->debug_policy, oblock, cblock);
	if (!r)
		ec = lookup_debug_entry_by_cache_block(p, *cblock);

	mutex_unlock(&p->lock);

	if (r) {
		switch (r) {
		case -ENOENT:
		case -EWOULDBLOCK:
			break;

		default:
			DMWARN("Invalid lookup code %u", r);
		}

	} else if (ec) {
		if (*cblock != ec->cblock)
			DMWARN("lookup returned invalid cblock=%llu; %llu expected!", (LLU) from_cblock(*cblock), (LLU) from_cblock(ec->cblock));

	} else
			DMWARN("lookup returned non-existing cblock=%llu!", (LLU) from_cblock(*cblock));

	return r;
}

static void debug_destroy(struct dm_cache_policy *pe)
{
	struct policy *p = to_policy(pe);

	p->hit = ~0 - 1; /* - 1 due to ++ in log_stats() */
	log_stats(p);

	DMINFO("Test %s", test_ok(p) ? "ok" : "FAILED");

	dm_cache_policy_destroy(p->debug_policy);
	free_debug_blocks_and_hashs(p);
	kfree(p);
}

static int debug_load_mapping(struct dm_cache_policy *pe,
			      dm_oblock_t oblock, dm_cblock_t cblock,
			      uint32_t hint, bool hint_valid)
{
	int r;
	struct policy *p = to_policy(pe);
	struct debug_entry *eo, *ec;

	mutex_lock(&p->lock);
	eo = lookup_debug_entry_by_origin_block(p, oblock);
	ec = lookup_debug_entry_by_cache_block(p, cblock);
	if (eo || ec) {
		if (modparms.verbose & 0x2)
			DMWARN("Entry on load for oblock=%llu/cblock=%u already existing invalid!", (LLU) from_oblock(oblock), from_cblock(cblock));

		free_debug_entry(p, eo ? eo : ec);
		p->bad.load++;

	} else {
		alloc_and_add_debug_entry(p, oblock, cblock);
		p->good.load++;
	}

	r = policy_load_mapping(p->debug_policy, oblock, cblock, hint, hint_valid);
	mutex_unlock(&p->lock);

	return r;
}

static int debug_walk_mappings(struct dm_cache_policy *pe, policy_walk_fn fn, void *context)
{
	struct policy *p = to_policy(pe);

	return policy_walk_mappings(p->debug_policy, fn, context);
}

static void debug_remove_mapping(struct dm_cache_policy *pe, dm_oblock_t oblock)
{
	struct policy *p = to_policy(pe);
	struct debug_entry *e;

	mutex_lock(&p->lock);
	e = lookup_debug_entry_by_origin_block(p, oblock);
	if (e) {
		free_debug_entry(p, e);
		p->good.remove++;

	} else {
		if (modparms.verbose & 0x2)
			DMWARN("No entry on remove for oblock=%llu invalid!", (LLU) from_oblock(oblock));

		p->bad.remove++;
	}

	policy_remove_mapping(p->debug_policy, oblock);
	mutex_unlock(&p->lock);
}

static void debug_force_mapping(struct dm_cache_policy *pe,
				dm_oblock_t current_oblock, dm_oblock_t oblock)
{
	struct policy *p = to_policy(pe);
	struct debug_entry *e;

	mutex_lock(&p->lock);
	e = lookup_debug_entry_by_origin_block(p, current_oblock);
	if (e) {
		enum policy_operation op = e->op;
		dm_cblock_t cblock = e->cblock;

		/* Replace with new information .*/
		free_debug_entry(p, e);
		e = alloc_and_add_debug_entry(p, oblock, cblock);
		e->op = op;
		p->good.force++;

	} else {
		if (modparms.verbose & 0x2)
			DMWARN("No entry on force for current_oblock=%llu/oblock=%llu invalid!", (LLU) from_oblock(current_oblock), (LLU) from_oblock(oblock));

		p->bad.force++;
	}

	policy_force_mapping(p->debug_policy, current_oblock, oblock);
	mutex_unlock(&p->lock);
}

static int debug_writeback_work(struct dm_cache_policy *pe,
				dm_oblock_t *oblock,
				dm_cblock_t *cblock)
{
	int r;
	struct policy *p = to_policy(pe);

	r = policy_writeback_work(p->debug_policy, oblock, cblock);
	if (r) {
		if (r != -ENOENT)
			DMWARN("remove_any return code %d invalid!", r);

	} else {
		if (from_cblock(*cblock) >= from_cblock(p->cache_blocks))
			DMWARN("remove_any cbock=%u invalid!", from_cblock(*cblock));

		if (from_oblock(*oblock) >= from_oblock(p->origin_blocks))
			DMWARN("remove_any cbock=%llu invalid!", (LLU) from_oblock(*oblock));
	}

	return r;
}

static dm_cblock_t debug_residency(struct dm_cache_policy *pe)
{
	struct policy *p = to_policy(pe);
	bool ok = true;
	dm_cblock_t r = policy_residency(p->debug_policy);

	if (from_cblock(r) > from_cblock(p->cache_blocks)) {
		if (modparms.verbose & 0x1)
			DMWARN("Residency=%u claimed larger than cache size=%u!", from_cblock(r), from_cblock(p->cache_blocks));

		p->bad.residency_larger++;
		ok = false;
	}

	if (from_cblock(r) != p->good.new) {
		if (modparms.verbose & 0x1)
			DMWARN("Claimed residency=%u invalid vs. %u", from_cblock(r), p->nr_dblocks_allocated);

		p->bad.residency_invalid++;
		ok = false;
	}

	if (ok)
		p->good.residency++;

	return r;
}

static void debug_tick(struct dm_cache_policy *pe)
{
	policy_tick(to_policy(pe)->debug_policy);
}

static int debug_status(struct dm_cache_policy *pe, status_type_t type,
			unsigned status_flags, char *result, unsigned maxlen)
{
	return policy_status(to_policy(pe)->debug_policy, type, status_flags, result, maxlen);
}

static int debug_message(struct dm_cache_policy *pe, unsigned argc, char **argv)
{
	return policy_message(to_policy(pe)->debug_policy, argc, argv);
}

/* Init the policy plugin interface function pointers. */
static void init_policy_functions(struct policy *p)
{
	p->policy.destroy = debug_destroy;
	p->policy.map = debug_map;
	p->policy.lookup = debug_lookup;
	p->policy.load_mapping = debug_load_mapping;
	p->policy.walk_mappings = debug_walk_mappings;
	p->policy.remove_mapping = debug_remove_mapping;
	p->policy.force_mapping = debug_force_mapping;
	p->policy.writeback_work = debug_writeback_work;
	p->policy.residency = debug_residency;
	p->policy.tick = debug_tick;
	p->policy.status = debug_status;
	p->policy.message = debug_message;
}

static struct dm_cache_policy *debug_create(dm_cblock_t cache_blocks,
					    sector_t origin_sectors, sector_t block_sectors,
					    int argc, char **argv)
{
	int r;
	uint64_t origin_blocks = origin_sectors;
	struct policy *p = kzalloc(sizeof(*p), GFP_KERNEL);

	if (!p)
		return NULL;

	init_policy_functions(p);

	do_div(origin_blocks, block_sectors);
	p->cache_blocks = cache_blocks;
	p->origin_blocks = to_oblock(origin_blocks);
	mutex_init(&p->lock);

	DMWARN("debugging \"%s\" cache replacement policy", modparms.policy_name);
	p->debug_policy = dm_cache_policy_create(modparms.policy_name, cache_blocks,
						 origin_sectors, block_sectors,
						 argc, argv);
	if (!p->debug_policy)
		goto bad_dm_cache_policy_create;

	r = alloc_debug_blocks_and_hashs(p, from_oblock(origin_blocks), cache_blocks);
	if (r)
		goto bad_alloc_debug_blocks_and_hash;

	return &p->policy;

bad_alloc_debug_blocks_and_hash:
	DMWARN("blocks_and_hashs allocation failed");
	dm_cache_policy_destroy(p->debug_policy);
bad_dm_cache_policy_create:
	kfree(p);

	return NULL;
}
/*----------------------------------------------------------------------------*/

static struct dm_cache_policy_type debug_policy_type = {
	.name = "debug",
	.owner = THIS_MODULE,
	.create = debug_create
};

static int __init debug_init(void)
{
	int r;

	debug_block_cache = KMEM_CACHE(debug_entry, 0);
	if (!debug_block_cache)
		return -ENOMEM;

	r = dm_cache_policy_register(&debug_policy_type);
	if (r)
		kmem_cache_destroy(debug_block_cache);

	return r;
}

static void __exit debug_exit(void)
{
	kmem_cache_destroy(debug_block_cache);
	dm_cache_policy_unregister(&debug_policy_type);
}

module_init(debug_init);
module_exit(debug_exit);

module_param_named(policy, modparms.policy_name, charp, S_IWUSR);
MODULE_PARM_DESC(policy, "name of cache replacement policy to debug");
module_param_named(verbose, modparms.verbose, uint, S_IWUSR);
MODULE_PARM_DESC(verbose, "verbose state output");

MODULE_AUTHOR("Heinz Mauelshagen <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("debug module for cache replacement policies");

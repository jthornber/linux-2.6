/*
 * Copyright 2013 NetApp, Inc. All Rights Reserved, contribution by
 * Morgan Mears.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details
 *
 */

#include "dm-cache-policy.h"
#include "dm-cache-policy-internal.h"
#include "dm.h"

#include <linux/hash.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#define DM_MSG_PREFIX "cache-policy-mq-era"

typedef uint32_t era_t;
#define MQ_ERA_MAX_ERA UINT_MAX

struct mq_era_policy {
	struct dm_cache_policy policy;
	struct mutex lock;
	struct dm_cache_policy *mq;
	dm_cblock_t cache_size;
	era_t *cb_to_era;
	era_t era_counter;
};

/*----------------------------------------------------------------*/

static struct mq_era_policy *to_mq_era_policy(struct dm_cache_policy *p)
{
	return container_of(p, struct mq_era_policy, policy);
}

static int incr_era_counter(struct mq_era_policy *mq_era, const char *curr_era_counter_str)
{
	era_t curr_era_counter;
	int r;

	/*
	 * If the era counter value provided by the user matches the current
	 * counter value while under lock, increment the counter (intention
	 * is to prevent races).  Rollover problems are avoided by locking
	 * the counter at a maximum value (the application must take
	 * appropriate action on this error to preserve correction, but
	 * a properly behaved set of applications will never trigger it;
	 * the era counter is meant to increment less than once a second
	 * and is 32 bits.
	 */

	if (kstrtou32(curr_era_counter_str, 10, &curr_era_counter))
		return -EINVAL;

	mutex_lock(&mq_era->lock);

	if (mq_era->era_counter != curr_era_counter)
		r = -ECANCELED;
	else if (mq_era->era_counter >= MQ_ERA_MAX_ERA)
		r = -EOVERFLOW;
	else {
		mq_era->era_counter++;
		r = 0;
	}

	mutex_unlock(&mq_era->lock);

	return r;
}

struct nested_walk_ctx {
	policy_walk_fn parent_fn;
	void *parent_ctx;
	struct mq_era_policy *mq_era;
};

static int nested_walk(void *context, dm_cblock_t cblock, dm_oblock_t oblock, uint32_t hint)
{
	struct nested_walk_ctx *ctx = (struct nested_walk_ctx *)context;

	/*
	 * Inserted as a filter into walk_mappings so we can take additional
	 * actions in the shim.
	 */

	DMDEBUG("calling parent walk_mappings function for cblock %u, "
		"oblock %llu (era %u)", from_cblock(cblock), oblock,
		ctx->mq_era->cb_to_era[from_cblock(cblock)]);

	/*
	 * XXX need to consolidate the hint being provided by our caller (mq)
	 * with the hint we want to preserve (era) once the hint size
	 * restriction goes away.
	 */

	return (*ctx->parent_fn)(ctx->parent_ctx, cblock, oblock,
				 ctx->mq_era->cb_to_era[from_cblock(cblock)]);
}

static int era_is_gt_value(era_t era, era_t value)
{
	return era > value;
}

static int era_is_gte_value(era_t era, era_t value)
{
	return era >= value;
}

static int era_is_lte_value(era_t era, era_t value)
{
	return era <= value;
}

static int era_is_lt_value(era_t era, era_t value)
{
	return era < value;
}

typedef int (*era_match_fn_t)(era_t, era_t);

struct find_oblocks_ctx {
	struct mq_era_policy *mq_era;
	era_match_fn_t era_match_fn;
	era_t test_era;
	uint32_t matches;
	uint32_t next_ob_idx;
	dm_oblock_t *oblocks;
};

static int find_oblocks(void *context, dm_cblock_t cblock,
			dm_oblock_t oblock, uint32_t hint)
{
	struct find_oblocks_ctx *ctx = (struct find_oblocks_ctx *)context;
	era_t era;

	/*
	 * Assembles a list of oblocks that are currently in the cache and
	 * whose cblocks have eras that satisfy the given matching function
	 * (currently >, >=, <=, or <)
	 */

	if (ctx->next_ob_idx >= ctx->matches)
		return -EOVERFLOW;

	era = ctx->mq_era->cb_to_era[from_cblock(cblock)];
	if (ctx->era_match_fn(era, ctx->test_era)) {
		DMDEBUG("cblock %u has era %u matching test_era %u; "
			"recording oblock %llu at oblocks %u.",
			from_cblock(cblock), era, ctx->test_era,
			oblock, ctx->next_ob_idx);
		ctx->oblocks[ctx->next_ob_idx++] = oblock;
		ctx->mq_era->cb_to_era[from_cblock(cblock)] = 0;
	}

	return 0;
}

static int cond_unmap_by_era(struct mq_era_policy *mq_era,
			     const char *test_era_str,
			     era_match_fn_t era_match_fn)
{
	struct find_oblocks_ctx fo_ctx;
	uint32_t cb_idx, matches, ob_idx, max_cb_idx;
	era_t test_era;
	int r;

	/*
	 * Unmap blocks with eras matching the given era, according to the
	 * given matching function.
	 */

	if (kstrtou32(test_era_str, 10, &test_era))
		return -EINVAL;

	/*
	 * This is a little convoluted, but is not expected to be a common
	 * operation.
	 */

	mutex_lock(&mq_era->lock);

	/* While locked, count matches */
	max_cb_idx = from_cblock(mq_era->cache_size);
	for (matches = 0, cb_idx = 0; cb_idx < max_cb_idx; cb_idx++)
		if (era_match_fn(mq_era->cb_to_era[cb_idx], test_era))
			matches++;

	/* If there aren't any, we're done */
	if (matches == 0) {
		r = 0;
		goto out;
	}

	/* Set up to find the origin block for each matching cache block */
	fo_ctx.mq_era = mq_era;
	fo_ctx.era_match_fn = era_match_fn;
	fo_ctx.test_era = test_era;
	fo_ctx.matches = matches;
	fo_ctx.next_ob_idx = 0;
	fo_ctx.oblocks = kzalloc(sizeof(*fo_ctx.oblocks) * matches, GFP_KERNEL);
	if (!fo_ctx.oblocks) {
		r = -ENOMEM;
		goto out;
	}

	/* Go ahead and find the origins */
	r = mq_era->mq->walk_mappings(mq_era->mq, find_oblocks, &fo_ctx);
	if (r)
		goto free_and_out;

	/* Unmap each matching origin */
	for (ob_idx = 0; ob_idx < fo_ctx.next_ob_idx; ob_idx++) {
		DMDEBUG("removing mapping for oblock %llu.", fo_ctx.oblocks[ob_idx]);
		mq_era->mq->remove_mapping(mq_era->mq, fo_ctx.oblocks[ob_idx]);
	}

free_and_out:
	kfree(fo_ctx.oblocks);
out:
	mutex_unlock(&mq_era->lock);
	return r;
}

/*
 * Public interface, via the policy struct.  See dm-cache-policy.h for a
 * description of these.
 */

static void mq_era_destroy(struct dm_cache_policy *p)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	DMDEBUG("destroyed mq_era %p, mq %p.", mq_era, mq_era->mq);
	mq_era->mq->destroy(mq_era->mq);
	kfree(mq_era->cb_to_era);
	kfree(mq_era);
}

static int mq_era_map(struct dm_cache_policy *p, dm_oblock_t oblock,
		      bool can_block, bool can_migrate, bool discarded_oblock,
		      struct bio *bio, struct policy_result *result)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	uint32_t cb_idx;
	int r;

	result->op = POLICY_MISS;

	if (can_block)
		mutex_lock(&mq_era->lock);
	else if (!mutex_trylock(&mq_era->lock))
		return -EWOULDBLOCK;

	/* Check for a mapping */
	r = mq_era->mq->map(mq_era->mq, oblock, can_block, can_migrate,
			    discarded_oblock, bio, result);

	/* If we got a hit and this is a write, update the era for the block */
	if (!r && (bio_data_dir(bio) == WRITE) && (result->op == POLICY_HIT)) {
		cb_idx = from_cblock(result->cblock);
		BUG_ON(cb_idx >= from_cblock(mq_era->cache_size));
		/* XXX remove this */
		DMDEBUG("assigning era %u to cblock %u, oblock %llu due to write hit.",
			mq_era->era_counter, result->cblock, oblock);
		mq_era->cb_to_era[cb_idx] = mq_era->era_counter;
	}

	mutex_unlock(&mq_era->lock);

	return r;
}

static int mq_era_lookup(struct dm_cache_policy *p, dm_oblock_t oblock,
			 dm_cblock_t *cblock)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	return mq_era->mq->lookup(mq_era->mq, oblock, cblock);
}

static void mq_era_set_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	mq_era->mq->set_dirty(mq_era->mq, oblock);
}

static void mq_era_clear_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	mq_era->mq->clear_dirty(mq_era->mq, oblock);
}

static int mq_era_load_mapping(struct dm_cache_policy *p,
			       dm_oblock_t oblock, dm_cblock_t cblock,
			       uint32_t hint, bool hint_valid)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	int r;

	/*
	 * XXX need to consolidate the hint being provided by our caller (mq)
	 * with the hint we want to preserve (era) once the hint size
	 * restriction goes away.
	 */

	r = mq_era->mq->load_mapping(mq_era->mq, oblock, cblock, 0, 0);
	if (!r && hint_valid &&
	    (from_cblock(cblock) < from_cblock(mq_era->cache_size))) {
		DMDEBUG("recovered era %u for cblock %u.", hint, cblock);
		mq_era->cb_to_era[from_cblock(cblock)] = hint;
		/*
		 * Make sure the era counter starts higher than the highest
		 * persisted era.
		 */
		if (hint >= mq_era->era_counter) {
			mq_era->era_counter = hint;
			if (mq_era->era_counter < MQ_ERA_MAX_ERA)
				mq_era->era_counter++;
			DMDEBUG("set era_counter to %u.", mq_era->era_counter);
		}
	}

	return r;
}

static int mq_era_walk_mappings(struct dm_cache_policy *p, policy_walk_fn fn,
				void *context)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	struct nested_walk_ctx nested_walk_ctx = {
		.parent_fn = fn,
		.parent_ctx = context,
		.mq_era = mq_era
	};
	int r;

	/* XXX remove this */
	DMDEBUG("call to mq_era_walk_mappings");

	mutex_lock(&mq_era->lock);

	r = mq_era->mq->walk_mappings(mq_era->mq, nested_walk, &nested_walk_ctx);

	mutex_unlock(&mq_era->lock);

	return r;
}

static void mq_era_remove_mapping(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	dm_cblock_t cblock;

	mutex_lock(&mq_era->lock);

	if (!mq_era->mq->lookup(mq_era->mq, oblock, &cblock)) {
		DMDEBUG("zeroed era for cblock %u (oblock %llu) due to a call "
			"to remove_mapping.", cblock, oblock);
		mq_era->cb_to_era[from_cblock(cblock)] = 0;
	}

	mq_era->mq->remove_mapping(mq_era->mq, oblock);

	mutex_unlock(&mq_era->lock);
}

static int mq_era_writeback_work(struct dm_cache_policy *p, dm_oblock_t *oblock,
				 dm_cblock_t *cblock)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	return mq_era->mq->writeback_work(mq_era->mq, oblock, cblock);
}

static void mq_era_force_mapping(struct dm_cache_policy *p,
				 dm_oblock_t current_oblock,
				 dm_oblock_t new_oblock)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	dm_cblock_t cblock;

	mutex_lock(&mq_era->lock);

	if (!mq_era->mq->lookup(mq_era->mq, current_oblock, &cblock)) {
		DMDEBUG("assigning era %u to cblock %u, oblock %llu "
			"(old_oblock %llu) due to force_mapping.",
			mq_era->era_counter, cblock, new_oblock,
			current_oblock);
		mq_era->cb_to_era[from_cblock(cblock)] = mq_era->era_counter;
	}

	mq_era->mq->force_mapping(mq_era->mq, current_oblock, new_oblock);

	mutex_unlock(&mq_era->lock);
}

static dm_cblock_t mq_era_residency(struct dm_cache_policy *p)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	return mq_era->mq->residency(mq_era->mq);
}

static void mq_era_tick(struct dm_cache_policy *p)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	mq_era->mq->tick(mq_era->mq);
}

static int mq_era_set_config_value(struct dm_cache_policy *p,
				   const char *key,
				   const char *value)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	int r;

	if (!strcasecmp(key, "increment_era_counter"))
		r = incr_era_counter(mq_era, value);
	else if (!strcasecmp(key, "unmap_blocks_from_later_eras"))
		r = cond_unmap_by_era(mq_era, value, era_is_gt_value);
	else if (!strcasecmp(key, "unmap_blocks_from_this_era_and_later"))
		r = cond_unmap_by_era(mq_era, value, era_is_gte_value);
	else if (!strcasecmp(key, "unmap_blocks_from_this_era_and_earlier"))
		r = cond_unmap_by_era(mq_era, value, era_is_lte_value);
	else if (!strcasecmp(key, "unmap_blocks_from_earlier_eras"))
		r = cond_unmap_by_era(mq_era, value, era_is_lt_value);
	else
		r =  mq_era->mq->set_config_value(mq_era->mq, key, value);

	return r;
}

static int mq_era_emit_config_values(struct dm_cache_policy *p, char *result,
				     unsigned maxlen)
{
	struct mq_era_policy *mq_era = to_mq_era_policy(p);
	ssize_t sz = 0;
	DMEMIT("era_counter %u ", mq_era->era_counter);
	return mq_era->mq->emit_config_values(mq_era->mq, result + sz, maxlen - sz);
}

/* Init the policy plugin interface function pointers. */
static void init_policy_functions(struct mq_era_policy *mq_era)
{
	mq_era->policy.destroy = mq_era_destroy;
	mq_era->policy.map = mq_era_map;
	mq_era->policy.lookup = mq_era_lookup;
	mq_era->policy.set_dirty = mq_era_set_dirty;
	mq_era->policy.clear_dirty = mq_era_clear_dirty;
	mq_era->policy.load_mapping = mq_era_load_mapping;
	mq_era->policy.walk_mappings = mq_era_walk_mappings;
	mq_era->policy.remove_mapping = mq_era_remove_mapping;
	mq_era->policy.writeback_work = mq_era_writeback_work;
	mq_era->policy.force_mapping = mq_era_force_mapping;
	mq_era->policy.residency = mq_era_residency;
	mq_era->policy.tick = mq_era_tick;
	mq_era->policy.emit_config_values = mq_era_emit_config_values;
	mq_era->policy.set_config_value = mq_era_set_config_value;
}

static struct dm_cache_policy *mq_era_create(dm_cblock_t cache_size,
					     sector_t origin_size,
					     sector_t cache_block_size)
{
	struct mq_era_policy *mq_era = kzalloc(sizeof(*mq_era), GFP_KERNEL);

	if (!mq_era)
		return NULL;

	init_policy_functions(mq_era);
	mq_era->cache_size = cache_size;
	mutex_init(&mq_era->lock);

	mq_era->cb_to_era = kzalloc(from_cblock(mq_era->cache_size) *
				    sizeof(*(mq_era->cb_to_era)),
			      	    GFP_KERNEL);
	if (!mq_era->cb_to_era)
		goto bad_alloc_cb_to_era;
	mq_era->era_counter = 1;

	mq_era->mq = dm_cache_policy_create("mq", cache_size, origin_size,
					    cache_block_size);
	if (!mq_era->mq)
		goto bad_policy_create;

	DMDEBUG("created mq_era %p, mq %p.", mq_era, mq_era->mq);

	return &mq_era->policy;

bad_policy_create:
	kfree(mq_era->cb_to_era);
bad_alloc_cb_to_era:
	kfree(mq_era);

	return NULL;
}

/*----------------------------------------------------------------*/

static struct dm_cache_policy_type mq_era_policy_type = {
	.name = "mq-era",
	.version = {1, 0, 0},
	.hint_size = 4,
	.owner = THIS_MODULE,
	.create = mq_era_create
};

static int __init mq_era_init(void)
{
	int r;

	r = dm_cache_policy_register(&mq_era_policy_type);
	if (!r) {
		DMINFO("version %u.%u.%u loaded",
		       mq_era_policy_type.version[0],
		       mq_era_policy_type.version[1],
		       mq_era_policy_type.version[2]);
		return 0;
	}

	DMERR("register failed %d", r);

	dm_cache_policy_unregister(&mq_era_policy_type);
	return -ENOMEM;
}

static void __exit mq_era_exit(void)
{
	dm_cache_policy_unregister(&mq_era_policy_type);
}

module_init(mq_era_init);
module_exit(mq_era_exit);

MODULE_AUTHOR("Morgan Mears <morgan.mears@netapp.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("mq-era cache policy");

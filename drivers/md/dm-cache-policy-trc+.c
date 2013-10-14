/*
 * Copyright 2013 NetApp, Inc. All Rights Reserved, contribution by
 * Morgan Mears.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Gentrcl Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Gentrcl Public License
 * for more details
 *
 */

/* FIXME: use from_[oc]block() */

#include "dm-cache-policy.h"
#include "dm-cache-policy-internal.h"
#include "dm-cache-shim-utils.h"
#include "dm.h"

#include <linux/module.h>

#define DM_MSG_PREFIX "cache-policy-trc+"
#define DM_TRC_OUT(lev, p, f, arg...) \
	do { \
		if (to_trc_policy(p)->trace_level >= lev) \
			DMINFO("%s: " f, __func__, ## arg); \
	} while (0);

enum dm_trace_lev_e {
	DM_TRC_LEV_OFF		= 0,
	DM_TRC_LEV_NORMAL	= 1,
	DM_TRC_LEV_VERBOSE	= 2
};

struct trc_policy {
	struct dm_cache_policy policy;
	int trace_level;
};

/*----------------------------------------------------------------*/

static struct trc_policy *to_trc_policy(struct dm_cache_policy *p)
{
	return container_of(p, struct trc_policy, policy);
}

static int set_trace_level(struct dm_cache_policy *p, const char *str)
{
	uint32_t val;

	if (kstrtou32(str, 10, &val))
		return -EINVAL;
	to_trc_policy(p)->trace_level = val;
	return 0;
}

/*
 * Public interface, via the policy struct.  See dm-cache-policy.h for a
 * description of these.
 */

static void trc_destroy(struct dm_cache_policy *p)
{
	DM_TRC_OUT(DM_TRC_LEV_NORMAL, p, "%p", p);
	kfree(p);
}

static int trc_map(struct dm_cache_policy *p, dm_oblock_t oblock,
		   bool can_block, bool can_migrate, bool discarded_oblock,
		   struct bio *bio, struct policy_result *result)
{
	DM_TRC_OUT(DM_TRC_LEV_NORMAL, p, "%p %llu %u %u %u %p %p", p,
		   oblock, can_block, can_migrate, discarded_oblock,
		   bio, result);
	return p->child->map(p->child, oblock, can_block, can_migrate,
			     discarded_oblock, bio, result);
}

static int trc_lookup(struct dm_cache_policy *p, dm_oblock_t oblock,
		      dm_cblock_t *cblock)
{
	DM_TRC_OUT(DM_TRC_LEV_NORMAL, p, "%p %llu %p", p, oblock, cblock);
	return p->child->lookup(p->child, oblock, cblock);
}

static int trc_set_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	DM_TRC_OUT(DM_TRC_LEV_NORMAL, p, "%p %llu", p, oblock);
	return p->child->set_dirty(p->child, oblock);
}

static int trc_clear_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	DM_TRC_OUT(DM_TRC_LEV_NORMAL, p, "%p %llu", p, oblock);
	return p->child->clear_dirty(p->child, oblock);
}

static int trc_load_mapping(struct dm_cache_policy *p,
			    dm_oblock_t oblock, dm_cblock_t cblock,
			    void *hint, bool hint_valid)
{
	DM_TRC_OUT(DM_TRC_LEV_NORMAL, p, "%p %llu %u %p %u", p, oblock,
		   cblock, hint, hint_valid);
	return p->child->load_mapping(p->child, oblock, cblock, hint, hint_valid);
}

static int trc_walk_mappings(struct dm_cache_policy *p, policy_walk_fn fn, void *context)
{
	DM_TRC_OUT(DM_TRC_LEV_NORMAL, p, "%p %p %p", p, fn, context);
	return dm_cache_shim_utils_walk_map(p, fn, context, NULL);
}

static void trc_remove_mapping(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	DM_TRC_OUT(DM_TRC_LEV_NORMAL, p, "%p %llu", p, oblock);
	p->child->remove_mapping(p->child, oblock);
}

static int trc_writeback_work(struct dm_cache_policy *p, dm_oblock_t *oblock,
			      dm_cblock_t *cblock)
{
	DM_TRC_OUT(DM_TRC_LEV_VERBOSE, p, "%p %p %p", p, oblock, cblock);
	return p->child->writeback_work(p->child, oblock, cblock);
}

static void trc_force_mapping(struct dm_cache_policy *p,
			       dm_oblock_t old_oblock,
			       dm_oblock_t new_oblock)
{
	DM_TRC_OUT(DM_TRC_LEV_NORMAL, p, "%p %llu %llu", p, old_oblock, new_oblock);
	p->child->force_mapping(p->child, old_oblock, new_oblock);
}

static int trc_invalidate_mapping(struct dm_cache_policy *p,
				  dm_oblock_t *oblock, dm_cblock_t *cblock)
{
	DM_TRC_OUT(DM_TRC_LEV_NORMAL, p, "%p %llu %u", p, from_oblock(*oblock), from_cblock(*cblock));
	return p->child->invalidate_mapping(p->child, oblock, cblock);
}

static dm_cblock_t trc_residency(struct dm_cache_policy *p)
{
	DM_TRC_OUT(DM_TRC_LEV_NORMAL, p, "%p", p);
	return p->child->residency(p->child);
}

static void trc_tick(struct dm_cache_policy *p)
{
	DM_TRC_OUT(DM_TRC_LEV_VERBOSE, p, "%p", p);
	p->child->tick(p->child);
}

static int trc_set_config_value(struct dm_cache_policy *p,
				const char *key,
				const char *value)
{
	int r;

	DM_TRC_OUT(DM_TRC_LEV_NORMAL, p, "%p %s %s", p, key, value);

	if (!strcasecmp(key, "set_trace_level"))
		r = set_trace_level(p, value);
	else
		r = p->child->set_config_value(p->child, key, value);

	return r;
}

static int trc_emit_config_values(struct dm_cache_policy *p, char *result,
				  unsigned maxlen)
{
	struct trc_policy *trc = to_trc_policy(p);
	ssize_t sz = 0;

	DM_TRC_OUT(DM_TRC_LEV_NORMAL, p, "%p %p %u", p, result, maxlen);

	DMEMIT("trace_level %u ", trc->trace_level);
	return p->child->emit_config_values(p->child, result + sz, maxlen - sz);
}

/* Init the policy plugin interface function pointers. */
static void init_policy_functions(struct trc_policy *trc)
{
	dm_cache_shim_utils_init_shim_policy(&trc->policy);
	trc->policy.destroy = trc_destroy;
	trc->policy.map = trc_map;
	trc->policy.lookup = trc_lookup;
	trc->policy.set_dirty = trc_set_dirty;
	trc->policy.clear_dirty = trc_clear_dirty;
	trc->policy.load_mapping = trc_load_mapping;
	trc->policy.walk_mappings = trc_walk_mappings;
	trc->policy.remove_mapping = trc_remove_mapping;
	trc->policy.writeback_work = trc_writeback_work;
	trc->policy.force_mapping = trc_force_mapping;
	trc->policy.invalidate_mapping = trc_invalidate_mapping;
	trc->policy.residency = trc_residency;
	trc->policy.tick = trc_tick;
	trc->policy.emit_config_values = trc_emit_config_values;
	trc->policy.set_config_value = trc_set_config_value;
}

static struct dm_cache_policy *trc_create(dm_cblock_t cache_size,
					  sector_t origin_size,
					  sector_t cache_block_size)
{
	struct trc_policy *trc = kzalloc(sizeof(*trc), GFP_KERNEL);

	if (!trc)
		return NULL;

	init_policy_functions(trc);
	trc->trace_level = DM_TRC_LEV_NORMAL;

	return &trc->policy;
}

/*----------------------------------------------------------------*/

static struct dm_cache_policy_type trc_policy_type = {
	.name = "trc+",
	.version = {1, 0, 0},
	.hint_size = 0,
	.owner = THIS_MODULE,
	.create = trc_create
};

static int __init trc_init(void)
{
	int r;

	r = dm_cache_policy_register(&trc_policy_type);
	if (!r) {
		DMINFO("version %u.%u.%u loaded",
		       trc_policy_type.version[0],
		       trc_policy_type.version[1],
		       trc_policy_type.version[2]);
		return 0;
	}

	DMERR("register failed %d", r);

	dm_cache_policy_unregister(&trc_policy_type);
	return -ENOMEM;
}

static void __exit trc_exit(void)
{
	dm_cache_policy_unregister(&trc_policy_type);
}

module_init(trc_init);
module_exit(trc_exit);

MODULE_AUTHOR("Morgan Mears <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("trc+ cache policy shim");

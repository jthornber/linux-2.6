/*
 * Copyright 2013 NetApp, Inc. All Rights Reserved, contribution by
 * Morgan Mears.
 *
 * This file is released under the GPLv2.
 */

#include "dm-cache-policy.h"
#include "dm-cache-policy-internal.h"
#include "dm-cache-shim-utils.h"
#include "dm.h"

#include <linux/module.h>

#define DM_MSG_PREFIX "cache-policy-trace"
#define DM_TRACE_MSG(level, p, f, arg...) \
	do { \
		if (to_trace_policy(p)->trace_level >= level) \
			DMTRACE("%s: " f, __func__, ## arg); \
	} while (0)

enum dm_trace_levels {
	DM_TRACE_LEVEL_OFF     = 0,
	DM_TRACE_LEVEL_NORMAL  = 1,
	DM_TRACE_LEVEL_VERBOSE = 2
};

struct trace_policy {
	struct dm_cache_policy policy;
	int trace_level;
};

/*----------------------------------------------------------------*/

static struct trace_policy *to_trace_policy(struct dm_cache_policy *p)
{
	return container_of(p, struct trace_policy, policy);
}

static int set_trace_level(struct dm_cache_policy *p, const char *str)
{
	uint32_t val;

	if (kstrtou32(str, 10, &val))
		return -EINVAL;
	to_trace_policy(p)->trace_level = val;

	return 0;
}

/*
 * Public interface, via the policy struct.  See dm-cache-policy.h for a
 * description of these.
 */

static void trace_destroy(struct dm_cache_policy *p)
{
	DM_TRACE_MSG(DM_TRACE_LEVEL_NORMAL, p, "%p", p);
	kfree(p);
}

static int trace_map(struct dm_cache_policy *p, dm_oblock_t oblock,
		     bool can_block, bool can_migrate, bool discarded_oblock,
		     struct bio *bio, struct policy_result *result)
{
	DM_TRACE_MSG(DM_TRACE_LEVEL_NORMAL, p, "%p %llu %u %u %u %p %p", p,
		   oblock, can_block, can_migrate, discarded_oblock,
		   bio, result);
	return policy_map(p->child, oblock, can_block, can_migrate,
			  discarded_oblock, bio, result);
}

static int trace_lookup(struct dm_cache_policy *p, dm_oblock_t oblock,
			dm_cblock_t *cblock)
{
	DM_TRACE_MSG(DM_TRACE_LEVEL_NORMAL, p, "%p %llu %p", p, oblock, cblock);
	return policy_lookup(p->child, oblock, cblock);
}

static int trace_set_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	DM_TRACE_MSG(DM_TRACE_LEVEL_NORMAL, p, "%p %llu", p, oblock);
	return policy_set_dirty(p->child, oblock);
}

static int trace_clear_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	DM_TRACE_MSG(DM_TRACE_LEVEL_NORMAL, p, "%p %llu", p, oblock);
	return policy_clear_dirty(p->child, oblock);
}

static int trace_load_mapping(struct dm_cache_policy *p,
			      dm_oblock_t oblock, dm_cblock_t cblock,
			      void *hint, bool hint_valid)
{
	DM_TRACE_MSG(DM_TRACE_LEVEL_NORMAL, p, "%p %llu %u %p %u", p, oblock,
		     cblock, hint, hint_valid);
	return policy_load_mapping(p->child, oblock, cblock, hint, hint_valid);
}

static int trace_walk_mappings(struct dm_cache_policy *p, policy_walk_fn fn,
			       void *context)
{
	DM_TRACE_MSG(DM_TRACE_LEVEL_NORMAL, p, "%p %p %p", p, fn, context);
	return dm_cache_shim_utils_walk_map(p, fn, context, NULL);
}

static void trace_remove_mapping(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	DM_TRACE_MSG(DM_TRACE_LEVEL_NORMAL, p, "%p %llu", p, oblock);
	policy_remove_mapping(p->child, oblock);
}

static int trace_writeback_work(struct dm_cache_policy *p, dm_oblock_t *oblock,
				dm_cblock_t *cblock)
{
	DM_TRACE_MSG(DM_TRACE_LEVEL_VERBOSE, p, "%p %p %p", p, oblock, cblock);
	return policy_writeback_work(p->child, oblock, cblock);
}

static void trace_force_mapping(struct dm_cache_policy *p,
				dm_oblock_t old_oblock, dm_oblock_t new_oblock)
{
	DM_TRACE_MSG(DM_TRACE_LEVEL_NORMAL, p, "%p %llu %llu",
		     p, old_oblock, new_oblock);
	policy_force_mapping(p->child, old_oblock, new_oblock);
}

static int trace_invalidate_mapping(struct dm_cache_policy *p,
				    dm_oblock_t *oblock, dm_cblock_t *cblock)
{
	DM_TRACE_MSG(DM_TRACE_LEVEL_NORMAL, p, "%p %llu %u",
		     p, from_oblock(*oblock), from_cblock(*cblock));
	return policy_invalidate_mapping(p->child, oblock, cblock);
}

static dm_cblock_t trace_residency(struct dm_cache_policy *p)
{
	DM_TRACE_MSG(DM_TRACE_LEVEL_NORMAL, p, "%p", p);
	return policy_residency(p->child);
}

static void trace_tick(struct dm_cache_policy *p)
{
	DM_TRACE_MSG(DM_TRACE_LEVEL_VERBOSE, p, "%p", p);
	policy_tick(p->child);
}

static int trace_set_config_value(struct dm_cache_policy *p,
				  const char *key, const char *value)
{
	int r;

	DM_TRACE_MSG(DM_TRACE_LEVEL_NORMAL, p, "%p %s %s", p, key, value);

	if (!strcasecmp(key, "set_trace_level"))
		r = set_trace_level(p, value);
	else
		r = policy_set_config_value(p->child, key, value);

	return r;
}

static unsigned trace_count_config_values(struct dm_cache_policy *p)
{
	return policy_count_config_values(p->child, result) + 1;
}

static int trace_emit_config_values(struct dm_cache_policy *p, char *result,
				    unsigned maxlen)
{
	struct trace_policy *trace = to_trace_policy(p);
	ssize_t sz = 0;

	DM_TRACE_MSG(DM_TRACE_LEVEL_NORMAL, p, "%p %p %u", p, result, maxlen);

	DMEMIT("trace_level %u ", trace->trace_level);
	return policy_emit_config_values(p->child, result + sz, maxlen - sz);
}

static void init_policy_functions(struct trace_policy *trace)
{
	dm_cache_shim_utils_init_shim_policy(&trace->policy);
	trace->policy.destroy = trace_destroy;
	trace->policy.map = trace_map;
	trace->policy.lookup = trace_lookup;
	trace->policy.set_dirty = trace_set_dirty;
	trace->policy.clear_dirty = trace_clear_dirty;
	trace->policy.load_mapping = trace_load_mapping;
	trace->policy.walk_mappings = trace_walk_mappings;
	trace->policy.remove_mapping = trace_remove_mapping;
	trace->policy.writeback_work = trace_writeback_work;
	trace->policy.force_mapping = trace_force_mapping;
	trace->policy.invalidate_mapping = trace_invalidate_mapping;
	trace->policy.residency = trace_residency;
	trace->policy.tick = trace_tick;
	trace->policy.count_config_pairs = trace_count_config_pairs;
	trace->policy.emit_config_values = trace_emit_config_values;
	trace->policy.set_config_value = trace_set_config_value;
}

static struct dm_cache_policy *trace_create(dm_cblock_t cache_size,
					    sector_t origin_size,
					    sector_t cache_block_size)
{
	struct trace_policy *trace = kzalloc(sizeof(*trace), GFP_KERNEL);

	if (!trace)
		return NULL;

	init_policy_functions(trace);
	trace->trace_level = DM_TRACE_LEVEL_NORMAL;

	return &trace->policy;
}

/*----------------------------------------------------------------*/

static struct dm_cache_policy_type trace_policy_type = {
	.name = "trace",
	.version = {1, 0, 0},
	.hint_size = 0,
	.owner = THIS_MODULE,
	.create = trace_create,
	.features = DM_CACHE_POLICY_SHIM
};

static int __init trace_init(void)
{
	int r;

	r = dm_cache_policy_register(&trace_policy_type);
	if (!r) {
		DMINFO("version %u.%u.%u loaded",
		       trace_policy_type.version[0],
		       trace_policy_type.version[1],
		       trace_policy_type.version[2]);
		return 0;
	}

	DMERR("register failed %d", r);

	dm_cache_policy_unregister(&trace_policy_type);
	return -ENOMEM;
}

static void __exit trace_exit(void)
{
	dm_cache_policy_unregister(&trace_policy_type);
}

module_init(trace_init);
module_exit(trace_exit);

MODULE_AUTHOR("Morgan Mears <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("trace cache policy shim");

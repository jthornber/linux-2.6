/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 */

#ifndef DM_CACHE_POLICY_INTERNAL_H
#define DM_CACHE_POLICY_INTERNAL_H

#include "dm-cache-policy.h"

/*----------------------------------------------------------------*/

/*
 * Little inline functions that simplify calling the policy methods.
 */
static inline int policy_map(struct dm_cache_policy *p, dm_oblock_t oblock,
			     bool can_block, bool can_migrate, bool discarded_oblock,
			     struct bio *bio, struct policy_result *result)
{
	return p->map(p, oblock, can_block, can_migrate, discarded_oblock, bio, result);
}

static inline int policy_lookup(struct dm_cache_policy *p, dm_oblock_t oblock, dm_cblock_t *cblock)
{
	BUG_ON(!p->lookup);
	return p->lookup(p, oblock, cblock);
}

static inline int policy_set_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	return p->set_dirty ? p->set_dirty(p, oblock) : -EOPNOTSUPP;
}

static inline int policy_clear_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	return p->clear_dirty ? p->clear_dirty(p, oblock) : -EOPNOTSUPP;
}

static inline int policy_load_mapping(struct dm_cache_policy *p,
				      dm_oblock_t oblock, dm_cblock_t cblock,
				      uint32_t hint, bool hint_valid)
{
	return p->load_mapping(p, oblock, cblock, hint, hint_valid);
}

static inline int policy_walk_mappings(struct dm_cache_policy *p,
				      policy_walk_fn fn, void *context)
{
	return p->walk_mappings ? p->walk_mappings(p, fn, context) : 0;
}

static inline int policy_writeback_work(struct dm_cache_policy *p,
					dm_oblock_t *oblock,
					dm_cblock_t *cblock)
{
	return p->writeback_work ? p->writeback_work(p, oblock, cblock) : -ENOENT;
}

static inline int policy_next_dirty_block(struct dm_cache_policy *p,
					  dm_oblock_t *oblock,
					  dm_cblock_t *cblock)
{
	return p->next_dirty_block ? p->next_dirty_block(p, oblock, cblock) : -ENOENT;
}

static inline void policy_remove_mapping(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	return p->remove_mapping(p, oblock);
}

static inline void policy_force_mapping(struct dm_cache_policy *p,
					dm_oblock_t current_oblock, dm_oblock_t new_oblock)
{
	return p->force_mapping(p, current_oblock, new_oblock);
}

static inline dm_cblock_t policy_residency(struct dm_cache_policy *p)
{
	return p->residency(p);
}

static inline void policy_tick(struct dm_cache_policy *p)
{
	if (p->tick)
		return p->tick(p);
}

static inline int policy_status(struct dm_cache_policy *p, status_type_t type,
				unsigned status_flags, char *result, unsigned maxlen)
{
	return p->status ? p->status(p, type, status_flags, result, maxlen) : 0;
}

static inline int policy_message(struct dm_cache_policy *p, unsigned argc, char **argv)
{
	return p->message ? p->message(p, argc, argv) : 0;
}

/*----------------------------------------------------------------*/

/*
 * Creates a new cache policy given a policy name, a cache size, an origin size and the block size.
 */
struct dm_cache_policy *dm_cache_policy_create(const char *name, dm_cblock_t cache_size,
					       sector_t origin_size, sector_t block_size,
					       int argc, char **argv);

/*
 * Destroys the policy.  This drops references to the policy module as well
 * as calling it's destroy method.  So always use this rather than calling
 * the policy->destroy method directly.
 */
void dm_cache_policy_destroy(struct dm_cache_policy *p);

/*
 * In case we've forgotten.
 */
const char *dm_cache_policy_get_name(struct dm_cache_policy *p);

size_t dm_cache_policy_get_hint_size(struct dm_cache_policy *p);

/*----------------------------------------------------------------*/

#endif

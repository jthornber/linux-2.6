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
static inline int policy_map(struct dm_cache_policy *p, dm_block_t origin_block,
			      bool can_migrate, bool discarded_oblock, struct bio *bio,
			      struct policy_result *result)
{
	return p->map(p, origin_block, can_migrate, discarded_oblock, bio, result);
}

static inline int policy_load_mapping(struct dm_cache_policy *p, dm_block_t oblock, dm_block_t cblock)
{
	return p->load_mapping(p, oblock, cblock);
}

static inline void policy_remove_mapping(struct dm_cache_policy *p, dm_block_t oblock)
{
	return p->remove_mapping(p, oblock);
}

static inline void policy_force_mapping(struct dm_cache_policy *p,
			dm_block_t current_oblock, dm_block_t new_oblock)
{
	return p->force_mapping(p, current_oblock, new_oblock);
}

static inline dm_block_t policy_residency(struct dm_cache_policy *p)
{
	return p->residency(p);
}

static inline void policy_tick(struct dm_cache_policy *p)
{
	return p->tick(p);
}

/*----------------------------------------------------------------*/

/*
 * Creates a new cache policy given a policy name, a cache size, an origin size and the block size.
 */
struct dm_cache_policy *dm_cache_policy_create(const char *name, dm_block_t cache_size,
					       sector_t origin_size, sector_t block_size);

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

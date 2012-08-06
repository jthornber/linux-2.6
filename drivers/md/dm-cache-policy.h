/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 */

#ifndef DM_CACHE_POLICY_H
#define DM_CACHE_POLICY_H

#include "persistent-data/dm-block-manager.h"

/*----------------------------------------------------------------*/

enum policy_operation {
	POLICY_HIT,
	POLICY_MISS,
	POLICY_NEW,
	POLICY_REPLACE
};

struct policy_result {
	enum policy_operation op;
	dm_block_t old_oblock;
	dm_block_t cblock;
};

struct dm_cache_policy {
	void (*destroy)(struct dm_cache_policy *p);
	void (*map)(struct dm_cache_policy *p, dm_block_t origin_block, int data_dir,
		    bool can_migrate, bool cheap_copy,
		    struct policy_result *result);
	int (*load_mapping)(struct dm_cache_policy *p, dm_block_t oblock, dm_block_t cblock);
	dm_block_t (*residency)(struct dm_cache_policy *p);
};

static inline void policy_destroy(struct dm_cache_policy *p)
{
	p->destroy(p);
}

static inline void policy_map(struct dm_cache_policy *p, dm_block_t origin_block, int data_dir,
			      bool can_migrate, bool cheap_copy,
			      struct policy_result *result)
{
	p->map(p, origin_block, data_dir, can_migrate, cheap_copy, result);
}

static inline int policy_load_mapping(struct dm_cache_policy *p, dm_block_t oblock, dm_block_t cblock)
{
	return p->load_mapping(p, oblock, cblock);
}

static inline dm_block_t policy_residency(struct dm_cache_policy *p)
{
	return p->residency(p);
}

/*----------------------------------------------------------------*/

struct dm_cache_policy *arc_policy_create(dm_block_t cache_size);

/*----------------------------------------------------------------*/

#endif

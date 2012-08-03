/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 */

#ifndef DM_CACHE_POLICY_H
#define DM_CACHE_POLICY_H

#include "persistent-data/dm-block-manager.h"

/*----------------------------------------------------------------*/

enum arc_operation {
	ARC_HIT,
	ARC_MISS,
	ARC_NEW,
	ARC_REPLACE
};

struct arc_result {
	enum arc_operation op;

	dm_block_t old_oblock;
	dm_block_t cblock;
};

struct arc_policy *arc_create(dm_block_t cache_size);
void arc_destroy(struct arc_policy *a);
void arc_map(struct arc_policy *a, dm_block_t origin_block, int data_dir,
	     bool can_migrate, bool cheap_copy, struct arc_result *result);
int arc_load_mapping(struct arc_policy *a, dm_block_t oblock, dm_block_t cblock);
dm_block_t arc_residency(struct arc_policy *a);

/*----------------------------------------------------------------*/

#endif

/*
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */
#ifndef _LINUX_DM_ARRAY_H
#define _LINUX_DM_ARRAY_H

#include "./dm-btree.h"

/*----------------------------------------------------------------*/

/*
 * Describes the array.
 */
struct dm_array_info {
	struct dm_transaction_manager *tm;
	struct dm_btree_value_type value_type;
	struct dm_btree_info btree_info;
};

void dm_setup_array_info(struct dm_array_info *info,
			 struct dm_transaction_manager *tm,
			 struct dm_btree_value_type *vt);

/*
 * Set up an empty array.
 */
int dm_array_empty(struct dm_array_info *info, dm_block_t *root);

/*
 * The values inc or dec will be called the appropriate number of times.
 * So if the caller is holding a reference they may want to drop it.
 */
int dm_array_resize(struct dm_array_info *info, dm_block_t root,
		    uint32_t old_size, uint32_t new_size,
		    const void *default_value,
		    dm_block_t *new_root)
	__dm_written_to_disk(value);

int dm_array_del(struct dm_array_info *info, dm_block_t root);

int dm_array_get(struct dm_array_info *info,
		 dm_block_t root,
		 uint32_t index,
		 void *value_le);

int dm_array_set(struct dm_array_info *info, dm_block_t root,
		 uint32_t index, const void *value, dm_block_t *new_root)
	__dm_written_to_disk(value);

/*----------------------------------------------------------------*/

#endif

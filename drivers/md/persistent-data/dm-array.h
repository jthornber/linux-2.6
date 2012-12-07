/*
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */
#ifndef _LINUX_DM_ARRAY_H
#define _LINUX_DM_ARRAY_H

#include "dm-btree.h"

/*----------------------------------------------------------------*/

/*
 * The dm-array is a persistent version of an array.  It packs the data
 * more efficiently than a btree which will result in less disk space use,
 * and a performance boost.  The get and set operations are still O(ln(n)),
 * but with a much smaller constant.
 *
 * The value type structure is reused from the btree type to support proper
 * reference counting of values.
 *
 * The arrays implicitly know their length, and bounds are checked for
 * lookups and updates.  It doesn't store this in an accessible place
 * because it would waste a whole metadata block.  Make sure you store the
 * size along with the array root in your encompassing data.
 */

/*
 * Describes an array.  Don't initialise this structure yourself, use the
 * setup function below.
 */
struct dm_array_info {
	struct dm_transaction_manager *tm;
	struct dm_btree_value_type value_type;
	struct dm_btree_info btree_info;
};

/*
 * Sets up a dm_array_info structure.
 *
 * info - the structure being filled in.
 * tm   - the transaction manager that should supervise this structure.
 * vt   - describes the leaf values.
 */
void dm_setup_array_info(struct dm_array_info *info,
			 struct dm_transaction_manager *tm,
			 struct dm_btree_value_type *vt);

/*
 * Initialise an empty array, zero length array.
 *
 * info - describes the array
 * root - on success this will be filled out with the root block
 */
int dm_array_empty(struct dm_array_info *info, dm_block_t *root);

/*
 * Resizes the array.
 *
 * info - describes the array
 * root - the root block of the array on disk
 * old_size - yes, the caller is responsible for remembering the size of the array
 * new_size - can be bigger or smaller than old_size
 * value - if we're growing the array the new entries will have this value
 * new_root - on success, points to the new root block
 *
 * If growing the inc function for value will be called the appropriate
 * number of times.  So if the caller is holding a reference they may want
 * to drop it.
 */
int dm_array_resize(struct dm_array_info *info, dm_block_t root,
		    uint32_t old_size, uint32_t new_size,
		    const void *value, dm_block_t *new_root)
	__dm_written_to_disk(value);

/*
 * Frees a whole array.  The value_type's decrement operation will be called
 * for all values in the array
 */
int dm_array_del(struct dm_array_info *info, dm_block_t root);

/*
 * Lookup a value in the array
 *
 * info - describes the array
 * root - root block of the array
 * index - array index
 * value - the value to be read.  Will be in on disk format of course.
 *
 * -ENODATA will be returned if the index is out of bounds.
 */
int dm_array_get(struct dm_array_info *info, dm_block_t root,
		 uint32_t index, void *value);

/*
 * Set an entry in the array.
 *
 * info - describes the array
 * root - root block of the array
 * index - array index
 * value - value to be written to disk.  Make sure you bless this before
 *         calling.
 * new_root - the new root block
 *
 * The old value being overwritten will be decremented, the new value
 * incremented.
 *
 * -ENODATA will be returned if the index is out of bounds.
 */
int dm_array_set(struct dm_array_info *info, dm_block_t root,
		 uint32_t index, const void *value, dm_block_t *new_root)
	__dm_written_to_disk(value);

/*
 * Walk through all the entries in an array.
 *
 * info - describes the array
 * root - root block of the array
 * fn - called back for every element
 * context - passed to the callback
 */
int dm_array_walk(struct dm_array_info *info, dm_block_t root,
		  int (*fn)(void *, uint64_t key, void *leaf),
		  void *context);

/*----------------------------------------------------------------*/

#endif

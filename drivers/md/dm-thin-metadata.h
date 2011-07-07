/*
 * Copyright (C) 2010 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#ifndef DM_THIN_METADATA_H
#define DM_THIN_METADATA_H

#include "persistent-data/dm-btree.h"

/*----------------------------------------------------------------*/

struct dm_thin_metadata;
struct dm_ms_device;
typedef uint64_t dm_thin_dev_t;

/*
 * Reopens or creates a new, empty metadata volume.
 */
struct dm_thin_metadata *
dm_thin_metadata_open(struct block_device *bdev,
		      sector_t data_block_size);

int dm_thin_metadata_close(struct dm_thin_metadata *mmd);

/*
 * Compat feature flags.  Any incompat flags beyond the ones
 * specified below will prevent use of the thin metadata.
 */
#define THIN_FEATURE_COMPAT_SUPP	  0UL
#define THIN_FEATURE_COMPAT_RO_SUPP	  0UL
#define THIN_FEATURE_INCOMPAT_SUPP	  0UL

/*
 * Device creation/deletion.
 */
int dm_thin_metadata_create_thin(struct dm_thin_metadata *mmd,
				 dm_thin_dev_t dev);

/*
 * An internal snapshot.
 *
 * You can only snapshot a quiesced origin.  i.e. one that is either
 * suspended or not instanced at all.
 */
int dm_thin_metadata_create_snap(struct dm_thin_metadata *mmd,
				 dm_thin_dev_t dev,
				 dm_thin_dev_t origin);

/*
 * Deletes a virtual device from the metadata.  It _is_ safe to call this
 * when that device is open, operations on that device will just start
 * failing.  You still need to call close() on the device.
 */
int dm_thin_metadata_delete_device(struct dm_thin_metadata *mmd,
				   dm_thin_dev_t dev);

/*
 * Thin devices don't have a size, however they do keep track of the
 * highest mapped block.  This trimming function allows the user to remove
 * mappings above a certain virtual block.
 */
int dm_thin_metadata_trim_thin_dev(struct dm_thin_metadata *mmd,
				   dm_thin_dev_t dev,
				   sector_t new_size);

/*
 * Commits _all_ metadata changes: device creation, deletion, mapping
 * updates.
 */
int dm_thin_metadata_commit(struct dm_thin_metadata *mmd);

/*
 * Set/get userspace transaction id
 */
int dm_thin_metadata_set_transaction_id(struct dm_thin_metadata *mmd,
					uint64_t current_id,
					uint64_t new_id);

int dm_thin_metadata_get_transaction_id(struct dm_thin_metadata *mmd,
					uint64_t *result);

/*
 * hold/get root for userspace transaction
 */
int dm_thin_metadata_hold_root(struct dm_thin_metadata *mmd);

int dm_thin_metadata_get_held_root(struct dm_thin_metadata *mmd,
				   dm_block_t *result);

/*
 * Actions on a single virtual device.
 */

/*
 * Opening the same device more than once will fail with -EBUSY.
 */
int dm_thin_metadata_open_device(struct dm_thin_metadata *mmd,
				 dm_thin_dev_t dev,
				 struct dm_ms_device **msd);

int dm_thin_metadata_close_device(struct dm_ms_device *msd);

dm_thin_dev_t dm_thin_device_dev(struct dm_ms_device *msd);

struct dm_thin_lookup_result {
	dm_block_t block;
	int shared;
};

/*
 * Returns:
 *   -EWOULDBLOCK iff @can_block is set and would block.
 *   -ENODATA iff that mapping is not present.
 *   0 success
 */
int dm_thin_metadata_lookup(struct dm_ms_device *msd,
			    dm_block_t block, int can_block,
			    struct dm_thin_lookup_result *result);

/* Inserts a new mapping */
int dm_thin_metadata_insert(struct dm_ms_device *msd, dm_block_t block,
			    dm_block_t data_block);

int dm_thin_metadata_remove(struct dm_ms_device *msd,
			    dm_block_t block);

int dm_thin_metadata_thin_highest_mapped_block(struct dm_ms_device *msd,
					       dm_block_t *highest_mapped);

/* FIXME: why are these passed an msd, rather than an mmd ? */
int dm_thin_metadata_alloc_data_block(struct dm_ms_device *msd,
				      dm_block_t *result);

int dm_thin_metadata_get_free_blocks(struct dm_thin_metadata *mmd,
				     dm_block_t *result);

int
dm_thin_metadata_get_free_blocks_metadata(struct dm_thin_metadata *mmd,
					  dm_block_t *result);

int dm_thin_metadata_get_data_block_size(struct dm_thin_metadata *mmd,
					 sector_t *result);

int dm_thin_metadata_get_data_dev_size(struct dm_thin_metadata *mmd,
				       dm_block_t *result);

int dm_thin_metadata_get_mapped_count(struct dm_ms_device *msd,
				      dm_block_t *result);

int dm_thin_metadata_get_highest_mapped_block(struct dm_ms_device *msd,
					      dm_block_t *result);

/*
 * Returns -ENOSPC if the new size is too small and already allocated
 * blocks would be lost.
 */
int dm_thin_metadata_resize_data_dev(struct dm_thin_metadata *mmd,
				     dm_block_t new_size);

/*----------------------------------------------------------------*/

#endif

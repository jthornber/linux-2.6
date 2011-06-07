/*
 * Copyright (C) 2011 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#ifndef DM_HSM_METADATA
#define DM_HSM_METADATA

#include "persistent-data/dm-btree.h"

/*----------------------------------------------------------------*/

struct hsm_metadata;

/*
 * Creates a new, empty hsm metadata.
 *
 * bdev - device that the metadata is stored on
 * bdev_size - amount of the device, in sectors, to use for metadata.
 */
struct hsm_metadata *hsm_metadata_open(struct block_device *bdev,
				       sector_t data_block_size,
				       dm_block_t data_dev_size);
void hsm_metadata_close(struct hsm_metadata *hsm);

/*
 * Return -EWOULDBLOCK if it would block.
 * May be called concurrently with insert,commit.
 */
int hsm_metadata_lookup(struct hsm_metadata *hsm,
			int can_block,
			dm_block_t origin_block,
			dm_block_t *cache_block);

int hsm_metadata_lookup_reverse(struct hsm_metadata *hsm,
				int can_block,
				dm_block_t cache_block,
				dm_block_t *origin_block);

/*
 * Returns -ENOSPC if the data volume is used up.
 * May be called concurrently with lookup.
 */
int hsm_metadata_insert(struct hsm_metadata *hsm,
			dm_block_t origin_block,
			dm_block_t cache_block);

int hsm_metadata_remove(struct hsm_metadata *hsm,
			dm_block_t origin_block);

int hsm_metadata_is_dirty(struct hsm_metadata *hsm, dm_block_t origin_block);
int hsm_metadata_mark_dirty(struct hsm_metadata *hsm, dm_block_t origin_block);
int hsm_metadata_clear_dirty(struct hsm_metadata *hsm, dm_block_t origin_block);

int hsm_metadata_commit(struct hsm_metadata *hsm);

int hsm_metadata_get_data_block_size(struct hsm_metadata *hsm, sector_t *result);
int hsm_metadata_get_data_dev_size(struct hsm_metadata *hsm, dm_block_t *result);

/*
 * Returns -ENOSPC if the new size is too small and already allocated
 * blocks would be lost.
 */
int hsm_metadata_resize_data_dev(struct hsm_metadata *hsm, dm_block_t new_size);

/*----------------------------------------------------------------*/

#endif /* DM_HSM_METADATA */

/*
 * Copyright (C) 2010 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#ifndef DM_MULTISNAP_METADATA_H
#define DM_MULTISNAP_METADATA_H

#include "persistent-data/btree.h"

/*----------------------------------------------------------------*/

struct multisnap_metadata;
typedef uint64_t multisnap_dev_t;

/*
 * Reopens or creates a new, empty metadata volume.
 */
struct multisnap_metadata *
multisnap_metadata_open(struct block_device *bdev,
			sector_t data_block_size,
			dm_block_t data_dev_size);

int multisnap_metadata_close(struct multisnap_metadata *mmd);

/*
 * Device creation/deletion.
 */
int multisnap_metadata_create_thin(struct multisnap_metadata *mmd,
				   multisnap_dev_t dev,
				   dm_block_t dev_size);

/*
 * An internal snapshot.
 *
 * You can only snapshot a quiesced origin.  i.e. one that is either
 * suspended or not instanced at all.
 */
int multisnap_metadata_create_snap(struct multisnap_metadata *mmd,
				   multisnap_dev_t dev,
				   multisnap_dev_t origin);

/*
 * Deletes a virtual device from the metadata.  It _is_ safe to call this
 * when that device is open, operations on that device will just start
 * failing.  You still need to call close() on the device.
 */
int multisnap_metadata_delete(struct multisnap_metadata *mmd,
			      multisnap_dev_t dev);

/*
 * Commits _all_ metadata changes: device creation, deletion, mapping
 * updates.
 */
int multisnap_metadata_commit(struct multisnap_metadata *mmd);

/*
 * Actions on a single virtual device.
 */
struct ms_device;

/*
 * Opening the same device more than once will fail with -EBUSY.
 */
int multisnap_metadata_open_device(struct multisnap_metadata *mmd,
				   multisnap_dev_t dev,
				   struct ms_device **msd);

int multisnap_metadata_close_device(struct ms_device *msd);

multisnap_dev_t multisnap_device_dev(struct ms_device *msd);

struct multisnap_lookup_result {
	dm_block_t block;
	int shared;
};

/*
 * Returns:
 *   -EWOULDBLOCK iff @can_block is set and would block.
 *   -ENODATA iff that mapping is not present.
 *   0 success
 */
int multisnap_metadata_lookup(struct ms_device *msd,
			      dm_block_t block,
			      int can_block,
			      struct multisnap_lookup_result *result);

/* Inserts a new mapping */
int multisnap_metadata_insert(struct ms_device *msd,
			      dm_block_t block,
			      dm_block_t data_block);

int multisnap_metadata_alloc_data_block(struct ms_device *msd,
					dm_block_t *result);
int multisnap_metadata_free_data_block(struct ms_device *msd,
				       dm_block_t result);

int multisnap_metadata_get_unprovisioned_blocks(struct multisnap_metadata *mmd,
						dm_block_t *result);
int multisnap_metadata_get_data_block_size(struct multisnap_metadata *mmd,
					   sector_t *result);
int multisnap_metadata_get_data_dev_size(struct multisnap_metadata *mmd,
					 dm_block_t *result);

int multisnap_metadata_get_mapped_count(struct ms_device *msd,
					dm_block_t *result);

/*
 * Returns -ENOSPC if the new size is too small and already allocated
 * blocks would be lost.
 */
int multisnap_metadata_resize_data_dev(struct multisnap_metadata *mmd,
				       dm_block_t new_size);

/*----------------------------------------------------------------*/

#endif

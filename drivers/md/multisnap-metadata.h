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
struct multisnap_metadata *multisnap_metadata_open(struct block_device *bdev,
						   sector_t data_block_size,
						   block_t data_dev_size);
int multisnap_metadata_close(struct multisnap_metadata *mmd);

/*
 * Device creation/deletion.
 */
int multisnap_metadata_create_thin(struct multisnap_metadata *mmd,
				   multisnap_dev_t dev,
				   block_t dev_size);

/* an internal snapshot */
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
 *
 * May be called concurrently with lookup.
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

/*
 * |io_direction| must be one of READ or WRITE
 * returns:
 *
 *   0 on success
 *   -EWOULDBLOCK if it would block.
 *   -ENOSPC if out of metadata or data space
 *   -ENODATA no mapping present (only occurs for READs)
 *   + other error codes
 *
 * The |can_block| parameter has become overloaded.  We should separate
 * into two flags.  Currently it means:
 *
 *   0 - This call will return -EWOULDBLOCK if it was going to block, also
 *       it wont modify the mapping.
 *  !0 - Can block, can modify.
 *
 * May be called concurrently with insert, commit.
 */
struct multisnap_map_result {
	block_t dest;		/* map to this block */

	/*
	 * If @need_copy is !0, then the block has not been initialised.  You
	 * should ensure that you either:
	 *
	 * - write to the whole block
	 * - overwrite the contents of @dest with @clone
	 */
	int need_copy;
	block_t clone;
};

int multisnap_metadata_map(struct ms_device *msd,
			   block_t block,
			   int io_direction,
			   int can_block,
			   struct multisnap_map_result *result);

int multisnap_metadata_get_unprovisioned_blocks(struct multisnap_metadata *mmd, block_t *result);
int multisnap_metadata_get_data_block_size(struct multisnap_metadata *mmd, sector_t *result);
int multisnap_metadata_get_data_dev_size(struct ms_device *msd, block_t *result);
int multisnap_metadata_get_mapped_count(struct ms_device *msd, block_t *result);

/*
 * Returns -ENOSPC if the new size is too small and already allocated
 * blocks would be lost.
 */
int multisnap_metadata_resize_data_dev(struct ms_device *msd, block_t new_size);

/*
 * All thinp devices should use this work queue to perform blocking
 * operations.
 */
struct workqueue_struct *
multisnap_metadata_get_workqueue(struct ms_device *msd);

/*----------------------------------------------------------------*/

#endif

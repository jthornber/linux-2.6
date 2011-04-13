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
 *
 * This may block until pending block copying is complete (see comment for
 * mm_map).
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

enum multisnap_map_code {
	/* A simple mapping, on you go */
	MS_MAPPED,

	/* The client must perform the specified copy operation before
	 * allowing the remapped io to continue.  Remember to tell the
	 * multisnap metadata that the copy is complete *before* continuing
	 * with the io.
	 */
	MS_NEED_COPY,

	/* This io may not proceed at this time.  Generally because it
	 * would change a block that is currently being copied.
	 *
	 * FIXME: How do we know when we can proceed?  Introduce a
	 * deferred_io_set abstraction?  It needs some way of removing
	 * items for quiescing.
	 */
	MS_DEFERRED
};

struct multisnap_map_result {
	int need_copy;

	block_t dest;		/* map to this block */

	/*
	 * If @need_copy is !0, then the block has not been initialised.  You
	 * should ensure that you either:
	 *
	 * - write to the whole block
	 * - overwrite the contents of @dest with @clone
	 */
	block_t origin;
};

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
 * If a copy is needed, then any further WRITE that maps to the @origin or
 * @dest will block until mm_complete_copy() is called.  READs will
 * continue to be mapped to @origin, until after mm_complete_copy() which
 * updates the metadata.
 */
int multisnap_metadata_map(struct ms_device *msd,
			   block_t block,
			   int io_direction,
			   int can_block,
			   struct multisnap_map_result *result);

/*
 * On disk metadata is not updated until this method is called.
 */
int multisnap_metadata_complete_copy(struct ms_device *msd,
				     block_t origin);

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

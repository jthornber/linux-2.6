/*
 * Copyright (C) 2010 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#ifndef DM_THINP_METADATA_H
#define DM_THINP_METADATA_H

#include "persistent-data/btree.h"

/*----------------------------------------------------------------*/

struct thinp_metadata;

/*
 * Creates a new, empty metadata.
 *
 * bdev - device that the metadata is stored on
 * bdev_size - amount of the device, in sectors, to use for metadata.
 */
/* FIXME: should get bdev_size from the bdev ? */

struct thinp_metadata *thinp_metadata_create(struct block_device *bdev, sector_t bdev_size,
					     sector_t data_block_size,
					     block_t data_dev_size);
/* FIXME: remove |bdev_size| */
struct thinp_metadata *thinp_metadata_open(struct block_device *bdev, sector_t bdev_size);
void thinp_metadata_close(struct thinp_metadata *tpm);

/*
 * After a commit you know any inserts have hit the disk.
 */
int thinp_metadata_commit(struct thinp_metadata *tpm);

/* returns -ENOSPC if the data volume is used up */
int thinp_metadata_insert(struct thinp_metadata *tpm,
			  block_t thinp_block,
			  block_t *pool_block);

/* returns -EWOULDBLOCK if it would block */
int thinp_metadata_lookup(struct thinp_metadata *tpm,
			  block_t thinp_block,
			  int can_block,
			  block_t *result);

int thinp_metadata_get_data_block_size(struct thinp_metadata *tpm, sector_t *result);
int thinp_metadata_get_data_dev_size(struct thinp_metadata *tpm, block_t *result);
int thinp_metadata_get_provisioned_blocks(struct thinp_metadata *tpm, block_t *result);

/*
 * Returns -ENOSPC if the new size is too small and already allocated
 * blocks would be lost.
 */
int thinp_metadata_resize_data_dev(struct thinp_metadata *tpm, block_t new_size);

/*----------------------------------------------------------------*/

#endif

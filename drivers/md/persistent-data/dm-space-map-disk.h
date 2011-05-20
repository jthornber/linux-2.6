#ifndef DM_SPACE_MAP_DISK_H
#define DM_SPACE_MAP_DISK_H

#include "dm-transaction-manager.h"
#include "dm-space-map.h"

/*----------------------------------------------------------------*/

/*
 * On disk format for a space map.
 */
struct dm_space_map *dm_sm_disk_create(struct dm_transaction_manager *tm,
				       dm_block_t nr_blocks);

/* Open from a previously recorded root */
struct dm_space_map *dm_sm_disk_open(struct dm_transaction_manager *tm,
				     void *root, size_t len);

/*----------------------------------------------------------------*/

#endif

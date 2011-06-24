#ifndef DM_SPACE_MAP_DISK_H
#define DM_SPACE_MAP_DISK_H

#include "dm-transaction-manager.h"
#include "dm-space-map.h"

/*----------------------------------------------------------------*/

/*
 * Unfortunately we have to use 2 phase construction due to the cycle
 * between the tm and sm.
 */
struct dm_space_map *dm_sm_disk_create(struct dm_transaction_manager *tm,
				       dm_block_t nr_blocks);

struct dm_space_map *dm_sm_disk_open(struct dm_transaction_manager *tm,
				     void *root, size_t len);

/*----------------------------------------------------------------*/

#endif

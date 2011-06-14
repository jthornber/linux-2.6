#ifndef DM_SPACE_MAP_DISK_H
#define DM_SPACE_MAP_DISK_H

#include "dm-transaction-manager.h"
#include "dm-space-map.h"

/*----------------------------------------------------------------*/

/*
 * Unfortunately we have to use 2 phase construction due to the cycle
 * between the tm and sm.
 */
struct dm_space_map *dm_sm_disk_init(void);

/*
 * On disk format for a space map.
 */
int dm_sm_disk_create(struct dm_space_map *sm,
		      struct dm_transaction_manager *tm,
		      dm_block_t nr_blocks);

/*
 * Use this one if the space map is managing it's own space.
 */
int dm_sm_disk_create_recursive(struct dm_space_map *sm,
				struct dm_transaction_manager *tm,
				dm_block_t nr_blocks);

/* Open from a previously recorded root */
int dm_sm_disk_open(struct dm_space_map *sm,
		    struct dm_transaction_manager *tm,
		    void *root, size_t len);

/*----------------------------------------------------------------*/

#endif

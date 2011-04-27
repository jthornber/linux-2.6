#ifndef SNAPSHOTS_SPACE_MAP_DISK_H
#define SNAPSHOTS_SPACE_MAP_DISK_H

#include "transaction-manager.h"
#include "space-map.h"

/*----------------------------------------------------------------*/

/*
 * On disk format for a space map.
 */
struct space_map *sm_disk_create(struct transaction_manager *tm,
				 dm_block_t nr_blocks);

/* Open from a previously recorded root */
struct space_map *sm_disk_open(struct transaction_manager *tm,
			       void *root, size_t len);

/*----------------------------------------------------------------*/

#endif

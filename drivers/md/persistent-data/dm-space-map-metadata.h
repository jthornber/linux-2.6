#ifndef DM_SPACE_MAP_METADATA_H
#define DM_SPACE_MAP_METADATA_H

#include "dm-transaction-manager.h"
#include "dm-space-map.h"

/*----------------------------------------------------------------*/

/*
 * Unfortunately we have to use 2 phase construction due to the cycle
 * between the tm and sm.
 */
struct dm_space_map *dm_sm_metadata_init(void);

/* create a fresh space map */
int dm_sm_metadata_create(struct dm_space_map *sm,
			  struct dm_transaction_manager *tm,
			  dm_block_t nr_blocks,
			  dm_block_t superblock);


/* Open from a previously recorded root */
int dm_sm_metadata_open(struct dm_space_map *sm,
			struct dm_transaction_manager *tm,
			void *root, size_t len);

/*----------------------------------------------------------------*/

#endif

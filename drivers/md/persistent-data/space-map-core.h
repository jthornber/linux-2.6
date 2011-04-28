#ifndef SNAPSHOTS_SPACE_MAP_CORE_H
#define SNAPSHOTS_SPACE_MAP_CORE_H

#include "space-map.h"

/*----------------------------------------------------------------*/

/*
 * The in core space map is only used for test code.
 */
struct dm_space_map *dm_sm_core_create(dm_block_t dev_size);

/*----------------------------------------------------------------*/

#endif

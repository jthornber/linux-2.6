#ifndef DM_SPACE_MAP_COMMON_H
#define DM_SPACE_MAP_COMMON_H

#include "dm-transaction-manager.h"

//----------------------------------------------------------------

unsigned sm__lookup_bitmap(void *addr, dm_block_t b);
void sm__set_bitmap(void *addr, dm_block_t b, unsigned val);
int sm__find_free(void *addr, unsigned begin, unsigned end,
		  unsigned *result);

//----------------------------------------------------------------

#endif

/*
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#ifndef DM_CACHE_METADATA_H
#define DM_CACHE_METADATA_H

#include "persistent-data/dm-block-manager.h"

/*----------------------------------------------------------------*/

#define CACHE_METADATA_BLOCK_SIZE 4096

/* FIXME: remove this restriction */
/*
 * The metadata device is currently limited in size.
 *
 * We have one block of index, which can hold 255 index entries.  Each
 * index entry contains allocation info about 16k metadata blocks.
 */
#define CACHE_METADATA_MAX_SECTORS (255 * (1 << 14) * (CACHE_METADATA_BLOCK_SIZE / (1 << SECTOR_SHIFT)))

/*
 * Compat feature flags.  Any incompat flags beyond the ones
 * specified below will prevent use of the thin metadata.
 */
#define CACHE_FEATURE_COMPAT_SUPP	  0UL
#define CACHE_FEATURE_COMPAT_RO_SUPP	  0UL
#define CACHE_FEATURE_INCOMPAT_SUPP	  0UL


/*
 * Returns NULL on failure.
 */
struct dm_cache_metadata *dm_cache_metadata_open(struct block_device *bdev,
						 sector_t data_block_size,
						 bool may_format_device);

void dm_cache_metadata_close(struct dm_cache_metadata *cmd);

int dm_cache_remove_mapping(struct dm_cache_metadata *cmd, dm_block_t oblock);
int dm_cache_insert_mapping(struct dm_cache_metadata *cmd, dm_block_t oblock, dm_block_t cblock);
int dm_cache_changed_this_transaction(struct dm_cache_metadata *cmd);

typedef int (*load_mapping_fn)(void *context, dm_block_t oblock, dm_block_t cblock);
int dm_cache_load_mappings(struct dm_cache_metadata *cmd,
			   load_mapping_fn fn,
			   void *context);

int dm_cache_commit(struct dm_cache_metadata *cmd);

/*----------------------------------------------------------------*/

#endif

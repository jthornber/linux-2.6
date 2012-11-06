/*
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#ifndef DM_CACHE_METADATA_H
#define DM_CACHE_METADATA_H

#include "persistent-data/dm-block-manager.h"

/*----------------------------------------------------------------*/

/*
 * It's helpful to get sparse to differentiate between indexes into the
 * origin device, and indexes into the cache device.
 */

typedef dm_block_t __bitwise__ dm_oblock_t;
typedef dm_block_t __bitwise__ dm_cblock_t;

static inline dm_oblock_t to_oblock(dm_block_t b)
{
	return (__force dm_oblock_t) b;
}

static inline dm_block_t from_oblock(dm_oblock_t b)
{
	return (__force dm_block_t) b;
}

static inline dm_cblock_t to_cblock(dm_block_t b)
{
	return (__force dm_cblock_t) b;
}

static inline dm_block_t from_cblock(dm_cblock_t b)
{
	return (__force dm_block_t) b;
}

/*----------------------------------------------------------------*/

#define CACHE_POLICY_NAME_SIZE 16
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
 * A metadata device larger than 16GB triggers a warning.
 */
#define CACHE_METADATA_MAX_SECTORS_WARNING (16 * (1024 * 1024 * 1024 >> SECTOR_SHIFT))

/*----------------------------------------------------------------*/

/*
 * Compat feature flags.  Any incompat flags beyond the ones
 * specified below will prevent use of the thin metadata.
 */
#define CACHE_FEATURE_COMPAT_SUPP	  0UL
#define CACHE_FEATURE_COMPAT_RO_SUPP	  0UL
#define CACHE_FEATURE_INCOMPAT_SUPP	  0UL

/*
 * Reopens or creates a new, empty metadata volume.
 * Returns an ERR_PTR on failure.
 */
struct dm_cache_metadata *dm_cache_metadata_open(struct block_device *bdev,
						 sector_t data_block_size,
						 bool may_format_device);

void dm_cache_metadata_close(struct dm_cache_metadata *cmd);

/*
 * The metadata needs to know how many cache blocks there are.  We're dont
 * care about the origin, assuming the core target is giving us valid
 * origin blocks to map to.
 */
int dm_cache_resize(struct dm_cache_metadata *cmd, dm_cblock_t new_cache_size);
dm_cblock_t dm_cache_size(struct dm_cache_metadata *cmd);

int dm_cache_remove_mapping(struct dm_cache_metadata *cmd, dm_cblock_t cblock);
int dm_cache_insert_mapping(struct dm_cache_metadata *cmd, dm_cblock_t cblock, dm_oblock_t oblock);
int dm_cache_changed_this_transaction(struct dm_cache_metadata *cmd);

typedef int (*load_mapping_fn)(void *context, dm_oblock_t oblock,
			       dm_cblock_t cblock, bool dirty,
			       uint32_t hint, bool hint_valid);
int dm_cache_load_mappings(struct dm_cache_metadata *cmd,
			   const char *policy_name,
			   load_mapping_fn fn,
			   void *context);

int dm_cache_set_dirty(struct dm_cache_metadata *cmd, dm_cblock_t cblock, bool dirty);

struct dm_cache_statistics {
	uint32_t read_hits;
	uint32_t read_misses;
	uint32_t write_hits;
	uint32_t write_misses;
};

void dm_cache_get_stats(struct dm_cache_metadata *cmd,
			struct dm_cache_statistics *stats);
void dm_cache_set_stats(struct dm_cache_metadata *cmd,
			struct dm_cache_statistics *stats);

int dm_cache_commit(struct dm_cache_metadata *cmd, bool clean_shutdown);

void dm_cache_dump(struct dm_cache_metadata *cmd);

/*
 * The policy is invited to save a 32bit hint value for every cblock (eg,
 * for a hit count).  These are stored against the policy name.  If
 * policies are changed, then hints will be lost.  If the machine crashes,
 * hints will be lost.
 *
 * The hints are indexed by the cblock, but many policies will not
 * neccessarily have a fast way of accessing efficiently via cblock.  So
 * rather than querying the policy for each cblock, we let it walk its data
 * structures and fill in the hints in whatever order it wishes.
 */

int dm_cache_begin_hints(struct dm_cache_metadata *cmd, const char *policy_name);

/*
 * requests hints for every cblock and stores in the metadata device.
 */
int dm_cache_save_hint(struct dm_cache_metadata *cmd,
		       dm_cblock_t cblock, uint32_t hint);

/*----------------------------------------------------------------*/

#endif

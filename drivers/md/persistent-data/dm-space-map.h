#ifndef DM_SPACE_MAP_H
#define DM_SPACE_MAP_H

#include "dm-block-manager.h"

/*----------------------------------------------------------------*/

/*
 * This structure keeps a record of how many times each block in a device
 * is referenced.  It needs to be persisted to disk as part of the
 * transaction.
 */

struct dm_space_map {
	void (*destroy)(struct dm_space_map *sm);

	int (*get_nr_blocks)(struct dm_space_map *sm, dm_block_t *count);
	int (*get_nr_free)(struct dm_space_map *sm, dm_block_t *count);

	int (*get_count)(struct dm_space_map *sm, dm_block_t b, uint32_t *result);
	int (*count_is_more_than_one)(struct dm_space_map *sm, dm_block_t b, int *result);
	int (*set_count)(struct dm_space_map *sm, dm_block_t b, uint32_t count);

	int (*commit)(struct dm_space_map *sm);

	int (*inc_block)(struct dm_space_map *sm, dm_block_t b);
	int (*dec_block)(struct dm_space_map *sm, dm_block_t b);

	int (*new_block)(struct dm_space_map *sm, dm_block_t *b); /* increments the returned block */

	/*
	 * The root contains all the information needed to persist the
	 * space map.  Generally this info is small, squirrel it away in a
	 * disk block along with other info.
	 */
	int (*root_size)(struct dm_space_map *sm, size_t *result);
	int (*copy_root)(struct dm_space_map *sm, void *copy_to_here, size_t len);
};

/*----------------------------------------------------------------*/

static inline void dm_sm_destroy(struct dm_space_map *sm)
{
	sm->destroy(sm);
}

static inline int dm_sm_get_nr_blocks(struct dm_space_map *sm, dm_block_t *count)
{
	return sm->get_nr_blocks(sm, count);
}

static inline int dm_sm_get_nr_free(struct dm_space_map *sm, dm_block_t *count)
{
	return sm->get_nr_free(sm, count);
}

static inline int dm_sm_get_count(struct dm_space_map *sm, dm_block_t b,
				  uint32_t *result)
{
	return sm->get_count(sm, b, result);
}

static inline int dm_sm_count_is_more_than_one(struct dm_space_map *sm, dm_block_t b, int *result)
{
	return sm->count_is_more_than_one(sm, b, result);
}

static inline int dm_sm_set_count(struct dm_space_map *sm, dm_block_t b,
				  uint32_t count)
{
	return sm->set_count(sm, b, count);
}

static inline int dm_sm_commit(struct dm_space_map *sm)
{
	return sm->commit(sm);
}

static inline int dm_sm_inc_block(struct dm_space_map *sm, dm_block_t b)
{
	return sm->inc_block(sm, b);
}

static inline int dm_sm_dec_block(struct dm_space_map *sm, dm_block_t b)
{
	return sm->dec_block(sm, b);
}

static inline int dm_sm_new_block(struct dm_space_map *sm, dm_block_t *b)
{
	return sm->new_block(sm, b);
}

static inline int dm_sm_root_size(struct dm_space_map *sm, size_t *result)
{
	return sm->root_size(sm, result);
}

static inline int dm_sm_copy_root(struct dm_space_map *sm,
				  void *copy_to_here, size_t len)
{
	return sm->copy_root(sm, copy_to_here, len);
}

/*----------------------------------------------------------------*/

#endif

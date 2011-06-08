#ifndef DM_SPACE_MAP_H
#define DM_SPACE_MAP_H

#include "dm-block-manager.h"

/*----------------------------------------------------------------*/

/*
 * FIXME: a lot of this comment is out of date.
 *
 * This structure keeps a record of how many times each block in a device
 * is referenced.  It needs to be persisted to disk as part of the
 * transaction.
 *
 * Writing the space map is a challenge.  It is used extensively by the
 * transaction manager, but we'd also like to implement its on-disk format
 * using the standard data structures such as the btree.  So we can easily
 * get into cycles.  For example:
 *
 * snapshot -> btree -> tm_shadow -> space_map_alloc -> btree -> shadow -> space_map alloc
 *
 * How do we break this cycle?  Have 2 modes for the space map to operate
 * in: IN_CORE and then a FLUSH_TO_DISK.  This just defers the cycle,
 * instead of being triggered by the snapshot, it'll be hit when the flush
 * is done:
 *
 * sm_flush -> btree -> tm_shadow -> space_map_alloc
 *
 * We get round this by (internally) running flush to write the allocations
 * caused by the snap client.  Then again to write the allocations caused
 * by the first flush etc.  Then again to write allocations from second
 * flush etc.  A good on disk format will be one that minimises the number
 * of cycles (possibly not a btree).
 */

struct dm_space_map;
struct dm_space_map_ops {
	void (*destroy)(struct dm_space_map *sm);

	int (*get_nr_blocks)(void *context, dm_block_t *count);
	int (*get_nr_free)(void *context, dm_block_t *count);
	int (*get_count)(void *context, dm_block_t b, uint32_t *result);
	int (*set_count)(void *context, dm_block_t b, uint32_t count);

	int (*begin)(void *context);
	int (*commit)(void *context);

	int (*inc_block)(void *context, dm_block_t b);
	int (*dec_block)(void *context, dm_block_t b);

	int (*new_block)(void *context, dm_block_t *b); /* increments the returned block */

	/*
	 * The root contains all the information needed to persist the
	 * space map.  Generally this info is small, squirrel it away in a
	 * disk block along with other info.
	 */
	int (*root_size)(void *context, size_t *result);
	int (*copy_root)(void *context, void *copy_to_here, size_t len);
};

struct dm_space_map {
	struct dm_space_map_ops *ops;
	void *context;
};

/*----------------------------------------------------------------*/

static inline void dm_sm_destroy(struct dm_space_map *sm)
{
	sm->ops->destroy(sm);
}

static inline int dm_sm_get_nr_blocks(struct dm_space_map *sm, dm_block_t *count)
{
	return sm->ops->get_nr_blocks(sm->context, count);
}

static inline int dm_sm_get_nr_free(struct dm_space_map *sm, dm_block_t *count)
{
	return sm->ops->get_nr_free(sm->context, count);
}

static inline int dm_sm_get_count(struct dm_space_map *sm, dm_block_t b,
				  uint32_t *result)
{
	return sm->ops->get_count(sm->context, b, result);
}

static inline int dm_sm_set_count(struct dm_space_map *sm, dm_block_t b,
				  uint32_t count)
{
	return sm->ops->set_count(sm->context, b, count);
}

static inline int dm_sm_begin(struct dm_space_map *sm)
{
	return sm->ops->commit(sm->context);
}

static inline int dm_sm_commit(struct dm_space_map *sm)
{
	return sm->ops->commit(sm->context);
}

/*
 * Beware of races when using the default implementations of inc and dec.
 */
static inline int dm_sm_inc_block(struct dm_space_map *sm, dm_block_t b)
{
	int r;
	uint32_t count;

	if (sm->ops->inc_block)
		return sm->ops->inc_block(sm->context, b);

	r = sm->ops->get_count(sm->context, b, &count);
	if (r < 0)
		return r;

	r = sm->ops->set_count(sm->context, b, count + 1);
	if (r < 0)
		return r;

	return 0;
}

static inline int dm_sm_dec_block(struct dm_space_map *sm, dm_block_t b)
{
	int r;
	uint32_t count;

	if (sm->ops->inc_block)
		return sm->ops->dec_block(sm->context, b);

	r = sm->ops->get_count(sm->context, b, &count);
	if (r < 0)
		return r;

	r = sm->ops->set_count(sm->context, b, count - 1);
	if (r < 0)
		return r;

	return 0;
}

static inline int dm_sm_new_block(struct dm_space_map *sm, dm_block_t *b)
{
	return sm->ops->new_block(sm->context, b);
}

static inline int dm_sm_root_size(struct dm_space_map *sm, size_t *result)
{
	return sm->ops->root_size(sm->context, result);
}

static inline int dm_sm_copy_root(struct dm_space_map *sm,
				  void *copy_to_here, size_t len)
{
	return sm->ops->copy_root(sm->context, copy_to_here, len);
}

/*----------------------------------------------------------------*/

#endif

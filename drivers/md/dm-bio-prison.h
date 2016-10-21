/*
 * Copyright (C) 2011-2012 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#ifndef DM_BIO_PRISON_H
#define DM_BIO_PRISON_H

#include "persistent-data/dm-block-manager.h" /* FIXME: for dm_block_t */
#include "dm-thin-metadata.h" /* FIXME: for dm_thin_id */

#include <linux/bio.h>
#include <linux/rbtree.h>
#include <linux/workqueue.h>

/*----------------------------------------------------------------*/

/*
 * Sometimes we can't deal with a bio straight away.  We put them in prison
 * where they can't cause any mischief.  Bios are put in a cell identified
 * by a key, multiple bios can be in the same cell.  When the cell is
 * subsequently unlocked the bios become available.
 */
struct dm_bio_prison;

/*
 * Keys define a range of blocks within either a virtual or physical
 * device.
 */
struct dm_cell_key {
	int virtual;
	dm_thin_id dev;
	dm_block_t block_begin, block_end;
};

/*
 * Treat this as opaque, only in header so callers can manage allocation
 * themselves.
 */
struct dm_bio_prison_cell {
	bool exclusive_lock;
	unsigned exclusive_level;
	unsigned shared_count;
	struct work_struct *quiesce_continuation;

	struct rb_node node;
	struct dm_cell_key key;
	struct bio_list bios;
};

struct dm_bio_prison *dm_bio_prison_create(struct workqueue_struct *wq);
void dm_bio_prison_destroy(struct dm_bio_prison *prison);

/*
 * These two functions just wrap a mempool.  This is a transitory step:
 * Eventually all bio prison clients should manage their own cell memory.
 *
 * Like mempool_alloc(), dm_bio_prison_alloc_cell() can only fail if called
 * in interrupt context or passed GFP_NOWAIT.
 */
struct dm_bio_prison_cell *dm_bio_prison_alloc_cell(struct dm_bio_prison *prison,
						    gfp_t gfp);
void dm_bio_prison_free_cell(struct dm_bio_prison *prison,
			     struct dm_bio_prison_cell *cell);

/*
 * Shared locks have a bio associated with them.
 *
 * If the lock is granted the caller can continue to use the bio, and must
 * call dm_cell_put() to drop the reference count when finished using it.
 *
 * If the lock cannot be granted then the bio will be tracked within the
 * cell, and later given to the holder of the exclusive lock.
 *
 * See dm_cell_lock() for discussion of the lock_level parameter.
 *
 * Compare *cell_result with cell_prealloc to see if the prealloc was used.
 *
 * Returns true if the lock is granted.
 */
bool dm_cell_get(struct dm_bio_prison *prison,
		 struct dm_cell_key *key,
		 unsigned lock_level,
		 struct bio *inmate,
		 struct dm_bio_prison_cell *cell_prealloc,
		 struct dm_bio_prison_cell **cell_result);

/*
 * Decrement the shared reference count for the lock.  Returns true if
 * returning ownership of the cell (ie. you should free it).
 */
bool dm_cell_put(struct dm_bio_prison *prison,
		 struct dm_bio_prison_cell *cell);

/*
 * Locks a cell.  No associated bio.  Exclusive locks get priority.  These
 * lock contrain whether the io locks are granted according to level.
 *
 * Shared locks will still be granted if the lock_level is > (not =) to the
 * exclusive lock level.
 *
 * If an _exclusive_ lock is already held then -EBUSY is returned.
 *
 * Return values:
 *  < 0 - error
 *  0   - locked; no quiescing needed
 *  1   - locked; quiescing needed
 */
int dm_cell_lock(struct dm_bio_prison *prison,
		 struct dm_cell_key *key,
		 unsigned lock_level,
		 struct dm_bio_prison_cell *cell_prealloc,
		 struct dm_bio_prison_cell **cell_result);

void dm_cell_quiesce(struct dm_bio_prison *prison,
		     struct dm_bio_prison_cell *cell,
		     struct work_struct *continuation);

/*
 * Promotes an _exclusive_ lock to a higher lock level.
 *
 * Return values:
 *  < 0 - error
 *  0   - promoted; no quiescing needed
 *  1   - promoted; quiescing needed
 */
int dm_cell_lock_promote(struct dm_bio_prison *prison,
			 struct dm_bio_prison_cell *cell,
			 unsigned new_lock_level);

/*
 * Adds any held bios to the bio list.  Always returns ownership of the
 * cell (you should free it).
 */
void dm_cell_unlock(struct dm_bio_prison *prison,
		    struct dm_bio_prison_cell *cell,
		    struct bio_list *bios);

/*----------------------------------------------------------------*/

#endif

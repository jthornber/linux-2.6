#ifndef DM_BLOCK_MANAGER_H
#define DM_BLOCK_MANAGER_H

#include <linux/blkdev.h>
#include <linux/types.h>

/*----------------------------------------------------------------*/

typedef uint64_t dm_block_t;

/* An opaque handle to a block of data */
struct dm_block;
dm_block_t dm_block_location(struct dm_block *b);
void *dm_block_data(struct dm_block *b);

/*----------------------------------------------------------------*/

struct dm_block_manager;
struct dm_block_manager *
dm_block_manager_create(struct block_device *bdev, unsigned block_size,
			unsigned cache_size);
void dm_block_manager_destroy(struct dm_block_manager *bm);

unsigned dm_bm_block_size(struct dm_block_manager *bm);
dm_block_t dm_bm_nr_blocks(struct dm_block_manager *bm);

/*
 * You can have multiple concurrent readers, or a single writer holding a
 * block lock.
 */

/*
 * dm_bm_lock() locks a block, and returns via |data| a pointer to memory that
 * holds a copy of that block.  If you have write locked the block then any
 * changes you make to memory pointed to by |data| will be written back to
 * the disk sometime after dm_bm_unlock is called.
 */
int dm_bm_read_lock(struct dm_block_manager *bm, dm_block_t b,
		    struct dm_block **result);

int dm_bm_write_lock(struct dm_block_manager *bm, dm_block_t b,
		     struct dm_block **result);

/*
 * The *_try_lock variants return -EWOULDBLOCK if the block isn't
 * immediately available.
 */
int dm_bm_read_try_lock(struct dm_block_manager *bm, dm_block_t b,
			struct dm_block **result);

/*
 * dm_bm_write_lock_zero() is for use when you know you're going to completely
 * overwrite the block.  It saves a disk read.
 */
int dm_bm_write_lock_zero(struct dm_block_manager *bm, dm_block_t b,
			  struct dm_block **result);

int dm_bm_unlock(struct dm_block *b);

/*
 * It's a common idiom to have a superblock that should be committed last.
 *
 * |superblock| should be write locked, it will be unlocked during this
 * function.  All dirty blocks are guaranteed to be written and flushed
 * before the superblock.
 *
 * This method always blocks.
 */
int dm_bm_flush_and_unlock(struct dm_block_manager *bm,
			   struct dm_block *superblock);

/*
 * Debug routines.
 */
unsigned dm_bm_locks_held(struct dm_block_manager *bm);

/*----------------------------------------------------------------*/

#endif

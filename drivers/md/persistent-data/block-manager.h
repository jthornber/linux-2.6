#ifndef DRIVERS_MD_TBD_BLOCK_MANAGER_H
#define DRIVERS_MD_TBD_BLOCK_MANAGER_H

#include <linux/blkdev.h>
#include <linux/types.h>

/*----------------------------------------------------------------*/

typedef uint64_t block_t;

/* An opaque handle to a block of data */
struct block;
block_t block_location(struct block *b);
void *block_data(struct block *b);

/*----------------------------------------------------------------*/

struct block_manager;
struct block_manager *
block_manager_create(struct block_device *bdev, unsigned block_size,
		     unsigned cache_size);
void block_manager_destroy(struct block_manager *bm);

size_t bm_block_size(struct block_manager *bm);
block_t bm_nr_blocks(struct block_manager *bm);

/*
 * You can have multiple concurrent readers, or a single writer holding a
 * block lock.
 */

/*
 * bm_lock() locks a block, and returns via |data| a pointer to memory that
 * holds a copy of that block.  If you have write locked the block then any
 * changes you make to memory pointed to by |data| will be written back to
 * the disk sometime after bm_unlock is called.
 */
int bm_read_lock(struct block_manager *bm, block_t b, struct block **result);
int bm_write_lock(struct block_manager *bm, block_t b, struct block **result);

/*
 * The *_try_lock variants return -EWOULDBLOCK if the block isn't
 * immediately available.
 */
int bm_read_try_lock(struct block_manager *bm, block_t b, struct block **result);

/*
 * bm_write_lock_zero() is for use when you know you're going to completely
 * overwrite the block.  It saves a disk read.
 */
int bm_write_lock_zero(struct block_manager *bm, block_t b, struct block **result);
int bm_unlock(struct block *b);

/*
 * bm_flush() tells the block manager to write all changed data back to the
 * disk.  If |should_block| is set then it will block until all data has
 * hit the disk.
 */
int bm_flush(struct block_manager *bm, int should_block);

/* It's a common idiom to have a superblock that should be committed last.
 *
 * |superblock| should be write locked, it will be unlocked during this
 * function.  All dirty blocks are guaranteed to be written and flushed
 * before the superblock.
 *
 * This method always blocks.
 */
int bm_flush_and_unlock(struct block_manager *bm, struct block *superblock);

/*
 * Debug routines.
 */
unsigned bm_locks_held(struct block_manager *bm);

/*----------------------------------------------------------------*/

#endif

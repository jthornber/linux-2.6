#ifndef DM_TRANSACTION_MANAGER_H
#define DM_TRANSACTION_MANAGER_H

#include "dm-block-manager.h"
#include "dm-space-map.h"

/*----------------------------------------------------------------*/

/*
 * This manages the scope of a transaction.  It also enforces immutability
 * of the on-disk data structures by limiting access to writeable blocks.
 *
 * Clients should not fiddle with the block manager directly.
 */
struct dm_transaction_manager;

struct dm_transaction_manager *
dm_tm_create(struct dm_block_manager *bm, struct dm_space_map *sm);

void dm_tm_destroy(struct dm_transaction_manager *tm);

/*
 * The non-blocking version of a transaction manager is intended for use in
 * fast path code that needs to do lookups.  eg, a dm mapping function.
 * You create the non-blocking variant from a normal tm.  The interface is
 * the same, except that most functions will just return -EWOULDBLOCK.
 * Call tm_destroy() as you would with a normal tm when you've finished
 * with it.  You may not destroy the original prior to clones.
 */
struct dm_transaction_manager *
dm_tm_create_non_blocking_clone(struct dm_transaction_manager *real);

/*
 * The client may want to manage some blocks directly (eg, the
 * superblocks).  Call this immediately after construction to reserve
 * blocks.
 */
int dm_tm_reserve_block(struct dm_transaction_manager *tm, dm_block_t b);

int dm_tm_begin(struct dm_transaction_manager *tm);

/*
 * We use a 2 phase commit here.
 *
 * i) In the first phase the block manager is told to start flushing, and
 * the changes to the space map are written to disk.  You should interogate
 * your particular space map to get detail of its root node etc. to be
 * included in your superblock.
 *
 * ii) |root| will be committed last.  You shouldn't use more than the
 * first 512 bytes of |root| if you wish the transaction to survive a power
 * failure.  You *must* have a write lock held on |root| for both stage (i)
 * and (ii).  The commit will drop the write lock.
 */
int dm_tm_pre_commit(struct dm_transaction_manager *tm);
int dm_tm_commit(struct dm_transaction_manager *tm, struct dm_block *root);

/*
 * These methods are the only way to get hold of a writeable block.
 *
 * tm_new_block() is pretty self explanatory.  Make sure you do actually
 * write to the whole of |data| before you unlock, otherwise you could get
 * a data leak.  (The other option is for tm_new_block() to zero new blocks
 * before handing them out, which will be redundant in most if not all
 * cases).
 *
 * tm_shadow_block() will allocate a new block and copy the data from orig
 * to it.  It then decrements the reference count on original block.  Use
 * this to update the contents of a block in a data structure, don't
 * confuse this with a clone - you shouldn't access the orig block after
 * this operation.  Because the tm knows the scope of the transaction it
 * can optimise requests for a shadow of a shadow to a no-op.  Don't forget
 * to unlock when you've finished with the shadow.
 *
 * The |inc_children| flag is used to tell the caller whether they need to
 * adjust reference counts for children (data in the block may refer to
 * other blocks).
 */
int dm_tm_alloc_block(struct dm_transaction_manager *tm, dm_block_t *new);

/* zeroes the new block at returns with write lock held */
int dm_tm_new_block(struct dm_transaction_manager *tm,
		    struct dm_block **result);

/*
 * Shadowing implicitly drops a reference on |orig|, so you must not have
 * it locked when you call this.
 */
int dm_tm_shadow_block(struct dm_transaction_manager *tm, dm_block_t orig,
		       struct dm_block **result, int *inc_children);

/*
 * Read access.  You can lock any block you want, if there's a write lock
 * on it outstanding then it'll block.
 */
int dm_tm_read_lock(struct dm_transaction_manager *tm, dm_block_t b,
		    struct dm_block **result);

int dm_tm_unlock(struct dm_transaction_manager *tm, struct dm_block *b);

/*
 * Functions for altering the reference count of a block directly.
 */
void dm_tm_inc(struct dm_transaction_manager *tm, dm_block_t b);

void dm_tm_dec(struct dm_transaction_manager *tm, dm_block_t b);

int dm_tm_ref(struct dm_transaction_manager *tm, dm_block_t b,
	      uint32_t *result);

struct dm_block_manager *dm_tm_get_bm(struct dm_transaction_manager *tm);

/*
 * A little utility that ties the knot by producing a transaction manager
 * that has a space map managed by the transaction manager ...
 *
 * Returns a tm that has an open transaction to write the new disk sm.
 * Caller should store the new sm root and commit.
 */
int dm_tm_create_with_sm(struct dm_block_manager *bm, dm_block_t sb_location,
			 struct dm_transaction_manager **tm,
			 struct dm_space_map **sm, struct dm_block **sblock);

int dm_tm_open_with_sm(struct dm_block_manager *bm, dm_block_t sb_location,
		       size_t root_offset, size_t root_max_len,
		       struct dm_transaction_manager **tm,
		       struct dm_space_map **sm, struct dm_block **sblock);

/* useful for debugging performance */
unsigned dm_tm_shadow_count(struct dm_transaction_manager *tm);

/*----------------------------------------------------------------*/

#endif

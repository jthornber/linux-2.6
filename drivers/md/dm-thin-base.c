/*
 * Copyright (C) 2011-2017 Red Hat UK.
 *
 * This file is released under the GPL.
 */

#include "dm-thin-base.h"
#include "dm-thin-metadata.h"
#include "dm-bio-prison-v2.h"
#include "dm.h"
#include "dm-utils.h"

#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/jiffies.h>
#include <linux/log2.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>
#include <linux/rbtree.h>

#define	DM_MSG_PREFIX	"thin"

/*
 * How do we handle breaking sharing of data blocks?
 * =================================================
 *
 * We use a standard copy-on-write btree to store the mappings for the
 * devices (note I'm talking about copy-on-write of the metadata here, not
 * the data).  When you take an internal snapshot you clone the root node
 * of the origin btree.  After this there is no concept of an origin or a
 * snapshot.  They are just two device trees that happen to point to the
 * same data blocks.
 *
 * When we get a write in we decide if it's to a shared data block using
 * some timestamp magic.  If it is, we have to break sharing.
 *
 * Let's say we write to a shared block in what was the origin.  The
 * steps are:
 *
 * i) plug io further to this physical block. (see bio_prison code).
 *
 * ii) quiesce any read io to that shared data block.  Obviously
 * including all devices that share this block.  (see dm_deferred_set code)
 *
 * iii) copy the data block to a newly allocate block.  This step can be
 * missed out if the io covers the block. (schedule_copy).
 *
 * iv) insert the new mapping into the origin's btree
 * (process_prepared_mapping).  This act of inserting breaks some
 * sharing of btree nodes between the two devices.  Breaking sharing only
 * effects the btree of that specific device.  Btrees for the other
 * devices that share the block never change.  The btree for the origin
 * device as it was after the last commit is untouched, ie. we're using
 * persistent data structures in the functional programming sense.
 *
 * v) unplug io to this physical block, including the io that triggered
 * the breaking of sharing.
 *
 * Steps (ii) and (iii) occur in parallel.
 *
 * The metadata _doesn't_ need to be committed before the io continues.  We
 * get away with this because the io is always written to a _new_ block.
 * If there's a crash, then:
 *
 * - The origin mapping will point to the old origin block (the shared
 * one).  This will contain the data as it was before the io that triggered
 * the breaking of sharing came in.
 *
 * - The snap mapping still points to the old block.  As it would after
 * the commit.
 *
 * The downside of this scheme is the timestamp magic isn't perfect, and
 * will continue to think that data block in the snapshot device is shared
 * even after the write to the origin has broken sharing.  I suspect data
 * blocks will typically be shared by many different devices, so we're
 * breaking sharing n + 1 times, rather than n, where n is the number of
 * devices that reference this data block.  At the moment I think the
 * benefits far, far outweigh the disadvantages.
 */

/*----------------------------------------------------------------*/

/*
 * Key building.
 */
// FIXME: do we still need PHYSICAL
enum lock_space {
	VIRTUAL,
	PHYSICAL
};

static void build_key(struct dm_thin_device *td, enum lock_space ls,
		      dm_block_t b, dm_block_t e, struct dm_cell_key_v2 *key)
{
	key->virtual = (ls == VIRTUAL);
	key->dev = dm_thin_dev_id(td);
	key->block_begin = b;
	key->block_end = e;
}

static void build_virtual_key(struct dm_thin_device *td, dm_block_t b,
			      struct dm_cell_key_v2 *key)
{
	build_key(td, VIRTUAL, b, b + 1llu, key);
}

/*----------------------------------------------------------------*/
#if 0
#define THROTTLE_THRESHOLD (1 * HZ)

static void throttle_init(struct throttle *t)
{
	init_rwsem(&t->lock);
	t->throttle_applied = false;
}

static void throttle_work_start(struct throttle *t)
{
	t->threshold = jiffies + THROTTLE_THRESHOLD;
}

static void throttle_work_update(struct throttle *t)
{
	if (!t->throttle_applied && jiffies > t->threshold) {
		down_write(&t->lock);
		t->throttle_applied = true;
	}
}

static void throttle_work_complete(struct throttle *t)
{
	if (t->throttle_applied) {
		t->throttle_applied = false;
		up_write(&t->lock);
	}
}

static void throttle_lock(struct throttle *t)
{
	down_read(&t->lock);
}

static void throttle_unlock(struct throttle *t)
{
	up_read(&t->lock);
}
#endif
/*----------------------------------------------------------------*/

/*
 * What lock modes do we need?  Read io can continue whilst sharing is being
 * broken, so it's useful to have lock modes for IO levels as well as for
 * metadata changes.  Is there a difference between forbidding IO and
 * forbidding IO + allowing metadata changes? (Probably not)
 *
 * level 0 - forbid writes
 * level 1 - forbid all io
 *
 * Provision:
 * - LOCK_IO
 * - alloc data block
 *   - alloc
 *   - commit
 *   - alloc
 * - zero block or external copy
 * - insert mapping
 * - unlock
 * - remap and issue held bios
 *
 * Break sharing:
 * - alloc data block
 * - LOCK_WRITES
 * - quiesce
 * - copy/issue overwrite
 * - LOCK_IO
 * - quiesce
 * - update metadata
 * - commit  - do we need to commit here?
 * - unlock
 * - remap all released bios
 *
 * Discard:
 * - LOCK_IO for all range
 * - quiesce
 * - sync passdown
 * - unmap
 * - commit
 * - unlock
 * - requeue any held bios (warn about any held bios within the discard range?)
 *
 * We could hard code all the steps, or implement a little VM with
 * instructions.  We have to be careful to include the error paths.  This
 * sounds fun, so let's try it and see if the code is simpler this way; I like
 * the idea of having the above steps clearly outlined in the code in one
 * place.  A little stack machine?  Pops args, then leaves results.  Need
 * conditional op to code up error recovery.
 */

static void next_instr(struct dm_thin_program *prg)
{
	prg->pc++;
}

static void push_v(struct dm_thin_program *prg, union value v)
{
	BUG_ON(prg->stack_size >= VALUE_STACK_SIZE);
	prg->stack[prg->stack_size] = v;
	prg->stack_size++;
}

static void push_ptr(struct dm_thin_program *prg, void *ptr)
{
	push_v(prg, (union value) {.ptr = ptr});
}

static void push_u(struct dm_thin_program *prg, uint64_t u)
{
	push_v(prg, (union value) {.u = u});
}

static void push_b(struct dm_thin_program *prg, bool b)
{
	push_v(prg, (union value) {.u = b});
}

static void pop_v(struct dm_thin_program *prg, union value *v)
{
	BUG_ON(!prg->stack_size);
	*v = prg->stack[--prg->stack_size];
}

static void *peek_ptr(struct dm_thin_program *prg)
{
	BUG_ON(!prg->stack_size);
	return prg->stack[prg->stack_size - 1].ptr;
}

static void *pop_ptr(struct dm_thin_program *prg)
{
	union value v;
	pop_v(prg, &v);
	return v.ptr;
}

static uint64_t pop_u(struct dm_thin_program *prg)
{
	union value v;
	pop_v(prg, &v);
	return v.u;
}

static void step_program(struct dm_thin_program *prg)
{
	i_fn fn;
	unsigned long flags;

	spin_lock_irqsave(&prg->lock, flags);
	do {
		fn = prg->pc->fn;
		prg->arg = prg->pc->arg;
		next_instr(prg);

	} while (fn(prg));
	spin_unlock_irqrestore(&prg->lock, flags);
}

static struct dm_thin_program *ws_to_prg(struct work_struct *ws)
{
	return container_of(container_of(ws, struct continuation, ws),
			    struct dm_thin_program,
			    k);
}

static void ws_step_program(struct work_struct *ws)
{
	step_program(ws_to_prg(ws));
}

static void schedule_program(struct dm_thin_program *prg)
{
	queue_continuation(prg->pool->wq, &prg->k);
}

static struct dm_thin_program *alloc_program(struct pool *pool, struct instruction *code)
{
	// FIXME: I think this need to come from a mempool to ensure progress
	struct dm_thin_program *prg = kmalloc(sizeof(*prg), GFP_NOIO);
	if (!prg)
		return NULL;

	prg->pool = pool;
	init_continuation(&prg->k, ws_step_program);
	prg->pc = code;
	prg->stack_size = 0;

	return prg;
}

static void free_program(struct dm_thin_program *prg)
{
	kfree(prg);
}

/*----------------------------------------------------------------*/

static bool block_size_is_power_of_two(struct pool *pool)
{
	return pool->sectors_per_block_shift >= 0;
}

static sector_t block_to_sectors(struct pool *pool, dm_block_t b)
{
	return block_size_is_power_of_two(pool) ?
		(b << pool->sectors_per_block_shift) :
		(b * pool->sectors_per_block);
}

/*----------------------------------------------------------------*/

static void remap(struct thin_c *tc, struct bio *bio, dm_block_t block)
{
	struct pool *pool = tc->pool;
	sector_t bi_sector = bio->bi_iter.bi_sector;

	bio->bi_bdev = tc->pool_dev->bdev;
	if (block_size_is_power_of_two(pool))
		bio->bi_iter.bi_sector =
			(block << pool->sectors_per_block_shift) |
			(bi_sector & (pool->sectors_per_block - 1));
	else
		bio->bi_iter.bi_sector = (block * pool->sectors_per_block) +
				 sector_div(bi_sector, pool->sectors_per_block);
}

static int bio_triggers_commit(struct thin_c *tc, struct bio *bio)
{
	return (bio->bi_opf & (REQ_PREFLUSH | REQ_FUA)) &&
		dm_thin_changed_this_transaction(tc->td);
}

static void issue(struct thin_c *tc, struct bio *bio)
{
	struct pool *pool = tc->pool;

	if (bio_triggers_commit(tc, bio)) {
		/*
		 * Complete bio with an error if earlier I/O caused changes to
		 * the metadata that can't be committed e.g, due to I/O errors
		 * on the metadata device.
		 */
		if (dm_thin_aborted_changes(tc->td))
			bio_io_error(bio);

		else {
			issue_after_commit(&pool->committer, bio);
			async_commit(&pool->committer);
		}

	} else
		generic_make_request(bio);
}

static void remap_and_issue(struct thin_c *tc, struct bio *bio,
			    dm_block_t block)
{
	remap(tc, bio, block);
	issue(tc, bio);
}

static bool error_bios(struct dm_thin_program *prg, int err)
{
	struct bio *bio;
	struct bio_list *bios = pop_ptr(prg);

	while ((bio = bio_list_pop(bios))) {
		bio->bi_error = err;
		bio_endio(bio);
	}

	return true;
}

/*----------------------------------------------------------------*/

#define LOCK_WRITES 0
#define LOCK_IO 1

static bool is_write(struct bio *bio)
{
	return bio_data_dir(bio) == WRITE;
}

static unsigned bio_lock_level(struct bio *bio)
{
	return is_write(bio) ? 0 : 1;
}

static int bio_detain(struct pool *pool, struct dm_cell_key_v2 *key,
		      struct bio *bio, struct dm_bio_prison_cell_v2 **cell_result)
{
	int r;
	struct dm_bio_prison_cell_v2 *cell_prealloc;

	/*
	 * Allocate a cell from the prison's mempool.  This might block but it
	 * can't fail.
	 */
	cell_prealloc = dm_bio_prison_alloc_cell_v2(pool->prison, GFP_NOIO);
	r = dm_cell_get_v2(pool->prison, key, bio_lock_level(bio),
			   bio, cell_prealloc, cell_result);
	if (r)
		/*
		 * We reused an old cell; we can get rid of
		 * the new one.
		 */
		dm_bio_prison_free_cell_v2(pool->prison, cell_prealloc);

	return r;
}

enum pool_mode get_pool_mode(struct pool *pool)
{
	return pool->pf.mode;
}

/*----------------------------------------------------------------*/

/*
 * Program control
 */
/* ( n1 n2 -- bool ) */
static bool i_cmp(struct dm_thin_program *prg)
{
	unsigned n1 = pop_u(prg);
	unsigned n2 = pop_u(prg);
	push_b(prg, n1 == n2);
	return true;
}

/* ( -- ) */
static bool i_branch(struct dm_thin_program *prg)
{
	prg->pc = prg->arg.ptr;
	return true;
}

/* (bool -- ) */
static bool i_branch_if(struct dm_thin_program *prg)
{
	if (pop_u(prg))
		prg->pc = prg->arg.ptr;

	return true;
}

/* ( -- ) */
static bool i_halt(struct dm_thin_program *prg)
{
	free_program(prg);
	return false;
}

/*
 * Stack manipulation
 */
/* (X -- ) */
static bool i_drop(struct dm_thin_program *prg)
{
	unsigned i;
	union value v;

	for (i = 0; i < prg->arg.u; i++)
		pop_v(prg, &v);

	return true;
}

/* (X -- X X) */
// FIXME: double check
static bool i_dup(struct dm_thin_program *prg)
{
	BUG_ON(prg->stack_size < prg->arg.u);
	BUG_ON(prg->stack_size + prg->arg.u > VALUE_STACK_SIZE);
	memcpy(prg->stack + prg->stack_size,
	       prg->stack + prg->stack_size - prg->arg.u,
	       sizeof(union value) * prg->arg.u);
	return true;
}

/* (X1 X2 ... Xn -- Xn X1 X2 .. Xn-1) */
// FIXME: double check
static bool i_tuck(struct dm_thin_program *prg)
{
	union value v;

	pop_v(prg, &v);
	memmove(prg->stack + prg->stack_size - prg->arg.u,
		prg->stack + prg->stack_size - prg->arg.u + 1,
		sizeof(union value) * prg->arg.u);
	prg->stack[prg->stack_size - prg->arg.u - 1] = v;
	return true;
}

/*
 * Locking
 */
// FIXME: move somewhere
static void free_prison_cell(struct pool *pool, struct dm_bio_prison_cell_v2 *cell)
{
	dm_bio_prison_free_cell_v2(pool->prison, cell);
}

/* (thin prealloc_cell vblock -- cell success) */
static bool lock__(struct dm_thin_program *prg,
		   enum lock_space ls, unsigned lock_level)
{
	bool r;
	dm_block_t vblock;
	struct dm_thin_device *td;
	struct dm_cell_key_v2 key;
	struct pool *pool = prg->pool;
	struct dm_bio_prison_cell_v2 *cell_prealloc, *cell;

	vblock = pop_u(prg);
	cell_prealloc = pop_ptr(prg);
	td = pop_ptr(prg);

	build_key(td, ls, vblock, vblock + 1ull, &key);
	r = dm_cell_lock_v2(pool->prison, &key, lock_level, cell_prealloc, &cell);
	if (r < 0) {
		/*
		 * Failed to get the lock.
		 */
		free_prison_cell(pool, cell_prealloc);
		push_ptr(prg, NULL);
		push_b(prg, false);
		return true;
	}

	if (cell != cell_prealloc)
		free_prison_cell(pool, cell_prealloc);

	if (r == 0) {
		/*
		 * No quiescing needed.
		 */
		push_ptr(prg, cell);
		push_b(prg, true);
		return true;
	}

	dm_cell_quiesce_v2(pool->prison, cell, &prg->k.ws);
	return false;
}

/*
 * (cell -- cell)
 * There's no point popping the cell since it'll still be needed.
 */
static bool i_quiesce(struct dm_thin_program *prg)
{
	struct dm_bio_prison_cell_v2 *cell = peek_ptr(prg);
	dm_cell_quiesce_v2(prg->pool->prison, cell, &prg->k.ws);
	return false;
}

/* (prealloc_cell vblock -- cell success) */
static bool i_lock_writes_v(struct dm_thin_program *prg)
{
	return lock__(prg, VIRTUAL, LOCK_WRITE);
}

/* (prealloc_cell vblock -- cell) */
static bool i_lock_io_v(struct dm_thin_program *prg)
{
	return lock__(prg, VIRTUAL, LOCK_IO);
}

/* (prealloc_cell pblock -- cell) */
static bool i_lock_writes_p(struct dm_thin_program *prg)
{
	return lock__(prg, PHYSICAL, LOCK_WRITE);
}

/* (pblock -- cell) */
static bool i_lock_io_p(struct dm_thin_program *prg)
{
	return lock__(prg, PHYSICAL, LOCK_IO);
}

/* (cell -- bios) */
static bool i_unlock(struct dm_thin_program *prg)
{
	struct dm_bio_prison_cell_v2 *cell = pop_ptr(prg);

	bio_list_init(&prg->bios);
	if (dm_cell_unlock_v2(prg->pool->prison, cell, &prg->bios))
		free_prison_cell(prg->pool, cell);

	push_ptr(prg, &prg->bios);
	return true;
}

/*
 * (cell -- bios)
 */
static bool i_unlock_to_shared(struct dm_thin_program *prg)
{
	struct dm_bio_prison_cell_v2 *cell = pop_ptr(prg);

	bio_list_init(&prg->bios);
	if (dm_cell_exclusive_to_shared(prg->pool->prison, cell, &prg->bios))
		free_prison_cell(prg->pool, cell);

	push_ptr(prg, &prg->bios);
	return true;
}

/*
 * Allocating
 */
static void check_low_water_mark(struct pool *pool, dm_block_t free_blocks)
{
	unsigned long flags;

	if (free_blocks <= pool->low_water_blocks && !pool->low_water_triggered) {
		DMWARN("%s: reached low water mark for data device: sending event.",
		       dm_device_name(pool->pool_md));
		spin_lock_irqsave(&pool->lock, flags);
		pool->low_water_triggered = true;
		spin_unlock_irqrestore(&pool->lock, flags);
		dm_table_event(pool->ti->table);
	}
}

/* ( -- block return_code)
 * 0 - error
 * 1 - no space
 * 2 - success
 */
static bool i_alloc_block(struct dm_thin_program *prg)
{
	int r;
	dm_block_t free_blocks;
	struct pool *pool = prg->pool;
	dm_block_t result;

	if (WARN_ON(get_pool_mode(pool) != PM_WRITE)) {
		push_u(prg, 0);
		return true;
	}

	r = dm_pool_get_free_block_count(pool->pmd, &free_blocks);
	if (r) {
		metadata_operation_failed(pool, "dm_pool_get_free_block_count", r);
		push_u(prg, 0);
		return true;
	}

	check_low_water_mark(pool, free_blocks);

	if (!free_blocks) {
		push_u(prg, 1);
		return true;
	}

	r = dm_pool_alloc_data_block(pool->pmd, &result);
	if (r) {
		metadata_operation_failed(pool, "dm_pool_alloc_data_block", r);
		push_b(prg, false);
		return true;
	}

	push_u(prg, result);
	push_u(prg, 2);
	return true;
}

/* ( -- ) */
static bool i_set_no_space_mode(struct dm_thin_program *prg)
{
	set_pool_mode(prg->pool, PM_OUT_OF_DATA_SPACE);
	return true;
}

/*
 * Initialising blocks
 */

static void zero_complete(int read_err, unsigned long write_err, void *context)
{
	unsigned long flags;
	struct dm_thin_program *prg = context;

	spin_lock_irqsave(&prg->lock, flags);
	push_b(prg, !(read_err || write_err));
	spin_unlock_irqrestore(&prg->lock, flags);

	schedule_program(prg);
}

/* (pblock -- success) */
static bool i_zero_block(struct dm_thin_program *prg)
{
	int r;
	struct dm_io_region to;
	dm_block_t block = pop_u(prg);

	to.bdev = prg->pool->md_dev;
	to.sector = block;
	to.count = prg->pool->sectors_per_block;

	r = dm_kcopyd_zero(prg->pool->copier, 1, &to, 0, zero_complete, prg);
	if (r < 0) {
		DMERR_LIMIT("dm_kcopyd_zero() failed");
		zero_complete(1, 1, prg);
		return true;
	}

	return false;
}

/*
 * Some functions for manipulating a ref_count on top of the program stack.
 */
static void inc_ref_count__(struct dm_thin_program *prg)
{
	uint64_t ref_count = pop_u(prg);
	push_u(prg, ++ref_count);
}

static bool dec_ref_count__(struct dm_thin_program *prg)
{
	uint64_t ref_count;

	ref_count = pop_u(prg);
	BUG_ON(!ref_count);
	if (--ref_count) {
		push_u(prg, ref_count);
		return false;
	} else
		return true;  /* ready for the next instruction */
}

static bool dec_ref_count(struct dm_thin_program *prg)
{
	bool r;
	unsigned long flags;

	spin_lock_irqsave(&prg->lock, flags);
	r = dec_ref_count__(prg);
	spin_unlock_irqrestore(&prg->lock, flags);

	return r;
}

static void copy_complete(int read_err, unsigned long write_err, void *context)
{
	struct dm_thin_program *prg = context;

	if (dec_ref_count(prg)) {
		push_b(prg, !(read_err || write_err));
		schedule_program(prg);
	}
}

/* (src_pblock dest_pblock len_sectors -- success) */
static bool i_copy(struct dm_thin_program *prg)
{
	int r;
	struct pool *pool = prg->pool;
	struct dm_io_region from, to;

	uint64_t len = pop_u(prg);
	uint64_t dest_pblock = pop_u(prg);
	uint64_t src_pblock = pop_u(prg);

	/*
	 * Push an initial reference count: quiesce action + copy action + an
	 * extra reference held for the duration of this function (we may need
	 * to inc later for a partial zero).
	 */
	push_u(prg, 3);

	from.bdev = pool->md_dev;
	from.sector = src_pblock * pool->sectors_per_block;
	from.count = len;

	to.bdev = pool->md_dev;
	to.sector = dest_pblock * pool->sectors_per_block;
	to.count = len;

	r = dm_kcopyd_copy(pool->copier, &from, 1, &to, 0, copy_complete, prg);
	if (r < 0) {
		DMERR_LIMIT("dm_kcopyd_copy() failed");
		copy_complete(1, 1, prg);

		/*
		 * We allow the zero to be issued, to simplify the
		 * error path.  Otherwise we'd need to start
		 * worrying about decrementing the prepare_actions
		 * counter.
		 */
	}

	/*
	 * Do we need to zero a tail region?
	 */
	if (len < pool->sectors_per_block && pool->pf.zero_new_blocks) {
		inc_ref_count__(prg);

		// FIXME: finish
#if 0
		ll_zero(tc, m,
			data_dest * pool->sectors_per_block + len,
			(data_dest + 1) * pool->sectors_per_block);
#endif
	}

	/*
	 * Drop our reference.
	 */
	return dec_ref_count__(prg);
}

static void overwrite_endio(struct bio *bio)
{
	unsigned long flags;
	struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));
	struct dm_thin_program *prg = h->overwrite_prg;

	spin_lock_irqsave(&prg->lock, flags);
	bio->bi_end_io = pop_ptr(prg);
	push_u(prg, bio->bi_error);
	spin_unlock_irqrestore(&prg->lock, flags);

	schedule_program(prg);
}

/* (thin bio pblock -- success) */
static bool i_overwrite(struct dm_thin_program *prg)
{
	uint64_t pblock = pop_u(prg);
	struct bio *bio = pop_ptr(prg);
	struct thin_c *tc = pop_ptr(prg);
	struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));
	union value v;

	h->overwrite_prg = prg;
	v.ptr = bio->bi_end_io;
	push_v(prg, v);
	bio->bi_end_io = overwrite_endio;
	remap_and_issue(tc, bio, pblock);

	return false;
}

/*
 * Updating metadata
 */

/* (thin vblock pblock -- success) */
static bool i_insert_mapping(struct dm_thin_program *prg)
{
	dm_block_t pblock = pop_u(prg);
	dm_block_t vblock = pop_u(prg);
	struct thin_c *tc = pop_ptr(prg);

	int r = dm_thin_insert_block(tc->td, vblock, pblock);
	if (r) {
		metadata_operation_failed(prg->pool, "dm_thin_insert_block", r);
		push_b(prg, false);
	} else
		push_b(prg, true);

	return true;
}

/* (vbegin vend -- success) */
static bool i_delete_mappings(struct dm_thin_program *prg)
{
	dm_block_t vbegin = pop_u(prg);
	dm_block_t vend = pop_u(prg);
	struct thin_c *tc = pop_ptr(prg);

	int r = dm_thin_remove_range(tc->td, vbegin, vend);
	if (r) {
		metadata_operation_failed(prg->pool, "dm_thin_remove_range", r);
		push_b(prg, false);
	} else
		push_b(prg, true);

	return true;
}

/* ( -- bool) */
static bool i_commit(struct dm_thin_program *prg)
{
	continue_after_commit(&prg->pool->committer, &prg->k);
	async_commit(&prg->pool->committer);
	return false;
}

/* ( -- ) */
static bool i_fail_mode(struct dm_thin_program *prg)
{
	set_pool_mode(prg->pool, PM_FAIL);
	return true;
}

/*
 * Bio handling
 */

/* (thin pblock bios -- ) */
static bool i_remap_and_issue_bios(struct dm_thin_program *prg)
{
	struct bio *bio;
	struct bio_list *bios = pop_ptr(prg);
	dm_block_t pblock = pop_u(prg);
	struct thin_c *tc = pop_ptr(prg);

	while ((bio = bio_list_pop(bios)))
		remap_and_issue(tc, bio, pblock);

	return true;
}

/* (bios -- ) */
static bool i_requeue_bios(struct dm_thin_program *prg)
{
	return error_bios(prg, DM_ENDIO_REQUEUE);
}

/* (bios -- ) */
static bool i_error_bios(struct dm_thin_program *prg)
{
	return error_bios(prg, -EIO);
}

/*----------------------------------------------------------------*/

#include "dm-thin-code.c"

/*
 * It's possible that many concurrent bios will trigger provisioning of the
 * same block.  We want to avoid a stampeding herd issue, so the cell is
 * promoted to exclusive before we setup any programs.  Note we do *not*
 * quiesce the cell, that will have to wait for the program.  Assumes the bio
 * is already holding a shared lock on the cell, which is dropped before the
 * end of the call.
 *
 * Returns:
 * < 0 - error
 * 0 - lock not granted, bio added to cell
 * 1 - lock granted
 */
static int promote_cell(struct pool *pool, struct dm_bio_prison_cell_v2 *cell,
		        struct bio *bio, unsigned lock_level)
{
	int r;
	struct dm_bio_prison_cell_v2 *prealloc_cell = NULL, *cell_result;

	/*
	 * We know this cell is present, so it's safe to pass in a NULL
	 * prealloc ptr.
	 */
	r = dm_cell_lock_v2(pool->prison, &cell->key, lock_level,
			    prealloc_cell, &cell_result);
	BUG_ON(cell_result != cell);

	/*
	 * A sneaky zwischenzug.  Drop our shared reference.  This has to
	 * be done after the cell_lock call.
	 */
	if (dm_cell_put_v2(pool->prison, bio_lock_level(bio), cell))
		// Unexpected ownership passed back
		BUG();

	if (r == -EBUSY) {
		/*
		 * We call get_, knowing that it will fail and the bio will be
		 * imprisoned.  Don't be tempted to 'optimise' by skipping both
		 * the put and subsequent get, that will prevent quiescing from
		 * completing.
		 */
		return 0;

	} if (r < 0) {
		return r;

	} else if (!r) {
		/*
		 * Locked, but no quiescing needed.  This can't happen since we
		 * haven't dropped the shared lock yet.
		 */
		BUG();
	}

	BUG_ON(cell_result != cell);
	return 1;
}

static void provision(struct thin_c *tc, struct dm_bio_prison_cell_v2 *cell,
		      struct bio *bio, dm_block_t vblock)
{
	struct dm_thin_program *prg;

	int r = promote_cell(prg->pool, cell, bio, LOCK_IO);
	if (r < 0) {
		bio_io_error(bio);
		return;

	} else if (!r) {
		/* nothing to do here */
		return;
	}

	prg = alloc_program(tc->pool, provision_code);

	// (:thin :vblock :cell)
	push_ptr(prg, tc);
	push_u(prg, vblock);
	push_ptr(prg, cell);
	schedule_program(prg);
}

static void break_sharing(struct thin_c *tc, struct bio *bio, dm_block_t vblock)
{
#if 0
	static uint16_t break_sharing_code[] = {
		// thin, vblock
		{i_dup, 2},
		{i_lock_writes_p}, // Does this scheme means we need to lock twice on the main io path
		{i_tuck, 2},
		// cell, thin, vblock

		{i_dup, 1},
		{i_alloc_block},
		{i_on_failure, alloc_fail},
		// cell, thin, vblock, pblock

		{i_tuck, 2},
		{i_dup, 2},
		// cell, pblock, thin, vblock, thin, vblock

		{i_lookup},
		{i_on_failure, lookup_fail},
		// cell, new_pblock, thin, vblock, old_pblock

		{i_lift, 3},
		// cell, thin, vblock, old_pblock, new_pblock

		{i_dup, 2},
		{i_copy},
		{i_on_failure, copy_fail},
		// cell, thin, vblock, old_pblock, new_pblock

		{i_dup, 2},
		{i_drop, 1},
		{i_lock_io_p},
		// cell, thin, vblock, old_pblock, new_pblock

		{i_lift, 1},
		{i_drop, 1},
		// cell, thin, vblock, new_pblock

		{i_dup, 1},
		{i_tuck, 3},
		// cell, new_pblock, thin, vblock, new_pblock

		{i_insert_mapping},
		{i_on_failure, insert_fail},
		// cell, new_pblock

		{i_tuck, 1},
		{i_unlock},
		{i_remap_and_issue},
		{i_halt},

		// alloc_fail
		{i_drop, 3},
		{i_unlock},
		{i_requeue_bios},
		{i_halt}
	};
#endif
	static struct instruction break_sharing_code[] = {
	};

	struct dm_thin_program *prg = alloc_program(tc->pool, break_sharing_code);

	push_ptr(prg, tc);
	push_u(prg, vblock);
	schedule_program(prg);
}

/*----------------------------------------------------------------*/

static dm_block_t get_bio_block(struct thin_c *tc, struct bio *bio)
{
	struct pool *pool = tc->pool;
	sector_t block_nr = bio->bi_iter.bi_sector;

	if (block_size_is_power_of_two(pool))
		block_nr >>= pool->sectors_per_block_shift;
	else
		(void) sector_div(block_nr, pool->sectors_per_block);

	return block_nr;
}

/*----------------------------------------------------------------*/

static void thin_hook_bio(struct thin_c *tc, struct bio *bio)
{
	struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));

	h->tc = tc;
	h->overwrite_prg = NULL;
	h->cell = NULL;
}

static void set_cell(struct bio *bio, struct dm_bio_prison_cell_v2 *cell)
{
	struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));
	h->cell = cell;
}

static void process_deferred_bios(struct pool *pool)
{
	// FIXME: finish
}

/*
 * Called only while mapping a thin bio to hand it over to the workqueue.
 */
static void thin_defer_bio(struct thin_c *tc, struct bio *bio)
{
	unsigned long flags;
	struct pool *pool = tc->pool;

	spin_lock_irqsave(&tc->lock, flags);
	bio_list_add(&tc->deferred_bio_list, bio);
	spin_unlock_irqrestore(&tc->lock, flags);

	process_deferred_bios(pool);
}

static void thin_defer_bio_with_throttle(struct thin_c *tc, struct bio *bio)
{
	//struct pool *pool = tc->pool;

	//throttle_lock(&pool->throttle);
	thin_defer_bio(tc, bio);
	//throttle_unlock(&pool->throttle);
}

/*
 * Non-blocking function called from the thin target's map function.
 */
int thin_bio_map(struct dm_target *ti, struct bio *bio)
{
	int r;
	struct dm_cell_key_v2 key;
	struct thin_c *tc = ti->private;
	struct dm_thin_device *td = tc->td;
	struct dm_thin_lookup_result result;
	dm_block_t vblock = get_bio_block(tc, bio);
	struct dm_bio_prison_cell_v2 *cell;

	thin_hook_bio(tc, bio);

	if (tc->requeue_mode) {
		bio->bi_error = DM_ENDIO_REQUEUE;
		bio_endio(bio);
		return DM_MAPIO_SUBMITTED;
	}

	if (get_pool_mode(tc->pool) == PM_FAIL) {
		bio_io_error(bio);
		return DM_MAPIO_SUBMITTED;
	}

#if 0
	// FIXME: can we handle flushing from within a program?
	if (bio->bi_opf & (REQ_PREFLUSH | REQ_FUA) ||
	    bio_op(bio) == REQ_OP_DISCARD) {
		thin_defer_bio_with_throttle(tc, bio);
		return DM_MAPIO_SUBMITTED;
	}
#endif

	/*
	 * We must hold the virtual cell before doing the lookup, otherwise
	 * there's a race with discard.
	 */
	build_virtual_key(tc->td, vblock, &key);
	if (bio_detain(tc->pool, &key, bio, &cell))
		return DM_MAPIO_SUBMITTED;
	set_cell(bio, cell);

	// FIXME: use a look aside within the cell to avoid this call.
	r = dm_thin_find_block(td, vblock, 0, &result);
	switch (r) {
	case 0:
		if (result.shared && is_write(bio)) {
			/*
			 * We have a race condition here between the
			 * result.shared value returned by the lookup and
			 * snapshot creation, which may cause new sharing.
			 *
			 * To avoid this always quiesce the origin before
			 * taking the snap.  You want to do this anyway to
			 * ensure a consistent application view (i.e. lockfs).
			 *
			 * More distant ancestors are irrelevant. The shared
			 * flag will be set in their case.
			 */
			break_sharing(tc, bio, vblock);
			return DM_MAPIO_SUBMITTED;
		}

		/*
		 * This is the fast path.
		 */
		remap(tc, bio, result.block);
		return DM_MAPIO_REMAPPED;

	case -ENODATA:
		provision(tc, cell, bio, vblock);
		return DM_MAPIO_SUBMITTED;

	case -EWOULDBLOCK:
		/*
		 * Slow path.  We need to do metadata IO to find where to send
		 * the bio.  Hand off to a work queue so we don't stall this
		 * thread which might be trying to submit some more bios that
		 * we do have in the cache.
		 */
		thin_defer_bio(tc, bio);
		return DM_MAPIO_SUBMITTED;

	default:
		/*
		 * Must always call bio_io_error on failure.
		 * dm_thin_find_block can fail with -EINVAL if the pool is
		 * switched to fail-io mode.
		 */
		bio_io_error(bio);
		return DM_MAPIO_SUBMITTED;
	}
}

/*----------------------------------------------------------------*/

/*
 * We want all commits to go through the batcher, so we have to build the
 * synchronous commit on top of it.
 */
struct sync_commit {
	struct continuation k;
	struct mutex lock;
};

static void commit_complete(struct work_struct *ws)
{
	struct sync_commit *sc = container_of(
			container_of(ws, struct continuation, ws),
			struct sync_commit,
			k);

	mutex_unlock(&sc->lock);
}

int commit(struct pool *pool)
{
	struct sync_commit sc;
	init_continuation(&sc.k, commit_complete);
	mutex_init(&sc.lock);

	mutex_lock(&sc.lock);
	continue_after_commit(&pool->committer, &sc.k);
	mutex_lock(&sc.lock);

	return sc.k.input;
}

/*----------------------------------------------------------------*/

void thin_get(struct thin_c *tc)
{
	atomic_inc(&tc->refcount);
}

void thin_put(struct thin_c *tc)
{
	if (atomic_dec_and_test(&tc->refcount))
		complete(&tc->can_destroy);
}

/*
 * We can't hold rcu_read_lock() around code that can block.  So we
 * find a thin with the rcu lock held; bump a refcount; then drop
 * the lock.
 */
struct thin_c *get_first_thin(struct pool *pool)
{
	struct thin_c *tc = NULL;

	rcu_read_lock();
	if (!list_empty(&pool->active_thins)) {
		tc = list_entry_rcu(pool->active_thins.next, struct thin_c, list);
		thin_get(tc);
	}
	rcu_read_unlock();

	return tc;
}

struct thin_c *get_next_thin(struct pool *pool, struct thin_c *tc)
{
	struct thin_c *old_tc = tc;

	rcu_read_lock();
	list_for_each_entry_continue_rcu(tc, &pool->active_thins, list) {
		thin_get(tc);
		thin_put(old_tc);
		rcu_read_unlock();
		return tc;
	}
	thin_put(old_tc);
	rcu_read_unlock();

	return NULL;
}


/*----------------------------------------------------------------*/

void set_pool_mode(struct pool *pool, enum pool_mode new_mode)
{
#if 0
	struct pool_c *pt = pool->ti->private;
	bool needs_check = dm_pool_metadata_needs_check(pool->pmd);
	enum pool_mode old_mode = get_pool_mode(pool); unsigned long no_space_timeout = ACCESS_ONCE(no_space_timeout_secs) * HZ; /* * Never allow the pool to transition to PM_WRITE mode if user * intervention is required to verify metadata and data consistency.  */ if (new_mode == PM_WRITE && needs_check) { DMERR("%s: unable to switch pool to write mode until repaired.", dm_device_name(pool->pool_md));
		if (old_mode != new_mode)
			new_mode = old_mode;
		else
			new_mode = PM_READ_ONLY;
	}
	/*
	 * If we were in PM_FAIL mode, rollback of metadata failed.  We're
	 * not going to recover without a thin_repair.	So we never let the
	 * pool move out of the old mode.
	 */
	if (old_mode == PM_FAIL)
		new_mode = old_mode;

	switch (new_mode) {
	case PM_FAIL:
		if (old_mode != new_mode)
			notify_of_pool_mode_change(pool, "failure");
		dm_pool_metadata_read_only(pool->pmd);
		pool->process_bio = process_bio_fail;
		pool->process_discard = process_bio_fail;
		pool->process_cell = process_cell_fail;
		pool->process_discard_cell = process_cell_fail;
		pool->process_prepared_mapping = process_prepared_mapping_fail;
		pool->process_prepared_discard = process_prepared_discard_fail;

		error_retry_list(pool);
		break;

	case PM_READ_ONLY:
		if (old_mode != new_mode)
			notify_of_pool_mode_change(pool, "read-only");
		dm_pool_metadata_read_only(pool->pmd);
		pool->process_bio = process_bio_read_only;
		pool->process_discard = process_bio_success;
		pool->process_cell = process_cell_read_only;
		pool->process_discard_cell = process_cell_success;
		pool->process_prepared_mapping = process_prepared_mapping_fail;
		pool->process_prepared_discard = process_prepared_discard_success;

		error_retry_list(pool);
		break;

	case PM_OUT_OF_DATA_SPACE:
		/*
		 * Ideally we'd never hit this state; the low water mark
		 * would trigger userland to extend the pool before we
		 * completely run out of data space.  However, many small
		 * IOs to unprovisioned space can consume data space at an
		 * alarming rate.  Adjust your low water mark if you're
		 * frequently seeing this mode.
		 */
		if (old_mode != new_mode)
			notify_of_pool_mode_change_to_oods(pool);
		pool->out_of_data_space = true;
		pool->process_bio = process_bio_read_only;
		pool->process_discard = process_discard_bio;
		pool->process_cell = process_cell_read_only;
		pool->process_prepared_mapping = process_prepared_mapping;
		set_discard_callbacks(pool);

		if (!pool->pf.error_if_no_space && no_space_timeout)
			queue_delayed_work(pool->wq, &pool->no_space_timeout, no_space_timeout);
		break;

	case PM_WRITE:
		if (old_mode != new_mode)
			notify_of_pool_mode_change(pool, "write");
		pool->out_of_data_space = false;
		pool->pf.error_if_no_space = pt->requested_pf.error_if_no_space;
		dm_pool_metadata_read_write(pool->pmd);
		pool->process_bio = process_bio;
		pool->process_discard = process_discard_bio;
		pool->process_cell = process_cell;
		pool->process_prepared_mapping = process_prepared_mapping;
		set_discard_callbacks(pool);
		break;
	}

	pool->pf.mode = new_mode;
	/*
	 * The pool mode may have changed, sync it so bind_control_target()
	 * doesn't cause an unexpected mode transition on resume.
	 */
	pt->adjusted_pf.mode = new_mode;
#endif
}

static void abort_transaction(struct pool *pool)
{
	const char *dev_name = dm_device_name(pool->pool_md);

	DMERR_LIMIT("%s: aborting current metadata transaction", dev_name);
	if (dm_pool_abort_metadata(pool->pmd)) {
		DMERR("%s: failed to abort metadata transaction", dev_name);
		set_pool_mode(pool, PM_FAIL);
	}

	if (dm_pool_metadata_set_needs_check(pool->pmd)) {
		DMERR("%s: failed to set 'needs_check' flag in metadata", dev_name);
		set_pool_mode(pool, PM_FAIL);
	}
}

void metadata_operation_failed(struct pool *pool, const char *op, int r)
{
	DMERR_LIMIT("%s: metadata operation '%s' failed: error = %d",
		    dm_device_name(pool->pool_md), op, r);

	abort_transaction(pool);
	set_pool_mode(pool, PM_READ_ONLY);
}

/*----------------------------------------------------------------*/

#define COMMIT_PERIOD HZ
/*
 * We want to commit periodically so that not too much
 * unwritten data builds up.
 */
void do_waker(struct work_struct *ws)
{
	struct pool *pool = container_of(to_delayed_work(ws), struct pool, waker);
	queue_delayed_work(pool->wq, &pool->waker, COMMIT_PERIOD);
}

/*----------------------------------------------------------------*/

// FIXME: duplication with continuations?  Merge?
struct pool_work {
	struct work_struct worker;
	struct completion complete;
};

static struct pool_work *to_pool_work(struct work_struct *ws)
{
	return container_of(ws, struct pool_work, worker);
}

static void pool_work_complete(struct pool_work *pw)
{
	complete(&pw->complete);
}

static void pool_work_wait(struct pool_work *pw, struct pool *pool,
			   void (*fn)(struct work_struct *))
{
	INIT_WORK_ONSTACK(&pw->worker, fn);
	init_completion(&pw->complete);
	queue_work(pool->wq, &pw->worker);
	wait_for_completion(&pw->complete);
}

/*----------------------------------------------------------------*/

struct noflush_work {
	struct pool_work pw;
	struct thin_c *tc;
};

static struct noflush_work *to_noflush(struct work_struct *ws)
{
	return container_of(to_pool_work(ws), struct noflush_work, pw);
}

void do_noflush_start(struct work_struct *ws)
{
	struct noflush_work *w = to_noflush(ws);
	w->tc->requeue_mode = true;
	//requeue_io(w->tc);
	pool_work_complete(&w->pw);
}

void do_noflush_stop(struct work_struct *ws)
{
	struct noflush_work *w = to_noflush(ws);
	w->tc->requeue_mode = false;
	pool_work_complete(&w->pw);
}

void noflush_work(struct thin_c *tc, void (*fn)(struct work_struct *))
{
	struct noflush_work w;

	w.tc = tc;
	pool_work_wait(&w.pw, tc->pool, fn);
}

/*----------------------------------------------------------------*/

static void notify_of_pool_mode_change(struct pool *pool, const char *new_mode)
{
	dm_table_event(pool->ti->table);
	DMINFO("%s: switching pool to %s mode",
	       dm_device_name(pool->pool_md), new_mode);
}

void notify_of_pool_mode_change_to_oods(struct pool *pool)
{
	if (!pool->pf.error_if_no_space)
		notify_of_pool_mode_change(pool, "out-of-data-space (queue IO)");
	else
		notify_of_pool_mode_change(pool, "out-of-data-space (error IO)");
}


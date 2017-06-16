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

#if 0

// FIXME: this will disappear and be replaced with the program stack.
struct dm_thin_new_mapping {
	struct list_head list;

	bool pass_discard:1;
	bool maybe_shared:1;

	/*
	 * Track quiescing, copying and zeroing preparation actions.  When this
	 * counter hits zero the block is prepared and can be inserted into the
	 * btree.
	 */
	atomic_t prepare_actions;

	int err;
	struct thin_c *tc;
	dm_block_t virt_begin, virt_end;
	dm_block_t data_block;
	struct dm_bio_prison_cell_v2 *cell;

	/*
	 * If the bio covers the whole area of a block then we can avoid
	 * zeroing or copying.  Instead this bio is hooked.  The bio will
	 * still be in the cell, so care has to be taken to avoid issuing
	 * the bio twice.
	 */
	struct bio *bio;
	bio_end_io_t *saved_bi_end_io;
};

#endif

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

static void build_data_key(struct dm_thin_device *td, dm_block_t b,
			   struct dm_cell_key_v2 *key)
{
	build_key(td, PHYSICAL, b, b + 1llu, key);
}

static void build_virtual_key(struct dm_thin_device *td, dm_block_t b,
			      struct dm_cell_key_v2 *key)
{
	build_key(td, VIRTUAL, b, b + 1llu, key);
}

/*----------------------------------------------------------------*/

#define THROTTLE_THRESHOLD (1 * HZ)

struct throttle {
	struct rw_semaphore lock;
	unsigned long threshold;
	bool throttle_applied;
};

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

static void push_v(struct dm_thin_program *prg, union value *v)
{
	BUG_ON(stack_size >= STACK_SIZE);

	prg->stack[prg->stack_size] = *v;
	prg->stack_size++;
}

static void push_ptr(struct dm_thin_program *prg, void *ptr)
{
	union value v;
	v.ptr = ptr;
	push_v(prg, &v);
}

static void push_u(struct dm_thin_program *prg, uint64_t u)
{
	union value v;
	v.u = u;
	push_v(prg, &v);
}

static void push_bool(struct dm_thin_program *prg, bool b)
{
	push_v(prg, (struct instruction) {.u = b});
}

static void pop_v(struct dm_thin_program *prg, union value *v)
{
	BUG_ON(!prg->stack_size);

	*v = prg->stack[prg->stack_size - 1];
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
	unsigned long flags;

	spin_lock_irqsave(&prg->lock, flags);
	do {
		i_fn fn = prg->pc->fn;
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
}

static void free_program(struct dm_thin_program *prg)
{
	kfree(prg);
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
	push_bool(prg, n1 == n2);
	return true;
}

/* ( -- ) */
static bool i_branch(struct dm_thin_program *prg)
{
	prg->pc = prg.arg.ptr;
	return true;
}

/* (bool -- ) */
static bool i_branch_if_true(struct dm_thin_program *prg)
{
	if (pop_u(prg))
		prg.pc = prg.arg.ptr;

	return true;
}

/* ( bool -- ) */
static bool i_branch_if_false(struct dm_thin_program *prg)
{
	if (!pop_u(prg))
		prg.pc = prg.arg.ptr;

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
/* ( -- ) */
static bool i_check(struct dm_thin_program *prg)
{
	BUG_ON(prg->stack_size != prg.arg.u);
	return true;
}

/* (X -- ) */
static bool i_drop(struct dm_thin_program *prg)
{
	unsigned i;

	for (i = 0; i < prg->arg.u; i++)
		pop_v(prg);

	return true;
}

/* (X -- X X) */
// FIXME: double check
static bool i_dup(struct dm_thin_program *prg)
{
	BUG_ON(prg->stack_size < prg->arg.u);
	BUG_ON(prg->stack_size + prg->arg.u > PRG_STACK_SIZE);
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
/* (prealloc_cell vblock -- cell success) */
static bool lock__(struct dm_thin_program *prg,
		   enum lock_space ls, unsigned lock_level)
{
	bool r;
	struct pool *pool = prg->pool;
	struct dm_cell_key_v2 key;
	union value v;
	dm_block_t vblock;
	struct dm_bio_prison_cell_v2 *cell_prealloc, *cell;
	struct bio *bio;

	vblock = pop_u(prg);
	cell_prealloc = pop_ptr(prg);

	build_key(td, ls, vblock, vblock + 1ull, &key);
	r = dm_cell_lock_v2(pool->prison, &key, lock_level, cell_prealloc, &cell);
	if (r < 0) {
		/*
		 * Failed to get the lock.
		 */
		free_prison_cell(pool, cell_prealloc);
		push_ptr(prg, NULL);
		push_bool(prg, false);
		return true;
	}

	if (cell != cell_prealloc)
		free_prison_cell(pool, cell_prealloc);

	if (r == 0) {
		/*
		 * No quiescing needed.
		 */
		push_ptr(prg, cell);
		push_bool(prg, true);
		return true;
	}

	dm_cell_quiesce_v2(pool->prison, cell, &prg->ws);
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
	bool r;
	struct dm_bio_prison_cell_v2 *cell = pop_ptr(prg);

	bio_list_init(&prg->bios);
	if (dm_cell_unlock_v2(prg->prison, cell, &prg->bios))
		push_ptr(prg, &prg->bios);
	else
		push_ptr(prg, NULL);

	return true;
}

/*
 * Allocating
 */

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

	r = dm_pool_alloc_data_block(pool->pmd, result);
	if (r) {
		metadata_operation_failed(pool, "dm_pool_alloc_data_block", r);
		push_bool(prg, false);
		return true;
	}

	push_ptr(prg, cell);
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
	push_bool(prg, !(read_err || write_err));
	spin_unlock_irqrestore(&prg->lock, flags);

	schedule_program(prg);
}

/* (pblock -- success) */
static bool i_zero(struct dm_thin_program *prg)
{
	int r;
	struct dm_io_region to;
	dm_block_t block = pop_u(prg);

	to.bdev = prg->pool->pool_dev;
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
		push_bool(prg, !(read_err || write_err));
		schedule_program(prg);
	}
}

/* (src_pblock dest_pblock len_sectors -- success) */
static bool i_copy(struct dm_thin_program *prg)
{
	int r;
	uint64_t ref_count;
	struct pool *pool = tc->pool;
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

	from.bdev = origin->bdev;
	from.sector = src_pblock * pool->sectors_per_block;
	from.count = len;

	to.bdev = pool->pool_dev->bdev;
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
		ll_zero(tc, m,
			data_dest * pool->sectors_per_block + len,
			(data_dest + 1) * pool->sectors_per_block);
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
	bio->bi_end_io = prg->saved_bi_end_io;
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

	h->overwrite_prg = prg;
	save_and_set_endio(bio, &prg->saved_bi_end_io, overwrite_endio);
	remap_and_issue(tc, bio, pblock);
}

/*
 * Updating metadata
 */

/* (thin vblock pblock -- success) */
static bool i_insert_mapping(struct dm_thin_program *prg)
{

}

/* (region -- success) */
static bool i_delete_mappings(struct dm_thin_program *prg)
{

}

/* ( -- bool) */
static bool i_commit(struct dm_thin_program *prg)
{
	continue_after_commit(&prg->pool->committer, &prg->k);
	async_commit(&pool->committer);
	return false;
}

/* ( -- ) */
static bool i_fail_mode(struct dm_thin_program *prg)
{

}

/*
 * Bio handling
 */

/* (pblock bios -- ) */
static bool i_remap_and_issue(struct dm_thin_program *prg)
{

}

/* (bios -- ) */
static bool i_requeue_bios(struct dm_thin_program *prg)
{

}

/* (bios -- ) */
static bool i_error_bios(struct dm_thin_program *prg)
{

}

/*----------------------------------------------------------------*/

static void provision(struct thin_c *tc, dm_block_t block)
{
	static struct instruction alloc_fail[] = {
		// cell, thin, vblock, pblock, alloc_code
		{i_check, {.u = 5}},
		{i_drop, (union value) {.u = 4}},
		{i_unlock},
		{i_requeue_bios},
		{i_halt}
	};

	static struct instruction zero_and_insert[] = {
		{i_dup, {.u = 1}},
		{i_zero_block},
		{i_branch_on_false, {.ptr = zero_fail}},
		// cell, thin, vblock, pblock

		{i_dup, {.u = 1}},
		{i_tuck, {.u = 4}},
		{i_insert_mapping},
		{i_branch_on_false, {.ptr = insert_fail}},
		// pblock, cell

		{i_unlock},
		// pblock, bios

		// FIXME: discards need to be filtered out
		{i_remap_and_issue},
		{i_halt},
	};

	static struct instruction no_space[] = {
		// cell, thin, vblock, pblock
		{i_check, {.u = 4}},
		{i_commit},
		{i_alloc_block},
		{i_dup, {.u = 1}},
		{i_branch_on_false, {.ptr = alloc_fail}},
		{i_cmp, {.u = 2}},
		{i_branch_on_true, {.ptr = zero_and_insert}},

		// cell, thin, vblock, pblock
		{i_set_no_space_mode},
		{i_drop, {.u = 3}},
		{i_unlock},
		{i_requeue_bios}
	};

	static struct instruction insert_fail[] = {
		// pblock, cell
		{i_unlock},
		{i_requeue_bios},
		{i_halt}
	};

	static struct instruction provision_code[] = {
		// thin, vblock
		{i_dup, {.u = 2}},
		{i_lock_io_v},
		{i_tuck, {.u = 2}},
		// cell, thin, vblock

		{i_alloc_block},
		{i_dup, {.u = 1}},
		{i_branch_on_false, {.ptr = alloc_fail}},
		{i_cmp, {.u = 1}},
		{i_branch_on_true, {.ptr = no_space}},
		// cell, thin, vblock, pblock

		{i_branch, {.ptr = zero_and_insert}},
	};

	struct dm_thin_program *prg = alloc_program(pool, provision_code);
	// FIXME: we need to prealloc a cell too
	push_ptr(prg, tc);
	push_u(prg, block);
	schedule_program(pool, prg);
}

static void break_sharing(struct thin_c *tc, dm_block_t vblock)
{
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

	struct dm_thin_program *prg = alloc_prg(pool, provision_code);
	push_ptr(prg, tc);
	push_u(prg, block);
	schedule_program(pool, prg);
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

static void thin_hook_bio(struct thin_c *tc, struct bio *bio)
{
	struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));

	h->tc = tc;
	h->shared_read_entry = NULL;
	h->all_io_entry = NULL;
	h->overwrite_mapping = NULL;
	h->cell = NULL;
}

/*
 * Non-blocking function called from the thin target's map function.
 */
int thin_bio_map(struct dm_target *ti, struct bio *bio)
{
	int r;
	struct thin_c *tc = ti->private;
	dm_block_t block = get_bio_block(tc, bio);
	struct dm_thin_device *td = tc->td;
	struct dm_thin_lookup_result result;
	struct dm_bio_prison_cell *virt_cell, *data_cell;
	struct dm_cell_key key;

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

	if (bio->bi_opf & (REQ_PREFLUSH | REQ_FUA) ||
	    bio_op(bio) == REQ_OP_DISCARD) {
		thin_defer_bio_with_throttle(tc, bio);
		return DM_MAPIO_SUBMITTED;
	}

	/*
	 * We must hold the virtual cell before doing the lookup, otherwise
	 * there's a race with discard.
	 */
	build_virtual_key(tc->td, block, &key);
	if (bio_detain(tc->pool, &key, bio, &virt_cell))
		return DM_MAPIO_SUBMITTED;

	r = dm_thin_find_block(td, block, 0, &result);

	/*
	 * Note that we defer readahead too.
	 */
	switch (r) {
	case 0:
		if (unlikely(result.shared)) {
			/*
			 * We have a race condition here between the
			 * result.shared value returned by the lookup and
			 * snapshot creation, which may cause new
			 * sharing.
			 *
			 * To avoid this always quiesce the origin before
			 * taking the snap.  You want to do this anyway to
			 * ensure a consistent application view
			 * (i.e. lockfs).
			 *
			 * More distant ancestors are irrelevant. The
			 * shared flag will be set in their case.
			 */
			thin_defer_cell(tc, virt_cell);
			return DM_MAPIO_SUBMITTED;
		}

		build_data_key(tc->td, result.block, &key);
		if (bio_detain(tc->pool, &key, bio, &data_cell)) {
			cell_defer_no_holder(tc, virt_cell);
			return DM_MAPIO_SUBMITTED;
		}

		inc_all_io_entry(tc->pool, bio);
		cell_defer_no_holder(tc, data_cell);
		cell_defer_no_holder(tc, virt_cell);

		remap(tc, bio, result.block);
		return DM_MAPIO_REMAPPED;

	case -ENODATA:
	case -EWOULDBLOCK:
		thin_defer_cell(tc, virt_cell);
		return DM_MAPIO_SUBMITTED;

	default:
		/*
		 * Must always call bio_io_error on failure.
		 * dm_thin_find_block can fail with -EINVAL if the
		 * pool is switched to fail-io mode.
		 */
		bio_io_error(bio);
		cell_defer_no_holder(tc, virt_cell);
		return DM_MAPIO_SUBMITTED;
	}
}





















































#if 0
struct discard_op {
	struct thin_c *tc;
	struct blk_plug plug;
	struct bio *parent_bio;
	struct bio *bio;
};

static void begin_discard(struct discard_op *op, struct thin_c *tc, struct bio *parent)
{
	BUG_ON(!parent);

	op->tc = tc;
	blk_start_plug(&op->plug);
	op->parent_bio = parent;
	op->bio = NULL;
}

static int issue_discard(struct discard_op *op, dm_block_t data_b, dm_block_t data_e)
{
	struct thin_c *tc = op->tc;
	sector_t s = block_to_sectors(tc->pool, data_b);
	sector_t len = block_to_sectors(tc->pool, data_e - data_b);

	return __blkdev_issue_discard(tc->pool_dev->bdev, s, len,
				      GFP_NOWAIT, 0, &op->bio);
}

static void end_discard(struct discard_op *op, int r)
{
	if (op->bio) {
		/*
		 * Even if one of the calls to issue_discard failed, we
		 * need to wait for the chain to complete.
		 */
		bio_chain(op->bio, op->parent_bio);
		bio_set_op_attrs(op->bio, REQ_OP_DISCARD, 0);
		submit_bio(op->bio);
	}

	blk_finish_plug(&op->plug);

	/*
	 * Even if r is set, there could be sub discards in flight that we
	 * need to wait for.
	 */
	if (r && !op->parent_bio->bi_error)
		op->parent_bio->bi_error = r;
	bio_endio(op->parent_bio);
}

/*----------------------------------------------------------------*/

static int bio_detain(struct pool *pool, struct dm_cell_key *key, struct bio *bio,
		      struct dm_bio_prison_cell **cell_result)
{
#if 0
	int r;
	struct dm_bio_prison_cell_v2 *cell_prealloc;

	/*
	 * Allocate a cell from the prison's mempool.
	 * This might block but it can't fail.
	 */
	cell_prealloc = dm_bio_prison_alloc_cell_v2(pool->prison, GFP_NOIO);

	r = dm_bio_detain(pool->prison, key, bio, cell_prealloc, cell_result);
	if (r)
		/*
		 * We reused an old cell; we can get rid of
		 * the new one.
		 */
		dm_bio_prison_free_cell(pool->prison, cell_prealloc);

	return r;
#else
	return 0;
#endif
}
#if 0
static void cell_release(struct pool *pool,
			 struct dm_bio_prison_cell *cell,
			 struct bio_list *bios)
{
	dm_cell_release_v2(pool->prison, cell, bios);
	dm_bio_prison_free_cell(pool->prison, cell);
}

static void cell_visit_release(struct pool *pool,
			       void (*fn)(void *, struct dm_bio_prison_cell *),
			       void *context,
			       struct dm_bio_prison_cell *cell)
{
	dm_cell_visit_release(pool->prison, fn, context, cell);
	dm_bio_prison_free_cell(pool->prison, cell);
}

static void cell_release_no_holder(struct pool *pool,
				   struct dm_bio_prison_cell *cell,
				   struct bio_list *bios)
{
	dm_cell_release_no_holder(pool->prison, cell, bios);
	dm_bio_prison_free_cell(pool->prison, cell);
}

static void cell_error_with_code(struct pool *pool,
				 struct dm_bio_prison_cell *cell, int error_code)
{
	dm_cell_error(pool->prison, cell, error_code);
	dm_bio_prison_free_cell(pool->prison, cell);
}

static int get_pool_io_error_code(struct pool *pool)
{
	return pool->out_of_data_space ? -ENOSPC : -EIO;
}

static void cell_error(struct pool *pool, struct dm_bio_prison_cell *cell)
{
	int error = get_pool_io_error_code(pool);

	cell_error_with_code(pool, cell, error);
}

static void cell_success(struct pool *pool, struct dm_bio_prison_cell *cell)
{
	cell_error_with_code(pool, cell, 0);
}

static void cell_requeue(struct pool *pool, struct dm_bio_prison_cell *cell)
{
	cell_error_with_code(pool, cell, DM_ENDIO_REQUEUE);
}
#endif
/*----------------------------------------------------------------*/

static void __merge_bio_list(struct bio_list *bios, struct bio_list *master)
{
	bio_list_merge(bios, master);
	bio_list_init(master);
}

static void error_bio_list(struct bio_list *bios, int error)
{
	struct bio *bio;

	while ((bio = bio_list_pop(bios))) {
		bio->bi_error = error;
		bio_endio(bio);
	}
}

static void error_thin_bio_list(struct thin_c *tc, struct bio_list *master, int error)
{
	struct bio_list bios;
	unsigned long flags;

	bio_list_init(&bios);

	spin_lock_irqsave(&tc->lock, flags);
	__merge_bio_list(&bios, master);
	spin_unlock_irqrestore(&tc->lock, flags);

	error_bio_list(&bios, error);
}

static void requeue_deferred_cells(struct thin_c *tc)
{
	struct pool *pool = tc->pool;
	unsigned long flags;
	struct list_head cells;
	struct dm_bio_prison_cell *cell, *tmp;

	INIT_LIST_HEAD(&cells);

	spin_lock_irqsave(&tc->lock, flags);
	list_splice_init(&tc->deferred_cells, &cells);
	spin_unlock_irqrestore(&tc->lock, flags);

	list_for_each_entry_safe(cell, tmp, &cells, user_list)
		cell_requeue(pool, cell);
}

static void requeue_io(struct thin_c *tc)
{
	struct bio_list bios;
	unsigned long flags;

	bio_list_init(&bios);

	spin_lock_irqsave(&tc->lock, flags);
	__merge_bio_list(&bios, &tc->deferred_bio_list);
	__merge_bio_list(&bios, &tc->retry_on_resume_list);
	spin_unlock_irqrestore(&tc->lock, flags);

	error_bio_list(&bios, DM_ENDIO_REQUEUE);
	requeue_deferred_cells(tc);
}

void error_retry_list_with_code(struct pool *pool, int error)
{
	struct thin_c *tc;

	rcu_read_lock();
	list_for_each_entry_rcu(tc, &pool->active_thins, list)
		error_thin_bio_list(tc, &tc->retry_on_resume_list, error);
	rcu_read_unlock();
}

static void error_retry_list(struct pool *pool)
{
	int error = get_pool_io_error_code(pool);

	error_retry_list_with_code(pool, error);
}

/*
 * This section of code contains the logic for processing a thin device's IO.
 * Much of the code depends on pool object resources (lists, workqueues, etc)
 * but most is exclusively called from the thin target rather than the thin-pool
 * target.
 */

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

/*
 * Returns the _complete_ blocks that this bio covers.
 */
static void get_bio_block_range(struct thin_c *tc, struct bio *bio,
				dm_block_t *begin, dm_block_t *end)
{
	struct pool *pool = tc->pool;
	sector_t b = bio->bi_iter.bi_sector;
	sector_t e = b + (bio->bi_iter.bi_size >> SECTOR_SHIFT);

	b += pool->sectors_per_block - 1ull; /* so we round up */

	if (block_size_is_power_of_two(pool)) {
		b >>= pool->sectors_per_block_shift;
		e >>= pool->sectors_per_block_shift;
	} else {
		(void) sector_div(b, pool->sectors_per_block);
		(void) sector_div(e, pool->sectors_per_block);
	}

	if (e < b)
		/* Can happen if the bio is within a single block. */
		e = b;

	*begin = b;
	*end = e;
}

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

static void remap_to_origin(struct thin_c *tc, struct bio *bio)
{
	bio->bi_bdev = tc->origin_dev->bdev;
}

static int bio_triggers_commit(struct thin_c *tc, struct bio *bio)
{
	return (bio->bi_opf & (REQ_PREFLUSH | REQ_FUA)) &&
		dm_thin_changed_this_transaction(tc->td);
}

static void inc_all_io_entry(struct pool *pool, struct bio *bio)
{
	struct dm_thin_endio_hook *h;

	if (bio_op(bio) == REQ_OP_DISCARD)
		return;

	h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));
	h->all_io_entry = dm_deferred_entry_inc(pool->all_io_ds);
}

static void issue(struct thin_c *tc, struct bio *bio)
{
	struct pool *pool = tc->pool;
	unsigned long flags;

	if (!bio_triggers_commit(tc, bio)) {
		generic_make_request(bio);
		return;
	}

	/*
	 * Complete bio with an error if earlier I/O caused changes to
	 * the metadata that can't be committed e.g, due to I/O errors
	 * on the metadata device.
	 */
	if (dm_thin_aborted_changes(tc->td)) {
		bio_io_error(bio);
		return;
	}

	/*
	 * Batch together any bios that trigger commits and then issue a
	 * single commit for them in process_deferred_bios().
	 */
	spin_lock_irqsave(&pool->lock, flags);
	bio_list_add(&pool->deferred_flush_bios, bio);
	spin_unlock_irqrestore(&pool->lock, flags);
}

static void remap_to_origin_and_issue(struct thin_c *tc, struct bio *bio)
{
	remap_to_origin(tc, bio);
	issue(tc, bio);
}

static void remap_and_issue(struct thin_c *tc, struct bio *bio,
			    dm_block_t block)
{
	remap(tc, bio, block);
	issue(tc, bio);
}

/*----------------------------------------------------------------*/

/*
 * Bio endio functions.
 */
static void __complete_mapping_preparation(struct dm_thin_new_mapping *m)
{
	struct pool *pool = m->tc->pool;

	if (atomic_dec_and_test(&m->prepare_actions)) {
		list_add_tail(&m->list, &pool->prepared_mappings);
		wake_worker(pool);
	}
}

static void complete_mapping_preparation(struct dm_thin_new_mapping *m)
{
	unsigned long flags;
	struct pool *pool = m->tc->pool;

	spin_lock_irqsave(&pool->lock, flags);
	__complete_mapping_preparation(m);
	spin_unlock_irqrestore(&pool->lock, flags);
}

/*----------------------------------------------------------------*/

/*
 * Workqueue.
 */

/*
 * Prepared mapping jobs.
 */

/*
 * This sends the bios in the cell, except the original holder, back
 * to the deferred_bios list.
 */
static void cell_defer_no_holder(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	struct pool *pool = tc->pool;
	unsigned long flags;

	spin_lock_irqsave(&tc->lock, flags);
	cell_release_no_holder(pool, cell, &tc->deferred_bio_list);
	spin_unlock_irqrestore(&tc->lock, flags);

	wake_worker(pool);
}

static void thin_defer_bio(struct thin_c *tc, struct bio *bio);

struct remap_info {
	struct thin_c *tc;
	struct bio_list defer_bios;
	struct bio_list issue_bios;
};

static void __inc_remap_and_issue_cell(void *context,
				       struct dm_bio_prison_cell *cell)
{
	struct remap_info *info = context;
	struct bio *bio;

	while ((bio = bio_list_pop(&cell->bios))) {
		if (bio->bi_opf & (REQ_PREFLUSH | REQ_FUA) ||
		    bio_op(bio) == REQ_OP_DISCARD)
			bio_list_add(&info->defer_bios, bio);
		else {
			inc_all_io_entry(info->tc->pool, bio);

			/*
			 * We can't issue the bios with the bio prison lock
			 * held, so we add them to a list to issue on
			 * return from this function.
			 */
			bio_list_add(&info->issue_bios, bio);
		}
	}
}

static void inc_remap_and_issue_cell(struct thin_c *tc,
				     struct dm_bio_prison_cell *cell,
				     dm_block_t block)
{
	struct bio *bio;
	struct remap_info info;

	info.tc = tc;
	bio_list_init(&info.defer_bios);
	bio_list_init(&info.issue_bios);

	/*
	 * We have to be careful to inc any bios we're about to issue
	 * before the cell is released, and avoid a race with new bios
	 * being added to the cell.
	 */
	cell_visit_release(tc->pool, __inc_remap_and_issue_cell,
			   &info, cell);

	while ((bio = bio_list_pop(&info.defer_bios)))
		thin_defer_bio(tc, bio);

	while ((bio = bio_list_pop(&info.issue_bios)))
		remap_and_issue(info.tc, bio, block);
}

static void process_prepared_mapping_fail(struct dm_thin_new_mapping *m)
{
	cell_error(m->tc->pool, m->cell);
	list_del(&m->list);
	mempool_free(m, m->tc->pool->mapping_pool);
}

static void process_prepared_mapping(struct dm_thin_new_mapping *m)
{
	struct thin_c *tc = m->tc;
	struct pool *pool = tc->pool;
	struct bio *bio = m->bio;
	int r;

	if (m->err) {
		cell_error(pool, m->cell);
		goto out;
	}

	/*
	 * Commit the prepared block into the mapping btree.
	 * Any I/O for this block arriving after this point will get
	 * remapped to it directly.
	 */
	r = dm_thin_insert_block(tc->td, m->virt_begin, m->data_block);
	if (r) {
		metadata_operation_failed(pool, "dm_thin_insert_block", r);
		cell_error(pool, m->cell);
		goto out;
	}

	/*
	 * Release any bios held while the block was being provisioned.
	 * If we are processing a write bio that completely covers the block,
	 * we already processed it so can ignore it now when processing
	 * the bios in the cell.
	 */
	if (bio) {
		inc_remap_and_issue_cell(tc, m->cell, m->data_block);
		bio_endio(bio);
	} else {
		inc_all_io_entry(tc->pool, m->cell->holder);
		remap_and_issue(tc, m->cell->holder, m->data_block);
		inc_remap_and_issue_cell(tc, m->cell, m->data_block);
	}

out:
	list_del(&m->list);
	mempool_free(m, pool->mapping_pool);
}

/*----------------------------------------------------------------*/

static void free_discard_mapping(struct dm_thin_new_mapping *m)
{
	struct thin_c *tc = m->tc;
	if (m->cell)
		cell_defer_no_holder(tc, m->cell);
	mempool_free(m, tc->pool->mapping_pool);
}

static void process_prepared_discard_fail(struct dm_thin_new_mapping *m)
{
	bio_io_error(m->bio);
	free_discard_mapping(m);
}

static void process_prepared_discard_success(struct dm_thin_new_mapping *m)
{
	bio_endio(m->bio);
	free_discard_mapping(m);
}

static void process_prepared_discard_no_passdown(struct dm_thin_new_mapping *m)
{
	int r;
	struct thin_c *tc = m->tc;

	r = dm_thin_remove_range(tc->td, m->cell->key.block_begin, m->cell->key.block_end);
	if (r) {
		metadata_operation_failed(tc->pool, "dm_thin_remove_range", r);
		bio_io_error(m->bio);
	} else
		bio_endio(m->bio);

	cell_defer_no_holder(tc, m->cell);
	mempool_free(m, tc->pool->mapping_pool);
}

/*----------------------------------------------------------------*/

static void passdown_double_checking_shared_status(struct dm_thin_new_mapping *m,
						   struct bio *discard_parent)
{
	/*
	 * We've already unmapped this range of blocks, but before we
	 * passdown we have to check that these blocks are now unused.
	 */
	int r = 0;
	bool used = true;
	struct thin_c *tc = m->tc;
	struct pool *pool = tc->pool;
	dm_block_t b = m->data_block, e, end = m->data_block + m->virt_end - m->virt_begin;
	struct discard_op op;

	begin_discard(&op, tc, discard_parent);
	while (b != end) {
		/* find start of unmapped run */
		for (; b < end; b++) {
			r = dm_pool_block_is_used(pool->pmd, b, &used);
			if (r)
				goto out;

			if (!used)
				break;
		}

		if (b == end)
			break;

		/* find end of run */
		for (e = b + 1; e != end; e++) {
			r = dm_pool_block_is_used(pool->pmd, e, &used);
			if (r)
				goto out;

			if (used)
				break;
		}

		r = issue_discard(&op, b, e);
		if (r)
			goto out;

		b = e;
	}
out:
	end_discard(&op, r);
}

static void queue_passdown_pt2(struct dm_thin_new_mapping *m)
{
	unsigned long flags;
	struct pool *pool = m->tc->pool;

	spin_lock_irqsave(&pool->lock, flags);
	list_add_tail(&m->list, &pool->prepared_discards_pt2);
	spin_unlock_irqrestore(&pool->lock, flags);
	wake_worker(pool);
}

static void passdown_endio(struct bio *bio)
{
	/*
	 * It doesn't matter if the passdown discard failed, we still want
	 * to unmap (we ignore err).
	 */
	queue_passdown_pt2(bio->bi_private);
}

static void process_prepared_discard_passdown_pt1(struct dm_thin_new_mapping *m)
{
	int r;
	struct thin_c *tc = m->tc;
	struct pool *pool = tc->pool;
	struct bio *discard_parent;
	dm_block_t data_end = m->data_block + (m->virt_end - m->virt_begin);

	/*
	 * Only this thread allocates blocks, so we can be sure that the
	 * newly unmapped blocks will not be allocated before the end of
	 * the function.
	 */
	r = dm_thin_remove_range(tc->td, m->virt_begin, m->virt_end);
	if (r) {
		metadata_operation_failed(pool, "dm_thin_remove_range", r);
		bio_io_error(m->bio);
		cell_defer_no_holder(tc, m->cell);
		mempool_free(m, pool->mapping_pool);
		return;
	}

	discard_parent = bio_alloc(GFP_NOIO, 1);
	if (!discard_parent) {
		DMWARN("%s: unable to allocate top level discard bio for passdown. Skipping passdown.",
		       dm_device_name(tc->pool->pool_md));
		queue_passdown_pt2(m);

	} else {
		discard_parent->bi_end_io = passdown_endio;
		discard_parent->bi_private = m;

		if (m->maybe_shared)
			passdown_double_checking_shared_status(m, discard_parent);
		else {
			struct discard_op op;

			begin_discard(&op, tc, discard_parent);
			r = issue_discard(&op, m->data_block, data_end);
			end_discard(&op, r);
		}
	}

	/*
	 * Increment the unmapped blocks.  This prevents a race between the
	 * passdown io and reallocation of freed blocks.
	 */
	r = dm_pool_inc_data_range(pool->pmd, m->data_block, data_end);
	if (r) {
		metadata_operation_failed(pool, "dm_pool_inc_data_range", r);
		bio_io_error(m->bio);
		cell_defer_no_holder(tc, m->cell);
		mempool_free(m, pool->mapping_pool);
		return;
	}
}

static void process_prepared_discard_passdown_pt2(struct dm_thin_new_mapping *m)
{
	int r;
	struct thin_c *tc = m->tc;
	struct pool *pool = tc->pool;

	/*
	 * The passdown has completed, so now we can decrement all those
	 * unmapped blocks.
	 */
	r = dm_pool_dec_data_range(pool->pmd, m->data_block,
				   m->data_block + (m->virt_end - m->virt_begin));
	if (r) {
		metadata_operation_failed(pool, "dm_pool_dec_data_range", r);
		bio_io_error(m->bio);
	} else
		bio_endio(m->bio);

	cell_defer_no_holder(tc, m->cell);
	mempool_free(m, pool->mapping_pool);
}

static void process_prepared(struct pool *pool, struct list_head *head,
			     process_mapping_fn *fn)
{
	unsigned long flags;
	struct list_head maps;
	struct dm_thin_new_mapping *m, *tmp;

	INIT_LIST_HEAD(&maps);
	spin_lock_irqsave(&pool->lock, flags);
	list_splice_init(head, &maps);
	spin_unlock_irqrestore(&pool->lock, flags);

	list_for_each_entry_safe(m, tmp, &maps, list)
		(*fn)(m);
}

/*
 * Deferred bio jobs.
 */
static int io_overlaps_block(struct pool *pool, struct bio *bio)
{
	return bio->bi_iter.bi_size ==
		(pool->sectors_per_block << SECTOR_SHIFT);
}

static int io_overwrites_block(struct pool *pool, struct bio *bio)
{
	return (bio_data_dir(bio) == WRITE) &&
		io_overlaps_block(pool, bio);
}

static void save_and_set_endio(struct bio *bio, bio_end_io_t **save,
			       bio_end_io_t *fn)
{
	*save = bio->bi_end_io;
	bio->bi_end_io = fn;
}

static int ensure_next_mapping(struct pool *pool)
{
	if (pool->next_mapping)
		return 0;

	pool->next_mapping = mempool_alloc(pool->mapping_pool, GFP_ATOMIC);

	return pool->next_mapping ? 0 : -ENOMEM;
}

static struct dm_thin_new_mapping *get_next_mapping(struct pool *pool)
{
	struct dm_thin_new_mapping *m = pool->next_mapping;

	BUG_ON(!pool->next_mapping);

	memset(m, 0, sizeof(struct dm_thin_new_mapping));
	INIT_LIST_HEAD(&m->list);
	m->bio = NULL;

	pool->next_mapping = NULL;

	return m;
}

static void ll_zero(struct thin_c *tc, struct dm_thin_new_mapping *m,
		    sector_t begin, sector_t end)
{
	int r;
	struct dm_io_region to;

	to.bdev = tc->pool_dev->bdev;
	to.sector = begin;
	to.count = end - begin;

	r = dm_kcopyd_zero(tc->pool->copier, 1, &to, 0, copy_complete, m);
	if (r < 0) {
		DMERR_LIMIT("dm_kcopyd_zero() failed");
		copy_complete(1, 1, m);
	}
}

/*
 * A partial copy also needs to zero the uncopied region.
 */
static void schedule_copy(struct thin_c *tc, dm_block_t virt_block,
			  struct dm_dev *origin, dm_block_t data_origin,
			  dm_block_t data_dest,
			  struct dm_bio_prison_cell *cell, struct bio *bio,
			  sector_t len)
{
	int r;
	struct pool *pool = tc->pool;
	struct dm_thin_new_mapping *m = get_next_mapping(pool);

	m->tc = tc;
	m->virt_begin = virt_block;
	m->virt_end = virt_block + 1u;
	m->data_block = data_dest;
	m->cell = cell;

	/*
	 * quiesce action + copy action + an extra reference held for the
	 * duration of this function (we may need to inc later for a
	 * partial zero).
	 */
	atomic_set(&m->prepare_actions, 3);

	if (!dm_deferred_set_add_work(pool->shared_read_ds, &m->list))
		complete_mapping_preparation(m); /* already quiesced */

	/*
	 * IO to pool_dev remaps to the pool target's data_dev.
	 *
	 * If the whole block of data is being overwritten, we can issue the
	 * bio immediately. Otherwise we use kcopyd to clone the data first.
	 */
	if (io_overwrites_block(pool, bio))
		remap_and_issue_overwrite(tc, bio, data_dest, m);
	else {
		struct dm_io_region from, to;

		from.bdev = origin->bdev;
		from.sector = data_origin * pool->sectors_per_block;
		from.count = len;

		to.bdev = tc->pool_dev->bdev;
		to.sector = data_dest * pool->sectors_per_block;
		to.count = len;

		r = dm_kcopyd_copy(pool->copier, &from, 1, &to,
				   0, copy_complete, m);
		if (r < 0) {
			DMERR_LIMIT("dm_kcopyd_copy() failed");
			copy_complete(1, 1, m);

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
			atomic_inc(&m->prepare_actions);
			ll_zero(tc, m,
				data_dest * pool->sectors_per_block + len,
				(data_dest + 1) * pool->sectors_per_block);
		}
	}

	complete_mapping_preparation(m); /* drop our ref */
}

static void schedule_internal_copy(struct thin_c *tc, dm_block_t virt_block,
				   dm_block_t data_origin, dm_block_t data_dest,
				   struct dm_bio_prison_cell *cell, struct bio *bio)
{
	schedule_copy(tc, virt_block, tc->pool_dev,
		      data_origin, data_dest, cell, bio,
		      tc->pool->sectors_per_block);
}

static void schedule_zero(struct thin_c *tc, dm_block_t virt_block,
			  dm_block_t data_block, struct dm_bio_prison_cell *cell,
			  struct bio *bio)
{
	struct pool *pool = tc->pool;
	struct dm_thin_new_mapping *m = get_next_mapping(pool);

	atomic_set(&m->prepare_actions, 1); /* no need to quiesce */
	m->tc = tc;
	m->virt_begin = virt_block;
	m->virt_end = virt_block + 1u;
	m->data_block = data_block;
	m->cell = cell;

	/*
	 * If the whole block of data is being overwritten or we are not
	 * zeroing pre-existing data, we can issue the bio immediately.
	 * Otherwise we use kcopyd to zero the data first.
	 */
	if (pool->pf.zero_new_blocks) {
		if (io_overwrites_block(pool, bio))
			remap_and_issue_overwrite(tc, bio, data_block, m);
		else
			ll_zero(tc, m, data_block * pool->sectors_per_block,
				(data_block + 1) * pool->sectors_per_block);
	} else
		process_prepared_mapping(m);
}

static void schedule_external_copy(struct thin_c *tc, dm_block_t virt_block,
				   dm_block_t data_dest,
				   struct dm_bio_prison_cell *cell, struct bio *bio)
{
	struct pool *pool = tc->pool;
	sector_t virt_block_begin = virt_block * pool->sectors_per_block;
	sector_t virt_block_end = (virt_block + 1) * pool->sectors_per_block;

	if (virt_block_end <= tc->origin_size)
		schedule_copy(tc, virt_block, tc->origin_dev,
			      virt_block, data_dest, cell, bio,
			      pool->sectors_per_block);

	else if (virt_block_begin < tc->origin_size)
		schedule_copy(tc, virt_block, tc->origin_dev,
			      virt_block, data_dest, cell, bio,
			      tc->origin_size - virt_block_begin);

	else
		schedule_zero(tc, virt_block, data_dest, cell, bio);
}

static void check_for_space(struct pool *pool)
{
	int r;
	dm_block_t nr_free;

	if (get_pool_mode(pool) != PM_OUT_OF_DATA_SPACE)
		return;

	r = dm_pool_get_free_block_count(pool->pmd, &nr_free);
	if (r)
		return;

	if (nr_free)
		set_pool_mode(pool, PM_WRITE);
}

/*
 * A non-zero return indicates read_only or fail_io mode.
 * Many callers don't care about the return value.
 */
int commit(struct pool *pool)
{
	int r;

	if (get_pool_mode(pool) >= PM_READ_ONLY)
		return -EINVAL;

	r = dm_pool_commit_metadata(pool->pmd);
	if (r)
		metadata_operation_failed(pool, "dm_pool_commit_metadata", r);
	else
		check_for_space(pool);

	return r;
}

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

static int alloc_data_block(struct thin_c *tc, dm_block_t *result)
{
	int r;
	dm_block_t free_blocks;
	struct pool *pool = tc->pool;

	if (WARN_ON(get_pool_mode(pool) != PM_WRITE))
		return -EINVAL;

	r = dm_pool_get_free_block_count(pool->pmd, &free_blocks);
	if (r) {
		metadata_operation_failed(pool, "dm_pool_get_free_block_count", r);
		return r;
	}

	check_low_water_mark(pool, free_blocks);

	if (!free_blocks) {
		/*
		 * Try to commit to see if that will free up some
		 * more space.
		 */
		r = commit(pool);
		if (r)
			return r;

		r = dm_pool_get_free_block_count(pool->pmd, &free_blocks);
		if (r) {
			metadata_operation_failed(pool, "dm_pool_get_free_block_count", r);
			return r;
		}

		if (!free_blocks) {
			set_pool_mode(pool, PM_OUT_OF_DATA_SPACE);
			return -ENOSPC;
		}
	}

	r = dm_pool_alloc_data_block(pool->pmd, result);
	if (r) {
		metadata_operation_failed(pool, "dm_pool_alloc_data_block", r);
		return r;
	}

	return 0;
}

/*
 * If we have run out of space, queue bios until the device is
 * resumed, presumably after having been reloaded with more space.
 */
static void retry_on_resume(struct bio *bio)
{
	struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));
	struct thin_c *tc = h->tc;
	unsigned long flags;

	spin_lock_irqsave(&tc->lock, flags);
	bio_list_add(&tc->retry_on_resume_list, bio);
	spin_unlock_irqrestore(&tc->lock, flags);
}

static int should_error_unserviceable_bio(struct pool *pool)
{
	enum pool_mode m = get_pool_mode(pool);

	switch (m) {
	case PM_WRITE:
		/* Shouldn't get here */
		DMERR_LIMIT("bio unserviceable, yet pool is in PM_WRITE mode");
		return -EIO;

	case PM_OUT_OF_DATA_SPACE:
		return pool->pf.error_if_no_space ? -ENOSPC : 0;

	case PM_READ_ONLY:
	case PM_FAIL:
		return -EIO;
	default:
		/* Shouldn't get here */
		DMERR_LIMIT("bio unserviceable, yet pool has an unknown mode");
		return -EIO;
	}
}

static void handle_unserviceable_bio(struct pool *pool, struct bio *bio)
{
	int error = should_error_unserviceable_bio(pool);

	if (error) {
		bio->bi_error = error;
		bio_endio(bio);
	} else
		retry_on_resume(bio);
}

static void retry_bios_on_resume(struct pool *pool, struct dm_bio_prison_cell *cell)
{
	struct bio *bio;
	struct bio_list bios;
	int error;

	error = should_error_unserviceable_bio(pool);
	if (error) {
		cell_error_with_code(pool, cell, error);
		return;
	}

	bio_list_init(&bios);
	cell_release(pool, cell, &bios);

	while ((bio = bio_list_pop(&bios)))
		retry_on_resume(bio);
}

static void process_discard_cell_no_passdown(struct thin_c *tc,
					     struct dm_bio_prison_cell *virt_cell)
{
	struct pool *pool = tc->pool;
	struct dm_thin_new_mapping *m = get_next_mapping(pool);

	/*
	 * We don't need to lock the data blocks, since there's no
	 * passdown.  We only lock data blocks for allocation and breaking sharing.
	 */
	m->tc = tc;
	m->virt_begin = virt_cell->key.block_begin;
	m->virt_end = virt_cell->key.block_end;
	m->cell = virt_cell;
	m->bio = virt_cell->holder;

	if (!dm_deferred_set_add_work(pool->all_io_ds, &m->list))
		pool->process_prepared_discard(m);
}

static void break_up_discard_bio(struct thin_c *tc, dm_block_t begin, dm_block_t end,
				 struct bio *bio)
{
	struct pool *pool = tc->pool;

	int r;
	bool maybe_shared;
	struct dm_cell_key data_key;
	struct dm_bio_prison_cell *data_cell;
	struct dm_thin_new_mapping *m;
	dm_block_t virt_begin, virt_end, data_begin;

	while (begin != end) {
		r = ensure_next_mapping(pool);
		if (r)
			/* we did our best */
			return;

		r = dm_thin_find_mapped_range(tc->td, begin, end, &virt_begin, &virt_end,
					      &data_begin, &maybe_shared);
		if (r)
			/*
			 * Silently fail, letting any mappings we've
			 * created complete.
			 */
			break;

		build_key(tc->td, PHYSICAL, data_begin, data_begin + (virt_end - virt_begin), &data_key);
		if (bio_detain(tc->pool, &data_key, NULL, &data_cell)) {
			/* contention, we'll give up with this range */
			begin = virt_end;
			continue;
		}

		/*
		 * IO may still be going to the destination block.  We must
		 * quiesce before we can do the removal.
		 */
		m = get_next_mapping(pool);
		m->tc = tc;
		m->maybe_shared = maybe_shared;
		m->virt_begin = virt_begin;
		m->virt_end = virt_end;
		m->data_block = data_begin;
		m->cell = data_cell;
		m->bio = bio;

		/*
		 * The parent bio must not complete before sub discard bios are
		 * chained to it (see end_discard's bio_chain)!
		 *
		 * This per-mapping bi_remaining increment is paired with
		 * the implicit decrement that occurs via bio_endio() in
		 * end_discard().
		 */
		bio_inc_remaining(bio);
		if (!dm_deferred_set_add_work(pool->all_io_ds, &m->list))
			pool->process_prepared_discard(m);

		begin = virt_end;
	}
}

static void process_discard_cell_passdown(struct thin_c *tc, struct dm_bio_prison_cell *virt_cell)
{
	struct bio *bio = virt_cell->holder;
	struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));

	/*
	 * The virt_cell will only get freed once the origin bio completes.
	 * This means it will remain locked while all the individual
	 * passdown bios are in flight.
	 */
	h->cell = virt_cell;
	break_up_discard_bio(tc, virt_cell->key.block_begin, virt_cell->key.block_end, bio);

	/*
	 * We complete the bio now, knowing that the bi_remaining field
	 * will prevent completion until the sub range discards have
	 * completed.
	 */
	bio_endio(bio);
}

static void process_discard_bio(struct thin_c *tc, struct bio *bio)
{
	dm_block_t begin, end;
	struct dm_cell_key virt_key;
	struct dm_bio_prison_cell *virt_cell;

	get_bio_block_range(tc, bio, &begin, &end);
	if (begin == end) {
		/*
		 * The discard covers less than a block.
		 */
		bio_endio(bio);
		return;
	}

	build_key(tc->td, VIRTUAL, begin, end, &virt_key);
	if (bio_detain(tc->pool, &virt_key, bio, &virt_cell))
		/*
		 * Potential starvation issue: We're relying on the
		 * fs/application being well behaved, and not trying to
		 * send IO to a region at the same time as discarding it.
		 * If they do this persistently then it's possible this
		 * cell will never be granted.
		 */
		return;

	tc->pool->process_discard_cell(tc, virt_cell);
}

#if 0
static void break_sharing(struct thin_c *tc, struct bio *bio, dm_block_t block,
			  struct dm_cell_key *key,
			  struct dm_thin_lookup_result *lookup_result,
			  struct dm_bio_prison_cell *cell)
{
	int r;
	dm_block_t data_block;
	struct pool *pool = tc->pool;

	r = alloc_data_block(tc, &data_block);
	switch (r) {
	case 0:
		schedule_internal_copy(tc, block, lookup_result->block,
				       data_block, cell, bio);
		break;

	case -ENOSPC:
		retry_bios_on_resume(pool, cell);
		break;

	default:
		DMERR_LIMIT("%s: alloc_data_block() failed: error = %d",
			    __func__, r);
		cell_error(pool, cell);
		break;
	}
}
#endif

static void __remap_and_issue_shared_cell(void *context,
					  struct dm_bio_prison_cell *cell)
{
	struct remap_info *info = context;
	struct bio *bio;

	while ((bio = bio_list_pop(&cell->bios))) {
		if ((bio_data_dir(bio) == WRITE) ||
		    (bio->bi_opf & (REQ_PREFLUSH | REQ_FUA) ||
		     bio_op(bio) == REQ_OP_DISCARD))
			bio_list_add(&info->defer_bios, bio);
		else {
			struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));;

			h->shared_read_entry = dm_deferred_entry_inc(info->tc->pool->shared_read_ds);
			inc_all_io_entry(info->tc->pool, bio);
			bio_list_add(&info->issue_bios, bio);
		}
	}
}

static void remap_and_issue_shared_cell(struct thin_c *tc,
					struct dm_bio_prison_cell *cell,
					dm_block_t block)
{
	struct bio *bio;
	struct remap_info info;

	info.tc = tc;
	bio_list_init(&info.defer_bios);
	bio_list_init(&info.issue_bios);

	cell_visit_release(tc->pool, __remap_and_issue_shared_cell,
			   &info, cell);

	while ((bio = bio_list_pop(&info.defer_bios)))
		thin_defer_bio(tc, bio);

	while ((bio = bio_list_pop(&info.issue_bios)))
		remap_and_issue(tc, bio, block);
}

static void process_shared_bio(struct thin_c *tc, struct bio *bio,
			       dm_block_t block,
			       struct dm_thin_lookup_result *lookup_result,
			       struct dm_bio_prison_cell *virt_cell)
{
	struct dm_bio_prison_cell *data_cell;
	struct pool *pool = tc->pool;
	struct dm_cell_key key;

	/*
	 * If cell is already occupied, then sharing is already in the process
	 * of being broken so we have nothing further to do here.
	 */
	build_data_key(tc->td, lookup_result->block, &key);
	if (bio_detain(pool, &key, bio, &data_cell)) {
		cell_defer_no_holder(tc, virt_cell);
		return;
	}

	if (bio_data_dir(bio) == WRITE && bio->bi_iter.bi_size) {
		break_sharing(tc, bio, block, &key, lookup_result, data_cell);
		cell_defer_no_holder(tc, virt_cell);
	} else {
		struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));

		h->shared_read_entry = dm_deferred_entry_inc(pool->shared_read_ds);
		inc_all_io_entry(pool, bio);
		remap_and_issue(tc, bio, lookup_result->block);

		remap_and_issue_shared_cell(tc, data_cell, lookup_result->block);
		remap_and_issue_shared_cell(tc, virt_cell, lookup_result->block);
	}
}

static void provision_block(struct thin_c *tc, struct bio *bio, dm_block_t block,
			    struct dm_bio_prison_cell *cell)
{
	int r;
	dm_block_t data_block;
	struct pool *pool = tc->pool;

	/*
	 * Remap empty bios (flushes) immediately, without provisioning.
	 */
	if (!bio->bi_iter.bi_size) {
		inc_all_io_entry(pool, bio);
		cell_defer_no_holder(tc, cell);

		remap_and_issue(tc, bio, 0);
		return;
	}

	/*
	 * Fill read bios with zeroes and complete them immediately.
	 */
	if (bio_data_dir(bio) == READ) {
		zero_fill_bio(bio);
		cell_defer_no_holder(tc, cell);
		bio_endio(bio);
		return;
	}

	r = alloc_data_block(tc, &data_block);
	switch (r) {
	case 0:
		if (tc->origin_dev)
			schedule_external_copy(tc, block, data_block, cell, bio);
		else
			schedule_zero(tc, block, data_block, cell, bio);
		break;

	case -ENOSPC:
		retry_bios_on_resume(pool, cell);
		break;

	default:
		DMERR_LIMIT("%s: alloc_data_block() failed: error = %d",
			    __func__, r);
		cell_error(pool, cell);
		break;
	}
}

static void process_cell(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	int r;
	struct pool *pool = tc->pool;
	struct bio *bio = cell->holder;
	dm_block_t block = get_bio_block(tc, bio);
	struct dm_thin_lookup_result lookup_result;

	if (tc->requeue_mode) {
		cell_requeue(pool, cell);
		return;
	}

	r = dm_thin_find_block(tc->td, block, 1, &lookup_result);
	switch (r) {
	case 0:
		if (lookup_result.shared)
			process_shared_bio(tc, bio, block, &lookup_result, cell);
		else {
			inc_all_io_entry(pool, bio);
			remap_and_issue(tc, bio, lookup_result.block);
			inc_remap_and_issue_cell(tc, cell, lookup_result.block);
		}
		break;

	case -ENODATA:
		if (bio_data_dir(bio) == READ && tc->origin_dev) {
			inc_all_io_entry(pool, bio);
			cell_defer_no_holder(tc, cell);

			if (bio_end_sector(bio) <= tc->origin_size)
				remap_to_origin_and_issue(tc, bio);

			else if (bio->bi_iter.bi_sector < tc->origin_size) {
				zero_fill_bio(bio);
				bio->bi_iter.bi_size = (tc->origin_size - bio->bi_iter.bi_sector) << SECTOR_SHIFT;
				remap_to_origin_and_issue(tc, bio);

			} else {
				zero_fill_bio(bio);
				bio_endio(bio);
			}
		} else
			provision_block(tc, bio, block, cell);
		break;

	default:
		DMERR_LIMIT("%s: dm_thin_find_block() failed: error = %d",
			    __func__, r);
		cell_defer_no_holder(tc, cell);
		bio_io_error(bio);
		break;
	}
}

static void process_bio(struct thin_c *tc, struct bio *bio)
{
	struct pool *pool = tc->pool;
	dm_block_t block = get_bio_block(tc, bio);
	struct dm_bio_prison_cell *cell;
	struct dm_cell_key key;

	/*
	 * If cell is already occupied, then the block is already
	 * being provisioned so we have nothing further to do here.
	 */
	build_virtual_key(tc->td, block, &key);
	if (bio_detain(pool, &key, bio, &cell))
		return;

	process_cell(tc, cell);
}

static void __process_bio_read_only(struct thin_c *tc, struct bio *bio,
				    struct dm_bio_prison_cell *cell)
{
	int r;
	int rw = bio_data_dir(bio);
	dm_block_t block = get_bio_block(tc, bio);
	struct dm_thin_lookup_result lookup_result;

	r = dm_thin_find_block(tc->td, block, 1, &lookup_result);
	switch (r) {
	case 0:
		if (lookup_result.shared && (rw == WRITE) && bio->bi_iter.bi_size) {
			handle_unserviceable_bio(tc->pool, bio);
			if (cell)
				cell_defer_no_holder(tc, cell);
		} else {
			inc_all_io_entry(tc->pool, bio);
			remap_and_issue(tc, bio, lookup_result.block);
			if (cell)
				inc_remap_and_issue_cell(tc, cell, lookup_result.block);
		}
		break;

	case -ENODATA:
		if (cell)
			cell_defer_no_holder(tc, cell);
		if (rw != READ) {
			handle_unserviceable_bio(tc->pool, bio);
			break;
		}

		if (tc->origin_dev) {
			inc_all_io_entry(tc->pool, bio);
			remap_to_origin_and_issue(tc, bio);
			break;
		}

		zero_fill_bio(bio);
		bio_endio(bio);
		break;

	default:
		DMERR_LIMIT("%s: dm_thin_find_block() failed: error = %d",
			    __func__, r);
		if (cell)
			cell_defer_no_holder(tc, cell);
		bio_io_error(bio);
		break;
	}
}

static void process_bio_read_only(struct thin_c *tc, struct bio *bio)
{
	__process_bio_read_only(tc, bio, NULL);
}

static void process_cell_read_only(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	__process_bio_read_only(tc, cell->holder, cell);
}

static void process_bio_success(struct thin_c *tc, struct bio *bio)
{
	bio_endio(bio);
}

static void process_bio_fail(struct thin_c *tc, struct bio *bio)
{
	bio_io_error(bio);
}

static void process_cell_success(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	cell_success(tc->pool, cell);
}

static void process_cell_fail(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	cell_error(tc->pool, cell);
}

/*
 * FIXME: should we also commit due to size of transaction, measured in
 * metadata blocks?
 */
static int need_commit_due_to_time(struct pool *pool)
{
	return !time_in_range(jiffies, pool->last_commit_jiffies,
			      pool->last_commit_jiffies + COMMIT_PERIOD);
}

#define thin_pbd(node) rb_entry((node), struct dm_thin_endio_hook, rb_node)
#define thin_bio(pbd) dm_bio_from_per_bio_data((pbd), sizeof(struct dm_thin_endio_hook))

static void __thin_bio_rb_add(struct thin_c *tc, struct bio *bio)
{
	struct rb_node **rbp, *parent;
	struct dm_thin_endio_hook *pbd;
	sector_t bi_sector = bio->bi_iter.bi_sector;

	rbp = &tc->sort_bio_list.rb_node;
	parent = NULL;
	while (*rbp) {
		parent = *rbp;
		pbd = thin_pbd(parent);

		if (bi_sector < thin_bio(pbd)->bi_iter.bi_sector)
			rbp = &(*rbp)->rb_left;
		else
			rbp = &(*rbp)->rb_right;
	}

	pbd = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));
	rb_link_node(&pbd->rb_node, parent, rbp);
	rb_insert_color(&pbd->rb_node, &tc->sort_bio_list);
}

static void __extract_sorted_bios(struct thin_c *tc)
{
	struct rb_node *node;
	struct dm_thin_endio_hook *pbd;
	struct bio *bio;

	for (node = rb_first(&tc->sort_bio_list); node; node = rb_next(node)) {
		pbd = thin_pbd(node);
		bio = thin_bio(pbd);

		bio_list_add(&tc->deferred_bio_list, bio);
		rb_erase(&pbd->rb_node, &tc->sort_bio_list);
	}

	WARN_ON(!RB_EMPTY_ROOT(&tc->sort_bio_list));
}

static void __sort_thin_deferred_bios(struct thin_c *tc)
{
	struct bio *bio;
	struct bio_list bios;

	bio_list_init(&bios);
	bio_list_merge(&bios, &tc->deferred_bio_list);
	bio_list_init(&tc->deferred_bio_list);

	/* Sort deferred_bio_list using rb-tree */
	while ((bio = bio_list_pop(&bios)))
		__thin_bio_rb_add(tc, bio);

	/*
	 * Transfer the sorted bios in sort_bio_list back to
	 * deferred_bio_list to allow lockless submission of
	 * all bios.
	 */
	__extract_sorted_bios(tc);
}

static void process_thin_deferred_bios(struct thin_c *tc)
{
	struct pool *pool = tc->pool;
	unsigned long flags;
	struct bio *bio;
	struct bio_list bios;
	struct blk_plug plug;
	unsigned count = 0;

	if (tc->requeue_mode) {
		error_thin_bio_list(tc, &tc->deferred_bio_list, DM_ENDIO_REQUEUE);
		return;
	}

	bio_list_init(&bios);

	spin_lock_irqsave(&tc->lock, flags);

	if (bio_list_empty(&tc->deferred_bio_list)) {
		spin_unlock_irqrestore(&tc->lock, flags);
		return;
	}

	__sort_thin_deferred_bios(tc);

	bio_list_merge(&bios, &tc->deferred_bio_list);
	bio_list_init(&tc->deferred_bio_list);

	spin_unlock_irqrestore(&tc->lock, flags);

	blk_start_plug(&plug);
	while ((bio = bio_list_pop(&bios))) {
		/*
		 * If we've got no free new_mapping structs, and processing
		 * this bio might require one, we pause until there are some
		 * prepared mappings to process.
		 */
		if (ensure_next_mapping(pool)) {
			spin_lock_irqsave(&tc->lock, flags);
			bio_list_add(&tc->deferred_bio_list, bio);
			bio_list_merge(&tc->deferred_bio_list, &bios);
			spin_unlock_irqrestore(&tc->lock, flags);
			break;
		}

		if (bio_op(bio) == REQ_OP_DISCARD)
			pool->process_discard(tc, bio);
		else
			pool->process_bio(tc, bio);

		if ((count++ & 127) == 0) {
			throttle_work_update(&pool->throttle);
			dm_pool_issue_prefetches(pool->pmd);
		}
	}
	blk_finish_plug(&plug);
}

static int cmp_cells(const void *lhs, const void *rhs)
{
	struct dm_bio_prison_cell *lhs_cell = *((struct dm_bio_prison_cell **) lhs);
	struct dm_bio_prison_cell *rhs_cell = *((struct dm_bio_prison_cell **) rhs);

	BUG_ON(!lhs_cell->holder);
	BUG_ON(!rhs_cell->holder);

	if (lhs_cell->holder->bi_iter.bi_sector < rhs_cell->holder->bi_iter.bi_sector)
		return -1;

	if (lhs_cell->holder->bi_iter.bi_sector > rhs_cell->holder->bi_iter.bi_sector)
		return 1;

	return 0;
}

static unsigned sort_cells(struct pool *pool, struct list_head *cells)
{
	unsigned count = 0;
	struct dm_bio_prison_cell *cell, *tmp;

	list_for_each_entry_safe(cell, tmp, cells, user_list) {
		if (count >= CELL_SORT_ARRAY_SIZE)
			break;

		pool->cell_sort_array[count++] = cell;
		list_del(&cell->user_list);
	}

	sort(pool->cell_sort_array, count, sizeof(cell), cmp_cells, NULL);

	return count;
}

static void process_thin_deferred_cells(struct thin_c *tc)
{
	struct pool *pool = tc->pool;
	unsigned long flags;
	struct list_head cells;
	struct dm_bio_prison_cell *cell;
	unsigned i, j, count;

	INIT_LIST_HEAD(&cells);

	spin_lock_irqsave(&tc->lock, flags);
	list_splice_init(&tc->deferred_cells, &cells);
	spin_unlock_irqrestore(&tc->lock, flags);

	if (list_empty(&cells))
		return;

	do {
		count = sort_cells(tc->pool, &cells);

		for (i = 0; i < count; i++) {
			cell = pool->cell_sort_array[i];
			BUG_ON(!cell->holder);

			/*
			 * If we've got no free new_mapping structs, and processing
			 * this bio might require one, we pause until there are some
			 * prepared mappings to process.
			 */
			if (ensure_next_mapping(pool)) {
				for (j = i; j < count; j++)
					list_add(&pool->cell_sort_array[j]->user_list, &cells);

				spin_lock_irqsave(&tc->lock, flags);
				list_splice(&cells, &tc->deferred_cells);
				spin_unlock_irqrestore(&tc->lock, flags);
				return;
			}

			if (bio_op(cell->holder) == REQ_OP_DISCARD)
				pool->process_discard_cell(tc, cell);
			else
				pool->process_cell(tc, cell);
		}
	} while (!list_empty(&cells));
}

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

static void process_deferred_bios(struct pool *pool)
{
	unsigned long flags;
	struct bio *bio;
	struct bio_list bios;
	struct thin_c *tc;

	tc = get_first_thin(pool);
	while (tc) {
		process_thin_deferred_cells(tc);
		process_thin_deferred_bios(tc);
		tc = get_next_thin(pool, tc);
	}

	/*
	 * If there are any deferred flush bios, we must commit
	 * the metadata before issuing them.
	 */
	bio_list_init(&bios);
	spin_lock_irqsave(&pool->lock, flags);
	bio_list_merge(&bios, &pool->deferred_flush_bios);
	bio_list_init(&pool->deferred_flush_bios);
	spin_unlock_irqrestore(&pool->lock, flags);

	if (bio_list_empty(&bios) &&
	    !(dm_pool_changed_this_transaction(pool->pmd) && need_commit_due_to_time(pool)))
		return;

	if (commit(pool)) {
		while ((bio = bio_list_pop(&bios)))
			bio_io_error(bio);
		return;
	}
	pool->last_commit_jiffies = jiffies;

	while ((bio = bio_list_pop(&bios)))
		generic_make_request(bio);
}

static void do_worker(struct work_struct *ws)
{
	struct pool *pool = container_of(ws, struct pool, worker);

	throttle_work_start(&pool->throttle);
	dm_pool_issue_prefetches(pool->pmd);
	throttle_work_update(&pool->throttle);
	process_prepared(pool, &pool->prepared_mappings, &pool->process_prepared_mapping);
	throttle_work_update(&pool->throttle);
	process_prepared(pool, &pool->prepared_discards, &pool->process_prepared_discard);
	throttle_work_update(&pool->throttle);
	process_prepared(pool, &pool->prepared_discards_pt2, &pool->process_prepared_discard_pt2);
	throttle_work_update(&pool->throttle);
	process_deferred_bios(pool);
	throttle_work_complete(&pool->throttle);
}

/*
 * We want to commit periodically so that not too much
 * unwritten data builds up.
 */
void do_waker(struct work_struct *ws)
{
	struct pool *pool = container_of(to_delayed_work(ws), struct pool, waker);
	wake_worker(pool);
	queue_delayed_work(pool->wq, &pool->waker, COMMIT_PERIOD);
}

/*----------------------------------------------------------------*/

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
	requeue_io(w->tc);
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

static enum pool_mode get_pool_mode(struct pool *pool)
{
	return pool->pf.mode;
}

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

static bool passdown_enabled(struct pool_c *pt)
{
	return pt->adjusted_pf.discard_passdown;
}

static void set_discard_callbacks(struct pool *pool)
{
	struct pool_c *pt = pool->ti->private;

	if (passdown_enabled(pt)) {
		pool->process_discard_cell = process_discard_cell_passdown;
		pool->process_prepared_discard = process_prepared_discard_passdown_pt1;
		pool->process_prepared_discard_pt2 = process_prepared_discard_passdown_pt2;
	} else {
		pool->process_discard_cell = process_discard_cell_no_passdown;
		pool->process_prepared_discard = process_prepared_discard_no_passdown;
	}
}

static void set_pool_mode(struct pool *pool, enum pool_mode new_mode)
{
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

static void metadata_operation_failed(struct pool *pool, const char *op, int r)
{
	DMERR_LIMIT("%s: metadata operation '%s' failed: error = %d",
		    dm_device_name(pool->pool_md), op, r);

	abort_transaction(pool);
	set_pool_mode(pool, PM_READ_ONLY);
}

/*----------------------------------------------------------------*/

/*
 * Mapping functions.
 */

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

	wake_worker(pool);
}

static void thin_defer_bio_with_throttle(struct thin_c *tc, struct bio *bio)
{
	struct pool *pool = tc->pool;

	throttle_lock(&pool->throttle);
	thin_defer_bio(tc, bio);
	throttle_unlock(&pool->throttle);
}

static void thin_defer_cell(struct thin_c *tc, struct dm_bio_prison_cell *cell)
{
	unsigned long flags;
	struct pool *pool = tc->pool;

	throttle_lock(&pool->throttle);
	spin_lock_irqsave(&tc->lock, flags);
	list_add_tail(&cell->user_list, &tc->deferred_cells);
	spin_unlock_irqrestore(&tc->lock, flags);
	throttle_unlock(&pool->throttle);

	wake_worker(pool);
}

void requeue_bios(struct pool *pool)
{
	struct thin_c *tc;
	unsigned long flags;

	rcu_read_lock();
	list_for_each_entry_rcu(tc, &pool->active_thins, list) {
		spin_lock_irqsave(&tc->lock, flags);
		bio_list_merge(&tc->deferred_bio_list, &tc->retry_on_resume_list);
		bio_list_init(&tc->retry_on_resume_list);
		spin_unlock_irqrestore(&tc->lock, flags);
	}
	rcu_read_unlock();
}
#endif

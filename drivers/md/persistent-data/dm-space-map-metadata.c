#include "dm-space-map-metadata.h"

#include <linux/list.h>
#include <linux/slab.h>
#include <asm-generic/bitops/le.h>

#include "dm-space-map-common.h"
#include "dm-space-map-metadata.h"

/*----------------------------------------------------------------
 * Useful maths that should probably be somewhere else
 *--------------------------------------------------------------*/

static uint64_t div_up(uint64_t v, uint64_t n)
{
	uint64_t t = v;
	uint64_t rem = do_div(t, n);
	return t + (rem > 0 ? 1 : 0);
}

/*----------------------------------------------------------------
 * index validator
 *--------------------------------------------------------------*/

static void index_prepare_for_write(struct dm_block_validator *v,
				    struct dm_block *b,
				    size_t block_size)
{
}

static int index_check(struct dm_block_validator *v,
		       struct dm_block *b,
		       size_t block_size)
{
	return 0;
}

struct dm_block_validator index_validator_ = {
	.name = "index",
	.prepare_for_write = index_prepare_for_write,
	.check = index_check
};

/*----------------------------------------------------------------
 * low level disk ops
 *--------------------------------------------------------------*/
static int ll_init(struct ll_disk *ll, struct dm_transaction_manager *tm)
{
	ll->tm = tm;

	ll->ref_count_info.tm = tm;
	ll->ref_count_info.levels = 1;
	ll->ref_count_info.value_type.size = sizeof(uint32_t);
	ll->ref_count_info.value_type.copy = NULL;
	ll->ref_count_info.value_type.del = NULL;
	ll->ref_count_info.value_type.equal = NULL;

	ll->block_size = dm_bm_block_size(dm_tm_get_bm(tm));

	if (ll->block_size > (1 << 30)) {
		printk(KERN_ALERT "block size too big to hold bitmaps");
		return -EINVAL;
	}
	ll->entries_per_block = (ll->block_size - sizeof(struct bitmap_header)) *
		ENTRIES_PER_BYTE;
	ll->nr_blocks = 0;
	ll->bitmap_root = 0;
	ll->ref_count_root = 0;

	return 0;
}

static int ll_new(struct ll_disk *ll, struct dm_transaction_manager *tm,
		  dm_block_t nr_blocks)
{
	int r;
	dm_block_t i;
	unsigned blocks;

	r = ll_init(ll, tm);
	if (r < 0)
		return r;

	ll->nr_blocks = nr_blocks;
	ll->nr_allocated = 0;

	blocks = div_up(nr_blocks, ll->entries_per_block);
	for (i = 0; i < blocks; i++) {
		struct dm_block *b;
		struct index_entry *idx = ll->index + i;

		r = dm_tm_new_block(tm, &dm_sm_bitmap_validator, &b);
		if (r < 0)
			return r;
		idx->blocknr = __cpu_to_le64(dm_block_location(b));

		r = dm_tm_unlock(tm, b);
		if (r < 0)
			return r;

		idx->nr_free = __cpu_to_le32(ll->entries_per_block);
		idx->none_free_before = 0;
	}

	r = dm_tm_alloc_block(tm, &ll->bitmap_root);
	if (r)
		return r;

	r = dm_btree_empty(&ll->ref_count_info, &ll->ref_count_root);
	if (r < 0) {
		dm_tm_dec(tm, ll->bitmap_root);
		return r;
	}

	return 0;
}

static int ll_open(struct ll_disk *ll, struct dm_transaction_manager *tm,
		   void *root, size_t len)
{
	int r;
	struct sm_root *smr = (struct sm_root *) root;
	struct dm_block *block;

	if (len < sizeof(struct sm_root)) {
		printk(KERN_ALERT "sm_disk root too small");
		return -ENOMEM;
	}

	r = ll_init(ll, tm);
	if (r < 0)
		return r;

	ll->nr_blocks = __le64_to_cpu(smr->nr_blocks);
	ll->nr_allocated = __le64_to_cpu(smr->nr_allocated);

	ll->bitmap_root = __le64_to_cpu(smr->bitmap_root);

	r = dm_tm_read_lock(tm, __le64_to_cpu(smr->bitmap_root),
			    &index_validator_, &block);
	if (r)
		return r;
	memcpy(&ll->index, dm_block_data(block), sizeof(ll->index));
	r = dm_tm_unlock(tm, block);
	if (r)
		return r;

	ll->ref_count_root = __le64_to_cpu(smr->ref_count_root);
	return 0;
}

static int ll_lookup_bitmap(struct ll_disk *ll, dm_block_t b, uint32_t *result)
{
	int r;
	dm_block_t index = b;
	struct index_entry *ie;
	struct dm_block *blk;

	b = do_div(index, ll->entries_per_block);
	ie = ll->index + index;

	r = dm_tm_read_lock(ll->tm, __le64_to_cpu(ie->blocknr), &dm_sm_bitmap_validator, &blk);
	if (r < 0)
		return r;
	*result = sm__lookup_bitmap(dm_bitmap_data(blk), b);
	return dm_tm_unlock(ll->tm, blk);
}

static int ll_lookup(struct ll_disk *ll, dm_block_t b, uint32_t *result)
{
	int r = ll_lookup_bitmap(ll, b, result);

	if (r)
		return r;

	if (*result == 3) {
		__le32 le_rc;
		r = dm_btree_lookup(&ll->ref_count_info, ll->ref_count_root,
				    &b, &le_rc);
		if (r < 0)
			return r;

		*result = __le32_to_cpu(le_rc);
	}

	return r;
}

static int ll_find_free_block(struct ll_disk *ll, dm_block_t begin,
			      dm_block_t end, dm_block_t *result)
{
	int r;
	struct index_entry *ie;
	dm_block_t i, index_begin = begin;
	dm_block_t index_end = div_up(end, ll->entries_per_block);

	/* FIXME: use shifts */
	begin = do_div(index_begin, ll->entries_per_block);
	end = do_div(end, ll->entries_per_block);

	for (i = index_begin; i < index_end; i++, begin = 0) {
		ie = ll->index + i;

		if (__le32_to_cpu(ie->nr_free) > 0) {
			struct dm_block *blk;
			unsigned position;
			uint32_t bit_end = (i == index_end - 1) ? end : ll->entries_per_block;

			r = dm_tm_read_lock(ll->tm, __le64_to_cpu(ie->blocknr), &dm_sm_bitmap_validator, &blk);
			if (r < 0)
				return r;

			r = sm__find_free(dm_bitmap_data(blk), begin, bit_end, &position);
			if (r < 0) {
				dm_tm_unlock(ll->tm, blk);
				return r;
			}

			r = dm_tm_unlock(ll->tm, blk);
			if (r < 0)
				return r;

			*result = i * ll->entries_per_block + (dm_block_t) position;
			return 0;
		}
	}

	return -ENOSPC;
}

static int ll_insert(struct ll_disk *ll, dm_block_t b, uint32_t ref_count)
{
	int r;
	uint32_t bit, old;
	struct dm_block *nb;
	dm_block_t index = b;
	struct index_entry *ie;
	void *bm;
	int inc;

	bit = do_div(index, ll->entries_per_block);
	ie = ll->index + index;

	r = dm_tm_shadow_block(ll->tm, __le64_to_cpu(ie->blocknr), &dm_sm_bitmap_validator, &nb, &inc);
	if (r < 0) {
		printk(KERN_ALERT "shadow failed");
		return r;
	}
	ie->blocknr = __cpu_to_le64(dm_block_location(nb));

	bm = dm_bitmap_data(nb);
	old = sm__lookup_bitmap(bm, bit);

	if (ref_count <= 2) {
		sm__set_bitmap(bm, bit, ref_count);

		r = dm_tm_unlock(ll->tm, nb);
		if (r < 0)
			return r;

		if (old > 2) {
			r = dm_btree_remove(&ll->ref_count_info, ll->ref_count_root,
					    &b, &ll->ref_count_root);

			if (r) {
				sm__set_bitmap(bm, bit, old);
				return r;
			}
		}
	} else {
		__le32 le_rc = __cpu_to_le32(ref_count);
		sm__set_bitmap(bm, bit, 3);
		r = dm_tm_unlock(ll->tm, nb);
		if (r < 0)
			return r;

		r = dm_btree_insert(&ll->ref_count_info, ll->ref_count_root,
				    &b, &le_rc, &ll->ref_count_root);
		if (r < 0) {
			/* FIXME: release shadow? or assume the whole transaction will be ditched */
			printk(KERN_ALERT "ref count insert failed");
			return r;
		}
	}

	if (ref_count && !old) {
		ll->nr_allocated++;
		ie->nr_free = __cpu_to_le32(__le32_to_cpu(ie->nr_free) - 1);
		if (__le32_to_cpu(ie->none_free_before) == b)
			ie->none_free_before = __cpu_to_le32(b + 1);

	} else if (old && !ref_count) {
		ll->nr_allocated--;
		ie->nr_free = __cpu_to_le32(__le32_to_cpu(ie->nr_free) + 1);
		ie->none_free_before = __cpu_to_le32(min((dm_block_t) __le32_to_cpu(ie->none_free_before), b));
	}

	return 0;
}

static int ll_inc(struct ll_disk *ll, dm_block_t b)
{
	int r;
	uint32_t rc;

	r = ll_lookup(ll, b, &rc);
	if (r)
		return r;

	return ll_insert(ll, b, rc + 1);
}

static int ll_dec(struct ll_disk *ll, dm_block_t b)
{
	int r;
	uint32_t rc;

	r = ll_lookup(ll, b, &rc);
	if (r)
		return r;

	return rc ? ll_insert(ll, b, rc - 1) : -EINVAL;
}

static int ll_commit(struct ll_disk *ll)
{
	int r, inc;
	struct dm_block *b;

	r = dm_tm_shadow_block(ll->tm, ll->bitmap_root, &index_validator_, &b, &inc);
	if (r)
		return r;

	memcpy(dm_block_data(b), ll->index, sizeof(ll->index));
	ll->bitmap_root = dm_block_location(b);
	return dm_tm_unlock(ll->tm, b);
}

/*----------------------------------------------------------------
 * Space map interface.
 *
 * The low level disk format is written using the standard btree and
 * transaction manager.  This means that performing disk operations may
 * cause us to recurse into the space map in order to allocate new blocks.
 * For this reason we have a pool of pre-allocated blocks large enough to
 * service any ll_disk operation.
 *--------------------------------------------------------------*/

/*
 * FIXME: we should calculate this based on the size of the device.
 * Only the metadata space map needs this functionality.
 */
#define MAX_RECURSIVE_ALLOCATIONS 1024

enum block_op_type {
	BOP_INC,
	BOP_DEC
};

struct block_op {
	enum block_op_type type;
	dm_block_t block;
};

struct sm_metadata {
	struct dm_space_map sm;

	struct ll_disk ll;
	struct ll_disk old_ll;

	dm_block_t begin;

	unsigned recursion_count;
	unsigned allocated_this_transaction;
	unsigned nr_uncommitted;
	struct block_op uncommitted[MAX_RECURSIVE_ALLOCATIONS];
};

static int add_bop(struct sm_metadata *smm, enum block_op_type type, dm_block_t b)
{
	struct block_op *op;

	if (smm->nr_uncommitted == MAX_RECURSIVE_ALLOCATIONS) {
		BUG_ON(1);
		return -1;
	}

	op = smm->uncommitted + smm->nr_uncommitted++;
	op->type = type;
	op->block = b;
	return 0;
}

static int commit_bop(struct sm_metadata *smm, struct block_op *op)
{
	int r = 0;

	switch (op->type) {
	case BOP_INC:
		r = ll_inc(&smm->ll, op->block);
		break;

	case BOP_DEC:
		r = ll_dec(&smm->ll, op->block);
		break;
	}

	return r;
}

static void in(struct sm_metadata *smm)
{
	smm->recursion_count++;
}

static void out(struct sm_metadata *smm)
{
	int r = 0;
	BUG_ON(!smm->recursion_count);

	if (smm->recursion_count == 1 && smm->nr_uncommitted) {
		while (smm->nr_uncommitted && !r)
			r = commit_bop(smm, smm->uncommitted + --smm->nr_uncommitted);
	}

	smm->recursion_count--;
}

static void no_recurse(struct sm_metadata *smm)
{
	BUG_ON(smm->recursion_count);
}

static int recursing(struct sm_metadata *smm)
{
	return smm->recursion_count;
}

static void sm_metadata_destroy(struct dm_space_map *sm)
{
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);
	kfree(smm);
}

static int sm_metadata_extend(struct dm_space_map *sm, dm_block_t extra_blocks)
{
	BUG_ON(1);
	return -1;
}

static int sm_metadata_get_nr_blocks(struct dm_space_map *sm, dm_block_t *count)
{
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);
	*count = smm->ll.nr_blocks;
	return 0;
}

static int sm_metadata_get_nr_free(struct dm_space_map *sm, dm_block_t *count)
{
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);

	*count = smm->old_ll.nr_blocks - smm->old_ll.nr_allocated - smm->allocated_this_transaction;
	return 0;
}

static int sm_metadata_get_count(struct dm_space_map *sm, dm_block_t b, uint32_t *result)
{
	int r, i;
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);
	unsigned adjustment = 0;

	/*
	 * we may have some uncommitted adjustments to add.  This list
	 * should always be really short.
	 */
	for (i = 0; i < smm->nr_uncommitted; i++) {
		struct block_op *op = smm->uncommitted + i;
		if (op->block == b)
			switch (op->type) {
			case BOP_INC:
				adjustment++;
				break;

			case BOP_DEC:
				adjustment--;
				break;
			}
	}

	r = ll_lookup(&smm->ll, b, result);
	if (r)
		return r;
	*result += adjustment;

	return 0;
}

static int sm_metadata_count_is_more_than_one(struct dm_space_map *sm, dm_block_t b, int *result)
{
	int r, i, adjustment = 0;
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);
	uint32_t rc;

	/*
	 * we may have some uncommitted adjustments to add.  This list
	 * should always be really short.
	 */
	for (i = 0; i < smm->nr_uncommitted; i++) {
		struct block_op *op = smm->uncommitted + i;
		if (op->block == b)
			switch (op->type) {
			case BOP_INC:
				adjustment++;
				break;

			case BOP_DEC:
				adjustment--;
				break;
			}
	}

	if (adjustment > 1) {
		*result = 1;
		return 0;
	}

	r = ll_lookup_bitmap(&smm->ll, b, &rc);
	if (r)
		return r;

	if (rc == 3)
		/* we err on the side of caution, and always return true */
		*result = 1;
	else
		*result = rc + adjustment > 1;

	return 0;
}

static int sm_metadata_set_count(struct dm_space_map *sm, dm_block_t b, uint32_t count)
{
	int r;
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);

	no_recurse(smm);

	in(smm);
	r = ll_insert(&smm->ll, b, count);
	out(smm);
	return r;
}

static int sm_metadata_inc_block(struct dm_space_map *sm, dm_block_t b)
{
	int r;
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);

	if (recursing(smm))
		r = add_bop(smm, BOP_INC, b);

	else {
		in(smm);
		r = ll_inc(&smm->ll, b);
		out(smm);
	}
	return r;
}

static int sm_metadata_dec_block(struct dm_space_map *sm, dm_block_t b)
{
	int r;
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);

	if (recursing(smm))
		r = add_bop(smm, BOP_DEC, b);

	else {
		in(smm);
		r = ll_dec(&smm->ll, b);
		out(smm);
	}
	return r;
}

static int sm_metadata_new_block(struct dm_space_map *sm, dm_block_t *b)
{
	int r;
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);

	r = ll_find_free_block(&smm->old_ll, smm->begin, smm->old_ll.nr_blocks, b);
	if (r)
		return r;

	smm->begin = *b + 1;

	if (recursing(smm))
		r = add_bop(smm, BOP_INC, *b);

	else {
		in(smm);
		r = ll_inc(&smm->ll, *b);
		out(smm);
	}

	if (!r)
		smm->allocated_this_transaction++;
	return r;
}

static int sm_metadata_commit(struct dm_space_map *sm)
{
	int r;
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);

	memcpy(&smm->old_ll, &smm->ll, sizeof(smm->old_ll));

	r = ll_commit(&smm->ll);
	if (r)
		return r;

	memcpy(&smm->old_ll, &smm->ll, sizeof(smm->old_ll));
	smm->begin = 0;
	smm->allocated_this_transaction = 0;
	return 0;
}

static int sm_metadata_root_size(struct dm_space_map *sm, size_t *result)
{
	*result = sizeof(struct sm_root);
	return 0;
}

static int sm_metadata_copy_root(struct dm_space_map *sm, void *where, size_t max)
{
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);
	struct sm_root root;

	root.nr_blocks = __cpu_to_le64(smm->ll.nr_blocks);
	root.nr_allocated = __cpu_to_le64(smm->ll.nr_allocated);
	root.bitmap_root = __cpu_to_le64(smm->ll.bitmap_root);
	root.ref_count_root = __cpu_to_le64(smm->ll.ref_count_root);

	if (max < sizeof(root))
		return -ENOSPC;

	memcpy(where, &root, sizeof(root));

	return 0;
}

static struct dm_space_map ops_ = {
	.destroy = sm_metadata_destroy,
	.extend = sm_metadata_extend,
	.get_nr_blocks = sm_metadata_get_nr_blocks,
	.get_nr_free = sm_metadata_get_nr_free,
	.get_count = sm_metadata_get_count,
	.count_is_more_than_one = sm_metadata_count_is_more_than_one,
	.set_count = sm_metadata_set_count,
	.inc_block = sm_metadata_inc_block,
	.dec_block = sm_metadata_dec_block,
	.new_block = sm_metadata_new_block,
	.commit = sm_metadata_commit,
	.root_size = sm_metadata_root_size,
	.copy_root = sm_metadata_copy_root
};

/*----------------------------------------------------------------*/

/*
 * When a new space map is created, that manages it's own space.  We use
 * this tiny bootstrap allocator.
 */
static void sm_bootstrap_destroy(struct dm_space_map *sm)
{
	BUG_ON(1);
}

static int sm_bootstrap_extend(struct dm_space_map *sm, dm_block_t extra_blocks)
{
	BUG_ON(1);
	return -1;
}

static int sm_bootstrap_get_nr_blocks(struct dm_space_map *sm, dm_block_t *count)
{
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);
	return smm->ll.nr_blocks;
}

static int sm_bootstrap_get_nr_free(struct dm_space_map *sm, dm_block_t *count)
{
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);
	*count = smm->ll.nr_blocks - smm->begin;
	return 0;
}

static int sm_bootstrap_get_count(struct dm_space_map *sm, dm_block_t b, uint32_t *result)
{
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);
	return b < smm->begin ? 1 : 0;
}

static int sm_bootstrap_count_is_more_than_one(struct dm_space_map *sm, dm_block_t b, int *result)
{
	*result = 0;
	return 0;
}

static int sm_bootstrap_set_count(struct dm_space_map *sm, dm_block_t b, uint32_t count)
{
	BUG_ON(1);
	return -1;
}

static int sm_bootstrap_new_block(struct dm_space_map *sm, dm_block_t *b)
{
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);

	/*
	 * We know the entire device is unused.
	 */
	if (smm->begin == smm->ll.nr_blocks)
		return -ENOSPC;

	*b = smm->begin++;
	return 0;
}

static int sm_bootstrap_inc_block(struct dm_space_map *sm, dm_block_t b)
{
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);
	return add_bop(smm, BOP_INC, b);
}

static int sm_bootstrap_dec_block(struct dm_space_map *sm, dm_block_t b)
{
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);
	return add_bop(smm, BOP_DEC, b);
}

static int sm_bootstrap_commit(struct dm_space_map *sm)
{
	return 0;
}

static int sm_bootstrap_root_size(struct dm_space_map *sm, size_t *result)
{
	BUG_ON(1);
	return -1;
}

static int sm_bootstrap_copy_root(struct dm_space_map *sm, void *where, size_t max)
{
	BUG_ON(1);
	return -1;
}

static struct dm_space_map bootstrap_ops_ = {
	.destroy = sm_bootstrap_destroy,
	.extend = sm_bootstrap_extend,
	.get_nr_blocks = sm_bootstrap_get_nr_blocks,
	.get_nr_free = sm_bootstrap_get_nr_free,
	.get_count = sm_bootstrap_get_count,
	.count_is_more_than_one = sm_bootstrap_count_is_more_than_one,
	.set_count = sm_bootstrap_set_count,
	.inc_block = sm_bootstrap_inc_block,
	.dec_block = sm_bootstrap_dec_block,
	.new_block = sm_bootstrap_new_block,
	.commit = sm_bootstrap_commit,
	.root_size = sm_bootstrap_root_size,
	.copy_root = sm_bootstrap_copy_root
};

/*----------------------------------------------------------------*/

struct dm_space_map *dm_sm_metadata_init(void)
{
	struct sm_metadata *smm;

	smm = kmalloc(sizeof(*smm), GFP_KERNEL);
	if (!smm)
		return ERR_PTR(-ENOMEM);

	memcpy(&smm->sm, &ops_, sizeof(smm->sm));
	return &smm->sm;
}
EXPORT_SYMBOL_GPL(dm_sm_metadata_init);

int dm_sm_metadata_create(struct dm_space_map *sm,
			  struct dm_transaction_manager *tm,
			  dm_block_t nr_blocks,
			  dm_block_t superblock)
{
	int r;
	dm_block_t i;
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);

	smm->begin = superblock + 1;
	smm->recursion_count = 0;
	smm->allocated_this_transaction = 0;
	smm->nr_uncommitted = 0;

	memcpy(&smm->sm, &bootstrap_ops_, sizeof(smm->sm));
	r = ll_new(&smm->ll, tm, nr_blocks);
	if (r)
		return r;
	memcpy(&smm->sm, &ops_, sizeof(smm->sm));

	/*
	 * Now we need to update the newly created data structures with the
	 * allocated blocks that they were built from.
	 */
	for (i = superblock; !r && i < smm->begin; i++)
		r = ll_inc(&smm->ll, i);

	if (r)
		return r;

	return sm_metadata_commit(sm);
}
EXPORT_SYMBOL_GPL(dm_sm_metadata_create);

int dm_sm_metadata_open(struct dm_space_map *sm,
			struct dm_transaction_manager *tm,
			void *root, size_t len)
{
	int r;
	struct sm_metadata *smm = container_of(sm, struct sm_metadata, sm);

	r = ll_open(&smm->ll, tm, root, len);
	if (r)
		return r;

	smm->begin = 0;
	smm->recursion_count = 0;
	smm->allocated_this_transaction = 0;
	smm->nr_uncommitted = 0;

	return sm_metadata_commit(sm);
}
EXPORT_SYMBOL_GPL(dm_sm_metadata_open);

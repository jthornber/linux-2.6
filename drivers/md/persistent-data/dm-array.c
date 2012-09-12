/*
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#include "dm-array.h"
#include "dm-space-map.h"
#include "dm-transaction-manager.h"

#include <linux/export.h>
#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "array"

/*----------------------------------------------------------------*/

/*
 * The array is implemented as a fully populated btree, which points to
 * blocks which contain the packed values.  This is more space efficient
 * than just using a btree since we don't store 1 key per value.
 */
struct array_block {
	__le64 blocknr; /* Block this node is supposed to live in. */
	__le32 csum;
	__le32 max_entries;
	__le32 nr_entries;
	__le32 value_size;
} __packed;

/*----------------------------------------------------------------*/

#define CSUM_XOR 595846735

static void array_block_prepare_for_write(struct dm_block_validator *v,
					  struct dm_block *b,
					  size_t block_size)
{
	struct array_block *bh_le = dm_block_data(b);

	bh_le->blocknr = cpu_to_le64(dm_block_location(b));
	bh_le->csum = cpu_to_le32(dm_bm_checksum(&bh_le->max_entries,
						 block_size - sizeof(__le32),
						 CSUM_XOR));
}

static int array_block_check(struct dm_block_validator *v,
			     struct dm_block *b,
			     size_t block_size)
{
	struct array_block *bh_le = dm_block_data(b);
	__le32 csum_disk;

	if (dm_block_location(b) != le64_to_cpu(bh_le->blocknr)) {
		DMERR("array_block_check failed blocknr %llu wanted %llu",
		      le64_to_cpu(bh_le->blocknr), dm_block_location(b));
		return -ENOTBLK;
	}

	csum_disk = cpu_to_le32(dm_bm_checksum(&bh_le->max_entries,
					       block_size - sizeof(__le32),
					       CSUM_XOR));
	if (csum_disk != bh_le->csum) {
		DMERR("array_block_check failed csum %u wanted %u",
		      le32_to_cpu(csum_disk), le32_to_cpu(bh_le->csum));
		return -EILSEQ;
	}

	return 0;
}

static struct dm_block_validator array_validator = {
	.name = "array",
	.prepare_for_write = array_block_prepare_for_write,
	.check = array_block_check
};

/*----------------------------------------------------------------*/

/*
 * Functions for manipulating the array blocks.
 */
static void *elt_at(struct dm_array_info *info, struct array_block *ab, unsigned index)
{
	unsigned char *entry = (unsigned char *) (ab + 1);
	entry += index * info->value_type.size;
	return entry;
}

static void on_entries(struct dm_array_info *info, struct array_block *ab, void (*fn)(void *, const void *))
{
	unsigned i, nr_entries = le32_to_cpu(ab->nr_entries);

	for (i = 0; i < nr_entries; i++)
		fn(info->value_type.context, elt_at(info, ab, i));
}

static void inc_ablock_entries(struct dm_array_info *info, struct array_block *ab)
{
	struct dm_btree_value_type *vt = &info->value_type;

	if (vt->inc)
		on_entries(info, ab, vt->inc);
}

static void dec_ablock_entries(struct dm_array_info *info, struct array_block *ab)
{
	struct dm_btree_value_type *vt = &info->value_type;

	if (vt->dec)
		on_entries(info, ab, vt->dec);
}

static uint32_t calc_max_entries(size_t value_size, size_t block_size)
{
	return (block_size - sizeof(struct array_block)) / value_size;
}

static int alloc_ablock(struct dm_array_info *info,
			size_t block_size,
			struct dm_block **result,
			struct array_block **ab)
{
	int r;

	r = dm_tm_new_block(info->btree_info.tm, &array_validator, result);
	if (r)
		return r;

	(*ab) = dm_block_data(*result);
	(*ab)->max_entries = cpu_to_le32(calc_max_entries(info->value_type.size, block_size));
	(*ab)->nr_entries = cpu_to_le32(0);
	(*ab)->value_size = cpu_to_le32(info->value_type.size);

	return 0;
}

static void fill_ablock(struct dm_array_info *info, struct array_block *ab,
			const void *value, unsigned new_nr)
{
	unsigned i;
	uint32_t nr_entries;
	struct dm_btree_value_type *vt = &info->value_type;

	BUG_ON(new_nr > le32_to_cpu(ab->max_entries));

	nr_entries = le32_to_cpu(ab->nr_entries);
	for (i = nr_entries; i < new_nr; i++) {
		if (vt->inc)
			vt->inc(vt->context, value);
		memcpy(elt_at(info, ab, i), value, vt->size);
	}
	ab->nr_entries = cpu_to_le32(new_nr);
}

static void trim_ablock(struct dm_array_info *info,
			struct array_block *ab,
			unsigned new_nr)
{
	unsigned i;
	uint32_t nr_entries;
	struct dm_btree_value_type *vt = &info->value_type;

	BUG_ON(new_nr > le32_to_cpu(ab->max_entries));

	nr_entries = le32_to_cpu(ab->nr_entries);
	for (i = nr_entries; i > new_nr; i--)
		if (vt->dec)
			vt->dec(vt->context, elt_at(info, ab, i - 1));
	ab->nr_entries = cpu_to_le32(new_nr);
}

static int get_ablock(struct dm_array_info *info,
		      dm_block_t b,
		      struct dm_block **block,
		      struct array_block **ab)
{
	int r;

	r = dm_tm_read_lock(info->btree_info.tm,
			    b,
			    &array_validator, block);
	if (r)
		return r;

	*ab = dm_block_data(*block);
	return 0;
}

static int unlock_ablock(struct dm_array_info *info, struct dm_block *block)
{
	return dm_tm_unlock(info->btree_info.tm, block);
}

/*----------------------------------------------------------------*/

/*
 * Btree manipulation.
 */
static int lookup_ablock(struct dm_array_info *info,
			 dm_block_t root,
			 unsigned index,
			 struct dm_block **block,
			 struct array_block **ab)
{
	int r;
	uint64_t key = index;
	__le64 block_le;

	r = dm_btree_lookup(&info->btree_info, root, &key, &block_le);
	if (r)
		return r;

	return get_ablock(info, le64_to_cpu(block_le), block, ab);
}

static int shadow_ablock(struct dm_array_info *info,
			 dm_block_t *root,
			 unsigned index,
			 struct dm_block **block,
			 struct array_block **result)
{
	int r, inc;
	uint64_t key = index;
	__le64 block_le, new_block_le;

	r = dm_btree_lookup(&info->btree_info, *root, &key, &block_le);
	if (r)
		return r;

	r = dm_tm_shadow_block(info->btree_info.tm,
			       le64_to_cpu(block_le),
			       &array_validator, block, &inc);
	if (r)
		return r;

	if (inc)
		inc_ablock_entries(info, *result);

	*result = dm_block_data(*block);

	new_block_le = cpu_to_le64(dm_block_location(*block));
	if (new_block_le != block_le) {
		__dm_bless_for_disk(&new_block_le);
		r = dm_btree_insert(&info->btree_info, *root, &key, &block_le, root);
	}

	return r;
}

static int insert_ablock(struct dm_array_info *info,
			 uint64_t index,
			 struct dm_block *block,
			 dm_block_t *root)
{
	__le64 block_le = cpu_to_le64(dm_block_location(block));
	__dm_bless_for_disk(block_le);
	return dm_btree_insert(&info->btree_info, *root, &index, &block_le, root);
}

/*
 * We don't need to create new blocks for every full block.  Since they all
 * have the same contents we can just share a single block.  Aren't
 * persistent data structures beautiful?
 */
static int insert_full_ablocks(struct dm_array_info *info,
			       size_t block_size,
			       unsigned begin_block,
			       unsigned end_block,
			       unsigned max_entries,
			       const void *value,
			       dm_block_t *root)
{
	int r;
	struct dm_block *block;
	struct array_block *ab;

	if (begin_block == end_block)
		return 0;

	r = alloc_ablock(info, block_size, &block, &ab);
	if (r)
		return r;

	fill_ablock(info, ab, value, le32_to_cpu(ab->max_entries));

	/* insert the same block into the tree, in many different places */
	while (begin_block != end_block) {
		r = insert_ablock(info, begin_block, block, root);
		if (r)
			goto out;

		dm_tm_inc(info->btree_info.tm, dm_block_location(block));
	}

out:
	unlock_ablock(info, block);
	dm_tm_dec(info->btree_info.tm, dm_block_location(block));
	return 0;
}

static int insert_partial_ablock(struct dm_array_info *info,
				 size_t block_size,
				 unsigned block_index,
				 unsigned nr,
				 const void *value,
				 dm_block_t *root)
{
	int r;
	struct dm_block *block;
	struct array_block *ab;

	if (nr == 0)
		return 0;

	r = alloc_ablock(info, block_size, &block, &ab);
	if (r)
		return r;

	fill_ablock(info, ab, value, nr);
	return insert_ablock(info, block_index, block, root);
}

struct resize {
	struct dm_array_info *info;
	dm_block_t *root;
	size_t block_size;
	unsigned max_entries;
	unsigned old_nr_full_blocks, new_nr_full_blocks;
	unsigned old_nr_entries_in_last_block, new_nr_entries_in_last_block;
	const void *value;
};

static int drop_blocks(struct resize *resize, unsigned begin_index, unsigned end_index)
{
	int r;

	while (begin_index != end_index) {
		uint64_t key = begin_index++;
		r = dm_btree_remove(&resize->info->btree_info, *resize->root, &key, resize->root);
		if (r)
			return r;
	}

	return 0;
}

static int shrink(struct resize *resize)
{
	int r;

	/* lose some blocks from the back? */
	if (resize->new_nr_full_blocks < resize->old_nr_full_blocks) {
		unsigned end = resize->old_nr_full_blocks;

		if (resize->old_nr_entries_in_last_block)
			end++;

		r = drop_blocks(resize, resize->old_nr_full_blocks, end);
		if (r)
			return r;
	}

	/* trim the new tail block */
	if (resize->new_nr_entries_in_last_block) {
		struct dm_block *block;
		struct array_block *ab;

		r = shadow_ablock(resize->info, resize->root, resize->new_nr_full_blocks, &block, &ab);
		if (r)
			return r;

		trim_ablock(resize->info, ab, resize->new_nr_entries_in_last_block);
		unlock_ablock(resize->info, block);
	}

	return 0;
}

static int grow(struct resize *resize)
{
	int r;

	/* extend old tail block */
	if (resize->old_nr_entries_in_last_block > 0) {
		struct dm_block *block;
		struct array_block *ab;

		r = shadow_ablock(resize->info, resize->root, resize->new_nr_full_blocks, &block, &ab);
		if (r)
			return r;

		if (resize->old_nr_full_blocks < resize->new_nr_full_blocks)
			fill_ablock(resize->info, ab, resize->value, resize->max_entries);
		else
			fill_ablock(resize->info, ab, resize->value, resize->new_nr_entries_in_last_block);

		unlock_ablock(resize->info, block);
	}

	/* add full entries */
	r = insert_full_ablocks(resize->info, resize->block_size, resize->old_nr_full_blocks, resize->new_nr_full_blocks,
				resize->max_entries, resize->value, resize->root);
	if (r)
		return r;

	/* add new tail block */
	return insert_partial_ablock(resize->info, resize->block_size, resize->new_nr_full_blocks,
				     resize->new_nr_entries_in_last_block, resize->value, resize->root);
}

/*----------------------------------------------------------------*/

/*
 * These are the value_type functions for the btree elements, which point
 * to array blocks.
 */
static void block_inc(void *context, const void *value)
{
	__le64 block_le;
	struct dm_array_info *info = context;

	memcpy(&block_le, value, sizeof(block_le));
	dm_tm_inc(info->btree_info.tm, le64_to_cpu(block_le));
}

static void block_dec(void *context, const void *value)
{
	int r;
	__le64 block_le;
	uint32_t ref_count;
	uint64_t b;
	struct dm_array_info *info = context;

	memcpy(&block_le, value, sizeof(block_le));
	b = le64_to_cpu(block_le);

	r = dm_tm_ref(info->btree_info.tm, b, &ref_count);
	if (r) {
		DMERR("couldn't get reference count");
		return;
	}

	if (ref_count == 1) {
		struct dm_block *block;
		struct array_block *ab;

		/*
		 * We're about to drop the last reference to this ablock.
		 * So we need to decrement the ref count of the contents.
		 */
		r = get_ablock(info, b, &block, &ab);
		if (r) {
			DMERR("couldn't get array block");
			return;
		}

		dec_ablock_entries(info, ab);
		unlock_ablock(info, block);
	}

	dm_tm_dec(info->btree_info.tm, b);
}

static int block_equal(void *context, const void *value1, const void *value2)
{
	return !memcmp(value1, value2, sizeof(__le64));
}

/*----------------------------------------------------------------*/

void dm_setup_array_info(struct dm_array_info *info,
			 struct dm_transaction_manager *tm,
			 struct dm_btree_value_type *vt)
{
	struct dm_btree_value_type *bvt = &info->btree_info.value_type;

	memcpy(&info->value_type, vt, sizeof(info->value_type));
	info->btree_info.tm = tm;
	info->btree_info.levels = 1;

	bvt->context = info;
	bvt->size = sizeof(__le64);
	bvt->inc = block_inc;
	bvt->dec = block_dec;
	bvt->equal = block_equal;
}
EXPORT_SYMBOL_GPL(dm_setup_array_info);

int dm_array_empty(struct dm_array_info *info, dm_block_t *root)
{
	return dm_btree_empty(&info->btree_info, root);
}
EXPORT_SYMBOL_GPL(dm_array_empty);

static int dm_array_resize_(struct dm_array_info *info, dm_block_t root,
			    uint32_t old_size, uint32_t new_size,
			    const void *value,
			    dm_block_t *new_root)
{
	int r;
	struct resize resize;

	if (old_size == new_size)
		return 0;

	resize.info = info;
	resize.root = &root;
	resize.block_size = dm_bm_block_size(dm_tm_get_bm(info->btree_info.tm));
	resize.max_entries = calc_max_entries(info->value_type.size, resize.block_size);

	resize.old_nr_full_blocks = old_size / resize.max_entries;
	resize.old_nr_entries_in_last_block = old_size % resize.max_entries;
	resize.new_nr_full_blocks = new_size / resize.max_entries;
	resize.new_nr_entries_in_last_block = new_size % resize.max_entries;

	r = ((old_size < new_size) ? shrink : grow)(&resize);
	if (r)
		return r;

	*new_root = *resize.root;
	return 0;
}

int dm_array_resize(struct dm_array_info *info, dm_block_t root,
		    uint32_t old_size, uint32_t new_size,
		    const void *default_value,
		    dm_block_t *new_root)
	__dm_written_to_disk(value)
{
	int r = dm_array_resize_(info, root, old_size, new_size, default_value, new_root);
	__dm_unbless_for_disk(default_value);
	return r;
}
EXPORT_SYMBOL_GPL(dm_array_resize);

int dm_array_del(struct dm_array_info *info, dm_block_t root)
{
	return dm_btree_del(&info->btree_info, root);
}
EXPORT_SYMBOL_GPL(dm_array_del);

int dm_array_get(struct dm_array_info *info,
		 dm_block_t root,
		 uint32_t index,
		 void *value_le)
{
	int r;
	struct dm_block *block;
	struct array_block *ab;
	size_t block_size;
	unsigned entry, max_entries;

	block_size = dm_bm_block_size(dm_tm_get_bm(info->btree_info.tm));
	max_entries = calc_max_entries(info->value_type.size, block_size);

	r = lookup_ablock(info, root, index / max_entries, &block, &ab);
	if (r)
		return r;

	entry = index % max_entries;
	memcpy(value_le, elt_at(info, ab, entry), sizeof(info->value_type.size));
	unlock_ablock(info, block);
	return 0;
}
EXPORT_SYMBOL_GPL(dm_array_get);

static int dm_array_set_(struct dm_array_info *info, dm_block_t root,
			 uint32_t index, const void *value, dm_block_t *new_root)
{
	int r;
	struct dm_block *block;
	struct array_block *ab;
	size_t block_size;
	unsigned max_entries;
	unsigned entry;
	void *old_value;
	struct dm_btree_value_type *vt = &info->value_type;

	block_size = dm_bm_block_size(dm_tm_get_bm(info->btree_info.tm));
	max_entries = calc_max_entries(info->value_type.size, block_size);

	r = shadow_ablock(info, &root, index / max_entries, &block, &ab);
	if (r)
		return r;
	*new_root = root;

	entry = index % max_entries;

	old_value = elt_at(info, ab, entry);
	if (vt->dec &&
	    (!vt->equal || !vt->equal(vt->context, old_value, value))) {
		vt->dec(vt->context, old_value);
		if (vt->inc)
			vt->inc(vt->context, value);
	}

	memcpy(elt_at(info, ab, entry), value, sizeof(info->value_type.size));
	unlock_ablock(info, block);
	return 0;
}

int dm_array_set(struct dm_array_info *info, dm_block_t root,
		 uint32_t index, const void *value, dm_block_t *new_root)
	__dm_written_to_disk(value)
{
	int r = dm_array_set_(info, root, index, value, new_root);
	__dm_unbless_for_disk(value);
	return r;
}

EXPORT_SYMBOL_GPL(dm_array_set);

/*----------------------------------------------------------------*/

/*
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#include "dm-bitset.h"
#include "dm-transaction-manager.h"

#include <linux/export.h>
#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "bitset"

#define USE_INCORE_AS_VALIDATION
#ifdef USE_INCORE_AS_VALIDATION
/*----------------------------------------------------------------*/

static size_t bitset_size_in_bytes(unsigned nr_entries)
{
	return sizeof(unsigned long) * dm_div_up(nr_entries, BITS_PER_LONG);
}

static unsigned long *alloc_bitset(unsigned nr_entries)
{
	size_t s = bitset_size_in_bytes(nr_entries);
	return vzalloc(s);
}

static void clear_bitset(void *bitset, unsigned nr_entries)
{
	size_t s = bitset_size_in_bytes(nr_entries);
	memset(bitset, 0, s);	
}

static void free_bitset(unsigned long *bits)
{
	vfree(bits);
}

#endif

/*----------------------------------------------------------------*/

struct dm_bitset {
	unsigned nr_entries;
	dm_block_t root;
	struct dm_array_info array_info;
#ifdef USE_INCORE_AS_VALIDATION
	unsigned long *incore_bitset;
#endif
	/* FIXME: to reduce disk access, need 2 64 values: bits_to_be_set and bits_to_be_cleared
	 * - only write to disk when access outside this word, or the flush call made
	 */
};

static struct dm_btree_value_type bitset_bvt = {
	.context = NULL,
	.size = sizeof(__le64),
	.inc = NULL,
	.dec = NULL,
	.equal = NULL,
};

/*----------------------------------------------------------------*/

struct dm_bitset *dm_bitset_create(struct dm_transaction_manager *tm,
				   dm_block_t *root)
{
	struct dm_bitset *bitset = kzalloc(sizeof(struct dm_bitset), GFP_KERNEL);

	if (!bitset)
		return ERR_PTR(-ENOMEM);

	dm_setup_array_info(&bitset->array_info, tm, &bitset_bvt);
	dm_array_empty(&bitset->array_info, root);
	bitset->root = *root;

	return bitset;
}
EXPORT_SYMBOL_GPL(dm_bitset_create);

int dm_bitset_resize(struct dm_bitset *bitset, uint32_t new_nr_entries,
		     dm_block_t *new_root, bool zero)
{
	int r;
	/* NOTE: given the use of ceiling, dm_div_up can return an extra entry */
	uint32_t nr_entries = dm_div_up(new_nr_entries, 64);
	__le64 value = (zero ? 0 : ~0);
	__dm_bless_for_disk(&value);

	r = dm_array_resize(&bitset->array_info, bitset->root,
			    bitset->nr_entries, nr_entries,
			    &value, &bitset->root);
	if (!r)
		bitset->nr_entries = nr_entries;

#ifdef USE_INCORE_AS_VALIDATION
	if (!r) {
		bitset->incore_bitset = alloc_bitset(new_nr_entries);
		clear_bitset(bitset->incore_bitset,  bitset->nr_entries);
	}
#endif
	return r;
}
EXPORT_SYMBOL_GPL(dm_bitset_resize);

void dm_bitset_destroy(struct dm_bitset *bitset)
{
#ifdef USE_INCORE_AS_VALIDATION
	free_bitset(bitset->incore_bitset);
#endif
	kfree(bitset);
}
EXPORT_SYMBOL_GPL(dm_bitset_destroy);

static void unpack_value(struct dm_bitset *bitset, uint64_t index,
			 unsigned long *value, uint32_t *value_index)
{
	int r;
	__le64 value_le;

	r = dm_array_get(&bitset->array_info, bitset->root, index, &value_le);
	WARN_ON_ONCE(r); /* FIXME: what to do on lookup failure? */
	if (r)
		return;
	*value = le64_to_cpu(value_le);
	*value_index = *value & 63;
}

static void pack_value(struct dm_bitset *bitset, uint64_t index, unsigned long value)
{
	int r;
	__le64 value_le = cpu_to_le64(value);

	r = dm_array_set(&bitset->array_info, bitset->root, index, &value_le, &bitset->root);
	WARN_ON_ONCE(r); /* FIXME: what to do on lookup failure? */
}

void dm_bitset_set_bit(uint64_t index, struct dm_bitset *bitset)
{
	unsigned long value;
	uint32_t uninitialized_var(value_index);

	unpack_value(bitset, index, &value, &value_index);
	set_bit(value_index, &value);
	pack_value(bitset, index, value);

#ifdef USE_INCORE_AS_VALIDATION
	set_bit(index, bitset->incore_bitset);
#endif
}
EXPORT_SYMBOL_GPL(dm_bitset_set_bit);

void dm_bitset_clear_bit(uint64_t index, struct dm_bitset *bitset)
{
	unsigned long value;
	uint32_t uninitialized_var(value_index);

	unpack_value(bitset, index, &value, &value_index);
	clear_bit(value_index, &value);
	pack_value(bitset, index, value);

#ifdef USE_INCORE_AS_VALIDATION
	clear_bit(index, bitset->incore_bitset);
#endif
}
EXPORT_SYMBOL_GPL(dm_bitset_clear_bit);

int dm_bitset_test_bit(uint64_t index, struct dm_bitset *bitset)
{
	unsigned long value;
	uint32_t uninitialized_var(value_index);
	int r1, r2;

	unpack_value(bitset, index, &value, &value_index);
	r1 = test_bit(value_index, &value);

#ifdef USE_INCORE_AS_VALIDATION
	r2 = test_bit(index, bitset->incore_bitset);
	WARN_ON_ONCE(r1 != r2);
#endif
	return r1;
}
EXPORT_SYMBOL_GPL(dm_bitset_test_bit);

/*----------------------------------------------------------------*/

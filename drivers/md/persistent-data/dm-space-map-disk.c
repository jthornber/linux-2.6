/*
 * Copyright (C) 2011 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "dm-space-map-common.h"
#include "dm-space-map-disk.h"
#include "dm-space-map.h"
#include "dm-transaction-manager.h"

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "space map disk"

/*
 * Bitmap validator
 */
static void bitmap_prepare_for_write(struct dm_block_validator *v,
				     struct dm_block *b,
				     size_t block_size)
{
	struct disk_bitmap_header *disk_header = dm_block_data(b);

	disk_header->blocknr = cpu_to_le64(dm_block_location(b));
	disk_header->csum = cpu_to_le32(dm_block_csum_data(&disk_header->not_used, block_size - sizeof(__le32)));
}

static int bitmap_check(struct dm_block_validator *v,
			struct dm_block *b,
			size_t block_size)
{
	struct disk_bitmap_header *disk_header = dm_block_data(b);
	__le32 csum_disk;

	if (dm_block_location(b) != le64_to_cpu(disk_header->blocknr)) {
		DMERR("bitmap check failed blocknr %llu wanted %llu",
		      le64_to_cpu(disk_header->blocknr), dm_block_location(b));
		return -ENOTBLK;
	}

	csum_disk = cpu_to_le32(dm_block_csum_data(&disk_header->not_used, block_size - sizeof(__le32)));
	if (csum_disk != disk_header->csum) {
		DMERR("bitmap check failed csum %u wanted %u",
		      le32_to_cpu(csum_disk), le32_to_cpu(disk_header->csum));
		return -EILSEQ;
	}

	return 0;
}

struct dm_block_validator dm_sm_bitmap_validator = {
	.name = "sm_bitmap",
	.prepare_for_write = bitmap_prepare_for_write,
	.check = bitmap_check
};

/*----------------------------------------------------------------*/

#define ENTRIES_PER_WORD 32
#define ENTRIES_SHIFT	5

void *dm_bitmap_data(struct dm_block *b)
{
	return dm_block_data(b) + sizeof(struct disk_bitmap_header);
}

#define WORD_MASK_HIGH 0xAAAAAAAAAAAAAAAAULL

static unsigned bitmap_word_used(void *addr, unsigned b)
{
	__le64 *words_le = addr;
	__le64 *w_le = words_le + (b >> ENTRIES_SHIFT);

	uint64_t bits = le64_to_cpu(*w_le);
	uint64_t mask = (bits + WORD_MASK_HIGH + 1) & WORD_MASK_HIGH;

	return !(~bits & mask);
}

unsigned sm_lookup_bitmap(void *addr, unsigned b)
{
	__le64 *words_le = addr;
	__le64 *w_le = words_le + (b >> ENTRIES_SHIFT);

	b = (b & (ENTRIES_PER_WORD - 1)) << 1;

	return (!!test_bit_le(b, (void *) w_le) << 1) |
		(!!test_bit_le(b + 1, (void *) w_le));
}

void sm_set_bitmap(void *addr, unsigned b, unsigned val)
{
	__le64 *words_le = addr;
	__le64 *w_le = words_le + (b >> ENTRIES_SHIFT);

	b = (b & (ENTRIES_PER_WORD - 1)) << 1;

	if (val & 2)
		__set_bit_le(b, (void *) w_le);
	else
		__clear_bit_le(b, (void *) w_le);

	if (val & 1)
		__set_bit_le(b + 1, (void *) w_le);
	else
		__clear_bit_le(b + 1, (void *) w_le);
}

int sm_find_free(void *addr, unsigned begin, unsigned end,
		 unsigned *result)
{
	while (begin < end) {
		if (!(begin & (ENTRIES_PER_WORD - 1)) &&
		    bitmap_word_used(addr, begin)) {
			begin += ENTRIES_PER_WORD;
			continue;
		}

		if (!sm_lookup_bitmap(addr, begin)) {
			*result = begin;
			return 0;
		}

		begin++;
	}

	return -ENOSPC;
}

/*----------------------------------------------------------------*/

/*
 * Space map interface.
 */
struct sm_disk {
	struct dm_space_map sm;

	struct ll_disk ll;
};

static void sm_disk_destroy(struct dm_space_map *sm)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	kfree(smd);
}

static int sm_disk_extend(struct dm_space_map *sm, dm_block_t extra_blocks)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	return sm_ll_extend(&smd->ll, extra_blocks);
}

static int sm_disk_get_nr_blocks(struct dm_space_map *sm, dm_block_t *count)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	*count = smd->ll.nr_blocks;

	return 0;
}

static int sm_disk_get_nr_free(struct dm_space_map *sm, dm_block_t *count)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	*count = smd->ll.nr_blocks - smd->ll.nr_allocated;

	return 0;
}

static int sm_disk_get_count(struct dm_space_map *sm, dm_block_t b,
			     uint32_t *result)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	return sm_ll_lookup(&smd->ll, b, result);
}

static int sm_disk_count_is_more_than_one(struct dm_space_map *sm, dm_block_t b,
					  int *result)
{
	int r;
	uint32_t count;

	r = sm_disk_get_count(sm, b, &count);
	if (r)
		return r;

	return count > 1;
}

static int sm_disk_set_count(struct dm_space_map *sm, dm_block_t b,
			     uint32_t count)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	return sm_ll_insert(&smd->ll, b, count);
}

static int sm_disk_inc_block(struct dm_space_map *sm, dm_block_t b)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	return sm_ll_inc(&smd->ll, b);
}

static int sm_disk_dec_block(struct dm_space_map *sm, dm_block_t b)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	return sm_ll_dec(&smd->ll, b);
}

static int sm_disk_new_block(struct dm_space_map *sm, dm_block_t *b)
{
	int r;
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	/*
	 * FIXME: We should start the search where we left off.
	 */
	r = sm_ll_find_free_block(&smd->ll, 0, smd->ll.nr_blocks, b);
	if (r)
		return r;

	return sm_ll_inc(&smd->ll, *b);
}

static int sm_disk_commit(struct dm_space_map *sm)
{
	return 0;
}

static int sm_disk_root_size(struct dm_space_map *sm, size_t *result)
{
	*result = sizeof(struct disk_sm_root);

	return 0;
}

static int sm_disk_copy_root(struct dm_space_map *sm, void *where_le, size_t max)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);
	struct disk_sm_root root_le;

	root_le.nr_blocks = cpu_to_le64(smd->ll.nr_blocks);
	root_le.nr_allocated = cpu_to_le64(smd->ll.nr_allocated);
	root_le.bitmap_root = cpu_to_le64(smd->ll.bitmap_root);
	root_le.ref_count_root = cpu_to_le64(smd->ll.ref_count_root);

	if (max < sizeof(root_le))
		return -ENOSPC;

	memcpy(where_le, &root_le, sizeof(root_le));

	return 0;
}

/*----------------------------------------------------------------*/

static struct dm_space_map ops = {
	.destroy = sm_disk_destroy,
	.extend = sm_disk_extend,
	.get_nr_blocks = sm_disk_get_nr_blocks,
	.get_nr_free = sm_disk_get_nr_free,
	.get_count = sm_disk_get_count,
	.count_is_more_than_one = sm_disk_count_is_more_than_one,
	.set_count = sm_disk_set_count,
	.inc_block = sm_disk_inc_block,
	.dec_block = sm_disk_dec_block,
	.new_block = sm_disk_new_block,
	.commit = sm_disk_commit,
	.root_size = sm_disk_root_size,
	.copy_root = sm_disk_copy_root
};

struct dm_space_map *dm_sm_disk_create(struct dm_transaction_manager *tm,
				       dm_block_t nr_blocks)
{
	int r;
	struct sm_disk *smd;

	smd = kmalloc(sizeof(*smd), GFP_KERNEL);
	if (!smd)
		return ERR_PTR(-ENOMEM);

	memcpy(&smd->sm, &ops, sizeof(smd->sm));

	r = sm_ll_new_disk(&smd->ll, tm);
	if (r)
		goto bad;

	r = sm_ll_extend(&smd->ll, nr_blocks);
	if (r)
		goto bad;

	r = sm_disk_commit(&smd->sm);
	if (r)
		goto bad;

	return &smd->sm;

bad:
	kfree(smd);
	return ERR_PTR(r);
}
EXPORT_SYMBOL_GPL(dm_sm_disk_create);

struct dm_space_map *dm_sm_disk_open(struct dm_transaction_manager *tm,
				     void *root_le, size_t len)
{
	int r;
	struct sm_disk *smd;

	smd = kmalloc(sizeof(*smd), GFP_KERNEL);
	if (!smd)
		return ERR_PTR(-ENOMEM);

	memcpy(&smd->sm, &ops, sizeof(smd->sm));

	r = sm_ll_open_disk(&smd->ll, tm, root_le, len);
	if (r)
		goto bad;

	r = sm_disk_commit(&smd->sm);
	if (r)
		goto bad;

	return &smd->sm;

bad:
	kfree(smd);
	return ERR_PTR(r);
}
EXPORT_SYMBOL_GPL(dm_sm_disk_open);

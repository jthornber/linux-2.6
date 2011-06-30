#ifndef DM_SPACE_MAP_COMMON_H
#define DM_SPACE_MAP_COMMON_H

#include "dm-transaction-manager.h"
#include "dm-btree.h"

/*----------------------------------------------------------------
 * Low level disk format
 *
 * Bitmap btree
 * ------------
 *
 * Each value stored in the btree is an index_entry.  This points to a
 * block that is used as a bitmap.  Within the bitmap hold 2 bits per
 * entry, which represent UNUSED = 0, REF_COUNT = 1, REF_COUNT = 2 and
 * REF_COUNT = many.
 *
 * Refcount btree
 * --------------
 *
 * Any entry that has a ref count higher than 2 gets entered in the ref
 * count tree.  The leaf values for this tree is the 32bit ref count.
 *--------------------------------------------------------------*/
struct index_entry {
	__le64 blocknr;
	__le32 nr_free;
	__le32 none_free_before;
}  __attribute__ ((packed));

struct ll_disk {
	struct dm_transaction_manager *tm;
	struct dm_btree_info bitmap_info;
	struct dm_btree_info ref_count_info;

	uint32_t block_size;
	uint32_t entries_per_block;
	dm_block_t nr_blocks;
	dm_block_t nr_allocated;
	dm_block_t bitmap_root;	/* sometimes a btree root, sometimes a simple index */
	dm_block_t ref_count_root;

	struct index_entry index[256]; /* only used by metadata */
};

struct sm_root {
	__le64 nr_blocks;
	__le64 nr_allocated;
	__le64 bitmap_root;
	__le64 ref_count_root;
} __attribute__ ((packed));

#define ENTRIES_PER_BYTE 4

struct bitmap_header {
	__le32 csum;
	__le32 not_used;
	__le64 blocknr;
} __attribute__ ((packed));

/*
 * These bitops work on a blocks worth of bits.
 */
unsigned sm__lookup_bitmap(void *addr, unsigned b);
void sm__set_bitmap(void *addr, unsigned b, unsigned val);
int sm__find_free(void *addr, unsigned begin, unsigned end,
		  unsigned *result);

void *dm_bitmap_data(struct dm_block *b);

extern struct dm_block_validator dm_sm_bitmap_validator;

//----------------------------------------------------------------

#endif

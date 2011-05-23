#include <linux/list.h>
#include <linux/slab.h>
#include <asm-generic/bitops/le.h>

#include "dm-space-map-disk.h"
#include "dm-btree-internal.h"

/*----------------------------------------------------------------*/

/* on disk data */
struct sm_root {
	__le64 nr_blocks;
	__le64 nr_allocated;
	__le64 bitmap_root;
	__le64 ref_count_root;
};

/* FIXME: add a spinlock to protect the in core structure */
struct sm_disk {
	struct dm_transaction_manager *tm;

	struct dm_btree_info bitmap_info;
	struct dm_btree_info ref_count_info;

	uint32_t block_size;
	uint32_t entries_per_block;
	dm_block_t nr_blocks;
	dm_block_t nr_allocated;
	dm_block_t bitmap_root;
	dm_block_t ref_count_root;
};

struct index_entry {
	__le64 b;
	__le32 nr_free;
        __le32 none_free_before;
};

#define ENTRIES_PER_BYTE 4

/*----------------------------------------------------------------*/

static uint64_t div_up(uint64_t v, uint64_t n)
{
	uint64_t t = v;
	uint64_t rem = do_div(t, n);
	return t + (rem > 0 ? 1 : 0);
}

static uint64_t mod64(uint64_t n, uint64_t d)
{
	return do_div(n, d);
}

/*
 * On disk format
 *
 * We hold 2 bits per block, which represent UNUSED = 0, REF_COUNT = 1,
 * REF_COUNT = 2 and REF_COUNT = many.  A separate btree holds ref counts
 * for blocks that are over 2.
 */
#define ENTRIES_PER_WORD 32
static unsigned __lookup_bitmap(void *addr, dm_block_t b)
{
	unsigned val = 0;
	__le64 *words = (__le64 *) addr;
	__le64 *w = words + (b / ENTRIES_PER_WORD);
	b %= ENTRIES_PER_WORD;

	val = test_bit_le(b * 2, (void *) w) ? 1 : 0;
	val <<= 1;
	val |= test_bit_le(b * 2 + 1, (void *) w) ? 1 : 0;
	return val;
}

static void __set_bitmap(void *addr, dm_block_t b, unsigned val)
{
	__le64 *words = (__le64 *) addr;
	__le64 *w = words + (b / ENTRIES_PER_WORD);
	b %= ENTRIES_PER_WORD;

	if (val & 2)
		__set_bit_le(b * 2, (void *) w);
	else
		__clear_bit_le(b * 2, (void *) w);

	if (val & 1)
		__set_bit_le(b * 2 + 1, (void *) w);
	else
		__clear_bit_le(b * 2 + 1, (void *) w);
}

static int __find_free(void *addr, unsigned begin, unsigned end,
		       unsigned *position)
{
	/* FIXME: slow, find a quicker way in Hackers Delight */
	while (begin < end) {
		if (!__lookup_bitmap(addr, begin)) {
			*position = begin;
			return 0;
		}
		begin++;
	}

	return -ENOSPC;
}

static inline dm_block_t min_block(dm_block_t b1, dm_block_t b2)
{
	return (b1 <= b2) ? b1 : b2;
}

static inline dm_block_t max_block(dm_block_t b1, dm_block_t b2)
{
	return (b1 >= b2) ? b1 : b2;
}

static struct sm_disk *alloc_smd(struct dm_transaction_manager *tm)
{
	return kmalloc(sizeof(struct sm_disk), GFP_KERNEL);
}

static int io_init(struct sm_disk *io, struct dm_transaction_manager *tm)
{
	io->tm = tm;
	io->bitmap_info.tm = tm;
	io->bitmap_info.levels = 1;

	/*
	 * Because the new bitmap blocks are created via a shadow
	 * operation, the old entry has already had it's reference count
	 * decremented.  So we don't need the btree to do any book
	 * keeping.
	 */
	io->bitmap_info.value_type.size = sizeof(struct index_entry);
	io->bitmap_info.value_type.copy = NULL;
	io->bitmap_info.value_type.del = NULL;
	io->bitmap_info.value_type.equal = NULL;

	io->ref_count_info.tm = tm;
	io->ref_count_info.levels = 1;
	io->ref_count_info.value_type.size = sizeof(uint32_t);
	io->ref_count_info.value_type.copy = NULL;
	io->ref_count_info.value_type.del = NULL;
	io->ref_count_info.value_type.equal = NULL;

	io->block_size = dm_bm_block_size(dm_tm_get_bm(tm));

	if (io->block_size > (1 << 30)) {
		printk(KERN_ALERT "block size too big to hold bitmaps");
		return -EINVAL;
	}
	io->entries_per_block = io->block_size * 4;
	io->nr_blocks = 0;
	io->bitmap_root = 0;
	io->ref_count_root = 0;

	return 0;
}

static int io_new(struct sm_disk *io, struct dm_transaction_manager *tm,
		  dm_block_t nr_blocks)
{
	int r;
	dm_block_t i;
	unsigned blocks;

	r = io_init(io, tm);
	if (r < 0)
		return r;

	io->nr_blocks = nr_blocks;
	io->nr_allocated = 0;
	r = dm_btree_empty(&io->bitmap_info, &io->bitmap_root);
	if (r < 0)
		return r;

	blocks = div_up(nr_blocks, io->entries_per_block);
	for (i = 0; i < blocks; i++) {
		struct dm_block *b;
		struct index_entry idx;

		r = dm_tm_new_block(tm, &b);
		if (r < 0)
			return r;
		idx.b = __cpu_to_le64(dm_block_location(b));

		r = dm_tm_unlock(tm, b);
		if (r < 0)
			return r;

		idx.nr_free = __cpu_to_le32(io->entries_per_block);
		idx.none_free_before = 0;

		r = dm_btree_insert(&io->bitmap_info, io->bitmap_root,
				    &i, &idx, &io->bitmap_root);
		if (r < 0)
			return r;
	}

	r = dm_btree_empty(&io->ref_count_info, &io->ref_count_root);
	if (r < 0) {
		dm_btree_del(&io->bitmap_info, io->bitmap_root);
		return r;
	}

	return 0;
}

static int io_open(struct sm_disk *io, struct dm_transaction_manager *tm,
		   void *root, size_t len)
{
	int r;
	struct sm_root *smr = (struct sm_root *) root;

	if (len < sizeof(struct sm_root)) {
		printk(KERN_ALERT "sm_disk root too small");
		return -ENOMEM;
	}

	r = io_init(io, tm);
	if (r < 0)
		return r;

	io->nr_blocks = __le64_to_cpu(smr->nr_blocks);
	io->nr_allocated = __le64_to_cpu(smr->nr_allocated);
	io->bitmap_root = __le64_to_cpu(smr->bitmap_root);
	io->ref_count_root = __le64_to_cpu(smr->ref_count_root);

	return 0;
}

static int io_lookup(struct sm_disk *io, dm_block_t b, uint32_t *result)
{
	int r;
	dm_block_t index = b;
	struct index_entry ie;

	do_div(index, io->entries_per_block);

	r = dm_btree_lookup_equal(&io->bitmap_info, io->bitmap_root, &index, &ie);
	if (r < 0)
		return r;

	{
		struct dm_block *blk;
		r = dm_tm_read_lock(io->tm, __le64_to_cpu(ie.b), &blk);
		if (r < 0)
			return r;

		*result = __lookup_bitmap(dm_block_data(blk),
					 mod64(b, io->entries_per_block));
		r = dm_tm_unlock(io->tm, blk);
		if (r < 0) {
			return r;
		}
	}

	if (*result == 3) {
		__le32 le_rc;
		r = dm_btree_lookup_equal(&io->ref_count_info,
					  io->ref_count_root,
					  &b, &le_rc);
		if (r < 0)
			return r;

		*result = __le32_to_cpu(le_rc);
	}

	return 0;
}

static int io_find_unused(struct sm_disk *io, dm_block_t begin,
			  dm_block_t end, dm_block_t *result)
{
	int r;
	struct index_entry ie;
	dm_block_t i, index_begin = begin;
	dm_block_t index_end = div_up(end, io->entries_per_block);

	do_div(index_begin, io->entries_per_block);
	for (i = index_begin; i < index_end; i++, begin = 0) {
		r = dm_btree_lookup_equal(&io->bitmap_info,
					  io->bitmap_root, &i, &ie);
		if (r < 0)
			return r;

		if (__le32_to_cpu(ie.nr_free) > 0) {
			struct dm_block *blk;
			unsigned position;

			uint32_t bit_end = (i == index_end - 1) ?
				mod64(end, io->entries_per_block) :
				io->entries_per_block;

			r = dm_tm_read_lock(io->tm, __le64_to_cpu(ie.b), &blk);
			if (r < 0)
				return r;

			r = __find_free(dm_block_data(blk),
					mod64(begin, io->entries_per_block),
					bit_end, &position);
			if (r < 0) {
				dm_tm_unlock(io->tm, blk);
				return r;
			}

			*result = i * io->entries_per_block + position;

			r = dm_tm_unlock(io->tm, blk);
			if (r < 0)
				return r;

			BUG_ON(*result >= io->nr_blocks);
			return 0;
		}
	}

	return -ENOSPC;
}

static int io_insert(struct sm_disk *io, dm_block_t b, uint32_t ref_count)
{
	int r;
	uint32_t bit, old;
	struct dm_block *nb;
	dm_block_t index = b;
	struct index_entry ie;
	void *bm;
	int inc;

	do_div(index, io->entries_per_block);
	r = dm_btree_lookup_equal(&io->bitmap_info, io->bitmap_root, &index, &ie);
	if (r < 0)
		return r;

	r = dm_tm_shadow_block(io->tm, __le64_to_cpu(ie.b), &nb, &inc);
	if (r < 0) {
		printk(KERN_ALERT "shadow failed");
		return r;
	}

	bm = dm_block_data(nb);
	bit = mod64(b, io->entries_per_block);
	old = __lookup_bitmap(bm, bit);

	if (ref_count <= 2) {
		__set_bitmap(bm, bit, ref_count);
		BUG_ON(__lookup_bitmap(bm, bit) != ref_count);

		if (old > 2) {
#if 0
			if (!btree_remove(&io->ref_count_info, io->ref_count_root,
					  &b, &io->ref_count_root))
				abort();
#endif
		}
	} else {
		__le32 le_rc = __cpu_to_le32(ref_count);
		__set_bitmap(bm, bit, 3);
		r = dm_btree_insert(&io->ref_count_info, io->ref_count_root,
				    &b, &le_rc, &io->ref_count_root);
		if (r < 0) {
			dm_tm_unlock(io->tm, nb);
			/* FIXME: release shadow? or assume the whole transaction will be ditched */
			printk(KERN_ALERT "ref count insert failed");
			return r;
		}
	}

	r = dm_tm_unlock(io->tm, nb);
	if (r < 0)
		return r;

	if (ref_count && !old) {
		io->nr_allocated++;
		ie.nr_free = __cpu_to_le32(__le32_to_cpu(ie.nr_free) - 1);
		if (__le32_to_cpu(ie.none_free_before) == b)
			ie.none_free_before = __cpu_to_le32(b + 1);

	} else if (old && !ref_count) {
		io->nr_allocated--;
		ie.nr_free = __cpu_to_le32(__le32_to_cpu(ie.nr_free) + 1);
		ie.none_free_before = __cpu_to_le32(min_block(__le32_to_cpu(ie.none_free_before), b));
	}

	/*
	 * FIXME: we have a race here, since another thread may have
	 * altered |ie| in the meantime.  Not important yet.
	 */
	ie.b = __cpu_to_le64(dm_block_location(nb));
	r = dm_btree_insert(&io->bitmap_info, io->bitmap_root,
			    &index, &ie, &io->bitmap_root);
	if (r < 0)
		return r;

	return 0;
}

/*----------------------------------------------------------------*/

static void sm_disk_destroy(void *context)
{
	struct sm_disk *smd = (struct sm_disk *) context;
	kfree(smd);
}

static int sm_disk_get_nr_blocks(void *context, dm_block_t *count)
{
	struct sm_disk *smd = (struct sm_disk *) context;

	*count = smd->nr_blocks;
	return 0;
}

static int sm_disk_get_nr_free(void *context, dm_block_t *count)
{
	struct sm_disk *smd = (struct sm_disk *) context;

	*count = smd->nr_blocks - smd->nr_allocated;
	return 0;
}

static int sm_disk_get_count(void *context, dm_block_t b, uint32_t *result)
{
	struct sm_disk *smd = (struct sm_disk *) context;
	return io_lookup(smd, b, result);
}

static int sm_disk_set_count(void *context, dm_block_t b, uint32_t count)
{
	struct sm_disk *smd = (struct sm_disk *) context;
	return io_insert(smd, b, count);
}

static int __get_free(void *context, dm_block_t low, dm_block_t high,
		      dm_block_t *b)
{
	struct sm_disk *smd = (struct sm_disk *) context;
	int r;

	high = min(high, smd->nr_blocks);
	if (low >= high)
		return -ENOSPC;

	r = io_find_unused(smd, low, high, b);
	if (r == -ENODATA)
		return -ENOSPC;
	else if (r < 0)
		return r;

	return 0;
}

static int sm_disk_get_free(void *context, dm_block_t *b)
{
	struct sm_disk *smd = (struct sm_disk *) context;
	return __get_free(context, 0, smd->nr_blocks, b);
}

static int sm_disk_get_free_in_range(void *context, dm_block_t low,
				     dm_block_t high, dm_block_t *b)
{
	return __get_free(context, low, high, b);
}

static int sm_disk_commit(void *context)
{
	/*
	 * We don't need to do anything here other than drop all held block
	 * locks.
	 */
	return 0;
}

static int sm_disk_root_size(void *context, size_t *result)
{
	*result = sizeof(struct sm_root);
	return 0;
}

static int sm_disk_copy_root(void *context, void *where, size_t max)
{
	struct sm_disk *smd = (struct sm_disk *) context;
	struct sm_root root;

	root.nr_blocks = __cpu_to_le64(smd->nr_blocks);
	root.nr_allocated = __cpu_to_le64(smd->nr_allocated);
	root.bitmap_root = __cpu_to_le64(smd->bitmap_root);
	root.ref_count_root = __cpu_to_le64(smd->ref_count_root);

	if (max < sizeof(root))
		return -ENOSPC;

	memcpy(where, &root, sizeof(root));

	return 0;
}

/*----------------------------------------------------------------*/

static struct dm_space_map_ops ops_ = {
	.destroy = sm_disk_destroy,
	.get_nr_blocks = sm_disk_get_nr_blocks,
	.get_nr_free = sm_disk_get_nr_free,
	.get_count = sm_disk_get_count,
	.set_count = sm_disk_set_count,
	.get_free = sm_disk_get_free,
	.get_free_in_range = sm_disk_get_free_in_range,
	.commit = sm_disk_commit,
	.root_size = sm_disk_root_size,
	.copy_root = sm_disk_copy_root
};

struct dm_space_map *dm_sm_disk_create(struct dm_transaction_manager *tm,
				       dm_block_t nr_blocks)
{
	int r;
	struct dm_space_map *sm = NULL;
	struct sm_disk *smd;
	
	smd = alloc_smd(tm);
	if (!smd)
		return ERR_PTR(-ENOMEM);

	r = io_new(smd, tm, nr_blocks);
	if (r < 0) {
		kfree(smd);
		return ERR_PTR(r);
	}

	sm = kmalloc(sizeof(*sm), GFP_KERNEL);
	if (!sm) {
		kfree(smd);
		return ERR_PTR(-ENOMEM);
	}
	sm->ops = &ops_;
	sm->context = smd;

	return sm;
}
EXPORT_SYMBOL_GPL(dm_sm_disk_create);

struct dm_space_map *dm_sm_disk_open(struct dm_transaction_manager *tm,
				     void *root, size_t len)
{
	int r;
	struct dm_space_map *sm = NULL;
	struct sm_disk *smd;

	smd = alloc_smd(tm);
	if (!smd)
		return ERR_PTR(-ENOMEM);

	r = io_open(smd, tm, root, len);
	if (r < 0) {
		kfree(smd);
		return ERR_PTR(r);
	}

	sm = kmalloc(sizeof(*sm), GFP_KERNEL);
	if (!sm) {
		kfree(smd);
		return ERR_PTR(-ENOMEM);
	}
	sm->ops = &ops_;
	sm->context = smd;

	return sm;
}
EXPORT_SYMBOL_GPL(dm_sm_disk_open);

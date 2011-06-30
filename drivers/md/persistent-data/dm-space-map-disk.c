#include "dm-space-map-common.h"
#include "dm-space-map-disk.h"

#include <linux/crc32c.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <asm-generic/bitops/le.h>

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

/*----------------------------------------------------------------
 * bitmap validator
 *--------------------------------------------------------------*/
static void bitmap_prepare_for_write(struct dm_block_validator *v,
				     struct dm_block *b,
				     size_t block_size)
{
	struct bitmap_header *header = dm_block_data(b);

	header->blocknr = __cpu_to_le64(dm_block_location(b));
	header->csum = __cpu_to_le32(crc32c(~ ((u32) 0),
					    &header->not_used,
					    block_size - sizeof(u32)));
}

static int bitmap_check(struct dm_block_validator *v,
			struct dm_block *b,
			size_t block_size)
{
	struct bitmap_header *header = dm_block_data(b);
	__le32 csum;

	if (dm_block_location(b) != __le64_to_cpu(header->blocknr)) {
		printk(KERN_ERR "space map bitmap check failed blocknr %llu "
		       "wanted %llu\n",
		       __le64_to_cpu(header->blocknr), dm_block_location(b));
		return -ENOTBLK;
	}

	csum = __cpu_to_le32(crc32c(~ ((u32) 0),
				    (void *) &header->not_used,
				    block_size - sizeof(u32)));
	if (csum != header->csum) {
		printk(KERN_ERR "space-map bitmap check failed csum %u wanted %u\n",
		       __le32_to_cpu(csum), __le32_to_cpu(header->csum));
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

void *dm_bitmap_data(struct dm_block *b)
{
	return dm_block_data(b) + sizeof(struct bitmap_header);
}

#define WORD_MASK_LOW 0x5555555555555555
#define WORD_MASK_HIGH 0xAAAAAAAAAAAAAAAA
#define WORD_MASK_ALL 0xFFFFFFFFFFFFFFFF

static unsigned bitmap_word_used(void *addr, unsigned b)
{
	__le64 *words = (__le64 *) addr;
        __le64 *w = words + (b / ENTRIES_PER_WORD); /* FIXME: 64 bit div, use shift */

	return ((*w & WORD_MASK_LOW) == WORD_MASK_LOW ||
		(*w & WORD_MASK_HIGH) == WORD_MASK_HIGH ||
		(*w & WORD_MASK_ALL) == WORD_MASK_ALL);
}

unsigned sm__lookup_bitmap(void *addr, unsigned b)
{
	unsigned val;
	__le64 *words = (__le64 *) addr;
        __le64 *w = words + (b / ENTRIES_PER_WORD); /* FIXME: 64 bit div, use shift */

	b %= ENTRIES_PER_WORD;
	val = test_bit_le(b * 2, (void*) w) ? 1 : 0;
	val <<= 1;
	val |= test_bit_le(b * 2 + 1, (void *) w) ? 1 : 0;

        return val;
}


void sm__set_bitmap(void *addr, unsigned b, unsigned val)
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

int sm__find_free(void *addr, unsigned begin, unsigned end,
		  unsigned *result)
{
	while (begin < end) {
		if (!(begin & (ENTRIES_PER_WORD - 1)) &&
		    bitmap_word_used(addr, begin)) {
			begin += ENTRIES_PER_WORD;
			continue;
		}

		if (sm__lookup_bitmap(addr, begin)) {
			begin++;

		} else {
			*result = begin;
			return 0;
		}
	}

	return -ENOSPC;
}

static int ll_init(struct ll_disk *io, struct dm_transaction_manager *tm)
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
	io->entries_per_block = (io->block_size - sizeof(struct bitmap_header)) *
		ENTRIES_PER_BYTE;
	io->nr_blocks = 0;
	io->bitmap_root = 0;
	io->ref_count_root = 0;

	return 0;
}

static int ll_new(struct ll_disk *io, struct dm_transaction_manager *tm)
{
	int r;

	r = ll_init(io, tm);
	if (r < 0)
		return r;

	io->nr_blocks = 0;
	io->nr_allocated = 0;
	r = dm_btree_empty(&io->bitmap_info, &io->bitmap_root);
	if (r < 0)
		return r;

	r = dm_btree_empty(&io->ref_count_info, &io->ref_count_root);
	if (r < 0) {
		dm_btree_del(&io->bitmap_info, io->bitmap_root);
		return r;
	}

	return 0;
}

static int ll_extend(struct ll_disk *io, dm_block_t extra_blocks)
{
	int r;
	dm_block_t i, nr_blocks;
	unsigned old_blocks, blocks;

	nr_blocks = io->nr_blocks + extra_blocks;
	old_blocks = div_up(io->nr_blocks, io->entries_per_block);
	blocks = div_up(nr_blocks, io->entries_per_block);
	for (i = old_blocks; i < blocks; i++) {
		struct dm_block *b;
		struct index_entry idx;

		r = dm_tm_new_block(io->tm, &dm_sm_bitmap_validator, &b);
		if (r < 0)
			return r;
		idx.blocknr = __cpu_to_le64(dm_block_location(b));

		r = dm_tm_unlock(io->tm, b);
		if (r < 0)
			return r;

		idx.nr_free = __cpu_to_le32(io->entries_per_block);
		idx.none_free_before = 0;

		r = dm_btree_insert(&io->bitmap_info, io->bitmap_root,
				    &i, &idx, &io->bitmap_root);
		if (r < 0)
			return r;
	}

	io->nr_blocks = nr_blocks;
	return 0;
}

static int ll_open(struct ll_disk *ll, struct dm_transaction_manager *tm,
		   void *root, size_t len)
{
	int r;
	struct sm_root *smr = (struct sm_root *) root;

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
	ll->ref_count_root = __le64_to_cpu(smr->ref_count_root);

	return 0;
}

static int ll_lookup_bitmap(struct ll_disk *io, dm_block_t b, uint32_t *result)
{
	int r;
	dm_block_t index = b;
	struct index_entry ie;
	struct dm_block *blk;

	do_div(index, io->entries_per_block);

	r = dm_btree_lookup(&io->bitmap_info, io->bitmap_root, &index, &ie);
	if (r < 0)
		return r;

	r = dm_tm_read_lock(io->tm, __le64_to_cpu(ie.blocknr), &dm_sm_bitmap_validator, &blk);
	if (r < 0)
		return r;
	*result = sm__lookup_bitmap(dm_bitmap_data(blk),
				     mod64(b, io->entries_per_block));
	return dm_tm_unlock(io->tm, blk);
}

static int ll_lookup(struct ll_disk *io, dm_block_t b, uint32_t *result)
{
	int r = ll_lookup_bitmap(io, b, result);

	if (r)
		return r;

	if (*result == 3) {
		__le32 le_rc;
		r = dm_btree_lookup(&io->ref_count_info, io->ref_count_root,
				    &b, &le_rc);
		if (r < 0)
			return r;

		*result = __le32_to_cpu(le_rc);
	}

	return r;
}

static int ll_find_free_block(struct ll_disk *io, dm_block_t begin,
			      dm_block_t end, dm_block_t *result)
{
	int r;
	struct index_entry ie;
	dm_block_t i, index_begin = begin;
	dm_block_t index_end = div_up(end, io->entries_per_block);

	begin = do_div(index_begin, io->entries_per_block);
	for (i = index_begin; i < index_end; i++, begin = 0) {
		r = dm_btree_lookup(&io->bitmap_info, io->bitmap_root, &i, &ie);
		if (r < 0)
			return r;

		if (__le32_to_cpu(ie.nr_free) > 0) {
			struct dm_block *blk;
			unsigned position;
			uint32_t bit_end = (i == index_end - 1) ?
				mod64(end, io->entries_per_block) :
				io->entries_per_block;

			r = dm_tm_read_lock(io->tm, __le64_to_cpu(ie.blocknr),
					    &dm_sm_bitmap_validator, &blk);
			if (r < 0)
				return r;

			r = sm__find_free(dm_bitmap_data(blk),
					  max((unsigned) begin, (unsigned) __le32_to_cpu(ie.none_free_before)),
					  bit_end, &position);
			if (r < 0) {
				dm_tm_unlock(io->tm, blk);
				continue;
			}

			r = dm_tm_unlock(io->tm, blk);
			if (r < 0)
				return r;

			*result = i * io->entries_per_block + (dm_block_t) position;
			return 0;
		}
	}

	return -ENOSPC;
}

static int ll_insert(struct ll_disk *io, dm_block_t b, uint32_t ref_count)
{
	int r;
	uint32_t bit, old;
	struct dm_block *nb;
	dm_block_t index = b;
	struct index_entry ie;
	void *bm;
	int inc;

	do_div(index, io->entries_per_block);
	r = dm_btree_lookup(&io->bitmap_info, io->bitmap_root, &index, &ie);
	if (r < 0)
		return r;

	r = dm_tm_shadow_block(io->tm, __le64_to_cpu(ie.blocknr),
			       &dm_sm_bitmap_validator, &nb, &inc);
	if (r < 0) {
		printk(KERN_ALERT "shadow failed");
		return r;
	}
	ie.blocknr = __cpu_to_le64(dm_block_location(nb));

	bm = dm_bitmap_data(nb);
	bit = mod64(b, io->entries_per_block);
	old = sm__lookup_bitmap(bm, bit);

	if (ref_count <= 2) {
		sm__set_bitmap(bm, bit, ref_count);
		BUG_ON(sm__lookup_bitmap(bm, bit) != ref_count);

		if (old > 2) {
			r = dm_btree_remove(&io->ref_count_info, io->ref_count_root,
					    &b, &io->ref_count_root);
			if (r) {
				dm_tm_unlock(io->tm, nb);
				return r;
			}
		}
	} else {
		__le32 le_rc = __cpu_to_le32(ref_count);
		sm__set_bitmap(bm, bit, 3);
		r = dm_btree_insert(&io->ref_count_info, io->ref_count_root,
				    &b, &le_rc, &io->ref_count_root);
		if (r < 0) {
			dm_tm_unlock(io->tm, nb);
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
		ie.none_free_before = __cpu_to_le32(min((dm_block_t) __le32_to_cpu(ie.none_free_before), b));
	}

	r = dm_btree_insert(&io->bitmap_info, io->bitmap_root,
			    &index, &ie, &io->bitmap_root);
	if (r < 0)
		return r;

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

	if (!rc)
		return -EINVAL;

	return ll_insert(ll, b, rc - 1);
}

/*----------------------------------------------------------------
 * Space map interface.
 *--------------------------------------------------------------*/
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
	return ll_extend(&smd->ll, extra_blocks);
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

static int sm_disk_get_count(struct dm_space_map *sm, dm_block_t b, uint32_t *result)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);
	return ll_lookup(&smd->ll, b, result);
}

static int sm_disk_count_is_more_than_one(struct dm_space_map *sm, dm_block_t b, int *result)
{
	int r;
	uint32_t count;

	r = sm_disk_get_count(sm, b, &count);
	if (r)
		return r;

	return count > 1;
}

static int sm_disk_set_count(struct dm_space_map *sm, dm_block_t b, uint32_t count)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);
	return ll_insert(&smd->ll, b, count);
}

static int sm_disk_inc_block(struct dm_space_map *sm, dm_block_t b)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);
	return ll_inc(&smd->ll, b);
}

static int sm_disk_dec_block(struct dm_space_map *sm, dm_block_t b)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);
	return ll_dec(&smd->ll, b);
}

static int sm_disk_new_block(struct dm_space_map *sm, dm_block_t *b)
{
	int r;
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);

	/* FIXME: we should start the search where we left off */
	r = ll_find_free_block(&smd->ll, 0, smd->ll.nr_blocks, b);
	if (r)
		return r;

	return ll_inc(&smd->ll, *b);
}

static int sm_disk_commit(struct dm_space_map *sm)
{
	return 0;
}

static int sm_disk_root_size(struct dm_space_map *sm, size_t *result)
{
	*result = sizeof(struct sm_root);
	return 0;
}

static int sm_disk_copy_root(struct dm_space_map *sm, void *where, size_t max)
{
	struct sm_disk *smd = container_of(sm, struct sm_disk, sm);
	struct sm_root root;

	root.nr_blocks = __cpu_to_le64(smd->ll.nr_blocks);
	root.nr_allocated = __cpu_to_le64(smd->ll.nr_allocated);
	root.bitmap_root = __cpu_to_le64(smd->ll.bitmap_root);
	root.ref_count_root = __cpu_to_le64(smd->ll.ref_count_root);

	if (max < sizeof(root))
		return -ENOSPC;

	memcpy(where, &root, sizeof(root));
	return 0;
}

/*----------------------------------------------------------------*/

static struct dm_space_map ops_ = {
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

	memcpy(&smd->sm, &ops_, sizeof(smd->sm));

	r = ll_new(&smd->ll, tm);
	if (r)
		return ERR_PTR(r);

	r = ll_extend(&smd->ll, nr_blocks);
	if (r)
		return ERR_PTR(r);

	r = sm_disk_commit(&smd->sm);
	if (r)
		return ERR_PTR(r);

	return &smd->sm;
}
EXPORT_SYMBOL_GPL(dm_sm_disk_create);

struct dm_space_map *dm_sm_disk_open(struct dm_transaction_manager *tm,
				     void *root, size_t len)
{
	int r;
	struct sm_disk *smd;

	smd = kmalloc(sizeof(*smd), GFP_KERNEL);
	if (!smd)
		return ERR_PTR(-ENOMEM);

	memcpy(&smd->sm, &ops_, sizeof(smd->sm));

	r = ll_open(&smd->ll, tm, root, len);
	if (r)
		return ERR_PTR(r);

	r = sm_disk_commit(&smd->sm);
	if (r)
		return ERR_PTR(r);

	return &smd->sm;
}
EXPORT_SYMBOL_GPL(dm_sm_disk_open);

#include <linux/slab.h>

#include "transaction-manager.h"

/*----------------------------------------------------------------*/

struct shadow_info {
	struct hlist_node hlist;
	dm_block_t where;
};

/* it would be nice if we scaled with the size of transaction */
#define HASH_SIZE 256
#define HASH_MASK (HASH_SIZE - 1)
struct transaction_manager {
	int is_clone;
	struct transaction_manager *real;

	struct dm_block_manager *bm;
	struct space_map *sm;

	struct hlist_head buckets[HASH_SIZE];

	/* stats */
	unsigned shadow_count;
};

/*----------------------------------------------------------------*/

/* FIXME: similar code in block-manager */
static unsigned hash_block(dm_block_t b)
{
	const unsigned BIG_PRIME = 4294967291UL;
	return (((unsigned) b) * BIG_PRIME) & HASH_MASK;
}

static int is_shadow(struct transaction_manager *tm, dm_block_t b)
{
	unsigned bucket = hash_block(b);
	struct shadow_info *si;
	struct hlist_node *n;

	hlist_for_each_entry (si, n, tm->buckets + bucket, hlist)
		if (si->where == b)
			return 1;

	return 0;
}

/*
 * This can silently fail if there's no memory.  We're ok with this since
 * creating redundant shadows causes no harm.
 */
static void insert_shadow(struct transaction_manager *tm, dm_block_t b)
{
	unsigned bucket;
	struct shadow_info *si = kmalloc(sizeof(*si), GFP_NOIO);
	if (si) {
		si->where = b;
		bucket = hash_block(b);
		hlist_add_head(&si->hlist, tm->buckets + bucket);
	} else
		printk(KERN_ALERT "shadow_insert failed"); /* FIXME: remove */
}

/*----------------------------------------------------------------*/

struct transaction_manager *tm_create(struct dm_block_manager *bm,
				      struct space_map *sm)
{
	struct transaction_manager *tm = kmalloc(sizeof(*tm), GFP_KERNEL);
	if (tm) {
		int i;

		tm->is_clone = 0;
		tm->real = NULL;
		tm->bm = bm;
		tm->sm = sm;

		for (i = 0; i < HASH_SIZE; i++)
			INIT_HLIST_HEAD(tm->buckets + i);

		tm->shadow_count = 0;
	}

	return tm;
}
EXPORT_SYMBOL_GPL(tm_create);

struct transaction_manager *tm_create_non_blocking_clone(struct transaction_manager *real)
{
	struct transaction_manager *tm = kmalloc(sizeof(*tm), GFP_KERNEL);
	if (tm) {
		tm->is_clone = 1;
		tm->real = real;
	}
	return tm;
}
EXPORT_SYMBOL_GPL(tm_create_non_blocking_clone);

void tm_destroy(struct transaction_manager *tm)
{
	kfree(tm);
}
EXPORT_SYMBOL_GPL(tm_destroy);

int tm_reserve_block(struct transaction_manager *tm, dm_block_t b)
{
	if (tm->is_clone)
		return -EWOULDBLOCK;

	return sm_inc_block(tm->sm, b);
}
EXPORT_SYMBOL_GPL(tm_reserve_block);

int tm_begin(struct transaction_manager *tm)
{
	return 0;
}
EXPORT_SYMBOL_GPL(tm_begin);

int tm_pre_commit(struct transaction_manager *tm)
{
	int r;

	if (tm->is_clone)
		return -EWOULDBLOCK;

	r = sm_commit(tm->sm);
	if (r < 0)
		return r;

	return 0;
}
EXPORT_SYMBOL_GPL(tm_pre_commit);

int tm_commit(struct transaction_manager *tm, struct dm_block *root)
{
	if (tm->is_clone)
		return -EWOULDBLOCK;

	return dm_bm_flush_and_unlock(tm->bm, root);
}
EXPORT_SYMBOL_GPL(tm_commit);

int tm_alloc_block(struct transaction_manager *tm, dm_block_t *new)
{
	if (tm->is_clone)
		return -EWOULDBLOCK;

	return sm_new_block(tm->sm, new);
}
EXPORT_SYMBOL_GPL(tm_alloc_block);

int tm_new_block(struct transaction_manager *tm, struct dm_block **result)
{
	int r;
	dm_block_t new;

	if (tm->is_clone)
		return -EWOULDBLOCK;

	r = sm_new_block(tm->sm, &new);
	if (r < 0)
		return r;

	r = dm_bm_write_lock_zero(tm->bm, new, result);
	if (r < 0) {
		sm_dec_block(tm->sm, new);
		return r;
	}

	/* New blocks count as shadows, in that they don't need to be
	 * shadowed again.
	 */
	insert_shadow(tm, new);
	return 0;
}
EXPORT_SYMBOL_GPL(tm_new_block);

static int tm_shadow_block_(struct transaction_manager *tm,
			    dm_block_t orig,
			    struct dm_block **result,
			    int *inc_children)
{
	int r;
	dm_block_t new;
	uint32_t count;
	struct dm_block *origb;

	r = sm_new_block(tm->sm, &new);
	if (r < 0) {
		printk(KERN_ALERT "shadow 1");
		return r;
	}

	r = dm_bm_write_lock_zero(tm->bm, new, result);
	if (r < 0) {
		printk(KERN_ALERT "shadow 2");
		sm_dec_block(tm->sm, new);
		return r;
	}

	r = dm_bm_read_lock(tm->bm, orig, &origb);
	if (r < 0) {
		sm_dec_block(tm->sm, new);
		return r;
	}
	memcpy(dm_block_data(*result),
	       dm_block_data(origb),
	       dm_bm_block_size(tm->bm));
	r = dm_bm_unlock(origb);
	if (r < 0) {
		sm_dec_block(tm->sm, new);
		return r;
	}

	r = sm_get_count(tm->sm, orig, &count);
	if (r < 0) {
		printk(KERN_ALERT "shadow 3");
		sm_dec_block(tm->sm, new);
		dm_bm_unlock(*result);
		return r;
	}

	r = sm_dec_block(tm->sm, orig);
	if (r < 0) {
		printk(KERN_ALERT "shadow 4");
		sm_dec_block(tm->sm, new);
		dm_bm_unlock(*result);
		return r;
	}

	*inc_children = count > 1;
	return 0;
}

int tm_shadow_block(struct transaction_manager *tm,
		    dm_block_t orig,
		    struct dm_block **result,
		    int *inc_children)
{
	int r;
	uint32_t count;
	//static unsigned shadows = 0;

	if (tm->is_clone)
		return -EWOULDBLOCK;

	if (is_shadow(tm, orig)) {
		r = sm_get_count(tm->sm, orig, &count);
		if (r < 0)
			return r;

		if (count < 2) {
			*inc_children = 0;
			return dm_bm_write_lock(tm->bm, orig, result);
		}

		/* fall through */
	}

	// putting a printk here reveals a bug
	//printk(KERN_ALERT "shadows = %u", ++shadows);
	r = tm_shadow_block_(tm, orig, result, inc_children);
	if (r < 0)
		return r;
	tm->shadow_count++;
	insert_shadow(tm, dm_block_location(*result));
	return r;
}
EXPORT_SYMBOL_GPL(tm_shadow_block);

int tm_read_lock(struct transaction_manager *tm,
		 dm_block_t b,
		 struct dm_block **blk)
{
	return tm->is_clone ?
		dm_bm_read_try_lock(tm->real->bm, b, blk) :
		dm_bm_read_lock(tm->bm, b, blk);
}
EXPORT_SYMBOL_GPL(tm_read_lock);

int tm_unlock(struct transaction_manager *tm,
	      struct dm_block *b)
{
	return dm_bm_unlock(b);
}
EXPORT_SYMBOL_GPL(tm_unlock);

void tm_inc(struct transaction_manager *tm,
	    dm_block_t b)
{
	BUG_ON(tm->is_clone);
	sm_inc_block(tm->sm, b);
}
EXPORT_SYMBOL_GPL(tm_inc);

void tm_dec(struct transaction_manager *tm,
	    dm_block_t b)
{
	BUG_ON(tm->is_clone);
	sm_dec_block(tm->sm, b);
}
EXPORT_SYMBOL_GPL(tm_dec);

int tm_ref(struct transaction_manager *tm,
	   dm_block_t b,
	   uint32_t *result)
{
	if (tm->is_clone)
		return -EWOULDBLOCK;

	return sm_get_count(tm->sm, b, result);
}
EXPORT_SYMBOL_GPL(tm_ref);

struct dm_block_manager *tm_get_bm(struct transaction_manager *tm)
{
	BUG_ON(tm->is_clone);
	return tm->bm;
}
EXPORT_SYMBOL_GPL(tm_get_bm);

/*----------------------------------------------------------------*/

// FIXME: does this belong here ?
#include "space-map-staged.h"
#include "space-map-disk.h"

int tm_create_with_sm(struct dm_block_manager *bm,
		      dm_block_t superblock,
		      struct transaction_manager **tm,
		      struct space_map **sm,
		      struct dm_block **sb)
{
	int r;
	struct space_map *dummy = sm_dummy_create(dm_bm_nr_blocks(bm)), *disk, *staged;

	staged = sm_staged_create(dummy);
	if (!staged) {
		printk(KERN_ALERT "couldn't create staged sm");
		return -1;
	}

	*tm = tm_create(bm, staged);
	if (!tm)
		return -1;


	/* nasty bootstrap problem, first create the disk space map ... */
	r = tm_begin(*tm);
	if (r < 0)
		return r;

	r = tm_reserve_block(*tm, superblock);
	if (r < 0) {
		printk(KERN_ALERT "couldn't reserve superblock");
		return r;
	}

	r = dm_bm_write_lock(tm_get_bm(*tm), superblock, sb);
	if (r < 0) {
		printk(KERN_ALERT "couldn't lock superblock");
		return r;
	}

	disk = sm_disk_create(*tm, dm_bm_nr_blocks(bm));
	if (!disk) {
		printk(KERN_ALERT "couldn't create disk space map");
		return -ENOMEM;
	}

	/* ... now we swap the dummy out and the disk in ... */
	r = sm_staged_set_wrappee(staged, disk);
	if (r < 0) {
		printk(KERN_ALERT "couldn't set staged wrappee");
		return r;
	}

	sm_destroy(dummy);
	*sm = staged;
	return 0;
}
EXPORT_SYMBOL_GPL(tm_create_with_sm);

int tm_open_with_sm(struct dm_block_manager *bm,
		    dm_block_t superblock,
		    size_t root_offset,
		    size_t root_max_len,
		    struct transaction_manager **tm,
		    struct space_map **sm,
		    struct dm_block **sb)
{
	int r;
	struct space_map *dummy = sm_dummy_create(dm_bm_nr_blocks(bm)), *disk, *staged;

	staged = sm_staged_create(dummy);
	if (!staged) {
		printk(KERN_ALERT "couldn't create staged sm");
		return -1;
	}

	*tm = tm_create(bm, staged);
	if (!tm) {
		sm_destroy(staged);
		return -ENOMEM;
	}

	/* nasty bootstrap problem, first create the disk space map ... */
	r = tm_begin(*tm);
	if (r < 0) {
		tm_destroy(*tm);
		sm_destroy(staged);
		return r;
	}

	r = tm_reserve_block(*tm, superblock);
	if (r < 0) {
		printk(KERN_ALERT "couldn't reserve superblock");
		tm_destroy(*tm);
		sm_destroy(staged);
		return r;
	}

	r = dm_bm_write_lock(tm_get_bm(*tm), superblock, sb);
	if (r < 0) {
		printk(KERN_ALERT "couldn't lock superblock");
		tm_destroy(*tm);
		sm_destroy(staged);
		return r;
	}

	disk = sm_disk_open(*tm, dm_block_data(*sb) + root_offset, root_max_len);
	if (!disk) {
		printk(KERN_ALERT "couldn't create disk space map");
		dm_bm_unlock(*sb);
		tm_destroy(*tm);
		sm_destroy(staged);
		return -ENOMEM;
	}

	/* ... now we swap the dummy out and the disk in ... */
	r = sm_staged_set_wrappee(staged, disk);
	if (r < 0) {
		printk(KERN_ALERT "couldn't set staged wrappee");
		dm_bm_unlock(*sb);
		tm_destroy(*tm);
		sm_destroy(staged);
		return r;
	}

	sm_destroy(dummy);
	*sm = staged;
	return 0;

}
EXPORT_SYMBOL_GPL(tm_open_with_sm);

unsigned tm_shadow_count(struct transaction_manager *tm)
{
	return tm->shadow_count;
}
EXPORT_SYMBOL_GPL(tm_shadow_count);

/*----------------------------------------------------------------*/

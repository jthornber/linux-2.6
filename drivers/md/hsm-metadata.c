/*
 * Copyright (C) 2011 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "hsm-metadata.h"

#include <linux/list.h>
#include <linux/device-mapper.h>
#include <linux/workqueue.h>

/*----------------------------------------------------------------*/
#if 0
#define	DM_MSG_PREFIX	"dm-hsm"
#define	DAEMON		DM_MSG_PREFIX	"d"

#define HSM_SUPERBLOCK_MAGIC 21081990
#define HSM_SUPERBLOCK_LOCATION 0
#define HSM_VERSION 1
#define HSM_METADATA_BLOCK_SIZE 4096
#define HSM_METADATA_CACHE_SIZE 1024
#define SECTOR_TO_BLOCK_SHIFT 3

struct superblock {
	__le64 magic;
	__le64 version;

	__le64 metadata_block_size; /* in sectors */
	__le64 metadata_nr_blocks;

	__le64 data_block_size;	/* in sectors */
	__le64 data_nr_blocks;
	__le64 first_free_block; /* Initial allocation. */
	__le64 freed_block;	 /* Allocation of freed block. */

	__le64 btree_root;
	__le64 btree_reverse_root;

	/*
	 * Space map fields.
	 *
	 * The space map stores its root here, it will probably be longer
	 * than a __le64.
	 */
	__le64 sm_root_start;
};

/* FIXME: we need some locking */
struct hsm_metadata {
	atomic_t ref_count;
	struct hlist_node hash;

	struct block_device *bdev;
	struct dm_block_manager *bm;
	struct dm_space_map *sm;
	struct dm_transaction_manager *tm;
	struct dm_transaction_manager *nb_tm;

	/*
	 * Two level btree, first level is hsm_dev_t,
	 * second level mappings.
	 * I need a reverse mapping btree with the same info
	 * to be able to free cached blocks.
	 */
	struct dm_btree_info info;

	/* non-blocking versions of the above */
	struct dm_btree_info nb_info;

	/* just the top level, for deleting whole devices */
	struct dm_btree_info dev_info;

	int have_updated;

	struct rw_semaphore root_lock;
	struct dm_block *sblock;

	dm_block_t root;
	dm_block_t reverse_root;
};

/*----------------------------------------------------------------*/

static int superblock_all_zeroes(struct dm_block_manager *bm, int *result)
{
	int r, i;
	struct dm_block *b;
	uint64_t *data;
	size_t block_size = dm_bm_block_size(bm) / sizeof(uint64_t);

	r = dm_bm_read_lock(bm, HSM_SUPERBLOCK_LOCATION, &b);
	if (r)
		return r;

	data = dm_block_data(b);
	*result = 1;
	for (i = 0; i < block_size; i++) {
		if (data[i] != 0LL) {
			*result = 0;
			break;
		}
	}

	return dm_bm_unlock(b);
}

static struct hsm_metadata *
alloc_(struct dm_block_manager *bm, int create)
{
	int r;
	struct dm_space_map *sm;
	struct dm_transaction_manager *tm;
	struct hsm_metadata *hsm;
	struct dm_block *sb;

	if (create) {
		r = dm_tm_create_with_sm(bm, HSM_SUPERBLOCK_LOCATION, &tm, &sm, &sb);
		if (r < 0) {
			printk(KERN_ALERT "tm_create_with_sm failed");
			dm_block_manager_destroy(bm);
			return NULL;
		}

		r = dm_tm_pre_commit(tm);
		if (r < 0) {
			printk(KERN_ALERT "couldn't pre commit");
			goto bad;
		}

		r = dm_tm_commit(tm, sb);
		if (r < 0) {
			printk(KERN_ALERT "couldn't commit");
			goto bad;
		}
	} else {
		struct superblock *s = NULL;

		r = dm_tm_open_with_sm(bm, HSM_SUPERBLOCK_LOCATION,
				    (size_t) &((struct superblock *) NULL)->sm_root_start,
				    32, 	/* FIXME: magic number */
				    &tm, &sm, &sb);
		if (r < 0) {
			printk(KERN_ALERT "tm_open_with_sm failed");
			dm_block_manager_destroy(bm);
			return NULL;
		}

		s = dm_block_data(sb);
		if (__le64_to_cpu(s->magic) != HSM_SUPERBLOCK_MAGIC) {
			printk(KERN_ALERT "hsm-metadata superblock is invalid");
			goto bad;
		}

		dm_tm_unlock(tm, sb);
	}

	hsm = kmalloc(sizeof(*hsm), GFP_KERNEL);
	if (!hsm) {
		printk(KERN_ALERT "hsm-metadata could not allocate metadata struct");
		goto bad;
	}

	hsm->bm = bm;
	hsm->sm = sm;
	hsm->tm = tm;
	hsm->nb_tm = dm_tm_create_non_blocking_clone(tm);
	if (!hsm->nb_tm) {
		printk(KERN_ALERT "hsm-metadata could not create clone tm");
		goto bad;
	}

	hsm->sblock = NULL;
	hsm->info.tm = tm;
	hsm->info.levels = 2;

	hsm->info.value_type.context = NULL;
	hsm->info.value_type.size = sizeof(dm_block_t);
	hsm->info.value_type.copy = NULL; /* because the blocks are held in a separate device */
	hsm->info.value_type.del = NULL;
	hsm->info.value_type.equal = NULL;

	memcpy(&hsm->nb_info, &hsm->info, sizeof(hsm->nb_info));
	hsm->nb_info.tm = hsm->nb_tm;

	hsm->dev_info.tm = tm;
	hsm->dev_info.levels = 1;
	hsm->dev_info.value_type.context = tm;
	hsm->dev_info.value_type.copy = NULL; /* FIXME: finish */
	hsm->dev_info.value_type.del = NULL;
	hsm->dev_info.value_type.equal = NULL;

	hsm->have_updated = 0;
	hsm->root = 0;

	init_rwsem(&hsm->root_lock);

	/*
	 * Create singlethreaded workqueue that will
	 * service all devices that use this metadata.
	 */
	hsm->wq = alloc_ordered_workqueue(DAEMON, WQ_MEM_RECLAIM);
	if (!hsm->wq) {
		printk(KERN_ALERT "couldn't create workqueue for metadata object");
		goto bad;
	}

	return hsm;

bad:
	dm_tm_destroy(tm);
	dm_sm_destroy(sm);
	dm_block_manager_destroy(bm);
	return NULL;
}

static int hsm_metadata_begin(struct hsm_metadata *hsm)
{
	int r;
	struct superblock *s;

	BUG_ON(hsm->sblock);
	hsm->have_updated = 0;
	r = dm_bm_write_lock(hsm->bm, HSM_SUPERBLOCK_LOCATION, &hsm->sblock);
	if (r)
		return r;

	s = (struct superblock *) dm_block_data(hsm->sblock);
	hsm->root = __le64_to_cpu(s->btree_root);
	hsm->reverse_root = __le64_to_cpu(s->btree_reverse_root);
	return 0;
}

static struct hsm_metadata *
hsm_metadata_open_(struct block_device *bdev,
		   sector_t data_block_size, dm_block_t data_dev_size)
{
	int r;
	struct superblock *sb;
	struct hsm_metadata *hsm;
	sector_t bdev_size = i_size_read(bdev->bd_inode) >> SECTOR_SHIFT;
	struct dm_block_manager *bm;
	int create;

	bm = dm_block_manager_create(bdev,
				  HSM_METADATA_BLOCK_SIZE,
				  HSM_METADATA_CACHE_SIZE);
	if (!bm) {
		printk(KERN_ALERT "hsm-metadata could not create block manager");
		return NULL;
	}

	r = superblock_all_zeroes(bm, &create);
	if (r) {
		dm_block_manager_destroy(bm);
		return NULL;
	}

	hsm = alloc_(bm, create);
	if (!hsm)
		return NULL;
	hsm->bdev = bdev;

	if (create) {
		if (!hsm->sblock) {
			r = hsm_metadata_begin(hsm);
			if (r < 0)
				goto bad;
		}

		sb = (struct superblock *) dm_block_data(hsm->sblock);
		sb->magic = __cpu_to_le64(HSM_SUPERBLOCK_MAGIC);
		sb->version = __cpu_to_le64(HSM_VERSION);
		sb->metadata_block_size = __cpu_to_le64(1 << SECTOR_TO_BLOCK_SHIFT);
		sb->metadata_nr_blocks = __cpu_to_le64(bdev_size >> SECTOR_TO_BLOCK_SHIFT);
		sb->data_block_size = __cpu_to_le64(data_block_size);
		sb->data_nr_blocks = __cpu_to_le64(data_dev_size);
		sb->first_free_block = 0;
		sb->freed_block = __cpu_to_le64(~0);

		r = dm_btree_empty(&hsm->info, &hsm->root);
		if (r < 0)
			goto bad;

		r = dm_btree_empty(&hsm->info, &hsm->reverse_root);
		if (r < 0) {
			dm_btree_del(&hsm->info, hsm->root);
			goto bad;
		}

		hsm->have_updated = 1;
		r = hsm_metadata_commit(hsm);
		if (r < 0)
			goto bad;
	} else {
		r = hsm_metadata_begin(hsm);
		if (r < 0)
			goto bad;
	}

	return hsm;

bad:
	hsm_metadata_close(hsm);
	return NULL;
}

struct hsm_metadata *
hsm_metadata_open(struct block_device *bdev,
		  sector_t data_block_size, dm_block_t data_dev_size)
{
	struct hsm_metadata *hsm;

	hsm = hsm_table_lookup(bdev);
	if (hsm)
		atomic_inc(&hsm->ref_count);
	else {
		hsm = hsm_metadata_open_(bdev, data_block_size, data_dev_size);
		atomic_set(&hsm->ref_count, 1);
		hsm_table_insert(hsm);
	}

	BUG_ON(!hsm->sblock);
	return hsm;
}
EXPORT_SYMBOL_GPL(hsm_metadata_open);

static void print_sblock(struct superblock *sb)
{
#if 0
	printk(KERN_ALERT "magic = %u", (unsigned) __le64_to_cpu(sb->magic));
	printk(KERN_ALERT "version = %u", (unsigned) __le64_to_cpu(sb->version));
	printk(KERN_ALERT "md block size = %u", (unsigned) __le64_to_cpu(sb->metadata_block_size));
	printk(KERN_ALERT "md nr blocks = %u", (unsigned) __le64_to_cpu(sb->metadata_nr_blocks));
	printk(KERN_ALERT "data block size = %u", (unsigned) __le64_to_cpu(sb->data_block_size));
	printk(KERN_ALERT "data nr blocks = %u", (unsigned) __le64_to_cpu(sb->data_nr_blocks));
	printk(KERN_ALERT "first free = %u", (unsigned) __le64_to_cpu(sb->first_free_block));
	printk(KERN_ALERT "btree root = %u", (unsigned) __le64_to_cpu(sb->btree_root));
	printk(KERN_ALERT "btree reverse_root = %u", (unsigned) __le64_to_cpu(sb->btree_reverse_root));
	printk(KERN_ALERT "sm nr blocks = %u", (unsigned) __le64_to_cpu(sb->sm_root_start));
	printk(KERN_ALERT "bitmap root = %u", (unsigned) __le64_to_cpu(
		       *(((__le64 *) &sb->sm_root_start) + 1)
		       ));
	printk(KERN_ALERT "ref count root = %u",(unsigned) __le64_to_cpu(
		       *(((__le64 *) &sb->sm_root_start) + 2)));
#endif
}

void
hsm_metadata_close(struct hsm_metadata *hsm)
{
	if (atomic_dec_and_test(&hsm->ref_count)) {
		printk(KERN_ALERT "destroying hsm");
		hsm_table_remove(hsm);

		if (hsm->sblock)
			hsm_metadata_commit(hsm);

		dm_tm_destroy(hsm->tm);
		dm_tm_destroy(hsm->nb_tm);
		dm_block_manager_destroy(hsm->bm);
		dm_sm_destroy(hsm->sm);

		if (hsm->wq)
			destroy_workqueue(hsm->wq);

		kfree(hsm);
	}
}
EXPORT_SYMBOL_GPL(hsm_metadata_close);

int hsm_metadata_commit(struct hsm_metadata *hsm)
{
	int r;
	size_t len;

	if (!hsm->have_updated)
		/* if nothing's been inserted, then nothing has changed */
		return 0;

	down_write(&hsm->root_lock);
	r = dm_tm_pre_commit(hsm->tm);
	if (r < 0) {
		up_write(&hsm->root_lock);
		return r;
	}

	r = dm_sm_root_size(hsm->sm, &len);
	if (r < 0) {
		up_write(&hsm->root_lock);
		return r;
	}

	{
		struct superblock *sb = dm_block_data(hsm->sblock);
		sb->btree_root = __cpu_to_le64(hsm->root);
		sb->btree_reverse_root = __cpu_to_le64(hsm->reverse_root);
		r = dm_sm_copy_root(hsm->sm, &sb->sm_root_start, len);
		if (r < 0) {
			up_write(&hsm->root_lock);
			return r;
		}

		print_sblock(sb);
	}

	r = dm_tm_commit(hsm->tm, hsm->sblock);

	/* open the next transaction */
	hsm->sblock = NULL;
	r = hsm_metadata_begin(hsm); /* FIXME: the semantics of failure are confusing here, probably have to make begin a public method again */
	up_write(&hsm->root_lock);

	return r;
}
EXPORT_SYMBOL_GPL(hsm_metadata_commit);

void split_result(dm_block_t result, dm_block_t *b, unsigned long *flags)
{
	*b = result & (((dm_block_t) 1 << 60) - 1);
	*flags = result >> 60;
}

int hsm_metadata_insert(struct hsm_metadata *hsm,
			hsm_dev_t dev,
			dm_block_t cache_block,
			dm_block_t *pool_block,
		        unsigned long *flags)
{
	int r;
	unsigned long f;
	dm_block_t b, b_le64, dummy, nr_blocks, keys[2];
	struct superblock *sb;

	keys[0] = dev;
	keys[1] = cache_block;

	down_write(&hsm->root_lock);
	sb = dm_block_data(hsm->sblock);
	nr_blocks = __le64_to_cpu(sb->data_nr_blocks);
	b = __le64_to_cpu(sb->first_free_block);

	if (b >= nr_blocks) {
		/* All allocated, look for any freed one. */
		b = __le64_to_cpu(sb->freed_block);
		if (b >= nr_blocks) {
			/*
			 * We've run out of space, client should
			 * remove block or extend and then retry.
			 */
			up_write(&hsm->root_lock);
			// printk(KERN_ALERT "out of hsm data space");
			return -ENOSPC;
		}
	}

	/* Block may not be interfearing with flags in the high bits. */
	split_result(b, &dummy, &f);
	if (f) {
		up_write(&hsm->root_lock);
		return -EPERM;
	}

	/* Inserted block doesn't need flag merging. Ie. flags = 0. */
	b_le64 = __cpu_to_le64(b);
	r = dm_btree_insert(&hsm->info, hsm->root, keys, &b_le64, &hsm->root);
	if (!r) {
		keys[1] = b;
		cache_block = __cpu_to_le64(cache_block);
		r = dm_btree_insert(&hsm->info, hsm->reverse_root,
				    keys, &cache_block, &hsm->reverse_root);
		if (r) {
			keys[1] = __le64_to_cpu(cache_block);
			dm_btree_remove(&hsm->info, hsm->root, keys,
					&hsm->root);
		}
	}

	if (sb->first_free_block < nr_blocks)
		sb->first_free_block = __cpu_to_le64(b + 1);

	if (r < 0) {
		up_write(&hsm->root_lock);
		return r;
	}

	sb->freed_block = __cpu_to_le64(~0);
	hsm->have_updated = 1;
	up_write(&hsm->root_lock);

	*pool_block = b;
	*flags = 0;
	return 0;
}
EXPORT_SYMBOL_GPL(hsm_metadata_insert);

int hsm_metadata_remove(struct hsm_metadata *hsm,
			hsm_dev_t dev,
			dm_block_t cache_block)
{
	int r;
	unsigned long dummy;
	dm_block_t keys[2], pool_block;
	struct superblock *sb = dm_block_data(hsm->sblock);

	/* Mapping has to exist on update. */
	r = hsm_metadata_lookup(hsm, dev, cache_block, 1, &pool_block, &dummy);
	if (r < 0)
		return r;

	keys[0] = dev;
	keys[1] = cache_block;

	down_write(&hsm->root_lock);
	r = dm_btree_remove(&hsm->info, hsm->root, keys, &hsm->root);
	BUG_ON(r);
	pool_block = __le64_to_cpu(pool_block);
	split_result(pool_block, &pool_block, &dummy); /* Remove any flags. */
	keys[1] = pool_block;
	r = dm_btree_remove(&hsm->info, hsm->reverse_root,
			    keys, &hsm->reverse_root);
	BUG_ON(r);
	sb->freed_block = __cpu_to_le64(pool_block);
	up_write(&hsm->root_lock);

	return r;
}
EXPORT_SYMBOL_GPL(hsm_metadata_remove);

int
_hsm_metadata_lookup(struct hsm_metadata *hsm,
		     hsm_dev_t dev, dm_block_t block_in, int can_block,
		     dm_block_t *block_out, unsigned long *flags,
		     dm_block_t btree_root)
{
	int r;
	dm_block_t keys[2], result;

	keys[0] = dev;
	keys[1] = block_in;

	if (can_block) {
		down_read(&hsm->root_lock);
		r = dm_btree_lookup(&hsm->info, btree_root, keys, &result);
		up_read(&hsm->root_lock);

	} else if (down_read_trylock(&hsm->root_lock)) {
		r = dm_btree_lookup(&hsm->nb_info, btree_root, keys, &result);
		up_read(&hsm->root_lock);

	} else
		r = -EWOULDBLOCK;

	if (!r) {
		result = __le64_to_cpu(result);

		if (btree_root == hsm->root)
			split_result(result, block_out, flags);
		else
			*block_out = result;
	}

	return r;
}

int
hsm_metadata_lookup(struct hsm_metadata *hsm,
		    hsm_dev_t dev, dm_block_t cache_block, int can_block,
		    dm_block_t *pool_block, unsigned long *flags)
{
	return _hsm_metadata_lookup(hsm, dev, cache_block, can_block,
				    pool_block, flags, hsm->root);
}
EXPORT_SYMBOL_GPL(hsm_metadata_lookup);

int
hsm_metadata_lookup_reverse(struct hsm_metadata *hsm,
			    hsm_dev_t dev, dm_block_t pool_block, int can_block,
			    dm_block_t *cache_block)
{
	unsigned long dummy;
	return _hsm_metadata_lookup(hsm, dev, pool_block, can_block,
				    cache_block, &dummy, hsm->reverse_root);
}
EXPORT_SYMBOL_GPL(hsm_metadata_lookup_reverse);

#define	LLU	long long unsigned
int hsm_metadata_update(struct hsm_metadata *hsm,
			hsm_dev_t dev,
			dm_block_t cache_block,
		        unsigned long flags)
{
	int r;
	unsigned long dummy;
	dm_block_t keys[2], pool_block;

	/* Mapping has to exists on update. */
	r = hsm_metadata_lookup(hsm, dev, cache_block, 1, &pool_block, &dummy);
	if (r < 0)
		return r;

// DMINFO("%s pool_block=%llu flags=%lu", __func__, (LLU) pool_block, flags);
	pool_block |= (flags << 60);
	pool_block = __cpu_to_le64(pool_block);

	keys[0] = dev;
	keys[1] = cache_block;

	down_write(&hsm->root_lock);
	hsm->have_updated = 1;
	r = dm_btree_insert(&hsm->info, hsm->root, keys, &pool_block,
			    &hsm->root);
	up_write(&hsm->root_lock);

	return r < 0 ? r : 0;
}
EXPORT_SYMBOL_GPL(hsm_metadata_update);

int
hsm_metadata_delete(struct hsm_metadata *hsm, hsm_dev_t dev)
{
	printk(KERN_ALERT "requested deletion of %u", (unsigned) dev);
	down_write(&hsm->root_lock);
	// FIXME: finish
	up_write(&hsm->root_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(hsm_metadata_delete);

int
hsm_metadata_get_data_block_size(struct hsm_metadata *hsm,
				   hsm_dev_t dev,
				   sector_t *result)
{
	down_read(&hsm->root_lock);
	*result = __le64_to_cpu(((struct superblock *) dm_block_data(hsm->sblock))->data_block_size);
	up_read(&hsm->root_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(hsm_metadata_get_data_block_size);

int
hsm_metadata_get_data_dev_size(struct hsm_metadata *hsm,
			       hsm_dev_t dev, dm_block_t *result)
{
	down_read(&hsm->root_lock);
	*result = __le64_to_cpu(((struct superblock *) dm_block_data(hsm->sblock))->data_nr_blocks);
	up_read(&hsm->root_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(hsm_metadata_get_data_dev_size);

int
hsm_metadata_get_provisioned_blocks(struct hsm_metadata *hsm,
				      hsm_dev_t dev,
				      dm_block_t *result)
{
	down_read(&hsm->root_lock);
	*result = __le64_to_cpu(((struct superblock *) dm_block_data(hsm->sblock))->first_free_block);
	up_read(&hsm->root_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(hsm_metadata_get_provisioned_blocks);

int
hsm_metadata_resize_data_dev(struct hsm_metadata *hsm,
			       hsm_dev_t dev,
			       dm_block_t new_size)
{
	dm_block_t b;

	down_write(&hsm->root_lock);
	{
		struct superblock *sb = (struct superblock *) dm_block_data(hsm->sblock);

		b = __le64_to_cpu(sb->first_free_block);
		if (b > new_size) {
			/* this would truncate mapped blocks */
			up_write(&hsm->root_lock);
			return -ENOSPC;
		}

		sb->data_nr_blocks = __cpu_to_le64(new_size);
	}
	up_write(&hsm->root_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(hsm_metadata_resize_data_dev);

struct workqueue_struct *
hsm_metadata_get_workqueue(struct hsm_metadata *hsm)
{
	return hsm->wq;
}
EXPORT_SYMBOL_GPL(hsm_metadata_get_workqueue);

static int hsm_metadata_init(void)
{
	hsm_table_init();
	return 0;
}

static void hsm_metadata_exit(void)
{
}

module_init(hsm_metadata_init);
module_exit(hsm_metadata_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joe Thornber");
MODULE_DESCRIPTION("Metadata manager for thin provisioning dm target");

/*----------------------------------------------------------------*/
#endif

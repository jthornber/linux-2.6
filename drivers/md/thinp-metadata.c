/*
 * Copyright (C) 2010 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "thinp-metadata.h"
#include "persistent-data/transaction-manager.h"
#include "persistent-data/space-map-core.h"

/*----------------------------------------------------------------*/

#define THINP_SUPERBLOCK_MAGIC 12112007
#define THINP_SUPERBLOCK_LOCATION 0
#define THINP_VERSION 1
#define THINP_METADATA_BLOCK_SIZE 4096
#define THINP_METADATA_CACHE_SIZE 128
#define SECTOR_TO_BLOCK_SHIFT 3

struct superblock {
	__le64 magic;
	__le64 version;

	__le64 metadata_block_size; /* in sectors */
	__le64 metadata_nr_blocks;

	__le64 data_block_size;	/* in sectors */
	__le64 data_nr_blocks;
	__le64 first_free_block;

	__le64 btree_root;

	/*
	 * Space map fields.
	 *
	 * The space map stores its root here, it will probably be longer
	 * than a __le64.
	 */
	__le64 sm_root_start;
};

struct thinp_metadata {
	struct block_manager *bm;
	struct space_map *sm;
	struct transaction_manager *tm;
	struct transaction_manager *nb_tm;
	struct block *sblock;

	struct btree_info info;
	struct btree_info nb_info;

	int have_inserted;
	block_t root;
};

static struct thinp_metadata *
alloc_(struct block_device *bdev, sector_t bdev_size)
{
	int r;
	struct space_map *sm;
	struct block_manager *bm;
	struct transaction_manager *tm;
	struct thinp_metadata *tpm;
	struct block *sb;

	bm = block_manager_create(bdev,
				  THINP_METADATA_BLOCK_SIZE,
				  THINP_METADATA_CACHE_SIZE);
	if (!bm) {
		printk(KERN_ALERT "thinp-metadata could not create block manager");
		return NULL;
	}

	r = tm_create_with_sm(bm, THINP_SUPERBLOCK_LOCATION, &tm, &sm, &sb);
	if (r < 0) {
		printk(KERN_ALERT "tm_create_with_sm failed");
		block_manager_destroy(bm);
		return NULL;
	}

	r = tm_pre_commit(tm);
	if (r < 0) {
		printk(KERN_ALERT "couldn't pre commit");
		goto bad;
	}

	r = tm_commit(tm, sb);
	if (r < 0) {
		printk(KERN_ALERT "couldn't commit");
		goto bad;
	}

	tpm = kmalloc(sizeof(*tpm), GFP_KERNEL);
	if (!tpm) {
		printk(KERN_ALERT "thinp-metadata could not allocate metadata struct");
		goto bad;
	}

	tpm->bm = bm;
	tpm->sm = sm;
	tpm->tm = tm;
	tpm->nb_tm = tm_create_non_blocking_clone(tm);
	if (!tpm->nb_tm) {
		printk(KERN_ALERT "thinp-metadata could not create clone tm");
		goto bad;
	}

	tpm->sblock = NULL;

	tpm->info.tm = tm;
	tpm->info.levels = 1;
	tpm->info.value_size = sizeof(block_t);
	tpm->info.adjust = value_is_meaningless; /* because the blocks are held in a separate device */
	tpm->info.eq = NULL;

	memcpy(&tpm->nb_info, &tpm->info, sizeof(tpm->nb_info));
	tpm->nb_info.tm = tpm->nb_tm;

	tpm->have_inserted = 0;
	tpm->root = 0;		/* not meaningful until in a transaction */

	return tpm;

bad:
	tm_destroy(tm);
	sm_destroy(sm);
	block_manager_destroy(bm);
	return NULL;
}

static int thinp_metadata_begin(struct thinp_metadata *tpm)
{
	BUG_ON(tpm->sblock);
	tpm->have_inserted = 0;
	return bm_write_lock(tpm->bm, THINP_SUPERBLOCK_LOCATION, &tpm->sblock);
}

struct thinp_metadata *
thinp_metadata_create(struct block_device *bdev, sector_t bdev_size,
		      sector_t data_block_size,
		      block_t data_dev_size)
{
	int r;
	struct superblock *sb;
	struct thinp_metadata *tpm = alloc_(bdev, bdev_size);

	if (!tpm)
		return NULL;

	if (!tpm->sblock) {
		int r = thinp_metadata_begin(tpm);
		if (r < 0)
			goto bad;
	}

	sb = (struct superblock *) block_data(tpm->sblock);
	sb->magic = __cpu_to_le64(THINP_SUPERBLOCK_MAGIC);
	sb->version = __cpu_to_le64(THINP_VERSION);
	sb->metadata_block_size = __cpu_to_le64(1 << SECTOR_TO_BLOCK_SHIFT);
	sb->metadata_nr_blocks = __cpu_to_le64(bdev_size >> SECTOR_TO_BLOCK_SHIFT);
	sb->data_block_size = __cpu_to_le64(data_block_size);
	sb->data_nr_blocks = __cpu_to_le64(data_dev_size);
	sb->first_free_block = 0;

	r = btree_empty(&tpm->info, &tpm->root);
	if (r < 0)
		goto bad;

	tpm->have_inserted = 1;
	r = thinp_metadata_commit(tpm);
	if (r < 0)
		goto bad;

	return tpm;

bad:
	thinp_metadata_close(tpm);
	return NULL;
}
EXPORT_SYMBOL_GPL(thinp_metadata_create);

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
	printk(KERN_ALERT "sm nr blocks = %u", (unsigned) __le64_to_cpu(sb->sm_root_start));
	printk(KERN_ALERT "bitmap root = %u", (unsigned) __le64_to_cpu(
		       *(((__le64 *) &sb->sm_root_start) + 1)
		       ));
	printk(KERN_ALERT "ref count root = %u",(unsigned) __le64_to_cpu(
		       *(((__le64 *) &sb->sm_root_start) + 2)));
#endif
}

/* FIXME: use alloc_ */
struct thinp_metadata *
thinp_metadata_open(struct block_device *bdev, sector_t bdev_size)
{
	int r;
	struct space_map *sm;
	struct block_manager *bm;
	struct transaction_manager *tm;
	struct thinp_metadata *tpm;
	struct block *sb;
	struct superblock *s;

	bm = block_manager_create(bdev,
				  THINP_METADATA_BLOCK_SIZE,
				  THINP_METADATA_CACHE_SIZE);
	if (!bm) {
		printk(KERN_ALERT "thinp-metadata could not create block manager");
		return NULL;
	}

	r = tm_open_with_sm(bm, THINP_SUPERBLOCK_LOCATION,
			    (size_t) &((struct superblock *) NULL)->sm_root_start,
			    32, // 16,	/* FIXME: sm should say how big its root is */
			    &tm, &sm, &sb);
	if (r < 0) {
		printk(KERN_ALERT "tm_open_with_sm failed");
		block_manager_destroy(bm);
		return NULL;
	}

	s = block_data(sb);
	if (__le64_to_cpu(s->magic) != THINP_SUPERBLOCK_MAGIC) {
		printk(KERN_ALERT "thinp-metadata superblock is invalid");
		goto bad;
	}

	tpm = kmalloc(sizeof(*tpm), GFP_KERNEL);
	if (!tpm) {
		printk(KERN_ALERT "thinp-metadata could not allocate metadata struct");
		goto bad;
	}

	tpm->bm = bm;
	tpm->sm = sm;
	tpm->tm = tm;
	tpm->nb_tm = tm_create_non_blocking_clone(tm);
	if (!tpm->nb_tm) {
		printk(KERN_ALERT "thinp-metadata could not create clone tm");
		goto bad;
	}

	tpm->sblock = sb;

	tpm->info.tm = tm;
	tpm->info.levels = 1;
	tpm->info.value_size = sizeof(block_t);
	tpm->info.adjust = value_is_meaningless; /* because the blocks are held in a separate device */
	tpm->info.eq = NULL;

	memcpy(&tpm->nb_info, &tpm->info, sizeof(tpm->nb_info));
	tpm->nb_info.tm = tpm->nb_tm;

	tpm->have_inserted = 0;
	tpm->root = __le64_to_cpu(s->btree_root);
	return tpm;

bad:
	tm_destroy(tm);
	sm_destroy(sm);
	block_manager_destroy(bm);
	return NULL;
}
EXPORT_SYMBOL_GPL(thinp_metadata_open);

void
thinp_metadata_close(struct thinp_metadata *tpm)
{
	if (tpm->sblock)
		thinp_metadata_commit(tpm);

	tm_destroy(tpm->tm);
	tm_destroy(tpm->nb_tm);
	block_manager_destroy(tpm->bm);
	sm_destroy(tpm->sm);
	kfree(tpm);
}
EXPORT_SYMBOL_GPL(thinp_metadata_close);

int thinp_metadata_commit(struct thinp_metadata *tpm)
{
	int r;
	size_t len;

	if (!tpm->sblock || !tpm->have_inserted)
		/* if nothing's been inserted, then nothing has changed */
		return 0;

	r = tm_pre_commit(tpm->tm);
	if (r < 0)
		return r;

	r = sm_root_size(tpm->sm, &len);
	if (r < 0)
		return r;

	{
		struct superblock *sb = block_data(tpm->sblock);
		sb->btree_root = __cpu_to_le64(tpm->root);
		r = sm_copy_root(tpm->sm, &sb->sm_root_start, len);
		if (r < 0)
			return r;

		print_sblock(sb);
	}

	r = tm_commit(tpm->tm, tpm->sblock);
	tpm->sblock = NULL;
	return r;
}
EXPORT_SYMBOL_GPL(thinp_metadata_commit);

int thinp_metadata_insert(struct thinp_metadata *tpm,
				 block_t thinp_block,
				 block_t *pool_block)
{
	int r;
	struct superblock *sb;
	block_t b, nr_blocks;

	if (!tpm->sblock) {
		r = thinp_metadata_begin(tpm);
		if (r < 0)
			return r;
	}

	tpm->have_inserted = 1;
	sb = block_data(tpm->sblock);
	nr_blocks = __le64_to_cpu(sb->data_nr_blocks);
	b = __le64_to_cpu(sb->first_free_block);

	if (b >= nr_blocks) {
		/* we've run out of space, client should extend and then retry */
		return -ENOSPC;
	}

	r = btree_insert(&tpm->info, tpm->root, &thinp_block, &b, &tpm->root);
	if (r < 0)
		return r;

	*pool_block = b;
	sb->first_free_block = __cpu_to_le64(b + 1);
	return 0;
}
EXPORT_SYMBOL_GPL(thinp_metadata_insert);

int
thinp_metadata_lookup(struct thinp_metadata *tpm,
		      block_t thinp_block,
		      int can_block,
		      block_t *result)
{
	int r;

	if (!tpm->sblock) {
		if (!can_block)
			return -EWOULDBLOCK;

		r = thinp_metadata_begin(tpm);
		if (r < 0)
			return r;
	}

	return btree_lookup_equal(can_block ? &tpm->info : &tpm->nb_info,
				  tpm->root, &thinp_block, result);
}

EXPORT_SYMBOL_GPL(thinp_metadata_lookup);

int
thinp_metadata_get_data_block_size(struct thinp_metadata *tpm, sector_t *result)
{
	struct superblock *sb;

	if (!tpm->sblock) {
		int r = thinp_metadata_begin(tpm);
		if (r < 0)
			return r;
	}
	sb = (struct superblock *) block_data(tpm->sblock);

	*result = __le64_to_cpu(sb->data_block_size);
	return 0;
}

EXPORT_SYMBOL_GPL(thinp_metadata_get_data_block_size);

int
thinp_metadata_get_data_dev_size(struct thinp_metadata *tpm, block_t *result)
{
	struct superblock *sb;

	if (!tpm->sblock) {
		int r = thinp_metadata_begin(tpm);
		if (r < 0)
			return r;
	}
	sb = (struct superblock *) block_data(tpm->sblock);

	*result = __le64_to_cpu(sb->data_nr_blocks);
	return 0;
}
EXPORT_SYMBOL_GPL(thinp_metadata_get_data_dev_size);

int
thinp_metadata_get_provisioned_blocks(struct thinp_metadata *tpm, block_t *result)
{
	struct superblock *sb;

	if (!tpm->sblock) {
		int r = thinp_metadata_begin(tpm);
		if (r < 0)
			return r;
	}
	sb = (struct superblock *) block_data(tpm->sblock);

	*result = __le64_to_cpu(sb->first_free_block);
	return 0;
}
EXPORT_SYMBOL_GPL(thinp_metadata_get_provisioned_blocks);

int
thinp_metadata_resize_data_dev(struct thinp_metadata *tpm, block_t new_size)
{
	struct superblock *sb;
	block_t b;

	if (!tpm->sblock) {
		int r = thinp_metadata_begin(tpm);
		if (r < 0)
			return r;
	}
	sb = (struct superblock *) block_data(tpm->sblock);

	b = __le64_to_cpu(sb->first_free_block);
	if (b > new_size) {
		/* this would truncate mapped blocks */
		return -ENOSPC;
	}

	sb->data_nr_blocks = __cpu_to_le64(new_size);
	return 0;
}
EXPORT_SYMBOL_GPL(thinp_metadata_resize_data_dev);

static int thinp_metadata_init(void)
{
	return 0;
}

static void thinp_metadata_exit(void)
{
}

module_init(thinp_metadata_init);
module_exit(thinp_metadata_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joe Thornber");
MODULE_DESCRIPTION("Metadata manager for thin provisioning dm target");

/*----------------------------------------------------------------*/

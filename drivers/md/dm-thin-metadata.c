/*
 * Copyright (C) 2011 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "dm-thin-metadata.h"
#include "persistent-data/dm-btree.h"
#include "persistent-data/dm-space-map.h"
#include "persistent-data/dm-space-map-disk.h"
#include "persistent-data/dm-transaction-manager.h"

#include <linux/list.h>
#include <linux/device-mapper.h>
#include <linux/workqueue.h>

/*--------------------------------------------------------------------------
 * As far as the metadata goes, there is:
 *
 * - A superblock in block zero, taking up fewer than 512 bytes for
 *   atomic writes.
 *
 * - A space map managing the metadata blocks
 *
 * - A space map managing the data blocks
 *
 * - A btree mapping our internal thin dev ids onto struct device_details
 *
 * - A hierarchical btree, with 2 levels.  Which effectively maps (thin
 *   dev id, virtual block) -> block_time.  Where block time is a 64 bit
 *   field holding the time in the low 24 bits, and block in the top 48
 *   bits.
 *
 * BTrees consist solely of btree_nodes, that fill a block.  Some are
 * internal nodes, as such their values are a __le64 pointing to other
 * nodes.  Leaf nodes can store data of any reasonable size (ie. much
 * smaller than the block size).  The nodes consist of the header,
 * followed by an array of keys, followed by an array of values.  We have
 * to binary search on the keys so they're all held together to help the
 * cpu cache.
 *
 * Space maps have 2 btrees:
 *
 * - One maps a uint64_t onto a struct index_entry.  Which points to a
 *   bitmap block, and has some details about how many free entries there
 *   are etc.
 *
 * - The bitmap blocks have a header (for the checksum).  Then the rest
 *   of the block is pairs of bits.  With the meaning being:
 *
 *   0 - ref count is 0
 *   1 - ref count is 1
 *   2 - ref count is 2
 *   3 - ref count is higher than 2
 *
 * - If the count is higher than 2 then the ref count is entered in a
 *   second btree that directly maps the block_address to a uint32_t ref
 *   count.
 *
 * The space map metadata variant doesn't have a bitmaps btree.  Instead
 * it has one single blocks worth of index_entries.  This avoids
 * recursive issues with the bitmap btree needing to allocate space in
 * order to insert.  With a small data block size such as 64k the
 * metadata support data devices that are hundreds of terrabytes.
 *
 * The space maps allocate space linearly from front to back.  Space that
 * is freed in a transaction is never recycled within that transaction.
 * To try and avoid fragmenting _free_ space the allocator always goes
 * back and fills in gaps.
 *
 * All metadata io is in THIN_METADATA_BLOCK_SIZE sized/aligned chunks
 * from the block manager.
 *--------------------------------------------------------------------------*/

#define DM_MSG_PREFIX   "thin metadata"

#define THIN_SUPERBLOCK_MAGIC 27022010
#define THIN_SUPERBLOCK_LOCATION 0
#define THIN_VERSION 1
#define THIN_METADATA_BLOCK_SIZE 4096
#define THIN_METADATA_CACHE_SIZE 64
#define SECTOR_TO_BLOCK_SHIFT 3

/* This should be plenty */
#define SPACE_MAP_ROOT_SIZE 128

struct thin_super_block {
	__le32 csum;
	__le32 flags;
	__le64 blocknr; /* this block number, dm_block_t */

	__u8 uuid[16]; /* uuid_t */
	__le64 magic;
	__le32 version;
	__le32 time;

	__le64 trans_id;
	/* root for userspace's transaction (for migration and friends) */
	__le64 held_root;

	__u8 data_space_map_root[SPACE_MAP_ROOT_SIZE];
	__u8 metadata_space_map_root[SPACE_MAP_ROOT_SIZE];

	/* 2 level btree mapping (dev_id, (dev block, time)) -> data block */
	__le64 data_mapping_root;

	/* device detail root mapping dev_id -> device_details */
	__le64 device_details_root;

	__le32 data_block_size;	/* in 512-byte sectors */

	__le32 metadata_block_size; /* in 512-byte sectors */
	__le64 metadata_nr_blocks;

	__le32 compat_flags;
	__le32 compat_ro_flags;
	__le32 incompat_flags;
} __packed;

struct device_details {
	__le64 mapped_blocks;
	__le64 transaction_id;	/* when created */
	__le32 creation_time;
	__le32 snapshotted_time;
} __packed;

struct dm_thin_metadata {
	struct hlist_node hash;

	struct block_device *bdev;
	struct dm_block_manager *bm;
	struct dm_space_map *metadata_sm;
	struct dm_space_map *data_sm;
	struct dm_transaction_manager *tm;
	struct dm_transaction_manager *nb_tm;

	/*
	 * Two level btree, first level is thin_dev_t, second level
	 * mappings.
	 */
	struct dm_btree_info info;

	/* non-blocking version of the above */
	struct dm_btree_info nb_info;

	/* just the top level, for deleting whole devices */
	struct dm_btree_info tl_info;

	/* just the bottom level for creating new devices */
	struct dm_btree_info bl_info;

	/* Describes the device details btree */
	struct dm_btree_info details_info;

	struct rw_semaphore root_lock;
	uint32_t time;
	int need_commit;
	struct dm_block *sblock;
	dm_block_t root;
	dm_block_t details_root;
	struct list_head thin_devices;
	uint64_t trans_id;
	unsigned long flags;
	sector_t data_block_size;
};

struct dm_thin_device {
	struct list_head list;
	struct dm_thin_metadata *tmd;
	dm_thin_dev_t id;

	int open_count;
	int changed;
	uint64_t mapped_blocks;
	uint64_t transaction_id;
	uint32_t creation_time;
	uint32_t snapshotted_time;
};

/*----------------------------------------------------------------
 * superblock validator
 *--------------------------------------------------------------*/

static void sb_prepare_for_write(struct dm_block_validator *v,
				 struct dm_block *b,
				 size_t block_size)
{
	struct thin_super_block *sb = dm_block_data(b);

	sb->blocknr = __cpu_to_le64(dm_block_location(b));
	sb->csum = dm_block_csum_data(&sb->flags,
				      sizeof(*sb) - sizeof(u32));
}

static int sb_check(struct dm_block_validator *v,
		    struct dm_block *b,
		    size_t block_size)
{
	struct thin_super_block *sb = dm_block_data(b);
	__le32 csum;

	if (dm_block_location(b) != __le64_to_cpu(sb->blocknr)) {
		DMERR("sb_check failed blocknr %llu "
		      "wanted %llu", __le64_to_cpu(sb->blocknr),
		      dm_block_location(b));
		return -ENOTBLK;
	}

	if (__le64_to_cpu(sb->magic) != THIN_SUPERBLOCK_MAGIC) {
		DMERR("sb_check failed magic %llu "
		      "wanted %llu", __le64_to_cpu(sb->magic),
		      (unsigned long long)THIN_SUPERBLOCK_MAGIC);
		return -EILSEQ;
	}

	csum = dm_block_csum_data(&sb->flags,
				  sizeof(*sb) - sizeof(u32));
	if (csum != sb->csum) {
		DMERR("sb_check failed csum %u wanted %u",
		      __le32_to_cpu(csum), __le32_to_cpu(sb->csum));
		return -EILSEQ;
	}

	return 0;
}

static struct dm_block_validator sb_validator_ = {
	.name = "superblock",
	.prepare_for_write = sb_prepare_for_write,
	.check = sb_check
};

/*----------------------------------------------------------------
 * Methods for the btree value types
 *--------------------------------------------------------------*/

static uint64_t pack_dm_block_time(dm_block_t b, uint32_t t)
{
	return (b << 24) | t;
}

static void unpack_dm_block_time(uint64_t v, dm_block_t *b, uint32_t *t)
{
	*b = v >> 24;
	*t = v & ((1 << 24) - 1);
}

static void data_block_inc(void *context, void *value)
{
	struct dm_space_map *sm = context;
	__le64 v;
	uint64_t b;
	uint32_t t;

	memcpy(&v, value, sizeof(v));
	unpack_dm_block_time(v, &b, &t);
	dm_sm_inc_block(sm, b);
}

static void data_block_dec(void *context, void *value)
{
	struct dm_space_map *sm = context;
	__le64 v;
	uint64_t b;
	uint32_t t;

	memcpy(&v, value, sizeof(v));
	unpack_dm_block_time(v, &b, &t);
	dm_sm_dec_block(sm, b);
}

static int data_block_equal(void *context, void *value1, void *value2)
{
	__le64 v1, v2;
	uint64_t b1, b2;
	uint32_t t;

	memcpy(&v1, value1, sizeof(v1));
	memcpy(&v2, value2, sizeof(v2));
	unpack_dm_block_time(v1, &b1, &t);
	unpack_dm_block_time(v2, &b2, &t);
	return b1 == b2;
}

static void subtree_inc(void *context, void *value)
{
	struct dm_btree_info *info = context;
	__le64 le_root;
	uint64_t root;

	memcpy(&le_root, value, sizeof(le_root));
	root = __le64_to_cpu(le_root);
	dm_tm_inc(info->tm, root);
}

static void subtree_dec(void *context, void *value)
{
	struct dm_btree_info *info = context;
	__le64 le_root;
	uint64_t root;

	memcpy(&le_root, value, sizeof(le_root));
	root = __le64_to_cpu(le_root);
	if (dm_btree_del(info, root))
		DMERR("btree delete failed\n");
}

static int subtree_equal(void *context, void *value1, void *value2)
{
	__le64 v1, v2;
	memcpy(&v1, value1, sizeof(v1));
	memcpy(&v2, value2, sizeof(v2));

	return v1 == v2;
}

/*----------------------------------------------------------------*/

static int superblock_all_zeroes(struct dm_block_manager *bm, int *result)
{
	int r;
	unsigned i;
	struct dm_block *b;
	uint64_t *data;
	unsigned block_size = dm_bm_block_size(bm) / sizeof(uint64_t);

	/*
	 * We can't use a validator here - it may be all zeroes.
	 */
	r = dm_bm_read_lock(bm, THIN_SUPERBLOCK_LOCATION, NULL, &b);
	if (r)
		return r;

	data = dm_block_data(b);
	*result = 1;
	for (i = 0; i < block_size; i++) {
		if (data[i]) {
			*result = 0;
			break;
		}
	}

	return dm_bm_unlock(b);
}

static struct dm_thin_metadata *alloc_tmd(struct dm_block_manager *bm,
					  dm_block_t nr_blocks, int create)
{
	int r;
	struct dm_space_map *sm, *data_sm;
	struct dm_transaction_manager *tm;
	struct dm_thin_metadata *tmd;
	struct dm_block *sblock;

	if (create) {
		r = dm_tm_create_with_sm(bm, THIN_SUPERBLOCK_LOCATION,
					 &sb_validator_, &tm, &sm, &sblock);
		if (r < 0) {
			DMERR("tm_create_with_sm failed");
			dm_block_manager_destroy(bm);
			return ERR_PTR(r);
		}

		data_sm = dm_sm_disk_create(tm, nr_blocks);
		if (IS_ERR(data_sm)) {
			DMERR("sm_disk_create failed");
			r = PTR_ERR(data_sm);
			goto bad;
		}

		r = dm_tm_pre_commit(tm);
		if (r < 0) {
			DMERR("couldn't pre commit");
			goto bad;
		}

		r = dm_tm_commit(tm, sblock);
		if (r < 0) {
			DMERR("couldn't commit");
			goto bad;
		}
	} else {
		struct thin_super_block *sb = NULL;
		size_t space_map_root_offset =
			offsetof(struct thin_super_block, metadata_space_map_root);

		r = dm_tm_open_with_sm(bm, THIN_SUPERBLOCK_LOCATION,
				       &sb_validator_, space_map_root_offset,
				       SPACE_MAP_ROOT_SIZE, &tm, &sm, &sblock);
		if (r < 0) {
			DMERR("tm_open_with_sm failed");
			dm_block_manager_destroy(bm);
			return ERR_PTR(r);
		}

		sb = dm_block_data(sblock);
		data_sm = dm_sm_disk_open(tm, sb->data_space_map_root,
					  sizeof(sb->data_space_map_root));
		if (IS_ERR(data_sm)) {
			DMERR("sm_disk_open failed");
			r = PTR_ERR(data_sm);
			goto bad;
		}

		dm_tm_unlock(tm, sblock);
	}

	tmd = kmalloc(sizeof(*tmd), GFP_KERNEL);
	if (!tmd) {
		DMERR("could not allocate metadata struct");
		r = -ENOMEM;
		goto bad;
	}

	tmd->bm = bm;
	tmd->metadata_sm = sm;
	tmd->data_sm = data_sm;
	tmd->tm = tm;
	tmd->nb_tm = dm_tm_create_non_blocking_clone(tm);
	if (!tmd->nb_tm) {
		DMERR("could not create clone tm");
		r = -ENOMEM;
		goto bad;
	}

	tmd->sblock = NULL;

	tmd->info.tm = tm;
	tmd->info.levels = 2;
	tmd->info.value_type.context = tmd->data_sm;
	tmd->info.value_type.size = sizeof(__le64);
	tmd->info.value_type.inc = data_block_inc;
	tmd->info.value_type.dec = data_block_dec;
	tmd->info.value_type.equal = data_block_equal;

	memcpy(&tmd->nb_info, &tmd->info, sizeof(tmd->nb_info));
	tmd->nb_info.tm = tmd->nb_tm;

	tmd->tl_info.tm = tm;
	tmd->tl_info.levels = 1;
	tmd->tl_info.value_type.context = &tmd->info;
	tmd->tl_info.value_type.size = sizeof(__le64);
	tmd->tl_info.value_type.inc = subtree_inc;
	tmd->tl_info.value_type.dec = subtree_dec;
	tmd->tl_info.value_type.equal = subtree_equal;

	tmd->bl_info.tm = tm;
	tmd->bl_info.levels = 1;
	tmd->bl_info.value_type.context = tmd->data_sm;
	tmd->bl_info.value_type.size = sizeof(__le64);
	tmd->bl_info.value_type.inc = data_block_inc;
	tmd->bl_info.value_type.dec = data_block_dec;
	tmd->bl_info.value_type.equal = data_block_equal;

	tmd->details_info.tm = tm;
	tmd->details_info.levels = 1;
	tmd->details_info.value_type.context = NULL;
	tmd->details_info.value_type.size = sizeof(struct device_details);
	tmd->details_info.value_type.inc = NULL;
	tmd->details_info.value_type.dec = NULL;
	tmd->details_info.value_type.equal = NULL;

	tmd->root = 0;

	init_rwsem(&tmd->root_lock);
	tmd->time = 0;
	tmd->need_commit = 0;
	tmd->details_root = 0;
	INIT_LIST_HEAD(&tmd->thin_devices);

	return tmd;

bad:
	dm_tm_destroy(tm);
	dm_sm_destroy(sm);
	dm_block_manager_destroy(bm);

	return ERR_PTR(r);
}

static int begin_transaction(struct dm_thin_metadata *tmd)
{
	int r;
	u32 features;
	struct thin_super_block *sb;

	/* dm_thin_metadata_commit() resets tmd->sblock */
	WARN_ON(tmd->sblock);
	tmd->need_commit = 0;
	/* superblock is unlocked via dm_tm_commit() */
	r = dm_bm_write_lock(tmd->bm, THIN_SUPERBLOCK_LOCATION,
			     &sb_validator_, &tmd->sblock);
	if (r)
		return r;

	sb = dm_block_data(tmd->sblock);
	tmd->time = __le32_to_cpu(sb->time);
	tmd->root = __le64_to_cpu(sb->data_mapping_root);
	tmd->details_root = __le64_to_cpu(sb->device_details_root);
	tmd->trans_id = __le64_to_cpu(sb->trans_id);
	tmd->flags = __le32_to_cpu(sb->flags);
	tmd->data_block_size = __le32_to_cpu(sb->data_block_size);

	features = __le32_to_cpu(sb->incompat_flags) & ~THIN_FEATURE_INCOMPAT_SUPP;
	if (features) {
		DMERR("could not access metadata due to "
		      "unsupported optional features (%lx).",
		      (unsigned long)features);
		return -EINVAL;
	}

	/* check for read-only metadata to skip the following RDWR checks */
	if (get_disk_ro(tmd->bdev->bd_disk))
		return 0;

	features = __le32_to_cpu(sb->compat_ro_flags) & ~THIN_FEATURE_COMPAT_RO_SUPP;
	if (features) {
		DMERR("could not access metadata RDWR due to "
		      "unsupported optional features (%lx).",
		      (unsigned long)features);
		return -EINVAL;
	}

	return 0;
}

struct dm_thin_metadata * dm_thin_metadata_open(struct block_device *bdev,
						sector_t data_block_size)
{
	int r;
	struct thin_super_block *sb;
	struct dm_thin_metadata *tmd;
	sector_t bdev_size = i_size_read(bdev->bd_inode) >> SECTOR_SHIFT;
	struct dm_block_manager *bm;
	int create;

	bm = dm_block_manager_create(bdev, THIN_METADATA_BLOCK_SIZE,
				     THIN_METADATA_CACHE_SIZE);
	if (!bm) {
		DMERR("could not create block manager");
		return ERR_PTR(-ENOMEM);
	}

	r = superblock_all_zeroes(bm, &create);
	if (r) {
		dm_block_manager_destroy(bm);
		return ERR_PTR(r);
	}

	tmd = alloc_tmd(bm, 0, create);
	if (IS_ERR(tmd)) {
		/* alloc_tmd() destroys the block manager on failure */
		return tmd; /* already an ERR_PTR */
	}
	tmd->bdev = bdev;

	if (!create) {
		r = begin_transaction(tmd);
		if (r < 0)
			goto bad;
		return tmd;
	}

	/* Create */
	if (!tmd->sblock) {
		r = begin_transaction(tmd);
		if (r < 0)
			goto bad;
	}

	sb = dm_block_data(tmd->sblock);
	sb->magic = __cpu_to_le64(THIN_SUPERBLOCK_MAGIC);
	sb->version = __cpu_to_le32(THIN_VERSION);
	sb->time = 0;
	sb->metadata_block_size = __cpu_to_le32(THIN_METADATA_BLOCK_SIZE >> SECTOR_SHIFT);
	sb->metadata_nr_blocks = __cpu_to_le64(bdev_size >> SECTOR_TO_BLOCK_SHIFT);
	sb->data_block_size = __cpu_to_le32(data_block_size);

	r = dm_btree_empty(&tmd->info, &tmd->root);
	if (r < 0)
		goto bad;

	r = dm_btree_empty(&tmd->details_info, &tmd->details_root);
	if (r < 0) {
		DMERR("couldn't create devices root");
		goto bad;
	}

	tmd->flags = 0;
	tmd->need_commit = 1;
	r = dm_thin_metadata_commit(tmd);
	if (r < 0) {
		DMERR("%s: dm_thin_metadata_commit() failed, error = %d",
		      __func__, r);
		goto bad;
	}

	return tmd;
bad:
	if (dm_thin_metadata_close(tmd) < 0)
		DMWARN("%s: dm_thin_metadata_close() failed.", __func__);
	return ERR_PTR(r);
}

int dm_thin_metadata_close(struct dm_thin_metadata *tmd)
{
	int r;
	unsigned open_devices = 0;
	struct dm_thin_device *td, *tmp;

	down_read(&tmd->root_lock);
	list_for_each_entry_safe(td, tmp, &tmd->thin_devices, list) {
		if (td->open_count)
			open_devices++;
		else {
			list_del(&td->list);
			kfree(td);
		}
	}
	up_read(&tmd->root_lock);

	if (open_devices) {
		DMERR("attempt to close tmd when %u device(s) are still open",
		       open_devices);
		return -EBUSY;
	}

	if (tmd->sblock) {
		r = dm_thin_metadata_commit(tmd);
		if (r)
			DMWARN("%s: dm_thin_metadata_commit() failed, error = %d",
			       __func__, r);
	}

	dm_tm_destroy(tmd->tm);
	dm_tm_destroy(tmd->nb_tm);
	dm_block_manager_destroy(tmd->bm);
	dm_sm_destroy(tmd->metadata_sm);
	dm_sm_destroy(tmd->data_sm);
	kfree(tmd);

	return 0;
}

int
dm_thin_metadata_rebind_block_device(struct dm_thin_metadata *tmd,
				     struct block_device *bdev)
{
	return dm_bm_rebind_block_device(tmd->bm, bdev);
}

static int __open_device(struct dm_thin_metadata *tmd,
			 dm_thin_dev_t dev, int create,
			 struct dm_thin_device **td)
{
	int r, changed = 0;
	struct dm_thin_device *td2;
	uint64_t key = dev;
	struct device_details details;

	/* check the device isn't already open */
	list_for_each_entry(td2, &tmd->thin_devices, list)
		if (td2->id == dev) {
			td2->open_count++;
			*td = td2;
			return 0;
		}

	/* check the device exists */
	r = dm_btree_lookup(&tmd->details_info, tmd->details_root,
			    &key, &details);
	if (r) {
		if (r != -ENODATA || !create)
			return r;

		changed = 1;
		details.mapped_blocks = 0;
		details.transaction_id = __cpu_to_le64(tmd->trans_id);
		details.creation_time = __cpu_to_le32(tmd->time);
		details.snapshotted_time = __cpu_to_le32(tmd->time);
	}

	*td = kmalloc(sizeof(**td), GFP_NOIO);
	if (!*td)
		return -ENOMEM;

	(*td)->tmd = tmd;
	(*td)->id = dev;
	(*td)->open_count = 1;
	(*td)->changed = changed;
	(*td)->mapped_blocks = __le64_to_cpu(details.mapped_blocks);
	(*td)->transaction_id = __le64_to_cpu(details.transaction_id);
	(*td)->creation_time = __le32_to_cpu(details.creation_time);
	(*td)->snapshotted_time = __le32_to_cpu(details.snapshotted_time);

	list_add(&(*td)->list, &tmd->thin_devices);

	return 0;
}

static void __close_device(struct dm_thin_device *td)
{
	--td->open_count;
}

static int __create_thin(struct dm_thin_metadata *tmd,
			 dm_thin_dev_t dev)
{
	int r;
	dm_block_t dev_root;
	uint64_t key = dev;
	struct device_details detail;
	struct dm_thin_device *td;
	__le64 value;

	r = dm_btree_lookup(&tmd->details_info, tmd->details_root,
			    &key, &detail);
	if (!r)
		return -EEXIST;

	/*
	 * Create an empty btree for the mappings.
	 */
	r = dm_btree_empty(&tmd->bl_info, &dev_root);
	if (r)
		return r;

	/*
	 * Insert it into the main mapping tree.
	 */
	value = __cpu_to_le64(dev_root);
	r = dm_btree_insert(&tmd->tl_info, tmd->root, &key, &value, &tmd->root);
	if (r) {
		dm_btree_del(&tmd->bl_info, dev_root);
		return r;
	}

	r = __open_device(tmd, dev, 1, &td);
	if (r) {
		__close_device(td);
		dm_btree_remove(&tmd->tl_info, tmd->root, &key, &tmd->root);
		dm_btree_del(&tmd->bl_info, dev_root);
		return r;
	}
	td->changed = 1;
	__close_device(td);

	return r;
}

int dm_thin_metadata_create_thin(struct dm_thin_metadata *tmd,
				 dm_thin_dev_t dev)
{
	int r;

	down_write(&tmd->root_lock);
	r = __create_thin(tmd, dev);
	up_write(&tmd->root_lock);

	return r;
}

static int __set_snapshot_details(struct dm_thin_metadata *tmd,
				  struct dm_thin_device *snap,
				  dm_thin_dev_t origin, uint32_t time)
{
	int r;
	struct dm_thin_device *td;

	r = __open_device(tmd, origin, 0, &td);
	if (r)
		return r;

	td->changed = 1;
	td->snapshotted_time = time;

	snap->mapped_blocks = td->mapped_blocks;
	snap->snapshotted_time = time;
	__close_device(td);

	return 0;
}

static int __create_snap(struct dm_thin_metadata *tmd,
			 dm_thin_dev_t dev, dm_thin_dev_t origin)
{
	int r;
	dm_block_t origin_root, snap_root;
	uint64_t key = origin, dev_key = dev;
	struct dm_thin_device *td;
	struct device_details detail;
	__le64 value;

	/* check this device is unused */
	r = dm_btree_lookup(&tmd->details_info, tmd->details_root,
			    &dev_key, &detail);
	if (!r)
		return -EEXIST;

	/* find the mapping tree for the origin */
	r = dm_btree_lookup(&tmd->tl_info, tmd->root, &key, &value);
	if (r)
		return r;
	origin_root = __le64_to_cpu(value);

	/* clone the origin */
	r = dm_btree_clone(&tmd->bl_info, origin_root, &snap_root);
	if (r)
		return r;

	/* insert into the main mapping tree */
	value = __cpu_to_le64(snap_root);
	key = dev;
	r = dm_btree_insert(&tmd->tl_info, tmd->root, &key, &value, &tmd->root);
	if (r) {
		dm_btree_del(&tmd->bl_info, snap_root);
		return r;
	}

	tmd->time++;

	r = __open_device(tmd, dev, 1, &td);
	if (r)
		goto bad;

	r = __set_snapshot_details(tmd, td, origin, tmd->time);
	if (r)
		goto bad;

	__close_device(td);
	return 0;

bad:
	__close_device(td);
	dm_btree_remove(&tmd->tl_info, tmd->root, &key, &tmd->root);
	dm_btree_remove(&tmd->details_info, tmd->details_root,
			&key, &tmd->details_root);
	return r;
}

int dm_thin_metadata_create_snap(struct dm_thin_metadata *tmd,
				 dm_thin_dev_t dev,
				 dm_thin_dev_t origin)
{
	int r;

	down_write(&tmd->root_lock);
	r = __create_snap(tmd, dev, origin);
	up_write(&tmd->root_lock);

	return r;
}

static int __delete_device(struct dm_thin_metadata *tmd,
			   dm_thin_dev_t dev)
{
	int r;
	uint64_t key = dev;
	struct dm_thin_device *td;

	/* TODO: failure should mark the transaction invalid */
	r = __open_device(tmd, dev, 0, &td);
	if (r)
		return r;

	if (td->open_count > 1) {
		__close_device(td);
		return -EBUSY;
	}

	list_del(&td->list);
	kfree(td);
	r = dm_btree_remove(&tmd->details_info, tmd->details_root,
			    &key, &tmd->details_root);
	if (r)
		return r;

	r = dm_btree_remove(&tmd->tl_info, tmd->root, &key, &tmd->root);
	if (r)
		return r;

	tmd->need_commit = 1;

	return 0;
}

int dm_thin_metadata_delete_device(struct dm_thin_metadata *tmd,
				   dm_thin_dev_t dev)
{
	int r;

	down_write(&tmd->root_lock);
	r = __delete_device(tmd, dev);
	up_write(&tmd->root_lock);

	return r;
}

static int __trim_thin_dev(struct dm_thin_device *td, sector_t new_size)
{
	struct dm_thin_metadata *tmd = td->tmd;
	/* FIXME: convert new size to blocks */
	uint64_t key[2] = { td->id, new_size - 1 };

	td->changed = 1;

	/*
	 * We need to truncate all the extraneous mappings.
	 *
	 * FIXME: We have to be careful to do this atomically.
	 * Perhaps clone the bottom layer first so we can revert?
	 */
	return dm_btree_del_gt(&tmd->info, tmd->root, key, &tmd->root);
}

int dm_thin_metadata_trim_thin_dev(struct dm_thin_metadata *tmd,
				   dm_thin_dev_t dev,
				   sector_t new_size)
{
	int r;
	struct dm_thin_device *td;

	down_write(&tmd->root_lock);
	r = __open_device(tmd, dev, 1, &td);
	if (r)
		DMERR("couldn't open virtual device");
	else {
		r = __trim_thin_dev(td, new_size);
		__close_device(td);
	}

	/* FIXME: update mapped_blocks */

	up_write(&tmd->root_lock);

	return r;
}

int dm_thin_metadata_set_transaction_id(struct dm_thin_metadata *tmd,
					uint64_t current_id,
					uint64_t new_id)
{
	down_write(&tmd->root_lock);
	if (tmd->trans_id != current_id) {
		up_write(&tmd->root_lock);
		DMERR("mismatched transaction id");
		return -EINVAL;
	}

	tmd->trans_id = new_id;
	tmd->need_commit = 1;
	up_write(&tmd->root_lock);

	return 0;
}

int dm_thin_metadata_get_transaction_id(struct dm_thin_metadata *tmd,
					uint64_t *result)
{
	down_read(&tmd->root_lock);
	*result = tmd->trans_id;
	up_read(&tmd->root_lock);

	return 0;
}

int dm_thin_metadata_get_held_root(struct dm_thin_metadata *tmd,
				   dm_block_t *result)
{
	struct thin_super_block *sb;

	down_read(&tmd->root_lock);
	sb = dm_block_data(tmd->sblock);
	*result = __le64_to_cpu(sb->held_root);
	up_read(&tmd->root_lock);

	return 0;
}

int dm_thin_metadata_open_device(struct dm_thin_metadata *tmd,
				 dm_thin_dev_t dev,
				 struct dm_thin_device **td)
{
	int r;

	down_write(&tmd->root_lock);
	r = __open_device(tmd, dev, 0, td);
	up_write(&tmd->root_lock);

	return r;
}

int dm_thin_metadata_close_device(struct dm_thin_device *td)
{
	down_write(&td->tmd->root_lock);
	__close_device(td);
	up_write(&td->tmd->root_lock);

	return 0;
}

dm_thin_dev_t dm_thin_device_dev(struct dm_thin_device *td)
{
	return td->id;
}

static int __snapshotted_since(struct dm_thin_device *td, uint32_t time)
{
	return td->snapshotted_time > time;
}

int dm_thin_metadata_lookup(struct dm_thin_device *td,
			    dm_block_t block, int can_block,
			    struct dm_thin_lookup_result *result)
{
	int r;
	uint64_t dm_block_time = 0;
	__le64 value;
	struct dm_thin_metadata *tmd = td->tmd;
	dm_block_t keys[2] = { td->id, block };

	if (can_block) {
		down_read(&tmd->root_lock);
		r = dm_btree_lookup(&tmd->info, tmd->root, keys, &value);
		if (!r)
			dm_block_time = __le64_to_cpu(value);
		up_read(&tmd->root_lock);

	} else if (down_read_trylock(&tmd->root_lock)) {
		r = dm_btree_lookup(&tmd->nb_info, tmd->root, keys, &value);
		if (!r)
			dm_block_time = __le64_to_cpu(value);
		up_read(&tmd->root_lock);

	} else
		return -EWOULDBLOCK;

	if (!r) {
		dm_block_t exception_block;
		uint32_t exception_time;
		unpack_dm_block_time(dm_block_time, &exception_block,
				     &exception_time);
		result->block = exception_block;
		result->shared = __snapshotted_since(td, exception_time);
	}

	return r;
}

static int __insert(struct dm_thin_device *td,
		    dm_block_t block, dm_block_t data_block)
{
	int r, inserted;
	__le64 value;
	struct dm_thin_metadata *tmd = td->tmd;
	dm_block_t keys[2] = { td->id, block };

	tmd->need_commit = 1;
	value = __cpu_to_le64(pack_dm_block_time(data_block, tmd->time));

	r = dm_btree_insert_notify(&tmd->info, tmd->root, keys, &value,
				   &tmd->root, &inserted);
	if (r)
		return r;

	if (inserted) {
		td->mapped_blocks++;
		td->changed = 1;
	}

	return 0;
}

int dm_thin_metadata_insert(struct dm_thin_device *td,
			    dm_block_t block, dm_block_t data_block)
{
	int r;

	down_write(&td->tmd->root_lock);
	r = __insert(td, block, data_block);
	up_write(&td->tmd->root_lock);

	return r;
}

static int __remove(struct dm_thin_device *td, dm_block_t block)
{
	int r;
	struct dm_thin_metadata *tmd = td->tmd;
	dm_block_t keys[2] = { td->id, block };

	r = dm_btree_remove(&tmd->info, tmd->root, keys, &tmd->root);
	if (r)
		return r;

	tmd->need_commit = 1;

	return 0;
}

int dm_thin_metadata_remove(struct dm_thin_device *td, dm_block_t block)
{
	int r;

	down_write(&td->tmd->root_lock);
	r = __remove(td, block);
	up_write(&td->tmd->root_lock);

	return r;
}

int dm_thin_metadata_alloc_data_block(struct dm_thin_device *td,
				      dm_block_t *result)
{
	int r;
	struct dm_thin_metadata *tmd = td->tmd;

	down_write(&tmd->root_lock);
	r = dm_sm_new_block(tmd->data_sm, result);
	tmd->need_commit = 1;
	up_write(&tmd->root_lock);

	return r;
}

static int __write_changed_details(struct dm_thin_metadata *tmd)
{
	int r;
	struct dm_thin_device *td, *tmp;
	struct device_details dd;
	uint64_t key;

	list_for_each_entry_safe(td, tmp, &tmd->thin_devices, list) {
		if (!td->changed)
			continue;

		key = td->id;

		dd.mapped_blocks = __cpu_to_le64(td->mapped_blocks);
		dd.transaction_id = __cpu_to_le64(td->transaction_id);
		dd.creation_time = __cpu_to_le32(td->creation_time);
		dd.snapshotted_time = __cpu_to_le32(td->snapshotted_time);

		r = dm_btree_insert(&tmd->details_info, tmd->details_root,
				    &key, &dd, &tmd->details_root);
		if (r)
			return r;

		if (td->open_count)
			td->changed = 0;
		else {
			list_del(&td->list);
			kfree(td);
		}

		tmd->need_commit = 1;
	}

	return 0;
}

int dm_thin_metadata_commit(struct dm_thin_metadata *tmd)
{
	/*
	 * FIXME: associated pool should be made read-only on
	 * dm_thin_metadata_commit failure.
	 */
	int r;
	size_t len;
	struct thin_super_block *sb;

	/*
	 * We need to know if the thin_super_block exceeds a 512-byte sector.
	 */
	BUILD_BUG_ON(sizeof(struct thin_super_block) > 512);

	down_write(&tmd->root_lock);
	r = __write_changed_details(tmd);
	if (r < 0)
		goto out;

	if (!tmd->need_commit)
		goto out;

	r = dm_tm_pre_commit(tmd->tm);
	if (r < 0)
		goto out;

	r = dm_sm_root_size(tmd->metadata_sm, &len);
	if (r < 0)
		goto out;

	sb = dm_block_data(tmd->sblock);
	sb->time = __cpu_to_le32(tmd->time);
	sb->data_mapping_root = __cpu_to_le64(tmd->root);
	sb->device_details_root = __cpu_to_le64(tmd->details_root);
	sb->trans_id = __cpu_to_le64(tmd->trans_id);
	sb->flags = __cpu_to_le32(tmd->flags);

	r = dm_sm_copy_root(tmd->metadata_sm, &sb->metadata_space_map_root, len);
	if (r < 0)
		goto out;

	r = dm_sm_copy_root(tmd->data_sm, &sb->data_space_map_root, len);
	if (r < 0)
		goto out;

	r = dm_tm_commit(tmd->tm, tmd->sblock);
	if (r < 0)
		goto out;

	/*
	 * Open the next transaction.
	 */
	tmd->sblock = NULL;

	r = begin_transaction(tmd);
out:
	up_write(&tmd->root_lock);
	return r;
}

int dm_thin_metadata_get_free_blocks(struct dm_thin_metadata *tmd,
				     dm_block_t *result)
{
	int r;

	down_read(&tmd->root_lock);
	r = dm_sm_get_nr_free(tmd->data_sm, result);
	up_read(&tmd->root_lock);

	return r;
}

int dm_thin_metadata_get_free_blocks_metadata(struct dm_thin_metadata *tmd,
					      dm_block_t *result)
{
	int r;

	down_read(&tmd->root_lock);
	r = dm_sm_get_nr_free(tmd->metadata_sm, result);
	up_read(&tmd->root_lock);

	return r;
}

int dm_thin_metadata_get_data_block_size(struct dm_thin_metadata *tmd,
					 sector_t *result)
{
	down_read(&tmd->root_lock);
	*result = tmd->data_block_size;
	up_read(&tmd->root_lock);

	return 0;
}

int dm_thin_metadata_get_data_dev_size(struct dm_thin_metadata *tmd,
				       dm_block_t *result)
{
	int r;

	down_read(&tmd->root_lock);
	r = dm_sm_get_nr_blocks(tmd->data_sm, result);
	up_read(&tmd->root_lock);

	return r;
}

int dm_thin_metadata_get_mapped_count(struct dm_thin_device *td,
				      dm_block_t *result)
{
	struct dm_thin_metadata *tmd = td->tmd;

	down_read(&tmd->root_lock);
	*result = td->mapped_blocks;
	up_read(&tmd->root_lock);

	return 0;
}

static int __highest_block(struct dm_thin_device *td, dm_block_t *result)
{
	int r;
	__le64 value;
	dm_block_t thin_root;
	struct dm_thin_metadata *tmd = td->tmd;

	r = dm_btree_lookup(&tmd->tl_info, tmd->root, &td->id, &value);
	if (r)
		return r;

	thin_root = __le64_to_cpu(value);

	return dm_btree_find_highest_key(&tmd->bl_info, thin_root, result);
}

int dm_thin_metadata_get_highest_mapped_block(struct dm_thin_device *td,
					      dm_block_t *result)
{
	int r;
	struct dm_thin_metadata *tmd = td->tmd;

	down_read(&tmd->root_lock);
	r = __highest_block(td, result);
	up_read(&tmd->root_lock);

	return r;
}

static int __resize_data_dev(struct dm_thin_metadata *tmd,
			     dm_block_t new_count)
{
	int r;
	dm_block_t old_count;

	r = dm_sm_get_nr_blocks(tmd->data_sm, &old_count);
	if (r)
		return r;

	if (new_count == old_count)
		return 0;

	if (new_count < old_count) {
		DMERR("cannot reduce size of data device");
		return -EINVAL;
	}

	r = dm_sm_extend(tmd->data_sm, new_count - old_count);
	if (!r)
		tmd->need_commit = 1;

	return r;
}

int dm_thin_metadata_resize_data_dev(struct dm_thin_metadata *tmd,
				     dm_block_t new_count)
{
	int r;

	down_write(&tmd->root_lock);
	r = __resize_data_dev(tmd, new_count);
	up_write(&tmd->root_lock);

	return r;
}

/*
 * Copyright (C) 2011 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "dm-thin-metadata.h"
#include "persistent-data/dm-transaction-manager.h"
#include "persistent-data/dm-space-map-disk.h"

#include <linux/list.h>
#include <linux/device-mapper.h>
#include <linux/workqueue.h>

/*----------------------------------------------------------------*/

#define DM_MSG_PREFIX   "thin-metadata"

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
	__le32 incompat_flags;
} __attribute__ ((packed));

struct device_details {
	__le64 mapped_blocks;
	__le64 transaction_id;	/* when created */
	__le32 creation_time;
	__le32 snapshotted_time;
} __attribute__ ((packed));

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
	struct list_head ms_devices;
	uint64_t trans_id;
	unsigned long flags;
	sector_t data_block_size;
};

struct dm_ms_device {
	struct list_head list;
	struct dm_thin_metadata *mmd;
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

/*----------------------------------------------------------------*/

static int superblock_all_zeroes(struct dm_block_manager *bm, int *result)
{
	int r, i;
	struct dm_block *b;
	uint64_t *data;
	unsigned block_size = dm_bm_block_size(bm) / sizeof(uint64_t);

	/*
	 * We can't use a validator here, it may be all zeroes.
	 */
	r = dm_bm_read_lock(bm, THIN_SUPERBLOCK_LOCATION, NULL, &b);
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

static struct dm_thin_metadata *alloc_mmd(struct dm_block_manager *bm,
					  dm_block_t nr_blocks, int create)
{
	int r;
	struct dm_space_map *sm, *data_sm;
	struct dm_transaction_manager *tm;
	struct dm_thin_metadata *mmd;
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

		r = dm_tm_open_with_sm(bm, THIN_SUPERBLOCK_LOCATION, &sb_validator_,
				       space_map_root_offset, SPACE_MAP_ROOT_SIZE,
				       &tm, &sm, &sblock);
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

	mmd = kmalloc(sizeof(*mmd), GFP_KERNEL);
	if (!mmd) {
		DMERR("could not allocate metadata struct");
		r = -ENOMEM;
		goto bad;
	}

	mmd->bm = bm;
	mmd->metadata_sm = sm;
	mmd->data_sm = data_sm;
	mmd->tm = tm;
	mmd->nb_tm = dm_tm_create_non_blocking_clone(tm);
	if (!mmd->nb_tm) {
		DMERR("could not create clone tm");
		r = -ENOMEM;
		goto bad;
	}

	mmd->sblock = NULL;

	mmd->info.tm = tm;
	mmd->info.levels = 2;
	mmd->info.value_type.context = NULL;
	mmd->info.value_type.size = sizeof(__le64);
	mmd->info.value_type.copy = NULL;
	mmd->info.value_type.del = NULL;
	mmd->info.value_type.equal = NULL;

	memcpy(&mmd->nb_info, &mmd->info, sizeof(mmd->nb_info));
	mmd->nb_info.tm = mmd->nb_tm;

	/* FIXME: fill out the value type */
	mmd->tl_info.tm = tm;
	mmd->tl_info.levels = 1;
	mmd->tl_info.value_type.context = NULL;
	mmd->tl_info.value_type.size = sizeof(__le64);
	mmd->tl_info.value_type.copy = NULL;
	mmd->tl_info.value_type.del = NULL;
	mmd->tl_info.value_type.equal = NULL;

	/* FIXME: fill out the value type */
	mmd->bl_info.tm = tm;
	mmd->bl_info.levels = 1;
	mmd->bl_info.value_type.context = NULL;
	mmd->bl_info.value_type.size = sizeof(__le64);
	mmd->bl_info.value_type.copy = NULL;
	mmd->bl_info.value_type.del = NULL;
	mmd->bl_info.value_type.equal = NULL;

	/* FIXME: fill out the value type */
	mmd->details_info.tm = tm;
	mmd->details_info.levels = 1;
	mmd->details_info.value_type.context = NULL;
	mmd->details_info.value_type.size = sizeof(struct device_details);
	mmd->details_info.value_type.copy = NULL;
	mmd->details_info.value_type.del = NULL;
	mmd->details_info.value_type.equal = NULL;

	mmd->root = 0;

	init_rwsem(&mmd->root_lock);
	mmd->time = 0;
	mmd->need_commit = 0;
	mmd->details_root = 0;
	INIT_LIST_HEAD(&mmd->ms_devices);

	return mmd;

bad:
	dm_tm_destroy(tm);
	dm_sm_destroy(sm);
	dm_block_manager_destroy(bm);

	return ERR_PTR(r);
}

static int begin_transaction(struct dm_thin_metadata *mmd)
{
	int r;
	u32 features;
	struct thin_super_block *sb;

	BUG_ON(mmd->sblock);
	mmd->need_commit = 0;
	/* superblock is unlocked via dm_tm_commit() */
	r = dm_bm_write_lock(mmd->bm, THIN_SUPERBLOCK_LOCATION,
			     &sb_validator_, &mmd->sblock);
	if (r)
		return r;

	sb = dm_block_data(mmd->sblock);
	mmd->time = __le32_to_cpu(sb->time);
	mmd->root = __le64_to_cpu(sb->data_mapping_root);
	mmd->details_root = __le64_to_cpu(sb->device_details_root);
	mmd->trans_id = __le64_to_cpu(sb->trans_id);
	mmd->flags = __le32_to_cpu(sb->flags);
	mmd->data_block_size = __le32_to_cpu(sb->data_block_size);

	features = __le32_to_cpu(sb->incompat_flags) &
		~THIN_FEATURE_INCOMPAT_SUPP;
	if (features) {
		DMERR("could not access metadata due to "
		      "unsupported optional features (%lx).",
		      (unsigned long)features);
		return -EINVAL;
	}

	return 0;
}

struct dm_thin_metadata *
dm_thin_metadata_open(struct block_device *bdev, sector_t data_block_size)
{
	int r;
	struct thin_super_block *sb;
	struct dm_thin_metadata *mmd;
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

	mmd = alloc_mmd(bm, 0, create);
	if (IS_ERR(mmd)) {
		/* alloc_mmd() destroys the block manager on failure */
		return mmd; /* already an ERR_PTR */
	}
	mmd->bdev = bdev;

	if (!create) {
		r = begin_transaction(mmd);
		if (r < 0)
			goto bad;
		return mmd;
	}

	/* Create */
	if (!mmd->sblock) {
		r = begin_transaction(mmd);
		if (r < 0)
			goto bad;
	}

	sb = dm_block_data(mmd->sblock);
	sb->magic = __cpu_to_le64(THIN_SUPERBLOCK_MAGIC);
	sb->version = __cpu_to_le32(THIN_VERSION);
	sb->time = 0;
	sb->metadata_block_size = __cpu_to_le32(THIN_METADATA_BLOCK_SIZE >> SECTOR_SHIFT);
	sb->metadata_nr_blocks = __cpu_to_le64(bdev_size >> SECTOR_TO_BLOCK_SHIFT);
	sb->data_block_size = __cpu_to_le32(data_block_size);

	r = dm_btree_empty(&mmd->info, &mmd->root);
	if (r < 0)
		goto bad;

	r = dm_btree_empty(&mmd->details_info, &mmd->details_root);
	if (r < 0) {
		DMERR("couldn't create devices root");
		goto bad;
	}

	mmd->flags = 0;
	mmd->need_commit = 1;
	r = dm_thin_metadata_commit(mmd);
	if (r < 0)
		goto bad;

	return mmd;
bad:
	dm_thin_metadata_close(mmd);
	return ERR_PTR(r);
}

int dm_thin_metadata_close(struct dm_thin_metadata *mmd)
{
	unsigned open_devices = 0;
	struct dm_ms_device *msd, *tmp;

	down_read(&mmd->root_lock);
	list_for_each_entry_safe (msd, tmp, &mmd->ms_devices, list) {
		if (msd->open_count)
			open_devices++;
		else {
			list_del(&msd->list);
			kfree(msd);
		}
	}
	up_read(&mmd->root_lock);

	if (open_devices) {
		DMERR("attempt to close mmd when %u device(s) are still open",
		       open_devices);
		return -EBUSY;
	}

	if (mmd->sblock)
		dm_thin_metadata_commit(mmd);

	dm_tm_destroy(mmd->tm);
	dm_tm_destroy(mmd->nb_tm);
	dm_block_manager_destroy(mmd->bm);
	dm_sm_destroy(mmd->metadata_sm);
	dm_sm_destroy(mmd->data_sm);
	kfree(mmd);

	return 0;
}

static int __open_device(struct dm_thin_metadata *mmd,
			 dm_thin_dev_t dev, int create,
			 struct dm_ms_device **msd)
{
	int r, changed = 0;
	struct dm_ms_device *msd2;
	uint64_t key = dev;
	struct device_details details;

	/* check the device isn't already open */
	list_for_each_entry (msd2, &mmd->ms_devices, list)
		if (msd2->id == dev) {
			msd2->open_count++;
			*msd = msd2;
			return 0;
		}

	/* check the device exists */
	r = dm_btree_lookup(&mmd->details_info, mmd->details_root,
			    &key, &details);
	if (r) {
		if (r == -ENODATA && create) {
			changed = 1;
			details.mapped_blocks = 0;
			details.transaction_id = __cpu_to_le64(mmd->trans_id);
			details.creation_time = __cpu_to_le32(mmd->time);
			details.snapshotted_time = __cpu_to_le32(mmd->time);

		} else
			return r;
	}

	*msd = kmalloc(sizeof(**msd), GFP_NOIO);
	if (!*msd)
		return -ENOMEM;

	(*msd)->mmd = mmd;
	(*msd)->id = dev;
	(*msd)->open_count = 1;
	(*msd)->changed = changed;
	(*msd)->mapped_blocks = __le64_to_cpu(details.mapped_blocks);
	(*msd)->transaction_id = __le64_to_cpu(details.transaction_id);
	(*msd)->creation_time = __le32_to_cpu(details.creation_time);
	(*msd)->snapshotted_time = __le32_to_cpu(details.snapshotted_time);

	list_add(&(*msd)->list, &mmd->ms_devices);

	return 0;
}

static void __close_device(struct dm_ms_device *msd)
{
	--msd->open_count;
}

static int __create_thin(struct dm_thin_metadata *mmd,
			 dm_thin_dev_t dev)
{
	int r;
	dm_block_t dev_root;
	uint64_t key = dev;
	__le64 value;
	struct dm_ms_device *msd;

	r = dm_btree_lookup(&mmd->details_info, mmd->details_root,
			    &key, &value);
	if (!r)
		return -EEXIST;

	/* create an empty btree for the mappings */
	r = dm_btree_empty(&mmd->bl_info, &dev_root);
	if (r)
		return r;

	/* insert it into the main mapping tree */
	value = __cpu_to_le64(dev_root);
	r = dm_btree_insert(&mmd->tl_info, mmd->root, &key, &value, &mmd->root);
	if (r) {
		dm_btree_del(&mmd->bl_info, dev_root);
		return r;
	}

	r = __open_device(mmd, dev, 1, &msd);
	if (r) {
		__close_device(msd);
		dm_btree_remove(&mmd->tl_info, mmd->root, &key, &mmd->root);
		dm_btree_del(&mmd->bl_info, dev_root);
		return r;
	}
	msd->changed = 1;
	__close_device(msd);

	return r;
}

int dm_thin_metadata_create_thin(struct dm_thin_metadata *mmd,
				 dm_thin_dev_t dev)
{
	int r;

	down_write(&mmd->root_lock);
	r = __create_thin(mmd, dev);
	up_write(&mmd->root_lock);

	return r;
}

static int __set_snapshot_details(struct dm_thin_metadata *mmd,
				  struct dm_ms_device *snap,
				  dm_thin_dev_t origin, uint32_t time)
{
	int r;
	struct dm_ms_device *msd;

	r = __open_device(mmd, origin, 0, &msd);
	if (r)
		return r;

	msd->changed = 1;
	msd->snapshotted_time = time;

	snap->mapped_blocks = msd->mapped_blocks;
	snap->snapshotted_time = time;
	__close_device(msd);

	return 0;
}

static int __create_snap(struct dm_thin_metadata *mmd,
			 dm_thin_dev_t dev, dm_thin_dev_t origin)
{
	int r;
	dm_block_t origin_root, snap_root;
	uint64_t key = origin;
	struct dm_ms_device *msd;
	__le64 value;

	/* find the mapping tree for the origin */
	r = dm_btree_lookup(&mmd->tl_info, mmd->root, &key, &value);
	if (r)
		return r;
	origin_root = __le64_to_cpu(value);

	/* clone the origin */
	r = dm_btree_clone(&mmd->bl_info, origin_root, &snap_root);
	if (r)
		return r;

	/* insert into the main mapping tree */
	value = __cpu_to_le64(snap_root);
	key = dev;
	r = dm_btree_insert(&mmd->tl_info, mmd->root, &key, &value, &mmd->root);
	if (r) {
		dm_btree_del(&mmd->bl_info, snap_root);
		return r;
	}

	mmd->time++;

	r = __open_device(mmd, dev, 1, &msd);
	if (r)
		goto bad;

	r = __set_snapshot_details(mmd, msd, origin, mmd->time);
	if (r)
		goto bad;

	__close_device(msd);
	return 0;

bad:
	__close_device(msd);
	dm_btree_remove(&mmd->tl_info, mmd->root, &key, &mmd->root);
	dm_btree_remove(&mmd->details_info, mmd->details_root,
			&key, &mmd->details_root);
	return r;
}

int dm_thin_metadata_create_snap(struct dm_thin_metadata *mmd,
				 dm_thin_dev_t dev,
				 dm_thin_dev_t origin)
{
	int r;

	down_write(&mmd->root_lock);
	r = __create_snap(mmd, dev, origin);
	up_write(&mmd->root_lock);

	return r;
}

static int __delete_device(struct dm_thin_metadata *mmd,
			   dm_thin_dev_t dev)
{
	uint64_t key = dev;

	return dm_btree_remove(&mmd->tl_info, mmd->root, &key, &mmd->root);
}

int dm_thin_metadata_delete_device(struct dm_thin_metadata *mmd,
				   dm_thin_dev_t dev)
{
	int r;

	down_write(&mmd->root_lock);
	r = __delete_device(mmd, dev);
	up_write(&mmd->root_lock);

	return r;
}

static int __trim_thin_dev(struct dm_ms_device *msd, sector_t new_size)
{
	struct dm_thin_metadata *mmd = msd->mmd;
	uint64_t key[2] = { msd->id, new_size - 1 }; /* FIXME: convert new size to blocks */

	msd->changed = 1;

	/*
	 * We need to truncate all the extraneous mappings.
	 *
	 * FIXME: We have to be careful to do this atomically.
	 * Perhaps clone the bottom layer first so we can revert?
	 */
	return dm_btree_del_gt(&mmd->info, mmd->root, key, &mmd->root);
}

int dm_thin_metadata_trim_thin_dev(struct dm_thin_metadata *mmd,
				   dm_thin_dev_t dev,
				   sector_t new_size)
{
	int r;
	struct dm_ms_device *msd;

	down_write(&mmd->root_lock);
	r = __open_device(mmd, dev, 1, &msd);
	if (r)
		DMERR("couldn't open virtual device");
	else {
		r = __trim_thin_dev(msd, new_size);
		__close_device(msd);
	}

	// FIXME: update mapped_blocks

	up_write(&mmd->root_lock);

	return r;
}

int dm_thin_metadata_set_transaction_id(struct dm_thin_metadata *mmd,
					uint64_t current_id,
					uint64_t new_id)
{
	down_write(&mmd->root_lock);
	if (mmd->trans_id != current_id) {
		up_write(&mmd->root_lock);
		DMERR("mismatched transaction id");
		return -EINVAL;
	}

	mmd->trans_id = new_id;
	mmd->need_commit = 1;
	up_write(&mmd->root_lock);

	return 0;
}

int dm_thin_metadata_get_transaction_id(struct dm_thin_metadata *mmd,
					uint64_t *result)
{
	down_read(&mmd->root_lock);
	*result = mmd->trans_id;
	up_read(&mmd->root_lock);

	return 0;
}

int dm_thin_metadata_hold_root(struct dm_thin_metadata *mmd)
{
	/* FIXME implement */

	return 0;
}

int dm_thin_metadata_get_held_root(struct dm_thin_metadata *mmd,
				   dm_block_t *result)
{
	struct thin_super_block *sb;

	down_read(&mmd->root_lock);
	sb = dm_block_data(mmd->sblock);
	*result = __le64_to_cpu(sb->held_root);
	up_read(&mmd->root_lock);

	return 0;
}

int dm_thin_metadata_open_device(struct dm_thin_metadata *mmd,
				 dm_thin_dev_t dev,
				 struct dm_ms_device **msd)
{
	int r;

	down_write(&mmd->root_lock);
	r = __open_device(mmd, dev, 0, msd);
	up_write(&mmd->root_lock);

	return r;
}

int dm_thin_metadata_close_device(struct dm_ms_device *msd)
{
	down_write(&msd->mmd->root_lock);
	__close_device(msd);
	up_write(&msd->mmd->root_lock);

	return 0;
}

dm_thin_dev_t dm_thin_device_dev(struct dm_ms_device *msd)
{
	return msd->id;
}

static uint64_t pack_dm_block_time(dm_block_t b, uint32_t t)
{
	return ((b << 24) | t);
}

static void unpack_dm_block_time(uint64_t v, dm_block_t *b, uint32_t *t)
{
	*b = v >> 24;
	*t = v & ((1 << 24) - 1);
}

static int __snapshotted_since(struct dm_ms_device *msd, uint32_t time)
{
	return msd->snapshotted_time > time;
}

int dm_thin_metadata_lookup(struct dm_ms_device *msd,
			    dm_block_t block, int can_block,
			    struct dm_thin_lookup_result *result)
{
	int r;
	uint64_t keys[2], dm_block_time = 0;
	__le64 value;
	struct dm_thin_metadata *mmd = msd->mmd;

	keys[0] = msd->id;
	keys[1] = block;

	if (can_block) {
		down_read(&mmd->root_lock);
		r = dm_btree_lookup(&mmd->info, mmd->root, keys, &value);
		if (!r)
			dm_block_time = __le64_to_cpu(value);
		up_read(&mmd->root_lock);

	} else if (down_read_trylock(&mmd->root_lock)) {
		r = dm_btree_lookup(&mmd->nb_info, mmd->root, keys, &value);
		if (!r)
			dm_block_time = __le64_to_cpu(value);
		up_read(&mmd->root_lock);

	} else
		return -EWOULDBLOCK;

	if (!r) {
		dm_block_t exception_block;
		uint32_t exception_time;
		unpack_dm_block_time(dm_block_time, &exception_block,
				     &exception_time);
		result->block = exception_block;
		result->shared = __snapshotted_since(msd, exception_time);
	}

	return r;
}

static int __insert(struct dm_ms_device *msd,
		    dm_block_t block, dm_block_t data_block)
{
	int r, inserted;
	dm_block_t keys[2];
	__le64 value;
	struct dm_thin_metadata *mmd = msd->mmd;

	keys[0] = msd->id;
	keys[1] = block;

	mmd->need_commit = 1;
	value = __cpu_to_le64(pack_dm_block_time(data_block, mmd->time));

	r = dm_btree_insert_notify(&mmd->info, mmd->root, keys, &value,
				   &mmd->root, &inserted);
	if (r)
		return r;

	if (inserted) {
		msd->mapped_blocks++;
		msd->changed = 1;
	}

	return 0;
}

int dm_thin_metadata_insert(struct dm_ms_device *msd,
			    dm_block_t block, dm_block_t data_block)
{
	int r;

	down_write(&msd->mmd->root_lock);
	r = __insert(msd, block, data_block);
	up_write(&msd->mmd->root_lock);

	return r;
}

static int __remove(struct dm_ms_device *msd, dm_block_t block)
{
	int r;
	struct dm_thin_metadata *mmd = msd->mmd;
	dm_block_t keys[2] = { msd->id, block };

	r = dm_btree_remove(&mmd->info, mmd->root, keys, &mmd->root);
	if (r)
		return r;

	mmd->need_commit = 1;
	return 0;
}

int dm_thin_metadata_remove(struct dm_ms_device *msd, dm_block_t block)
{
	int r;

	down_write(&msd->mmd->root_lock);
	r = __remove(msd, block);
	up_write(&msd->mmd->root_lock);

	return r;
}

int dm_thin_metadata_alloc_data_block(struct dm_ms_device *msd,
				      dm_block_t *result)
{
	int r;
	struct dm_thin_metadata *mmd = msd->mmd;

	down_write(&mmd->root_lock);
	r = dm_sm_new_block(mmd->data_sm, result);
	mmd->need_commit = 1;
	up_write(&mmd->root_lock);

	return r;
}

int dm_thin_metadata_free_data_block(struct dm_ms_device *msd,
				     dm_block_t result)
{
	int r;
	struct dm_thin_metadata *mmd = msd->mmd;

	down_write(&mmd->root_lock);
	r = dm_sm_dec_block(mmd->data_sm, result);
	mmd->need_commit = 1;
	up_write(&mmd->root_lock);

	return r;
}

static int __write_changed_details(struct dm_thin_metadata *mmd)
{
	int r;
	struct dm_ms_device *msd, *tmp;

	list_for_each_entry_safe (msd, tmp, &mmd->ms_devices, list) {
		if (msd->changed) {
			struct device_details dd;
			uint64_t key = msd->id;

			dd.mapped_blocks = __cpu_to_le64(msd->mapped_blocks);
			dd.transaction_id = __cpu_to_le64(msd->transaction_id);
			dd.creation_time = __cpu_to_le32(msd->creation_time);
			dd.snapshotted_time = __cpu_to_le32(msd->snapshotted_time);

			r = dm_btree_insert(&mmd->details_info, mmd->details_root,
					    &key, &dd, &mmd->details_root);
			if (r)
				return r;

			if (msd->open_count)
				msd->changed = 0;
			else {
				list_del(&msd->list);
				kfree(msd);
			}

			mmd->need_commit = 1;
		}
	}

	return 0;
}

int dm_thin_metadata_commit(struct dm_thin_metadata *mmd)
{
	int r;
	size_t len;
	struct thin_super_block *sb;

	/* We want to know if/when the thin_super_block exceeds a 512b sector */
	BUILD_BUG_ON(sizeof(struct thin_super_block) > 512);

	down_write(&mmd->root_lock);
	r = __write_changed_details(mmd);
	if (r < 0)
		goto out;

	if (!mmd->need_commit)
		goto out;

	r = dm_tm_pre_commit(mmd->tm);
	if (r < 0)
		goto out;

	r = dm_sm_root_size(mmd->metadata_sm, &len);
	if (r < 0)
		goto out;

	sb = dm_block_data(mmd->sblock);
	sb->time = __cpu_to_le32(mmd->time);
	sb->data_mapping_root = __cpu_to_le64(mmd->root);
	sb->device_details_root = __cpu_to_le64(mmd->details_root);
	sb->trans_id = __cpu_to_le64(mmd->trans_id);
	sb->flags = __cpu_to_le32(mmd->flags);
	r = dm_sm_copy_root(mmd->metadata_sm, &sb->metadata_space_map_root, len);
	if (r < 0)
		goto out;

	r = dm_sm_copy_root(mmd->data_sm, &sb->data_space_map_root, len);
	if (r < 0)
		goto out;

	/* FIXME: unchecked dm_tm_commit() and begin_transaction() error codes? */
	r = dm_tm_commit(mmd->tm, mmd->sblock);

	/* open the next transaction */
	mmd->sblock = NULL;

	/* FIXME: the semantics of failure are confusing here, did the commit fail, or the begin? */
	r = begin_transaction(mmd);
out:
	up_write(&mmd->root_lock);
	return r;
}

int dm_thin_metadata_get_free_blocks(struct dm_thin_metadata *mmd,
				     dm_block_t *result)
{
	int r;

	down_read(&mmd->root_lock);
	r = dm_sm_get_nr_free(mmd->data_sm, result);
	up_read(&mmd->root_lock);

	return r;
}

int
dm_thin_metadata_get_free_blocks_metadata(struct dm_thin_metadata *mmd,
					  dm_block_t *result)
{
	int r;

	down_read(&mmd->root_lock);
	r = dm_sm_get_nr_free(mmd->metadata_sm, result);
	up_read(&mmd->root_lock);

	return r;
}

int dm_thin_metadata_get_data_block_size(struct dm_thin_metadata *mmd,
					 sector_t *result)
{
	down_read(&mmd->root_lock);
	*result = mmd->data_block_size;
	up_read(&mmd->root_lock);

	return 0;
}

int dm_thin_metadata_get_data_dev_size(struct dm_thin_metadata *mmd,
				       dm_block_t *result)
{
	int r;

	down_read(&mmd->root_lock);
	r = dm_sm_get_nr_blocks(mmd->data_sm, result);
	up_read(&mmd->root_lock);

	return r;
}

int dm_thin_metadata_get_mapped_count(struct dm_ms_device *msd,
				      dm_block_t *result)
{
	struct dm_thin_metadata *mmd = msd->mmd;

	down_read(&mmd->root_lock);
	*result = msd->mapped_blocks;
	up_read(&mmd->root_lock);

	return 0;
}

static int __highest_block(struct dm_ms_device *msd, dm_block_t *result)
{
	int r;
	dm_block_t thin_root;
	struct dm_thin_metadata *mmd = msd->mmd;

	r = dm_btree_lookup(&mmd->tl_info, mmd->root, &msd->id, &thin_root);
	if (r)
		return r;

	return dm_btree_find_highest_key(&mmd->bl_info, thin_root, result);
}

int dm_thin_metadata_get_highest_mapped_block(struct dm_ms_device *msd,
					      dm_block_t *result)
{
	int r;
	struct dm_thin_metadata *mmd = msd->mmd;

	down_read(&mmd->root_lock);
	r = __highest_block(msd, result);
	up_read(&mmd->root_lock);

	return r;
}

static int __resize_data_dev(struct dm_thin_metadata *mmd,
			     dm_block_t new_count)
{
	int r;
	dm_block_t old_count;

	r = dm_sm_get_nr_blocks(mmd->data_sm, &old_count);
	if (r)
		return r;

	if (new_count < old_count) {
		DMERR("cannot reduce size of data device");
		return -EINVAL;
	}

	if (new_count > old_count) {
		r = dm_sm_extend(mmd->data_sm, new_count - old_count);
		if (!r)
			mmd->need_commit = 1;
		return r;
	} else
		return 0;
}

int dm_thin_metadata_resize_data_dev(struct dm_thin_metadata *mmd,
				     dm_block_t new_count)
{
	int r;

	down_write(&mmd->root_lock);
	r = __resize_data_dev(mmd, new_count);
	up_write(&mmd->root_lock);

	return r;
}

/*----------------------------------------------------------------*/

/*
 * Copyright (C) 2011 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "dm-multisnap-metadata.h"
#include "persistent-data/dm-transaction-manager.h"
#include "persistent-data/dm-space-map-disk.h"

#include <linux/list.h>
#include <linux/device-mapper.h>
#include <linux/workqueue.h>

/*----------------------------------------------------------------*/

#define	DAEMON "multisnap-metadata"

#define MULTISNAP_SUPERBLOCK_MAGIC 27022010
#define MULTISNAP_SUPERBLOCK_LOCATION 0
#define MULTISNAP_VERSION 1
#define MULTISNAP_METADATA_BLOCK_SIZE 4096
#define MULTISNAP_METADATA_CACHE_SIZE 64
#define SECTOR_TO_BLOCK_SHIFT 3

/* This should be plenty */
#define SPACE_MAP_ROOT_SIZE 128

// FIXME: we should put some form of checksum in here
struct superblock {
	__le64 magic;
	__le64 version;
	__le32 time;
	__u8 padding[4];

	__le32 data_block_size;	/* in 512-byte sectors */

	__le32 metadata_block_size; /* in 512-byte sectors */
	__le64 metadata_nr_blocks;

	/* 2 level btree mapping (dev_id, (dev block, time)) -> data block */
	__le64 data_mapping_root;

	/* device detail root mapping dev_id -> device_details */
	__le64 device_details_root;

	__u8 data_space_map_root[SPACE_MAP_ROOT_SIZE];
	__u8 metadata_space_map_root[SPACE_MAP_ROOT_SIZE];
} __attribute__ ((packed));

struct device_details {
	__le64 dev_size;
	__le64 mapped_blocks;
	__le32 snapshotted_time;
} __attribute__ ((packed));

struct dm_multisnap_metadata {
	struct hlist_node hash;

	struct block_device *bdev;
	struct dm_block_manager *bm;
	struct dm_space_map *metadata_sm;
	struct dm_space_map *data_sm;
	struct dm_transaction_manager *tm;
	struct dm_transaction_manager *nb_tm;

	/*
	 * Two level btree, first level is multisnap_dev_t, second level
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
	int have_inserted;
	struct dm_block *sblock;
	dm_block_t root;
	dm_block_t details_root;
	struct list_head ms_devices;
};

struct dm_ms_device {
	struct list_head list;
	struct dm_multisnap_metadata *mmd;
	dm_multisnap_dev_t id;

	int is_open;
	int changed;
	uint64_t dev_size;
	uint64_t mapped_blocks;
	uint32_t snapshotted_time;
};

/*----------------------------------------------------------------*/

static int superblock_all_zeroes(struct dm_block_manager *bm, int *result)
{
	int r, i;
	struct dm_block *b;
	uint64_t *data;
	unsigned block_size = dm_bm_block_size(bm) / sizeof(uint64_t);

	r = dm_bm_read_lock(bm, MULTISNAP_SUPERBLOCK_LOCATION, &b);
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

static struct dm_multisnap_metadata *alloc_mmd(struct dm_block_manager *bm,
					       dm_block_t nr_blocks, int create)
{
	int r;
	struct dm_space_map *sm, *data_sm;
	struct dm_transaction_manager *tm;
	struct dm_multisnap_metadata *mmd;
	struct dm_block *sb;

	if (create) {
		r = dm_tm_create_with_sm(bm, MULTISNAP_SUPERBLOCK_LOCATION,
					 &tm, &sm, &sb);
		if (r < 0) {
			printk(KERN_ALERT "tm_create_with_sm failed");
			dm_block_manager_destroy(bm);
			return NULL;
		}

		data_sm = dm_sm_disk_create(tm, nr_blocks);
		if (IS_ERR(data_sm)) {
			printk(KERN_ALERT "sm_disk_create");
			goto bad;
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

		r = dm_tm_open_with_sm(bm, MULTISNAP_SUPERBLOCK_LOCATION,
				       offsetof(struct superblock, metadata_space_map_root),
				       SPACE_MAP_ROOT_SIZE,
				       &tm, &sm, &sb);
		if (r < 0) {
			printk(KERN_ALERT "tm_open_with_sm failed");
			dm_block_manager_destroy(bm);
			return NULL;
		}

		s = dm_block_data(sb);
		if (__le64_to_cpu(s->magic) != MULTISNAP_SUPERBLOCK_MAGIC) {
			printk(KERN_ALERT "multisnap-metadata superblock is invalid (was %llu)",
			       __le64_to_cpu(s->magic));
			goto bad;
		}

		data_sm = dm_sm_disk_open(tm, s->data_space_map_root,
					  sizeof(s->data_space_map_root));
		if (!data_sm) {
			printk(KERN_ALERT "sm_disk_open failed");
			goto bad;
		}

		dm_tm_unlock(tm, sb);
	}

	mmd = kmalloc(sizeof(*mmd), GFP_KERNEL);
	if (!mmd) {
		printk(KERN_ALERT "multisnap-metadata could not allocate metadata struct");
		goto bad;
	}

	mmd->bm = bm;
	mmd->metadata_sm = sm;
	mmd->data_sm = data_sm;
	mmd->tm = tm;
	mmd->nb_tm = dm_tm_create_non_blocking_clone(tm);
	if (!mmd->nb_tm) {
		printk(KERN_ALERT "multisnap-metadata could not create clone tm");
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
	mmd->have_inserted = 0;
	mmd->details_root = 0;
	INIT_LIST_HEAD(&mmd->ms_devices);

	return mmd;

bad:
	dm_tm_destroy(tm);
	dm_sm_destroy(sm);
	dm_block_manager_destroy(bm);

	return NULL;
}

static int begin(struct dm_multisnap_metadata *mmd)
{
	int r;
	struct superblock *s;

	BUG_ON(mmd->sblock);
	mmd->have_inserted = 0;
	r = dm_bm_write_lock(mmd->bm, MULTISNAP_SUPERBLOCK_LOCATION, &mmd->sblock);
	if (r)
		return r;

	s = (struct superblock *) dm_block_data(mmd->sblock);
	mmd->time = __le32_to_cpu(s->time);
	mmd->root = __le64_to_cpu(s->data_mapping_root);
	mmd->details_root = __le64_to_cpu(s->device_details_root);

	return 0;
}

struct dm_multisnap_metadata *
dm_multisnap_metadata_open(struct block_device *bdev, unsigned data_block_size,
			   dm_block_t data_dev_size)
{
	int r;
	struct superblock *sb;
	struct dm_multisnap_metadata *mmd;
	sector_t bdev_size = i_size_read(bdev->bd_inode) >> SECTOR_SHIFT;
	struct dm_block_manager *bm;
	int create;

	bm = dm_block_manager_create(bdev, MULTISNAP_METADATA_BLOCK_SIZE,
				     MULTISNAP_METADATA_CACHE_SIZE);
	if (!bm) {
		printk(KERN_ALERT "multisnap-metadata could not create block manager");
		return NULL;
	}

	r = superblock_all_zeroes(bm, &create);
	if (r) {
		dm_block_manager_destroy(bm);
		return NULL;
	}

	mmd = alloc_mmd(bm, data_dev_size, create);
	if (!mmd)
		return NULL;
	mmd->bdev = bdev;

	if (!create) {
		r = begin(mmd);
		if (r < 0)
			goto bad;
		return mmd;
	}

	/* Create */
	if (!mmd->sblock) {
		r = begin(mmd);
		if (r < 0)
			goto bad;
	}

	sb = (struct superblock *) dm_block_data(mmd->sblock);
	sb->magic = __cpu_to_le64(MULTISNAP_SUPERBLOCK_MAGIC);
	sb->version = __cpu_to_le64(MULTISNAP_VERSION);
	sb->time = 0;
	sb->metadata_block_size = __cpu_to_le32(MULTISNAP_METADATA_BLOCK_SIZE >> SECTOR_SHIFT);
	sb->metadata_nr_blocks = __cpu_to_le64(bdev_size >> SECTOR_TO_BLOCK_SHIFT);
	sb->data_block_size = __cpu_to_le32(data_block_size);

	r = dm_btree_empty(&mmd->info, &mmd->root);
	if (r < 0)
		goto bad;

	r = dm_btree_empty(&mmd->details_info, &mmd->details_root);
	if (r < 0) {
		printk(KERN_ALERT "couldn't create devices root");
		goto bad;
	}

	mmd->have_inserted = 1;
	r = dm_multisnap_metadata_commit(mmd);
	if (r < 0)
		goto bad;

	return mmd;
bad:
	dm_multisnap_metadata_close(mmd);
	return NULL;
}

int dm_multisnap_metadata_close(struct dm_multisnap_metadata *mmd)
{
	unsigned open_devices = 0;
	struct dm_ms_device *msd, *tmp;

	down_read(&mmd->root_lock);
	list_for_each_entry_safe (msd, tmp, &mmd->ms_devices, list) {
		if (msd->is_open)
			open_devices++;
		else {
			list_del(&msd->list);
			kfree(msd);
		}
	}
	up_read(&mmd->root_lock);

	if (open_devices) {
		printk(KERN_ALERT "attempt to close mmd when %u device(s) are still open",
		       open_devices);
		return -EBUSY;
	}

	if (mmd->sblock)
		dm_multisnap_metadata_commit(mmd);

	dm_tm_destroy(mmd->tm);
	dm_tm_destroy(mmd->nb_tm);
	dm_block_manager_destroy(mmd->bm);
	dm_sm_destroy(mmd->metadata_sm);
	kfree(mmd);

	return 0;
}

static int __open_device(struct dm_multisnap_metadata *mmd,
			 dm_multisnap_dev_t dev, int create,
			 struct dm_ms_device **msd)
{
	int r, changed = 0;
	struct dm_ms_device *msd2;
	uint64_t key = dev;
	struct device_details details;

	/* check the device isn't already open */
	list_for_each_entry (msd2, &mmd->ms_devices, list)
		if (msd2->id == dev) {
			*msd = msd2;
			return 0;
		}

	/* check the device exists */
	r = dm_btree_lookup(&mmd->details_info, mmd->details_root,
			    &key, &details);
	if (r) {
		if (r == -ENODATA && create) {
			changed = 1;
			details.dev_size = 0;
			details.mapped_blocks = 0;
			details.snapshotted_time = __cpu_to_le32(mmd->time);

		} else
			return r;
	}

	*msd = kmalloc(sizeof(**msd), GFP_KERNEL);
	if (!*msd)
		return -ENOMEM;

	(*msd)->mmd = mmd;
	(*msd)->id = dev;
	(*msd)->is_open = 0;
	(*msd)->changed = changed;
	(*msd)->dev_size = __le64_to_cpu(details.dev_size);
	(*msd)->mapped_blocks = __le64_to_cpu(details.mapped_blocks);
	(*msd)->snapshotted_time = __le64_to_cpu(details.snapshotted_time);

	list_add(&(*msd)->list, &mmd->ms_devices);

	return 0;
}

static int __create_thin(struct dm_multisnap_metadata *mmd,
			 dm_multisnap_dev_t dev, dm_block_t dev_size)
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
		dm_btree_remove(&mmd->tl_info, mmd->root, &key, &mmd->root);
		dm_btree_del(&mmd->bl_info, dev_root);
		return r;
	}
	msd->dev_size = dev_size;

	return r;
}

int dm_multisnap_metadata_create_thin(struct dm_multisnap_metadata *mmd,
				      dm_multisnap_dev_t dev,
				      dm_block_t dev_size)
{
	int r;

	down_write(&mmd->root_lock);
	r = __create_thin(mmd, dev, dev_size);
	up_write(&mmd->root_lock);

	return r;
}

static int __set_snapshot_details(struct dm_multisnap_metadata *mmd,
				  struct dm_ms_device *snap,
				  dm_multisnap_dev_t origin, uint32_t time)
{
	int r;
	struct dm_ms_device *msd;

	r = __open_device(mmd, origin, 0, &msd);
	if (r)
		return r;

	msd->changed = 1;
	msd->snapshotted_time = time;

	snap->dev_size = msd->dev_size;
	snap->mapped_blocks = msd->mapped_blocks;
	snap->snapshotted_time = time;

	return 0;
}

static int __create_snap(struct dm_multisnap_metadata *mmd,
			 dm_multisnap_dev_t dev, dm_multisnap_dev_t origin)
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
	if (r) {
		dm_btree_remove(&mmd->tl_info, mmd->root, &key, &mmd->root);
		dm_btree_remove(&mmd->details_info, mmd->details_root,
				&key, &mmd->details_root);
	}

	r = __set_snapshot_details(mmd, msd, origin, mmd->time);
	if (r) {
		dm_btree_remove(&mmd->tl_info, mmd->root, &key, &mmd->root);
		dm_btree_remove(&mmd->details_info, mmd->details_root,
				&key, &mmd->details_root);
	}

	return r;
}

int dm_multisnap_metadata_create_snap(struct dm_multisnap_metadata *mmd,
				      dm_multisnap_dev_t dev,
				      dm_multisnap_dev_t origin)
{
	int r;

	down_write(&mmd->root_lock);
	r = __create_snap(mmd, dev, origin);
	up_write(&mmd->root_lock);

	return r;
}

static int __delete_device(struct dm_multisnap_metadata *mmd,
			   dm_multisnap_dev_t dev)
{
	uint64_t key = dev;

	return dm_btree_remove(&mmd->tl_info, mmd->root, &key, &mmd->root);
}

int dm_multisnap_metadata_delete_device(struct dm_multisnap_metadata *mmd,
					dm_multisnap_dev_t dev)
{
	int r;

	down_write(&mmd->root_lock);
	r = __delete_device(mmd, dev);
	up_write(&mmd->root_lock);

	return r;
}

int dm_multisnap_metadata_open_device(struct dm_multisnap_metadata *mmd,
				      dm_multisnap_dev_t dev,
				      struct dm_ms_device **msd)
{
	int r;

	down_write(&mmd->root_lock);
	r = __open_device(mmd, dev, 0, msd);
	if (!r) {
		if ((*msd)->is_open)
			r = -EBUSY;
		else
			(*msd)->is_open = 1;
	}
	up_write(&mmd->root_lock);

	return r;
}

int dm_multisnap_metadata_close_device(struct dm_ms_device *msd)
{
	down_write(&msd->mmd->root_lock);
	msd->is_open = 0;
	up_write(&msd->mmd->root_lock);

	return 0;
}

dm_multisnap_dev_t dm_multisnap_device_dev(struct dm_ms_device *msd)
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

int dm_multisnap_metadata_lookup(struct dm_ms_device *msd,
				 dm_block_t block, int can_block,
				 struct dm_multisnap_lookup_result *result)
{
	int r;
	uint64_t keys[2], dm_block_time = 0;
	__le64 value;
	struct dm_multisnap_metadata *mmd = msd->mmd;

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

int __insert(struct dm_ms_device *msd,
	     dm_block_t block, dm_block_t data_block)
{
	dm_block_t keys[2];
	__le64 value;
	struct dm_multisnap_metadata *mmd = msd->mmd;

	keys[0] = msd->id;
	keys[1] = block;

	mmd->have_inserted = 1;
	value = __cpu_to_le64(pack_dm_block_time(data_block, mmd->time));

	return dm_btree_insert(&mmd->info, mmd->root, keys, &value, &mmd->root);
}

int dm_multisnap_metadata_insert(struct dm_ms_device *msd,
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
	struct dm_multisnap_metadata *mmd = msd->mmd;
	dm_block_t keys[2] = { msd->id, block };

	r = dm_btree_remove(&mmd->info, mmd->root, keys, &mmd->root);
	if (r)
		return r;

	mmd->have_inserted = 1;
	return 0;
}

int dm_multisnap_metadata_remove(struct dm_ms_device *msd, dm_block_t block)
{
	int r;

	down_write(&msd->mmd->root_lock);
	r = __remove(msd, block);
	up_write(&msd->mmd->root_lock);

	return r;
}

int dm_multisnap_metadata_alloc_data_block(struct dm_ms_device *msd,
					   dm_block_t *result)
{
	int r;
	struct dm_multisnap_metadata *mmd = msd->mmd;

	/*
	 * FIXME: we need to persist allocations that haven't yet been
	 * inserted.
	 */
	down_write(&mmd->root_lock);
	r = dm_sm_new_block(msd->mmd->data_sm, result);
	up_write(&mmd->root_lock);

	return r;
}

int dm_multisnap_metadata_free_data_block(struct dm_ms_device *msd,
					  dm_block_t result)
{
	int r;
	struct dm_multisnap_metadata *mmd = msd->mmd;

	down_write(&mmd->root_lock);
	r = dm_sm_dec_block(msd->mmd->data_sm, result);
	up_write(&mmd->root_lock);

	return r;
}

static int __write_changed_details(struct dm_multisnap_metadata *mmd)
{
	int r;
	struct dm_ms_device *msd, *tmp;

	list_for_each_entry_safe (msd, tmp, &mmd->ms_devices, list) {
		if (msd->changed) {
			struct device_details dd;
			uint64_t key = msd->id;

			dd.dev_size = __cpu_to_le64(msd->dev_size);
			dd.mapped_blocks = __cpu_to_le64(msd->mapped_blocks);
			dd.snapshotted_time = __cpu_to_le32(msd->snapshotted_time);

			r = dm_btree_insert(&mmd->details_info, mmd->details_root,
					    &key, &dd, &mmd->details_root);
			if (r)
				return r;

			if (msd->is_open)
				msd->changed = 0;
			else {
				list_del(&msd->list);
				kfree(msd);
			}
		}
	}

	return 0;
}

int dm_multisnap_metadata_commit(struct dm_multisnap_metadata *mmd)
{
	int r;
	size_t len;
	struct superblock *sb;

	down_read(&mmd->root_lock);
	if (!mmd->have_inserted) {
		up_read(&mmd->root_lock);
		return 0;
	}
	up_read(&mmd->root_lock);

	down_write(&mmd->root_lock);
	r = __write_changed_details(mmd);
	if (r < 0)
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
	r = dm_sm_copy_root(mmd->metadata_sm, &sb->metadata_space_map_root, len);
	if (r < 0)
		goto out;

	r = dm_sm_copy_root(mmd->data_sm, &sb->data_space_map_root, len);
	if (r < 0)
		goto out;

	/* FIXME: unchecked dm_tm_commit() and begin() error codes? */
	r = dm_tm_commit(mmd->tm, mmd->sblock);

	/* open the next transaction */
	mmd->sblock = NULL;

	/* FIXME: the semantics of failure are confusing here, did the commit fail, or the begin? */
	r = begin(mmd);
out:
	up_write(&mmd->root_lock);
	return r;
}

int dm_multisnap_metadata_get_free_blocks(struct dm_multisnap_metadata *mmd,
					  dm_block_t *result)
{
	int r;

	down_read(&mmd->root_lock);
	r = dm_sm_get_nr_free(mmd->data_sm, result);
	up_read(&mmd->root_lock);

	return r;
}

int dm_multisnap_metadata_get_data_block_size(struct dm_multisnap_metadata *mmd,
					      unsigned *result)
{
	struct superblock *sb;

	down_read(&mmd->root_lock);
	sb = (struct superblock *) dm_block_data(mmd->sblock);
	*result = __le32_to_cpu(sb->data_block_size);
	up_read(&mmd->root_lock);

	return 0;
}

int dm_multisnap_metadata_get_data_dev_size(struct dm_multisnap_metadata *mmd,
					    dm_block_t *result)
{
	int r;

	down_read(&mmd->root_lock);
	r = dm_sm_get_nr_blocks(mmd->data_sm, result);
	up_read(&mmd->root_lock);

	return r;
}

int dm_multisnap_metadata_get_mapped_count(struct dm_ms_device *msd,
					   dm_block_t *result)
{
	struct dm_multisnap_metadata *mmd = msd->mmd;

	down_read(&mmd->root_lock);
	*result = msd->mapped_blocks;
	up_read(&mmd->root_lock);

	return 0;
}

int dm_multisnap_metadata_resize_virt_dev(struct dm_ms_device *msd,
					  dm_block_t new_size)
{
	down_write(&msd->mmd->root_lock);
	msd->dev_size = new_size;
	msd->changed = 1;
	up_write(&msd->mmd->root_lock);

	return 0;
}

int dm_multisnap_metadata_resize_data_dev(struct dm_multisnap_metadata *mmd,
					  dm_block_t new_size)
{
	down_write(&mmd->root_lock);
	/* FIXME: finish */

	up_write(&mmd->root_lock);

	return 0;
}

/*----------------------------------------------------------------*/

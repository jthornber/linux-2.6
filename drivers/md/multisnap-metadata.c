/*
 * Copyright (C) 2010 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "multisnap-metadata.h"
#include "persistent-data/transaction-manager.h"
#include "persistent-data/space-map-disk.h"

#include <linux/list.h>
#include <linux/device-mapper.h>
#include <linux/workqueue.h>

/*----------------------------------------------------------------*/

#define	DAEMON "multisnap-metadata"

#define MULTISNAP_SUPERBLOCK_MAGIC 27022010
#define MULTISNAP_SUPERBLOCK_LOCATION 0
#define MULTISNAP_VERSION 1
#define MULTISNAP_METADATA_BLOCK_SIZE 4096
#define MULTISNAP_METADATA_CACHE_SIZE 128
#define SECTOR_TO_BLOCK_SHIFT 3

/* This should be plenty */
#define SPACE_MAP_ROOT_SIZE 128

// FIXME: we should put some form of checksum in here
struct superblock {
	__le64 magic;
	__le64 version;
	__le64 time;

	__le64 metadata_block_size; /* in sectors */
	__le64 metadata_nr_blocks;

	__le64 data_block_size;	/* in 512-byte sectors */

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

struct multisnap_metadata {
	struct hlist_node hash;

	struct block_device *bdev;
	struct block_manager *bm;
	struct space_map *metadata_sm;
	struct space_map *data_sm;
	struct transaction_manager *tm;
	struct transaction_manager *nb_tm;

	/*
	 * Two level btree, first level is multisnap_dev_t, second level
	 * mappings.
	 */
	struct btree_info info;

	/* non-blocking version of the above */
	struct btree_info nb_info;

	/* just the top level, for deleting whole devices */
	struct btree_info tl_info;

	/* just the bottom level for creating new devices */
	struct btree_info bl_info;

	/* Describes the device details btree */
	struct btree_info details_info;

	struct rw_semaphore root_lock;
	uint32_t time;		/* FIXME: persist this */
	int have_inserted;
	struct block *sblock;
	block_t root;
	block_t details_root;
	struct list_head ms_devices;
};

struct ms_device {
	struct list_head list;
	struct multisnap_metadata *mmd;
	multisnap_dev_t id;

	int is_open;
	int changed;
	uint64_t dev_size;
	uint64_t mapped_blocks;
	uint32_t snapshotted_time;
};

/*----------------------------------------------------------------*/

static int
superblock_all_zeroes(struct block_manager *bm, int *result)
{
	int r, i;
	struct block *b;
	uint64_t *data;
	size_t block_size = bm_block_size(bm) / sizeof(uint64_t);

	r = bm_read_lock(bm, MULTISNAP_SUPERBLOCK_LOCATION, &b);
	if (r)
		return r;

	data = block_data(b);
	*result = 1;
	for (i = 0; i < block_size; i++) {
		if (data[i] != 0LL) {
			*result = 0;
			break;
		}
	}

	return bm_unlock(b);
}

static struct multisnap_metadata *
alloc_(struct block_manager *bm, block_t nr_blocks, int create)
{
	int r;
	struct space_map *sm, *data_sm;
	struct transaction_manager *tm;
	struct multisnap_metadata *mmd;
	struct block *sb;

	if (create) {
		r = tm_create_with_sm(bm, MULTISNAP_SUPERBLOCK_LOCATION, &tm, &sm, &sb);
		if (r < 0) {
			printk(KERN_ALERT "tm_create_with_sm failed");
			block_manager_destroy(bm);
			return NULL;
		}

		printk(KERN_ALERT "creating data space map with %u blocks",
		       (unsigned) nr_blocks);
		data_sm = sm_disk_create(tm, nr_blocks);
		if (!data_sm) {
			printk(KERN_ALERT "sm_disk_create");
			goto bad;
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
	} else {
		struct superblock *s = NULL;

		r = tm_open_with_sm(bm, MULTISNAP_SUPERBLOCK_LOCATION,
				    (size_t) &((struct superblock *) NULL)->metadata_space_map_root,
				    SPACE_MAP_ROOT_SIZE,
				    &tm, &sm, &sb);
		if (r < 0) {
			printk(KERN_ALERT "tm_open_with_sm failed");
			block_manager_destroy(bm);
			return NULL;
		}

		s = block_data(sb);
		if (__le64_to_cpu(s->magic) != MULTISNAP_SUPERBLOCK_MAGIC) {
			printk(KERN_ALERT "multisnap-metadata superblock is invalid (was %llu)",
			       __le64_to_cpu(s->magic));
			goto bad;
		}

		data_sm = sm_disk_open(tm, s->data_space_map_root, sizeof(s->data_space_map_root));
		if (!data_sm) {
			printk(KERN_ALERT "sm_disk_open failed");
			goto bad;
		}

		tm_unlock(tm, sb);
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
	mmd->nb_tm = tm_create_non_blocking_clone(tm);
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
	tm_destroy(tm);
	sm_destroy(sm);
	block_manager_destroy(bm);
	return NULL;
}

static int
multisnap_metadata_begin(struct multisnap_metadata *mmd)
{
	int r;
	struct superblock *s;

	BUG_ON(mmd->sblock);
	mmd->have_inserted = 0;
	r = bm_write_lock(mmd->bm, MULTISNAP_SUPERBLOCK_LOCATION, &mmd->sblock);
	if (r)
		return r;

	s = (struct superblock *) block_data(mmd->sblock);
	mmd->root = __le64_to_cpu(s->data_mapping_root);
	mmd->details_root = __le64_to_cpu(s->device_details_root);
	return 0;
}

struct multisnap_metadata *
multisnap_metadata_open(struct block_device *bdev,
			sector_t data_block_size,
			block_t data_dev_size)
{
	int r;
	struct superblock *sb;
	struct multisnap_metadata *mmd;
	sector_t bdev_size = i_size_read(bdev->bd_inode) >> SECTOR_SHIFT;
	struct block_manager *bm;
	int create;

	bm = block_manager_create(bdev,
				  MULTISNAP_METADATA_BLOCK_SIZE,
				  MULTISNAP_METADATA_CACHE_SIZE);
	if (!bm) {
		printk(KERN_ALERT "multisnap-metadata could not create block manager");
		return NULL;
	}

	r = superblock_all_zeroes(bm, &create);
	if (r) {
		block_manager_destroy(bm);
		return NULL;
	}

	if (create)
		printk(KERN_ALERT "superblock has been zeroed, creating new mmd");
	else
		printk(KERN_ALERT "superblock not zeroes, reopening mmd");

	mmd = alloc_(bm, data_dev_size, create);
	if (!mmd)
		return NULL;
	mmd->bdev = bdev;

	if (create) {
		if (!mmd->sblock) {
			r = multisnap_metadata_begin(mmd);
			if (r < 0)
				goto bad;
		}

		sb = (struct superblock *) block_data(mmd->sblock);
		sb->magic = __cpu_to_le64(MULTISNAP_SUPERBLOCK_MAGIC);
		sb->version = __cpu_to_le64(MULTISNAP_VERSION);
		sb->time = 0;
		sb->metadata_block_size = __cpu_to_le64(1 << SECTOR_TO_BLOCK_SHIFT);
		sb->metadata_nr_blocks = __cpu_to_le64(bdev_size >> SECTOR_TO_BLOCK_SHIFT);
		sb->data_block_size = __cpu_to_le64(data_block_size);

		r = btree_empty(&mmd->info, &mmd->root);
		if (r < 0)
			goto bad;

		r = btree_empty(&mmd->details_info, &mmd->details_root);
		if (r < 0) {
			printk(KERN_ALERT "couldn't create devices root");
			goto bad;
		}

		mmd->have_inserted = 1;
		r = multisnap_metadata_commit(mmd);
		if (r < 0)
			goto bad;
	} else {
		r = multisnap_metadata_begin(mmd);
		if (r < 0)
			goto bad;
	}

	return mmd;

bad:
	multisnap_metadata_close(mmd);
	return NULL;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_open);

int
multisnap_metadata_close(struct multisnap_metadata *mmd)
{
	unsigned open_devices = 0;
	struct ms_device *msd, *tmp;

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
		multisnap_metadata_commit(mmd);

	tm_destroy(mmd->tm);
	tm_destroy(mmd->nb_tm);
	block_manager_destroy(mmd->bm);
	sm_destroy(mmd->metadata_sm);
	kfree(mmd);

	return 0;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_close);

static int
open_device_(struct multisnap_metadata *mmd,
	     multisnap_dev_t dev,
	     int create,
	     struct ms_device **msd)
{
	int r, changed = 0;
	struct ms_device *msd2;
	uint64_t key = dev;
	struct device_details details;

	/* check the device isn't already open */
	list_for_each_entry (msd2, &mmd->ms_devices, list)
		if (msd2->id == dev) {
			*msd = msd2;
			return 0;
		}

	/* check the device exists */
	r = btree_lookup_equal(&mmd->details_info, mmd->details_root, &key, &details);
	if (r) {
		if (r == -ENODATA && create) {
			changed = 1;
			details.dev_size = 0;
			details.mapped_blocks = 0;
			details.snapshotted_time = __cpu_to_le64(mmd->time);

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

static int
multisnap_metadata_create_thin_(struct multisnap_metadata *mmd,
				multisnap_dev_t dev,
				block_t dev_size)
{
	int r;
	block_t dev_root;
	uint64_t key = dev;
	__le64 value;
	struct ms_device *msd;

	r = btree_lookup_equal(&mmd->details_info, mmd->details_root, &key, &value);
	if (!r)
		return -EEXIST;

	/* create an empty btree for the mappings */
	r = btree_empty(&mmd->bl_info, &dev_root);
	if (r)
		return r;

	/* insert it into the main mapping tree */
	value = __cpu_to_le64(dev_root);
	r = btree_insert(&mmd->tl_info, mmd->root, &key, &value, &mmd->root);
	if (r) {
		btree_del(&mmd->bl_info, dev_root);
		return r;
	}

	r = open_device_(mmd, dev, 1, &msd);
	if (r) {
		btree_remove(&mmd->tl_info, mmd->root, &key, &mmd->root);
		btree_del(&mmd->bl_info, dev_root);
		return r;
	}
	msd->dev_size = dev_size;

	return r;
}

int multisnap_metadata_create_thin(struct multisnap_metadata *mmd,
				   multisnap_dev_t dev,
				   block_t dev_size)
{
	int r;
	down_write(&mmd->root_lock);
	r = multisnap_metadata_create_thin_(mmd, dev, dev_size);
	up_write(&mmd->root_lock);
	return r;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_create_thin);

static int
snapshot_details_(struct multisnap_metadata *mmd,
		  struct ms_device *snap,
		  multisnap_dev_t origin,
		  uint32_t t)
{
	int r;
	struct ms_device *msd;

	r = open_device_(mmd, origin, 0, &msd);
	if (r)
		return r;

	msd->changed = 1;
	msd->snapshotted_time = t;

	snap->dev_size = msd->dev_size;
	snap->mapped_blocks = msd->mapped_blocks;
	snap->snapshotted_time = t;

	return 0;
}

static int
multisnap_metadata_create_snap_(struct multisnap_metadata *mmd,
				multisnap_dev_t dev,
				multisnap_dev_t origin)
{
	int r;
	block_t origin_root, snap_root;
	uint64_t key = origin;
	struct ms_device *msd;
	__le64 value;

	/* find the mapping tree for the origin */
	r = btree_lookup_equal(&mmd->tl_info, mmd->root, &key, &value);
	if (r)
		return r;
	origin_root = __le64_to_cpu(value);

	/* clone the origin */
	r = btree_clone(&mmd->bl_info, origin_root, &snap_root);
	if (r)
		return r;

	/* insert into the main mapping tree */
	value = __cpu_to_le64(snap_root);
	key = dev;
	r = btree_insert(&mmd->tl_info, mmd->root, &key, &value, &mmd->root);
	if (r) {
		btree_del(&mmd->bl_info, snap_root);
		return r;
	}

	mmd->time++;

	r = open_device_(mmd, dev, 1, &msd);
	if (r) {
		btree_remove(&mmd->tl_info, mmd->root, &key, &mmd->root);
		btree_remove(&mmd->details_info, mmd->details_root, &key, &mmd->details_root);
	}

	r = snapshot_details_(mmd, msd, origin, mmd->time);
	if (r) {
		btree_remove(&mmd->tl_info, mmd->root, &key, &mmd->root);
		btree_remove(&mmd->details_info, mmd->details_root, &key, &mmd->details_root);
	}

	return r;
}

int multisnap_metadata_create_snap(struct multisnap_metadata *mmd,
				   multisnap_dev_t dev,
				   multisnap_dev_t origin)
{
	int r;
	down_write(&mmd->root_lock);
	r = multisnap_metadata_create_snap_(mmd, dev, origin);
	up_write(&mmd->root_lock);
	return r;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_create_snap);

static int
multisnap_metadata_delete_(struct multisnap_metadata *mmd,
			   multisnap_dev_t dev)
{
	uint64_t key = dev;
	return btree_remove(&mmd->tl_info, mmd->root, &key, &mmd->root);
}

int
multisnap_metadata_delete(struct multisnap_metadata *mmd,
			  multisnap_dev_t dev)
{
	int r;
	down_write(&mmd->root_lock);
	r = multisnap_metadata_delete_(mmd, dev);
	up_write(&mmd->root_lock);
	return r;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_delete);

int
multisnap_metadata_open_device(struct multisnap_metadata *mmd,
			       multisnap_dev_t dev,
			       struct ms_device **msd)
{
	int r;
	down_write(&mmd->root_lock);
	r = open_device_(mmd, dev, 0, msd);
	if (!r) {
		if ((*msd)->is_open)
			r = -EBUSY;
		else
			(*msd)->is_open = 1;
	}
	up_write(&mmd->root_lock);
	return r;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_open_device);

int
multisnap_metadata_close_device(struct ms_device *msd)
{
	down_write(&msd->mmd->root_lock);
	msd->is_open = 0;
	up_write(&msd->mmd->root_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_close_device);

multisnap_dev_t multisnap_device_dev(struct ms_device *msd)
{
	return msd->id;
}


static uint64_t pack_block_time(block_t b, uint32_t t)
{
	return ((b << 24) | t);
}

static void unpack_block_time(uint64_t v, block_t *b, uint32_t *t)
{
	*b = v >> 24;
	*t = v & ((1 << 24) - 1);
}

static int
snapshotted_since_(struct ms_device *msd,
		      uint32_t time)
{
	return msd->snapshotted_time > time;
}

int
multisnap_metadata_lookup(struct ms_device *msd,
			  block_t block,
			  int can_block,
			  struct multisnap_lookup_result *result)
{
	int r;
	uint64_t keys[2], block_time = 0;
	__le64 value;
	struct multisnap_metadata *mmd = msd->mmd;

	keys[0] = msd->id;
	keys[1] = block;

	if (can_block) {
		down_read(&mmd->root_lock);
		r = btree_lookup_equal(&mmd->info, mmd->root, keys, &value);
		if (!r)
			block_time = __le64_to_cpu(value);
		up_read(&mmd->root_lock);

	} else if (down_read_trylock(&mmd->root_lock)) {
		r = btree_lookup_equal(&mmd->nb_info, mmd->root, keys, &value);
		if (!r)
			block_time = __le64_to_cpu(value);
		up_read(&mmd->root_lock);

	} else
		return -EWOULDBLOCK;

	if (!r) {
		block_t exception_block;
		uint32_t exception_time;
		unpack_block_time(block_time, &exception_block, &exception_time);
		result->block = exception_block;
		result->shared = snapshotted_since_(msd, exception_time);
	}

	return r;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_lookup);

int multisnap_metadata_insert(struct ms_device *msd,
			      block_t block,
			      block_t data_block)
{
	/* FIXME: remove @data_block from the allocated tracking data structure */
	block_t keys[2];
	__le64 value;
	struct multisnap_metadata *mmd = msd->mmd;

	keys[0] = msd->id;
	keys[1] = block;

	mmd->have_inserted = 1;
	value = __cpu_to_le64(pack_block_time(data_block, mmd->time));
	return btree_insert(&mmd->info, mmd->root, keys, &value, &mmd->root);
}
EXPORT_SYMBOL_GPL(multisnap_metadata_insert);

int
multisnap_metadata_alloc_data_block(struct ms_device *msd,
				    block_t *result)
{
	int r;
	struct multisnap_metadata *mmd = msd->mmd;

	/*
	 * FIXME: we need to persist allocations that haven't yet been
	 * inserted.
	 */
	down_write(&mmd->root_lock);
	r = sm_new_block(msd->mmd->data_sm, result);
	up_write(&mmd->root_lock);

	return r;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_alloc_data_block);

int
multisnap_metadata_free_data_block(struct ms_device *msd,
				   block_t result)
{
	int r;
	struct multisnap_metadata *mmd = msd->mmd;

	down_write(&mmd->root_lock);
	r = sm_dec_block(msd->mmd->data_sm, result);
	up_write(&mmd->root_lock);

	return r;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_free_data_block);

static int
write_changed_details_(struct multisnap_metadata *mmd)
{
	int r;
	struct ms_device *msd, *tmp;

	list_for_each_entry_safe (msd, tmp, &mmd->ms_devices, list) {
		if (msd->changed) {
			struct device_details dd;
			uint64_t key = msd->id;

			dd.dev_size = __cpu_to_le64(msd->dev_size);
			dd.mapped_blocks = __cpu_to_le64(msd->mapped_blocks);
			dd.snapshotted_time = __cpu_to_le32(msd->snapshotted_time);

			r = btree_insert(&mmd->details_info, mmd->details_root,
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

int multisnap_metadata_commit(struct multisnap_metadata *mmd)
{
	int r;
	size_t len;

	down_write(&mmd->root_lock);
	r = write_changed_details_(mmd);
	if (r < 0) {
		up_write(&mmd->root_lock);
		return r;
	}

	r = tm_pre_commit(mmd->tm);
	if (r < 0) {
		up_write(&mmd->root_lock);
		return r;
	}

	r = sm_root_size(mmd->metadata_sm, &len);
	if (r < 0) {
		up_write(&mmd->root_lock);
		return r;
	}

	{
		struct superblock *sb = block_data(mmd->sblock);
		sb->time = __cpu_to_le64(mmd->time);
		sb->data_mapping_root = __cpu_to_le64(mmd->root);
		sb->device_details_root = __cpu_to_le64(mmd->details_root);
		r = sm_copy_root(mmd->metadata_sm, &sb->metadata_space_map_root, len);
		if (r < 0) {
			up_write(&mmd->root_lock);
			return r;
		}

		r = sm_copy_root(mmd->data_sm, &sb->data_space_map_root, len);
		if (r < 0) {
			up_write(&mmd->root_lock);
			return r;
		}
	}

	r = tm_commit(mmd->tm, mmd->sblock);

	/* open the next transaction */
	mmd->sblock = NULL;

	/* FIXME: the semantics of failure are confusing here, did the commit fail, or the begin? */
	r = multisnap_metadata_begin(mmd);
	up_write(&mmd->root_lock);

	return r;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_commit);

int
multisnap_metadata_get_unprovisioned_blocks(struct multisnap_metadata *mmd, block_t *result)
{
	int r;

	down_read(&mmd->root_lock);
	/* FIXME: this is the total number of blocks, not the free count.
	 * We need to extend the space map abstraction to provide this.
	 */
	r = sm_get_nr_blocks(mmd->data_sm, result);
	up_read(&mmd->root_lock);

	return r;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_get_unprovisioned_blocks);

int
multisnap_metadata_get_data_block_size(struct multisnap_metadata *mmd,
				       sector_t *result)
{
	struct superblock *sb;

	down_read(&mmd->root_lock);
	sb = (struct superblock *) block_data(mmd->sblock);
	*result = __le64_to_cpu(sb->data_block_size);
	up_read(&mmd->root_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_get_data_block_size);

int
multisnap_metadata_get_data_dev_size(struct ms_device *msd,
				     block_t *result)
{
	struct multisnap_metadata *mmd = msd->mmd;
	down_read(&mmd->root_lock);
	*result = msd->dev_size;
	up_read(&mmd->root_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_get_data_dev_size);

int
multisnap_metadata_get_mapped_count(struct ms_device *msd, block_t *result)
{
	struct multisnap_metadata *mmd = msd->mmd;
	down_read(&mmd->root_lock);
	*result = msd->mapped_blocks;
	up_read(&mmd->root_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_get_mapped_count);

int
multisnap_metadata_resize_data_dev(struct ms_device *msd, block_t new_size)
{
	struct multisnap_metadata *mmd = msd->mmd;
	down_write(&mmd->root_lock);
	msd->dev_size = new_size;
	msd->changed = 1;
	up_write(&mmd->root_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_resize_data_dev);

/*----------------------------------------------------------------*/


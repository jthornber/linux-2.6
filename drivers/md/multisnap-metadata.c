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

/* FIXME: what's this file got to do with dm ? */
#define	DAEMON "dm-multisnap-provd"

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
	atomic_t ref_count;
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

	struct workqueue_struct *wq;	/* Work queue. */
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

/* A little global cache of multisnap metadata devs */
struct multisnap_metadata;

/* FIXME: add a spin lock round the table */
#define MMD_TABLE_SIZE 1024
static struct hlist_head mmd_table_[MMD_TABLE_SIZE];

static void
mmd_table_init(void)
{
	unsigned i;
	for (i = 0; i < MMD_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(mmd_table_ + i);
}

static unsigned
hash_bdev(struct block_device *bdev)
{
	/* FIXME: finish */
	/* bdev -> dev_t -> unsigned */
	return 0;
}

static void
mmd_table_insert(struct multisnap_metadata *mmd)
{
	unsigned bucket = hash_bdev(mmd->bdev);
	hlist_add_head(&mmd->hash, mmd_table_ + bucket);
}

static void
mmd_table_remove(struct multisnap_metadata *mmd)
{
	hlist_del(&mmd->hash);
}

static struct multisnap_metadata *
mmd_table_lookup(struct block_device *bdev)
{
	unsigned bucket = hash_bdev(bdev);
	struct multisnap_metadata *mmd;
	struct hlist_node *n;

	hlist_for_each_entry (mmd, n, mmd_table_ + bucket, hash)
		if (mmd->bdev == bdev)
			return mmd;

	return NULL;
}

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

	/* Create singlethreaded workqueue that will service all devices
	 * that use this metadata.
	 */
	mmd->wq = alloc_ordered_workqueue(DAEMON, WQ_MEM_RECLAIM);
	if (!mmd->wq) {
		printk(KERN_ALERT "couldn't create workqueue for metadata object");
		goto bad;
	}

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

static struct multisnap_metadata *
multisnap_metadata_open_(struct block_device *bdev,
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

struct multisnap_metadata *
multisnap_metadata_open(struct block_device *bdev,
			sector_t data_block_size,
			block_t data_dev_size)
{
	struct multisnap_metadata *mmd;

	mmd = mmd_table_lookup(bdev);
	if (mmd)
		atomic_inc(&mmd->ref_count);
	else {
		mmd = multisnap_metadata_open_(bdev, data_block_size, data_dev_size);
		if (!mmd) {
			printk(KERN_ALERT "couldn't open new multisnap metadata device");
			return NULL;
		}

		atomic_set(&mmd->ref_count, 1);
		mmd_table_insert(mmd);
	}

	BUG_ON(!mmd->sblock);
	return mmd;
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

	if (atomic_dec_and_test(&mmd->ref_count)) {
		printk(KERN_ALERT "destroying mmd");
		mmd_table_remove(mmd);

		if (mmd->sblock)
			multisnap_metadata_commit(mmd);

		tm_destroy(mmd->tm);
		tm_destroy(mmd->nb_tm);
		block_manager_destroy(mmd->bm);
		sm_destroy(mmd->metadata_sm);

		if (mmd->wq)
			destroy_workqueue(mmd->wq);

		kfree(mmd);
	}

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
	(*msd)->dev_size = 0;	list_add(&(*msd)->list, &mmd->ms_devices);

	return 0;
}

static int
multisnap_metadata_create_thin_(struct multisnap_metadata *mmd,
				multisnap_dev_t dev)
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
	if (r)
		btree_del(&mmd->bl_info, dev_root);

	r = open_device_(mmd, dev, 1, &msd);
	if (r) {
		// FIXME: finish
	}

	return r;
}

int multisnap_metadata_create_thin(struct multisnap_metadata *mmd,
				   multisnap_dev_t dev,
				   block_t dev_size)
{
	int r;
	down_write(&mmd->root_lock);
	r = multisnap_metadata_create_thin_(mmd, dev);
	up_write(&mmd->root_lock);
	return r;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_create_thin);

static int
set_snapshotted_time_(struct multisnap_metadata *mmd,
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
#if 0
		btree_remove(&mmd->tl_info, mmd->root, key, &mmd->root);
		btree_remove(&mmd->details_info, mmd->details_root, &key, &mmd->details_root);
#endif
	}

	r = set_snapshotted_time_(mmd, origin, mmd->time);
	if (r) {
#if 0
		btree_remove(&mmd->tl_info, mmd->root, key, &mmd->root);
		btree_remove(&mmd->details_info, mmd->details_root, &key, &mmd->details_root);
#endif
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
#if 0
	uint64_t key = dev;
	return btree_remove(&mmd->tl_info, mmd->root, &key, &mmd->root);
#else
	return 0;
#endif
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
insert_(struct ms_device *msd,
	block_t block,
	block_t *pool_block)
{
	int r;
	block_t keys[2];
	__le64 value;
	struct multisnap_metadata *mmd = msd->mmd;

	keys[0] = msd->id;
	keys[1] = block;

	mmd->have_inserted = 1;
	r = sm_new_block(mmd->data_sm, pool_block);
	if (r)
		return r;

	/* FIXME: check the thinp version of this, I think it omits the endian conversion */
	value = __cpu_to_le64(pack_block_time(*pool_block, mmd->time));
	r = btree_insert(&mmd->info, mmd->root, keys, &value, &mmd->root);
	if (r) {
		sm_dec_block(mmd->data_sm, *pool_block);
		return r;
	}

	return 0;
}

static int
snapshotted_since_(struct ms_device *msd,
		      uint32_t time)
{
	return msd->snapshotted_time > time;
}

int
multisnap_metadata_map(struct ms_device *msd,
		       block_t block,
		       int io_direction,
		       int can_block,
		       block_t *result)
{
	int r;
	uint64_t keys[2], block_time = 0;
	__le64 value, value2;
	struct multisnap_metadata *mmd = msd->mmd;
	block_t exception_block;
	uint32_t exception_time;

	keys[0] = msd->id;
	keys[1] = block;

restart:
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

	if (r && r != -ENODATA)
		return r;

	unpack_block_time(block_time, &exception_block, &exception_time);
	*result = exception_block;

	if (io_direction == WRITE && (r == -ENODATA || snapshotted_since_(msd, exception_time))) {
		if (!can_block)
			return -EWOULDBLOCK;

		down_write(&mmd->root_lock);

#if 0
		/*
		 * FIXME: really we should upgrade the read lock to a write
		 * lock here to avoid the duplicate lookup.
		 */
		r = btree_lookup_equal(&mmd->info, mmd->root, keys, &value2);
		if (!r && value2 != value) {
			/* something's changed, start again */
			up_write(&mmd->root_lock);
			printk(KERN_ALERT "hit by race!");
			goto restart;
		}
#endif

		r = insert_(msd, block, result);
		up_write(&mmd->root_lock);
	}

	return r;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_map);

struct workqueue_struct *
multisnap_metadata_get_workqueue(struct ms_device *msd)
{
	return msd->mmd->wq;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_get_workqueue);

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



























/*----------------------------------------------------------------*/
#if 0
/*
 * Utilities for managing the device details list.  The |root_lock| needs
 * to be held around all of these functions.
 */
static struct device_detail *find_dd(struct multisnap_metadata *tpm,
				     multisnap_dev_t dev)
{
	struct device_detail *dd;

	list_for_each_entry (dd, &tpm->device_details, list)
		if (dd->dev == dev)
			return dd;

	return NULL;
}

static int insert_dd(struct multisnap_metadata *tpm,
		     multisnap_dev_t dev,
		     uint32_t provisioned_count)
{
	/* FIXME: use a mempool?  since this is on the io path, alternative is to
	   allocate space for the details when the individual device targets are
	   created (where we may block). */
	struct device_detail *dd = kmalloc(sizeof(*dd), GFP_KERNEL);
	if (!dd)
		return -ENOMEM;

	dd->dev = dev;
	dd->changed = 1;
	dd->provisioned_count = provisioned_count;
	list_add(&dd->list, &tpm->device_details);
	return 0;
}

static int add_dd(struct multisnap_metadata *tpm,
		  multisnap_dev_t dev)
{
	int r;
	uint64_t key = dev;
	__le64 count;
	struct device_detail *dd = find_dd(tpm, dev);
	if (dd)
		/* already present */
		return 0;

	printk(KERN_ALERT "using devices_root = %u", (unsigned) tpm->devices_root);
	r = btree_lookup_equal(&tpm->devices_info, tpm->devices_root, &key, &count);
	printk(KERN_ALERT "btree_lookup completed");
	switch (r) {
	case 0:
		return insert_dd(tpm, dev, __le64_to_cpu(count));

	case -ENODATA:
		return insert_dd(tpm, dev, 0);

	default:
		return r;
	}
}

static void del_dd(struct multisnap_metadata *tpm,
		   multisnap_dev_t dev)
{
	struct device_detail *dd = find_dd(tpm, dev);
	if (dd) {
		list_del(&dd->list);
		kfree(dd);
	}
}

static int get_provisioned_count(struct multisnap_metadata *tpm,
				 multisnap_dev_t dev,
				 uint64_t *result)
{
	struct device_detail *dd = find_dd(tpm, dev);
	if (dd) {
		*result = dd->provisioned_count;
		return 0;
	}

	return -ENOMEM;
}

static int inc_provisioned_count(struct multisnap_metadata *tpm,
				 multisnap_dev_t dev)
{
	struct device_detail *dd = find_dd(tpm, dev);
	if (dd) {
		dd->changed = 1;
		dd->provisioned_count++;
		return 0;
	}

	return -ENOMEM;
}

int
multisnap_metadata_get_data_block_size(struct multisnap_metadata *tpm,
				       multisnap_dev_t dev,
				       sector_t *result)
{
	down_read(&tpm->root_lock);
	{
		struct superblock *sb = (struct superblock *) block_data(tpm->sblock);
		*result = __le64_to_cpu(sb->data_block_size);
	}
	up_read(&tpm->root_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_get_data_block_size);

int
multisnap_metadata_get_provisioned_blocks(struct multisnap_metadata *tpm,
					  multisnap_dev_t dev,
					  block_t *result)
{
	int r;

	down_read(&tpm->root_lock);
	r = get_provisioned_count(tpm, dev, result);
	up_read(&tpm->root_lock);
	return r;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_get_provisioned_blocks);

int multisnap_metadata_get_unprovisioned_blocks(struct multisnap_metadata *tpm, block_t *result)
{
	int r;
	struct superblock *s;
	block_t nr_free;

	down_read(&tpm->root_lock);
	BUG_ON(!tpm->sblock);
	s = (struct superblock *) block_data(tpm->sblock);
	r = sm_get_free(tpm->data_sm, &nr_free);
	if (!r)
		*result = nr_free;
	up_read(&tpm->root_lock);
	return r;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_get_unprovisioned_blocks);

int
multisnap_metadata_get_data_dev_size(struct multisnap_metadata *tpm,
				     multisnap_dev_t dev,
				     block_t *result)
{
	struct device_detail *dd;

	down_read(&tpm->root_lock);
	dd = find_dd(tpm, dev);
	if (dd)
		*result = dd->dev_size;
	up_read(&tpm->root_lock);
	return dd ? 0 : -ENOMEM;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_get_data_dev_size);

int
multisnap_metadata_resize_data_dev(struct multisnap_metadata *tpm,
				   multisnap_dev_t dev,
				   block_t new_size)
{
#if 0
	block_t b;
	down_write(&tpm->root_lock);
	{
		struct superblock *sb = (struct superblock *) block_data(tpm->sblock);

		b = __le64_to_cpu(sb->first_free_block);
		if (b > new_size) {
			/* this would truncate mapped blocks */
			up_write(&tpm->root_lock);
			return -ENOSPC;
		}

		sb->data_nr_blocks = __cpu_to_le64(new_size);
	}
	up_write(&tpm->root_lock);
#endif
	return 0;
}
EXPORT_SYMBOL_GPL(multisnap_metadata_resize_data_dev);
#endif


static int multisnap_metadata_init(void)
{
	mmd_table_init();
	return 0;
}

static void multisnap_metadata_exit(void)
{
}

module_init(multisnap_metadata_init);
module_exit(multisnap_metadata_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joe Thornber");
MODULE_DESCRIPTION("Metadata manager for thin provisioning dm target");

/*----------------------------------------------------------------*/

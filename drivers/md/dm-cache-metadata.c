/*
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#include "dm-cache-metadata.h"

#include "persistent-data/dm-btree.h"
#include "persistent-data/dm-space-map.h"
#include "persistent-data/dm-space-map-disk.h"
#include "persistent-data/dm-transaction-manager.h"

#include <linux/device-mapper.h>

/*----------------------------------------------------------------*/

//#define debug(x...) pr_alert(x)
#define debug(x...) ;

#define DM_MSG_PREFIX   "thin metadata"

#define CACHE_SUPERBLOCK_MAGIC 06142003
#define CACHE_SUPERBLOCK_LOCATION 0
#define CACHE_VERSION 1
#define CACHE_METADATA_CACHE_SIZE 64

/*
 *  3 for btree insert +
 *  2 for btree lookup used within space map
 */
#define CACHE_MAX_CONCURRENT_LOCKS 5

/* This should be plenty */
#define SPACE_MAP_ROOT_SIZE 128

struct cache_disk_superblock {
	__le32 csum;
	__le32 flags;
	__le64 blocknr;

	__u8 uuid[16];
	__le64 magic;
	__le32 version;

	__u8 metadata_space_map_root[SPACE_MAP_ROOT_SIZE];
	__le64 mapping_root;
	__le32 data_block_size;
	__le32 metadata_block_size;

	__le32 compat_flags;
	__le32 compat_ro_flags;
	__le32 incompat_flags;

} __packed;

struct dm_cache_metadata {
	struct block_device *bdev;
	struct dm_block_manager *bm;
	struct dm_space_map *metadata_sm;
	struct dm_transaction_manager *tm;

	struct dm_btree_info info;

	struct rw_semaphore root_lock;
	dm_block_t root;
	sector_t data_block_size;
	bool changed;
};

/*-------------------------------------------------------------------
 * superblock validator
 *-----------------------------------------------------------------*/

#define SUPERBLOCK_CSUM_XOR 9031977

static void sb_prepare_for_write(struct dm_block_validator *v,
				 struct dm_block *b,
				 size_t block_size)
{
	struct cache_disk_superblock *disk_super = dm_block_data(b);

	disk_super->blocknr = cpu_to_le64(dm_block_location(b));
	disk_super->csum = cpu_to_le32(dm_bm_checksum(&disk_super->flags,
						      block_size - sizeof(__le32),
						      SUPERBLOCK_CSUM_XOR));
}

static int sb_check(struct dm_block_validator *v,
		    struct dm_block *b,
		    size_t block_size)
{
	struct cache_disk_superblock *disk_super = dm_block_data(b);
	__le32 csum_le;

	if (dm_block_location(b) != le64_to_cpu(disk_super->blocknr)) {
		DMERR("sb_check failed: blocknr %llu: "
		      "wanted %llu", le64_to_cpu(disk_super->blocknr),
		      (unsigned long long)dm_block_location(b));
		return -ENOTBLK;
	}

	if (le64_to_cpu(disk_super->magic) != CACHE_SUPERBLOCK_MAGIC) {
		DMERR("sb_check failed: magic %llu: "
		      "wanted %llu", le64_to_cpu(disk_super->magic),
		      (unsigned long long)CACHE_SUPERBLOCK_MAGIC);
		return -EILSEQ;
	}

	csum_le = cpu_to_le32(dm_bm_checksum(&disk_super->flags,
					     block_size - sizeof(__le32),
					     SUPERBLOCK_CSUM_XOR));
	if (csum_le != disk_super->csum) {
		DMERR("sb_check failed: csum %u: wanted %u",
		      le32_to_cpu(csum_le), le32_to_cpu(disk_super->csum));
		return -EILSEQ;
	}

	return 0;
}

static struct dm_block_validator sb_validator = {
	.name = "superblock",
	.prepare_for_write = sb_prepare_for_write,
	.check = sb_check
};

/*----------------------------------------------------------------*/

static int superblock_lock_zero(struct dm_cache_metadata *cmd,
				struct dm_block **sblock)
{
	return dm_bm_write_lock_zero(cmd->bm, CACHE_SUPERBLOCK_LOCATION,
				     &sb_validator, sblock);
}

static int superblock_lock(struct dm_cache_metadata *cmd,
			   struct dm_block **sblock)
{
	return dm_bm_write_lock(cmd->bm, CACHE_SUPERBLOCK_LOCATION,
				&sb_validator, sblock);
}

static int __superblock_all_zeroes(struct dm_block_manager *bm, int *result)
{
	int r;
	unsigned i;
	struct dm_block *b;
	__le64 *data_le, zero = cpu_to_le64(0);
	unsigned block_size = dm_bm_block_size(bm) / sizeof(__le64);

	/*
	 * We can't use a validator here - it may be all zeroes.
	 */
	r = dm_bm_read_lock(bm, CACHE_SUPERBLOCK_LOCATION, NULL, &b);
	if (r)
		return r;

	data_le = dm_block_data(b);
	*result = 1;
	for (i = 0; i < block_size; i++) {
		if (data_le[i] != zero) {
			*result = 0;
			break;
		}
	}

	return dm_bm_unlock(b);
}

static void __setup_btree_details(struct dm_cache_metadata *cmd)
{
	cmd->info.tm = cmd->tm;
	cmd->info.levels = 1;
	cmd->info.value_type.context = NULL;
	cmd->info.value_type.size = sizeof(__le64);
	cmd->info.value_type.inc = NULL;
	cmd->info.value_type.dec = NULL;
	cmd->info.value_type.equal = NULL;
}

static int __write_initial_superblock(struct dm_cache_metadata *cmd)
{
	int r;
	struct dm_block *sblock;
	size_t metadata_len;
	struct cache_disk_superblock *disk_super;
	sector_t bdev_size = i_size_read(cmd->bdev->bd_inode) >> SECTOR_SHIFT;

	/* FIXME: see if we can lose the max sectors limit */
	if (bdev_size > CACHE_METADATA_MAX_SECTORS)
		bdev_size = CACHE_METADATA_MAX_SECTORS;

	r = dm_sm_root_size(cmd->metadata_sm, &metadata_len);
	if (r < 0)
		return r;

	r = dm_tm_pre_commit(cmd->tm);
	if (r < 0)
		return r;

	r = superblock_lock_zero(cmd, &sblock);
	if (r)
		return r;

	disk_super = dm_block_data(sblock);
	disk_super->flags = 0;
	memset(disk_super->uuid, 0, sizeof(disk_super->uuid));
	disk_super->magic = cpu_to_le64(CACHE_SUPERBLOCK_MAGIC);
	disk_super->version = cpu_to_le32(CACHE_VERSION);

	r = dm_sm_copy_root(cmd->metadata_sm, &disk_super->metadata_space_map_root,
			    metadata_len);
	if (r < 0)
		goto bad_locked;

	disk_super->mapping_root = cpu_to_le64(cmd->root);
	disk_super->metadata_block_size = cpu_to_le32(CACHE_METADATA_BLOCK_SIZE >> SECTOR_SHIFT);
	disk_super->data_block_size = cpu_to_le32(cmd->data_block_size);

	return dm_tm_commit(cmd->tm, sblock);

bad_locked:
	dm_bm_unlock(sblock);
	return r;
}

static int __format_metadata(struct dm_cache_metadata *cmd)
{
	int r;

	debug("formatting metadata dev");
	r = dm_tm_create_with_sm(cmd->bm, CACHE_SUPERBLOCK_LOCATION,
				 &cmd->tm, &cmd->metadata_sm);
	if (r < 0) {
		DMERR("tm_create_with_sm failed");
		return r;
	}

	__setup_btree_details(cmd);

	r = dm_btree_empty(&cmd->info, &cmd->root);
	if (r < 0)
		goto bad;

	r = __write_initial_superblock(cmd);
	if (r)
		goto bad;

	return 0;

bad:
	dm_tm_destroy(cmd->tm);
	dm_sm_destroy(cmd->metadata_sm);

	return r;
}

static int __check_incompat_features(struct cache_disk_superblock *disk_super,
				     struct dm_cache_metadata *cmd)
{
	uint32_t features;

	features = le32_to_cpu(disk_super->incompat_flags) & ~CACHE_FEATURE_INCOMPAT_SUPP;
	if (features) {
		DMERR("could not access metadata due to unsupported optional features (%lx).",
		      (unsigned long)features);
		return -EINVAL;
	}

	/*
	 * Check for read-only metadata to skip the following RDWR checks.
	 */
	if (get_disk_ro(cmd->bdev->bd_disk))
		return 0;

	features = le32_to_cpu(disk_super->compat_ro_flags) & ~CACHE_FEATURE_COMPAT_RO_SUPP;
	if (features) {
		DMERR("could not access metadata RDWR due to unsupported optional features (%lx).",
		      (unsigned long)features);
		return -EINVAL;
	}

	return 0;
}

static int __open_metadata(struct dm_cache_metadata *cmd)
{
	int r;
	struct dm_block *sblock;
	struct cache_disk_superblock *disk_super;

	r = dm_bm_read_lock(cmd->bm, CACHE_SUPERBLOCK_LOCATION,
			    &sb_validator, &sblock);
	if (r < 0) {
		DMERR("couldn't read superblock");
		return r;
	}

	disk_super = dm_block_data(sblock);

	r = __check_incompat_features(disk_super, cmd);
	if (r < 0)
		goto bad;

	r = dm_tm_open_with_sm(cmd->bm, CACHE_SUPERBLOCK_LOCATION,
			       disk_super->metadata_space_map_root,
			       sizeof(disk_super->metadata_space_map_root),
			       &cmd->tm, &cmd->metadata_sm);
	if (r < 0) {
		DMERR("tm_open_with_sm failed");
		goto bad;
	}

	__setup_btree_details(cmd);
	return dm_bm_unlock(sblock);

bad:
	dm_bm_unlock(sblock);
	return r;
}

static int __open_or_format_metadata(struct dm_cache_metadata *cmd, bool format_device)
{
	int r, unformatted;

	r = __superblock_all_zeroes(cmd->bm, &unformatted);
	if (r)
		return r;

	if (unformatted)
		return format_device ? __format_metadata(cmd) : -EPERM;

	return __open_metadata(cmd);
}

static int __create_persistent_data_objects(struct dm_cache_metadata *cmd, bool may_format_device)
{
	int r;
	cmd->bm = dm_block_manager_create(cmd->bdev, CACHE_METADATA_BLOCK_SIZE,
					  CACHE_METADATA_CACHE_SIZE,
					  CACHE_MAX_CONCURRENT_LOCKS);
	if (IS_ERR(cmd->bm)) {
		DMERR("could not create block manager");
		return PTR_ERR(cmd->bm);
	}

	r = __open_or_format_metadata(cmd, may_format_device);
	if (r)
		dm_block_manager_destroy(cmd->bm);

	return r;
}

static void __destroy_persistent_data_objects(struct dm_cache_metadata *cmd)
{
	dm_sm_destroy(cmd->metadata_sm);
	dm_tm_destroy(cmd->tm);
	dm_block_manager_destroy(cmd->bm);
}

static int __begin_transaction(struct dm_cache_metadata *cmd)
{
	int r;
	struct cache_disk_superblock *disk_super;
	struct dm_block *sblock;

	/*
	 * We re-read the superblock every time.  Shouldn't need to do this
	 * really.
	 */
	r = dm_bm_read_lock(cmd->bm, CACHE_SUPERBLOCK_LOCATION,
			    &sb_validator, &sblock);
	if (r)
		return r;

	disk_super = dm_block_data(sblock);
	cmd->root = le64_to_cpu(disk_super->mapping_root);
	cmd->data_block_size = le32_to_cpu(disk_super->data_block_size);
	cmd->changed = 0;

	dm_bm_unlock(sblock);
	return 0;
}

static int __commit_transaction(struct dm_cache_metadata *cmd)
{
	int r;
	size_t metadata_len;
	struct cache_disk_superblock *disk_super;
	struct dm_block *sblock;

	debug("__commit_transaction\n");
	/*
	 * We need to know if the thin_disk_superblock exceeds a 512-byte sector.
	 */
	BUILD_BUG_ON(sizeof(struct cache_disk_superblock) > 512);

	r = dm_tm_pre_commit(cmd->tm);
	if (r < 0)
		return r;

	r = dm_sm_root_size(cmd->metadata_sm, &metadata_len);
	if (r < 0)
		return r;

	r = superblock_lock(cmd, &sblock);
	if (r)
		return r;

	disk_super = dm_block_data(sblock);
	debug("root = %lu\n", (unsigned long) cmd->root);
	disk_super->mapping_root = cpu_to_le64(cmd->root);

	r = dm_sm_copy_root(cmd->metadata_sm, &disk_super->metadata_space_map_root,
			    metadata_len);
	if (r < 0) {
		dm_bm_unlock(sblock);
		return r;
	}

	return dm_tm_commit(cmd->tm, sblock);
}

/*----------------------------------------------------------------*/

struct dm_cache_metadata *dm_cache_metadata_open(struct block_device *bdev,
						 sector_t data_block_size,
						 bool may_format_device)
{
	int r;
	struct dm_cache_metadata *cmd;

	cmd = kmalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		DMERR("could not allocate metadata struct");
		return NULL;
	}

	init_rwsem(&cmd->root_lock);
	cmd->bdev = bdev;
	cmd->data_block_size = data_block_size;
	cmd->changed = 1;
	r = __create_persistent_data_objects(cmd, may_format_device);
	if (r) {
		kfree(cmd);
		return NULL;
	}

	r = __begin_transaction(cmd);
	if (r < 0) {
		dm_cache_metadata_close(cmd);
		return NULL;
	}

	return cmd;
}

void dm_cache_metadata_close(struct dm_cache_metadata *cmd)
{
	__commit_transaction(cmd);
	__destroy_persistent_data_objects(cmd);
	kfree(cmd);
}

static int __remove(struct dm_cache_metadata *cmd, dm_block_t oblock)
{
	int r;

	debug("__remove %lu\n", (unsigned long) oblock);
	r = dm_btree_remove(&cmd->info, cmd->root, &oblock, &cmd->root);
	if (r)
		return r;

	cmd->changed = 1;
	return 0;
}

int dm_cache_remove_mapping(struct dm_cache_metadata *cmd, dm_block_t oblock)
{
	int r;

	down_write(&cmd->root_lock);
	r = __remove(cmd, oblock);
	up_write(&cmd->root_lock);

	return r;
}

static int __insert(struct dm_cache_metadata *cmd,
		    dm_block_t oblock, dm_block_t cblock)
{
	int r;
	__le64 value = cpu_to_le64(cblock);
	__dm_bless_for_disk(&value);

	debug("__insert %lu -> %lu\n", (unsigned long) oblock, (unsigned long) cblock);
	r = dm_btree_insert(&cmd->info, cmd->root, &oblock, &value, &cmd->root);
	if (r)
		return r;

	cmd->changed = 1;
	return 0;
}

int dm_cache_insert_mapping(struct dm_cache_metadata *cmd, dm_block_t oblock, dm_block_t cblock)
{
	int r;

	down_write(&cmd->root_lock);
	r = __insert(cmd, oblock, cblock);
	up_write(&cmd->root_lock);

	return r;
}

struct thunk {
	load_mapping_fn fn;
	void *context;
};

static int __load_mapping(void *context, uint64_t *keys, void *leaf)
{
	__le64 value;
	dm_block_t oblock = keys[0], cblock;
	struct thunk *thunk = context;

	memcpy(&value, leaf, sizeof(value));
	cblock = le64_to_cpu(value);

	return thunk->fn(thunk->context, oblock, cblock);
}

static int __load_mappings(struct dm_cache_metadata *cmd,
			   load_mapping_fn fn,
			   void *context)
{
	struct thunk thunk;

	thunk.fn = fn;
	thunk.context = context;
	return dm_btree_walk(&cmd->info, cmd->root, __load_mapping, &thunk);
}

int dm_cache_load_mappings(struct dm_cache_metadata *cmd,
			   load_mapping_fn fn,
			   void *context)
{
	int r;

	debug("> dm_cache_load_mappings\n");
	down_read(&cmd->root_lock);
	r = __load_mappings(cmd, fn, context);
	up_read(&cmd->root_lock);
	debug("< dm_cache_load_mappings\n");

	return r;
}

int dm_cache_changed_this_transaction(struct dm_cache_metadata *cmd)
{
	int r;

	down_read(&cmd->root_lock);
	r = cmd->changed;
	up_read(&cmd->root_lock);

	return r;
}

int dm_cache_commit(struct dm_cache_metadata *cmd)
{
	int r;

	down_write(&cmd->root_lock);
	r = __commit_transaction(cmd);
	if (r)
		goto out;

	r = __begin_transaction(cmd);

out:
	up_write(&cmd->root_lock);
	return r;
}

/*----------------------------------------------------------------*/


/*
 * Copyright (C) 2011-2017 Red Hat UK.
 *
 * This file is released under the GPL.
 */

#include "dm-thin-base.h"
#include "dm-thin-metadata.h"
#include "dm-bio-prison-v2.h"
#include "dm.h"
#include "dm-utils.h"

#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/jiffies.h>
#include <linux/log2.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>
#include <linux/rbtree.h>

#define	DM_MSG_PREFIX	"thin"

DECLARE_DM_KCOPYD_THROTTLE_WITH_MODULE_PARM(snapshot_copy_throttle,
		"A percentage of time allocated for copy on write");

/*
 * Tunable constants
 */
#define ENDIO_HOOK_POOL_SIZE 1024
#define NO_SPACE_TIMEOUT_SECS 60

/*
 * The block size of the device holding pool data must be
 * between 64KB and 1GB.
 */
#define DATA_DEV_BLOCK_SIZE_MIN_SECTORS (64 * 1024 >> SECTOR_SHIFT)
#define DATA_DEV_BLOCK_SIZE_MAX_SECTORS (1024 * 1024 * 1024 >> SECTOR_SHIFT)

/*
 * Device id is restricted to 24 bits.
 */
#define MAX_DEV_ID ((1 << 24) - 1)

/*----------------------------------------------------------------*/

/*
 * A global list of pools that uses a struct mapped_device as a key.
 */
static struct dm_thin_pool_table {
	struct mutex mutex;
	struct list_head pools;
} dm_thin_pool_table;

static void pool_table_init(void)
{
	mutex_init(&dm_thin_pool_table.mutex);
	INIT_LIST_HEAD(&dm_thin_pool_table.pools);
}

static void __pool_table_insert(struct pool *pool)
{
	BUG_ON(!mutex_is_locked(&dm_thin_pool_table.mutex));
	list_add(&pool->list, &dm_thin_pool_table.pools);
}

static void __pool_table_remove(struct pool *pool)
{
	BUG_ON(!mutex_is_locked(&dm_thin_pool_table.mutex));
	list_del(&pool->list);
}

static struct pool *__pool_table_lookup(struct mapped_device *md)
{
	struct pool *pool = NULL, *tmp;

	BUG_ON(!mutex_is_locked(&dm_thin_pool_table.mutex));

	list_for_each_entry(tmp, &dm_thin_pool_table.pools, list) {
		if (tmp->pool_md == md) {
			pool = tmp;
			break;
		}
	}

	return pool;
}

static struct pool *__pool_table_lookup_metadata_dev(struct block_device *md_dev)
{
	struct pool *pool = NULL, *tmp;

	BUG_ON(!mutex_is_locked(&dm_thin_pool_table.mutex));

	list_for_each_entry(tmp, &dm_thin_pool_table.pools, list) {
		if (tmp->md_dev == md_dev) {
			pool = tmp;
			break;
		}
	}

	return pool;
}

/*----------------------------------------------------------------
 * Pool creation
 *--------------------------------------------------------------*/
/* Initialize pool features. */
static void pool_features_init(struct pool_features *pf)
{
	pf->mode = PM_WRITE;
	pf->zero_new_blocks = true;
	pf->discard_enabled = true;
	pf->discard_passdown = true;
	pf->error_if_no_space = false;
}

static void __pool_destroy(struct pool *pool)
{
	__pool_table_remove(pool);

	if (dm_pool_metadata_close(pool->pmd) < 0)
		DMWARN("%s: dm_pool_metadata_close() failed.", __func__);

	dm_bio_prison_destroy_v2(pool->prison);
	dm_kcopyd_client_destroy(pool->copier);

	if (pool->wq)
		destroy_workqueue(pool->wq);

	mempool_destroy(pool->program_pool);
	kfree(pool);
}

/*
 * We're holding onto IO to allow userland time to react.  After the
 * timeout either the pool will have been resized (and thus back in
 * PM_WRITE mode), or we degrade to PM_OUT_OF_DATA_SPACE w/ error_if_no_space.
 */
static void do_no_space_timeout(struct work_struct *ws)
{
	struct pool *pool = container_of(to_delayed_work(ws), struct pool,
					 no_space_timeout);

	if (get_pool_mode(pool) == PM_OUT_OF_DATA_SPACE && !pool->pf.error_if_no_space) {
		pool->pf.error_if_no_space = true;
		notify_of_pool_mode_change_to_oods(pool);
		//error_retry_list_with_code(pool, -ENOSPC);
	}
}

static struct kmem_cache *_program_cache;

static struct pool *pool_create(struct mapped_device *pool_md,
				struct block_device *metadata_dev,
				unsigned long block_size,
				int read_only, char **error)
{
	int r;
	void *err_p;
	struct pool *pool;
	struct dm_pool_metadata *pmd;
	bool format_device = read_only ? false : true;

	pmd = dm_pool_metadata_open(metadata_dev, block_size, format_device);
	if (IS_ERR(pmd)) {
		*error = "Error creating metadata object";
		return (struct pool *)pmd;
	}

	pool = kmalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool) {
		*error = "Error allocating memory for pool";
		err_p = ERR_PTR(-ENOMEM);
		goto bad_pool;
	}

	pool->pmd = pmd;
	pool->sectors_per_block = block_size;
	if (block_size & (block_size - 1))
		pool->sectors_per_block_shift = -1;
	else
		pool->sectors_per_block_shift = __ffs(block_size);
	pool->low_water_blocks = 0;
	pool_features_init(&pool->pf);

#if 0
	pool->prison = dm_bio_prison_create_v2();
	if (!pool->prison) {
		*error = "Error creating pool's bio prison";
		err_p = ERR_PTR(-ENOMEM);
		goto bad_prison;
	}
#endif

	pool->copier = dm_kcopyd_client_create(&dm_kcopyd_throttle);
	if (IS_ERR(pool->copier)) {
		r = PTR_ERR(pool->copier);
		*error = "Error creating pool's kcopyd client";
		err_p = ERR_PTR(r);
		goto bad_kcopyd_client;
	}

	/*
	 * Create singlethreaded workqueue that will service all devices
	 * that use this metadata.
	 */
	pool->wq = alloc_ordered_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!pool->wq) {
		*error = "Error creating pool's workqueue";
		err_p = ERR_PTR(-ENOMEM);
		goto bad_wq;
	}

	//throttle_init(&pool->throttle);
	INIT_DELAYED_WORK(&pool->no_space_timeout, do_no_space_timeout);
	spin_lock_init(&pool->lock);
	INIT_LIST_HEAD(&pool->active_thins);
	pool->low_water_triggered = false;
	pool->suspended = true;
	pool->out_of_data_space = false;

	pool->program_pool = mempool_create_slab_pool(1024, _program_cache);
	if (!pool->program_pool) {
		*error = "Error creating pool's mapping mempool";
		err_p = ERR_PTR(-ENOMEM);
		goto bad_program_pool;
	}

	pool->ref_count = 1;
	pool->last_commit_jiffies = jiffies;
	pool->pool_md = pool_md;
	pool->md_dev = metadata_dev;
	__pool_table_insert(pool);

	return pool;

	// FIXME: rewrite
	mempool_destroy(pool->program_pool);
bad_program_pool:
	destroy_workqueue(pool->wq);
bad_wq:
	dm_kcopyd_client_destroy(pool->copier);
bad_kcopyd_client:
	dm_bio_prison_destroy_v2(pool->prison);
	kfree(pool);
bad_pool:
	if (dm_pool_metadata_close(pmd))
		DMWARN("%s: dm_pool_metadata_close() failed.", __func__);

	return err_p;
}

static void __pool_inc(struct pool *pool)
{
	BUG_ON(!mutex_is_locked(&dm_thin_pool_table.mutex));
	pool->ref_count++;
}

static void __pool_dec(struct pool *pool)
{
	BUG_ON(!mutex_is_locked(&dm_thin_pool_table.mutex));
	BUG_ON(!pool->ref_count);
	if (!--pool->ref_count)
		__pool_destroy(pool);
}

static struct pool *__pool_find(struct mapped_device *pool_md,
				struct block_device *metadata_dev,
				unsigned long block_size, int read_only,
				char **error, int *created)
{
	struct pool *pool = __pool_table_lookup_metadata_dev(metadata_dev);

	if (pool) {
		if (pool->pool_md != pool_md) {
			*error = "metadata device already in use by a pool";
			return ERR_PTR(-EBUSY);
		}
		__pool_inc(pool);

	} else {
		pool = __pool_table_lookup(pool_md);
		if (pool) {
			if (pool->md_dev != metadata_dev) {
				*error = "different pool cannot replace a pool";
				return ERR_PTR(-EINVAL);
			}
			__pool_inc(pool);

		} else {
			pool = pool_create(pool_md, metadata_dev, block_size, read_only, error);
			*created = 1;
		}
	}

	return pool;
}

/*----------------------------------------------------------------
 * Binding of control targets to a pool object
 *--------------------------------------------------------------*/
static bool data_dev_supports_discard(struct pool_c *pt)
{
	struct request_queue *q = bdev_get_queue(pt->data_dev->bdev);

	return q && blk_queue_discard(q);
}

static bool is_factor(sector_t block_size, uint32_t n)
{
	return !sector_div(block_size, n);
}

/*
 * If discard_passdown was enabled verify that the data device
 * supports discards.  Disable discard_passdown if not.
 */
static void disable_passdown_if_not_supported(struct pool_c *pt)
{
	struct pool *pool = pt->pool;
	struct block_device *data_bdev = pt->data_dev->bdev;
	struct queue_limits *data_limits = &bdev_get_queue(data_bdev)->limits;
	const char *reason = NULL;
	char buf[BDEVNAME_SIZE];

	if (!pt->adjusted_pf.discard_passdown)
		return;

	if (!data_dev_supports_discard(pt))
		reason = "discard unsupported";

	else if (data_limits->max_discard_sectors < pool->sectors_per_block)
		reason = "max discard sectors smaller than a block";

	if (reason) {
		DMWARN("Data device (%s) %s: Disabling discard passdown.", bdevname(data_bdev, buf), reason);
		pt->adjusted_pf.discard_passdown = false;
	}
}

static int bind_control_target(struct pool *pool, struct dm_target *ti)
{
	struct pool_c *pt = ti->private;

	/*
	 * We want to make sure that a pool in PM_FAIL mode is never upgraded.
	 */
	enum pool_mode old_mode = get_pool_mode(pool);
	enum pool_mode new_mode = pt->adjusted_pf.mode;

	/*
	 * Don't change the pool's mode until set_pool_mode() below.
	 * Otherwise the pool's process_* function pointers may
	 * not match the desired pool mode.
	 */
	pt->adjusted_pf.mode = old_mode;

	pool->ti = ti;
	pool->pf = pt->adjusted_pf;
	pool->low_water_blocks = pt->low_water_blocks;

	set_pool_mode(pool, new_mode);

	return 0;
}

static void unbind_control_target(struct pool *pool, struct dm_target *ti)
{
	if (pool->ti == ti)
		pool->ti = NULL;
}

/*----------------------------------------------------------------
 * Pool target methods
 *--------------------------------------------------------------*/
static void pool_dtr(struct dm_target *ti)
{
	struct pool_c *pt = ti->private;

	mutex_lock(&dm_thin_pool_table.mutex);

	unbind_control_target(pt->pool, ti);
	__pool_dec(pt->pool);
	dm_put_device(ti, pt->metadata_dev);
	dm_put_device(ti, pt->data_dev);
	kfree(pt);

	mutex_unlock(&dm_thin_pool_table.mutex);
}

static int parse_pool_features(struct dm_arg_set *as, struct pool_features *pf,
			       struct dm_target *ti)
{
	int r;
	unsigned argc;
	const char *arg_name;

	static struct dm_arg _args[] = {
		{0, 4, "Invalid number of pool feature arguments"},
	};

	/*
	 * No feature arguments supplied.
	 */
	if (!as->argc)
		return 0;

	r = dm_read_arg_group(_args, as, &argc, &ti->error);
	if (r)
		return -EINVAL;

	while (argc && !r) {
		arg_name = dm_shift_arg(as);
		argc--;

		if (!strcasecmp(arg_name, "skip_block_zeroing"))
			pf->zero_new_blocks = false;

		else if (!strcasecmp(arg_name, "ignore_discard"))
			pf->discard_enabled = false;

		else if (!strcasecmp(arg_name, "no_discard_passdown"))
			pf->discard_passdown = false;

		else if (!strcasecmp(arg_name, "read_only"))
			pf->mode = PM_READ_ONLY;

		else if (!strcasecmp(arg_name, "error_if_no_space"))
			pf->error_if_no_space = true;

		else {
			ti->error = "Unrecognised pool feature requested";
			r = -EINVAL;
			break;
		}
	}

	return r;
}

static void metadata_low_callback(void *context)
{
	struct pool *pool = context;

	DMWARN("%s: reached low water mark for metadata device: sending event.",
	       dm_device_name(pool->pool_md));

	dm_table_event(pool->ti->table);
}

static sector_t get_dev_size(struct block_device *bdev)
{
	return i_size_read(bdev->bd_inode) >> SECTOR_SHIFT;
}

static void warn_if_metadata_device_too_big(struct block_device *bdev)
{
	sector_t metadata_dev_size = get_dev_size(bdev);
	char buffer[BDEVNAME_SIZE];

	if (metadata_dev_size > THIN_METADATA_MAX_SECTORS_WARNING)
		DMWARN("Metadata device %s is larger than %u sectors: excess space will not be used.",
		       bdevname(bdev, buffer), THIN_METADATA_MAX_SECTORS);
}

static sector_t get_metadata_dev_size(struct block_device *bdev)
{
	sector_t metadata_dev_size = get_dev_size(bdev);

	if (metadata_dev_size > THIN_METADATA_MAX_SECTORS)
		metadata_dev_size = THIN_METADATA_MAX_SECTORS;

	return metadata_dev_size;
}

static dm_block_t get_metadata_dev_size_in_blocks(struct block_device *bdev)
{
	sector_t metadata_dev_size = get_metadata_dev_size(bdev);

	sector_div(metadata_dev_size, THIN_METADATA_BLOCK_SIZE);

	return metadata_dev_size;
}

/*
 * When a metadata threshold is crossed a dm event is triggered, and
 * userland should respond by growing the metadata device.  We could let
 * userland set the threshold, like we do with the data threshold, but I'm
 * not sure they know enough to do this well.
 */
static dm_block_t calc_metadata_threshold(struct pool_c *pt)
{
	/*
	 * 4M is ample for all ops with the possible exception of thin
	 * device deletion which is harmless if it fails (just retry the
	 * delete after you've grown the device).
	 */
	dm_block_t quarter = get_metadata_dev_size_in_blocks(pt->metadata_dev->bdev) / 4;
	return min((dm_block_t)1024ULL /* 4M */, quarter);
}

static int pool_is_congested(struct dm_target_callbacks *cb, int bdi_bits)
{
	struct pool_c *pt = container_of(cb, struct pool_c, callbacks);
	struct request_queue *q;

	if (get_pool_mode(pt->pool) == PM_OUT_OF_DATA_SPACE)
		return 1;

	q = bdev_get_queue(pt->data_dev->bdev);
	return bdi_congested(&q->backing_dev_info, bdi_bits);
}

/*
 * thin-pool <metadata dev> <data dev>
 *	     <data block size (sectors)>
 *	     <low water mark (blocks)>
 *	     [<#feature args> [<arg>]*]
 *
 * Optional feature arguments are:
 *	     skip_block_zeroing: skips the zeroing of newly-provisioned blocks.
 *	     ignore_discard: disable discard
 *	     no_discard_passdown: don't pass discards down to the data device
 *	     read_only: Don't allow any changes to be made to the pool metadata.
 *	     error_if_no_space: error IOs, instead of queueing, if no space.
 */
static int pool_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r, pool_created = 0;
	struct pool_c *pt;
	struct pool *pool;
	struct pool_features pf;
	struct dm_arg_set as;
	struct dm_dev *data_dev;
	unsigned long block_size;
	dm_block_t low_water_blocks;
	struct dm_dev *metadata_dev;
	fmode_t metadata_mode;

	/*
	 * FIXME Remove validation from scope of lock.
	 */
	mutex_lock(&dm_thin_pool_table.mutex);

	if (argc < 4) {
		ti->error = "Invalid argument count";
		r = -EINVAL;
		goto out_unlock;
	}

	as.argc = argc;
	as.argv = argv;

	/*
	 * Set default pool features.
	 */
	pool_features_init(&pf);

	dm_consume_args(&as, 4);
	r = parse_pool_features(&as, &pf, ti);
	if (r)
		goto out_unlock;

	metadata_mode = FMODE_READ | ((pf.mode == PM_READ_ONLY) ? 0 : FMODE_WRITE);
	r = dm_get_device(ti, argv[0], metadata_mode, &metadata_dev);
	if (r) {
		ti->error = "Error opening metadata block device";
		goto out_unlock;
	}
	warn_if_metadata_device_too_big(metadata_dev->bdev);

	r = dm_get_device(ti, argv[1], FMODE_READ | FMODE_WRITE, &data_dev);
	if (r) {
		ti->error = "Error getting data device";
		goto out_metadata;
	}

	if (kstrtoul(argv[2], 10, &block_size) || !block_size ||
	    block_size < DATA_DEV_BLOCK_SIZE_MIN_SECTORS ||
	    block_size > DATA_DEV_BLOCK_SIZE_MAX_SECTORS ||
	    block_size & (DATA_DEV_BLOCK_SIZE_MIN_SECTORS - 1)) {
		ti->error = "Invalid block size";
		r = -EINVAL;
		goto out;
	}

	if (kstrtoull(argv[3], 10, (unsigned long long *)&low_water_blocks)) {
		ti->error = "Invalid low water mark";
		r = -EINVAL;
		goto out;
	}

	pt = kzalloc(sizeof(*pt), GFP_KERNEL);
	if (!pt) {
		r = -ENOMEM;
		goto out;
	}

	pool = __pool_find(dm_table_get_md(ti->table), metadata_dev->bdev,
			   block_size, pf.mode == PM_READ_ONLY, &ti->error, &pool_created);
	if (IS_ERR(pool)) {
		r = PTR_ERR(pool);
		goto out_free_pt;
	}

	/*
	 * 'pool_created' reflects whether this is the first table load.
	 * Top level discard support is not allowed to be changed after
	 * initial load.  This would require a pool reload to trigger thin
	 * device changes.
	 */
	if (!pool_created && pf.discard_enabled != pool->pf.discard_enabled) {
		ti->error = "Discard support cannot be disabled once enabled";
		r = -EINVAL;
		goto out_flags_changed;
	}

	pt->pool = pool;
	pt->ti = ti;
	pt->metadata_dev = metadata_dev;
	pt->data_dev = data_dev;
	pt->low_water_blocks = low_water_blocks;
	pt->adjusted_pf = pt->requested_pf = pf;
	ti->num_flush_bios = 1;

	/*
	 * Only need to enable discards if the pool should pass
	 * them down to the data device.  The thin device's discard
	 * processing will cause mappings to be removed from the btree.
	 */
	ti->discard_zeroes_data_unsupported = true;
	if (pf.discard_enabled && pf.discard_passdown) {
		ti->num_discard_bios = 1;

		/*
		 * Setting 'discards_supported' circumvents the normal
		 * stacking of discard limits (this keeps the pool and
		 * thin devices' discard limits consistent).
		 */
		ti->discards_supported = true;
	}
	ti->private = pt;

	r = dm_pool_register_metadata_threshold(pt->pool->pmd,
						calc_metadata_threshold(pt),
						metadata_low_callback,
						pool);
	if (r)
		goto out_flags_changed;

	pt->callbacks.congested_fn = pool_is_congested;
	dm_table_add_target_callbacks(ti->table, &pt->callbacks);

	mutex_unlock(&dm_thin_pool_table.mutex);

	return 0;

out_flags_changed:
	__pool_dec(pool);
out_free_pt:
	kfree(pt);
out:
	dm_put_device(ti, data_dev);
out_metadata:
	dm_put_device(ti, metadata_dev);
out_unlock:
	mutex_unlock(&dm_thin_pool_table.mutex);

	return r;
}

static int pool_map(struct dm_target *ti, struct bio *bio)
{
	int r;
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	unsigned long flags;

	/*
	 * As this is a singleton target, ti->begin is always zero.
	 */
	spin_lock_irqsave(&pool->lock, flags);
	bio->bi_bdev = pt->data_dev->bdev;
	r = DM_MAPIO_REMAPPED;
	spin_unlock_irqrestore(&pool->lock, flags);

	return r;
}

static int maybe_resize_data_dev(struct dm_target *ti, bool *need_commit)
{
	int r;
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	sector_t data_size = ti->len;
	dm_block_t sb_data_size;

	*need_commit = false;

	(void) sector_div(data_size, pool->sectors_per_block);

	r = dm_pool_get_data_dev_size(pool->pmd, &sb_data_size);
	if (r) {
		DMERR("%s: failed to retrieve data device size",
		      dm_device_name(pool->pool_md));
		return r;
	}

	if (data_size < sb_data_size) {
		DMERR("%s: pool target (%llu blocks) too small: expected %llu",
		      dm_device_name(pool->pool_md),
		      (unsigned long long)data_size, sb_data_size);
		return -EINVAL;

	} else if (data_size > sb_data_size) {
		if (dm_pool_metadata_needs_check(pool->pmd)) {
			DMERR("%s: unable to grow the data device until repaired.",
			      dm_device_name(pool->pool_md));
			return 0;
		}

		if (sb_data_size)
			DMINFO("%s: growing the data device from %llu to %llu blocks",
			       dm_device_name(pool->pool_md),
			       sb_data_size, (unsigned long long)data_size);
		r = dm_pool_resize_data_dev(pool->pmd, data_size);
		if (r) {
			metadata_operation_failed(pool, "dm_pool_resize_data_dev", r);
			return r;
		}

		*need_commit = true;
	}

	return 0;
}

static int maybe_resize_metadata_dev(struct dm_target *ti, bool *need_commit)
{
	int r;
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	dm_block_t metadata_dev_size, sb_metadata_dev_size;

	*need_commit = false;

	metadata_dev_size = get_metadata_dev_size_in_blocks(pool->md_dev);

	r = dm_pool_get_metadata_dev_size(pool->pmd, &sb_metadata_dev_size);
	if (r) {
		DMERR("%s: failed to retrieve metadata device size",
		      dm_device_name(pool->pool_md));
		return r;
	}

	if (metadata_dev_size < sb_metadata_dev_size) {
		DMERR("%s: metadata device (%llu blocks) too small: expected %llu",
		      dm_device_name(pool->pool_md),
		      metadata_dev_size, sb_metadata_dev_size);
		return -EINVAL;

	} else if (metadata_dev_size > sb_metadata_dev_size) {
		if (dm_pool_metadata_needs_check(pool->pmd)) {
			DMERR("%s: unable to grow the metadata device until repaired.",
			      dm_device_name(pool->pool_md));
			return 0;
		}

		warn_if_metadata_device_too_big(pool->md_dev);
		DMINFO("%s: growing the metadata device from %llu to %llu blocks",
		       dm_device_name(pool->pool_md),
		       sb_metadata_dev_size, metadata_dev_size);
		r = dm_pool_resize_metadata_dev(pool->pmd, metadata_dev_size);
		if (r) {
			metadata_operation_failed(pool, "dm_pool_resize_metadata_dev", r);
			return r;
		}

		*need_commit = true;
	}

	return 0;
}

/*
 * Retrieves the number of blocks of the data device from
 * the superblock and compares it to the actual device size,
 * thus resizing the data device in case it has grown.
 *
 * This both copes with opening preallocated data devices in the ctr
 * being followed by a resume
 * -and-
 * calling the resume method individually after userspace has
 * grown the data device in reaction to a table event.
 */
static int pool_preresume(struct dm_target *ti)
{
	int r;
	bool need_commit1, need_commit2;
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;

	/*
	 * Take control of the pool object.
	 */
	r = bind_control_target(pool, ti);
	if (r)
		return r;

	r = maybe_resize_data_dev(ti, &need_commit1);
	if (r)
		return r;

	r = maybe_resize_metadata_dev(ti, &need_commit2);
	if (r)
		return r;

	if (need_commit1 || need_commit2)
		(void) commit(pool);

	return 0;
}

static void pool_suspend_active_thins(struct pool *pool)
{
	struct thin_c *tc;

	/* Suspend all active thin devices */
	tc = get_first_thin(pool);
	while (tc) {
		dm_internal_suspend_noflush(tc->thin_md);
		tc = get_next_thin(pool, tc);
	}
}

static void pool_resume_active_thins(struct pool *pool)
{
	struct thin_c *tc;

	/* Resume all active thin devices */
	tc = get_first_thin(pool);
	while (tc) {
		dm_internal_resume(tc->thin_md);
		tc = get_next_thin(pool, tc);
	}
}

static void pool_resume(struct dm_target *ti)
{
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	unsigned long flags;

	/*
	 * Must requeue active_thins' bios and then resume
	 * active_thins _before_ clearing 'suspend' flag.
	 */
	//requeue_bios(pool);
	pool_resume_active_thins(pool);

	spin_lock_irqsave(&pool->lock, flags);
	pool->low_water_triggered = false;
	pool->suspended = false;
	spin_unlock_irqrestore(&pool->lock, flags);

	do_waker(&pool->waker.work);
}

static void pool_presuspend(struct dm_target *ti)
{
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	unsigned long flags;

	spin_lock_irqsave(&pool->lock, flags);
	pool->suspended = true;
	spin_unlock_irqrestore(&pool->lock, flags);

	pool_suspend_active_thins(pool);
}

static void pool_presuspend_undo(struct dm_target *ti)
{
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	unsigned long flags;

	pool_resume_active_thins(pool);

	spin_lock_irqsave(&pool->lock, flags);
	pool->suspended = false;
	spin_unlock_irqrestore(&pool->lock, flags);
}

static void pool_postsuspend(struct dm_target *ti)
{
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;

	cancel_delayed_work_sync(&pool->waker);
	cancel_delayed_work_sync(&pool->no_space_timeout);
	flush_workqueue(pool->wq);
	(void) commit(pool);
}

static int check_arg_count(unsigned argc, unsigned args_required)
{
	if (argc != args_required) {
		DMWARN("Message received with %u arguments instead of %u.",
		       argc, args_required);
		return -EINVAL;
	}

	return 0;
}

static int read_dev_id(char *arg, dm_thin_id *dev_id, int warning)
{
	if (!kstrtoull(arg, 10, (unsigned long long *)dev_id) &&
	    *dev_id <= MAX_DEV_ID)
		return 0;

	if (warning)
		DMWARN("Message received with invalid device id: %s", arg);

	return -EINVAL;
}

static int process_create_thin_mesg(unsigned argc, char **argv, struct pool *pool)
{
	dm_thin_id dev_id;
	int r;

	r = check_arg_count(argc, 2);
	if (r)
		return r;

	r = read_dev_id(argv[1], &dev_id, 1);
	if (r)
		return r;

	r = dm_pool_create_thin(pool->pmd, dev_id);
	if (r) {
		DMWARN("Creation of new thinly-provisioned device with id %s failed.",
		       argv[1]);
		return r;
	}

	return 0;
}

static int process_create_snap_mesg(unsigned argc, char **argv, struct pool *pool)
{
	dm_thin_id dev_id;
	dm_thin_id origin_dev_id;
	int r;

	r = check_arg_count(argc, 3);
	if (r)
		return r;

	r = read_dev_id(argv[1], &dev_id, 1);
	if (r)
		return r;

	r = read_dev_id(argv[2], &origin_dev_id, 1);
	if (r)
		return r;

	r = dm_pool_create_snap(pool->pmd, dev_id, origin_dev_id);
	if (r) {
		DMWARN("Creation of new snapshot %s of device %s failed.",
		       argv[1], argv[2]);
		return r;
	}

	return 0;
}

static int process_delete_mesg(unsigned argc, char **argv, struct pool *pool)
{
	dm_thin_id dev_id;
	int r;

	r = check_arg_count(argc, 2);
	if (r)
		return r;

	r = read_dev_id(argv[1], &dev_id, 1);
	if (r)
		return r;

	r = dm_pool_delete_thin_device(pool->pmd, dev_id);
	if (r)
		DMWARN("Deletion of thin device %s failed.", argv[1]);

	return r;
}

static int process_set_transaction_id_mesg(unsigned argc, char **argv, struct pool *pool)
{
	dm_thin_id old_id, new_id;
	int r;

	r = check_arg_count(argc, 3);
	if (r)
		return r;

	if (kstrtoull(argv[1], 10, (unsigned long long *)&old_id)) {
		DMWARN("set_transaction_id message: Unrecognised id %s.", argv[1]);
		return -EINVAL;
	}

	if (kstrtoull(argv[2], 10, (unsigned long long *)&new_id)) {
		DMWARN("set_transaction_id message: Unrecognised new id %s.", argv[2]);
		return -EINVAL;
	}

	r = dm_pool_set_metadata_transaction_id(pool->pmd, old_id, new_id);
	if (r) {
		DMWARN("Failed to change transaction id from %s to %s.",
		       argv[1], argv[2]);
		return r;
	}

	return 0;
}

static int process_reserve_metadata_snap_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	(void) commit(pool);

	r = dm_pool_reserve_metadata_snap(pool->pmd);
	if (r)
		DMWARN("reserve_metadata_snap message failed.");

	return r;
}

static int process_release_metadata_snap_mesg(unsigned argc, char **argv, struct pool *pool)
{
	int r;

	r = check_arg_count(argc, 1);
	if (r)
		return r;

	r = dm_pool_release_metadata_snap(pool->pmd);
	if (r)
		DMWARN("release_metadata_snap message failed.");

	return r;
}

/*
 * Messages supported:
 *   create_thin	<dev_id>
 *   create_snap	<dev_id> <origin_id>
 *   delete		<dev_id>
 *   set_transaction_id <current_trans_id> <new_trans_id>
 *   reserve_metadata_snap
 *   release_metadata_snap
 */
static int pool_message(struct dm_target *ti, unsigned argc, char **argv)
{
	int r = -EINVAL;
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;

	if (get_pool_mode(pool) >= PM_READ_ONLY) {
		DMERR("%s: unable to service pool target messages in READ_ONLY or FAIL mode",
		      dm_device_name(pool->pool_md));
		return -EOPNOTSUPP;
	}

	if (!strcasecmp(argv[0], "create_thin"))
		r = process_create_thin_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "create_snap"))
		r = process_create_snap_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "delete"))
		r = process_delete_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "set_transaction_id"))
		r = process_set_transaction_id_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "reserve_metadata_snap"))
		r = process_reserve_metadata_snap_mesg(argc, argv, pool);

	else if (!strcasecmp(argv[0], "release_metadata_snap"))
		r = process_release_metadata_snap_mesg(argc, argv, pool);

	else
		DMWARN("Unrecognised thin pool target message received: %s", argv[0]);

	if (!r)
		(void) commit(pool);

	return r;
}

static void emit_flags(struct pool_features *pf, char *result,
		       unsigned sz, unsigned maxlen)
{
	unsigned count = !pf->zero_new_blocks + !pf->discard_enabled +
		!pf->discard_passdown + (pf->mode == PM_READ_ONLY) +
		pf->error_if_no_space;
	DMEMIT("%u ", count);

	if (!pf->zero_new_blocks)
		DMEMIT("skip_block_zeroing ");

	if (!pf->discard_enabled)
		DMEMIT("ignore_discard ");

	if (!pf->discard_passdown)
		DMEMIT("no_discard_passdown ");

	if (pf->mode == PM_READ_ONLY)
		DMEMIT("read_only ");

	if (pf->error_if_no_space)
		DMEMIT("error_if_no_space ");
}

/*
 * Status line is:
 *    <transaction id> <used metadata sectors>/<total metadata sectors>
 *    <used data sectors>/<total data sectors> <held metadata root>
 *    <pool mode> <discard config> <no space config> <needs_check>
 */
static void pool_status(struct dm_target *ti, status_type_t type,
			unsigned status_flags, char *result, unsigned maxlen)
{
	int r;
	unsigned sz = 0;
	uint64_t transaction_id;
	dm_block_t nr_free_blocks_data;
	dm_block_t nr_free_blocks_metadata;
	dm_block_t nr_blocks_data;
	dm_block_t nr_blocks_metadata;
	dm_block_t held_root;
	char buf[BDEVNAME_SIZE];
	char buf2[BDEVNAME_SIZE];
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;

	switch (type) {
	case STATUSTYPE_INFO:
		if (get_pool_mode(pool) == PM_FAIL) {
			DMEMIT("Fail");
			break;
		}

		/* Commit to ensure statistics aren't out-of-date */
		if (!(status_flags & DM_STATUS_NOFLUSH_FLAG) && !dm_suspended(ti))
			(void) commit(pool);

		r = dm_pool_get_metadata_transaction_id(pool->pmd, &transaction_id);
		if (r) {
			DMERR("%s: dm_pool_get_metadata_transaction_id returned %d",
			      dm_device_name(pool->pool_md), r);
			goto err;
		}

		r = dm_pool_get_free_metadata_block_count(pool->pmd, &nr_free_blocks_metadata);
		if (r) {
			DMERR("%s: dm_pool_get_free_metadata_block_count returned %d",
			      dm_device_name(pool->pool_md), r);
			goto err;
		}

		r = dm_pool_get_metadata_dev_size(pool->pmd, &nr_blocks_metadata);
		if (r) {
			DMERR("%s: dm_pool_get_metadata_dev_size returned %d",
			      dm_device_name(pool->pool_md), r);
			goto err;
		}

		r = dm_pool_get_free_block_count(pool->pmd, &nr_free_blocks_data);
		if (r) {
			DMERR("%s: dm_pool_get_free_block_count returned %d",
			      dm_device_name(pool->pool_md), r);
			goto err;
		}

		r = dm_pool_get_data_dev_size(pool->pmd, &nr_blocks_data);
		if (r) {
			DMERR("%s: dm_pool_get_data_dev_size returned %d",
			      dm_device_name(pool->pool_md), r);
			goto err;
		}

		r = dm_pool_get_metadata_snap(pool->pmd, &held_root);
		if (r) {
			DMERR("%s: dm_pool_get_metadata_snap returned %d",
			      dm_device_name(pool->pool_md), r);
			goto err;
		}

		DMEMIT("%llu %llu/%llu %llu/%llu ",
		       (unsigned long long)transaction_id,
		       (unsigned long long)(nr_blocks_metadata - nr_free_blocks_metadata),
		       (unsigned long long)nr_blocks_metadata,
		       (unsigned long long)(nr_blocks_data - nr_free_blocks_data),
		       (unsigned long long)nr_blocks_data);

		if (held_root)
			DMEMIT("%llu ", held_root);
		else
			DMEMIT("- ");

		if (pool->pf.mode == PM_OUT_OF_DATA_SPACE)
			DMEMIT("out_of_data_space ");
		else if (pool->pf.mode == PM_READ_ONLY)
			DMEMIT("ro ");
		else
			DMEMIT("rw ");

		if (!pool->pf.discard_enabled)
			DMEMIT("ignore_discard ");
		else if (pool->pf.discard_passdown)
			DMEMIT("discard_passdown ");
		else
			DMEMIT("no_discard_passdown ");

		if (pool->pf.error_if_no_space)
			DMEMIT("error_if_no_space ");
		else
			DMEMIT("queue_if_no_space ");

		if (dm_pool_metadata_needs_check(pool->pmd))
			DMEMIT("needs_check ");
		else
			DMEMIT("- ");

		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%s %s %lu %llu ",
		       format_dev_t(buf, pt->metadata_dev->bdev->bd_dev),
		       format_dev_t(buf2, pt->data_dev->bdev->bd_dev),
		       (unsigned long)pool->sectors_per_block,
		       (unsigned long long)pt->low_water_blocks);
		emit_flags(&pt->requested_pf, result, sz, maxlen);
		break;
	}
	return;

err:
	DMEMIT("Error");
}

static int pool_iterate_devices(struct dm_target *ti,
				iterate_devices_callout_fn fn, void *data)
{
	struct pool_c *pt = ti->private;

	return fn(ti, pt->data_dev, 0, ti->len, data);
}

static void pool_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct pool_c *pt = ti->private;
	struct pool *pool = pt->pool;
	sector_t io_opt_sectors = limits->io_opt >> SECTOR_SHIFT;

	/*
	 * If max_sectors is smaller than pool->sectors_per_block adjust it
	 * to the highest possible power-of-2 factor of pool->sectors_per_block.
	 * This is especially beneficial when the pool's data device is a RAID
	 * device that has a full stripe width that matches pool->sectors_per_block
	 * -- because even though partial RAID stripe-sized IOs will be issued to a
	 *    single RAID stripe; when aggregated they will end on a full RAID stripe
	 *    boundary.. which avoids additional partial RAID stripe writes cascading
	 */
	if (limits->max_sectors < pool->sectors_per_block) {
		while (!is_factor(pool->sectors_per_block, limits->max_sectors)) {
			if ((limits->max_sectors & (limits->max_sectors - 1)) == 0)
				limits->max_sectors--;
			limits->max_sectors = rounddown_pow_of_two(limits->max_sectors);
		}
	}

	/*
	 * If the system-determined stacked limits are compatible with the
	 * pool's blocksize (io_opt is a factor) do not override them.
	 */
	if (io_opt_sectors < pool->sectors_per_block ||
	    !is_factor(io_opt_sectors, pool->sectors_per_block)) {
		if (is_factor(pool->sectors_per_block, limits->max_sectors))
			blk_limits_io_min(limits, limits->max_sectors << SECTOR_SHIFT);
		else
			blk_limits_io_min(limits, pool->sectors_per_block << SECTOR_SHIFT);
		blk_limits_io_opt(limits, pool->sectors_per_block << SECTOR_SHIFT);
	}

	/*
	 * pt->adjusted_pf is a staging area for the actual features to use.
	 * They get transferred to the live pool in bind_control_target()
	 * called from pool_preresume().
	 */
	if (!pt->adjusted_pf.discard_enabled) {
		/*
		 * Must explicitly disallow stacking discard limits otherwise the
		 * block layer will stack them if pool's data device has support.
		 * QUEUE_FLAG_DISCARD wouldn't be set but there is no way for the
		 * user to see that, so make sure to set all discard limits to 0.
		 */
		limits->discard_granularity = 0;
		return;
	}

	disable_passdown_if_not_supported(pt);

	/*
	 * The pool uses the same discard limits as the underlying data
	 * device.  DM core has already set this up.
	 */
}

static struct target_type pool_target = {
	.name = "thin-pool",
	.features = DM_TARGET_SINGLETON | DM_TARGET_ALWAYS_WRITEABLE |
		    DM_TARGET_IMMUTABLE,
	.version = {1, 19, 0},
	.module = THIS_MODULE,
	.ctr = pool_ctr,
	.dtr = pool_dtr,
	.map = pool_map,
	.presuspend = pool_presuspend,
	.presuspend_undo = pool_presuspend_undo,
	.postsuspend = pool_postsuspend,
	.preresume = pool_preresume,
	.resume = pool_resume,
	.message = pool_message,
	.status = pool_status,
	.iterate_devices = pool_iterate_devices,
	.io_hints = pool_io_hints,
};

/*----------------------------------------------------------------
 * Thin target methods
 *--------------------------------------------------------------*/

static void thin_dtr(struct dm_target *ti)
{
	struct thin_c *tc = ti->private;
	unsigned long flags;

	spin_lock_irqsave(&tc->pool->lock, flags);
	list_del_rcu(&tc->list);
	spin_unlock_irqrestore(&tc->pool->lock, flags);
	synchronize_rcu();

	thin_put(tc);
	wait_for_completion(&tc->can_destroy);

	mutex_lock(&dm_thin_pool_table.mutex);

	__pool_dec(tc->pool);
	dm_pool_close_thin_device(tc->td);
	dm_put_device(ti, tc->pool_dev);
	if (tc->origin_dev)
		dm_put_device(ti, tc->origin_dev);
	kfree(tc);

	mutex_unlock(&dm_thin_pool_table.mutex);
}

/*
 * Thin target parameters:
 *
 * <pool_dev> <dev_id> [origin_dev]
 *
 * pool_dev: the path to the pool (eg, /dev/mapper/my_pool)
 * dev_id: the internal device identifier
 * origin_dev: a device external to the pool that should act as the origin
 *
 * If the pool device has discards disabled, they get disabled for the thin
 * device as well.
 */
static int thin_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	struct thin_c *tc;
	struct dm_dev *pool_dev, *origin_dev;
	struct mapped_device *pool_md;
	unsigned long flags;

	mutex_lock(&dm_thin_pool_table.mutex);

	if (argc != 2 && argc != 3) {
		ti->error = "Invalid argument count";
		r = -EINVAL;
		goto out_unlock;
	}

	tc = ti->private = kzalloc(sizeof(*tc), GFP_KERNEL);
	if (!tc) {
		ti->error = "Out of memory";
		r = -ENOMEM;
		goto out_unlock;
	}
	tc->thin_md = dm_table_get_md(ti->table);
	spin_lock_init(&tc->lock);
	INIT_LIST_HEAD(&tc->deferred_cells);
	bio_list_init(&tc->deferred_bio_list);
	bio_list_init(&tc->retry_on_resume_list);
	tc->sort_bio_list = RB_ROOT;

	if (argc == 3) {
		r = dm_get_device(ti, argv[2], FMODE_READ, &origin_dev);
		if (r) {
			ti->error = "Error opening origin device";
			goto bad_origin_dev;
		}
		tc->origin_dev = origin_dev;
	}

	r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &pool_dev);
	if (r) {
		ti->error = "Error opening pool device";
		goto bad_pool_dev;
	}
	tc->pool_dev = pool_dev;

	if (read_dev_id(argv[1], (unsigned long long *)&tc->dev_id, 0)) {
		ti->error = "Invalid device id";
		r = -EINVAL;
		goto bad_common;
	}

	pool_md = dm_get_md(tc->pool_dev->bdev->bd_dev);
	if (!pool_md) {
		ti->error = "Couldn't get pool mapped device";
		r = -EINVAL;
		goto bad_common;
	}

	tc->pool = __pool_table_lookup(pool_md);
	if (!tc->pool) {
		ti->error = "Couldn't find pool object";
		r = -EINVAL;
		goto bad_pool_lookup;
	}
	__pool_inc(tc->pool);

	if (get_pool_mode(tc->pool) == PM_FAIL) {
		ti->error = "Couldn't open thin device, Pool is in fail mode";
		r = -EINVAL;
		goto bad_pool;
	}

	r = dm_pool_open_thin_device(tc->pool->pmd, tc->dev_id, &tc->td);
	if (r) {
		ti->error = "Couldn't open thin internal device";
		goto bad_pool;
	}

	r = dm_set_target_max_io_len(ti, tc->pool->sectors_per_block);
	if (r)
		goto bad;

	ti->num_flush_bios = 1;
	ti->flush_supported = true;
	ti->per_io_data_size = sizeof(struct dm_thin_endio_hook);

	/* In case the pool supports discards, pass them on. */
	ti->discard_zeroes_data_unsupported = true;
	if (tc->pool->pf.discard_enabled) {
		ti->discards_supported = true;
		ti->num_discard_bios = 1;
		ti->split_discard_bios = false;
	}

	mutex_unlock(&dm_thin_pool_table.mutex);

	spin_lock_irqsave(&tc->pool->lock, flags);
	if (tc->pool->suspended) {
		spin_unlock_irqrestore(&tc->pool->lock, flags);
		mutex_lock(&dm_thin_pool_table.mutex); /* reacquire for __pool_dec */
		ti->error = "Unable to activate thin device while pool is suspended";
		r = -EINVAL;
		goto bad;
	}
	atomic_set(&tc->refcount, 1);
	init_completion(&tc->can_destroy);
	list_add_tail_rcu(&tc->list, &tc->pool->active_thins);
	spin_unlock_irqrestore(&tc->pool->lock, flags);
	/*
	 * This synchronize_rcu() call is needed here otherwise we risk a
	 * wake_worker() call finding no bios to process (because the newly
	 * added tc isn't yet visible).  So this reduces latency since we
	 * aren't then dependent on the periodic commit to wake_worker().
	 */
	synchronize_rcu();

	dm_put(pool_md);

	return 0;

bad:
	dm_pool_close_thin_device(tc->td);
bad_pool:
	__pool_dec(tc->pool);
bad_pool_lookup:
	dm_put(pool_md);
bad_common:
	dm_put_device(ti, tc->pool_dev);
bad_pool_dev:
	if (tc->origin_dev)
		dm_put_device(ti, tc->origin_dev);
bad_origin_dev:
	kfree(tc);
out_unlock:
	mutex_unlock(&dm_thin_pool_table.mutex);

	return r;
}

static int thin_map(struct dm_target *ti, struct bio *bio)
{
	bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

	return thin_bio_map(ti, bio);
}

static int thin_endio(struct dm_target *ti, struct bio *bio, int err)
{
#if 0
	unsigned long flags;
	struct dm_thin_endio_hook *h = dm_per_bio_data(bio, sizeof(struct dm_thin_endio_hook));
	struct list_head work;
	struct dm_thin_new_mapping *m, *tmp;
	struct pool *pool = h->tc->pool;

	if (h->shared_read_entry) {
		INIT_LIST_HEAD(&work);
		dm_deferred_entry_dec(h->shared_read_entry, &work);

		spin_lock_irqsave(&pool->lock, flags);
		list_for_each_entry_safe(m, tmp, &work, list) {
			list_del(&m->list);
			__complete_mapping_preparation(m);
		}
		spin_unlock_irqrestore(&pool->lock, flags);
	}

	if (h->all_io_entry) {
		INIT_LIST_HEAD(&work);
		dm_deferred_entry_dec(h->all_io_entry, &work);
		if (!list_empty(&work)) {
			spin_lock_irqsave(&pool->lock, flags);
			list_for_each_entry_safe(m, tmp, &work, list)
				list_add_tail(&m->list, &pool->prepared_discards);
			spin_unlock_irqrestore(&pool->lock, flags);
			wake_worker(pool);
		}
	}

	if (h->cell)
		cell_defer_no_holder(h->tc, h->cell);

#endif
	return 0;
}

static void thin_presuspend(struct dm_target *ti)
{
	struct thin_c *tc = ti->private;

	if (dm_noflush_suspending(ti))
		noflush_work(tc, do_noflush_start);
}

static void thin_postsuspend(struct dm_target *ti)
{
	struct thin_c *tc = ti->private;

	/*
	 * The dm_noflush_suspending flag has been cleared by now, so
	 * unfortunately we must always run this.
	 */
	noflush_work(tc, do_noflush_stop);
}

static int thin_preresume(struct dm_target *ti)
{
	struct thin_c *tc = ti->private;

	if (tc->origin_dev)
		tc->origin_size = get_dev_size(tc->origin_dev->bdev);

	return 0;
}

/*
 * <nr mapped sectors> <highest mapped sector>
 */
static void thin_status(struct dm_target *ti, status_type_t type,
			unsigned status_flags, char *result, unsigned maxlen)
{
	int r;
	ssize_t sz = 0;
	dm_block_t mapped, highest;
	char buf[BDEVNAME_SIZE];
	struct thin_c *tc = ti->private;

	if (get_pool_mode(tc->pool) == PM_FAIL) {
		DMEMIT("Fail");
		return;
	}

	if (!tc->td)
		DMEMIT("-");
	else {
		switch (type) {
		case STATUSTYPE_INFO:
			r = dm_thin_get_mapped_count(tc->td, &mapped);
			if (r) {
				DMERR("dm_thin_get_mapped_count returned %d", r);
				goto err;
			}

			r = dm_thin_get_highest_mapped_block(tc->td, &highest);
			if (r < 0) {
				DMERR("dm_thin_get_highest_mapped_block returned %d", r);
				goto err;
			}

			DMEMIT("%llu ", mapped * tc->pool->sectors_per_block);
			if (r)
				DMEMIT("%llu", ((highest + 1) *
						tc->pool->sectors_per_block) - 1);
			else
				DMEMIT("-");
			break;

		case STATUSTYPE_TABLE:
			DMEMIT("%s %lu",
			       format_dev_t(buf, tc->pool_dev->bdev->bd_dev),
			       (unsigned long) tc->dev_id);
			if (tc->origin_dev)
				DMEMIT(" %s", format_dev_t(buf, tc->origin_dev->bdev->bd_dev));
			break;
		}
	}

	return;

err:
	DMEMIT("Error");
}

static int thin_iterate_devices(struct dm_target *ti,
				iterate_devices_callout_fn fn, void *data)
{
	sector_t blocks;
	struct thin_c *tc = ti->private;
	struct pool *pool = tc->pool;

	/*
	 * We can't call dm_pool_get_data_dev_size() since that blocks.  So
	 * we follow a more convoluted path through to the pool's target.
	 */
	if (!pool->ti)
		return 0;	/* nothing is bound */

	blocks = pool->ti->len;
	(void) sector_div(blocks, pool->sectors_per_block);
	if (blocks)
		return fn(ti, tc->pool_dev, 0, pool->sectors_per_block * blocks, data);

	return 0;
}

static void thin_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct thin_c *tc = ti->private;
	struct pool *pool = tc->pool;

	if (!pool->pf.discard_enabled)
		return;

	limits->discard_granularity = pool->sectors_per_block << SECTOR_SHIFT;
	limits->max_discard_sectors = 2048 * 1024 * 16; /* 16G */
}

static struct target_type thin_target = {
	.name = "thin",
	.version = {1, 19, 0},
	.module	= THIS_MODULE,
	.ctr = thin_ctr,
	.dtr = thin_dtr,
	.map = thin_map,
	.end_io = thin_endio,
	.preresume = thin_preresume,
	.presuspend = thin_presuspend,
	.postsuspend = thin_postsuspend,
	.status = thin_status,
	.iterate_devices = thin_iterate_devices,
	.io_hints = thin_io_hints,
};

/*----------------------------------------------------------------*/

static int __init dm_thin_init(void)
{
	int r;

	pool_table_init();

	r = dm_register_target(&thin_target);
	if (r)
		return r;

	r = dm_register_target(&pool_target);
	if (r)
		goto bad_pool_target;

	r = -ENOMEM;

	_program_cache = KMEM_CACHE(dm_thin_program, 0);
	if (!_program_cache)
		goto bad_program_cache;

	return 0;

bad_program_cache:
	dm_unregister_target(&pool_target);
bad_pool_target:
	dm_unregister_target(&thin_target);

	return r;
}

static void dm_thin_exit(void)
{
	dm_unregister_target(&thin_target);
	dm_unregister_target(&pool_target);

	kmem_cache_destroy(_program_cache);
}

module_init(dm_thin_init);
module_exit(dm_thin_exit);

static unsigned no_space_timeout_secs = NO_SPACE_TIMEOUT_SECS;
module_param_named(no_space_timeout, no_space_timeout_secs, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(no_space_timeout, "Out of data space queue IO timeout in seconds");

MODULE_DESCRIPTION(DM_NAME " thin provisioning target");
MODULE_AUTHOR("Joe Thornber <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");

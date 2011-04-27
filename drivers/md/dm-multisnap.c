/*
 * Copyright (C) 2011 Red Hat UK.  All rights reserved.
 *
 * This file is released under the GPL.
 */

// static const char version[] = "0.1";

#include "dm.h"
#include "multisnap-metadata.h"
#include "persistent-data/transaction-manager.h"

#include <linux/blkdev.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

#define	DM_MSG_PREFIX	"multisnap"

/*----------------------------------------------------------------*/

/*
 * Sometimes we can't deal with a bio straight away.  We put them in prison
 * where they can't cause any mischief.  Bios are put in a cell identified
 * by a key, multiple bios can be in the same cell.  When the cell is
 * subsequently unlocked the bios become available.
 */
struct bio_prison;

struct cell_key {
	int virtual;
	multisnap_dev_t dev;
	block_t block;
};

struct cell {
	struct hlist_node list;
	struct bio_prison *prison;
	struct cell_key key;
	unsigned count;
	struct bio_list bios;
};

struct bio_prison {
	spinlock_t lock;
	mempool_t *cell_pool;

	unsigned nr_buckets;
	unsigned hash_mask;
	struct hlist_head *cells;
};

static uint32_t calc_nr_buckets(unsigned nr_cells)
{
	uint32_t n = 128;
	nr_cells /= 4;
	nr_cells = min(nr_cells, 8192u);
	while (n < nr_cells)
		n <<= 1;

	return n;
}

/*
 * @nr_cells should be the number of cells you want in use _concurrently_.
 * Don't confuse it with the number of distinct keys.
 */
static struct bio_prison *
prison_create(unsigned nr_cells)
{
	int i;
	uint32_t nr_buckets = calc_nr_buckets(nr_cells);
	size_t len = sizeof(struct bio_prison) +
		(sizeof(struct hlist_head) * nr_buckets);
	struct bio_prison *prison = kmalloc(len, GFP_KERNEL);
	if (!prison)
		return NULL;

	spin_lock_init(&prison->lock);
	prison->cell_pool = mempool_create_kmalloc_pool(nr_cells,
						      sizeof(struct cell));
	prison->nr_buckets = nr_buckets;
	prison->hash_mask = nr_buckets - 1;
	prison->cells = (struct hlist_head *) (prison + 1);
	for (i = 0; i < nr_buckets; i++)
		INIT_HLIST_HEAD(prison->cells + i);

	return prison;
}

static void prison_destroy(struct bio_prison *prison)
{
	mempool_destroy(prison->cell_pool);
	kfree(prison);
}

static uint32_t hash_key(struct bio_prison *prison, struct cell_key *key)
{
	const unsigned BIG_PRIME = 4294967291UL;
	uint64_t hash = key->block * BIG_PRIME;
	return (uint32_t) (hash & prison->hash_mask);
}

/*
 * This may block if a new cell needs allocating.  You must ensure that
 * cells will be unlocked even if the calling thread is blocked.
 *
 * returns the number of entries in the cell prior to the new addition. or
 * < 0 on failure.
 */
static int bio_detain(struct bio_prison *prison,
		      struct cell_key key,
		      struct bio *inmate,
		      struct cell **ref)
{
	int r, found = 0;
	unsigned long flags;
	uint32_t hash = hash_key(prison, &key);
	struct cell *cell;
	struct hlist_node *tmp;

	BUG_ON(hash > prison->nr_buckets);

	spin_lock_irqsave(&prison->lock, flags);
	hlist_for_each_entry (cell, tmp, prison->cells + hash, list)
		if (!memcmp(&cell->key, &key, sizeof(key))) {
			found = 1;
			break;
		}
	spin_unlock_irqrestore(&prison->lock, flags);

	if (!found) {
		/* allocate a new cell */
		cell = mempool_alloc(prison->cell_pool, GFP_NOIO);
		cell->prison = prison;
		memcpy(&cell->key, &key, sizeof(key));
		cell->count = 0;
		bio_list_init(&cell->bios);
		hlist_add_head(&cell->list, prison->cells + hash);
	}

	spin_lock_irqsave(&prison->lock, flags);
	r = cell->count++;
	bio_list_add(&cell->bios, inmate);
	spin_unlock_irqrestore(&prison->lock, flags);

	*ref = cell;
	return r;
}

/* @inmates must have been initialised prior to this call */
static void cell_release_(struct cell *cell,
			 struct bio_list *inmates)
{
	struct bio_prison *prison = cell->prison;
	hlist_del(&cell->list);
	bio_list_merge(inmates, &cell->bios);
	mempool_free(cell, prison->cell_pool);
}

static void cell_release(struct cell *cell, struct bio_list *bios)
{
	unsigned long flags;
	struct bio_prison *prison = cell->prison;

	spin_lock_irqsave(&prison->lock, flags);
	cell_release_(cell, bios);
	spin_unlock_irqrestore(&prison->lock, flags);
}

static void cell_error(struct cell *cell)
{
	struct bio_prison *prison = cell->prison;
	struct bio_list bios;
	struct bio *bio;
	unsigned long flags;

	bio_list_init(&bios);

	spin_lock_irqsave(&prison->lock, flags);
	cell_release_(cell, &bios);
	spin_unlock_irqrestore(&prison->lock, flags);

	while ((bio = bio_list_pop(&bios)))
		bio_io_error(bio);
}

/*----------------------------------------------------------------*/

/*
 * Key building.
 */
static struct cell_key data_key(block_t b)
{
	struct cell_key r;
	r.virtual = 0;
	r.dev = 0;
	r.block = b;
	return r;
}

static struct cell_key virtual_key(struct ms_device *msd, block_t b)
{
	struct cell_key r;
	r.virtual = 1;
	r.dev = multisnap_device_dev(msd);
	r.block = b;
	return r;
}

/*----------------------------------------------------------------*/

/*
 * A pool device ties together a metadata device and a data device.  It
 * also provides the interface for creating and destroying internal
 * devices.
 */
struct pool_c;

struct new_mapping {
	struct list_head list;

	struct pool_c *pool;
	struct ms_device *msd;
	block_t virt_block;
	block_t data_block;
	struct cell *cell;
	int err;

	/*
	 * If the bio covers the whole area of a block then we can avoid
	 * zeroing or copying.  Instead this bio is hooked.  The bio will
	 * still be in the cell, so care has to be taken to avoid issuing
	 * the bio twice.
	 */
	struct bio *bio;
	bio_end_io_t *bi_end_io;
	void *bi_private;
};

struct pool_c {
	struct dm_target *ti;
	struct block_device *pool_dev;
	struct dm_dev *metadata_dev;
	struct dm_dev *data_dev;
	struct multisnap_metadata *mmd;

	sector_t data_size;
	uint32_t sectors_per_block;
	unsigned block_shift;
	block_t offset_mask;

	struct bio_prison *prison;
	struct dm_kcopyd_client *copier;

	struct workqueue_struct *wq;
	struct work_struct ws;

	spinlock_t lock;
	struct bio_list deferred_bios;
	struct list_head prepared_mappings;

	mempool_t *mapping_pool;
};

/*----------------------------------------------------------------*/

/*
 * We need to maintain an association between a bio and an ms_device.  To
 * save lookups in an auxillary table, or wrapping bios in objects from a
 * mempool we hide this value in the bio->bi_bdev field, which we know is
 * not used while the bio is being processed.
 */
static void set_msd(struct bio *bio, struct ms_device *msd)
{
	bio->bi_bdev = (struct block_device *) msd;
}

static struct ms_device *get_msd(struct bio *bio)
{
	return (struct ms_device *) bio->bi_bdev;
}

/*----------------------------------------------------------------*/

static block_t get_bio_block(struct pool_c *pool,
			     struct bio *bio)
{
	return bio->bi_sector >> pool->block_shift;
}

static void remap(struct pool_c *pool,
		  struct bio *bio,
		  block_t block)
{
	bio->bi_bdev = pool->pool_dev;
	bio->bi_sector = (block << pool->block_shift) +
		(bio->bi_sector & pool->offset_mask);
}

static void remap_and_issue(struct pool_c *pool,
			    struct bio *bio,
			    block_t block)
{
	if (bio->bi_rw & (REQ_FLUSH | REQ_FUA)) {
		int r = multisnap_metadata_commit(pool->mmd);
		if (r) {
			printk(KERN_ALERT "multisnap_metadata_commit failed");
			bio_io_error(bio);
			return;
		}
	}

	remap(pool, bio, block);
	generic_make_request(bio);
}

static void wake_worker(struct pool_c *pool)
{
	queue_work(pool->wq, &pool->ws);
}

static void copy_complete(int read_err,
			  unsigned long write_err,
			  void *context)
{
	unsigned long flags;
	struct new_mapping *m = (struct new_mapping *) context;

	m->err = read_err || write_err ? -EIO : 0;

	spin_lock_irqsave(&m->pool->lock, flags);
	list_add(&m->list, &m->pool->prepared_mappings);
	spin_unlock_irqrestore(&m->pool->lock, flags);

	wake_worker(m->pool);
}

static void bio_complete(struct bio *bio, int err)
{
	unsigned long flags;
	struct new_mapping *m = (struct new_mapping *) bio->bi_private;

	/*
	 * We can't call the proper endio function here, because the
	 * mapping hasn't been inserted yet.  Shame, the context switch to
	 * the worker is going to cause latency.
	 */
	m->err = err;

	spin_lock_irqsave(&m->pool->lock, flags);
	list_add(&m->list, &m->pool->prepared_mappings);
	spin_unlock_irqrestore(&m->pool->lock, flags);

	wake_worker(m->pool);
}

static int io_covers_block(struct pool_c *pool,
			   struct bio *bio)
{
	return ((bio->bi_sector & pool->offset_mask) == 0) &&
		(bio->bi_size == (pool->sectors_per_block << SECTOR_SHIFT));
}

static void schedule_copy(struct pool_c *pool,
			  struct ms_device *msd,
			  block_t virt_block,
			  block_t data_origin,
			  block_t data_dest,
			  struct cell *cell,
			  struct bio *bio)
{
	int r;
	struct new_mapping *m = mempool_alloc(pool->mapping_pool, GFP_NOIO);

	m->pool = pool;
	m->msd = msd;
	m->virt_block = virt_block;
	m->data_block = data_dest;
	m->cell = cell;
	m->err = 0;
	m->bio = NULL;

	if (io_covers_block(pool, bio)) {
		/* no copy needed, since all data is going to change */
		m->bio = bio;
		m->bi_end_io = bio->bi_end_io;
		m->bi_private = bio->bi_private;
		bio->bi_end_io = bio_complete;
		bio->bi_private = m;
		remap_and_issue(pool, bio, data_dest);

	} else {
		/* use kcopyd */
		struct dm_io_region from, to;

		from.bdev = pool->data_dev->bdev;
		from.sector = data_origin * pool->sectors_per_block;
		from.count = pool->sectors_per_block;

		to.bdev = pool->data_dev->bdev;
		to.sector = data_dest * pool->sectors_per_block;
		to.count = pool->sectors_per_block;

		r = dm_kcopyd_copy(pool->copier, &from, 1, &to, 0, copy_complete, m);
		if (r < 0) {
			mempool_free(m, pool->mapping_pool);
			printk(KERN_ALERT "dm_kcopyd_copy() failed");
			cell_error(cell);
		}
	}
}

static void schedule_zero(struct pool_c *pool,
			  struct ms_device *msd,
			  block_t virt_block,
			  block_t data_block,
			  struct cell *cell,
			  struct bio *bio)
{
	struct new_mapping *m = mempool_alloc(pool->mapping_pool, GFP_NOIO);

	m->pool = pool;
	m->msd = msd;
	m->virt_block = virt_block;
	m->data_block = data_block;
	m->cell = cell;
	m->err = 0;
	m->bio = NULL;

	if (io_covers_block(pool, bio)) {
		/* no copy needed, since all data is going to change */
		m->bio = bio;
		m->bi_end_io = bio->bi_end_io;
		m->bi_private = bio->bi_private;
		bio->bi_end_io = bio_complete;
		bio->bi_private = m;
		remap_and_issue(pool, bio, data_block);

	} else {
		/* FIXME: zeroing not implemented yet */

		copy_complete(0, 0, m);
	}
}

static void cell_remap_and_issue(struct pool_c *pool,
				 struct cell *cell,
				 block_t data_block)
{
	struct bio_list bios;
	struct bio *bio;
	bio_list_init(&bios);
	cell_release(cell, &bios);

	while ((bio = bio_list_pop(&bios)))
		remap_and_issue(pool, bio, data_block);
}

static void cell_remap_and_issue_except(struct pool_c *pool,
					struct cell *cell,
					block_t data_block,
					struct bio *exception)
{
	struct bio_list bios;
	struct bio *bio;
	bio_list_init(&bios);
	cell_release(cell, &bios);

	while ((bio = bio_list_pop(&bios)))
		if (bio != exception)
			remap_and_issue(pool, bio, data_block);
}

static void process_bio(struct pool_c *pool,
			struct ms_device *msd,
			struct bio *bio)
{
	int r, count;
	block_t block = get_bio_block(pool, bio), data_block;
	struct multisnap_lookup_result lookup_result;
	struct bio_list bios;
	struct cell *cell;

	/*
	 * First we detain the bio against the cell for the virtual cell.
	 * We can then check whether it's been provisioned.
	 */
	count = bio_detain(pool->prison, virtual_key(msd, block), bio, &cell);
	if (count > 0)
		/* Someone's already handling this, leave it to them. */
		return;

	r = multisnap_metadata_lookup(msd, block, 1, &lookup_result);
	switch (r) {
	case 0:
		/*
		 * A virtual block will only ever be locked once, during
		 * provisioning.  We know this has been provisioned, so
		 * it's safe to release the bio.
		 */
		bio_list_init(&bios);
		cell_release(cell, &bios);

		if (bio_data_dir(bio) == WRITE) {
			/*
			 * Given it's a WRITE io, we may need to break
			 * sharing on a data block.
			 */
			count = bio_detain(pool->prison, data_key(block), bio, &cell);
			if (count > 0)
				return; /* already underway */

			if (lookup_result.shared) {
				r = multisnap_metadata_alloc_data_block(msd, &data_block);
				if (r) {
					printk(KERN_ALERT "multisnap_metadata_alloc_data_block() failed");
					cell_error(cell);
				} else
					schedule_copy(pool, msd,
						      block,
						      lookup_result.block,
						      data_block, cell, bio);
			} else
				cell_remap_and_issue(pool, cell, lookup_result.block);
		} else
			remap_and_issue(pool, bio, lookup_result.block);
		break;

	case -ENODATA:
		/* prepare a new block */
		r = multisnap_metadata_alloc_data_block(msd, &data_block);
		if (r) {
			printk(KERN_ALERT "multisnap_metadata_alloc_data_block() failed");
			cell_error(cell);
		} else
			schedule_zero(pool, msd, block, data_block, cell, bio);
		break;

	default:
		printk(KERN_ALERT "error returned from multisnap_metadata_lookup (%d)", r);
		bio_io_error(bio);
	}
}

static void process_bios(struct pool_c *pool)
{
	unsigned long flags;
	struct bio *bio;
	struct bio_list bios;
	bio_list_init(&bios);

	spin_lock_irqsave(&pool->lock, flags);
	bio_list_merge(&bios, &pool->deferred_bios);
	bio_list_init(&pool->deferred_bios);
	spin_unlock_irqrestore(&pool->lock, flags);

	while ((bio = bio_list_pop(&bios))) {
		struct ms_device *msd = get_msd(bio);
		process_bio(pool, msd, bio);
	}
}

static void process_prepared_mappings(struct pool_c *pool)
{
	int r;
	unsigned long flags;
	struct list_head maps;
	struct new_mapping *m, *tmp;
	struct bio *bio;

	INIT_LIST_HEAD(&maps);
	spin_lock_irqsave(&pool->lock, flags);
	list_splice_init(&pool->prepared_mappings, &maps);
	spin_unlock_irqrestore(&pool->lock, flags);

	list_for_each_entry_safe (m, tmp, &maps, list) {
		bio = m->bio;

		if (bio) {
			bio->bi_end_io = m->bi_end_io;
			bio->bi_private = m->bi_private;
		}

		if (m->err)
			cell_error(m->cell);

		else {
			r = multisnap_metadata_insert(m->msd, m->virt_block, m->data_block);
			if (r) {
				printk(KERN_ALERT "multisnap_metadata_insert() failed");
				cell_error(m->cell);
			} else {
				if (m->bio) {
					bio_endio(bio, 0);
					cell_remap_and_issue_except(pool, m->cell, m->data_block, bio);
				} else
					cell_remap_and_issue(pool, m->cell, m->data_block);

				list_del(&m->list);
				mempool_free(m, pool->mapping_pool);
			}
		}
	}
}

static void do_work(struct work_struct *ws)
{
	struct pool_c *pool = container_of(ws, struct pool_c, ws);

	process_bios(pool);
	process_prepared_mappings(pool);
}

static void defer_bio(struct pool_c *pool, struct ms_device *msd, struct bio *bio)
{
	set_msd(bio, msd);

	spin_lock(&pool->lock);
	bio_list_add(&pool->deferred_bios, bio);
	spin_unlock(&pool->lock);

	wake_worker(pool);
}

/*
 * Non-blocking function designed to be called from the targets map
 * function.
 */
int bio_map(struct pool_c *pool,
	    struct ms_device *msd,
	    struct bio *bio)
{
	int r;
	block_t block = get_bio_block(pool, bio);
	struct multisnap_lookup_result result;

	if (bio->bi_rw & (REQ_FLUSH | REQ_FUA)) {
		defer_bio(pool, msd, bio);
		return DM_MAPIO_SUBMITTED;
	}

	r = multisnap_metadata_lookup(msd, block, 0, &result);
	switch (r) {
	case 0:
		if (bio_data_dir(bio) == WRITE && result.shared) {
			/*
			 * We have a race condition here between the
			 * result.shared value returned by the lookup and
			 * snapshot creation, which may cause new
			 * sharing.
			 *
			 * To avoid this always quiesce the origin before
			 * taking the snap.  You want to do this anyway to
			 * ensure a consistent application view
			 * (i.e. lockfs).
			 *
			 * More distant ancestors are irrelevant, the
			 * shared flag will be set in their case.
			 */
			defer_bio(pool, msd, bio);
			r = DM_MAPIO_SUBMITTED;
		} else {
			remap(pool, bio, result.block);
			r = DM_MAPIO_REMAPPED;
		}
		break;

	case -ENODATA:
	case -EWOULDBLOCK:
		defer_bio(pool, msd, bio);
		r = DM_MAPIO_SUBMITTED;
		break;
	}

	return r;
}

static int is_congested(void *congested_data, int bdi_bits)
{
	int r;
	struct pool_c *pool = congested_data;

#if 0
	spin_lock(&pool->no_space_lock);
	r = !bio_list_empty(&mc->no_space);
	spin_unlock(&pool->no_space_lock);

	if (!r) {
#endif
		struct request_queue *q = bdev_get_queue(pool->data_dev->bdev);
		r = bdi_congested(&q->backing_dev_info, bdi_bits);
#if 0
	}
#endif

	return r;
}

static void set_congestion_fn(struct pool_c *pool)
{
	struct mapped_device *md = dm_table_get_md(pool->ti->table);
	struct backing_dev_info *bdi = &dm_disk(md)->queue->backing_dev_info;

	/* Set congested function and data. */
	bdi->congested_fn = is_congested;
	bdi->congested_data = pool;
}

/*----------------------------------------------------------------*/

// FIXME: global pool for now
struct pool_c *global_pool_;

/*----------------------------------------------------------------*/

static void pool_dtr(struct dm_target *ti)
{
	struct pool_c *pool = ti->private;

	multisnap_metadata_close(pool->mmd);
	dm_put_device(ti, pool->metadata_dev);
	dm_put_device(ti, pool->data_dev);

	prison_destroy(pool->prison);
	dm_kcopyd_client_destroy(pool->copier);
	if (pool->wq)
		destroy_workqueue(pool->wq);

	mempool_destroy(pool->mapping_pool);
	kfree(pool);
}

/*
 * multisnap-pool <metadata dev>
 *                <data dev>
 *                <data block size in sectors>
 * FIXME: add low water mark
 */
#define KCOPYD_NR_PAGES 1024
static int pool_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	long long unsigned block_size;
	struct pool_c *pool;
	struct multisnap_metadata *mmd;
	struct dm_dev *metadata_dev, *data_dev;
	block_t data_size;

	if (argc != 3) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	r = dm_get_device(ti, argv[0], FMODE_READ | FMODE_WRITE, &metadata_dev);
	if (r) {
		ti->error = "Error getting metadata device";
		return r;
	}

	r = dm_get_device(ti, argv[1], FMODE_READ | FMODE_WRITE, &data_dev);
	if (r) {
		ti->error = "Error getting data device";
		dm_put_device(ti, metadata_dev);
		return r;
	}

	if (sscanf(argv[2], "%llu", &block_size) != 1) {
		ti->error = "Invalid block size";
		dm_put_device(ti, metadata_dev);
		dm_put_device(ti, data_dev);
		return -EINVAL;
	}

	data_size = (i_size_read(data_dev->bdev->bd_inode) >> SECTOR_SHIFT) / block_size;
	mmd = multisnap_metadata_open(metadata_dev->bdev, block_size, data_size);
	if (!mmd) {
		ti->error = "Error opening metadata device";
		dm_put_device(ti, metadata_dev);
		dm_put_device(ti, data_dev);
		return -ENOMEM;
	}

	pool = kmalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool) {
		ti->error = "Error allocating memory";
		multisnap_metadata_close(mmd);
		dm_put_device(ti, metadata_dev);
		dm_put_device(ti, data_dev);
		return -ENOMEM;
	}
	pool->pool_dev = dm_bdev(dm_table_get_md(pool->ti->table));
	pool->metadata_dev = metadata_dev;
	pool->data_dev = data_dev;
	pool->mmd = mmd;
	pool->data_size = data_size;
	pool->sectors_per_block = block_size;
	pool->block_shift = ffs(block_size) - 1;
	pool->offset_mask = block_size - 1;
	pool->prison = prison_create(1024); /* FIXME: magic number */
	if (!pool->prison) {
		/* FIXME: finish */
	}

	r = dm_kcopyd_client_create(KCOPYD_NR_PAGES, &pool->copier); /* FIXME: magic numbers */
	if (r) {
		/* FIXME: finish */
	}

	/* Create singlethreaded workqueue that will service all devices
	 * that use this metadata.
	 */
	pool->wq = alloc_ordered_workqueue(DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!pool->wq) {
		printk(KERN_ALERT "couldn't create workqueue for metadata object");
		/* FIXME: finish */
	}

	INIT_WORK(&pool->ws, do_work);
	spin_lock_init(&pool->lock);
	bio_list_init(&pool->deferred_bios);
	INIT_LIST_HEAD(&pool->prepared_mappings);
	pool->mapping_pool = mempool_create_kmalloc_pool(1024, sizeof(struct new_mapping)); /* FIXME: magic numbers */
	global_pool_ = pool;
	pool->ti = ti;
	set_congestion_fn(pool);
	ti->num_flush_requests = 1;
	ti->private = pool;

	return 0;
}

static int pool_map(struct dm_target *ti, struct bio *bio,
		    union map_info *map_context)
{
	struct pool_c *pool = ti->private;
	bio->bi_bdev = pool->data_dev->bdev;
	return DM_MAPIO_REMAPPED;
}

/*
 * Messages supported:
 *   new-thin <dev id> <dev size in sectors>
 *   new-snap <dev id> <origin id>
 *   del      <dev id>
 */
static int pool_message(struct dm_target *ti, unsigned argc, char **argv)
{
	/* ti->error doesn't have a const qualifier :( */
	char *invalid_args = "Incorrect number of arguments";

	int r;
	struct pool_c *pool = ti->private;
	multisnap_dev_t dev_id;

	if (argc < 2) {
		ti->error = invalid_args;
		return -EINVAL;
	}

	if (sscanf(argv[1], "%llu", &dev_id) != 1) {
		ti->error = "Invalid dev id";
		return -EINVAL;
	}

	if (!strcmp(argv[0], "new-thin")) {
		block_t dev_size;

		if (argc != 3) {
			ti->error = invalid_args;
			return -EINVAL;
		}

		if (sscanf(argv[2], "%llu", &dev_size) != 1) {
			ti->error = "Invalid dev size";
			return -EINVAL;
		}

		r = multisnap_metadata_create_thin(pool->mmd, dev_id, dev_size >> pool->block_shift);
		if (r) {
			ti->error = "Creation of thin provisioned device failed";
			return r;
		}

	} else if (!strcmp(argv[0], "new-snap")) {
		multisnap_dev_t origin_id;

		if (argc != 3) {
			ti->error = invalid_args;
			return -EINVAL;
		}

		if (sscanf(argv[2], "%llu", &origin_id) != 1) {
			ti->error = "Invalid origin id";
			return -EINVAL;
		}

		r = multisnap_metadata_create_snap(pool->mmd, dev_id, origin_id);
		if (r) {
			ti->error = "Creation of snapshot failed";
			return r;
		}

	} else if (!strcmp(argv[0], "del")) {
		if (argc != 2) {
			ti->error = invalid_args;
			return -EINVAL;
		}

		r = multisnap_metadata_delete(pool->mmd, dev_id);

	} else
		return -EINVAL;

	return 0;
}

static int pool_iterate_devices(struct dm_target *ti,
				     iterate_devices_callout_fn fn,
				     void *data)
{
	struct pool_c *pool = ti->private;
	return fn(ti, pool->data_dev, 0, pool->data_size * pool->sectors_per_block, data);
}

static int pool_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
		      struct bio_vec *biovec, int max_size)
{
	struct pool_c *pool = ti->private;
	struct request_queue *q = bdev_get_queue(pool->data_dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = pool->data_dev->bdev;
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static void
pool_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct pool_c *pool = ti->private;

	blk_limits_io_min(limits, 0);
	blk_limits_io_opt(limits, pool->sectors_per_block << SECTOR_SHIFT);
}

static struct target_type pool_target = {
	.name =    "multisnap-pool",
	.version = {1, 0, 0},
	.module =  THIS_MODULE,
	.ctr =	   pool_ctr,
	.dtr =	   pool_dtr,
	.map =	   pool_map,
	.message = pool_message,
	.merge =   pool_merge,
	.iterate_devices = pool_iterate_devices,
	.io_hints = pool_io_hints,
};

/*----------------------------------------------------------------*/

struct multisnap_c {
	struct pool_c *pool;
	struct dm_dev *pool_dev;
	struct ms_device *msd;
};

static void multisnap_dtr(struct dm_target *ti)
{
	struct multisnap_c *mc = ti->private;
	if (mc->msd)
		multisnap_metadata_close_device(mc->msd);
	dm_put_device(ti, mc->pool_dev);
	kfree(mc);
}

/*
 * Construct a multisnap device:
 *
 * <start> <length> multisnap <pool dev> <dev id>
 *
 * pool dev: the path to the pool (eg, /dev/mapper/my_pool)
 * dev id: the internal device identifier
 */
static int
multisnap_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	unsigned long dev_id;
	struct multisnap_c *mc;
	struct dm_dev *pool_dev;

	if (argc != 2) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	mc = ti->private = kzalloc(sizeof(*mc), GFP_KERNEL);
	if (!mc) {
		ti->error = "Out of memory";
		return -ENOMEM;
	}

	r = dm_get_device(ti, argv[0], FMODE_READ | FMODE_WRITE, &pool_dev);
	if (r) {
		ti->error = "Error opening pool device";
		kfree(mc);
	}
	mc->pool_dev = pool_dev;

	if (sscanf(argv[1], "%lu", &dev_id) != 1) {
		ti->error = "Invalid device id";
		multisnap_dtr(ti);
		return -EINVAL;
	}

	mc->pool = global_pool_;
	mc->pool->pool_dev = pool_dev->bdev; /* FIXME: hack */

	r = multisnap_metadata_open_device(mc->pool->mmd, dev_id, &mc->msd);
	if (r) {
		ti->error = "Couldn't open multisnap internal device";
		multisnap_dtr(ti);
		return r;
	}
	ti->split_io = mc->pool->sectors_per_block;
	ti->num_flush_requests = 1;

	return 0;
}

static int
multisnap_map(struct dm_target *ti, struct bio *bio,
	      union map_info *map_context)
{
	struct multisnap_c *mc = ti->private;

	bio->bi_sector -= ti->begin;
	return bio_map(mc->pool, mc->msd, bio);
}
#if 0
static void
multisnap_presuspend(struct dm_target *ti)
{
	struct multisnap_c *mc = ti->private;

	spin_lock(&mc->lock);
	mc->bounce_mode = 1;
	spin_unlock(&mc->lock);

	multisnap_flush(ti);
	requeue_all_bios(mc);
}

/*
 * Retrieves the number of blocks of the data device from
 * the superblock and compares it to the actual device size,
 * thus resizing the data device in case it has grown.
 *
 * This both copes with opening preallocated data devices in the ctr
 * being followed by a resume
 * -and-
 * calling the resume method individually after userpace has
 * grown the data device in reaction to a table event.
 */
static int
multisnap_preresume(struct dm_target *ti)
{
	struct multisnap_c *mc = ti->private;

	spin_lock(&mc->lock);
	mc->bounce_mode = 0;
	spin_unlock(&mc->lock);

	return 0;
}
#endif
static int
multisnap_status(struct dm_target *ti, status_type_t type,
		 char *result, unsigned maxlen)
{
#if 0
	int r;
	ssize_t sz = 0;
	block_t mapped;
	char buf[BDEVNAME_SIZE];
	struct multisnap_c *mc = ti->private;
	unsigned long dev_id;

	r = multisnap_metadata_get_mapped_count(mc->msd, &mapped);
	if (r)
		return r;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%llu", mapped);
		break;

	case STATUSTYPE_TABLE:
		dev_id = mc->dev_id;
		DMEMIT("%s %lu",
		       format_dev_t(buf, mc->pool_dev->bdev->bd_dev),
		       dev_id);
	}

	return 0;
#else
	return -1;
#endif
}

/* bvec merge method. */
static int
multisnap_bvec_merge(struct dm_target *ti,
		     struct bvec_merge_data *bvm,
		     struct bio_vec *biovec, int max_size)
{
	struct multisnap_c *mc = ti->private;
	struct pool_c * pool = mc->pool;

#if 0
	struct request_queue *q = bdev_get_queue(_remap_dev(mc));
	block_t block;
	struct multisnap_map_result mapping;

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = _remap_dev(mc);
	bvm->bi_sector -= ti->begin;
	block = _sector_to_block(mc, bvm->bi_sector);

	/*
	 * We look this up as a WRITE in case the bio is going to cause a
	 * new mapping.  Because we've selected non-blocking we know no
	 * mapping will be inserted.
	 */
	if (multisnap_metadata_map(mc->msd, block, WRITE, 0, &mapping) < 0)
		return 0;

	bvm->bi_sector = _remap_sector(mc, bvm->bi_sector, mapping.dest);
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
#else
	/*
	 * We fib here, because the space may not have been provisioned yet
	 * we can't give a good answer.  It's better to return the block
	 * size, and incur extra splitting in a few cases than always
	 * return the smallest, page sized, chunk.
	 */
	return pool->sectors_per_block << SECTOR_SHIFT;
#endif
}

static int multisnap_iterate_devices(struct dm_target *ti,
				     iterate_devices_callout_fn fn,
				     void *data)
{
	struct multisnap_c *mc = ti->private;
	return fn(ti, mc->pool_dev, 0, mc->pool->sectors_per_block, data);
}

static void
multisnap_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct multisnap_c *mc = ti->private;
	struct pool_c *pool = mc->pool;

	blk_limits_io_min(limits, 0);
	blk_limits_io_opt(limits, pool->sectors_per_block << SECTOR_SHIFT);
}

static struct target_type multisnap_target = {
	.name =        "multisnap",
	.version =     {1, 0, 0},
	.module =      THIS_MODULE,
	.ctr =	       multisnap_ctr,
	.dtr =	       multisnap_dtr,
//	.flush =       multisnap_flush,
	.map =	       multisnap_map,
//	.presuspend =  multisnap_presuspend,
//	.preresume =   multisnap_preresume,
	.status =      multisnap_status,
	.merge =       multisnap_bvec_merge,
	.iterate_devices = multisnap_iterate_devices,
	.io_hints =    multisnap_io_hints,
};

/*----------------------------------------------------------------*/

static int __init dm_multisnap_init(void)
{
	int r = dm_register_target(&multisnap_target);
	if (r)
		return r;

	r = dm_register_target(&pool_target);
	if (r)
		dm_unregister_target(&multisnap_target);

	return r;
}

static void dm_multisnap_exit(void)
{
	dm_unregister_target(&multisnap_target);
	dm_unregister_target(&pool_target);
}

module_init(dm_multisnap_init);
module_exit(dm_multisnap_exit);

MODULE_DESCRIPTION(DM_NAME "device-mapper multisnap target");
MODULE_AUTHOR("Joe Thornber <thornber@redhat.com>");
MODULE_LICENSE("GPL");

/*----------------------------------------------------------------*/






















#if 0
static void requeue_bios(struct multisnap_c *mc, struct bio_list *bl, spinlock_t *lock)
{
	struct bio *bio;
	struct bio_list bios;

	bio_list_init(&bios);
	spin_lock(lock);
	bio_list_merge(&bios, bl);
	bio_list_init(bl);
	spin_unlock(lock);

	while ((bio = bio_list_pop(&bios)))
		bio_endio(bio, DM_ENDIO_REQUEUE);
}

static void requeue_all_bios(struct multisnap_c *mc)
{
	requeue_bios(mc, &mc->work, &mc->lock);
	requeue_bios(mc, &mc->no_space, &mc->no_space_lock);
}

static void do_bios(struct multisnap_c *mc, struct bio_list *bios)
{
	int r;
	struct bio *bio;
	block_t block;
	struct multisnap_map_result mapping;

	while ((bio = bio_list_pop(bios))) {
		block = _sector_to_block(mc, bio->bi_sector);
		r = multisnap_metadata_map(mc->msd, block, bio_data_dir(bio),
					   1, &mapping);
		if (r == -ENODATA) {
			/* don't create a new mapping for a read */
			if (bio_data_dir(bio) == READ) {
				zero_fill_bio(bio);
				bio_endio(bio, 0);
				continue;
			}

			/* can't get here if it's a write */
			BUG_ON(bio_data_dir(bio) == WRITE);

		} else if (r == -ENOSPC) {
			/*
			 * No data space, so we postpone the bio
			 * until more space added by userland.
			 */
			spin_lock(&mc->no_space_lock);
			bio_list_add(&mc->no_space, bio);
			spin_unlock(&mc->no_space_lock);
			continue;
		}

		if (r)
			bio_io_error(bio);
		else {
#if 0
			/*
			 * Copying io must be issued before commit.  The
			 * commit will wait for it to complete.
			 */
			r = issue_copy_io(mc, &mapping, bio);
			if (r < 0) {
				/* FIXME: we need to unpick the mapping */
				bio_io_error(bio);
				continue;
			}
#endif

			/*
			 * REQ_FUA should only trigger a commit() if it's
			 * to a block that is pending.  I'm not sure
			 * whether the overhead of tracking pending blocks
			 * is worth it though.
			 */
			if ((bio->bi_rw & (REQ_FUA | REQ_FLUSH))) {
				r = multisnap_metadata_commit(mc->mmd);
				if (r < 0) {
					bio_io_error(bio);
					continue;
				}
			}

			remap_bio(mc, bio, mapping.dest);
			generic_make_request(bio);
		}
	}
}

static void do_work(struct work_struct *ws)
{
	int bounce_mode;
	struct multisnap_c *mc = container_of(ws, struct multisnap_c, ws);
	struct bio_list bios;
	bio_list_init(&bios);

	spin_lock(&mc->lock);
	bio_list_merge(&bios, &mc->work);
	bio_list_init(&mc->work);
	bounce_mode = mc->bounce_mode;
	spin_unlock(&mc->lock);

	if (bounce_mode) {
		struct bio *bio;
		while ((bio = bio_list_pop(&bios)))
			bio_endio(bio, DM_ENDIO_REQUEUE);
	} else
		do_bios(mc, &bios);
}

static void multisnap_flush(struct dm_target *ti)
{
	struct multisnap_c *mc = ti->private;

	/* Wait until all io has been processed. */

	/* FIXME: other multisnaps will still be working, so we can't
	 * flush, should instead keep a count of how many our jobs are
	 * pending. */
	flush_workqueue(multisnap_metadata_get_workqueue(mc->msd));
	if (multisnap_metadata_commit(mc->mmd) < 0) {
		printk(KERN_ALERT "multisnap metadata write failed.");
		/* FIXME: invalidate device? error the next FUA or FLUSH bio ?*/
	}
}

#endif


















#if 0
#define TABLE_SIZE 1024
static spinlock_t table_lock_;
static struct hlist_head table_[TABLE_SIZE];

static void
table_init(void)
{
	unsigned i;
	spinlock_init(&table_lock_);
	for (i = 0; i < TABLE_SIZE; i++)
		INIT_HLIST_HEAD(table_ + i);
}

static unsigned
hash_bdev(struct block_device *bdev)
{
	/* FIXME: finish */
	/* bdev -> dev_t -> unsigned */
	return 0;
}

static void
table_insert(struct block_device *bdev, struct pool_c *p)
{
	unsigned bucket = hash_bdev(bdev);
	hlist_add_head(hash, table_ + bucket);
}

static void
table_remove(struct hash_node *hash)
{
	hlist_del(hash);
}

static struct pool_c *
table_lookup(struct block_device *bdev)
{
	unsigned bucket = hash_bdev(bdev);
	struct multisnap_metadata *mmd;
	struct hlist_node *n;

	hlist_for_each_entry (mmd, n, mmd_table_ + bucket, hash)
		if (mmd->bdev == bdev)
			return mmd;

	return NULL;
}

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
#endif

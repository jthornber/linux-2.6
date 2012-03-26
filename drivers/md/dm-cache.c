/*
 * Copyright (C) 2012 Red Hat GmbH. All rights reserved.
 *
 * This file is released under the GPL.
 *
 * Hierarchical Storage Management target.
 *
 * Features:
 * o manages a storage pool of blocks on a fast block device to
 *   allocate from in order to cache blocks of a slower cached device
 * o data block size selectable (2^^N)
 * o - status <chunks free> <chunks used>
 *   - userland to kernel message just be a single resume (no prior suspend)
 *   - status provide metadata stats, userland resizes via same
 *     mechanism as data extend
 *
 * FIXME:
 * o support DISCARD requests to free unused blocks
 * o support relocation of blocks to allow for hot spot removal
 *   and shrinking of the data device.
 * o writethrough
 * o eventually drop metadata store creation once userspace does it
 *
 */

#include "dm.h"
#include "dm-bio-prison.h"

#include <asm/div64.h>

#include <linux/blkdev.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/rbtree.h>
#include <linux/slab.h>

/* FIXME: describe, mechanism/controller/metadata split */

/* FIXME: I think all the md_ functions will eventually be able to block,
 * once we allow for this we can drop the irq spin locking.
 */

#define debug(x...) ;

/*----------------------------------------------------------------*/

/*
 * Simple, in-core metadata, just a quick hack for development.
 */
struct mapping {
	/*
	 * These two fields are protected by the spin lock in the struct
	 * metadata.
	 */
	struct list_head list;
	struct rb_node node;

	sector_t block_size;

	/* FIXME: is the lock needed if they're only every changed from the worker thread? */
	spinlock_t lock;	/* protects subsequent fields */
	dm_block_t origin;
	dm_block_t cache;

	/* used to determine if the cache is dirty wrt the origin */
	/* FIXME: uses too much space, but nice way to define semantics */
	atomic64_t origin_gen;
	atomic64_t cache_gen;

	unsigned long valid_sectors[0];
};

struct metadata {
	sector_t block_size;
	dm_block_t nr_cache_blocks;

	spinlock_t lock;
	struct list_head lru;	  /* in the rbtree */
	struct list_head free;	  /* unallocated */
	struct list_head migrating;
	struct rb_root mappings;

	atomic_t nr_migrating;
	wait_queue_head_t migrating_wq; /* FIXME: not sure this should be here */

	unsigned valid_array_size; /* how many ulongs are in the mapping->valid_sectors arrays */
};

static sector_t div_up(sector_t n, sector_t d)
{
	return ((n + d - 1) / d);
}

static void free_list(struct list_head *head)
{
	struct mapping *m, *tmp;
	list_for_each_entry_safe (m, tmp, head, list)
		kfree(m);
}

static void metadata_destroy(struct metadata *md)
{
	free_list(&md->lru);
	free_list(&md->free);
	kfree(md);
}

static struct metadata *metadata_create(sector_t block_size, unsigned nr_cache_blocks)
{
	dm_block_t b;
	size_t mapping_size;
	struct mapping *m;
	struct metadata *md = kmalloc(sizeof(*md), GFP_KERNEL);
	if (!md)
		return NULL;

	md->valid_array_size = div_up(block_size, BITS_PER_LONG);
	mapping_size = sizeof(struct mapping) + md->valid_array_size * sizeof(unsigned long);

	md->block_size = block_size;
	md->nr_cache_blocks = nr_cache_blocks;
	spin_lock_init(&md->lock);

	INIT_LIST_HEAD(&md->lru);
	INIT_LIST_HEAD(&md->free);
	INIT_LIST_HEAD(&md->migrating);
	md->mappings = RB_ROOT;
	atomic_set(&md->nr_migrating, 0);
	init_waitqueue_head(&md->migrating_wq);

	for (b = 0; b < nr_cache_blocks; b++) {
		/* FIXME: use a slab */
		m = kmalloc(mapping_size, GFP_KERNEL);
		if (!m) {
			metadata_destroy(md);
			return NULL;
		}

		spin_lock_init(&m->lock);
		INIT_LIST_HEAD(&m->list);
		rb_init_node(&m->node);
		m->origin = 0;
		m->cache = b;

		list_add_tail(&m->list, &md->free);
	}

	return md;
}

static struct mapping *__md_alloc_mapping(struct metadata *md)
{
	if (list_empty(&md->free))
		return NULL;

	return list_first_entry(&md->free, struct mapping, list);
}

static struct mapping *md_alloc_mapping(struct metadata *md)
{
	struct mapping *m;
	unsigned long flags;

	spin_lock_irqsave(&md->lock, flags);
	m = __md_alloc_mapping(md);
	spin_unlock_irqrestore(&md->lock, flags);

	return m;
}

static struct mapping *__rb_lookup(struct rb_node *root,
				   dm_block_t origin_block)
{
	struct mapping *m;
	struct rb_node *n = root;

	while (n) {
		m = rb_entry(n, struct mapping, node);

		if (origin_block < m->origin)
			n = n->rb_left;
		else if (origin_block > m->origin)
			n = n->rb_right;
		else
			return m;
	}

	return NULL;
}

static struct mapping *md_lookup_mapping(struct metadata *md,
					 dm_block_t origin_block)
{
	struct mapping *m;
	unsigned long flags;

	spin_lock_irqsave(&md->lock, flags);
	m = __rb_lookup(md->mappings.rb_node, origin_block);
	if (m)
		list_move_tail(&m->list, &md->lru);
	spin_unlock_irqrestore(&md->lock, flags);

	return m;
}

static struct mapping *__rb_insert(struct rb_node **root,
				   dm_block_t origin_block,
				   struct rb_node *node)
{
	struct rb_node **p = root;
	struct rb_node *parent = NULL;
	struct mapping *m;

	while (*p) {
		parent = *p;
		m = rb_entry(*p, struct mapping, node);

		if (origin_block < m->origin)
			p = &(*p)->rb_left;

		else if (origin_block > m->origin)
			p = &(*p)->rb_right;

		else {
			BUG();
			return m;
		}
	}

	rb_link_node(node, parent, p);
	return NULL;
}

static int __md_insert_mapping(struct metadata *md,
			       struct mapping *m)
{
	struct mapping *tmp;

	tmp = __rb_insert(&md->mappings.rb_node, m->origin, &m->node);
	rb_insert_color(&m->node, &md->mappings);
	list_move_tail(&m->list, &md->lru);
	atomic64_set(&m->origin_gen, 0);
	atomic64_set(&m->cache_gen, 0);
	memset(&m->valid_sectors, 0, sizeof(long) * md->valid_array_size);

	return 0;
}

static int md_insert_mapping(struct metadata *md,
			     struct mapping *m)
{
	int r;
	unsigned long flags;

	spin_lock_irqsave(&md->lock, flags);
	r = __md_insert_mapping(md, m);
	spin_unlock_irqrestore(&md->lock, flags);

	return r;
}

/*
 * m should be on the pending list, and not in the rbtree.  ie. acquired
 * with md_reclaim_mapping().
 */
static void md_remove_mapping(struct metadata *md, struct mapping *m)
{
	unsigned long flags;

	spin_lock_irqsave(&md->lock, flags);
	rb_erase(&m->node, &md->mappings);
	rb_init_node(&m->node);
	list_move_tail(&m->list, &md->free);
	spin_unlock_irqrestore(&md->lock, flags);
}

/* FIXME: clean blocks should be chosen in preference? */
static struct mapping *md_idle_mapping(struct metadata *md)
{
	struct mapping *m = NULL;
	unsigned long flags;

	spin_lock_irqsave(&md->lock, flags);
	if (!list_empty(&md->lru))
		m = list_first_entry(&md->lru, struct mapping, list);
	spin_unlock_irqrestore(&md->lock, flags);

	return m;
}

/*
 * FIXME: be careful of races here, assumes calling from single thread.
 */
static int md_is_clean(struct mapping *m)
{
	return atomic64_read(&m->origin_gen) == atomic64_read(&m->cache_gen);
}

static void md_inc_origin_gen(struct mapping *m)
{
	atomic64_add(1, &m->origin_gen);
}

static void md_inc_cache_gen(struct mapping *m)
{
	atomic64_add(1, &m->cache_gen);
}

static uint64_t md_get_cache_gen(struct mapping *m)
{
	return atomic64_read(&m->cache_gen);
}

static void md_set_origin_gen(struct mapping *m, uint64_t gen)
{
	atomic64_set(&m->origin_gen, gen);
}

static void md_set_migrating(struct metadata *md, struct mapping *m, unsigned n)
{
	unsigned long flags;

	spin_lock_irqsave(&m->lock, flags);
	list_move(&m->list, n ? &md->migrating : &md->lru);
	spin_unlock_irqrestore(&m->lock, flags);

	if (n)
		atomic_sub(1, &md->nr_migrating);
	else
		atomic_add(1, &md->nr_migrating);

	wake_up(&md->migrating_wq);
}

static void md_clear_valid_sectors(struct metadata *md, struct mapping *m)
{
	unsigned i;

	for (i = 0; i < md->valid_array_size; i++)
		m->valid_sectors[i] = 0;
}

// FIXME: slow, slow, slow
static void md_mark_valid_sectors(struct metadata *md, struct mapping *m, struct bio *bio)
{
	unsigned b = bio->bi_sector & (md->block_size - 1);
	unsigned e = b + (bio->bi_size >> SECTOR_SHIFT);

	while (b != e) {
		set_bit(b, m->valid_sectors);
		b++;
	}
}

static int md_all_valid_sectors(struct metadata *md, struct mapping *m, struct bio *bio)
{
	unsigned b = bio->bi_sector & (md->block_size - 1);
	unsigned e = b + (bio->bi_size >> SECTOR_SHIFT);

	while (b != e) {
		if (!test_bit(b, m->valid_sectors))
			return 0;
		b++;
	}

	return 1;
}

/*----------------------------------------------------------------*/

/* Mechanism */

#define BLOCK_SIZE_MIN 64
#define DM_MSG_PREFIX "cache"
#define DAEMON "cached"
#define PRISON_CELLS 1024
#define ENDIO_HOOK_POOL_SIZE 10240
#define MIGRATION_POOL_SIZE 128

/* FIXME: split target from mech */
struct cache_c {
	struct dm_target *ti;

	struct dm_dev *origin_dev;
	struct dm_dev *cache_dev;

	sector_t origin_size;
	sector_t sectors_per_block;
	sector_t offset_mask;
	unsigned int block_shift;

	spinlock_t lock;
	struct bio_list deferred_bios;

	struct list_head quiesced_migrations;
	struct list_head copied_migrations;

	struct dm_kcopyd_client *copier;
	struct workqueue_struct *wq;
	struct work_struct worker;

	struct bio_prison *prison;
	struct deferred_set *all_io_ds;

	struct metadata *md;

	mempool_t *endio_hook_pool;
	mempool_t *migration_pool;

	unsigned suspending:1;

	atomic_t total;
	atomic_t read_hit;
	atomic_t read_miss;
	atomic_t read_union;
	atomic_t write_hit;
	atomic_t write_miss;
	atomic_t write_miss_partial;
	atomic_t writeback;
	atomic_t write_hit_new;
};

struct endio_hook {
	struct cache_c *cache;
	struct deferred_entry *all_io_entry;
	struct cell *cell;
};

/*
 * FIXME: add a bitmap, to allow us to specify subset migrations.
 */
struct migration {
	struct list_head list;

	unsigned to_cache:1;
	unsigned free_mapping:1;

	struct mapping *m;
	uint64_t gen;
	struct cell *cell;
	int err;
	atomic_t kcopyd_jobs;

	struct cache_c *cache;
};

static void build_key(dm_block_t block, struct cell_key *key)
{
	key->virtual = 0;
	key->dev = 0;
	key->block = block;
}

static void wake_worker(struct cache_c *cache)
{
	queue_work(cache->wq, &cache->worker);
}

/*----------------------------------------------------------------
 * Migration processing
 *--------------------------------------------------------------*/
static void cell_defer(struct cache_c *cache, struct cell *cell, int holder)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	(holder ? cell_release : cell_release_no_holder)(cell, &cache->deferred_bios);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}

static void copy_complete(int read_err, unsigned long write_err, void *context)
{
	unsigned long flags;
	struct migration *mg = (struct migration *) context;
	struct cache_c *cache = mg->cache;

	if (!mg->err)
		mg->err = read_err || write_err ? -EIO : 0;

	if (atomic_dec_and_test(&mg->kcopyd_jobs)) {
		spin_lock_irqsave(&cache->lock, flags);
		list_add(&mg->list, &cache->copied_migrations);
		spin_unlock_irqrestore(&cache->lock, flags);

		wake_worker(cache);
	}
}

static void process_quiesced(struct cache_c *cache, struct migration *mg)
{
	int r;
	struct dm_io_region o_region, c_region;

	BUG_ON(!cache);
	BUG_ON(!mg);
	BUG_ON(!mg->m);

	atomic_set(&mg->kcopyd_jobs, 0);
	o_region.bdev = cache->origin_dev->bdev;
	c_region.bdev = cache->cache_dev->bdev;

	// FIXME: refactor
	if (mg->to_cache) {
		/*
		 * Copy the whole block.
		 */
		o_region.sector = mg->m->origin * cache->sectors_per_block;
		o_region.count = cache->sectors_per_block;

		c_region.sector = mg->m->cache * cache->sectors_per_block;
		c_region.count = cache->sectors_per_block;

		atomic_inc(&mg->kcopyd_jobs);
		r = dm_kcopyd_copy(cache->copier,
				   mg->to_cache ? &o_region : &c_region,
				   1,
				   mg->to_cache ? &c_region : &o_region,
				   0, copy_complete, mg);
	} else {
		/*
		 * copy all the valid regions in the cache.
		 */
		unsigned b = 0, e = 0;

		while (e != cache->md->block_size) {
			b = e;

			while (b < cache->md->block_size && !test_bit(b, mg->m->valid_sectors))
				b++;

			if (b >= cache->md->block_size)
				break;

			e = b;

			while (e < cache->md->block_size && test_bit(e, mg->m->valid_sectors))
				e++;

			o_region.sector = mg->m->origin * cache->sectors_per_block + b;
			o_region.count = e - b;

			c_region.sector = mg->m->cache * cache->sectors_per_block + b;
			c_region.count = e - b;

			atomic_inc(&mg->kcopyd_jobs);
			r = dm_kcopyd_copy(cache->copier,
					   mg->to_cache ? &o_region : &c_region,
					   1,
					   mg->to_cache ? &c_region : &o_region,
					   0, copy_complete, mg);
			if (r)
				break;
		}
	}

	if (r < 0) {
		if (mg->cell)
			cell_defer(cache, mg->cell, 1);
		mempool_free(mg, cache->migration_pool);
	}
}

static void process_copied(struct cache_c *cache, struct migration *mg)
{
	md_set_migrating(cache->md, mg->m, 0);

	/* the migration failed, we reinsert the old mapping. */
	if (!mg->err && !mg->to_cache)
		md_set_origin_gen(mg->m, mg->gen);

	if (!mg->err && mg->free_mapping)
		md_remove_mapping(cache->md, mg->m);

	/*
	 * Even if there was an error we can release the bios from
	 * the cell and let them proceed using the old location.
	 */
	if (mg->cell)
		cell_defer(cache, mg->cell, 1);

	mempool_free(mg, cache->migration_pool);
}

static void process_migrations(struct cache_c *cache, struct list_head *head,
			       void (*fn)(struct cache_c *, struct migration *))
{
	unsigned long flags;
	struct list_head list;
	struct migration *mg, *tmp;

	INIT_LIST_HEAD(&list);
	spin_lock_irqsave(&cache->lock, flags);
	list_splice_init(head, &list);
	spin_unlock_irqrestore(&cache->lock, flags);

	list_for_each_entry_safe(mg, tmp, &list, list)
		fn(cache, mg);
}

static void migrate(struct cache_c *cache, struct mapping *m, int to_cache, int free_mapping, struct cell *cell)
{
	struct migration *mg;

	md_set_migrating(cache->md, m, 1);
	mg = mempool_alloc(cache->migration_pool, GFP_NOIO);
	mg->to_cache = to_cache;
	mg->free_mapping = free_mapping;
	mg->m = m;
	mg->gen = md_get_cache_gen(m);
	mg->cell = cell;
	mg->err = 0;
	mg->cache = cache;
	if (!ds_add_work(cache->all_io_ds, &mg->list))
		list_add_tail(&mg->list, &cache->quiesced_migrations);
}

/*----------------------------------------------------------------
 * bio processing
 *--------------------------------------------------------------*/
static int io_overlaps_block(struct cache_c *cache, struct bio *bio)
{
	return !(bio->bi_sector & cache->offset_mask) &&
		(bio->bi_size == (cache->sectors_per_block << SECTOR_SHIFT));

}

static void defer_bio(struct cache_c *cache, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_add(&cache->deferred_bios, bio);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}

static void remap_to_origin(struct cache_c *cache, struct bio *bio)
{
	bio->bi_bdev = cache->origin_dev->bdev;
}

static void remap_to_cache(struct cache_c *cache, struct bio *bio, struct mapping *m)
{
	if (bio_data_dir(bio) == WRITE) {
		md_inc_cache_gen(m);
		md_mark_valid_sectors(cache->md, m, bio);
	}

	bio->bi_bdev = cache->cache_dev->bdev;
	bio->bi_sector = (m->cache << cache->block_shift) +
		(bio->bi_sector & cache->offset_mask);
}

static dm_block_t get_bio_block(struct cache_c *cache, struct bio *bio)
{
	return bio->bi_sector >> cache->block_shift;
}

static void issue(struct cache_c *cache, struct bio *bio)
{
	if (bio->bi_rw & (REQ_FLUSH | REQ_FUA)) {
#if 0
		int r = cache_metadata_commit(cache->hmd);
		if (r) {
			bio_io_error(bio);
			return;
		}
#endif
	}

	generic_make_request(bio);
}

/*----------------------------------------------------------------*/

/*
 * Controller.
 */
#define MAX_ACTIONS 4

enum action_cmd {
	REMAP_ORIGIN,
	REMAP_CACHE,
	REMAP_NEW_CACHE,
	REMAP_UNION,		/* some of the data is on the origin, some in the cache (eek!) */

	WRITEBACK,
};

struct action {
	enum action_cmd cmd;
	struct mapping *m;
};

static void __push_action(enum action_cmd cmd, struct mapping *m,
			  struct action *actions, unsigned *count)
{
	actions[*count].cmd = cmd;
	actions[*count].m = m;
	(*count)++;
}

#define push_action(cmd, m) __push_action(cmd, m, actions, count)

/* FIXME: get rid of the cache arg */
static void get_actions(struct metadata *md,
			dm_block_t block,
			struct bio *bio,
			struct action *actions,
			unsigned *count)
{
	struct mapping *m;
	int is_write = bio_data_dir(bio) == WRITE;

	*count = 0;

	m = md_lookup_mapping(md, block);
	if (m) {
		if (!is_write && !md_all_valid_sectors(md, m, bio))
			push_action(REMAP_UNION, m);
		else
			push_action(REMAP_CACHE, m);

	} else {
		/* FIXME: too nested, too opaque */
		if (is_write) {
			m = md_alloc_mapping(md);
			if (m)
				push_action(REMAP_NEW_CACHE, m);

			else {
				m = md_idle_mapping(md);
				if (!m)
					push_action(REMAP_ORIGIN, NULL);

				else {
					if (md_is_clean(m))
						push_action(REMAP_NEW_CACHE, m);

					else {
						/* writeback this cache block so we can use it later */
						/* FIXME: how do we avoid multiple migrations? */
						push_action(WRITEBACK, m);
						push_action(REMAP_ORIGIN, NULL);
					}
				}
			}

		} else
			push_action(REMAP_ORIGIN, NULL);
	}
}

static void get_background_action(struct metadata *md,
				  struct action *actions,
				  unsigned *count)
{
	struct mapping *m;
	dm_block_t migrating_target = md->nr_cache_blocks / 16;

	*count = 0;
	if (atomic_read(&md->nr_migrating) < migrating_target) {
		list_for_each_entry(m, &md->lru, list) {
			if (!md_is_clean(m)) {
				push_action(WRITEBACK, m);
				return;
			}
		}
	}
}

/*----------------------------------------------------------------*/

static int map_bio(struct cache_c *cache, struct bio *bio)
{
	int r, i;
	dm_block_t block = get_bio_block(cache, bio);
	struct cell_key key;
	struct cell *cell;
	struct mapping *m;
	struct endio_hook *h = dm_get_mapinfo(bio)->ptr;
	int release_cell = 1;
	struct action actions[MAX_ACTIONS];
	unsigned count = 0;
	int is_write = bio_data_dir(bio) == WRITE;

	/* FIXME: paranoia */
	memset(actions, 0, sizeof(actions));

	/*
	 * Check to see if that block is currently migrating.
	 */
	build_key(block, &key);
	r = bio_detain(cache->prison, &key, bio, &cell);
	if (r > 0)
		return DM_MAPIO_SUBMITTED;

	get_actions(cache->md, block, bio, actions, &count);
	atomic_inc(&cache->total);

	r = DM_MAPIO_REMAPPED;
	for (i = 0; i < count; i++) {
		m = actions[i].m;

		switch (actions[i].cmd) {
		case REMAP_ORIGIN:
			BUG_ON(m);
			debug("REMAP_ORIGIN\n");
			atomic_inc(is_write ? &cache->write_miss : &cache->read_miss);
			remap_to_origin(cache, bio);
			break;

		case REMAP_CACHE:
			BUG_ON(!m);
			debug("REMAP_CACHE\n");
			atomic_inc(is_write ? &cache->write_hit : &cache->write_miss);
			remap_to_cache(cache, bio, m);
			break;

		case REMAP_NEW_CACHE:
			BUG_ON(!m);
			debug("REMAP_NEW_CACHE\n");
			atomic_inc(&cache->write_hit_new);
			md_remove_mapping(cache->md, m);
			m->origin = block;
			md_insert_mapping(cache->md, m);
			md_clear_valid_sectors(cache->md, m);
			h->cell = cell;
			remap_to_cache(cache, bio, m);
			release_cell = 0;
			break;

		case WRITEBACK:
			BUG_ON(!m);
			debug("REMAP_WRITEBACK\n");
			atomic_inc(&cache->writeback);
			migrate(cache, m, 0, 0, NULL);
			break;

		case REMAP_UNION:
			BUG_ON(!m);
			debug("REMAP_UNION\n");
			atomic_inc(&cache->read_union);

			/* slow, but simple ... we writeback, drop the cache entry, then retry */
			migrate(cache, m, 0, 1, cell);
			release_cell = 0;
			r = DM_MAPIO_SUBMITTED;
			break;

		default:
			BUG();
		}
		debug("done");
	}

	if (release_cell)
		cell_release_singleton(cell, bio);

	return r;
}

static void process_bio(struct cache_c *cache, struct bio *bio)
{
	struct endio_hook *h;

	switch (map_bio(cache, bio)) {
	case DM_MAPIO_REMAPPED:
		h = dm_get_mapinfo(bio)->ptr;
		h->all_io_entry = ds_inc(cache->all_io_ds);
		issue(cache, bio);
		break;

	case DM_MAPIO_SUBMITTED:
		break;

	default:
		bio_io_error(bio);
		break;
	}
}

static void process_deferred_bios(struct cache_c *cache)
{
	unsigned long flags;
	struct bio_list bios;
	struct bio *bio;

	bio_list_init(&bios);

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_merge(&bios, &cache->deferred_bios);
	bio_list_init(&cache->deferred_bios);
	spin_unlock_irqrestore(&cache->lock, flags);

	while ((bio = bio_list_pop(&bios)))
		process_bio(cache, bio);
}

static void process_background_work(struct cache_c *cache)
{
	int i;
	struct mapping *m;
	struct action actions[MAX_ACTIONS];
	unsigned count = 0;

	/* FIXME: paranoia */
	memset(actions, 0, sizeof(actions));

	do {
		get_background_action(cache->md, actions, &count);

		/* FIXME: duplicate code */
		for (i = 0; i < count; i++) {
			m = actions[i].m;

			switch (actions[i].cmd) {
			case WRITEBACK:
				BUG_ON(!m);
				debug("REMAP_WRITEBACK\n");
				atomic_inc(&cache->writeback);
				migrate(cache, m, 0, 0, NULL);
				break;

			default:
				BUG();
			}
		}

	} while (count);
}

/*----------------------------------------------------------------
 * Main worker loop
 *--------------------------------------------------------------*/
static int more_work(struct cache_c *cache)
{
	return !bio_list_empty(&cache->deferred_bios) ||
		!list_empty(&cache->quiesced_migrations) ||
		!list_empty(&cache->copied_migrations);
}

static void do_work(struct work_struct *ws)
{
	unsigned sus;
	unsigned long flags;
	struct cache_c *cache = container_of(ws, struct cache_c, worker);

	do {
		process_deferred_bios(cache);
		process_migrations(cache, &cache->quiesced_migrations, process_quiesced);
		process_migrations(cache, &cache->copied_migrations, process_copied);

		spin_lock_irqsave(&cache->lock, flags);
		sus = cache->suspending;
		spin_unlock_irqrestore(&cache->lock, flags);

		if (!sus)
			process_background_work(cache);

	} while (more_work(cache));
}

/*----------------------------------------------------------------*/

static int is_congested(struct dm_dev *dev, int bdi_bits)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);
	return bdi_congested(&q->backing_dev_info, bdi_bits);
}

static int congested(void *congested_data, int bdi_bits)
{
	struct cache_c *cache = congested_data;

	return is_congested(cache->origin_dev, bdi_bits) ||
		is_congested(cache->cache_dev, bdi_bits);
}

static void set_congestion_fn(struct cache_c *cache)
{
	struct mapped_device *md = dm_table_get_md(cache->ti->table);
	struct backing_dev_info *bdi = &dm_disk(md)->queue->backing_dev_info;

	/* Set congested function and data. */
	bdi->congested_fn = congested;
	bdi->congested_data = cache;
}

/*----------------------------------------------------------------
 * Target methods
 *--------------------------------------------------------------*/

static void cache_dtr(struct dm_target *ti)
{
	struct cache_c *cache = ti->private;

	pr_alert("dm-cache statistics:\n");
	pr_alert("total ios:\t%u\n", (unsigned) atomic_read(&cache->total));
	pr_alert("read hits:\t%u\n", (unsigned) atomic_read(&cache->read_hit));
	pr_alert("read misses:\t%u\n", (unsigned) atomic_read(&cache->read_miss));
	pr_alert("read union:\t%u\n", (unsigned) atomic_read(&cache->read_union));
	pr_alert("write hits:\t%u\n", (unsigned) atomic_read(&cache->write_hit));
	pr_alert("write misses:\t%u\n", (unsigned) atomic_read(&cache->write_miss));
	pr_alert("write misses due to partial block:\t%u\n", (unsigned) atomic_read(&cache->write_miss_partial));
	pr_alert("writebacks:\t%u\n", (unsigned) atomic_read(&cache->writeback));
	pr_alert("write hit new:\t%u\n", (unsigned) atomic_read(&cache->write_hit_new));

	mempool_destroy(cache->migration_pool);
	mempool_destroy(cache->endio_hook_pool);
	metadata_destroy(cache->md);
	ds_destroy(cache->all_io_ds);
	prison_destroy(cache->prison);
	destroy_workqueue(cache->wq);
	dm_kcopyd_client_destroy(cache->copier);
	dm_put_device(ti, cache->origin_dev);
	dm_put_device(ti, cache->cache_dev);

	kfree(cache);
}

static int get_device_(struct dm_target *ti, char *arg, struct dm_dev **dev,
		 char *errstr)
{
	int r = dm_get_device(ti, arg, FMODE_READ | FMODE_WRITE, dev);
	if (r)
		ti->error = errstr;

	return r;
}

static sector_t get_dev_size(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

/*
 * Construct a hierarchical storage device mapping:
 *
 * cache <origin dev> <cache dev> <block size>
 *
 * origin dev	   : slow device holding original data blocks
 * cache dev	   : fast device holding cached data blocks
 * data block size : cache unit size in sectors
 */
static int cache_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	dm_block_t nr_cache_blocks;
	sector_t block_size;
	struct cache_c *cache;
	char *end;

	if (argc != 3) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	block_size = simple_strtoul(argv[2], &end, 10);
	if (block_size < BLOCK_SIZE_MIN ||
	    !is_power_of_2(block_size) || *end) {
		ti->error = "Invalid data block size argument";
		return -EINVAL;
	}

	cache = ti->private = kzalloc(sizeof(*cache), GFP_KERNEL);
	if (!cache) {
		ti->error = "Error allocating cache context";
		return -ENOMEM;
	}
	cache->ti = ti;

	if (get_device_(cache->ti, argv[0], &cache->origin_dev,
			"Error opening origin device"))
		goto bad1;

	if (get_device_(cache->ti, argv[1], &cache->cache_dev,
			"Error opening cache device"))
		goto bad2;

	cache->origin_size = get_dev_size(cache->origin_dev);
	if (ti->len > cache->origin_size) {
		ti->error = "Device size larger than cached device";
		goto bad3;
	}

	cache->sectors_per_block = block_size;
	cache->offset_mask = block_size - 1;
	cache->block_shift = ffs(block_size) - 1;

	spin_lock_init(&cache->lock);
	bio_list_init(&cache->deferred_bios);

	INIT_LIST_HEAD(&cache->quiesced_migrations);
	INIT_LIST_HEAD(&cache->copied_migrations);

	cache->copier = dm_kcopyd_client_create();
	if (IS_ERR(cache->copier)) {
		ti->error = "Couldn't create kcopyd client";
		goto bad3;
	}

	cache->wq = alloc_ordered_workqueue(DAEMON, WQ_MEM_RECLAIM);
	if (!cache->wq) {
		ti->error = "couldn't create workqueue for metadata object";
		goto bad4;
	}
	INIT_WORK(&cache->worker, do_work);

	cache->prison = prison_create(PRISON_CELLS);
	if (!cache->prison) {
		ti->error = "couldn't create bio prison";
		goto bad5;
	}

	cache->all_io_ds = ds_create();
	if (!cache->all_io_ds) {
		ti->error = "couldn't create all_io deferred set";
		goto bad6;
	}

	nr_cache_blocks = get_dev_size(cache->cache_dev) >> cache->block_shift;
	cache->md = metadata_create(block_size, nr_cache_blocks);
	if (!cache->md) {
		ti->error = "couldn't create metadata";
		goto bad7;
	}

	cache->endio_hook_pool =
		mempool_create_kmalloc_pool(ENDIO_HOOK_POOL_SIZE, sizeof(struct endio_hook));
	if (!cache->endio_hook_pool) {
		ti->error = "Error creating cache's endio_hook mempool";
		goto bad8;
	}

	cache->migration_pool =
		mempool_create_kmalloc_pool(MIGRATION_POOL_SIZE, sizeof(struct migration));
	if (!cache->migration_pool) {
		ti->error = "Error creating cache's endio_hook mempool";
		goto bad9;
	}

	cache->suspending = 0;
	atomic_set(&cache->total, 0);
	atomic_set(&cache->read_hit, 0);
	atomic_set(&cache->read_miss, 0);
	atomic_set(&cache->read_union, 0);
	atomic_set(&cache->write_hit, 0);
	atomic_set(&cache->write_miss, 0);
	atomic_set(&cache->write_miss_partial, 0);
	atomic_set(&cache->writeback, 0);
	atomic_set(&cache->write_hit_new, 0);

	ti->split_io = cache->sectors_per_block;
	ti->num_flush_requests = 1;
	ti->num_discard_requests = 0;
	set_congestion_fn(cache);
	smp_wmb();
	return 0;

bad9:
	mempool_destroy(cache->migration_pool);
bad8:
	metadata_destroy(cache->md);
bad7:
	ds_destroy(cache->all_io_ds);
bad6:
	prison_destroy(cache->prison);
bad5:
	destroy_workqueue(cache->wq);
bad4:
	dm_kcopyd_client_destroy(cache->copier);
bad3:
	dm_put_device(ti, cache->cache_dev);
bad2:
	dm_put_device(ti, cache->origin_dev);
bad1:
	kfree(cache);
	return -EINVAL;
}

static int cache_map(struct dm_target *ti, struct bio *bio,
		   union map_info *map_context)
{
	struct cache_c *cache = ti->private;
	struct endio_hook *h = mempool_alloc(cache->endio_hook_pool, GFP_NOIO);

	h->cache = cache;
	h->all_io_entry = NULL;
	h->cell = NULL;
	map_context->ptr = h;

	/*
	 * Let's keep it simple to start with and defer everything.
	 */
	defer_bio(cache, bio);
	return DM_MAPIO_SUBMITTED;
}

static int cache_end_io(struct dm_target *ti, struct bio *bio,
		      int error, union map_info *info)
{
	int r = 0;
	unsigned long flags;
	struct cache_c *cache = ti->private;
	struct list_head work;
	struct endio_hook *h = info->ptr;

	INIT_LIST_HEAD(&work);
	ds_dec(h->all_io_entry, &work);

	if (!list_empty(&work)) {
		spin_lock_irqsave(&cache->lock, flags);
		list_splice(&work, &cache->quiesced_migrations);
		spin_unlock_irqrestore(&cache->lock, flags);
		wake_worker(cache);
	}

	if (h->cell)
		cell_defer(cache, h->cell, 0);

	return r;
}

static void cache_postsuspend(struct dm_target *ti)
{
	struct cache_c *cache = ti->private;
	struct metadata *md = cache->md;
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	cache->suspending = 1;
	spin_unlock_irqrestore(&cache->lock, flags);

	flush_workqueue(cache->wq);

	/*
	 * Wait for any background migrations to finish.
	 */
	wait_event(md->migrating_wq, !atomic_read(&md->nr_migrating));
}

static void cache_resume(struct dm_target *ti)
{
	struct cache_c *cache = ti->private;
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	cache->suspending = 0;
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}

static int cache_status(struct dm_target *ti, status_type_t type,
		      char *result, unsigned maxlen)
{
	ssize_t sz = 0;
	char buf[BDEVNAME_SIZE];
	struct cache_c *cache = ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		/*   <hits> <misses> */
		DMEMIT("%llu %llu", 0LL, 0LL);
		break;

	case STATUSTYPE_TABLE:
		format_dev_t(buf, cache->origin_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
		format_dev_t(buf, cache->cache_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
	}

	return 0;
}

static int cache_iterate_devices(struct dm_target *ti,
				 iterate_devices_callout_fn fn, void *data)
{
	struct cache_c *cache = ti->private;

	/*
	 * We don't include the cache device in the iteration since
	 * device_area_is_invalid checks that all iteratees are at least
	 * the size of the target.
	 */
	return fn(ti, cache->origin_dev, 0, ti->len, data);
}

static int cache_bvec_merge(struct dm_target *ti,
			  struct bvec_merge_data *bvm,
			  struct bio_vec *biovec, int max_size)
{
	struct cache_c *cache = ti->private;
	struct request_queue *q = bdev_get_queue(cache->origin_dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = cache->origin_dev->bdev;
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static void cache_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct cache_c *cache = ti->private;

	blk_limits_io_min(limits, 0);
	blk_limits_io_opt(limits, cache->sectors_per_block << SECTOR_SHIFT);
}

/*----------------------------------------------------------------*/

static struct target_type cache_target = {
	.name = "cache",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = cache_ctr,
	.dtr = cache_dtr,
	.map = cache_map,
	.end_io = cache_end_io,
	.postsuspend = cache_postsuspend,
	.resume = cache_resume,
	.status = cache_status,
	.iterate_devices = cache_iterate_devices,
	.merge = cache_bvec_merge,
	.io_hints = cache_io_hints,
};

static int __init dm_cache_init(void)
{
	int r;

	r = dm_register_target(&cache_target);
	if (r) {
		DMERR("Failed to register %s", DM_MSG_PREFIX);
	} else
		DMINFO("Registered %s", DM_MSG_PREFIX);

	return r;
}

static void dm_cache_exit(void)
{
	dm_unregister_target(&cache_target);
}

/* Module hooks */
module_init(dm_cache_init);
module_exit(dm_cache_exit);

MODULE_DESCRIPTION(DM_NAME "device-mapper cache target");
MODULE_AUTHOR("Joe Thornber <ejt@redhat.com>");
MODULE_LICENSE("GPL");

/*----------------------------------------------------------------*/

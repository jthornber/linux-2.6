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

//#define debug(x...) pr_alert(x)
#define debug(x...) ;

/*----------------------------------------------------------------*/

struct lru_queue {
	unsigned size;
	struct list_head elts;
};

static void lru_init(struct lru_queue *ll)
{
	ll->size = 0;
	INIT_LIST_HEAD(&ll->elts);
}

static unsigned lru_size(struct lru_queue *ll)
{
	return ll->size;
}

static struct list_head *lru_pop(struct lru_queue *ll)
{
	struct list_head *r;

	BUG_ON(list_empty(&ll->elts));
	r = ll->elts.next;
	list_del(r);
	ll->size--;

	return r;
}

static void lru_push(struct lru_queue *ll, struct list_head *elt)
{
	list_add_tail(elt, &ll->elts);
	ll->size++;
}

/*----------------------------------------------------------------*/

enum arc_state {
	ARC_B1,
	ARC_T1,
	ARC_B2,
	ARC_T2
};

enum arc_outcome {
	ARC_HIT,
	ARC_MISS,
	ARC_NEW,
	ARC_REPLACE
};

struct arc_entry {
	enum arc_state state;
	struct hlist_node hlist;
	struct list_head list;
	dm_block_t origin;
	dm_block_t cache;

	/* fields that aren't strictly part of the arc alg. */
	unsigned dirty:1;
};

struct arc_policy {
	dm_block_t cache_size;

	spinlock_t lock;

	dm_block_t p;		/* the magic factor that balances lru vs lfu */
	struct lru_queue b1, t1, b2, t2;

	/*
	 * We know exactly how many entries will be needed, so we can
	 * allocate them up front.
	 */
	struct arc_entry *entries;
	dm_block_t nr_allocated;

	unsigned nr_buckets;
	dm_block_t hash_mask;
	struct hlist_head *table;

	dm_block_t *interesting_blocks;
};

static struct arc_policy *arc_create(dm_block_t cache_size)
{
	dm_block_t nr_buckets;
	struct arc_policy *a = kmalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return NULL;

	a->cache_size = cache_size;
	spin_lock_init(&a->lock);
	a->p = 0;

	lru_init(&a->b1);
	lru_init(&a->t1);
	lru_init(&a->b2);
	lru_init(&a->t2);

	/* FIXME: use vmalloc ? */
	a->entries = kmalloc(sizeof(*a->entries) * 2 * cache_size, GFP_KERNEL);
	if (!a->entries) {
		kfree(a);
		return NULL;
	}

	a->nr_allocated = 0;

	a->nr_buckets = cache_size / 8;
	nr_buckets = 16;
	while (nr_buckets < a->nr_buckets)
		nr_buckets <<= 1;
	a->nr_buckets = nr_buckets;

	a->hash_mask = a->nr_buckets - 1;
	a->table = kmalloc(sizeof(*a->table) * a->nr_buckets, GFP_KERNEL);
	if (!a->table) {
		vfree(a->entries);
		kfree(a);
		return NULL;
	}

	a->interesting_blocks = kmalloc(sizeof(*a->interesting_blocks) * cache_size, GFP_KERNEL);
	if (!a->interesting_blocks) {
		kfree(a->table);
		kfree(a->entries);
		kfree(a);
	}

	return a;
}

static void arc_destroy(struct arc_policy *a)
{
	kfree(a->interesting_blocks);
	kfree(a->table);
	vfree(a->entries);
	kfree(a);
}

static unsigned hash(struct arc_policy *a, dm_block_t b)
{
	const dm_block_t BIG_PRIME = 4294967291UL;
	dm_block_t h = b * BIG_PRIME;

	return (uint32_t) (h & a->hash_mask);
}

static void __arc_insert(struct arc_policy *a, struct arc_entry *e)
{
	unsigned h = hash(a, e->origin);
	hlist_add_head(&e->hlist, a->table + h);
}

static struct arc_entry *__arc_lookup(struct arc_policy *a, dm_block_t origin)
{
	unsigned h = hash(a, origin);
	struct hlist_head *bucket = a->table + h;
	struct hlist_node *tmp;
	struct arc_entry *e;

	hlist_for_each_entry(e, tmp, bucket, hlist)
		if (e->origin == origin)
			return e;

	return NULL;
}

static void __arc_remove(struct arc_policy *a, struct arc_entry *e)
{
	hlist_del(&e->hlist);
}

/*
 * This sets up the e->cache field.
 */
static struct arc_entry *__arc_alloc_entry(struct arc_policy *a)
{
	struct arc_entry *e;

	BUG_ON(a->nr_allocated >= 2 * a->cache_size);
	e = a->entries + a->nr_allocated;
	e->cache = a->nr_allocated++;
	return e;
}

static void __arc_push(struct arc_policy *a,
		     enum arc_state s, struct arc_entry *e)
{
	e->state = s;

	switch (s) {
	case ARC_T1:
		lru_push(&a->t1, &e->list);
		__arc_insert(a, e);
		break;

	case ARC_T2:
		lru_push(&a->t2, &e->list);
		__arc_insert(a, e);
		break;

	case ARC_B1:
		lru_push(&a->b1, &e->list);
		break;

	case ARC_B2:
		lru_push(&a->b2, &e->list);
		break;
	}
}

static struct arc_entry *__arc_pop(struct arc_policy *a, enum arc_state s)
{
	struct arc_entry *e;

#define POP(x) container_of(lru_pop(x), struct arc_entry, list)

	switch (s) {
	case ARC_T1:
		e = POP(&a->t1);
		__arc_remove(a, e);
		break;

	case ARC_T2:
		e = POP(&a->t2);
		__arc_remove(a, e);
		break;

	case ARC_B1:
		e = POP(&a->b1);
		break;

	case ARC_B2:
		e = POP(&a->b2);
		break;
	}

#undef POP

	return e;
}

/*
 * fe may be NULL.
 */
static dm_block_t __arc_demote(struct arc_policy *a, struct arc_entry *fe)
{
	struct arc_entry *e;
	dm_block_t t1_size = lru_size(&a->t1);

	if (t1_size &&
	    ((t1_size > a->p) || (fe && (fe->state == ARC_B2) && (t1_size == a->p)))) {
		e = __arc_pop(a, ARC_T1);
		/* FIXME: writeback */
		__arc_push(a, ARC_B1, e);
	} else {
		e = __arc_pop(a, ARC_T2);
		/* FIXME: writeback */
		__arc_push(a, ARC_B2, e);
	}

	return e->cache;
}

/*
 * FIXME: the size of the interesting blocks hash table seems to be
 * directly related to the eviction rate.  So maybe we should resize on the
 * fly to get to a target eviction rate?
 */
static int __arc_interesting_block(struct arc_policy *a, dm_block_t origin)
{
	const dm_block_t BIG_PRIME = 4294967291UL;
	dm_block_t h = origin * BIG_PRIME;
	unsigned h = ((unsigned) (origin * BIG_PRIME)) % a->cache_size;

	if (a->interesting_blocks[h] == origin)
		return 1;

	a->interesting_blocks[h] = origin;
	return 0;
}

static enum arc_outcome __arc_map(struct arc_policy *a,
				  dm_block_t origin_block, struct arc_entry **result)
{
	enum arc_outcome r;
	dm_block_t new_cache;
	dm_block_t delta;
	dm_block_t b1_size = lru_size(&a->b1);
	dm_block_t b2_size = lru_size(&a->b2);
	dm_block_t l1_size, l2_size;

	struct arc_entry *e = __arc_lookup(a, origin_block);
	if (e) {
		switch (e->state) {
		case ARC_T1:
		case ARC_T2:
			list_del(&e->list);
			break;

		case ARC_B1:
			delta = (b1_size > b2_size) ? 1 : max(b2_size / b1_size, 1ULL);
			a->p = min(a->p + delta, a->cache_size);
			new_cache = __arc_demote(a, e);

			list_del(&e->list);

			e->origin = origin_block;
			e->cache = new_cache;
			break;

		case ARC_B2:
			delta = b2_size >= b1_size ? 1 : max(b1_size / b2_size, 1ULL);
			a->p = max(a->p - delta, 0ULL);
			new_cache = __arc_demote(a, e);

			list_del(&e->list);

			e->origin = origin_block;
			e->cache = new_cache;
			break;
		}

		__arc_push(a, ARC_T2, e);
		*result = e;
		return ARC_HIT;
	}

	if (!__arc_interesting_block(a, origin_block))
		return ARC_MISS;

	l1_size = lru_size(&a->t1) + b1_size;
	l2_size = lru_size(&a->t2) + b2_size;
	r = ARC_REPLACE;
	if (l1_size == a->cache_size) {
		if (lru_size(&a->t1) < a->cache_size) {
			e = __arc_pop(a, ARC_B1);

			new_cache = __arc_demote(a, NULL);
			e->origin = origin_block;
			e->cache = new_cache;

		} else {
			e = __arc_pop(a, ARC_T1);
			/* FIXME: writeback? */
			e->origin = origin_block;
		}

	} else if (l1_size < a->cache_size && (l1_size + l2_size >= a->cache_size)) {
		if (l1_size + l2_size == 2 * a->cache_size) {
			e = __arc_pop(a, ARC_B2);
			e->origin = origin_block;
			e->cache = __arc_demote(a, NULL);

		} else {
			e = __arc_alloc_entry(a);
			e->origin = origin_block;
			e->cache = __arc_demote(a, NULL);
		}

	} else {
		e = __arc_alloc_entry(a);
		e->origin = origin_block;
		r = ARC_NEW;
	}

	__arc_push(a, ARC_T1, e);
	*result = e;
	return r;
}

static enum arc_outcome arc_map(struct arc_policy *a, dm_block_t origin_block, struct arc_entry **result)
{
	unsigned long flags;
	enum arc_outcome r;

	spin_lock_irqsave(&a->lock, flags);
	r = __arc_map(a, origin_block, result);
	spin_unlock_irqrestore(&a->lock, flags);

	return r;
}

static void arc_mark_dirty(struct arc_policy *a, struct arc_entry *e)
{
	unsigned long flags;

	spin_lock_irqsave(&a->lock, flags);
	e->dirty = 1;
	spin_unlock_irqrestore(&a->lock, flags);
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

	/*
	 * We have a need to chain several ios, (eg, a read from the origin
	 * followed by a write to the cache).  An endio fn cannot call
	 * generic_make_request(), so we use the daemon to submit these.
	 */
	struct bio_list submit_bios;

	struct list_head quiesced_migrations;
	struct list_head copied_migrations;

	struct dm_kcopyd_client *copier;
	struct workqueue_struct *wq;
	struct work_struct worker;

	struct bio_prison *prison;
	struct deferred_set *all_io_ds;

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
	atomic_t promotion;
	atomic_t write_hit_new;
	atomic_t useless_writebacks;

	atomic_t writeback_threshold;

	/*
	 * Here are the fields I'm pulling out of the metadata object.
	 * They should probably go into the policy object eventually.
	 */
	struct list_head lru;
	wait_queue_head_t migrating_wq;
	atomic_t nr_migrating;
	struct list_head migrating;
};

struct endio_hook {
	struct list_head list;
	struct deferred_entry *all_io_entry;
	struct cell *cell;
};

/* FIXME: way too big */
struct migration {
	struct list_head list;

	unsigned to_cache:1;
	unsigned free_mapping:1;

	struct bio *bio;
	struct mapping *m;
	uint64_t gen;
	struct cell *cell;
	int err;
	atomic_t kcopyd_jobs;

	struct cache_c *cache;

	bio_end_io_t *saved_end_io;
	void *saved_private;
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
 * Remapping
 *--------------------------------------------------------------*/
static void remap_to_origin(struct cache_c *cache, struct bio *bio)
{
	bio->bi_bdev = cache->origin_dev->bdev;
}

/* FIXME: the name doesn't really indicate there's a side effect */
/* FIXME: refactor these two fns */
static void remap_to_cache(struct cache_c *cache, struct bio *bio, struct arc_entry *e)
{
	if (bio_data_dir(bio) == WRITE)
		arc_mark_dirty(a, e);

	bio->bi_bdev = cache->cache_dev->bdev;
	bio->bi_sector = (e->cache << cache->block_shift) +
		(bio->bi_sector & cache->offset_mask);
}

static dm_block_t get_bio_block(struct cache_c *cache, struct bio *bio)
{
	return bio->bi_sector >> cache->block_shift;
}

/*----------------------------------------------------------------
 * Submitted bios
 *--------------------------------------------------------------*/
static void process_submit_bios(struct cache_c *cache)
{
	unsigned long flags;
	struct bio *bio;
	struct bio_list bios;

	bio_list_init(&bios);

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_merge(&bios, &cache->submit_bios);
	bio_list_init(&cache->submit_bios);
	spin_unlock_irqrestore(&cache->lock, flags);

	while ((bio = bio_list_pop(&bios)))
		generic_make_request(bio);
}

static void __submit_bio(struct cache_c *cache, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_add(&cache->submit_bios, bio);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}

/*----------------------------------------------------------------
 * Migration processing
 *--------------------------------------------------------------*/
static void set_migrating(struct cache_c *cache, struct mapping *m, unsigned n)
{
	unsigned long flags;

	spin_lock_irqsave(&m->lock, flags);
	list_move_tail(&m->list, n ? &cache->migrating : &cache->lru);
	spin_unlock_irqrestore(&m->lock, flags);

	if (n)
		atomic_add(1, &cache->nr_migrating);
	else
		if (atomic_dec_and_test(&cache->nr_migrating)) {
			BUG_ON(!list_empty(&cache->migrating));
			wake_up(&cache->migrating_wq);
		}
}

static void cell_defer(struct cache_c *cache, struct cell *cell, int holder)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	(holder ? cell_release : cell_release_no_holder)(cell, &cache->deferred_bios);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}

static void promote_read_endio(struct bio *bio, int err)
{
	struct migration *mg = bio->bi_private;
	struct bio *dup = mg->bio;

	debug("in promote_read_endio\n");
	bio->bi_end_io = mg->saved_end_io;
	bio->bi_private = mg->saved_private;
	mg->bio = bio;
	__submit_bio(mg->cache, dup);
}

static void promote_write_endio(struct bio *bio, int err)
{
	struct migration *mg = bio->bi_private;
	struct cache_c *cache = mg->cache;

	debug("in promote_write_endio\n");
	bio_put(bio);

	set_migrating(cache, mg->m, 0);

	cache->md->mark_valid_sectors(cache->md, mg->m, bio);
	bio_endio(mg->bio, 0);
	cell_defer(cache, mg->cell, 0);
	mempool_free(mg, cache->migration_pool);
}

static void copy_via_clone(struct cache_c *cache, struct migration *mg)
{
	struct bio *bio = mg->bio;
	struct bio *dup = bio_clone(bio, GFP_NOIO);

	BUG_ON(!bio);
	BUG_ON(!dup);

	remap_to_origin(cache, bio);
	mg->saved_end_io = bio->bi_end_io;
	mg->saved_private = bio->bi_private;
	bio->bi_end_io = promote_read_endio;
	bio->bi_private = mg;

	remap_to_cache(cache, dup, mg->m);

	dup->bi_rw = WRITE;
	dup->bi_end_io = promote_write_endio;
	dup->bi_private = mg;
	mg->bio = dup;

	generic_make_request(bio);
}

static void copy_complete(int read_err, unsigned long write_err, void *context)
{
	unsigned long flags;
	struct migration *mg = (struct migration *) context;
	struct cache_c *cache = mg->cache;

	debug("in copy complete");

	if (!mg->err)
		mg->err = read_err || write_err ? -EIO : 0;

	if (atomic_dec_and_test(&mg->kcopyd_jobs)) {
		spin_lock_irqsave(&cache->lock, flags);
		list_add(&mg->list, &cache->copied_migrations);
		spin_unlock_irqrestore(&cache->lock, flags);

		wake_worker(cache);
	}
}

static void copy_via_kcopyd(struct cache_c *cache, struct migration *mg)
{
	int r;
	struct dm_io_region o_region, c_region;

	debug("in process_quiesced\n");
	BUG_ON(!cache);
	BUG_ON(!mg);
	BUG_ON(!mg->m);

	atomic_set(&mg->kcopyd_jobs, 0);
	o_region.bdev = cache->origin_dev->bdev;
	c_region.bdev = cache->cache_dev->bdev;

	// FIXME: refactor
	if (mg->to_cache) {
		debug("copying to cache\n");
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
		int submitted_something = 0;
		unsigned b = 0, e = 0;

		debug("copying to origin\n");
		while (e != cache->sectors_per_block) {
			b = e;

			while (b < cache->sectors_per_block && !test_bit(b, mg->m->valid_sectors))
				b++;

			if (b >= cache->sectors_per_block)
				break;

			e = b;

			while (e < cache->sectors_per_block && test_bit(e, mg->m->valid_sectors))
				e++;

			o_region.sector = mg->m->origin * cache->sectors_per_block + b;
			o_region.count = e - b;

			c_region.sector = mg->m->cache * cache->sectors_per_block + b;
			c_region.count = e - b;

			atomic_inc(&mg->kcopyd_jobs);

			debug("o_region.sector = %u, o_region.count = %u\n",
			      (unsigned) o_region.sector, (unsigned) o_region.count);
			debug("c_region.sector = %u, c_region.count = %u\n",
			      (unsigned) c_region.sector, (unsigned) c_region.count);

			r = dm_kcopyd_copy(cache->copier,
					   mg->to_cache ? &o_region : &c_region,
					   1,
					   mg->to_cache ? &c_region : &o_region,
					   0, copy_complete, mg);
			if (r) {
				debug("kcopyd call failed\n");
				break;
			}

			submitted_something = 1;
		}

		BUG_ON(!submitted_something);
	}

	if (r < 0) {
		if (mg->cell)
			cell_defer(cache, mg->cell, 1);
		mempool_free(mg, cache->migration_pool);
	}
}

static void process_quiesced(struct cache_c *cache, struct migration *mg)
{
	pr_alert("quiesced migration %p\n", mg);
	// (mg->to_cache ? copy_via_clone : copy_via_kcopyd)(cache, mg);
	copy_via_kcopyd(cache, mg);
}

static void process_copied(struct cache_c *cache, struct migration *mg)
{
	pr_alert("copied migration %p\n", mg);
	debug("in process_copied");
	set_migrating(cache, mg->m, 0);

	/* if the migration failed, we reinsert the old mapping. */
	if (!mg->err && !mg->to_cache) {
		cache->md->set_origin_gen(cache->md, mg->m, mg->gen);
		if (mg->gen != cache->md->get_cache_gen(cache->md, mg->m))
			atomic_inc(&cache->useless_writebacks);
	}

	if (!mg->err && mg->free_mapping)
		cache->md->remove_mapping(cache->md, mg->m);

	if (!mg->err && mg->to_cache)
		cache->md->set_valid_sectors(cache->md, mg->m);
#if 0
	if (mg->bio) {
		spin_lock_irqsave(&cache->lock, flags);
		bio_list_add(&cache->deferred_bios, mg->bio);
		spin_unlock_irqrestore(&cache->lock, flags);
		wake_worker(cache);
	}
#endif
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

static void new_migration(struct cache_c *cache, int to_cache, int free_mapping,
			  struct mapping *m, struct bio *bio, struct cell *cell)
{
	struct migration *mg;

	mg = mempool_alloc(cache->migration_pool, GFP_NOIO);
	mg->to_cache = to_cache;
	mg->free_mapping = free_mapping;
	mg->bio = bio;
	mg->m = m;
	mg->gen = cache->md->get_cache_gen(cache->md, m);
	mg->cell = cell;
	mg->err = 0;
	mg->cache = cache;

	set_migrating(cache, m, 1);
	if (!ds_add_work(cache->all_io_ds, &mg->list)) {
		list_add_tail(&mg->list, &cache->quiesced_migrations);

		// FIXME: this is the worker, so do we really need this?
		wake_worker(cache);
	}
	pr_alert("queued migration %p\n", mg);
}

static void promote(struct cache_c *cache, struct mapping *m, struct bio *bio, struct cell *cell)
{
	new_migration(cache, 1, 0, m, bio, cell);
}

static void writeback(struct cache_c *cache, struct mapping *m, int free_mapping, struct cell *cell)
{
	new_migration(cache, 0, free_mapping, m, NULL, cell);
}

/*----------------------------------------------------------------
 * bio processing
 *--------------------------------------------------------------*/
#if 0
static int io_overlaps_block(struct cache_c *cache, struct bio *bio)
{
	return !(bio->bi_sector & cache->offset_mask) &&
		(bio->bi_size == (cache->sectors_per_block << SECTOR_SHIFT));

}
#endif
static void defer_bio(struct cache_c *cache, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_add(&cache->deferred_bios, bio);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
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

static int map_bio(struct cache_c *cache, struct bio *bio)
{
	int r, i;
	dm_block_t block = get_bio_block(cache, bio);
	struct cell_key key;
	struct cell *cell;
	struct mapping *m;
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

	get_actions(cache, cache->md, block, bio, actions, &count);
	atomic_inc(&cache->total);

#if 0
	struct arc_entry *entry;
	enum arc_outcome outcome = arc_map(cache->md, block, &entry);

	*count = 0;
	switch (outcome) {
	case ARC_HIT:
		m = md->lookup_mapping(md, block); /* FIXME: duplicate lookup, the policy has already done this */
		push_action(REMAP_CACHE, m);
		break;

	case ARC_MISS:
		push_action(REMAP_ORIGIN, NULL);
		break;

	case ARC_NEW:
		m = md->lookup_by_cache(md, entry->cache);
		if (!m) {

		}
		push_action(PROMOTE, entry->cache);
		break;

	case ARC_REPLACE:

		break;
	}
#endif

	r = DM_MAPIO_REMAPPED;
	for (i = 0; i < count; i++) {
		m = actions[i].m;

		switch (actions[i].cmd) {
		case REMAP_ORIGIN:
			BUG_ON(m);
			debug("REMAP_ORIGIN\n");

			if (is_write) {
				atomic_inc(&cache->write_miss);
				atomic_inc(&cache->writeback_threshold);
			} else
				atomic_inc(&cache->read_miss);

			remap_to_origin(cache, bio);
			break;

		case REMAP_CACHE:
			BUG_ON(!m);
			debug("REMAP_CACHE\n");
			atomic_inc(is_write ? &cache->write_hit : &cache->read_hit);
			remap_to_cache(cache, bio, m);
			break;

		case REMAP_NEW_CACHE:
			BUG_ON(!m);
			debug("REMAP_NEW_CACHE\n");
			atomic_inc(&cache->write_hit_new);
			cache->md->remove_mapping(cache->md, m);
			m->origin = block;
			cache->md->insert_mapping(cache->md, m);
			list_move_tail(&m->list, &cache->lru);
			cache->md->clear_valid_sectors(cache->md, m);
			remap_to_cache(cache, bio, m);
			break;

		case WRITEBACK:
			BUG_ON(!m);
			debug("REMAP_WRITEBACK\n");
			atomic_inc(&cache->writeback);

			/*
			 * Even though we're writing back an old mapping,
			 * we don't let the bio proceed.
			 */
			writeback(cache, m, 0, cell);
			release_cell = 0;
			r = DM_MAPIO_SUBMITTED;
			break;

		case PROMOTE:
#if 1
			BUG_ON(!m);
			debug("PROMOTE\n");
			atomic_inc(&cache->promotion);
			cache->md->remove_mapping(cache->md, m);
			m->origin = block;
			cache->md->insert_mapping(cache->md, m);
			list_move_tail(&m->list, &cache->lru);
			promote(cache, m, bio, cell);
			release_cell = 0;
			r = DM_MAPIO_SUBMITTED;
#else
			remap_to_origin(cache, bio);
#endif

			break;

		case REMAP_UNION:
			BUG_ON(!m);
			debug("REMAP_UNION\n");
			atomic_inc(&cache->read_union);

			/* slow, but simple ... we writeback, drop the cache entry, then retry */
			atomic_inc(&cache->writeback);
			writeback(cache, m, 1, cell);
			release_cell = 0;
			r = DM_MAPIO_SUBMITTED;
			break;

		default:
			BUG();
		}
		debug("done");
	}

	if (release_cell)
		cell_defer(cache, cell, 0);

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
		// FIXME: all_io_entry not used?
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

/*----------------------------------------------------------------
 * Main worker loop
 *--------------------------------------------------------------*/
static int more_work(struct cache_c *cache)
{
	return !bio_list_empty(&cache->deferred_bios) ||
		!bio_list_empty(&cache->submit_bios) ||
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
		process_submit_bios(cache);

		spin_lock_irqsave(&cache->lock, flags);
		sus = cache->suspending;
		spin_unlock_irqrestore(&cache->lock, flags);

	} while (more_work(cache));
}

/*----------------------------------------------------------------*/
#if 0
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
#endif
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
	pr_alert("promotions:\t%u\n", (unsigned) atomic_read(&cache->promotion));
	pr_alert("write hit new:\t%u\n", (unsigned) atomic_read(&cache->write_hit_new));
	pr_alert("useless writebacks:\t%u\n", (unsigned) atomic_read(&cache->useless_writebacks));

	mempool_destroy(cache->migration_pool);
	mempool_destroy(cache->endio_hook_pool);
	cache->md->destroy(cache->md);
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
	bio_list_init(&cache->submit_bios);

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
	pr_alert("%u cache blocks\n", (unsigned) nr_cache_blocks);
	cache->md = dm_cache_metadata_create(block_size, nr_cache_blocks);
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
	atomic_set(&cache->useless_writebacks, 0);
	atomic_set(&cache->writeback_threshold, 0);

	INIT_LIST_HEAD(&cache->lru);
	INIT_LIST_HEAD(&cache->migrating);
	init_waitqueue_head(&cache->migrating_wq);
	atomic_set(&cache->nr_migrating, 0);

	ti->split_io = cache->sectors_per_block;
	ti->num_flush_requests = 1;
	ti->num_discard_requests = 0;
	return 0;

bad9:
	mempool_destroy(cache->migration_pool);
bad8:
	cache->md->destroy(cache->md);
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
	dm_block_t block = get_bio_block(cache, bio);
	struct cell_key key;
	struct cell *cell;
	struct endio_hook *h = mempool_alloc(cache->endio_hook_pool, GFP_NOIO);
	struct mapping *m;
	int is_write = bio_data_dir(bio) == WRITE;
	int r;
	unsigned long flags;

	h->all_io_entry = NULL;
	h->cell = NULL;
	map_context->ptr = h;

	build_key(block, &key);
	r = bio_detain_if_occupied(cache->prison, &key, bio, &cell);
	if (r > 0)
		return DM_MAPIO_SUBMITTED;

	m = cache->md->lookup_mapping(cache->md, block);
	if (m) {
		if (is_write) {
			spin_lock_irqsave(&cache->lock, flags);
			list_move_tail(&m->list, &cache->lru);
			spin_unlock_irqrestore(&cache->lock, flags);

			atomic_inc(&cache->total);
			atomic_inc(&cache->write_hit);
			h->all_io_entry = ds_inc(cache->all_io_ds);
			remap_to_cache(cache, bio, m);
			return DM_MAPIO_REMAPPED;

		} else if (cache->md->check_valid_sectors(cache->md, m, bio)) {

			spin_lock_irqsave(&cache->lock, flags);
			list_move_tail(&m->list, &cache->lru);
			spin_unlock_irqrestore(&cache->lock, flags);

			atomic_inc(&cache->total);
			atomic_inc(&cache->read_hit);
			h->all_io_entry = ds_inc(cache->all_io_ds);
			remap_to_cache(cache, bio, m);
			return DM_MAPIO_REMAPPED;

		} else {
			defer_bio(cache, bio);
			return DM_MAPIO_SUBMITTED;
		}
	}

	defer_bio(cache, bio);
	return DM_MAPIO_SUBMITTED;
}

static int cache_end_io(struct dm_target *ti, struct bio *bio,
			int error, union map_info *info)
{
	unsigned long flags;
	struct cache_c *cache = ti->private;
	struct list_head work;
	struct endio_hook *h = info->ptr;

	INIT_LIST_HEAD(&work);
	if (h->all_io_entry)
		ds_dec(h->all_io_entry, &work);

	if (!list_empty(&work)) {
		spin_lock_irqsave(&cache->lock, flags);
		list_splice(&work, &cache->quiesced_migrations);
		spin_unlock_irqrestore(&cache->lock, flags);
		wake_worker(cache);
	}

	if (h->cell)
		cell_defer(cache, h->cell, 0);

	mempool_free(h, cache->endio_hook_pool);
	return 0;
}

static void cache_postsuspend(struct dm_target *ti)
{
	struct cache_c *cache = ti->private;
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	cache->suspending = 1;
	spin_unlock_irqrestore(&cache->lock, flags);

	flush_workqueue(cache->wq);

	/*
	 * Wait for any background migrations to finish.
	 */
	wait_event(cache->migrating_wq, !atomic_read(&cache->nr_migrating));
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

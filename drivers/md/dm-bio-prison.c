/*
 * Copyright (C) 2012-2016 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#include "dm.h"
#include "dm-bio-prison.h"

#include <linux/spinlock.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/slab.h>

/*----------------------------------------------------------------*/

#define MIN_CELLS 1024

struct dm_bio_prison {
	struct workqueue_struct *wq;

	spinlock_t lock;
	mempool_t *cell_pool;
	struct rb_root cells;
};

static struct kmem_cache *_cell_cache;

/*----------------------------------------------------------------*/

/*
 * @nr_cells should be the number of cells you want in use _concurrently_.
 * Don't confuse it with the number of distinct keys.
 */
struct dm_bio_prison *dm_bio_prison_create(struct workqueue_struct *wq)
{
	struct dm_bio_prison *prison = kmalloc(sizeof(*prison), GFP_KERNEL);

	if (!prison)
		return NULL;

	prison->wq = wq;
	spin_lock_init(&prison->lock);

	prison->cell_pool = mempool_create_slab_pool(MIN_CELLS, _cell_cache);
	if (!prison->cell_pool) {
		kfree(prison);
		return NULL;
	}

	prison->cells = RB_ROOT;

	return prison;
}
EXPORT_SYMBOL_GPL(dm_bio_prison_create);

void dm_bio_prison_destroy(struct dm_bio_prison *prison)
{
	mempool_destroy(prison->cell_pool);
	kfree(prison);
}
EXPORT_SYMBOL_GPL(dm_bio_prison_destroy);

struct dm_bio_prison_cell *dm_bio_prison_alloc_cell(struct dm_bio_prison *prison, gfp_t gfp)
{
	return mempool_alloc(prison->cell_pool, gfp);
}
EXPORT_SYMBOL_GPL(dm_bio_prison_alloc_cell);

void dm_bio_prison_free_cell(struct dm_bio_prison *prison,
			     struct dm_bio_prison_cell *cell)
{
	mempool_free(cell, prison->cell_pool);
}
EXPORT_SYMBOL_GPL(dm_bio_prison_free_cell);

static void __setup_new_cell(struct dm_cell_key *key,
			     struct dm_bio_prison_cell *cell)
{
       memcpy(&cell->key, key, sizeof(cell->key));
       bio_list_init(&cell->bios);
}

static int cmp_keys(struct dm_cell_key *lhs,
		    struct dm_cell_key *rhs)
{
	if (lhs->virtual < rhs->virtual)
		return -1;

	if (lhs->virtual > rhs->virtual)
		return 1;

	if (lhs->dev < rhs->dev)
		return -1;

	if (lhs->dev > rhs->dev)
		return 1;

	if (lhs->block_end <= rhs->block_begin)
		return -1;

	if (lhs->block_begin >= rhs->block_end)
		return 1;

	return 0;
}

/*
 * Returns true if node found, otherwise it inserts a new one.
 */
static bool __find_or_insert(struct dm_bio_prison *prison,
			     struct dm_cell_key *key,
			     struct dm_bio_prison_cell *cell_prealloc,
			     struct dm_bio_prison_cell **result)
{
	int r;
	struct rb_node **new = &prison->cells.rb_node, *parent = NULL;

	while (*new) {
		struct dm_bio_prison_cell *cell =
			container_of(*new, struct dm_bio_prison_cell, node);

		r = cmp_keys(key, &cell->key);

		parent = *new;
		if (r < 0)
			new = &((*new)->rb_left);

		else if (r > 0)
			new = &((*new)->rb_right);

		else {
			*result = cell;
			return true;
		}
	}

	__setup_new_cell(key, cell_prealloc);
	*result = cell_prealloc;
	rb_link_node(&cell_prealloc->node, parent, new);
	rb_insert_color(&cell_prealloc->node, &prison->cells);

	return false;
}

static bool __get(struct dm_bio_prison *prison,
		  struct dm_cell_key *key,
		  unsigned lock_level,
		  struct bio *inmate,
		  struct dm_bio_prison_cell *cell_prealloc,
		  struct dm_bio_prison_cell **cell_result)
{
	struct dm_bio_prison_cell *cell;

	if (__find_or_insert(prison, key, cell_prealloc, &cell)) {
		if (cell->exclusive_lock && lock_level <= cell->exclusive_level) {
			bio_list_add(&cell->bios, inmate);
			*cell_result = cell;
			return false;
		}

		cell->shared_count++;
		*cell_result = cell;

	} else {
		cell = cell_prealloc;
		__setup_new_cell(key, cell);
		cell->shared_count = 1;
		*cell_result = cell;
	}

	return true;
}

bool dm_cell_get(struct dm_bio_prison *prison,
		 struct dm_cell_key *key,
		 unsigned lock_level,
		 struct bio *inmate,
		 struct dm_bio_prison_cell *cell_prealloc,
		 struct dm_bio_prison_cell **cell_result)
{
	int r;
	unsigned long flags;

	spin_lock_irqsave(&prison->lock, flags);
	r = __get(prison, key, lock_level, inmate, cell_prealloc, cell_result);
	spin_unlock_irqrestore(&prison->lock, flags);

	return r;
}
EXPORT_SYMBOL_GPL(dm_cell_get);

static bool __put(struct dm_bio_prison *prison,
		  struct dm_bio_prison_cell *cell)
{
	BUG_ON(!cell->shared_count);
	cell->shared_count--;

	if (!cell->shared_count) {
		if (cell->exclusive_lock) {
			queue_work(prison->wq, cell->quiesce_continuation);
			cell->quiesce_continuation = NULL;

		} else {
			rb_erase(&cell->node, &prison->cells);
			return true;
		}
	}

	return false;
}

bool dm_cell_put(struct dm_bio_prison *prison,
		 struct dm_bio_prison_cell *cell)
{
	bool r;
	unsigned long flags;

	spin_lock_irqsave(&prison->lock, flags);
	r = __put(prison, cell);
	spin_unlock_irqrestore(&prison->lock, flags);

	return r;
}
EXPORT_SYMBOL_GPL(dm_cell_put);

static int __lock(struct dm_bio_prison *prison,
		  struct dm_cell_key *key,
		  unsigned lock_level,
		  struct dm_bio_prison_cell *cell_prealloc,
		  struct dm_bio_prison_cell **cell_result)
{
	struct dm_bio_prison_cell *cell;

	if (__find_or_insert(prison, key, cell_prealloc, &cell)) {
		if (cell->exclusive_lock)
			return -EBUSY;

		cell->exclusive_lock = true;
		cell->exclusive_level = lock_level;
		*cell_result = cell;

		// FIXME: we don't yet know what level these shared locks
		// were taken at, so have to quiesce them all.
		return cell->shared_count > 0;

	} else {
		cell = cell_prealloc;
		__setup_new_cell(key, cell);
		cell->shared_count = 0;
		cell->exclusive_lock = true;
		cell->exclusive_level = lock_level;
		*cell_result = cell;
	}

	return 0;
}

int dm_cell_lock(struct dm_bio_prison *prison,
		 struct dm_cell_key *key,
		 unsigned lock_level,
		 struct dm_bio_prison_cell *cell_prealloc,
		 struct dm_bio_prison_cell **cell_result)
{
	int r;
	unsigned long flags;

	spin_lock_irqsave(&prison->lock, flags);
	r = __lock(prison, key, lock_level, cell_prealloc, cell_result);
	spin_unlock_irqrestore(&prison->lock, flags);

	return r;
}
EXPORT_SYMBOL_GPL(dm_cell_lock);

static void __quiesce(struct dm_bio_prison *prison,
		      struct dm_bio_prison_cell *cell,
		      struct work_struct *continuation)
{
	if (!cell->shared_count)
		queue_work(prison->wq, continuation);
	else
		cell->quiesce_continuation = continuation;
}

void dm_cell_quiesce(struct dm_bio_prison *prison,
		     struct dm_bio_prison_cell *cell,
		     struct work_struct *continuation)
{
	unsigned long flags;

	spin_lock_irqsave(&prison->lock, flags);
	__quiesce(prison, cell, continuation);
	spin_unlock_irqrestore(&prison->lock, flags);
}
EXPORT_SYMBOL_GPL(dm_cell_quiesce);

static int __promote(struct dm_bio_prison *prison,
		     struct dm_bio_prison_cell *cell,
		     unsigned new_lock_level)
{
	if (!cell->exclusive_lock)
		return -EINVAL;

	cell->exclusive_level = new_lock_level;
	return cell->shared_count > 0;
}

int dm_cell_lock_promote(struct dm_bio_prison *prison,
			 struct dm_bio_prison_cell *cell,
			 unsigned new_lock_level)
{
	int r;
	unsigned long flags;

	spin_lock_irqsave(&prison->lock, flags);
	r = __promote(prison, cell, new_lock_level);
	spin_unlock_irqrestore(&prison->lock, flags);

	return r;
}
EXPORT_SYMBOL_GPL(dm_cell_lock_promote);

static void __unlock(struct dm_bio_prison *prison,
		     struct dm_bio_prison_cell *cell,
		     struct bio_list *bios)
{
	bio_list_merge(bios, &cell->bios);
}

void dm_cell_unlock(struct dm_bio_prison *prison,
		    struct dm_bio_prison_cell *cell,
		    struct bio_list *bios)
{
	unsigned long flags;

	spin_lock_irqsave(&prison->lock, flags);
	__unlock(prison, cell, bios);
	spin_unlock_irqrestore(&prison->lock, flags);
}
EXPORT_SYMBOL_GPL(dm_cell_unlock);

/*----------------------------------------------------------------*/

static int __init dm_bio_prison_init(void)
{
	_cell_cache = KMEM_CACHE(dm_bio_prison_cell, 0);
	if (!_cell_cache)
		return -ENOMEM;

	return 0;
}

static void __exit dm_bio_prison_exit(void)
{
	kmem_cache_destroy(_cell_cache);
	_cell_cache = NULL;
}

/*
 * module hooks
 */
module_init(dm_bio_prison_init);
module_exit(dm_bio_prison_exit);

MODULE_DESCRIPTION(DM_NAME " bio prison");
MODULE_AUTHOR("Joe Thornber <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");

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
#include <linux/rwsem.h>

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
	memset(cell, 0, sizeof(*cell));
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
		  struct dm_bio_prison_cell **cell)
{
	if (__find_or_insert(prison, key, cell_prealloc, cell)) {
		if ((*cell)->exclusive_lock) {
			if (lock_level <= (*cell)->exclusive_level) {
				bio_list_add(&(*cell)->bios, inmate);
				return false;
			} else {
				pr_alert("shared lock granted whilst exclusive, req lock level = %u, exclusive level = %u\n",
					 lock_level, (*cell)->exclusive_level);
			}
		}

		(*cell)->shared_count++;

	} else
		(*cell)->shared_count = 1;

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

	// FIXME: shared locks granted above the lock level could starve this
	if (!cell->shared_count) {
		if (cell->exclusive_lock){
			if (cell->quiesce_continuation) {
				queue_work(prison->wq, cell->quiesce_continuation);
				cell->quiesce_continuation = NULL;
			}
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

static bool __unlock(struct dm_bio_prison *prison,
		     struct dm_bio_prison_cell *cell,
		     struct bio_list *bios)
{
	BUG_ON(!cell->exclusive_lock);

	bio_list_merge(bios, &cell->bios);
	bio_list_init(&cell->bios);

	if (cell->shared_count) {
		cell->exclusive_lock = 0;
		return false;
	}

	rb_erase(&cell->node, &prison->cells);
	return true;
}

bool dm_cell_unlock(struct dm_bio_prison *prison,
		    struct dm_bio_prison_cell *cell,
		    struct bio_list *bios)
{
	bool r;
	unsigned long flags;

	spin_lock_irqsave(&prison->lock, flags);
	r = __unlock(prison, cell, bios);
	spin_unlock_irqrestore(&prison->lock, flags);

	return r;
}
EXPORT_SYMBOL_GPL(dm_cell_unlock);

/*----------------------------------------------------------------*/

static void test_create_destroy(struct dm_bio_prison *prison,
				struct workqueue_struct *wq)
{
	/* empty */
}

static void test_shared_lock_ordered(struct dm_bio_prison *prison,
				     struct workqueue_struct *wq)
{
	int r;
	unsigned i;
	struct bio *bio = NULL;
	struct dm_cell_key key;
	struct dm_bio_prison_cell *prealloc;

#define COUNT 10000
	static struct dm_bio_prison_cell *cells[COUNT];

	for (i = 0; i < COUNT; i++) {
		prealloc = dm_bio_prison_alloc_cell(prison, GFP_NOWAIT);
		BUG_ON(!prealloc);

		key.virtual = 0;
		key.dev = 0;
		key.block_begin = i;
		key.block_end = i + 1;
		r = dm_cell_get(prison, &key, 0, bio, prealloc, cells + i);
		BUG_ON(!r);
		BUG_ON(cells[i] != prealloc);
	}

	for (i = 0; i < COUNT; i++) {
		BUG_ON(!dm_cell_put(prison, cells[i]));
		dm_bio_prison_free_cell(prison, cells[i]);
	}
}

static void test_shared_lock_random(struct dm_bio_prison *prison,
				    struct workqueue_struct *wq)
{
	int r;
	unsigned i;
	struct bio *bio = NULL;
	struct dm_cell_key key;
	struct dm_bio_prison_cell *prealloc;

#define COUNT 10000
	static struct dm_bio_prison_cell *cells[COUNT];

	for (i = 0; i < COUNT; i++) {
		prealloc = dm_bio_prison_alloc_cell(prison, GFP_NOWAIT);
		BUG_ON(!prealloc);

		key.virtual = 0;
		key.dev = 0;
		key.block_begin = hash_64(i, 32);
		key.block_end = key.block_end + 1;
		r = dm_cell_get(prison, &key, 0, bio, prealloc, cells + i);
		BUG_ON(!r);
		if (cells[i] != prealloc)
			dm_bio_prison_free_cell(prison, prealloc);
	}

	for (i = 0; i < COUNT; i++)
		if (dm_cell_put(prison, cells[i]))
			dm_bio_prison_free_cell(prison, cells[i]);
}

static void test_shared_repeatedly(struct dm_bio_prison *prison,
				   struct workqueue_struct *wq)
{
	int r;
	unsigned i;
	struct bio *bio = NULL;
	struct dm_cell_key key;
	struct dm_bio_prison_cell *prealloc;

	unsigned count = 1000;
	struct dm_bio_prison_cell *cell;

	prealloc = dm_bio_prison_alloc_cell(prison, GFP_NOWAIT);
	BUG_ON(!prealloc);

	key.virtual = 0;
	key.dev = 0;
	key.block_begin = hash_64(i, 32);
	key.block_end = key.block_end + 1;
	r = dm_cell_get(prison, &key, 0, bio, prealloc, &cell);
	BUG_ON(!r);
	BUG_ON(cell != prealloc);

	for (i = 1; i < count; i++) {
		prealloc = dm_bio_prison_alloc_cell(prison, GFP_NOWAIT);
		BUG_ON(!prealloc);

		r = dm_cell_get(prison, &key, 0, bio, prealloc, &cell);
		BUG_ON(!r);
		BUG_ON(cell == prealloc);
		dm_bio_prison_free_cell(prison, prealloc);
	}

	for (i = 1; i < count; i++)
		BUG_ON(dm_cell_put(prison, cell));

	BUG_ON(!dm_cell_put(prison, cell));
	dm_bio_prison_free_cell(prison, cell);
}

static void test_shared_at_different_levels(struct dm_bio_prison *prison,
					    struct workqueue_struct *wq)
{
	int r;
	unsigned i;
	struct bio *bio = NULL;
	struct dm_cell_key key;
	struct dm_bio_prison_cell *prealloc;
	struct dm_bio_prison_cell *cell;

	// Level 0
	prealloc = dm_bio_prison_alloc_cell(prison, GFP_NOWAIT);
	BUG_ON(!prealloc);

	key.virtual = 0;
	key.dev = 0;
	key.block_begin = hash_64(i, 32);
	key.block_end = key.block_end + 1;
	r = dm_cell_get(prison, &key, 0, bio, prealloc, &cell);
	BUG_ON(!r);
	BUG_ON(cell != prealloc);

	// level 1
	prealloc = dm_bio_prison_alloc_cell(prison, GFP_NOWAIT);
	BUG_ON(!prealloc);
	r = dm_cell_get(prison, &key, 1, bio, prealloc, &cell);
	BUG_ON(!r);
	BUG_ON(cell == prealloc);

	// level 2
	// prealloc wasn't used so, we can use it again.
	r = dm_cell_get(prison, &key, 2, bio, prealloc, &cell);
	BUG_ON(!r);
	BUG_ON(cell == prealloc);

	// now we need to put three times
	BUG_ON(dm_cell_put(prison, cell));
	BUG_ON(dm_cell_put(prison, cell));
	BUG_ON(!dm_cell_put(prison, cell));
	dm_bio_prison_free_cell(prison, cell);
}

static void test_exclusive(struct dm_bio_prison *prison,
			   struct workqueue_struct *wq)
{
	int r;
	unsigned i;
	struct dm_cell_key key;
	struct dm_bio_prison_cell *prealloc;
	struct dm_bio_prison_cell *excl_cell;
	struct bio_list bios;

	bio_list_init(&bios);

	prealloc = dm_bio_prison_alloc_cell(prison, GFP_NOWAIT);
	BUG_ON(!prealloc);

	key.virtual = 0;
	key.dev = 0;
	key.block_begin = hash_64(i, 32);
	key.block_end = key.block_end + 1;
	r = dm_cell_lock(prison, &key, 0, prealloc, &excl_cell);
	BUG_ON(r < 0);
	BUG_ON(r);
	BUG_ON(excl_cell != prealloc);

	dm_cell_unlock(prison, excl_cell, &bios);
	BUG_ON(!bio_list_empty(&bios));
	dm_bio_prison_free_cell(prison, excl_cell);
}

static void test_shared_then_exclusive1(struct dm_bio_prison *prison,
					struct workqueue_struct *wq)
{
	int r;
	unsigned i;
	struct bio *bio = NULL;
	struct dm_cell_key key;
	struct dm_bio_prison_cell *prealloc;
	struct dm_bio_prison_cell *excl_cell, *shd_cell;
	struct bio_list bios;

	bio_list_init(&bios);

	prealloc = dm_bio_prison_alloc_cell(prison, GFP_NOWAIT);
	BUG_ON(!prealloc);

	key.virtual = 0;
	key.dev = 0;
	key.block_begin = hash_64(i, 32);
	key.block_end = key.block_end + 1;

	r = dm_cell_get(prison, &key, 0, bio, prealloc, &shd_cell);
	BUG_ON(!r);
	BUG_ON(shd_cell != prealloc);

	prealloc = dm_bio_prison_alloc_cell(prison, GFP_NOWAIT);
	BUG_ON(!prealloc);

	r = dm_cell_lock(prison, &key, 0, prealloc, &excl_cell);
	BUG_ON(r < 0);
	BUG_ON(!r);		/* we should need a quiesce */
	BUG_ON(excl_cell != shd_cell);

	// We shouldn't unlock without quiescing first.
	dm_cell_put(prison, shd_cell);
	dm_cell_unlock(prison, excl_cell, &bios);

	BUG_ON(!bio_list_empty(&bios));
	dm_bio_prison_free_cell(prison, excl_cell);
}

#if 0
struct wrapped_semaphore {
	struct rw_semaphore sem;
	struct work_struct ws;
};

static void dec_sem(struct work_struct *ws)
{
	struct wrapped_semaphore *sem = container_of(ws, struct wrapped_semaphore, ws);
	up_read(&sem->sem);
}

struct wrapped_cell {
	struct dm_bio_prison *prison;
	struct dm_bio_prison_cell *cell;
	struct delayed_work ws;
};

static void drop_cell(struct work_struct *ws)
{
	struct delayed_work *dw = to_delayed_work(ws);
	struct wrapped_cell *wcell = container_of(dw, struct wrapped_cell, ws);
	dm_cell_put(wcell->prison, wcell->cell);
}

static void test_shared_then_exclusive2(struct dm_bio_prison *prison,
					struct workqueue_struct *wq)
{
	int r;
	unsigned i;
	struct bio *bio = NULL;
	struct dm_cell_key key;
	struct dm_bio_prison_cell *prealloc;
	struct dm_bio_prison_cell *excl_cell, *shd_cell;
	struct bio_list bios;

	struct wrapped_semaphore sem;
	struct wrapped_cell wcell;

	init_rwsem(&sem.sem);
	INIT_WORK(&sem.ws, dec_sem);

	bio_list_init(&bios);

	prealloc = dm_bio_prison_alloc_cell(prison, GFP_NOWAIT);
	BUG_ON(!prealloc);

	key.virtual = 0;
	key.dev = 0;
	key.block_begin = hash_64(i, 32);
	key.block_end = key.block_end + 1;

	r = dm_cell_get(prison, &key, 0, bio, prealloc, &shd_cell);
	BUG_ON(!r);
	BUG_ON(shd_cell != prealloc);
	down_read(&sem.sem);

	prealloc = dm_bio_prison_alloc_cell(prison, GFP_NOWAIT);
	BUG_ON(!prealloc);

	r = dm_cell_lock(prison, &key, 0, prealloc, &excl_cell);
	BUG_ON(r < 0);
	BUG_ON(!r);		/* we should need a quiesce */
	BUG_ON(excl_cell != shd_cell);

	// drop the shared locks in a bit
	wcell.prison = prison;
	wcell.cell = shd_cell;
	INIT_DELAYED_WORK(&wcell.ws, drop_cell);
	queue_delayed_work(wq, &wcell.ws, 2 * HZ);

	dm_cell_quiesce(prison, excl_cell, &sem.ws);
	up_write(&sem.sem);	/* blocks until quiesced */

	dm_cell_put(prison, shd_cell);
	dm_cell_unlock(prison, excl_cell, &bios);

	BUG_ON(!bio_list_empty(&bios));
	dm_bio_prison_free_cell(prison, excl_cell);
}
#endif

static void dm_bio_prison_unit_test(void)
{
	static struct {
		const char *name;
		void (*fn)(struct dm_bio_prison *, struct workqueue_struct *);
	} tests[] = {
		{"create/destroy", test_create_destroy},
		{"shared_lock ordered", test_shared_lock_ordered},
		{"shared_lock random", test_shared_lock_random},
		{"shared_lock repeated", test_shared_repeatedly},
		{"shared_lock at different levels", test_shared_at_different_levels},
		{"exclusive", test_exclusive},
		{"shared then exlusive needs quiescing/1", test_shared_then_exclusive1},
//		{"shared then exlusive needs quiescing/2", test_shared_then_exclusive2}
	};

	int i;
	struct workqueue_struct *wq;
	struct dm_bio_prison *prison;

	for (i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
		pr_alert("running test '%s' ... ", tests[i].name);

		wq = alloc_ordered_workqueue("dm-bio-prison-unit-test", WQ_MEM_RECLAIM);
		BUG_ON(!wq);

		prison = dm_bio_prison_create(wq);
		BUG_ON(!prison);

		tests[i].fn(prison, wq);

		dm_bio_prison_destroy(prison);
		destroy_workqueue(wq);
	}
}

/*----------------------------------------------------------------*/

static int __init dm_bio_prison_init(void)
{
	_cell_cache = KMEM_CACHE(dm_bio_prison_cell, 0);
	if (!_cell_cache)
		return -ENOMEM;

//	dm_bio_prison_unit_test();

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

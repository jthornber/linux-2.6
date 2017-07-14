/*
 * Copyright (C) 2010-2017 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#ifndef DM_THIN_BASE_H
#define DM_THIN_BASE_H

#include "dm-thin-metadata.h"
#include "dm-bio-prison-v2.h"
#include "dm-utils.h"

// FIXME: audit which of these are actually needed
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

/*----------------------------------------------------------------*/

/*
 * A pool device ties together a metadata device and a data device.  It
 * also provides the interface for creating and destroying internal
 * devices.
 */
struct throttle {
	struct rw_semaphore lock;
	unsigned long threshold;
	bool throttle_applied;
};

/*
 * The pool runs in 4 modes.  Ordered in degraded order for comparisons.
 */
enum pool_mode {
	PM_WRITE,		/* metadata may be changed */
	PM_OUT_OF_DATA_SPACE,	/* metadata may be changed, though data may not be allocated */
	PM_READ_ONLY,		/* metadata may not be changed */
	PM_FAIL,		/* all I/O fails */
};

struct pool_features {
	enum pool_mode mode;

	bool zero_new_blocks:1;
	bool discard_enabled:1;
	bool discard_passdown:1;
	bool error_if_no_space:1;
};

struct thin_c;

struct pool {
	struct list_head list;
	struct dm_target *ti;	/* Only set if a pool target is bound */

	struct mapped_device *pool_md;
	struct block_device *md_dev;
	struct dm_pool_metadata *pmd;

	dm_block_t low_water_blocks;
	uint32_t sectors_per_block;
	int sectors_per_block_shift;

	struct pool_features pf;
	bool low_water_triggered:1;	/* A dm event has been sent */
	bool suspended:1;
	bool out_of_data_space:1;

	struct dm_bio_prison_v2 *prison;
	struct dm_kcopyd_client *copier;

	struct workqueue_struct *wq;
	struct delayed_work waker;
	struct delayed_work no_space_timeout;

	unsigned long last_commit_jiffies;
	unsigned ref_count;

	spinlock_t lock;
	struct list_head active_thins;

	mempool_t *program_pool;
	struct batcher committer;
};

enum pool_mode get_pool_mode(struct pool *pool);
void metadata_operation_failed(struct pool *pool, const char *op, int r);

/*
 * Target context for a pool.
 */
struct pool_c {
	struct dm_target *ti;
	struct pool *pool;
	struct dm_dev *data_dev;
	struct dm_dev *metadata_dev;
	struct dm_target_callbacks callbacks;

	dm_block_t low_water_blocks;
	struct pool_features requested_pf; /* Features requested during table load */
	struct pool_features adjusted_pf;  /* Features used after adjusting for constituent devices */
};

/*
 * Target context for a thin.
 */
struct thin_c {
	struct list_head list;
	struct dm_dev *pool_dev;
	struct dm_dev *origin_dev;
	sector_t origin_size;
	dm_thin_id dev_id;

	struct pool *pool;
	struct dm_thin_device *td;
	struct mapped_device *thin_md;

	bool requeue_mode:1;
	spinlock_t lock;
	struct list_head deferred_cells;
	struct bio_list deferred_bio_list;
	struct bio_list retry_on_resume_list;
	struct rb_root sort_bio_list; /* sorted list of deferred bios */

	/*
	 * Ensures the thin is not destroyed until the worker has finished
	 * iterating the active_thins list.
	 */
	atomic_t refcount;
	struct completion can_destroy;
};

struct dm_thin_program;
typedef bool (*i_fn)(struct dm_thin_program *);

union value {
	void *ptr;
	uint64_t u;
};

struct instruction {
	i_fn fn;
	union value arg;
};

#define VALUE_STACK_SIZE 16

struct dm_thin_program {
	struct pool *pool;
	struct continuation k;

	spinlock_t lock;
	struct instruction *pc;

	unsigned stack_size;
	union value stack[VALUE_STACK_SIZE];

	/*
	 * A few instructions take an argument, eg, the jump offset
	 * in the on_failure instruction.
	 */
	union value arg;
	struct bio_list bios;  // prealloc
};

struct dm_thin_endio_hook {
	struct thin_c *tc;
	struct dm_thin_program *overwrite_prg;
	struct dm_bio_prison_cell_v2 *cell;
	struct rb_node rb_node;
};

void thin_get(struct thin_c *tc);
void thin_put(struct thin_c *tc);
struct thin_c *get_first_thin(struct pool *pool);
struct thin_c *get_next_thin(struct pool *pool, struct thin_c *tc);

void set_pool_mode(struct pool *pool, enum pool_mode new_mode);
int commit(struct pool *pool);
void notify_of_pool_mode_change_to_oods(struct pool *pool);
void error_retry_list_with_code(struct pool *pool, int error);
void requeue_bios(struct pool *pool);
void do_waker(struct work_struct *ws);
int thin_bio_map(struct dm_target *ti, struct bio *bio);
void noflush_work(struct thin_c *tc, void (*fn)(struct work_struct *));
void do_noflush_start(struct work_struct *ws);
void do_noflush_stop(struct work_struct *ws);

/*----------------------------------------------------------------*/

#endif

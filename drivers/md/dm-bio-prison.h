/*
 * Copyright (C) 2011 Red Hat UK.  All rights reserved.
 *
 * This file is released under the GPL.
 */

#ifndef DM_BIO_PRISON_H
#define DM_BIO_PRISON_H

#include "dm-multisnap-metadata.h"

#include <linux/list.h>

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
	dm_multisnap_dev_t dev;
	dm_block_t block;
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

/*
 * @nr_cells should be the number of cells you want in use _concurrently_.
 * Don't confuse it with the number of distinct keys.
 */
struct bio_prison *prison_create(unsigned nr_cells);
void prison_destroy(struct bio_prison *prison);

/*
 * This may block if a new cell needs allocating.  You must ensure that
 * cells will be unlocked even if the calling thread is blocked.
 *
 * returns the number of entries in the cell prior to the new addition. or
 * < 0 on failure.
 *
 * @inmate may be NULL if you just wish to prepare the cell for further
 * bios.
 */
int bio_detain(struct bio_prison *prison, struct cell_key *key,
	       struct bio *inmate, struct cell **ref);

int bio_detain_if_occupied(struct bio_prison *prison, struct cell_key *key,
			   struct bio *inmate, struct cell **ref);

void cell_release(struct cell *cell, struct bio_list *bios);
void cell_error(struct cell *cell);


/*----------------------------------------------------------------*/

/*
 * We use the deferred set to keep track of pending reads to shared blocks.
 * We do this to ensure the new mapping caused by a write isn't performed
 * until these prior reads have completed.  Otherwise the insertion of the
 * new mapping could free the old block that the read bios are mapped to.
 */
#define DEFERRED_SET_SIZE 64

struct deferred_set;
struct deferred_entry {
	struct deferred_set *ds;
	unsigned count;
	struct list_head work_items;
};

struct deferred_set {
	spinlock_t lock;
	unsigned current_entry;
	unsigned sweeper;
	struct deferred_entry entries[DEFERRED_SET_SIZE];
};

void ds_init(struct deferred_set *ds);
struct deferred_entry *ds_inc(struct deferred_set *ds);
void ds_dec(struct deferred_entry *entry, struct list_head *head);
int ds_add_work(struct deferred_set *ds, struct list_head *work);

/*----------------------------------------------------------------*/

#endif

/*
 * Copyright (C) 2012 Red Hat UK.  All rights reserved.
 *
 * This file is released under the GPL.
 */

#ifndef DM_BIO_PRISON_H
#define DM_BIO_PRISON_H

#include <linux/list.h>
#include <linux/bio.h>

/*----------------------------------------------------------------*/

/* FIXME: prefix everything */


typedef uint64_t dm_thin_id;	// FIXME: rename
typedef uint64_t dm_block_t;	// FIXME: rename

/*
 * Sometimes we can't deal with a bio straight away.  We put them in prison
 * where they can't cause any mischief.  Bios are put in a cell identified
 * by a key, multiple bios can be in the same cell.  When the cell is
 * subsequently unlocked the bios become available.
 */
struct bio_prison;
struct cell;

struct cell_key {
	int virtual;
	dm_thin_id dev;
	dm_block_t block;
};

struct bio_prison *prison_create(unsigned nr_cells);
void prison_destroy(struct bio_prison *prison);

/*
 * This may block if a new cell needs allocating.  You must ensure that
 * cells will be unlocked even if the calling thread is blocked.
 *
 * Returns 1 if the cell was already held, 0 if @inmate is the new holder.
 */
int bio_detain(struct bio_prison *prison, struct cell_key *key,
	       struct bio *inmate, struct cell **ref);

void cell_release(struct cell *cell, struct bio_list *bios);
void cell_release_singleton(struct cell *cell, struct bio *bio);
void cell_release_no_holder(struct cell *cell, struct bio_list *inmates);
void cell_error(struct cell *cell);

/*----------------------------------------------------------------*/

/*
 * We use the deferred set to keep track of pending reads to shared blocks.
 * We do this to ensure the new mapping caused by a write isn't performed
 * until these prior reads have completed.  Otherwise the insertion of the
 * new mapping could free the old block that the read bios are mapped to.
 */

struct deferred_set;
struct deferred_entry;

struct deferred_set *ds_create(void);
void ds_destroy(struct deferred_set *ds);

struct deferred_entry *ds_inc(struct deferred_set *ds);
void ds_dec(struct deferred_entry *entry, struct list_head *head);
int ds_add_work(struct deferred_set *ds, struct list_head *work);

/*----------------------------------------------------------------*/

#endif

/*
 * Copyright (C) 2012 Red Hat GmbH. All rights reserved.
 *
 * This file is released under the GPL.
 *
 */

#ifndef DM_CACHE_METADATA_H
#define DM_CACHE_METADATA_H

#include <linux/rbtree.h>

/*----------------------------------------------------------------*/

/* FIXME: most of this should be opaque. */
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

struct dm_cache_metadata {
	void (*destroy)(struct dm_cache_metadata *md);

	struct mapping *(*alloc_mapping)(struct dm_cache_metadata *md); // FIXME: not sure this should be here

	uint64_t (*get_nr_cache_blocks)(struct dm_cache_metadata *md);
	uint64_t (*get_nr_migrating)(struct dm_cache_metadata *md);

	struct mapping *(*lookup_mapping)(struct dm_cache_metadata *md, dm_block_t origin_block);
	int (*insert_mapping)(struct dm_cache_metadata *md, struct mapping *m);
	void (*remove_mapping)(struct dm_cache_metadata *md, struct mapping *m);
	struct mapping *(*idle_mapping)(struct dm_cache_metadata *md);
	int (*is_clean)(struct dm_cache_metadata *md, struct mapping *m);
	void (*set_origin_gen)(struct dm_cache_metadata *md, struct mapping *m, uint64_t gen);
	void (*inc_cache_gen)(struct dm_cache_metadata *md, struct mapping *m);
	uint64_t (*get_cache_gen)(struct dm_cache_metadata *md, struct mapping *m);
	void (*set_migrating)(struct dm_cache_metadata *md, struct mapping *m, int flag);
	void (*clear_valid_sectors)(struct dm_cache_metadata *md, struct mapping *m);
	void (*set_valid_sectors)(struct dm_cache_metadata *md, struct mapping *m);
	void (*mark_valid_sectors)(struct dm_cache_metadata *md, struct mapping *m, struct bio *bio);
	int (*all_valid_sectors)(struct dm_cache_metadata *md, struct mapping *m, struct bio *bio);

};

/* creates a temporary in-core md */
struct dm_cache_metadata *dm_cache_metadata_create(sector_t block_size, unsigned nr_cache_blocks);

/*----------------------------------------------------------------*/

#endif

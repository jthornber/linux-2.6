/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 */

#ifndef DM_CACHE_POLICY_H
#define DM_CACHE_POLICY_H

#include "persistent-data/dm-block-manager.h"

/*----------------------------------------------------------------*/

enum policy_operation {
	POLICY_HIT,
	POLICY_MISS,
	POLICY_NEW,
	POLICY_REPLACE
};

struct policy_result {
	enum policy_operation op;
	dm_block_t old_oblock;
	dm_block_t cblock;
};

struct dm_cache_policy {
	void (*destroy)(struct dm_cache_policy *p);

	/*
	 * May only return 0, or -EWOULDBLOCK
	 */
	int (*map)(struct dm_cache_policy *p, dm_block_t origin_block, int data_dir,
		   bool can_migrate, bool cheap_copy, bool can_block, struct bio *bio,
		   struct policy_result *result);

	int (*load_mapping)(struct dm_cache_policy *p, dm_block_t oblock, dm_block_t cblock);

	/* must succeed */
	void (*remove_mapping)(struct dm_cache_policy *p, dm_block_t oblock);
	void (*force_mapping)(struct dm_cache_policy *p, dm_block_t current_oblock,
			      dm_block_t new_oblock);

	dm_block_t (*residency)(struct dm_cache_policy *p);
	void (*set_seq_io_threshold)(struct dm_cache_policy *p,
				     unsigned int seq_io_thresh);

	void (*tick)(struct dm_cache_policy *p);

	void *private;		/* book keeping ptr, not for general use */
};

/*----------------------------------------------------------------*/

static inline int policy_map(struct dm_cache_policy *p, dm_block_t origin_block, int data_dir,
			      bool can_migrate, bool cheap_copy, bool can_block, struct bio *bio,
			      struct policy_result *result)
{
	return p->map(p, origin_block, data_dir, can_migrate, cheap_copy, can_block, bio, result);
}

static inline int policy_load_mapping(struct dm_cache_policy *p, dm_block_t oblock, dm_block_t cblock)
{
	return p->load_mapping(p, oblock, cblock);
}

static inline void policy_remove_mapping(struct dm_cache_policy *p, dm_block_t oblock)
{
	return p->remove_mapping(p, oblock);
}

static inline void policy_force_mapping(struct dm_cache_policy *p,
			dm_block_t current_oblock, dm_block_t new_oblock)
{
	return p->force_mapping(p, current_oblock, new_oblock);
}

static inline dm_block_t policy_residency(struct dm_cache_policy *p)
{
	return p->residency(p);
}

static inline void policy_set_seq_io_threshold(struct dm_cache_policy *p, unsigned int seq_io_thresh)
{
	return p->set_seq_io_threshold(p, seq_io_thresh);
}

static inline void policy_tick(struct dm_cache_policy *p)
{
	return p->tick(p);
}

/*----------------------------------------------------------------*/

/*
 * We maintain a little register of the different policy types.
 */
#define CACHE_POLICY_NAME_MAX 16

struct dm_cache_policy_type {
	struct list_head list;

	char name[CACHE_POLICY_NAME_MAX];
	struct module *owner;
	struct dm_cache_policy *(*create)(dm_block_t cache_size);
};

int dm_cache_policy_register(struct dm_cache_policy_type *type);
void dm_cache_policy_unregister(struct dm_cache_policy_type *type);

struct dm_cache_policy *dm_cache_policy_create(const char *name, dm_block_t cache_size);

void dm_cache_policy_destroy(struct dm_cache_policy *p);

const char *dm_cache_policy_get_name(struct dm_cache_policy *p);

/*----------------------------------------------------------------*/

#endif

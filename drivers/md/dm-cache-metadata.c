/*
 * Copyright (C) 2012 Red Hat GmbH. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include <linux/blkdev.h>
#include <linux/rbtree.h>
#include "dm-bio-prison.h"
#include "dm-cache-metadata.h"
#include "dm.h"

/*----------------------------------------------------------------*/

/*
 * Simple, in-core metadata, just a quick hack for development.
 */
struct metadata {
	struct dm_cache_metadata md;

	sector_t block_size;
	dm_block_t nr_cache_blocks;

	spinlock_t lock;
	struct list_head free;	  /* unallocated */
	struct rb_root mappings;

	unsigned valid_array_size; /* how many ulongs are in the mapping->valid_sectors arrays */
};

#define DECLARE_MD struct metadata *md = container_of(cmd, struct metadata, md)

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

static void md_destroy(struct dm_cache_metadata *cmd)
{
	DECLARE_MD;
	struct mapping *m;

	/* Slow, but in-core isn't for production anyway. */
	while (!RB_EMPTY_ROOT(&md->mappings)) {
		m = rb_entry(rb_first(&md->mappings), struct mapping, node);
		rb_erase(&m->node, &md->mappings);
	}

	free_list(&md->free);
	kfree(md);
}

static uint64_t md_get_nr_cache_blocks(struct dm_cache_metadata *cmd)
{
	DECLARE_MD;
	return md->nr_cache_blocks;
}

static struct mapping *__md_new_mapping(struct metadata *md)
{
	struct mapping *m;

	if (list_empty(&md->free))
		return NULL;

	m = list_first_entry(&md->free, struct mapping, list);
	if (m)
		list_del_init(&m->list);

	return m;
}

static struct mapping *md_new_mapping(struct dm_cache_metadata *cmd)
{
	DECLARE_MD;
	struct mapping *m;
	unsigned long flags;

	spin_lock_irqsave(&md->lock, flags);
	m = __md_new_mapping(md);
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

static struct mapping *md_lookup_mapping(struct dm_cache_metadata *cmd,
					 dm_block_t origin_block)
{
	DECLARE_MD;
	struct mapping *m;
	unsigned long flags;

	spin_lock_irqsave(&md->lock, flags);
	m = __rb_lookup(md->mappings.rb_node, origin_block);
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
	atomic64_set(&m->origin_gen, 0);
	atomic64_set(&m->cache_gen, 0);
	memset(&m->valid_sectors, 0, sizeof(long) * md->valid_array_size);

	return 0;
}

static int md_insert_mapping(struct dm_cache_metadata *cmd,
			     struct mapping *m)
{
	DECLARE_MD;
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
static void md_remove_mapping(struct dm_cache_metadata *cmd, struct mapping *m)
{
	DECLARE_MD;
	unsigned long flags;

	spin_lock_irqsave(&md->lock, flags);
	rb_erase(&m->node, &md->mappings);
	rb_init_node(&m->node);
	list_move_tail(&m->list, &md->free);
	spin_unlock_irqrestore(&md->lock, flags);
}

/*
 * FIXME: be careful of races here, assumes calling from single thread.
 */
static int md_is_clean(struct dm_cache_metadata *cmd, struct mapping *m)
{
	return atomic64_read(&m->origin_gen) == atomic64_read(&m->cache_gen);
}

static void md_inc_cache_gen(struct dm_cache_metadata *cmd, struct mapping *m)
{
	atomic64_add(1, &m->cache_gen);
}

static uint64_t md_get_cache_gen(struct dm_cache_metadata *cmd, struct mapping *m)
{
	return atomic64_read(&m->cache_gen);
}

static void md_set_origin_gen(struct dm_cache_metadata *cmd, struct mapping *m, uint64_t gen)
{
	// FIXME: check the atomicity guarantees of this
	atomic64_set(&m->origin_gen, gen);
}

static void md_clear_valid_sectors(struct dm_cache_metadata *cmd, struct mapping *m)
{
	DECLARE_MD;
	memset(&m->valid_sectors, 0, sizeof(long) * md->valid_array_size);
}

static void md_set_valid_sectors(struct dm_cache_metadata *cmd, struct mapping *m)
{
	DECLARE_MD;
	memset(&m->valid_sectors, -1, sizeof(long) * md->valid_array_size);
}

// FIXME: slow, slow, slow
static void md_mark_valid_sectors(struct dm_cache_metadata *cmd, struct mapping *m, struct bio *bio)
{
	DECLARE_MD;
	unsigned b = bio->bi_sector & (md->block_size - 1);
	unsigned e = b + (bio->bi_size >> SECTOR_SHIFT);

	while (b != e) {
		set_bit(b, m->valid_sectors);
		b++;
	}
}

static int md_check_valid_sectors(struct dm_cache_metadata *cmd, struct mapping *m, struct bio *bio)
{
	DECLARE_MD;
	unsigned b = bio->bi_sector & (md->block_size - 1);
	unsigned e = b + (bio->bi_size >> SECTOR_SHIFT);

	while (b != e) {
		if (!test_bit(b, m->valid_sectors))
			return 0;
		b++;
	}

	return 1;
}

struct dm_cache_metadata *dm_cache_metadata_create(sector_t block_size, unsigned nr_cache_blocks)
{
	dm_block_t b;
	size_t mapping_size;
	struct mapping *m;
	struct metadata *md = kmalloc(sizeof(*md), GFP_KERNEL);
	if (!md)
		return NULL;

	md->md.destroy = md_destroy;
	md->md.get_nr_cache_blocks = md_get_nr_cache_blocks;
	md->md.new_mapping = md_new_mapping;

	md->md.lookup_mapping = md_lookup_mapping;
	md->md.insert_mapping = md_insert_mapping;
	md->md.remove_mapping = md_remove_mapping;

	md->md.is_clean = md_is_clean;
	md->md.set_origin_gen = md_set_origin_gen;
	md->md.inc_cache_gen = md_inc_cache_gen;
	md->md.get_cache_gen = md_get_cache_gen;

	md->md.clear_valid_sectors = md_clear_valid_sectors;
	md->md.set_valid_sectors = md_set_valid_sectors;
	md->md.mark_valid_sectors = md_mark_valid_sectors;
	md->md.check_valid_sectors = md_check_valid_sectors;

	md->valid_array_size = div_up(block_size, BITS_PER_LONG);
	mapping_size = sizeof(struct mapping) + md->valid_array_size * sizeof(unsigned long);

	md->block_size = block_size;
	md->nr_cache_blocks = nr_cache_blocks;
	spin_lock_init(&md->lock);

	INIT_LIST_HEAD(&md->free);
	md->mappings = RB_ROOT;

	for (b = 0; b < nr_cache_blocks; b++) {
		/* FIXME: use a slab */
		m = kmalloc(mapping_size, GFP_KERNEL);
		if (!m) {
			md_destroy(&md->md);
			return NULL;
		}

		spin_lock_init(&m->lock);
		INIT_LIST_HEAD(&m->list);
		rb_init_node(&m->node);
		m->origin = 0;
		m->cache = b;

		list_add_tail(&m->list, &md->free);
	}

	return &md->md;
}

/*----------------------------------------------------------------*/

#include "btree.h"
#include "space-map-staged.h"

/* FIXME: this will vary depending on the transaction size */
#define CACHE_MIN 10240

/* we have a little hash table of the reference count changes */
struct cache_entry {
	struct list_head lru;
	struct hlist_node hash;

	dm_block_t block;
	uint32_t ref_count;	/* Ref count from last transaction */
	int32_t delta;		/* how this has changed within the current transaction */
	int32_t unwritten;      /* what still needs to be written to the current transaction */
};

#define NR_BUCKETS 1024
#define MASK (NR_BUCKETS - 1)
#define PRIME 4294967291UL

struct sm_staged {
	struct kmem_cache *slab;
	mempool_t *pool;
	struct list_head deltas;
	struct hlist_head buckets[NR_BUCKETS];

	struct space_map *sm_wrapped;
	dm_block_t maybe_first_free;
};

/*----------------------------------------------------------------*/

/* FIXME: we're hashing blocks elsewhere, factor out the hash fn */
static unsigned hash_block(dm_block_t b)
{
	return (b * PRIME) & MASK;
}

static struct cache_entry *find_entry(struct sm_staged *sm, dm_block_t b)
{
	struct hlist_node *l;
	struct cache_entry *ce;

	hlist_for_each_entry (ce, l, sm->buckets + hash_block(b), hash) {
		if (ce->block == b)
			return ce;
	}

	return NULL;
}

/*
 * Only call this if you know the entry is _not_ already present.
 */
static struct cache_entry *add_entry(struct sm_staged *sm, dm_block_t b, uint32_t ref_count)
{
	struct cache_entry *ce = mempool_alloc(sm->pool, GFP_NOIO);

	if (!ce)
		return NULL;

	list_add(&ce->lru, &sm->deltas);
	hlist_add_head(&ce->hash, sm->buckets + hash_block(b));
	ce->block = b;
	ce->ref_count = ref_count;
	ce->delta = 0;
	ce->unwritten = 0;
	return ce;
}

static int add_delta(struct sm_staged *sm, dm_block_t b, int32_t delta)
{
	int r;
	struct cache_entry *ce = find_entry(sm, b);

	if (!ce) {
		uint32_t ref_count = 0;
		r = sm_get_count(sm->sm_wrapped, b, &ref_count);
		if (r < 0)
			return r;

		ce = add_entry(sm, b, ref_count);
		if (!ce)
			return -ENOMEM;
	}

	ce->delta += delta;
	ce->unwritten += delta;

	if (ce->unwritten)
		list_move(&ce->lru, &sm->deltas);
	else {
		/* deltas have cancelled each other out */
		list_del(&ce->lru);
		INIT_LIST_HEAD(&ce->lru); /* FIXME: why is this needed? */
	}

	if (ce->delta < 0)
		BUG_ON(ce->ref_count < -ce->delta);

	return 0;
}

static struct sm_staged *sm_alloc(struct space_map *sm_wrapped)
{
	unsigned i;
	struct sm_staged *sm = kmalloc(sizeof(*sm), GFP_KERNEL);

	if (!sm)
		return NULL;

	sm->sm_wrapped = sm_wrapped;
	sm->maybe_first_free = 0;

	sm->slab = kmem_cache_create("space_map_cache_entries",
				     sizeof(struct cache_entry),
				     0,
				     SLAB_HWCACHE_ALIGN,
				     NULL);
	if (!sm->slab) {
		kfree(sm);
		return NULL;
	}

	sm->pool = mempool_create_slab_pool(CACHE_MIN, sm->slab);
	if (!sm->pool) {
		kmem_cache_destroy(sm->slab);
		kfree(sm);
		return NULL;
	}

	INIT_LIST_HEAD(&sm->deltas);
	for (i = 0; i < NR_BUCKETS; i++)
		INIT_HLIST_HEAD(sm->buckets + i);

	return sm;
}

static void inc_entry(struct sm_staged *sm, struct cache_entry *ce)
{
	list_move(&ce->lru, &sm->deltas);
	ce->delta++;
	ce->unwritten++;
}

static int get_free_in_range_(struct sm_staged *sm, dm_block_t low, dm_block_t high, struct cache_entry **ce)
{
	int r;
	dm_block_t b, nr_blocks;

	r = sm_get_nr_blocks(sm->sm_wrapped, &nr_blocks);
	if (r < 0)
		return r;

retry:
	low = max(low, sm->maybe_first_free);
	high = min(high, nr_blocks);
	if (low >= high)
		return -ENOSPC;

	/*
	 * We don't recycle |ce| entries that have ref_count +
	 * delta == 0 for fear of trashing the previous transaction
	 * before this one is totally committed.
	 *
	 * We could check the hash for blocks that have been _both_
	 * allocated and freed within this transaction.
	 */
	r = sm_get_free_in_range(sm->sm_wrapped, low, high, &b);
	if (r < 0)
		return r;

	*ce = find_entry(sm, b);
	if (!*ce) {
		*ce = add_entry(sm, b, 0);
		if (!*ce)
			return -ENOMEM;

		sm->maybe_first_free = b + 1;
		return 0;
	}

	/* if we already have an entry does that mean it's been allocated
	 * in this transaction already? */
	sm->maybe_first_free = b + 1;
	goto retry;		/* FIXME: not sure why this happens */

	/* never get here */
	return -ENOMEM;
}

static int flush_once(struct sm_staged *sm)
{
	int r;
	struct list_head head;
	struct cache_entry *ce, *tmp;

	INIT_LIST_HEAD(&head);
	list_splice(&sm->deltas, &head);
	INIT_LIST_HEAD(&sm->deltas);

	list_for_each_entry_safe (ce, tmp, &head, lru) {
		uint32_t shadow = ce->unwritten;
		if (!ce->unwritten)
			continue;

		r = sm_set_count(sm->sm_wrapped, ce->block, ce->ref_count + shadow);
		if (r < 0)
			return r;

		/*
		 * The |unwritten| value may have increased as a result of
		 * the insert above.  So we subtract |shadow|, rather than
		 * setting to 0.
		 */
		ce->unwritten -= shadow;
	}

	return 0;
}

/*----------------------------------------------------------------*/

static void destroy(void *context)
{
	struct sm_staged *sm = (struct sm_staged *) context;
	struct cache_entry *ce, *tmp;

	if (sm->sm_wrapped)
		sm_destroy(sm->sm_wrapped);

	list_for_each_entry_safe (ce, tmp, &sm->deltas, lru) {
		mempool_free(ce, sm->pool);
	}

	mempool_destroy(sm->pool);
	kmem_cache_destroy(sm->slab);
	kfree(sm);
}

static int get_nr_blocks(void *context, dm_block_t *count)
{
	struct sm_staged *sm = (struct sm_staged *) context;
	return sm_get_nr_blocks(sm->sm_wrapped, count);
}

static int get_count(void *context, dm_block_t b, uint32_t *result)
{
	struct sm_staged *sm = (struct sm_staged *) context;
	struct cache_entry *ce = find_entry(sm, b);

	if (ce) {
		*result = ce->ref_count + ce->delta;
		return 0;
	}

	return sm_get_count(sm->sm_wrapped, b, result);
}

static int set_count(void *context, dm_block_t b, uint32_t count)
{
	/* FIXME: inefficient */
	int r;
	uint32_t old_count;
	int32_t delta;
	struct sm_staged *sm = (struct sm_staged *) context;

	r = get_count(context, b, &old_count);
	if (r < 0)
		return r;

	if (count > old_count)
		delta = (int32_t) (count - old_count);
	else
		delta = - (int32_t) (old_count - count);

	return add_delta(sm, b, delta);
}

static int get_free_in_range(void *context, dm_block_t low, dm_block_t high, dm_block_t *b)
{
	int r;
	struct sm_staged *sm = (struct sm_staged *) context;
	struct cache_entry *ce;

	r = get_free_in_range_(sm, low, high, &ce);
	if (r < 0)
		return r;

	*b = ce->block;
	return r;
}
static int get_free(void *context, dm_block_t *b)
{
	int r;
	dm_block_t nr_blocks;
	struct sm_staged *sm = (struct sm_staged *) context;
	r = sm_get_nr_blocks(sm->sm_wrapped, &nr_blocks);
	if (r < 0)
		return r;

	return get_free_in_range(context, 0, nr_blocks, b);
}

static int inc_block(void *context, dm_block_t b)
{
	struct sm_staged *sm = (struct sm_staged *) context;
	return add_delta(sm, b, 1);
}

static int dec_block(void *context, dm_block_t b)
{
	struct sm_staged *sm = (struct sm_staged *) context;
	return add_delta(sm, b, -1);
}

static int new_block(void *context, dm_block_t *b)
{
	int r;
	dm_block_t nr_blocks;
	struct sm_staged *sm = (struct sm_staged *) context;
	struct cache_entry *ce;

	r = sm_get_nr_blocks(sm->sm_wrapped, &nr_blocks);
	if (r < 0)
		return r;

	r = get_free_in_range_(context, 0, nr_blocks, &ce);
	if (r < 0)
		return r;

	inc_entry(sm, ce);
	*b = ce->block;
	return r;
}

static int root_size(void *context, size_t *result)
{
	struct sm_staged *sm = (struct sm_staged *) context;
	return sm_root_size(sm->sm_wrapped, result);
}

static int copy_root(void *context, void *copy_to_here, size_t len)
{
	struct sm_staged *sm = (struct sm_staged *) context;
	return sm_copy_root(sm->sm_wrapped, copy_to_here, len);
}

static int commit(void *context)
{
	int r;
	unsigned i;
	struct sm_staged *sm = (struct sm_staged *) context;

	while (!list_empty(&sm->deltas)) {
		r = flush_once(sm);
		if (r < 0)
			return r;
	}

	/* wipe the cache completely */
	for (i = 0; i < NR_BUCKETS; i++) {
		struct cache_entry *ce;
		struct hlist_node *l, *tmp;
		hlist_for_each_entry_safe (ce, l, tmp, sm->buckets + i, hash) {
			mempool_free(ce, sm->pool);
		}
		INIT_HLIST_HEAD(sm->buckets + i);
	}

	return 0;
}

/*----------------------------------------------------------------*/

static struct space_map_ops combined_ops_ = {
	.destroy = destroy,
	.get_nr_blocks = get_nr_blocks,
	.get_count = get_count,
	.set_count = set_count,
	.get_free = get_free,
	.get_free_in_range = get_free_in_range,
	.inc_block = inc_block,
	.dec_block = dec_block,
	.new_block = new_block,
	.root_size = root_size,
	.copy_root = copy_root,
	.commit = commit,
};

struct space_map *sm_staged_create(struct space_map *wrappee)
{
	struct space_map *sm = NULL;
	struct sm_staged *smc = sm_alloc(wrappee);
	if (smc) {
		sm = kmalloc(sizeof(*sm), GFP_KERNEL);
		if (!sm) {
			kfree(smc);
		} else {
			sm->ops = &combined_ops_;
			sm->context = smc;
		}
	}

	return sm;
}
EXPORT_SYMBOL_GPL(sm_staged_create);

int sm_staged_set_wrappee(struct space_map *sm,
			  struct space_map *wrappee)
{
	struct sm_staged *staged = (struct sm_staged *) sm->context;
	staged->sm_wrapped = wrappee;
	return 0;
}
EXPORT_SYMBOL_GPL(sm_staged_set_wrappee);

/*----------------------------------------------------------------*/

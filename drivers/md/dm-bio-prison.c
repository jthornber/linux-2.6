#include "dm-bio-prison.h"

/*----------------------------------------------------------------*/

static uint32_t calc_nr_buckets(unsigned nr_cells)
{
	uint32_t n = 128;
	nr_cells /= 4;
	nr_cells = min(nr_cells, 8192u);
	while (n < nr_cells)
		n <<= 1;

	return n;
}

/*
 * @nr_cells should be the number of cells you want in use _concurrently_.
 * Don't confuse it with the number of distinct keys.
 */
struct bio_prison *prison_create(unsigned nr_cells)
{
	int i;
	uint32_t nr_buckets = calc_nr_buckets(nr_cells);
	size_t len = sizeof(struct bio_prison) +
		(sizeof(struct hlist_head) * nr_buckets);
	struct bio_prison *prison = kmalloc(len, GFP_KERNEL);
	if (!prison)
		return NULL;

	spin_lock_init(&prison->lock);
	prison->cell_pool = mempool_create_kmalloc_pool(nr_cells,
						      sizeof(struct cell));
	prison->nr_buckets = nr_buckets;
	prison->hash_mask = nr_buckets - 1;
	prison->cells = (struct hlist_head *) (prison + 1);
	for (i = 0; i < nr_buckets; i++)
		INIT_HLIST_HEAD(prison->cells + i);

	return prison;
}

void prison_destroy(struct bio_prison *prison)
{
	mempool_destroy(prison->cell_pool);
	kfree(prison);
}

static uint32_t hash_key(struct bio_prison *prison, struct cell_key *key)
{
	const unsigned BIG_PRIME = 4294967291UL;
	uint64_t hash = key->block * BIG_PRIME;
	return (uint32_t) (hash & prison->hash_mask);
}

static struct cell *__search_bucket(struct hlist_head *bucket, struct cell_key *key)
{
	struct cell *cell;
	struct hlist_node *tmp;

	hlist_for_each_entry (cell, tmp, bucket, list)
		if (!memcmp(&cell->key, key, sizeof(cell->key)))
			return cell;

	return NULL;
}

/*
 * This may block if a new cell needs allocating.  You must ensure that
 * cells will be unlocked even if the calling thread is blocked.
 *
 * returns the number of entries in the cell prior to the new addition. or
 * < 0 on failure.
 */
int bio_detain(struct bio_prison *prison, struct cell_key *key,
	       struct bio *inmate, struct cell **ref)
{
	int r;
	unsigned long flags;
	uint32_t hash = hash_key(prison, key);
	struct cell *uninitialized_var(cell), *cell2 = NULL;

	BUG_ON(hash > prison->nr_buckets);

	spin_lock_irqsave(&prison->lock, flags);
	cell = __search_bucket(prison->cells + hash, key);

	if (!cell) {
		/* allocate a new cell */
		spin_unlock_irqrestore(&prison->lock, flags);
		cell2 = mempool_alloc(prison->cell_pool, GFP_NOIO);
		spin_lock_irqsave(&prison->lock, flags);

		/*
		 * We've been unlocked, so we have to double check that
		 * nobody else has inserted this cell in the mean time.
		 */
		cell = __search_bucket(prison->cells + hash, key);

		if (!cell) {
			cell = cell2;
			cell2 = NULL;

			cell->prison = prison;
			memcpy(&cell->key, key, sizeof(cell->key));
			cell->count = 0;
			bio_list_init(&cell->bios);
			hlist_add_head(&cell->list, prison->cells + hash);
		}
	}

	r = cell->count++;
	if (inmate)
		bio_list_add(&cell->bios, inmate);
	spin_unlock_irqrestore(&prison->lock, flags);

	if (cell2)
		mempool_free(cell2, prison->cell_pool);

	*ref = cell;
	return r;
}

int bio_detain_if_occupied(struct bio_prison *prison, struct cell_key *key,
			   struct bio *inmate, struct cell **ref)
{
	int r;
	unsigned long flags;
	uint32_t hash = hash_key(prison, key);
	struct cell *uninitialized_var(cell);

	BUG_ON(hash > prison->nr_buckets);

	spin_lock_irqsave(&prison->lock, flags);
	cell = __search_bucket(prison->cells + hash, key);

	if (!cell) {
		spin_unlock_irqrestore(&prison->lock, flags);
		return 0;
	}

	r = cell->count++;
	bio_list_add(&cell->bios, inmate);
	spin_unlock_irqrestore(&prison->lock, flags);

	*ref = cell;
	return r;
}

/* @inmates must have been initialised prior to this call */
static void __cell_release(struct cell *cell, struct bio_list *inmates)
{
	struct bio_prison *prison = cell->prison;
	hlist_del(&cell->list);
	if (inmates)
		bio_list_merge(inmates, &cell->bios);
	mempool_free(cell, prison->cell_pool);
}

void cell_release(struct cell *cell, struct bio_list *bios)
{
	unsigned long flags;
	struct bio_prison *prison = cell->prison;

	spin_lock_irqsave(&prison->lock, flags);
	__cell_release(cell, bios);
	spin_unlock_irqrestore(&prison->lock, flags);
}

void cell_error(struct cell *cell)
{
	struct bio_prison *prison = cell->prison;
	struct bio_list bios;
	struct bio *bio;
	unsigned long flags;

	bio_list_init(&bios);

	spin_lock_irqsave(&prison->lock, flags);
	__cell_release(cell, &bios);
	spin_unlock_irqrestore(&prison->lock, flags);

	while ((bio = bio_list_pop(&bios)))
		bio_io_error(bio);
}

/*----------------------------------------------------------------*/

void ds_init(struct deferred_set *ds)
{
	int i;

	spin_lock_init(&ds->lock);
	ds->current_entry = 0;
	ds->sweeper = 0;
	for (i = 0; i < DEFERRED_SET_SIZE; i++) {
		ds->entries[i].ds = ds;
		ds->entries[i].count = 0;
		INIT_LIST_HEAD(&ds->entries[i].work_items);
	}
}

struct deferred_entry *ds_inc(struct deferred_set *ds)
{
	unsigned long flags;
	struct deferred_entry *entry;

	spin_lock_irqsave(&ds->lock, flags);
	entry = ds->entries + ds->current_entry;
	entry->count++;
	spin_unlock_irqrestore(&ds->lock, flags);

	return entry;
}

static unsigned ds_next(unsigned index)
{
	return (index + 1) % DEFERRED_SET_SIZE;
}

static void __sweep(struct deferred_set *ds, struct list_head *head)
{
	while ((ds->sweeper != ds->current_entry) && !ds->entries[ds->sweeper].count) {
		list_splice_init(&ds->entries[ds->sweeper].work_items, head);
		ds->sweeper = ds_next(ds->sweeper);
	}

	if ((ds->sweeper == ds->current_entry) && !ds->entries[ds->sweeper].count)
		list_splice_init(&ds->entries[ds->sweeper].work_items, head);
}

void ds_dec(struct deferred_entry *entry, struct list_head *head)
{
	unsigned long flags;

	spin_lock_irqsave(&entry->ds->lock, flags);
	BUG_ON(!entry->count);
	--entry->count;
	__sweep(entry->ds, head);
	spin_unlock_irqrestore(&entry->ds->lock, flags);
}

/* 1 if deferred, 0 if no pending items to delay job */
int ds_add_work(struct deferred_set *ds, struct list_head *work)
{
	int r = 1;
	unsigned long flags;
	unsigned next_entry;

	spin_lock_irqsave(&ds->lock, flags);
	if ((ds->sweeper == ds->current_entry) &&
	    !ds->entries[ds->current_entry].count)
		r = 0;
	else {
		list_add(work, &ds->entries[ds->current_entry].work_items);
		next_entry = ds_next(ds->current_entry);
		if (!ds->entries[next_entry].count) {
			BUG_ON(!list_empty(&ds->entries[next_entry].work_items));
			ds->current_entry = next_entry;
		}
	}
	spin_unlock_irqrestore(&ds->lock, flags);

	return r;
}

/*----------------------------------------------------------------*/




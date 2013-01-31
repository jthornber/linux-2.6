
#include "bcache.h"
#include "btree.h"

#include <linux/random.h>

/*
 * Allocation in bcache is done in terms of buckets:
 *
 * Each bucket has associated an 8 bit gen; this gen corresponds to the gen in
 * btree pointers - they must match for the pointer to be considered valid.
 *
 * Thus (assuming a bucket has no dirty data or metadata in it) we can reuse a
 * bucket simply by incrementing its gen.
 *
 * The gens (along with the priorities; it's really the gens are important but
 * the code is named as if it's the priorities) are written in an arbitrary list
 * of buckets on disk, with a pointer to them in the journal header.
 *
 * When we invalidate a bucket, we have to write its new gen to disk and wait
 * for that write to complete before we use it - otherwise after a crash we
 * could have pointers that appeared to be good but pointed to data that had
 * been overwritten.
 *
 * Since the gens and priorities are all stored contiguously on disk, we can
 * batch this up: We fill up the free_inc list with freshly invalidated buckets,
 * call prio_write() - and when prio_write() eventually finishes it toggles
 * c->prio_written and the buckets in free_inc are now ready to be used. When
 * the free_inc list empties, we toggle c->prio_written and the cycle repeats.
 *
 * free_inc isn't the only freelist - if it was, we'd often to sleep while
 * priorities and gens were being written before we could allocate. c->free is a
 * smaller freelist, and buckets on that list are always ready to be used.
 *
 * If we've got discards enabled, that happens when a bucket moves from the
 * free_inc list to the free list.
 *
 * There is another freelist, because sometimes we have buckets that we know
 * have nothing pointing into them - these we can reuse without waiting for
 * priorities to be rewritten. These come from freed btree nodes and buckets
 * that garbage collection discovered no longer had valid keys pointing into
 * them (because they were overwritten). That's the unused list - buckets on the
 * unused list move to the free list, optionally being discarded in the process.
 *
 * It's also important to ensure that gens don't wrap around - with respect to
 * either the oldest gen in the btree or the gen on disk. This is quite
 * difficult to do in practice, but we explicitly guard against it anyways - if
 * a bucket is in danger of wrapping around we simply skip invalidating it that
 * time around, and we garbage collect or rewrite the priorities sooner than we
 * would have otherwise.
 *
 * bch_bucket_alloc() allocates a single bucket from a specific cache.
 *
 * bch_bucket_alloc_set() allocates one or more buckets from different caches
 * out of a cache set.
 *
 * free_some_buckets() drives all the processes described above. It's called
 * from bch_bucket_alloc() and a few other places that need to make sure free
 * buckets are ready.
 *
 * invalidate_buckets_(lru|fifo)() find buckets that are available to be
 * invalidated, and then invalidate them and stick them on the free_inc list -
 * in either lru or fifo order.
 */

#define MAX_IN_FLIGHT_DISCARDS		8

static void do_discard(struct cache *);

/* Bucket heap / gen */

uint8_t bch_inc_gen(struct cache *ca, struct bucket *b)
{
	uint8_t ret = ++b->gen;

	ca->set->need_gc = max(ca->set->need_gc, bucket_gc_gen(b));
	WARN_ON_ONCE(ca->set->need_gc > BUCKET_GC_GEN_MAX);

	if (CACHE_SYNC(&ca->set->sb)) {
		ca->need_save_prio = max(ca->need_save_prio, bucket_disk_gen(b));
		WARN_ON_ONCE(ca->need_save_prio > BUCKET_DISK_GEN_MAX);
	}

	return ret;
}

void bch_rescale_priorities(struct cache_set *c, int sectors)
{
	struct cache *ca;
	struct bucket *b;
	unsigned next = c->nbuckets * c->sb.bucket_size / 1024;
	int r;

	atomic_sub(sectors, &c->rescale);

	do {
		r = atomic_read(&c->rescale);

		if (r >= 0)
			return;
	} while (atomic_cmpxchg(&c->rescale, r, r + next) != r);

	mutex_lock(&c->bucket_lock);

	c->min_prio = USHRT_MAX;

	for_each_cache(ca, c)
		for_each_bucket(b, ca)
			if (b->prio &&
			    b->prio != BTREE_PRIO &&
			    !atomic_read(&b->pin)) {
				b->prio--;
				c->min_prio = min(c->min_prio, b->prio);
			}

	mutex_unlock(&c->bucket_lock);
}

static long pop_freed(struct cache *ca)
{
	long r;

	if ((!CACHE_SYNC(&ca->set->sb) ||
	     !atomic_read(&ca->set->prio_blocked)) &&
	    fifo_pop(&ca->unused, r))
		return r;

	if ((!CACHE_SYNC(&ca->set->sb) ||
	     atomic_read(&ca->prio_written) > 0) &&
	    fifo_pop(&ca->free_inc, r))
		return r;

	return -1;
}

/* Discard/TRIM */

struct discard {
	struct list_head	list;
	struct work_struct	work;
	struct cache		*ca;
	long			bucket;

	struct bio		bio;
	struct bio_vec		bv;
};

static void discard_finish(struct work_struct *w)
{
	struct discard *d = container_of(w, struct discard, work);
	struct cache *ca = d->ca;
	char buf[BDEVNAME_SIZE];
	bool run = false;

	if (!test_bit(BIO_UPTODATE, &d->bio.bi_flags)) {
		printk(KERN_NOTICE "bcache: discard error on %s, disabling\n",
		       bdevname(ca->bdev, buf));
		d->ca->discard = 0;
	}

	mutex_lock(&ca->set->bucket_lock);
	if (fifo_empty(&ca->free) ||
	    fifo_used(&ca->free) == 8)
		run = true;

	fifo_push(&ca->free, d->bucket);

	list_add(&d->list, &ca->discards);

	do_discard(ca);
	mutex_unlock(&ca->set->bucket_lock);

	if (run)
		closure_wake_up(&ca->set->bucket_wait);

	closure_put(&ca->set->cl);
}

static void discard_endio(struct bio *bio, int error)
{
	struct discard *d = container_of(bio, struct discard, bio);

	PREPARE_WORK(&d->work, discard_finish);
	schedule_work(&d->work);
}

static void discard_work(struct work_struct *w)
{
	struct discard *d = container_of(w, struct discard, work);
	submit_bio(0, &d->bio);
}

static void do_discard(struct cache *ca)
{
	struct request_queue *q = bdev_get_queue(ca->bdev);
	int s = q->limits.logical_block_size;

	lockdep_assert_held(&ca->set->bucket_lock);

	while (ca->discard &&
	       !atomic_read(&ca->set->closing) &&
	       !list_empty(&ca->discards) &&
	       fifo_free(&ca->free) >= MAX_IN_FLIGHT_DISCARDS) {
		struct discard *d = list_first_entry(&ca->discards,
						     struct discard, list);

		d->bucket = pop_freed(ca);
		if (d->bucket == -1)
			break;

		list_del(&d->list);
		closure_get(&ca->set->cl);

		bio_init(&d->bio);
		memset(&d->bv, 0, sizeof(struct bio_vec));
		bio_set_prio(&d->bio, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));

		d->bio.bi_sector	= bucket_to_sector(ca->set, d->bucket);
		d->bio.bi_bdev		= ca->bdev;
		d->bio.bi_rw		= REQ_WRITE|REQ_DISCARD;
		d->bio.bi_max_vecs	= 1;
		d->bio.bi_io_vec	= d->bio.bi_inline_vecs;
		d->bio.bi_end_io	= discard_endio;

		if (bio_add_pc_page(q, &d->bio, ca->discard_page, s, 0) < s) {
			printk(KERN_DEBUG "bcache: bio_add_pc_page failed\n");
			ca->discard = 0;
			fifo_push(&ca->free, d->bucket);
			list_add(&d->list, &ca->discards);
			break;
		}

		d->bio.bi_size = bucket_bytes(ca);

		schedule_work(&d->work);
	}
}

void bch_free_discards(struct cache *ca)
{
	struct discard *d;

	while (!list_empty(&ca->discards)) {
		d = list_first_entry(&ca->discards, struct discard, list);
		cancel_work_sync(&d->work);
		list_del(&d->list);
		kfree(d);
	}
}

int bch_alloc_discards(struct cache *ca)
{
	for (int i = 0; i < MAX_IN_FLIGHT_DISCARDS; i++) {
		struct discard *d = kzalloc(sizeof(*d), GFP_KERNEL);
		if (!d)
			return -ENOMEM;

		d->ca = ca;
		INIT_WORK(&d->work, discard_work);
		list_add(&d->list, &ca->discards);
	}

	return 0;
}

/* Allocation */

static inline bool can_inc_bucket_gen(struct bucket *b)
{
	return bucket_gc_gen(b) < BUCKET_GC_GEN_MAX &&
		bucket_disk_gen(b) < BUCKET_DISK_GEN_MAX;
}

bool bch_bucket_add_unused(struct cache *ca, struct bucket *b)
{
	BUG_ON(GC_MARK(b) || GC_SECTORS_USED(b));

	if (ca->prio_alloc == prio_buckets(ca) &&
	    CACHE_REPLACEMENT(&ca->sb) == CACHE_REPLACEMENT_FIFO)
		return false;

	b->prio = 0;

	if (can_inc_bucket_gen(b) &&
	    fifo_push(&ca->unused, b - ca->buckets)) {
		atomic_inc(&b->pin);
		return true;
	}

	return false;
}

static bool can_invalidate_bucket(struct cache *ca, struct bucket *b)
{
	return GC_MARK(b) == GC_MARK_RECLAIMABLE &&
		!atomic_read(&b->pin) &&
		can_inc_bucket_gen(b);
}

static void invalidate_one_bucket(struct cache *ca, struct bucket *b)
{
	bch_inc_gen(ca, b);
	b->prio = INITIAL_PRIO;
	atomic_inc(&b->pin);
	fifo_push(&ca->free_inc, b - ca->buckets);
}

static void invalidate_buckets_lru(struct cache *ca)
{
	unsigned bucket_prio(struct bucket *b)
	{
		return ((unsigned) (b->prio - ca->set->min_prio)) *
			GC_SECTORS_USED(b);
	}

	bool bucket_max_cmp(struct bucket *l, struct bucket *r)
	{
		return bucket_prio(l) < bucket_prio(r);
	}

	bool bucket_min_cmp(struct bucket *l, struct bucket *r)
	{
		return bucket_prio(l) > bucket_prio(r);
	}

	struct bucket *b;

	ca->heap.used = 0;

	for_each_bucket(b, ca) {
		if (!can_invalidate_bucket(ca, b))
			continue;

		if (!GC_SECTORS_USED(b)) {
			if (!bch_bucket_add_unused(ca, b))
				return;
		} else {
			if (!heap_full(&ca->heap))
				heap_add(&ca->heap, b, bucket_max_cmp);
			else if (bucket_max_cmp(b, heap_peek(&ca->heap))) {
				ca->heap.data[0] = b;
				heap_sift(&ca->heap, 0, bucket_max_cmp);
			}
		}
	}

	if (ca->heap.used * 2 < ca->heap.size)
		bch_queue_gc(ca->set);

	for (ssize_t i = ca->heap.used / 2 - 1; i >= 0; --i)
		heap_sift(&ca->heap, i, bucket_min_cmp);

	while (!fifo_full(&ca->free_inc)) {
		if (!heap_pop(&ca->heap, b, bucket_min_cmp)) {
			/* We don't want to be calling invalidate_buckets()
			 * multiple times when it can't do anything
			 */
			ca->invalidate_needs_gc = 1;
			bch_queue_gc(ca->set);
			return;
		}

		invalidate_one_bucket(ca, b);
	}
}

static void invalidate_buckets_fifo(struct cache *ca)
{
	struct bucket *b;
	size_t checked = 0;

	while (!fifo_full(&ca->free_inc)) {
		if (ca->fifo_last_bucket <  ca->sb.first_bucket ||
		    ca->fifo_last_bucket >= ca->sb.nbuckets)
			ca->fifo_last_bucket = ca->sb.first_bucket;

		b = ca->buckets + ca->fifo_last_bucket++;

		if (can_invalidate_bucket(ca, b))
			invalidate_one_bucket(ca, b);

		if (++checked >= ca->sb.nbuckets) {
			ca->invalidate_needs_gc = 1;
			bch_queue_gc(ca->set);
			return;
		}
	}
}

static void invalidate_buckets_random(struct cache *ca)
{
	struct bucket *b;
	size_t checked = 0;

	while (!fifo_full(&ca->free_inc)) {
		size_t n;
		get_random_bytes(&n, sizeof(n));

		n %= (size_t) (ca->sb.nbuckets - ca->sb.first_bucket);
		n += ca->sb.first_bucket;

		b = ca->buckets + n;

		if (can_invalidate_bucket(ca, b))
			invalidate_one_bucket(ca, b);

		if (++checked >= ca->sb.nbuckets / 2) {
			ca->invalidate_needs_gc = 1;
			bch_queue_gc(ca->set);
			return;
		}
	}
}

static void invalidate_buckets(struct cache *ca)
{
	/* free_some_buckets() may just need to write priorities to keep gens
	 * from wrapping around
	 */
	if (!ca->set->gc_mark_valid ||
	    ca->invalidate_needs_gc)
		return;

	switch (CACHE_REPLACEMENT(&ca->sb)) {
	case CACHE_REPLACEMENT_LRU:
		invalidate_buckets_lru(ca);
		break;
	case CACHE_REPLACEMENT_FIFO:
		invalidate_buckets_fifo(ca);
		break;
	case CACHE_REPLACEMENT_RANDOM:
		invalidate_buckets_random(ca);
		break;
	}
}

bool bch_can_save_prios(struct cache *ca)
{
	return ((ca->need_save_prio > 64 ||
		 (ca->set->gc_mark_valid &&
		  !ca->invalidate_needs_gc)) &&
		!atomic_read(&ca->prio_written) &&
		!atomic_read(&ca->set->prio_blocked));
}

void bch_free_some_buckets(struct cache *ca)
{
	long r;
	lockdep_assert_held(&ca->set->bucket_lock);

	/*
	 * XXX: do_discard(), prio_write() take refcounts on the cache set.  How
	 * do we know that refcount is nonzero?
	 */

	if (ca->discard)
		do_discard(ca);
	else
		while (!fifo_full(&ca->free) &&
		       (r = pop_freed(ca)) != -1)
			fifo_push(&ca->free, r);

	while (ca->prio_alloc != prio_buckets(ca) &&
	       fifo_pop(&ca->free, r)) {
		struct bucket *b = ca->buckets + r;
		ca->prio_next[ca->prio_alloc++] = r;

		SET_GC_MARK(b, GC_MARK_BTREE);
		atomic_dec_bug(&b->pin);
	}

	if (!CACHE_SYNC(&ca->set->sb)) {
		if (fifo_empty(&ca->free_inc))
			invalidate_buckets(ca);
		return;
	}

	/* XXX: tracepoint for when c->need_save_prio > 64 */

	if (ca->need_save_prio <= 64 &&
	    fifo_used(&ca->unused) > ca->unused.size / 2)
		return;

	if (atomic_read(&ca->prio_written) > 0 &&
	    (fifo_empty(&ca->free_inc) ||
	     ca->need_save_prio > 64))
		atomic_set(&ca->prio_written, 0);

	if (!bch_can_save_prios(ca))
		return;

	invalidate_buckets(ca);

	if (!fifo_empty(&ca->free_inc) ||
	    ca->need_save_prio > 64)
		bch_prio_write(ca);
}

static long bch_bucket_alloc(struct cache *ca, int mark,
			     uint16_t write_prio, struct closure *cl)
{
	long r = -1;
	unsigned watermark;

	if (mark == GC_MARK_BTREE)
		watermark = 0;
	else if (write_prio)
		watermark = 8;
	else
		watermark = ca->free.size / 2;

again:
	bch_free_some_buckets(ca);

	if (fifo_used(&ca->free) > watermark &&
	    fifo_pop(&ca->free, r)) {
		struct bucket *b = ca->buckets + r;
#ifdef CONFIG_BCACHE_EDEBUG
		long i;
		for (unsigned j = 0; j < prio_buckets(ca); j++)
			BUG_ON(ca->prio_buckets[j] == (uint64_t) r);
		for (unsigned j = 0; j < ca->prio_alloc; j++)
			BUG_ON(ca->prio_next[j] == (uint64_t) r);

		fifo_for_each(i, &ca->free)
			BUG_ON(i == r);
		fifo_for_each(i, &ca->free_inc)
			BUG_ON(i == r);
		fifo_for_each(i, &ca->unused)
			BUG_ON(i == r);
#endif
		BUG_ON(atomic_read(&b->pin) != 1);

		SET_GC_MARK(b, mark);
		SET_GC_SECTORS_USED(b, ca->sb.bucket_size);
		b->prio		= (mark == GC_MARK_BTREE)
			? BTREE_PRIO : INITIAL_PRIO;

		return r;
	}

	pr_debug("no free buckets, prio_written %i, blocked %i, "
		 "free %zu, free_inc %zu, unused %zu",
		 atomic_read(&ca->prio_written),
		 atomic_read(&ca->set->prio_blocked), fifo_used(&ca->free),
		 fifo_used(&ca->free_inc), fifo_used(&ca->unused));

	if (cl) {
		closure_wait(&ca->set->bucket_wait, cl);

		if (closure_blocking(cl)) {
			mutex_unlock(&ca->set->bucket_lock);
			closure_sync(cl);
			mutex_lock(&ca->set->bucket_lock);
			goto again;
		}
	}

	return -1;
}

void bch_bucket_free(struct cache_set *c, struct bkey *k)
{
	for (unsigned i = 0; i < KEY_PTRS(k); i++) {
		struct bucket *b = PTR_BUCKET(c, k, i);

		SET_GC_MARK(b, 0);
		SET_GC_SECTORS_USED(b, 0);
		bch_bucket_add_unused(PTR_CACHE(c, k, i), b);
	}
}

int __bch_bucket_alloc_set(struct cache_set *c, int mark, uint16_t write_prio,
			   struct bkey *k, int n, struct closure *cl)
{
	lockdep_assert_held(&c->bucket_lock);
	BUG_ON(!n || n > c->caches_loaded || n > 8);

	bkey_init(k);

	/* sort by free space/prio of oldest data in caches */

	for (int i = 0; i < n; i++) {
		struct cache *ca = c->cache_by_alloc[i];
		long b = bch_bucket_alloc(ca, mark, write_prio, cl);

		if (b == -1)
			goto err;

		k->ptr[i] = PTR(ca->buckets[b].gen,
				bucket_to_sector(c, b),
				ca->sb.nr_this_dev);

		SET_KEY_PTRS(k, i + 1);
	}

	return 0;
err:
	bch_bucket_free(c, k);
	__bkey_put(c, k);
	return -1;
}

int bch_bucket_alloc_set(struct cache_set *c, int mark, uint16_t write_prio,
			 struct bkey *k, int n, struct closure *cl)
{
	int ret;
	mutex_lock(&c->bucket_lock);
	ret = __bch_bucket_alloc_set(c, mark, write_prio, k, n, cl);
	mutex_unlock(&c->bucket_lock);
	return ret;
}

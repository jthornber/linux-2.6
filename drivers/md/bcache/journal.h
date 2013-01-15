#ifndef _BCACHE_JOURNAL_H
#define _BCACHE_JOURNAL_H

/*
 * THE JOURNAL:
 *
 * The journal is treated as a circular buffer of buckets - a journal entry
 * never spans two buckets. This means (not implemented yet) we can resize the
 * journal at runtime, and will be needed for bcache on raw flash support.
 *
 * Journal entries contain a list of keys, ordered by the time they were
 * inserted; thus journal replay just has to reinsert the keys.
 *
 * We also keep some things in the journal header that are logically part of the
 * superblock - all the things that are frequently updated. This is for future
 * bcache on raw flash support; the superblock (which will become another
 * journal) can't be moved or wear leveled, so it contains just enough
 * information to find the main journal, and the superblock only has to be
 * rewritten when we want to move/wear level the main journal.
 *
 * Currently, we don't journal BTREE_REPLACE operations - this will hopefully be
 * fixed eventually. This isn't a bug - BTREE_REPLACE is used for insertions
 * from cache misses, which don't have to be journaled, and for writeback and
 * moving gc we work around it by flushing the btree to disk before updating the
 * gc information. But it is a potential issue with incremental garbage
 * collection, and it's fragile.
 *
 * OPEN JOURNAL ENTRIES:
 *
 * Each journal entry contains, in the header, the sequence number of the last
 * journal entry still open - i.e. that has keys that haven't been flushed to
 * disk in the btree.
 *
 * We track this by maintaining a refcount for every open journal entry, in a
 * fifo; the size of the fifo tells us the number of open journal entries, and
 * when the atomic_t at the end of the fifo goes to 0 we can pop it off.
 *
 * We take a refcount on a journal entry when we add some keys to a journal
 * entry that we're going to insert (held by struct btree_op), and then when we
 * insert those keys into the btree the btree write we're setting up takes a
 * copy of that refcount (held by struct btree_write). That refcount is dropped
 * when the btree write completes.
 *
 * A struct btree_write can only hold a refcount on a single journal entry, but
 * might contain keys for many journal entries - we handle this by making sure
 * it always has a refcount on the _oldest_ journal entry of all the journal
 * entries it has keys for.
 */

#define BCACHE_JSET_VERSION_UUIDv1	1
/* Always latest UUID format */
#define BCACHE_JSET_VERSION_UUID	1
#define BCACHE_JSET_VERSION		1

/*
 * On disk format for a journal entry:
 * seq is monotonically increasing; every journal entry has its own unique
 * sequence number.
 *
 * last_seq is the oldest journal entry that still has keys the btree hasn't
 * flushed to disk yet.
 *
 * version is for on disk format changes.
 */
struct jset {
	uint64_t		csum;
	uint64_t		magic;
	uint64_t		seq;
	uint32_t		version;
	uint32_t		keys;

	uint64_t		last_seq;

	BKEY_PADDED(uuid_bucket);
	BKEY_PADDED(btree_root);
	uint16_t		btree_level;
	uint16_t		pad[3];

	uint64_t		prio_bucket[MAX_CACHES_PER_SET];

	union {
		struct bkey	start[0];
		uint64_t	d[0];
	};
};

/*
 * Only used for holding the journal entries we read in btree_journal_read()
 * during cache_registration
 */
struct journal_replay {
	struct list_head	list;
	atomic_t		*pin;
	struct jset		j;
};

/*
 * We put two of these in struct journal; we used them for writes to the
 * journal that are being staged or in flight.
 */
struct journal_write {
	struct jset		*data;
#define JSET_BITS		3

	struct cache_set	*c;
	struct closure_waitlist	wait;
	bool			need_write;
};

struct journal {
	spinlock_t		lock;
	/* used when waiting because the journal was full */
	struct closure_waitlist	wait;
	struct closure_with_timer io;

	unsigned		blocks_free;
	uint64_t		seq;
	DECLARE_FIFO(atomic_t, pin);

	BKEY_PADDED(key);

	struct journal_write	w[2], *cur;
};

struct journal_device {
	unsigned		cur;
	unsigned		last;
	uint64_t		seq[SB_JOURNAL_BUCKETS];

	struct bio		bio;
	struct bio_vec		bv[8];
};

#define journal_pin_cmp(c, l, r)				\
	(fifo_idx(&(c)->journal.pin, (l)->journal) >		\
	 fifo_idx(&(c)->journal.pin, (r)->journal))

#define JOURNAL_PIN	20000

#define journal_full(j)						\
	(!(j)->blocks_free || fifo_free(&(j)->pin) <= 1)

struct closure;
struct cache_set;
struct btree_op;

void bch_journal(struct closure *);
void bch_journal_next(struct journal *);
void bch_journal_mark(struct cache_set *, struct list_head *);
void bch_journal_meta(struct cache_set *, struct closure *);
int bch_journal_read(struct cache_set *, struct list_head *,
			struct btree_op *);
int bch_journal_replay(struct cache_set *, struct list_head *,
			  struct btree_op *);

void bch_journal_free(struct cache_set *);
int bch_journal_alloc(struct cache_set *);

#endif /* _BCACHE_JOURNAL_H */

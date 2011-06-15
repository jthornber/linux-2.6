#include "dm-block-manager.h"

#include <linux/dm-io.h>
#include <linux/slab.h>
#include <linux/device-mapper.h> /* For SECTOR_SHIFT */
#include <linux/crc32c.h>
#include <asm/unaligned.h>

#define DEBUG

/*----------------------------------------------------------------*/

#define SECTOR_SIZE 512

enum dm_block_state {
	BS_EMPTY,
	BS_CLEAN,
	BS_READING,
	BS_WRITING,
	BS_READ_LOCKED,
	BS_READ_LOCKED_DIRTY, 	/* block was dirty before it was read locked */
	BS_WRITE_LOCKED,
	BS_DIRTY,
	BS_ERROR
};

struct dm_block {
	struct list_head list;
	struct hlist_node hlist;

	dm_block_t where;
	struct dm_block_validator *validator;
	void *data_actual;
	void *data;
	wait_queue_head_t io_q;
	unsigned read_lock_count;
	unsigned write_lock_pending;
	enum dm_block_state state;

	/* Extra flags like REQ_FLUSH and REQ_FUA can be set here.  This is
	 * mainly as to avoid a race condition in flush_and_unlock() where
	 * the newly unlocked superblock may have been submitted for a
	 * write before the write_all_dirty() call is made.
	 */
	int io_flags;

	/*
	 * Sadly we need an up pointer so we can get to the bm on io
	 * completion.
	 */
	struct dm_block_manager *bm;
};

struct dm_block_manager {
	struct block_device *bdev;
	unsigned cache_size; /* in bytes */
	unsigned block_size; /* in bytes */
	dm_block_t nr_blocks;

	/* this will trigger everytime an io completes */
	wait_queue_head_t io_q;

	struct dm_io_client *io;

	/* |lock| protects all the lists and the hash table */
	spinlock_t lock;
	struct list_head empty_list; /* no block assigned */
	struct list_head clean_list; /* unlocked and clean */
	struct list_head dirty_list; /* unlocked and dirty */
	struct list_head error_list;
	unsigned available_count;
	unsigned reading_count;
	unsigned writing_count;

#ifdef DEBUG
	/* FIXME: debug only */
	unsigned locks_held;
	unsigned shared_read_count;
#endif

	/*
	 * Hash table of cached blocks, holds everything that isn't in the
	 * BS_EMPTY state.
	 */
	unsigned hash_size;
	unsigned hash_mask;
	struct hlist_head buckets[0]; /* must be last member of struct */
};

dm_block_t dm_block_location(struct dm_block *b)
{
	return b->where;
}
EXPORT_SYMBOL_GPL(dm_block_location);

void *dm_block_data(struct dm_block *b)
{
	return b->data;
}
EXPORT_SYMBOL_GPL(dm_block_data);

u32 dm_block_csum_data(char *data, u32 seed, size_t len)
{
	return crc32c(seed, data, len);
}
EXPORT_SYMBOL_GPL(dm_block_csum_data);

void dm_block_csum_final(u32 crc, __le32 *result)
{
	put_unaligned_le32(~crc, result);
}
EXPORT_SYMBOL_GPL(dm_block_csum_final);

/*----------------------------------------------------------------
 * Hash table
 *--------------------------------------------------------------*/
static unsigned hash_block(struct dm_block_manager *bm, dm_block_t b)
{
	const unsigned BIG_PRIME = 4294967291UL;

	return (((unsigned) b) * BIG_PRIME) & bm->hash_mask;
}

static struct dm_block *__find_block(struct dm_block_manager *bm, dm_block_t b)
{
	unsigned bucket = hash_block(bm, b);
	struct dm_block *blk;
	struct hlist_node *n;

	hlist_for_each_entry(blk, n, bm->buckets + bucket, hlist)
		if (blk->where == b)
			return blk;

	return NULL;
}

static void __insert_block(struct dm_block_manager *bm, struct dm_block *b)
{
	unsigned bucket = hash_block(bm, b->where);

	hlist_add_head(&b->hlist, bm->buckets + bucket);
}

/*----------------------------------------------------------------
 * Block state:
 * __transition() handles transition of a block between different states.
 * Study this to understand the state machine.
 *
 * Alternatively install graphviz and run:
 *     grep DOT dm-block-manager.c | grep -v '  ' |
 *       sed -e 's/.*DOT: //' -e 's/\*\///' |
 *       dot -Tps -o states.ps
 *
 * Assumes bm->lock is held.
 *--------------------------------------------------------------*/
static void __transition(struct dm_block *b, enum dm_block_state new_state)
{
	/* DOT: digraph BlockStates { */
	struct dm_block_manager *bm = b->bm;

	switch (new_state) {
	case BS_EMPTY:
		/* DOT: error -> empty */
		/* DOT: clean -> empty */
		BUG_ON(!((b->state == BS_ERROR) ||
			 (b->state == BS_CLEAN)));
		hlist_del(&b->hlist);
		list_move(&b->list, &bm->empty_list);
		b->write_lock_pending = 0;
		b->read_lock_count = 0;
		b->io_flags = 0;
		b->validator = NULL;

		if (b->state == BS_ERROR)
			bm->available_count++;
		break;

	case BS_CLEAN:
		/* DOT: reading -> clean */
		/* DOT: writing -> clean */
		/* DOT: read_locked -> clean */
		BUG_ON(!((b->state == BS_READING) ||
			 (b->state == BS_WRITING) ||
			 (b->state == BS_READ_LOCKED)));
		switch (b->state) {
		case BS_READING:
			BUG_ON(bm->reading_count == 0);
			bm->reading_count--;
			break;

		case BS_WRITING:
			BUG_ON(bm->writing_count == 0);
			bm->writing_count--;
			b->io_flags = 0;
			break;

		default:
			break;
		}
		list_add_tail(&b->list, &bm->clean_list);
		bm->available_count++;
		break;

	case BS_READING:
		/* DOT: empty -> reading */
		BUG_ON(!(b->state == BS_EMPTY));
		/* FIXME: insert into the hash */
		__insert_block(bm, b);
		list_del(&b->list);
		bm->available_count--;
		bm->reading_count++;
		break;

	case BS_WRITING:
		/* DOT: dirty -> writing */
		BUG_ON(!(b->state == BS_DIRTY));
		list_del(&b->list);
		bm->writing_count++;
		break;

	case BS_READ_LOCKED:
		/* DOT: clean -> read_locked */
		BUG_ON(!(b->state == BS_CLEAN));
		list_del(&b->list);
		bm->available_count--;
		break;

	case BS_READ_LOCKED_DIRTY:
		/* DOT: dirty -> read_locked_dirty */
		BUG_ON(!((b->state == BS_DIRTY)));
		list_del(&b->list);
		break;

	case BS_WRITE_LOCKED:
		/* DOT: dirty -> write_locked */
		/* DOT: clean -> write_locked */
		BUG_ON(!((b->state == BS_DIRTY) ||
			 (b->state == BS_CLEAN)));
		list_del(&b->list);

		if (b->state == BS_CLEAN)
			bm->available_count--;
		break;

	case BS_DIRTY:
		/* DOT: write_locked -> dirty */
		/* DOT: read_locked_dirty -> dirty */
		BUG_ON(!((b->state == BS_WRITE_LOCKED) ||
			 (b->state == BS_READ_LOCKED_DIRTY)));
		list_add_tail(&b->list, &bm->dirty_list);
		break;

	case BS_ERROR:
		/* DOT: writing -> error */
		/* DOT: reading -> error */
		BUG_ON(!((b->state == BS_WRITING) ||
			 (b->state == BS_READING)));
		list_add_tail(&b->list, &bm->error_list);
		break;
	}

	b->state = new_state;
	/* DOT: } */
}

/*----------------------------------------------------------------
 * low level io
 *--------------------------------------------------------------*/
typedef void (completion_fn)(unsigned long error, struct dm_block *b);

static void submit_io(struct dm_block *b, int rw,
		      completion_fn fn)
{
	struct dm_block_manager *bm = b->bm;
	struct dm_io_request req;
	struct dm_io_region region;
	unsigned sectors_per_block = bm->block_size >> SECTOR_SHIFT;

	region.bdev = bm->bdev;
	region.sector = b->where * sectors_per_block;
	region.count = sectors_per_block;

	req.bi_rw = rw;
	req.mem.type = DM_IO_KMEM;
	req.mem.offset = 0;
	req.mem.ptr.addr = b->data;
	req.notify.fn = (void (*)(unsigned long, void *)) fn;
	req.notify.context = b;
	req.client = bm->io;

	if (dm_io(&req, 1, &region, NULL) < 0)
		fn(1, b);
}

/*----------------------------------------------------------------
 * High level io
 *--------------------------------------------------------------*/
static void __complete_io(unsigned long error, struct dm_block *b)
{
	struct dm_block_manager *bm = b->bm;

	if (error) {
		printk(KERN_ALERT "io error %u", (unsigned) b->where);
		__transition(b, BS_ERROR);
	} else
		__transition(b, BS_CLEAN);

	wake_up(&b->io_q);
	wake_up(&bm->io_q);
}

static void complete_io(unsigned long error, struct dm_block *b)
{
	struct dm_block_manager *bm = b->bm;
	unsigned long flags;

	spin_lock_irqsave(&bm->lock, flags);
	__complete_io(error, b);
	spin_unlock_irqrestore(&bm->lock, flags);
}

static void read_block(struct dm_block *b)
{
	submit_io(b, READ, complete_io);
}

static void write_block(struct dm_block *b)
{
	if (b->validator)
		b->validator->prepare_for_write(b->validator, b);

	submit_io(b, WRITE | b->io_flags, complete_io);
}

static void write_dirty(struct dm_block_manager *bm, unsigned count)
{
	struct dm_block *b, *tmp;
	struct list_head dirty;
	unsigned long flags;

	/* Grab the first |count| entries from the dirty list */
	INIT_LIST_HEAD(&dirty);
	spin_lock_irqsave(&bm->lock, flags);
	list_for_each_entry_safe (b, tmp, &bm->dirty_list, list) {
		if (count-- == 0)
			break;
		__transition(b, BS_WRITING);
		list_add_tail(&b->list, &dirty);
	}
	spin_unlock_irqrestore(&bm->lock, flags);

	list_for_each_entry_safe (b, tmp, &dirty, list) {
		list_del(&b->list);
		write_block(b);
	}
}

static void write_all_dirty(struct dm_block_manager *bm)
{
	write_dirty(bm, bm->cache_size);
}

static void __clear_errors(struct dm_block_manager *bm)
{
	struct dm_block *b, *tmp;
	list_for_each_entry_safe (b, tmp, &bm->error_list, list)
		__transition(b, BS_EMPTY);
}

/*----------------------------------------------------------------
 * Waiting
 *--------------------------------------------------------------*/
#ifdef __CHECKER__
# define __retains(x)	__attribute__((context(x,1,1)))
#else
# define __retains(x)
#endif

#ifdef USE_PLUGGING
static inline unplug(void)
{
	blk_flush_plug(current);
}
#else
static inline void unplug(void) {}
#endif

#define __wait_block(wq, lock, flags, sched_fn, condition)	\
do {   								\
       	int ret = 0;  						\
       	       	       	    					\
	DEFINE_WAIT(wait);     	    				\
       	add_wait_queue(wq, &wait);  				\
       	       	      						\
       	for (;;) {    						\
 		prepare_to_wait(wq, &wait, TASK_INTERRUPTIBLE); \
 		if (condition)  				\
 		      	break;         	       	       		\
       	       	       	       			      		\
		spin_unlock_irqrestore(lock, flags);  		\
		if (signal_pending(current)) {  		\
		      	ret = -ERESTARTSYS;    	       	 	\
		      	spin_lock_irqsave(lock, flags);  	\
		       	break;  				\
       	       	}     						\
       	       	       	     					\
		sched_fn();    	       	       	 		\
	       	spin_lock_irqsave(lock, flags);  		\
       	}  							\
       	       	       	       	  				\
	finish_wait(wq, &wait);        	       	       	       	\
	return ret;   						\
} while (0)

static int __wait_io(struct dm_block *b, unsigned long *flags)
	__retains(&b->bm->lock)
{
	unplug();
	__wait_block(&b->io_q, &b->bm->lock, *flags, io_schedule,
		     ((b->state != BS_READING) && (b->state != BS_WRITING)));
}

static int __wait_unlocked(struct dm_block *b, unsigned long *flags)
	__retains(&b->bm->lock)
{
	__wait_block(&b->io_q, &b->bm->lock, *flags, schedule,
		     ((b->state == BS_CLEAN) || (b->state == BS_DIRTY)));
}

static int __wait_read_lockable(struct dm_block *b, unsigned long *flags)
	__retains(&b->bm->lock)
{
	__wait_block(&b->io_q, &b->bm->lock, *flags, schedule,
		     (!b->write_lock_pending && (b->state == BS_CLEAN ||
						 b->state == BS_DIRTY ||
						 b->state == BS_READ_LOCKED)));
}

static int __wait_all_writes(struct dm_block_manager *bm, unsigned long *flags)
	__retains(&bm->lock)
{
	unplug();
	__wait_block(&bm->io_q, &bm->lock, *flags, io_schedule,
		     !bm->writing_count);
}

static int __wait_clean(struct dm_block_manager *bm, unsigned long *flags)
	__retains(&bm->lock)
{
	unplug();
	__wait_block(&bm->io_q, &bm->lock, *flags, io_schedule,
		     (!list_empty(&bm->clean_list) ||
		      (bm->writing_count == 0)));
}

/*----------------------------------------------------------------
 * Finding a free block to recycle
 *--------------------------------------------------------------*/
static int recycle_block(struct dm_block_manager *bm, dm_block_t where,
			 int need_read, struct dm_block **result)
{
	int ret = 0;
	struct dm_block *b;
	unsigned long flags, available;

	/* wait for a block to appear on the empty or clean lists */
	spin_lock_irqsave(&bm->lock, flags);
	while (1) {
		/*
		 * Once we can lock and do io concurrently then we should
		 * probably flush at bm->cache_size / 2 and write _all_
		 * dirty blocks.
		 */
		available = bm->available_count + bm->writing_count;
		if (available < bm->cache_size / 4) {
			spin_unlock_irqrestore(&bm->lock, flags);
			write_dirty(bm, bm->cache_size / 4);
			spin_lock_irqsave(&bm->lock, flags);
		}

		if (!list_empty(&bm->empty_list)) {
			b = list_first_entry(&bm->empty_list, struct dm_block, list);
			break;

		} else if (!list_empty(&bm->clean_list)) {
			b = list_first_entry(&bm->clean_list, struct dm_block, list);
			__transition(b, BS_EMPTY);
			break;
		}

		__wait_clean(bm, &flags);
	}

	b->where = where;
	__transition(b, BS_READING);

	if (!need_read) {
		memset(b->data, 0, bm->block_size);
		__transition(b, BS_CLEAN);
	} else {
		spin_unlock_irqrestore(&bm->lock, flags);
		read_block(b);
		spin_lock_irqsave(&bm->lock, flags);
		__wait_io(b, &flags);

		/* FIXME: can |b| have been recycled between io completion and here ? */

		/* did the io succeed ? */
		if (b->state == BS_ERROR) {
			/* Since this is a read that has failed we can
			 * clear the error immediately.  Failed writes are
			 * revealed during a commit.
			 */
			__transition(b, BS_EMPTY);
			ret = -EIO;
		}

		if (b->validator && b->validator->check(b->validator, b)) {
			__transition(b, BS_EMPTY);
			ret = -EILSEQ;
		}
	}
	spin_unlock_irqrestore(&bm->lock, flags);

	if (ret == 0)
		*result = b;
	return ret;
}

#ifdef USE_PLUGGING
static int recycle_block_with_plugging(struct dm_block_manager *bm, dm_block_t where,
				       int need_read, struct dm_block **result)
{
	int r;
	struct blk_plug plug;

	blk_start_plug(&plug);
	r = recycle_block(bm, where, need_read, result);
	blk_finish_plug(&plug);

	return r;
}
#endif

/*----------------------------------------------------------------
 * Low level block management
 *--------------------------------------------------------------*/
static void *align(void *ptr, size_t amount)
{
	size_t offset = (uint64_t) ptr & (amount - 1);
	return ((unsigned char *) ptr) + (amount - offset);
}

static struct dm_block *alloc_block(struct dm_block_manager *bm)
{
	struct dm_block *b = kmalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return NULL;

	INIT_LIST_HEAD(&b->list);
	INIT_HLIST_NODE(&b->hlist);

	if (!(b->data_actual = kmalloc(bm->block_size + SECTOR_SIZE, GFP_KERNEL))) {
		kfree(b);
		return NULL;
	}
	b->validator = NULL;
	b->data = align(b->data_actual, SECTOR_SIZE);
	b->state = BS_EMPTY;
	init_waitqueue_head(&b->io_q);
	b->read_lock_count = 0;
	b->write_lock_pending = 0;
	b->io_flags = 0;
	b->bm = bm;

	return b;
}

static void free_block(struct dm_block *b)
{
	kfree(b->data_actual);
	kfree(b);
}

static int populate_bm(struct dm_block_manager *bm, unsigned count)
{
	int i;
	LIST_HEAD(bs);

	for (i = 0; i < count; i++) {
		struct dm_block *b = alloc_block(bm);
		if (!b) {
			struct dm_block *tmp;
			list_for_each_entry_safe (b, tmp, &bs, list)
				free_block(b);
			return -ENOMEM;
		}

		list_add(&b->list, &bs);
	}

	list_replace(&bs, &bm->empty_list);
	bm->available_count = count;

	return 0;
}

/*----------------------------------------------------------------
 * Public interface
 *--------------------------------------------------------------*/
static unsigned calc_hash_size(unsigned cache_size)
{
	unsigned r = 32;	/* minimum size is 16 */

	while (r < cache_size)
		r <<= 1;

	return r >> 1;
}

struct dm_block_manager *
dm_block_manager_create(struct block_device *bdev,
			unsigned block_size, unsigned cache_size)
{
	unsigned i;
	unsigned hash_size = calc_hash_size(cache_size);
	size_t len = sizeof(struct dm_block_manager) +
		sizeof(struct hlist_head) * hash_size;
	struct dm_block_manager *bm;

	bm = kmalloc(len, GFP_KERNEL);
	if (!bm)
		return NULL;
	bm->bdev = bdev;
	bm->cache_size = max(16u, cache_size);
	bm->block_size = block_size;
	bm->nr_blocks = i_size_read(bdev->bd_inode);
	do_div(bm->nr_blocks, block_size);
	init_waitqueue_head(&bm->io_q);
	spin_lock_init(&bm->lock);

	INIT_LIST_HEAD(&bm->empty_list);
	INIT_LIST_HEAD(&bm->clean_list);
	INIT_LIST_HEAD(&bm->dirty_list);
	INIT_LIST_HEAD(&bm->error_list);
	bm->available_count = 0;
	bm->reading_count = 0;
	bm->writing_count = 0;

	bm->hash_size = hash_size;
	bm->hash_mask = hash_size - 1;
	for (i = 0; i < hash_size; i++)
		INIT_HLIST_HEAD(bm->buckets + i);

	if (!(bm->io = dm_io_client_create())) {
		kfree(bm);
		return NULL;
	}

	if (populate_bm(bm, cache_size) < 0) {
		dm_io_client_destroy(bm->io);
		kfree(bm);
		return NULL;
	}

#ifdef DEBUG
	bm->locks_held = 0;
	bm->shared_read_count = 0;
#endif
	return bm;
}
EXPORT_SYMBOL_GPL(dm_block_manager_create);

void dm_block_manager_destroy(struct dm_block_manager *bm)
{
	int i;
	struct dm_block *b, *btmp;
	struct hlist_node *n, *tmp;

	dm_io_client_destroy(bm->io);

	for (i = 0; i < bm->hash_size; i++)
		hlist_for_each_entry_safe (b, n, tmp, bm->buckets + i, hlist)
			free_block(b);

	list_for_each_entry_safe (b, btmp, &bm->empty_list, list)
		free_block(b);

	kfree(bm);
}
EXPORT_SYMBOL_GPL(dm_block_manager_destroy);

unsigned dm_bm_block_size(struct dm_block_manager *bm)
{
	return bm->block_size;
}
EXPORT_SYMBOL_GPL(dm_bm_block_size);

dm_block_t dm_bm_nr_blocks(struct dm_block_manager *bm)
{
	return bm->nr_blocks;
}
EXPORT_SYMBOL_GPL(dm_bm_nr_blocks);

static int lock_internal(struct dm_block_manager *bm, dm_block_t block,
			 int how, int need_read, int can_block,
			 struct dm_block_validator *v,
			 struct dm_block **result)
{
	int ret = 0;
	struct dm_block *b;
	unsigned long flags;

	spin_lock_irqsave(&bm->lock, flags);
retry:
	b = __find_block(bm, block);
	if (b) {
		if (b->validator && need_read && (v != b->validator)) {
			printk(KERN_ALERT "validator mismatch");
			spin_unlock_irqrestore(&bm->lock, flags);
			return -EINVAL;
		}

		switch (how) {
		case READ:
			if (b->write_lock_pending || (b->state != BS_CLEAN &&
						      b->state != BS_DIRTY &&
						      b->state != BS_READ_LOCKED)) {
				if (!can_block) {
					spin_unlock_irqrestore(&bm->lock, flags);
					return -EWOULDBLOCK;
				}

				__wait_read_lockable(b, &flags);

				if (b->where != block)
					goto retry;
			}
			break;

		case WRITE:
			while (b->state != BS_CLEAN && b->state != BS_DIRTY) {
				if (!can_block) {
					spin_unlock_irqrestore(&bm->lock, flags);
					return -EWOULDBLOCK;
				}

				b->write_lock_pending++;
				__wait_unlocked(b, &flags);
				b->write_lock_pending--;
				if (b->where != block)
					goto retry;
			}
			break;
		}

	} else if (!can_block) {
		ret = -EWOULDBLOCK;

	} else {
		spin_unlock_irqrestore(&bm->lock, flags);
#ifdef USE_PLUGGING
		ret = recycle_block_with_plugging(bm, block, need_read, &b);
#else
		ret = recycle_block(bm, block, need_read, &b);
#endif
		spin_lock_irqsave(&bm->lock, flags);
	}

	if (ret == 0) {
		switch (how) {
		case READ:
			b->read_lock_count++;
#ifdef DEBUG
			if (b->read_lock_count > 1)
				bm->shared_read_count++;
#endif
			if (b->state == BS_DIRTY)
				__transition(b, BS_READ_LOCKED_DIRTY);
			else if (b->state == BS_CLEAN)
				__transition(b, BS_READ_LOCKED);
			break;

		case WRITE:
			__transition(b, BS_WRITE_LOCKED);
			break;
		}

		*result = b;
	}

#ifdef DEBUG
	if (ret == 0 && how == WRITE)
		bm->locks_held++;
#endif

	spin_unlock_irqrestore(&bm->lock, flags);
	return ret;
}

int dm_bm_read_lock(struct dm_block_manager *bm, dm_block_t b,
		    struct dm_block_validator *v,
		    struct dm_block **result)
{
	return lock_internal(bm, b, READ, 1, 1, v, result);
}
EXPORT_SYMBOL_GPL(dm_bm_read_lock);

int dm_bm_write_lock(struct dm_block_manager *bm,
		     dm_block_t b, struct dm_block_validator *v,
		     struct dm_block **result)
{
	return lock_internal(bm, b, WRITE, 1, 1, v, result);
}
EXPORT_SYMBOL_GPL(dm_bm_write_lock);

int dm_bm_read_try_lock(struct dm_block_manager *bm,
			dm_block_t b, struct dm_block_validator *v,
			struct dm_block **result)
{
	return lock_internal(bm, b, READ, 1, 0, v, result);
}
EXPORT_SYMBOL_GPL(dm_bm_read_try_lock);

int dm_bm_write_lock_zero(struct dm_block_manager *bm,
			  dm_block_t b, struct dm_block_validator *v,
			  struct dm_block **result)
{
	return lock_internal(bm, b, WRITE, 0, 1, v, result);
}
EXPORT_SYMBOL_GPL(dm_bm_write_lock_zero);

int dm_bm_unlock(struct dm_block *b)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&b->bm->lock, flags);

#ifdef DEBUG
	if (ret == 0 && b->state == BS_WRITE_LOCKED)
		b->bm->locks_held--;
#endif

	switch (b->state) {
	case BS_WRITE_LOCKED:
		__transition(b, BS_DIRTY);
		wake_up(&b->io_q);
		break;

	case BS_READ_LOCKED:
		if (!--b->read_lock_count) {
			__transition(b, BS_CLEAN);
			wake_up(&b->io_q);
		}
		break;

	case BS_READ_LOCKED_DIRTY:
		if (!--b->read_lock_count) {
			__transition(b, BS_DIRTY);
			wake_up(&b->io_q);
		}
		break;

	default:
		printk(KERN_ALERT "block not locked");
		ret = -EINVAL;
		break;
	}
	spin_unlock_irqrestore(&b->bm->lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(dm_bm_unlock);

static int __wait_flush(struct dm_block_manager *bm)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&bm->lock, flags);
	__wait_all_writes(bm, &flags);

	if (!list_empty(&bm->error_list)) {
		ret = -EIO;
		__clear_errors(bm);
	}
	spin_unlock_irqrestore(&bm->lock, flags);

	return ret;
}

int dm_bm_flush_and_unlock(struct dm_block_manager *bm,
			   struct dm_block *superblock)
{
	int r;
	unsigned long flags;

	write_all_dirty(bm);
	r = __wait_flush(bm);
	if (r)
		return r;

	spin_lock_irqsave(&bm->lock, flags);
	superblock->io_flags = REQ_FUA | REQ_FLUSH;
	spin_unlock_irqrestore(&bm->lock, flags);

	dm_bm_unlock(superblock);
	write_all_dirty(bm);

	return __wait_flush(bm);
}
EXPORT_SYMBOL_GPL(dm_bm_flush_and_unlock);

#ifdef DEBUG
unsigned dm_bm_locks_held(struct dm_block_manager *bm)
{
	unsigned r;
	unsigned long flags;

	spin_lock_irqsave(&bm->lock, flags);
	r = bm->locks_held;
	spin_unlock_irqrestore(&bm->lock, flags);

	return r;
}
EXPORT_SYMBOL_GPL(dm_bm_locks_held);
#endif

/*----------------------------------------------------------------*/

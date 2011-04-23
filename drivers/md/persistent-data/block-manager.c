#include "block-manager.h"

#include <linux/dm-io.h>
#include <linux/slab.h>

#define DEBUG

/*----------------------------------------------------------------*/

enum block_state {
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

struct block {
	struct list_head list;
	struct hlist_node hlist;

	block_t where;
	void *data;
	enum block_state state;
	wait_queue_head_t io_q;
	unsigned read_lock_count;
	unsigned write_lock_pending;

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
	struct block_manager *bm;
};

struct block_manager {
	struct block_device *bdev;
	unsigned cache_size;
	size_t block_size;
	sector_t sectors_per_block;
	block_t nr_blocks;

	/* this will trigger everytime an io completes */
	wait_queue_head_t io_q;

	/* |lock| protects all the lists and the hash table */
	spinlock_t lock;
	struct list_head empty_list; /* no block assigned */
	struct list_head clean_list; /* unlocked and clean */
	struct list_head dirty_list; /* unlocked and dirty */
	struct list_head error_list;
	unsigned available_count;
	unsigned reading_count;
	unsigned writing_count;
	struct dm_io_client *io;

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
	struct hlist_head buckets[0];
};

block_t block_location(struct block *b)
{
	return b->where;
}
EXPORT_SYMBOL_GPL(block_location);

void *block_data(struct block *b)
{
	return b->data;
}
EXPORT_SYMBOL_GPL(block_data);

/*----------------------------------------------------------------
 * Hash table
 *--------------------------------------------------------------*/
static unsigned hash_block(struct block_manager *bm, block_t b)
{
	const unsigned BIG_PRIME = 4294967291UL;
	return (((unsigned) b) * BIG_PRIME) & bm->hash_mask;
}

static struct block *find_block_(struct block_manager *bm, block_t b)
{
	unsigned bucket = hash_block(bm, b);
	struct block *blk;
	struct hlist_node *n;

	hlist_for_each_entry (blk, n, bm->buckets + bucket, hlist)
		if (blk->where == b)
			return blk;

	return NULL;
}

static void insert_block_(struct block_manager *bm, struct block *b)
{
	unsigned bucket = hash_block(bm, b->where);
	hlist_add_head(&b->hlist, bm->buckets + bucket);
}

/*----------------------------------------------------------------
 * Block state:
 * transition_() handles transition of a block between different states.
 * Study this to understand the state machine.
 *
 * Alternatively run:
 *     grep DOT block-manager.c |
 *       sed -e 's/.*DOT: //' -e 's/\*\///' |
 *       dot -Tps -o states.ps
 *
 * Assumes bm->lock is held.
 *--------------------------------------------------------------*/
static void transition_(struct block *b, enum block_state new_state)
{
	/* DOT: digraph BlockStates { */
	struct block_manager *bm = b->bm;

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
		insert_block_(bm, b);
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
typedef void (completion_fn)(unsigned long error, struct block *b);

static void submit_io(struct block *b,
		      int rw,
		      completion_fn fn,
		      completion_fn fail)
{
	struct block_manager *bm = b->bm;
	struct dm_io_request req;
	struct dm_io_region region;

	region.bdev = bm->bdev;
	region.sector = b->where * bm->sectors_per_block;
	region.count = bm->sectors_per_block;

	req.bi_rw = rw;
	req.mem.type = DM_IO_KMEM;
	req.mem.offset = 0;
	req.mem.ptr.addr = b->data;
	req.notify.fn = (void (*)(unsigned long, void *)) fn;
	req.notify.context = b;
	req.client = bm->io;

	if (dm_io(&req, 1, &region, NULL) < 0)
		fail(1, b);
}

/*----------------------------------------------------------------
 * High level io
 *--------------------------------------------------------------*/
static void complete_io_(unsigned long error, struct block *b)
{
	struct block_manager *bm = b->bm;

	if (error) {
		printk(KERN_ALERT "io error %u", (unsigned) b->where);
		transition_(b, BS_ERROR);
	} else {
		transition_(b, BS_CLEAN);
	}

	wake_up(&b->io_q);
	wake_up(&bm->io_q);
}

static void complete_io_irq(unsigned long error, struct block *b)
{
	struct block_manager *bm = b->bm;

	spin_lock(&bm->lock);
	complete_io_(error, b);
	spin_unlock(&bm->lock);
}

static void complete_io_fail(unsigned long error, struct block *b)
{
	struct block_manager *bm = b->bm;
	unsigned long flags;

	spin_lock_irqsave(&bm->lock, flags);
	complete_io_(error, b);
	spin_unlock_irqrestore(&bm->lock, flags);
}

static void read_block(struct block *b)
{
	submit_io(b, READ, complete_io_irq, complete_io_fail);
}

static void write_block(struct block *b)
{
	submit_io(b, WRITE | b->io_flags, complete_io_irq, complete_io_fail);
}

static void write_dirty(struct block_manager *bm, unsigned count)
{
	struct block *b, *tmp;
	struct list_head dirty;
	unsigned long flags;

	/* Grab the first |count| entries from the dirty list */
	INIT_LIST_HEAD(&dirty);
	spin_lock_irqsave(&bm->lock, flags);
	list_for_each_entry_safe (b, tmp, &bm->dirty_list, list) {
		if (count-- == 0)
			break;
		transition_(b, BS_WRITING);
		list_add_tail(&b->list, &dirty);
	}
	spin_unlock_irqrestore(&bm->lock, flags);

	list_for_each_entry (b, &dirty, list)
		write_block(b);
}

static void write_all_dirty(struct block_manager *bm)
{
	write_dirty(bm, bm->cache_size);
}

static void clear_errors_(struct block_manager *bm)
{
	struct block *b, *tmp;
	list_for_each_entry_safe (b, tmp, &bm->error_list, list)
		transition_(b, BS_EMPTY);
}

static void unplug(struct block_manager *bm)
{
	/* I think this is unneccessary, and will stop us scaling */
	//blk_unplug(bdev_get_queue(bm->bdev));
}

/*----------------------------------------------------------------
 * Waiting
 *--------------------------------------------------------------*/
#ifdef __CHECKER__
# define __retains(x)	__attribute__((context(x,1,1)))
#else
# define __retains(x)
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

static int wait_io_(struct block *b, unsigned long *flags)
	__retains(&b->bm->lock)
{
	__wait_block(&b->io_q, &b->bm->lock, *flags, io_schedule,
		     ((b->state != BS_READING) && (b->state != BS_WRITING)));
}

static int wait_unlocked_(struct block *b, unsigned long *flags)
	__retains(&b->bm->lock)
{
	__wait_block(&b->io_q, &b->bm->lock, *flags, schedule,
		     ((b->state == BS_CLEAN) || (b->state == BS_DIRTY)));
}

static int wait_read_lockable_(struct block *b, unsigned long *flags)
	__retains(&b->bm->lock)
{
	__wait_block(&b->io_q, &b->bm->lock, *flags, schedule,
		     (!b->write_lock_pending && (b->state == BS_CLEAN ||
						 b->state == BS_DIRTY ||
						 b->state == BS_READ_LOCKED)));
}

static int wait_all_writes_(struct block_manager *bm, unsigned long *flags)
	__retains(&bm->lock)
{
	__wait_block(&bm->io_q, &bm->lock, *flags, io_schedule, !bm->writing_count);
}

static int wait_clean_(struct block_manager *bm, unsigned long *flags)
	__retains(&bm->lock)
{
	__wait_block(&bm->io_q, &bm->lock, *flags, io_schedule,
		     (!list_empty(&bm->clean_list) ||
		      (bm->writing_count == 0)));
}

/*----------------------------------------------------------------
 * Finding a free block to recycle
 *--------------------------------------------------------------*/
static int recycle_block(struct block_manager *bm, block_t where, int need_read, struct block **result)
{
	int ret = 0;
	struct block *b;
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
			{
				write_dirty(bm, bm->cache_size / 4);
				unplug(bm);
			}
			spin_lock_irqsave(&bm->lock, flags);
		}

		if (!list_empty(&bm->empty_list)) {
			b = list_first_entry(&bm->empty_list, struct block, list);
			break;

		} else if (!list_empty(&bm->clean_list)) {
			b = list_first_entry(&bm->clean_list, struct block, list);
			transition_(b, BS_EMPTY);
			break;
		}

		wait_clean_(bm, &flags);
	}

	b->where = where;
	transition_(b, BS_READING);

	if (!need_read) {
		memset(b->data, 0, bm->block_size);
		transition_(b, BS_CLEAN);
	} else {
		spin_unlock_irqrestore(&bm->lock, flags);
		read_block(b);
		unplug(bm);
		spin_lock_irqsave(&bm->lock, flags);
		wait_io_(b, &flags);

		/* FIXME: can |b| have been recycled between io completion and here ? */

		/* did the io succeed ? */
		if (b->state == BS_ERROR) {
			/* Since this is a read that has failed we can
			 * clear the error immediately.  Failed writes are
			 * revealed during a commit.
			 */
			transition_(b, BS_EMPTY);
			ret = -EIO;
		}
	}
	spin_unlock_irqrestore(&bm->lock, flags);

	if (ret == 0)
		*result = b;
	return ret;
}

/*----------------------------------------------------------------
 * Low level block management
 *--------------------------------------------------------------*/
static struct block *alloc_block(struct block_manager *bm)
{
	struct block *b = kmalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return NULL;

	INIT_LIST_HEAD(&b->list);
	INIT_HLIST_NODE(&b->hlist);

	if (!(b->data = kmalloc(bm->block_size, GFP_KERNEL))) {
		kfree(b);
		return NULL;
	}
	b->state = BS_EMPTY;
	init_waitqueue_head(&b->io_q);
	b->read_lock_count = 0;
	b->write_lock_pending = 0;
	b->io_flags = 0;
	b->bm = bm;

	return b;
}

static void free_block(struct block *b)
{
	kfree(b->data);
	kfree(b);
}

static int populate_bm(struct block_manager *bm, unsigned count)
{
	int i;
	LIST_HEAD(bs);

	for (i = 0; i < count; i++) {
		struct block *b = alloc_block(bm);
		if (!b) {
			struct block *tmp;
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

struct block_manager *
block_manager_create(struct block_device *bdev,
		     unsigned block_size,
		     unsigned cache_size)
{
	unsigned i;
	unsigned hash_size = calc_hash_size(cache_size);
	size_t len = sizeof(struct block_manager) + sizeof(struct hlist_head) * hash_size;
	struct block_manager *bm = kmalloc(len, GFP_KERNEL);
	if (!bm)
		return NULL;

	bm->bdev = bdev;
	bm->cache_size = max(16u, cache_size);
	bm->block_size = block_size;
	bm->sectors_per_block = block_size / 512;
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

	if (!(bm->io = dm_io_client_create(cache_size / 4))) {
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
EXPORT_SYMBOL_GPL(block_manager_create);

void block_manager_destroy(struct block_manager *bm)
{
	int i;
	struct block *b, *btmp;
	struct hlist_node *n, *tmp;

	dm_io_client_destroy(bm->io);

	for (i = 0; i < bm->hash_size; i++)
		hlist_for_each_entry_safe (b, n, tmp, bm->buckets + i, hlist)
			free_block(b);

	list_for_each_entry_safe (b, btmp, &bm->empty_list, list)
		free_block(b);

	kfree(bm);
}
EXPORT_SYMBOL_GPL(block_manager_destroy);

size_t bm_block_size(struct block_manager *bm)
{
	return bm->block_size;
}
EXPORT_SYMBOL_GPL(bm_block_size);

block_t bm_nr_blocks(struct block_manager *bm)
{
	return bm->nr_blocks;
}
EXPORT_SYMBOL_GPL(bm_nr_blocks);

static int bm_lock_internal(struct block_manager *bm, block_t block,
			    int how, int need_read, int can_block,
			    struct block **result)
{
	int ret = 0;
	struct block *b;
	unsigned long flags;

	spin_lock_irqsave(&bm->lock, flags);
retry:
	b = find_block_(bm, block);
	if (b) {
		switch (how) {
		case READ:
			if (b->write_lock_pending || (b->state != BS_CLEAN &&
						      b->state != BS_DIRTY &&
						      b->state != BS_READ_LOCKED)) {
				if (!can_block) {
					spin_unlock_irqrestore(&bm->lock, flags);
					return -EWOULDBLOCK;
				}

				wait_read_lockable_(b, &flags);

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
				wait_unlocked_(b, &flags);
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
		ret = recycle_block(bm, block, need_read, &b);
		spin_lock_irqsave(&bm->lock, flags);
	}

	if (ret == 0) {
		switch (how) {
		case READ:
			b->read_lock_count++;
			if (b->read_lock_count > 1)
				bm->shared_read_count++;
			if (b->state == BS_DIRTY)
				transition_(b, BS_READ_LOCKED_DIRTY);
			else if (b->state == BS_CLEAN)
				transition_(b, BS_READ_LOCKED);
			break;

		case WRITE:
			transition_(b, BS_WRITE_LOCKED);
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

int bm_read_lock(struct block_manager *bm, block_t b, struct block **result)
{
	return bm_lock_internal(bm, b, READ, 1, 1, result);
}
EXPORT_SYMBOL_GPL(bm_read_lock);

int bm_write_lock(struct block_manager *bm, block_t b, struct block **result)
{
	return bm_lock_internal(bm, b, WRITE, 1, 1, result);
}
EXPORT_SYMBOL_GPL(bm_write_lock);

int bm_read_try_lock(struct block_manager *bm, block_t b, struct block **result)
{
	return bm_lock_internal(bm, b, READ, 1, 0, result);
}

int bm_write_lock_zero(struct block_manager *bm, block_t b, struct block **result)
{
	return bm_lock_internal(bm, b, WRITE, 0, 1, result);
}
EXPORT_SYMBOL_GPL(bm_write_lock_zero);

int bm_unlock(struct block *b)
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
		transition_(b, BS_DIRTY);
		wake_up(&b->io_q);
		break;

	case BS_READ_LOCKED:
		if (!--b->read_lock_count) {
			transition_(b, BS_CLEAN);
			wake_up(&b->io_q);
		}
		break;

	case BS_READ_LOCKED_DIRTY:
		if (!--b->read_lock_count) {
			transition_(b, BS_DIRTY);
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
EXPORT_SYMBOL_GPL(bm_unlock);

static int wait_flush_(struct block_manager *bm)
{
	int ret = 0;
	unsigned long flags;

	unplug(bm);
	spin_lock_irqsave(&bm->lock, flags);
	wait_all_writes_(bm, &flags);

	if (!list_empty(&bm->error_list)) {
		ret = -EIO;
		clear_errors_(bm);
	}
	spin_unlock_irqrestore(&bm->lock, flags);
	return ret;
}

int bm_flush(struct block_manager *bm, int block)
{
	write_all_dirty(bm);
	if (!block)
		return 0;

	/* FIXME: we need to issue a REQ_FLUSH, and wait for _that_ to
	 * complete.
	 */

	return wait_flush_(bm);
}
EXPORT_SYMBOL_GPL(bm_flush);

int bm_flush_and_unlock(struct block_manager *bm, struct block *superblock)
{
	int r;
	unsigned long flags;

	write_all_dirty(bm);
	r = wait_flush_(bm);
	if (r)
		return r;

	spin_lock_irqsave(&bm->lock, flags);
	superblock->io_flags = REQ_FUA | REQ_FLUSH;
	spin_unlock_irqrestore(&bm->lock, flags);

	bm_unlock(superblock);
	write_all_dirty(bm);

	return wait_flush_(bm);
}
EXPORT_SYMBOL_GPL(bm_flush_and_unlock);

#ifdef DEBUG
unsigned bm_locks_held(struct block_manager *bm)
{
	unsigned r;
	unsigned long flags;

	spin_lock_irqsave(&bm->lock, flags);
	r = bm->locks_held;
	spin_unlock_irqrestore(&bm->lock, flags);

	return r;
}
EXPORT_SYMBOL_GPL(bm_locks_held);
#endif

/*----------------------------------------------------------------*/

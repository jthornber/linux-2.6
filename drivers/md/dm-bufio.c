/*
 * Copyright (C) 2009 Red Hat Czech, s.r.o.
 *
 * Mikulas Patocka <mpatocka@redhat.com>
 *
 * This file is released under the GPL.
 */

#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "dm.h"

#include <linux/dm-bufio.h>

/*
 * Memory management policy:
 *	Limit the number of buffers to DM_BUFIO_MEMORY_RATIO of main memory or
 *	DM_BUFIO_VMALLOC_RATIO of vmalloc memory (whichever is lower).
 *	Always allocate at least DM_BUFIO_MIN_BUFFERS buffers.
 *	When there are DM_BUFIO_WRITEBACK_RATIO dirty buffers, start background
 *	writeback.
 */

#define DM_BUFIO_MIN_BUFFERS		8
#define DM_BUFIO_MEMORY_RATIO		2 / 100
#define DM_BUFIO_VMALLOC_RATIO		1 / 4
#define DM_BUFIO_WRITEBACK_RATIO	3 / 4

/* Check buffer ages in this interval (seconds) */
#define DM_BUFIO_WORK_TIMER		10

/* Free buffers when they are older than this (seconds) */
#define DM_BUFIO_DEFAULT_AGE		60

/*
 * The number of bvec entries that are embedded directly in the buffer.
 * If the chunk size is larger, dm-io is used to do the io.
 */
#define DM_BUFIO_INLINE_VECS		16

/*
 * Buffer hash
 */
#define DM_BUFIO_HASH_BITS	20
#define DM_BUFIO_HASH(block)	((((block) >> DM_BUFIO_HASH_BITS) ^ (block)) & ((1 << DM_BUFIO_HASH_BITS) - 1))

/*
 * Don't try to kmalloc blocks larger than this.
 * For explanation, see dm_bufio_alloc_buffer_data below.
 */
#define DM_BUFIO_BLOCK_SIZE_KMALLOC_LIMIT	(PAGE_SIZE >> 1)
#define DM_BUFIO_BLOCK_SIZE_GFP_LIMIT		(PAGE_SIZE << (MAX_ORDER - 1))

/*
 * dm_buffer->list_mode
 */
#define LIST_CLEAN	0
#define LIST_DIRTY	1
#define LIST_N		2

struct dm_bufio_client {
	/*
	 * Linking of buffers:
	 *	all buffers are linked to cache_hash with their hash_list field.
	 *	clean buffers that are not being written (B_WRITING not set)
	 *		are linked to lru[LIST_CLEAN] with their lru_list field.
	 *	dirty and clean buffers that are being written are linked
	 *		to lru[LIST_DIRTY] with their lru_list field. When the
	 *		write finishes, the buffer cannot be immediately
	 *		relinked (because we are in an interrupt context and
	 *		relinking requires process context), so some
	 *		clean-not-writing buffers can be held on dirty_lru too.
	 *		They are later added to lru in the process context.
	 */
	struct mutex lock;

	struct list_head lru[LIST_N];
	unsigned long n_buffers[LIST_N];

	struct block_device *bdev;
	unsigned block_size;
	unsigned char sectors_per_block_bits;
	unsigned char pages_per_block_bits;
	unsigned aux_size;
	void (*alloc_callback)(struct dm_buffer *);
	void (*write_callback)(struct dm_buffer *);

	struct dm_io_client *dm_io;

	struct list_head reserved_buffers;
	unsigned need_reserved_buffers;

	struct hlist_head *cache_hash;
	wait_queue_head_t free_buffer_wait;

	int async_write_error;

	struct list_head client_list;
};

/*
 * Buffer state bits.
 */
#define B_READING	0
#define B_WRITING	1
#define B_DIRTY		2

/*
 * A method, with which the data is allocated:
 * kmalloc(), __get_free_pages() or vmalloc().
 * See the comment at dm_bufio_alloc_buffer_data.
 */
#define DATA_MODE_KMALLOC		0
#define DATA_MODE_GET_FREE_PAGES	1
#define DATA_MODE_VMALLOC		2
#define DATA_MODE_LIMIT			3

struct dm_buffer {
	struct hlist_node hash_list;
	struct list_head lru_list;
	sector_t block;
	void *data;
	unsigned char data_mode;		/* DATA_MODE_* */
	unsigned char list_mode;		/* LIST_* */
	unsigned hold_count;
	int read_error;
	int write_error;
	unsigned long state;
	unsigned long last_accessed;
	struct dm_bufio_client *c;
	struct bio bio;
	struct bio_vec bio_vec[DM_BUFIO_INLINE_VECS];
};


/* Default cache size --- available memory divided by the ratio */
static unsigned long dm_bufio_default_cache_size = 0;

/* Total cache size set by the user */
static unsigned long dm_bufio_cache_size = 0;

/* A copy of dm_bufio_cache_size because dm_bufio_cache_size can change anytime.
   If it disagrees, the user has changed cache size */
static unsigned long dm_bufio_cache_size_latch = 0;

/* The module parameter */
module_param_named(cache_size, dm_bufio_cache_size, ulong, 0644);
MODULE_PARM_DESC(cache_size, "Size of metadata cache");

/* Buffers are freed after this timeout */
static unsigned dm_bufio_max_age = DM_BUFIO_DEFAULT_AGE;
module_param_named(max_age, dm_bufio_max_age, uint, 0644);
MODULE_PARM_DESC(max_age, "Max age of a buffer in seconds");

/* Total allocated memory */
static unsigned long dm_bufio_total_allocated = 0;
module_param_named(total_allocated, dm_bufio_total_allocated, ulong, 0444);
MODULE_PARM_DESC(total_allocated, "Allocated memory");

/* Memory allocated with kmalloc / get_free_pages / vmalloc */
static unsigned long dm_bufio_allocated_kmalloc = 0;
module_param_named(allocated_kmalloc, dm_bufio_allocated_kmalloc, ulong, 0444);
MODULE_PARM_DESC(allocated_kmalloc, "Memory allocated with kmalloc");
static unsigned long dm_bufio_allocated_get_free_pages = 0;
module_param_named(allocated_get_free_pages, dm_bufio_allocated_get_free_pages, ulong, 0444);
MODULE_PARM_DESC(allocated_get_free_pages, "Memory allocated with get_free_pages");
static unsigned long dm_bufio_allocated_vmalloc = 0;
module_param_named(allocated_vmalloc, dm_bufio_allocated_vmalloc, ulong, 0444);
MODULE_PARM_DESC(allocated_vmalloc, "Memory allocated with vmalloc");

/* Per-client cache: dm_bufio_cache_size / dm_bufio_client_count */
static unsigned long dm_bufio_cache_size_per_client;

/* The current number of clients */
static int dm_bufio_client_count;

/* The list of all clients */
static LIST_HEAD(dm_bufio_all_clients);

/* This mutex protects dm_bufio_cache_size_latch,
   dm_bufio_cache_size_per_client, dm_bufio_client_count */
static DEFINE_MUTEX(dm_bufio_clients_lock);

static void write_dirty_buffer(struct dm_buffer *b);
static void dm_bufio_write_dirty_buffers_async_unlocked(
				struct dm_bufio_client *c, int no_wait);


static void add_atomic(unsigned long *ptr, long diff)
{
	unsigned long latch;
	do {
		latch = *ptr;
		/* use barrier() so that *ptr is not read multiple times */
		barrier();
	} while (unlikely(cmpxchg(ptr, latch, latch + diff) != latch));
}

/*
 * An atomic addition to unsigned long.
 */
static void adjust_total_allocated(int class, long diff)
{
	unsigned long * const class_ptr[DATA_MODE_LIMIT] = {
		&dm_bufio_allocated_kmalloc,
		&dm_bufio_allocated_get_free_pages,
		&dm_bufio_allocated_vmalloc,
	};
	add_atomic(class_ptr[class], diff);
	add_atomic(&dm_bufio_total_allocated, diff);
}

/*
 * Change the number of clients and recalculate per-client limit.
 */
static void cache_size_refresh(void)
{
	BUG_ON(!mutex_is_locked(&dm_bufio_clients_lock));
	BUG_ON(dm_bufio_client_count < 0);
	dm_bufio_cache_size_latch = dm_bufio_cache_size;

	/*
	 * Prevent the compiler from using dm_bufio_cache_size anymore because
	 * it can change.
	 */
	barrier();

	if (!dm_bufio_cache_size_latch) {
		/*
		 * If the user uses "0", it means default.
		 * Modify dm_bufio_cache_size to report the real used cache
		 * size to the user.
		 */
		(void)cmpxchg(&dm_bufio_cache_size, 0,
			      dm_bufio_default_cache_size);
		dm_bufio_cache_size_latch = dm_bufio_default_cache_size;
	}
	dm_bufio_cache_size_per_client = dm_bufio_cache_size_latch /
		(dm_bufio_client_count ? dm_bufio_client_count : 1);
}

/*
 * Get writeback threshold and buffer limit for a given client.
 */
static void get_memory_limit(struct dm_bufio_client *c,
			     unsigned long *threshold_buffers,
			     unsigned long *limit_buffers)
{
	unsigned long buffers;

	if (unlikely(dm_bufio_cache_size != dm_bufio_cache_size_latch)) {
		mutex_lock(&dm_bufio_clients_lock);
		cache_size_refresh();
		mutex_unlock(&dm_bufio_clients_lock);
	}

	buffers = dm_bufio_cache_size_per_client >>
		  (c->sectors_per_block_bits + SECTOR_SHIFT);
	if (unlikely(buffers < DM_BUFIO_MIN_BUFFERS))
		buffers = DM_BUFIO_MIN_BUFFERS;
	*limit_buffers = buffers;
	*threshold_buffers = buffers * DM_BUFIO_WRITEBACK_RATIO;
}

/*
 * Allocating buffer data.
 *
 * Small buffers are allocated with kmalloc, to use space optimally.
 *
 * Large buffers:
 * We use get_free_pages or vmalloc, both have their advantages and
 * disadvantages.
 * __get_free_pages can randomly fail, if the memory is fragmented.
 * __vmalloc won't randomly fail, but vmalloc space is limited (it may be
 *	as low as 128M) --- so using it for caching is not appropriate.
 * If the allocation may fail we use __get_free_pages. Memory fragmentation
 *	won't have fatal effect here, it just causes flushes of some other
 *	buffers and more I/O will be performed. Don't use __get_free_pages if
 *	it always fails (i.e. order >= MAX_ORDER).
 * If the allocation shouldn't fail we use __vmalloc. This is only for
 *	the initial reserve allocation, so there's no risk of wasting
 *	all vmalloc space.
 */
static void *dm_bufio_alloc_buffer_data(struct dm_bufio_client *c,
					gfp_t gfp_mask, char *data_mode)
{
	if (c->block_size <= DM_BUFIO_BLOCK_SIZE_KMALLOC_LIMIT) {
		*data_mode = DATA_MODE_KMALLOC;
		return kmalloc(c->block_size, gfp_mask);
	} else if (c->block_size <= DM_BUFIO_BLOCK_SIZE_GFP_LIMIT &&
		   gfp_mask & __GFP_NORETRY) {
		*data_mode = DATA_MODE_GET_FREE_PAGES;
		return (void *)__get_free_pages(gfp_mask,
						c->pages_per_block_bits);
	} else {
		*data_mode = DATA_MODE_VMALLOC;
		return __vmalloc(c->block_size, gfp_mask, PAGE_KERNEL);
	}
}

/*
 * Free buffer's data.
 */
static void dm_bufio_free_buffer_data(struct dm_bufio_client *c,
				      void *data, char data_mode)
{
	switch (data_mode) {

	case DATA_MODE_KMALLOC:
		kfree(data);
		break;
	case DATA_MODE_GET_FREE_PAGES:
		free_pages((unsigned long)data, c->pages_per_block_bits);
		break;
	case DATA_MODE_VMALLOC:
		vfree(data);
		break;
	default:
		printk(KERN_CRIT "dm_bufio_free_buffer_data: bad data mode: %d",
		       data_mode);
		BUG();

	}
}

/*
 * Allocate buffer and its data.
 */
static struct dm_buffer *alloc_buffer(struct dm_bufio_client *c, gfp_t gfp_mask)
{
	struct dm_buffer *b;
	b = kmalloc(sizeof(struct dm_buffer) + c->aux_size, gfp_mask);
	if (unlikely(!b))
		return NULL;
	b->c = c;
	b->data = dm_bufio_alloc_buffer_data(c, gfp_mask, &b->data_mode);
	if (unlikely(!b->data)) {
		kfree(b);
		return NULL;
	}
	adjust_total_allocated(b->data_mode, (long)c->block_size);
	return b;
}

/*
 * Free buffer and its data.
 */
static void free_buffer(struct dm_buffer *b)
{
	struct dm_bufio_client *c = b->c;
	adjust_total_allocated(b->data_mode, -(long)c->block_size);
	dm_bufio_free_buffer_data(c, b->data, b->data_mode);
	kfree(b);
}


/*
 * Link buffer to the hash list and clean or dirty queue.
 */
static void link_buffer(struct dm_buffer *b, sector_t block, int dirty)
{
	struct dm_bufio_client *c = b->c;
	c->n_buffers[dirty]++;
	b->block = block;
	b->list_mode = dirty;
	list_add(&b->lru_list, &c->lru[dirty]);
	hlist_add_head(&b->hash_list, &c->cache_hash[DM_BUFIO_HASH(block)]);
	b->last_accessed = jiffies;
}

/*
 * Unlink buffer from the hash list and dirty or clean queue.
 */
static void unlink_buffer(struct dm_buffer *b)
{
	struct dm_bufio_client *c = b->c;
	BUG_ON(!c->n_buffers[b->list_mode]);
	c->n_buffers[b->list_mode]--;
	hlist_del(&b->hash_list);
	list_del(&b->lru_list);
}

/*
 * Place the buffer to the head of dirty or clean LRU queue.
 */
static void relink_lru(struct dm_buffer *b, int dirty)
{
	struct dm_bufio_client *c = b->c;
	BUG_ON(!c->n_buffers[b->list_mode]);
	c->n_buffers[b->list_mode]--;
	c->n_buffers[dirty]++;
	b->list_mode = dirty;
	list_del(&b->lru_list);
	list_add(&b->lru_list, &c->lru[dirty]);
}

/*
 * This function is called when wait_on_bit is actually waiting.
 */
static int do_io_schedule(void *word)
{
	io_schedule();

	return 0;
}

/*
 * Wait until any activity on the buffer finishes.
 * Possibly write the buffer if it is dirty.
 * When this function finishes, there is no I/O running on the buffer
 * and the buffer is not dirty.
 */
static void make_buffer_clean(struct dm_buffer *b)
{
	BUG_ON(b->hold_count);
	if (likely(!b->state))	/* fast case */
		return;
	wait_on_bit(&b->state, B_READING, do_io_schedule, TASK_UNINTERRUPTIBLE);
	write_dirty_buffer(b);
	wait_on_bit(&b->state, B_WRITING, do_io_schedule, TASK_UNINTERRUPTIBLE);
}

/*
 * Find some buffer that is not held by anybody, clean it, unlink it and
 * return it.
 * If "wait" is zero, try less hard and don't block.
 */
static struct dm_buffer *get_unclaimed_buffer(struct dm_bufio_client *c)
{
	struct dm_buffer *b;
	list_for_each_entry_reverse(b, &c->lru[LIST_CLEAN], lru_list) {
		cond_resched();
		BUG_ON(test_bit(B_WRITING, &b->state));
		BUG_ON(test_bit(B_DIRTY, &b->state));
		if (likely(!b->hold_count)) {
			make_buffer_clean(b);
			unlink_buffer(b);
			return b;
		}
	}
	list_for_each_entry_reverse(b, &c->lru[LIST_DIRTY], lru_list) {
		cond_resched();
		BUG_ON(test_bit(B_READING, &b->state));
		if (likely(!b->hold_count)) {
			make_buffer_clean(b);
			unlink_buffer(b);
			return b;
		}
	}
	return NULL;
}

/*
 * Wait until some other threads free some buffer or release hold count
 * on some buffer.
 *
 * This function is entered with c->lock held, drops it and regains it before
 * exiting.
 */
static void wait_for_free_buffer(struct dm_bufio_client *c)
{
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue(&c->free_buffer_wait, &wait);
	set_task_state(current, TASK_UNINTERRUPTIBLE);
	mutex_unlock(&c->lock);

	io_schedule();

	set_task_state(current, TASK_RUNNING);
	remove_wait_queue(&c->free_buffer_wait, &wait);

	mutex_lock(&c->lock);
}

/*
 * Allocate a new buffer. If the allocation is not possible, wait until some
 * other thread frees a buffer.
 *
 * May drop the lock and regain it.
 */
static struct dm_buffer *alloc_buffer_wait(struct dm_bufio_client *c)
{
	struct dm_buffer *b;

retry:
	/*
	 * This is useful for debugging. When we set cache size to 1,
	 * no new buffers are allocated at all.
	 */
	if (unlikely(dm_bufio_cache_size_latch == 1))
		goto skip_direct_alloc;

	/*
	 * dm-bufio is resistant to allocation failures (it just keeps
	 * one buffer reserved in cases all the allocations fail).
	 * So set flags to not try too hard:
	 *	GFP_NOIO: don't recurse into the I/O layer
	 *	__GFP_NORETRY: don't retry and rather return failure
	 *	__GFP_NOMEMALLOC: don't use emergency reserves
	 *	__GFP_NOWARN: don't print a warning in case of failure
	 */
	b = alloc_buffer(c, GFP_NOIO | __GFP_NORETRY | __GFP_NOMEMALLOC | __GFP_NOWARN);
	if (likely(b != NULL))
		goto return_b;

skip_direct_alloc:
	if (!list_empty(&c->reserved_buffers)) {
		b = list_entry(c->reserved_buffers.next, struct dm_buffer,
			       lru_list);
		list_del(&b->lru_list);
		c->need_reserved_buffers++;
		goto return_b;
	}

	b = get_unclaimed_buffer(c);
	if (b)
		goto return_b;

	wait_for_free_buffer(c);
	goto retry;

return_b:
	if (c->alloc_callback)
		c->alloc_callback(b);
	return b;
}

/*
 * Free a buffer and wake other threads waiting for free buffers.
 */
static void free_buffer_wake(struct dm_buffer *b)
{
	struct dm_bufio_client *c = b->c;

	if (unlikely(c->need_reserved_buffers != 0)) {
		list_add(&b->lru_list, &c->reserved_buffers);
		c->need_reserved_buffers--;
	} else
		free_buffer(b);

	wake_up(&c->free_buffer_wait);

	cond_resched();
}

/*
 * Check if we're over watermark.
 * If we are over threshold_buffers, start freeing buffers.
 * If we're over "limit_buffers", blocks until we get under the limit.
 */
static void check_watermark(struct dm_bufio_client *c)
{
	unsigned long threshold_buffers, limit_buffers;
	get_memory_limit(c, &threshold_buffers, &limit_buffers);

	while (c->n_buffers[LIST_CLEAN] + c->n_buffers[LIST_DIRTY] >
	       limit_buffers) {
		struct dm_buffer *b;
		b = get_unclaimed_buffer(c);
		if (!b)
			return;
		free_buffer_wake(b);
	}
	if (c->n_buffers[LIST_DIRTY] > threshold_buffers)
		dm_bufio_write_dirty_buffers_async_unlocked(c, 1);
}

static void dm_bufio_dmio_complete(unsigned long error, void *context);

/*
 * Submit I/O on the buffer.
 *
 * Bio interface is faster but it has some problems:
 *	- the vector list is limited (increasing this limit increases
 *		memory-consumption per buffer, so it is not viable)
 *	- the memory must be direct-mapped, not vmallocated
 *	- the I/O driver can spuriously reject requests if it thinks that
 *		the requests are too big for the device or if they cross a
 *		controller-defined memory boundary
 *
 * If the buffer is small enough (up to DM_BUFIO_INLINE_VECS pages) and
 * it is not vmalloc()ated, try using the bio interface.
 *
 * If the buffer is big, if it is vmalloc()ated or if the underlying device
 * rejects the bio because it is too large, use dm-io layer to do the I/O.
 * dmio layer splits the I/O to multiple requests, solving the above
 * shortcomings.
 */
static void dm_bufio_submit_io(struct dm_buffer *b, int rw, sector_t block,
			       bio_end_io_t *end_io)
{
	if (b->c->block_size <= DM_BUFIO_INLINE_VECS * PAGE_SIZE &&
	    b->data_mode != DATA_MODE_VMALLOC) {
		char *ptr;
		int len;
		bio_init(&b->bio);
		b->bio.bi_io_vec = b->bio_vec;
		b->bio.bi_max_vecs = DM_BUFIO_INLINE_VECS;
		b->bio.bi_sector = block << b->c->sectors_per_block_bits;
		b->bio.bi_bdev = b->c->bdev;
		b->bio.bi_end_io = end_io;

		/*
		 * we assume that if len >= PAGE_SIZE, ptr is page-aligned,
		 * if len < PAGE_SIZE, the buffer doesn't cross page boundary.
		 */
		ptr = b->data;
		len = b->c->block_size;
		do {
			if (!bio_add_page(&b->bio, virt_to_page(ptr),
					  len < PAGE_SIZE ? len : PAGE_SIZE,
					  virt_to_phys(ptr) & (PAGE_SIZE - 1))) {
				BUG_ON(b->c->block_size <= PAGE_SIZE);
				goto use_dmio;
			}
			len -= PAGE_SIZE;
			ptr += PAGE_SIZE;
		} while (len > 0);
		submit_bio(rw, &b->bio);
	} else
use_dmio : {
		int r;
		struct dm_io_request io_req = {
			.bi_rw = rw,
			.notify.fn = dm_bufio_dmio_complete,
			.notify.context = b,
			.client = b->c->dm_io,
		};
		struct dm_io_region region = {
			.bdev = b->c->bdev,
			.sector = block << b->c->sectors_per_block_bits,
			.count = b->c->block_size >> SECTOR_SHIFT,
		};
		if (b->data_mode != DATA_MODE_VMALLOC) {
			io_req.mem.type = DM_IO_KMEM;
			io_req.mem.ptr.addr = b->data;
		} else {
			io_req.mem.type = DM_IO_VMA;
			io_req.mem.ptr.vma = b->data;
		}
		b->bio.bi_end_io = end_io;
		r = dm_io(&io_req, 1, &region, NULL);
		if (unlikely(r))
			end_io(&b->bio, r);
	}
}

/*
 * dm-io completion routine. It just calls b->bio.bi_end_io, pretending
 * that the request was handled directly with bio interface.
 */
static void dm_bufio_dmio_complete(unsigned long error, void *context)
{
	struct dm_buffer *b = context;
	int err = 0;
	if (unlikely(error != 0))
		err = -EIO;
	b->bio.bi_end_io(&b->bio, err);
}

/* Find a buffer in the hash. */
static struct dm_buffer *dm_bufio_find(struct dm_bufio_client *c, sector_t block)
{
	struct dm_buffer *b;
	struct hlist_node *hn;
	hlist_for_each_entry(b, hn, &c->cache_hash[DM_BUFIO_HASH(block)], hash_list) {
		cond_resched();
		if (b->block == block)
			return b;
	}

	return NULL;
}

static void read_endio(struct bio *bio, int error);

#define DM_BUFIO_NEW_READ_NEW		0
#define DM_BUFIO_NEW_READ_READ		1
#define DM_BUFIO_NEW_READ_GET		2

/*
 * A common routine for dm_bufio_new and dm_bufio_read.
 * Operation of these function is very similar, except that dm_bufio_new
 * doesn't read the buffer from the disk (assuming that the caller overwrites
 * all the data and uses dm_bufio_mark_buffer_dirty to write new data back).
 */
static void *dm_bufio_new_read(struct dm_bufio_client *c, sector_t block,
			       struct dm_buffer **bp, int read)
{
	struct dm_buffer *b, *new_b = NULL;

	cond_resched();
	mutex_lock(&c->lock);
retry_search:
	b = dm_bufio_find(c, block);
	if (b) {
		if (unlikely(new_b != NULL))
			free_buffer_wake(new_b);
		b->hold_count++;
		relink_lru(b, test_bit(B_DIRTY, &b->state) ||
			      test_bit(B_WRITING, &b->state));
unlock_wait_ret:
		mutex_unlock(&c->lock);
wait_ret:
		wait_on_bit(&b->state, B_READING,
			    do_io_schedule, TASK_UNINTERRUPTIBLE);
		if (unlikely(b->read_error != 0)) {
			int error = b->read_error;
			dm_bufio_release(b);
			return ERR_PTR(error);
		}
		*bp = b;
		return b->data;
	}
	if (read == DM_BUFIO_NEW_READ_GET) {
		mutex_unlock(&c->lock);
		return NULL;
	}
	if (!new_b) {
		new_b = alloc_buffer_wait(c);
		goto retry_search;
	}

	check_watermark(c);

	b = new_b;
	b->hold_count = 1;
	b->read_error = 0;
	b->write_error = 0;
	link_buffer(b, block, 0);

	if (read == DM_BUFIO_NEW_READ_NEW) {
		b->state = 0;
		goto unlock_wait_ret;
	}

	b->state = 1 << B_READING;

	mutex_unlock(&c->lock);

	dm_bufio_submit_io(b, READ, b->block, read_endio);

	goto wait_ret;
}

/* Get a buffer from cache, but don't read it from disk */
void *dm_bufio_get(struct dm_bufio_client *c, sector_t block,
		   struct dm_buffer **bp)
{
	return dm_bufio_new_read(c, block, bp, DM_BUFIO_NEW_READ_GET);
}
EXPORT_SYMBOL(dm_bufio_get);

/* Read the buffer and hold reference on it */
void *dm_bufio_read(struct dm_bufio_client *c, sector_t block,
		    struct dm_buffer **bp)
{
	return dm_bufio_new_read(c, block, bp, DM_BUFIO_NEW_READ_READ);
}
EXPORT_SYMBOL(dm_bufio_read);

/* Get the buffer with possibly invalid data and hold reference on it */
void *dm_bufio_new(struct dm_bufio_client *c, sector_t block,
		   struct dm_buffer **bp)
{
	return dm_bufio_new_read(c, block, bp, DM_BUFIO_NEW_READ_NEW);
}
EXPORT_SYMBOL(dm_bufio_new);

/*
 * The endio routine for reading: set the error, clear the bit and wake up
 * anyone waiting on the buffer.
 */
static void read_endio(struct bio *bio, int error)
{
	struct dm_buffer *b = container_of(bio, struct dm_buffer, bio);
	b->read_error = error;
	BUG_ON(!test_bit(B_READING, &b->state));
	smp_mb__before_clear_bit();
	clear_bit(B_READING, &b->state);
	smp_mb__after_clear_bit();
	wake_up_bit(&b->state, B_READING);
}

/*
 * Release the reference held on the buffer.
 */
void dm_bufio_release(struct dm_buffer *b)
{
	struct dm_bufio_client *c = b->c;
	mutex_lock(&c->lock);
	BUG_ON(test_bit(B_READING, &b->state));
	BUG_ON(!b->hold_count);
	b->hold_count--;
	if (likely(!b->hold_count)) {
		wake_up(&c->free_buffer_wait);
		/*
		 * If there were errors on the buffer, and the buffer is not
		 * to be written, free the buffer. There is no point in caching
		 * invalid buffer.
		 */
		if ((b->read_error || b->write_error) &&
		    !test_bit(B_WRITING, &b->state) &&
		    !test_bit(B_DIRTY, &b->state)) {
			unlink_buffer(b);
			free_buffer_wake(b);
		}
	}
	mutex_unlock(&c->lock);
}
EXPORT_SYMBOL(dm_bufio_release);

/*
 * Mark that the data in the buffer were modified and the buffer needs to
 * be written back.
 */
void dm_bufio_mark_buffer_dirty(struct dm_buffer *b)
{
	struct dm_bufio_client *c = b->c;

	mutex_lock(&c->lock);

	if (!test_and_set_bit(B_DIRTY, &b->state))
		relink_lru(b, 1);

	mutex_unlock(&c->lock);
}
EXPORT_SYMBOL(dm_bufio_mark_buffer_dirty);

static void write_endio(struct bio *bio, int error);

/*
 * Initiate a write on a dirty buffer, but don't wait for it.
 * If the buffer is not dirty, exit.
 * If there some previous write going on, wait for it to finish (we can't
 * have two writes on the same buffer simultaneously).
 * Finally, submit our write and don't wait on it. We set B_WRITING indicating
 * that there is a write in progress.
 */
static void write_dirty_buffer(struct dm_buffer *b)
{
	if (!test_bit(B_DIRTY, &b->state))
		return;
	clear_bit(B_DIRTY, &b->state);
	wait_on_bit_lock(&b->state, B_WRITING,
			 do_io_schedule, TASK_UNINTERRUPTIBLE);
	if (b->c->write_callback)
		b->c->write_callback(b);
	dm_bufio_submit_io(b, WRITE, b->block, write_endio);
}

/*
 * The endio routine for write.
 * Set the error, clear B_WRITING bit and wake anyone who was waiting on it.
 */
static void write_endio(struct bio *bio, int error)
{
	struct dm_buffer *b = container_of(bio, struct dm_buffer, bio);
	b->write_error = error;
	if (unlikely(error)) {
		struct dm_bufio_client *c = b->c;
		(void)cmpxchg(&c->async_write_error, 0, error);
	}
	BUG_ON(!test_bit(B_WRITING, &b->state));
	smp_mb__before_clear_bit();
	clear_bit(B_WRITING, &b->state);
	smp_mb__after_clear_bit();
	wake_up_bit(&b->state, B_WRITING);
}

static void dm_bufio_write_dirty_buffers_async_unlocked(
				struct dm_bufio_client *c, int no_wait)
{
	struct dm_buffer *b, *tmp;
	list_for_each_entry_safe_reverse(b, tmp, &c->lru[LIST_DIRTY], lru_list) {
		cond_resched();
		BUG_ON(test_bit(B_READING, &b->state));
		if (!test_bit(B_DIRTY, &b->state) &&
		    !test_bit(B_WRITING, &b->state)) {
			relink_lru(b, 0);
			continue;
		}
		if (no_wait && test_bit(B_WRITING, &b->state))
			return;
		write_dirty_buffer(b);
	}
}

/*
 * Start writing all the dirty buffers. Don't wait for results.
 */
void dm_bufio_write_dirty_buffers_async(struct dm_bufio_client *c)
{
	mutex_lock(&c->lock);
	dm_bufio_write_dirty_buffers_async_unlocked(c, 0);
	mutex_unlock(&c->lock);
}
EXPORT_SYMBOL(dm_bufio_write_dirty_buffers_async);

/*
 * Write all the dirty buffers synchronously.
 * For performance, it is essential that the buffers are written asynchronously
 * and simultaneously (so that the block layer can merge the writes) and then
 * waited upon.
 *
 * Finally, we flush hardware disk cache.
 */
int dm_bufio_write_dirty_buffers(struct dm_bufio_client *c)
{
	int a, f;
	unsigned long buffers_processed = 0;
	struct dm_buffer *b, *tmp;

	dm_bufio_write_dirty_buffers_async(c);

	mutex_lock(&c->lock);
again:
	list_for_each_entry_safe_reverse(b, tmp, &c->lru[LIST_DIRTY], lru_list) {
		int dropped_lock = 0;
		if (buffers_processed < c->n_buffers[LIST_DIRTY])
			buffers_processed++;
		cond_resched();
		BUG_ON(test_bit(B_READING, &b->state));
		if (test_bit(B_WRITING, &b->state)) {
			if (buffers_processed < c->n_buffers[LIST_DIRTY]) {
				dropped_lock = 1;
				b->hold_count++;
				mutex_unlock(&c->lock);
				wait_on_bit(&b->state, B_WRITING,
					    do_io_schedule, TASK_UNINTERRUPTIBLE);
				mutex_lock(&c->lock);
				b->hold_count--;
			} else
				wait_on_bit(&b->state, B_WRITING,
					    do_io_schedule, TASK_UNINTERRUPTIBLE);
		}
		if (!test_bit(B_DIRTY, &b->state) &&
		    !test_bit(B_WRITING, &b->state))
			relink_lru(b, 0);

		/*
		 * If we dropped the lock, the list is no longer consistent,
		 * so we must restart the search.
		 *
		 * In the most common case, the buffer just processed is
		 * relinked to the clean list, so we won't loop scanning the
		 * same buffer again and again.
		 *
		 * This may livelock if there is another thread simultaneously
		 * dirtying buffers, so we count the number of buffers walked
		 * and if it exceeds the total number of buffers, it means that
		 * someone is doing some writes simultaneously with us --- in
		 * this case, stop dropping the lock.
		 */
		if (dropped_lock)
			goto again;
	}
	wake_up(&c->free_buffer_wait);
	mutex_unlock(&c->lock);

	a = xchg(&c->async_write_error, 0);
	f = dm_bufio_issue_flush(c);
	if (unlikely(a))
		return a;
	return f;
}
EXPORT_SYMBOL(dm_bufio_write_dirty_buffers);

/*
 * Use dm-io to send and empty barrier flush the device.
 */
int dm_bufio_issue_flush(struct dm_bufio_client *c)
{
	struct dm_io_request io_req = {
		.bi_rw = REQ_FLUSH,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = NULL,
		.client = c->dm_io,
	};
	struct dm_io_region io_reg = {
		.bdev = c->bdev,
		.sector = 0,
		.count = 0,
	};
	return dm_io(&io_req, 1, &io_reg, NULL);
}
EXPORT_SYMBOL(dm_bufio_issue_flush);

/*
 * Release the buffer and copy it to the new location.
 *
 * We first delete any other buffer that may be at that new location.
 *
 * Then, we write the buffer to the original location if it was dirty.
 *
 * Then, if we are the only one who is holding the buffer, relink the buffer
 * in the hash queue for the new location.
 *
 * If there was someone else holding the buffer, we write it to the new
 * location but not relink it, because that other user needs to have the buffer
 * at the same place.
 */
void dm_bufio_release_move(struct dm_buffer *b, sector_t new_block)
{
	struct dm_bufio_client *c = b->c;
	struct dm_buffer *underlying;

	mutex_lock(&c->lock);

retry:
	underlying = dm_bufio_find(c, new_block);
	if (unlikely(underlying != NULL)) {
		if (underlying->hold_count) {
			wait_for_free_buffer(c);
			goto retry;
		}
		make_buffer_clean(underlying);
		unlink_buffer(underlying);
		free_buffer_wake(underlying);
	}

	BUG_ON(!b->hold_count);
	BUG_ON(test_bit(B_READING, &b->state));
	write_dirty_buffer(b);
	if (b->hold_count == 1) {
		wait_on_bit(&b->state, B_WRITING,
			    do_io_schedule, TASK_UNINTERRUPTIBLE);
		set_bit(B_DIRTY, &b->state);
		unlink_buffer(b);
		link_buffer(b, new_block, 1);
	} else {
		wait_on_bit_lock(&b->state, B_WRITING,
				 do_io_schedule, TASK_UNINTERRUPTIBLE);
		dm_bufio_submit_io(b, WRITE, new_block, write_endio);
		wait_on_bit(&b->state, B_WRITING,
			    do_io_schedule, TASK_UNINTERRUPTIBLE);
	}
	mutex_unlock(&c->lock);
	dm_bufio_release(b);
}
EXPORT_SYMBOL(dm_bufio_release_move);

unsigned dm_bufio_get_block_size(struct dm_bufio_client *c)
{
	return c->block_size;
}
EXPORT_SYMBOL(dm_bufio_get_block_size);

sector_t dm_bufio_get_device_size(struct dm_bufio_client *c)
{
	return i_size_read(c->bdev->bd_inode) >>
				(SECTOR_SHIFT + c->sectors_per_block_bits);
}
EXPORT_SYMBOL(dm_bufio_get_device_size);

sector_t dm_bufio_get_block_number(struct dm_buffer *b)
{
	return b->block;
}
EXPORT_SYMBOL(dm_bufio_get_block_number);

void *dm_bufio_get_block_data(struct dm_buffer *b)
{
	return b->data;
}
EXPORT_SYMBOL(dm_bufio_get_block_data);

void *dm_bufio_get_aux_data(struct dm_buffer *b)
{
	return b + 1;
}
EXPORT_SYMBOL(dm_bufio_get_aux_data);

struct dm_bufio_client *dm_bufio_get_client(struct dm_buffer *b)
{
	return b->c;
}
EXPORT_SYMBOL(dm_bufio_get_client);

/*
 * Free all the buffers (and possibly write them if they were dirty)
 * It is required that the calling thread doesn't have any reference on
 * any buffer.
 */
void dm_bufio_drop_buffers(struct dm_bufio_client *c)
{
	struct dm_buffer *b;
	int i;

	/* an optimization ... so that the buffers are not written one-by-one */
	dm_bufio_write_dirty_buffers_async(c);

	mutex_lock(&c->lock);
	while ((b = get_unclaimed_buffer(c)))
		free_buffer_wake(b);

	for (i = 0; i < LIST_N; i++) {
		list_for_each_entry(b, &c->lru[i], lru_list) {
			printk(KERN_ERR "dm-bufio: leaked buffer %llx, hold count %u, list %d",
				(unsigned long long)b->block, b->hold_count, i);
		}
	}
	for (i = 0; i < LIST_N; i++)
		BUG_ON(!list_empty(&c->lru[i]));

	mutex_unlock(&c->lock);
}
EXPORT_SYMBOL(dm_bufio_drop_buffers);

/* Create the buffering interface */
struct dm_bufio_client *
dm_bufio_client_create(struct block_device *bdev, unsigned block_size,
		       unsigned reserved_buffers, unsigned aux_size,
		       void (*alloc_callback)(struct dm_buffer *),
		       void (*write_callback)(struct dm_buffer *))
{
	int r;
	struct dm_bufio_client *c;
	unsigned i;

	BUG_ON(block_size < 1 << SECTOR_SHIFT ||
	       (block_size & (block_size - 1)));

	c = kmalloc(sizeof(*c), GFP_KERNEL);
	if (!c) {
		r = -ENOMEM;
		goto bad_client;
	}
	c->cache_hash = vmalloc(sizeof(struct hlist_head) << DM_BUFIO_HASH_BITS);
	if (!c->cache_hash) {
		r = -ENOMEM;
		goto bad_hash;
	}

	c->bdev = bdev;
	c->block_size = block_size;
	c->sectors_per_block_bits = ffs(block_size) - 1 - SECTOR_SHIFT;
	c->pages_per_block_bits = (ffs(block_size) - 1 >= PAGE_SHIFT) ?
		(ffs(block_size) - 1 - PAGE_SHIFT) : 0;
	c->aux_size = aux_size;
	c->alloc_callback = alloc_callback;
	c->write_callback = write_callback;
	for (i = 0; i < LIST_N; i++) {
		INIT_LIST_HEAD(&c->lru[i]);
		c->n_buffers[i] = 0;
	}
	for (i = 0; i < 1 << DM_BUFIO_HASH_BITS; i++)
		INIT_HLIST_HEAD(&c->cache_hash[i]);
	mutex_init(&c->lock);
	INIT_LIST_HEAD(&c->reserved_buffers);
	c->need_reserved_buffers = reserved_buffers;

	init_waitqueue_head(&c->free_buffer_wait);
	c->async_write_error = 0;

	c->dm_io = dm_io_client_create();
	if (IS_ERR(c->dm_io)) {
		r = PTR_ERR(c->dm_io);
		goto bad_dm_io;
	}

	while (c->need_reserved_buffers) {
		struct dm_buffer *b = alloc_buffer(c, GFP_KERNEL);
		if (!b) {
			r = -ENOMEM;
			goto bad_buffer;
		}
		free_buffer_wake(b);
	}

	mutex_lock(&dm_bufio_clients_lock);
	dm_bufio_client_count++;
	list_add(&c->client_list, &dm_bufio_all_clients);
	cache_size_refresh();
	mutex_unlock(&dm_bufio_clients_lock);

	return c;

bad_buffer:
	while (!list_empty(&c->reserved_buffers)) {
		struct dm_buffer *b = list_entry(c->reserved_buffers.next,
						 struct dm_buffer, lru_list);
		list_del(&b->lru_list);
		free_buffer(b);
	}
	dm_io_client_destroy(c->dm_io);
bad_dm_io:
	vfree(c->cache_hash);
bad_hash:
	kfree(c);
bad_client:
	return ERR_PTR(r);
}
EXPORT_SYMBOL(dm_bufio_client_create);

/*
 * Free the buffering interface.
 * It is required that there are no references on any buffers.
 */
void dm_bufio_client_destroy(struct dm_bufio_client *c)
{
	unsigned i;
	dm_bufio_drop_buffers(c);

	mutex_lock(&dm_bufio_clients_lock);
	list_del(&c->client_list);
	dm_bufio_client_count--;
	cache_size_refresh();
	mutex_unlock(&dm_bufio_clients_lock);

	for (i = 0; i < 1 << DM_BUFIO_HASH_BITS; i++)
		BUG_ON(!hlist_empty(&c->cache_hash[i]));
	BUG_ON(c->need_reserved_buffers);
	while (!list_empty(&c->reserved_buffers)) {
		struct dm_buffer *b = list_entry(c->reserved_buffers.next,
						 struct dm_buffer, lru_list);
		list_del(&b->lru_list);
		free_buffer(b);
	}

	for (i = 0; i < LIST_N; i++) {
		if (c->n_buffers[i] != 0) {
			printk(KERN_ERR "dm-bufio: leaked buffer count %d: %ld",
				i, c->n_buffers[i]);
		}
	}
	for (i = 0; i < LIST_N; i++)
		BUG_ON(c->n_buffers[i] != 0);

	dm_io_client_destroy(c->dm_io);
	vfree(c->cache_hash);
	kfree(c);
}
EXPORT_SYMBOL(dm_bufio_client_destroy);

/*
 * Test if the buffer is unused and too old, and commit it.
 * At this point we must not do any I/O because we hold dm_bufio_clients_lock
 * and we would risk deadlock if the I/O gets rerouted to different bufio
 * client.
 */
static int cleanup_old_buffer(struct dm_buffer *b, unsigned long max_age)
{
	if (jiffies - b->last_accessed < max_age)
		return 1;

	if (unlikely(test_bit(B_READING, &b->state)) ||
	    unlikely(test_bit(B_WRITING, &b->state)) ||
	    unlikely(test_bit(B_DIRTY, &b->state)))
		return 1;

	if (unlikely(b->hold_count != 0))
		return 1;

	make_buffer_clean(b);
	unlink_buffer(b);
	free_buffer_wake(b);

	return 0;
}

static void cleanup_old_buffers(void)
{
	unsigned long long max_age;
	struct dm_bufio_client *c;

	max_age = dm_bufio_max_age;
	barrier();	/* prevent reusing of dm_bufio_max_age */
	max_age *= HZ;
	if (unlikely(max_age > ULONG_MAX))
		max_age = ULONG_MAX;

	mutex_lock(&dm_bufio_clients_lock);
	list_for_each_entry(c, &dm_bufio_all_clients, client_list) {
		struct dm_buffer *b;

		if (!mutex_trylock(&c->lock))
			continue;

		while (!list_empty(&c->lru[LIST_CLEAN])) {
			b = list_entry(c->lru[LIST_CLEAN].prev,
				       struct dm_buffer, lru_list);
			if (cleanup_old_buffer(b, max_age))
				break;
		}

		mutex_unlock(&c->lock);
	}
	mutex_unlock(&dm_bufio_clients_lock);
}


static struct workqueue_struct *dm_bufio_wq;
static struct delayed_work dm_bufio_work;

static void dm_bufio_work_fn(struct work_struct *w)
{
	cleanup_old_buffers();
	queue_delayed_work(dm_bufio_wq, &dm_bufio_work, DM_BUFIO_WORK_TIMER * HZ);
}

/*
 * This is called only once for the whole dm_bufio module.
 * It initializes memory limit.
 */
static int __init dm_bufio_init(void)
{
	__u64 mem;

	mem = (__u64)((totalram_pages - totalhigh_pages) * DM_BUFIO_MEMORY_RATIO)
		<< PAGE_SHIFT;
	if (mem > ULONG_MAX)
		mem = ULONG_MAX;
#ifdef CONFIG_MMU
	/*
	 * Get the size of vmalloc space,
	 * the same way as VMALLOC_TOTAL in fs/proc/internal.h
	 */
	if (mem > (VMALLOC_END - VMALLOC_START) * DM_BUFIO_VMALLOC_RATIO)
		mem = (VMALLOC_END - VMALLOC_START) * DM_BUFIO_VMALLOC_RATIO;
#endif
	dm_bufio_default_cache_size = mem;
	mutex_lock(&dm_bufio_clients_lock);
	cache_size_refresh();
	mutex_unlock(&dm_bufio_clients_lock);

	dm_bufio_wq = create_singlethread_workqueue("dm_bufio_cache");
	if (!dm_bufio_wq)
		return -ENOMEM;
	INIT_DELAYED_WORK(&dm_bufio_work, dm_bufio_work_fn);
	queue_delayed_work(dm_bufio_wq, &dm_bufio_work, DM_BUFIO_WORK_TIMER * HZ);

	return 0;
}

/*
 * This is called once when unloading the dm_bufio module.
 */
static void __exit dm_bufio_exit(void)
{
	int bug;

	cancel_delayed_work_sync(&dm_bufio_work);
	destroy_workqueue(dm_bufio_wq);

	bug = 0;
	if (dm_bufio_client_count != 0) {
		printk(KERN_CRIT "%s: dm_bufio_client_count leaked: %d",
			__func__, dm_bufio_client_count);
		bug = 1;
	}
	if (dm_bufio_total_allocated != 0) {
		printk(KERN_CRIT "%s: dm_bufio_total_allocated leaked: %lu",
			__func__, dm_bufio_total_allocated);
		bug = 1;
	}
	if (bug)
		BUG();
}

module_init(dm_bufio_init)
module_exit(dm_bufio_exit)

MODULE_AUTHOR("Mikulas Patocka <mpatocka@redhat.com>");
MODULE_DESCRIPTION(DM_NAME " buffered I/O library");
MODULE_LICENSE("GPL");


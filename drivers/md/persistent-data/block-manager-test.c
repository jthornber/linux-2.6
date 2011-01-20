#include "block-manager.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>

/*----------------------------------------------------------------*/

#define BM_BLOCK_SIZE 4096
#define NR_BLOCKS 1024
#define CACHE_SIZE 16

typedef int (*test_fn)(struct block_manager *);

static unsigned char data[BM_BLOCK_SIZE];

static void barf(const char *msg)
{
	printk(KERN_ALERT "%s\n", msg);
	BUG_ON(1);
}

static int run_test(const char *name, test_fn fn)
{
	int r;
	int mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;
	struct block_device *bdev = blkdev_get_by_path("/dev/sdb",
						       mode,
						       &run_test);
	struct block_manager *bm;

	if (IS_ERR(bdev))
		return -1;
	printk(KERN_ALERT "bdev opened\n");

	bm = block_manager_create(bdev, BM_BLOCK_SIZE, CACHE_SIZE);

	if (!bm)
		barf("couldn't create bm");

	printk(KERN_ALERT "running %s ... ", name);
	r = fn(bm);
	printk(r == 0 ? KERN_ALERT "pass\n" : KERN_ALERT "fail\n");

	block_manager_destroy(bm);
	blkdev_put(bdev, mode);
	return 0;
}

static int read_test(struct block_manager *bm)
{
	int i;
	struct block *b;

	for (i = 0; i < NR_BLOCKS; i++) {
		if (bm_read_lock(bm, i, &b) < 0)
			barf("bm_lock failed");

		memset(data, i, sizeof(data));
		if (memcmp(data, block_data(b), BM_BLOCK_SIZE))
			printk(KERN_ALERT "block %d failed\n", i);

		if (bm_unlock(b) < 0)
			barf("bm_unlock failed");
	}

	if (bm_locks_held(bm) != 0) {
		printk(KERN_ALERT "locks still held %u\n", bm_locks_held(bm));
		return -1;
	}

	return 0;
}

/*
 * scrolls a window of write locks across the device.
 */
#define WINDOW_SIZE CACHE_SIZE

static int windowed_writes(struct block_manager *bm)
{
	block_t bi;
	struct block **pb;
	static struct block *blocks[WINDOW_SIZE];

	for (bi = 0; bi < WINDOW_SIZE; bi++) {
		pb = blocks + bi;
		if (bm_write_lock(bm, bi, pb) < 0)
			barf("couldn't lock block");

		memset(block_data(*pb), 1, BM_BLOCK_SIZE);
	}

	if (bm_locks_held(bm) != WINDOW_SIZE) {
		printk(KERN_ALERT "locks still held %u\n", bm_locks_held(bm));
		return -1;
	}

	for (; bi < NR_BLOCKS; bi++) {
		pb = blocks + (bi % WINDOW_SIZE);
		if (bm_unlock(*pb) < 0)
			barf("bm_unlock");

		if (bm_write_lock(bm, bi, pb) < 0)
			barf("couldn't lock block");

		memset(block_data(*pb), 1, BM_BLOCK_SIZE);
	}


	printk(KERN_ALERT "about to unlock last window\n");
	for (bi = 0; bi < WINDOW_SIZE; bi++) {
		pb = blocks + (bi % WINDOW_SIZE);
		if (bm_unlock(*pb) < 0)
			barf("bm_unlock");
	}

	memset(data, 1, BM_BLOCK_SIZE);
	for (bi = 0; bi < NR_BLOCKS; bi++) {
		struct block *blk;

		if (bm_read_lock(bm, bi, &blk) < 0)
			barf("bm_lock");

		BUG_ON(memcmp(block_data(blk), data, BM_BLOCK_SIZE));

		if (bm_unlock(blk) < 0)
			barf("bm_unlock");
	}

	bm_flush(bm, 1);

	for (bi = 0; bi < NR_BLOCKS; bi++) {
		struct block *blk;

		if (bm_read_lock(bm, bi, &blk) < 0)
			barf("bm_lock");

		BUG_ON(memcmp(block_data(blk), data, BM_BLOCK_SIZE));

		if (bm_unlock(blk) < 0)
			barf("bm_unlock");
	}

	return 0;
}

/* FIXME: this behaviour will change, when we start to support concurrency
 * properly.
 */
static int double_read_lock_fails(struct block_manager *bm)
{
	struct block *b;

	if (bm_read_lock(bm, 0, &b) < 0) {
		printk(KERN_ALERT "bm_read_lock failed\n");
		return -1;
	}

	if (bm_read_lock(bm, 0, &b) == 0) {
		printk(KERN_ALERT "bm_read_lock unexpectedly succeeded\n");
		return -1;
	}

	if (bm_unlock(b) < 0) {
		printk(KERN_ALERT "bm_unlock failed\n");
		return -1;
	}

	return 0;
}

/* FIXME: this behaviour will change, when we start to support concurrency
 * properly.
 */
static int double_write_lock_fails(struct block_manager *bm)
{
	struct block *b;

	if (bm_write_lock(bm, 0, &b) < 0) {
		printk(KERN_ALERT "bm_write_lock failed\n");
		return -1;
	}

	if (bm_write_lock(bm, 0, &b) == 0) {
		printk(KERN_ALERT "bm_write_lock unexpectedly succeeded\n");
		return -1;
	}

	if (bm_unlock(b) < 0) {
		printk(KERN_ALERT "bm_unlock failed\n");
		return -1;
	}

	return 0;
}

/*----------------------------------------------------------------*/

static int block_manager_test_init(void)
{
	static struct {
		const char *name;
		test_fn fn;
	} table_[] = {
		{"read blocks", read_test},
		{"windowed writes", windowed_writes},
		{"trying to read lock twice", double_read_lock_fails},
		{"trying to write lock twice", double_write_lock_fails}
	};

	int i;

	for (i = 0; i < sizeof(table_) / sizeof(*table_); i++)
		run_test(table_[i].name, table_[i].fn);

	return 0;
}

static void block_manager_test_exit(void)
{
	printk(KERN_ALERT "block_manager_test exit\n");
}

module_init(block_manager_test_init);
module_exit(block_manager_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joe Thornber");
MODULE_DESCRIPTION("Test code for block-manager");

/*----------------------------------------------------------------*/

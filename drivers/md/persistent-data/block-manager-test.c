#include "dm-block-manager.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>

/*----------------------------------------------------------------*/

#define BM_BLOCK_SIZE 4096
#define NR_BLOCKS 1024
#define CACHE_SIZE 16

typedef int (*test_fn)(struct dm_block_manager *);

static unsigned char data[BM_BLOCK_SIZE];

static void barf(const char *msg)
{
	pr_alert("%s\n", msg);
	BUG_ON(1);
}

static int run_test(const char *name, test_fn fn)
{
	int r;
	fmode_t mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;
	struct block_device *bdev = blkdev_get_by_path("/dev/vdc",
						       mode,
						       &run_test);
	struct dm_block_manager *bm;

	if (IS_ERR(bdev))
		return -1;
	pr_alert("bdev opened\n");

	bm = dm_block_manager_create(bdev, BM_BLOCK_SIZE, CACHE_SIZE, CACHE_SIZE);

	if (!bm)
		barf("couldn't create bm");

	pr_alert("running %s ... ", name);
	r = fn(bm);
	if (!r)
		pr_alert("pass\n");
	else
		pr_alert("fail\n");

	dm_block_manager_destroy(bm);
	blkdev_put(bdev, mode);
	return 0;
}

static int read_test(struct dm_block_manager *bm)
{
	int i;
	struct dm_block *b;

	for (i = 0; i < NR_BLOCKS; i++) {
		if (dm_bm_read_lock(bm, i, NULL, &b) < 0)
			barf("dm_bm_lock failed");

		if (dm_bm_unlock(b) < 0)
			barf("dm_bm_unlock failed");
	}

#if 0
	if (dm_bm_locks_held(bm) != 0) {
		pr_alert("locks still held %u\n", dm_bm_locks_held(bm));
		return -1;
	}
#endif

	return 0;
}

/*
 * scrolls a window of write locks across the device.
 */
#define WINDOW_SIZE CACHE_SIZE

static int windowed_writes(struct dm_block_manager *bm)
{
	dm_block_t bi;
	struct dm_block **pb;
	static struct dm_block *blocks[WINDOW_SIZE];

	for (bi = 0; bi < WINDOW_SIZE; bi++) {
		pb = blocks + bi;
		if (dm_bm_write_lock(bm, bi, NULL, pb) < 0)
			barf("couldn't lock block");

		memset(dm_block_data(*pb), 1, BM_BLOCK_SIZE);
	}

#if 0
	if (dm_bm_locks_held(bm) != WINDOW_SIZE) {
		pr_alert("locks still held %u\n", dm_bm_locks_held(bm));
		return -1;
	}
#endif

	for (; bi < NR_BLOCKS; bi++) {
		pb = blocks + (bi % WINDOW_SIZE);
		if (dm_bm_unlock(*pb) < 0)
			barf("dm_bm_unlock");

		if (dm_bm_write_lock(bm, bi, NULL, pb) < 0)
			barf("couldn't lock block");

		memset(dm_block_data(*pb), 1, BM_BLOCK_SIZE);
	}


	pr_alert("about to unlock last window\n");
	for (bi = 0; bi < WINDOW_SIZE; bi++) {
		pb = blocks + (bi % WINDOW_SIZE);
		if (dm_bm_unlock(*pb) < 0)
			barf("dm_bm_unlock");
	}

	memset(data, 1, BM_BLOCK_SIZE);
	for (bi = 0; bi < NR_BLOCKS; bi++) {
		struct dm_block *blk;

		if (dm_bm_read_lock(bm, bi, NULL, &blk) < 0)
			barf("dm_bm_lock");

		BUG_ON(memcmp(dm_block_data(blk), data, BM_BLOCK_SIZE));

		if (dm_bm_unlock(blk) < 0)
			barf("dm_bm_unlock");
	}

	for (bi = 0; bi < NR_BLOCKS; bi++) {
		struct dm_block *blk;

		if (dm_bm_read_lock(bm, bi, NULL, &blk) < 0)
			barf("dm_bm_lock");

		BUG_ON(memcmp(dm_block_data(blk), data, BM_BLOCK_SIZE));

		if (dm_bm_unlock(blk) < 0)
			barf("dm_bm_unlock");
	}

	return 0;
}

/*----------------------------------------------------------------*/

static int __init block_manager_test_init(void)
{
	static struct {
		const char *name;
		test_fn fn;
	} table_[] = {
		{"read blocks", read_test},
		{"windowed writes", windowed_writes},
	};

	int i;

	for (i = 0; i < sizeof(table_) / sizeof(*table_); i++)
		run_test(table_[i].name, table_[i].fn);

	return 0;
}

module_init(block_manager_test_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joe Thornber");
MODULE_DESCRIPTION("Test code for block-manager");

/*----------------------------------------------------------------*/

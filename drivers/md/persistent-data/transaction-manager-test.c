#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>

#include "transaction-manager.h"
#include "space-map-core.h"

/*----------------------------------------------------------------*/

#define NR_BLOCKS 1024
#define BM_BLOCK_SIZE 4096
#define CACHE_SIZE 16

typedef int (*test_fn)(struct transaction_manager *);

/*----------------------------------------------------------------*/

static int check_commit(struct transaction_manager *tm)
{
	int r, i;
	block_t sb;
	struct block *superblock;

	r = tm_begin(tm);
	if (r < 0)
		return r;

	r = tm_new_block(tm, &superblock);
	if (r < 0)
		return r;

	for (i = 0; i < 10; i++) {
		struct block *b;
		r = tm_new_block(tm, &b);
		if (r < 0)
			return r;
	}

	r = tm_pre_commit(tm);
	if (r < 0)
		return r;

	sb = block_location(superblock);

	r = tm_commit(tm, superblock);
	if (r < 0)
		return r;

	/* check the lock on superblock was dropped */
	r = tm_read_lock(tm, sb, &superblock);
	if (r < 0)
		return r;

	return 0;
}

/*----------------------------------------------------------------*/

static int run_test(const char *name, test_fn fn)
{
	int r;
	struct space_map *sm = sm_core_create(NR_BLOCKS);
	int mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;
	struct block_device *bdev = blkdev_get_by_path("/dev/sdb", mode, &run_test);
	struct block_manager *bm;
	struct transaction_manager *tm;

	if (IS_ERR(bdev))
		return -1;

	bm = block_manager_create(bdev, BM_BLOCK_SIZE, CACHE_SIZE);
	if (!bm)
		return -1;

	tm = tm_create(bm, sm);
	if (!tm)
		return -1;

	printk(KERN_ALERT "running %s ... ", name);
	r = fn(tm);
	printk(r == 0 ? KERN_ALERT "pass\n" : KERN_ALERT "fail\n");

	tm_destroy(tm);
	block_manager_destroy(bm);
	blkdev_put(bdev, mode);
	sm_destroy(sm);
	return 0;
}

static int transaction_manager_test_init(void)
{
	static struct {
		const char *name;
		test_fn fn;
	} table_[] = {
		{"check commit", check_commit}
	};

	int i;

	for (i = 0; i < sizeof(table_) / sizeof(*table_); i++)
		run_test(table_[i].name, table_[i].fn);

	return 0;
}

static void transaction_manager_test_exit(void)
{
}

module_init(transaction_manager_test_init);
module_exit(transaction_manager_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joe Thornber");
MODULE_DESCRIPTION("Test code for transaction manager");

/*----------------------------------------------------------------*/

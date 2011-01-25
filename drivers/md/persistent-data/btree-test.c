#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>

#include "btree.h"
#include "transaction-manager.h"
#include "space-map-core.h"

/*----------------------------------------------------------------*/

#define NR_BLOCKS 1024
#define BM_BLOCK_SIZE 4096
#define CACHE_SIZE 16		/* small enough that there will be a lot of contention */

typedef int (*test_fn)(struct transaction_manager *);

/*----------------------------------------------------------------*/

/*
 * For these tests we're not interested in the space map root, so we roll
 * tm_pre_commit() and tm_commit() into one function.
 */
static int begin(struct transaction_manager *tm, struct block **superblock)
{
	int r;

	r = tm_new_block(tm, superblock);
	if (r < 0)
		return r;

	return tm_begin(tm);
}

static int begin_again(struct transaction_manager *tm, block_t sb, struct block **superblock)
{
	int r = bm_write_lock(tm_get_bm(tm), sb, superblock);
	if (r < 0)
		return r;

	return tm_begin(tm);
}

static void commit(struct transaction_manager *tm, struct block *superblock)
{
	tm_pre_commit(tm);
	tm_commit(tm, superblock);
}

static uint64_t next_rand(uint64_t last)
{
	/* FIXME: check how good this is */
	const uint64_t a = 274177;
	const uint64_t c = 1;
	return a * last + c;
}

#define INSERT_COUNT 5000
static int check_insert_commit_every(struct transaction_manager *tm,
				     unsigned commit_interval)
{
	int r, i, committed = 1;
	uint64_t key = 0;
	uint64_t value = 0;
	block_t root = 0;
	struct btree_info info;
	struct block *superblock;

	info.tm = tm;
	info.levels = 1;
	info.value_size = sizeof(uint64_t);
	info.adjust = value_is_meaningless;
	info.eq = NULL;

	r = begin(tm, &superblock);
	if (r < 0) {
		printk(KERN_ALERT "begin failed");
		return r;
	}

	r = btree_empty(&info, &root);
	if (r < 0) {
		printk(KERN_ALERT "btree_empty failed");
		return r;
	}

	/* write some random entries into the btree */
	for (i = 0; i < INSERT_COUNT; i++) {
		committed = 0;
		key = next_rand(value);
		value = next_rand(key);
		r = btree_insert(&info, root, &key, &value, &root);
		if (r < 0) {
			printk(KERN_ALERT "insert failed");
			return r;
		}

		if ((i + 1 % commit_interval) == 0) {
			block_t b = block_location(superblock);
			commit(tm, superblock);
			r = begin_again(tm, b, &superblock);
			if (r < 0)
				return r;
			committed = 1;
		}
	}

	if (!committed)
		commit(tm, superblock);

	/* check they're all still there */
	key = value = 0;
	for (i = 0; i < INSERT_COUNT; i++) {
		uint64_t value2;
		key = next_rand(value);
		value = next_rand(key);

		r = btree_lookup_equal(&info, root, &key, &value2);
		if (r < 0)
			return r;

		if (value2 != value) {
			printk(KERN_ALERT "wrong value");
			return -1;
		}
	}

	return 0;
}

static int check_insert(struct transaction_manager *tm)
{
	return check_insert_commit_every(tm, 100000);
}

static int check_multiple_commits(struct transaction_manager *tm)
{
	return check_insert_commit_every(tm, 100);
}

static int check_lookup_empty(struct transaction_manager *tm)
{
	int r;
	uint64_t key = 100;
	__le64 value;
	block_t root = 0;
	struct btree_info info;
	struct block *superblock;

	info.tm = tm;
	info.levels = 1;
	info.value_size = sizeof(uint64_t);
	info.adjust = value_is_meaningless;
	info.eq = NULL;

	r = begin(tm, &superblock);
	if (r < 0) {
		printk(KERN_ALERT "begin failed");
		return r;
	}

	r = btree_empty(&info, &root);
	if (r < 0) {
		printk(KERN_ALERT "btree_empty failed");
		return r;
	}

	r = btree_lookup_equal(&info, root, &key, &value);
	if (r == 0) {
		printk(KERN_ALERT "value unexpectedly found");
		return -1;
	}

	if (r < 0 && r != -ENODATA)
		return r;

	commit(tm, superblock);
	return 0;
}

static int check_insert_h(struct transaction_manager *tm)
{
	typedef uint64_t table_entry[5];
	static table_entry table[] = {
		{ 1, 1, 1, 1, 100 },
		{ 1, 1, 1, 2, 101 },
		{ 1, 1, 1, 3, 102 },

		{ 1, 1, 2, 1, 200 },
		{ 1, 1, 2, 2, 201 },
		{ 1, 1, 2, 3, 202 },

		{ 2, 1, 1, 1, 301 },
		{ 2, 1, 1, 2, 302 },
		{ 2, 1, 1, 3, 303 }
	};

	static table_entry overwrites[] = {
		{ 1, 1, 1, 1, 1000 }
	};

	uint64_t value;
	block_t root = 0, sb;
	int i, r;
	struct btree_info info;
	struct block *superblock;

	info.tm = tm;
	info.levels = 4;
	info.value_size = sizeof(uint64_t);
	info.adjust = value_is_meaningless;
	info.eq = NULL;

	r = begin(tm, &superblock);
	if (r < 0)
		return r;
	sb = block_location(superblock);

	r = btree_empty(&info, &root);
	if (r < 0) {
		printk(KERN_ALERT "btree_empty() failed");
		return r;
	}

	for (i = 0; i < sizeof(table) / sizeof(*table); i++) {
		r = btree_insert(&info, root, table[i], &table[i][4], &root);
		if (r < 0) {
			printk(KERN_ALERT "btree_insert failed");
			return r;
		}
	}
	commit(tm, superblock);

	for (i = 0; i < sizeof(table) / sizeof(*table); i++) {
		r = btree_lookup_equal(&info, root, table[i], &value);
		if (r < 0) {
			printk(KERN_ALERT "btree_lookup_equal failed");
			return r;
		}

		if (value != table[i][4]) {
			printk(KERN_ALERT "bad lookup");
			return -1;
		}
	}

	/* check multiple transactions are ok */
	{
		uint64_t keys[4] = { 1, 1, 1, 4 }, value, v = 2112;

		r = begin_again(tm, sb, &superblock);
		if (r < 0)
			return r;

		r = btree_insert(&info, root, keys, &v, &root);
		if (r < 0) {
			printk(KERN_ALERT "btree_insert failed");
			return r;
		}

		commit(tm, superblock);

		r = btree_lookup_equal(&info, root, keys, &value);
		if (r < 0) {
			printk(KERN_ALERT "btree_lookup_equal failed");
			return r;
		}

		if (value != 2112) {
			printk(KERN_ALERT "unexpected lookup");
			return -1;
		}
	}

	/* check overwrites */
	begin_again(tm, sb, &superblock);
	for (i = 0; i < sizeof(overwrites) / sizeof(*overwrites); i++) {
		r = btree_insert(&info, root, overwrites[i], &overwrites[i][4], &root);
		if (r < 0) {
			printk(KERN_ALERT "btree_insert failed");
			return r;
		}
	}
	commit(tm, superblock);

	for (i = 0; i < sizeof(overwrites) / sizeof(*overwrites); i++) {
		r = btree_lookup_equal(&info, root, overwrites[i], &value);
		if (r < 0) {
			printk(KERN_ALERT "btree_lookup_equal failed");
			return r;
		}

		if (value != overwrites[i][4]) {
			printk(KERN_ALERT "bad lookup");
			return -1;
		}
	}
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

static int btree_test_init(void)
{
	static struct {
		const char *name;
		test_fn fn;
	} table_[] = {
		{"lookup in an empty btree", check_lookup_empty},
		{"check insert", check_insert},
		{"check insert, commit every 100", check_multiple_commits},
		{"check hierarchical insert", check_insert_h}
	};

	int i;

	for (i = 0; i < sizeof(table_) / sizeof(*table_); i++)
		run_test(table_[i].name, table_[i].fn);

	return 0;
}

static void btree_test_exit(void)
{
}

module_init(btree_test_init);
module_exit(btree_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joe Thornber");
MODULE_DESCRIPTION("Test code for B+ trees");

/*----------------------------------------------------------------*/

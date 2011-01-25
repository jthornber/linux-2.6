#include <linux/blkdev.h>
#include <linux/device-mapper.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "thinp-metadata.h"

/*----------------------------------------------------------------*/

#define NR_BLOCKS 1024
#define BM_BLOCK_SIZE 4096
#define CACHE_SIZE 16
#define DATA_BLOCK_SIZE ((1024 * 1024 * 128) >> SECTOR_SHIFT)

#define DATA_DEV_SIZE 10000

typedef int (*test_fn)(struct thinp_metadata *tpm);

/*----------------------------------------------------------------*/

static int check_empty_transaction(struct thinp_metadata *tpm)
{
	return thinp_metadata_commit(tpm);
}

static int check_insert_1_transaction(struct thinp_metadata *tpm)
{
	int r;
	static block_t map[DATA_DEV_SIZE];
	block_t tb;

	for (tb = 0; tb < DATA_DEV_SIZE; tb++) {
		block_t pb;

		r = thinp_metadata_insert(tpm, 0, tb, map + tb);
		if (r < 0) {
			printk(KERN_ALERT "insert failed");
			return r;
		}

		/* check we can lookup straight away */
		r = thinp_metadata_lookup(tpm, 0, tb, 1, &pb);
		if (r < 0) {
			printk(KERN_ALERT "first lookup failed (%u)", (unsigned) tb);
			return r;
		}

		if (pb != map[tb]) {
			printk(KERN_ALERT "first comparison failed");
			return -1;
		}
	}

	r = thinp_metadata_commit(tpm);
	if (r < 0) {
		printk(KERN_ALERT "commit failed");
		return r;
	}
	printk(KERN_ALERT "%u inserts in a single commit",
	       DATA_DEV_SIZE);

	/* check we can lookup after a commit */
	for (tb = 0; tb < DATA_DEV_SIZE; tb++) {
		block_t pb;

		r = thinp_metadata_lookup(tpm, 0, tb, 1, &pb);
		if (r < 0) {
			printk(KERN_ALERT "thinp-metadata_lookup failed for block %u",
			       (unsigned) tb);
			return r;
		}

		if (pb != map[tb]) {
			printk(KERN_ALERT "unexpected mapping");
			return -1;
		}
	}


	return 0;
}

static int check_insert_multi_transaction(struct thinp_metadata *tpm)
{
	int r;
	static block_t map[DATA_DEV_SIZE];
	block_t tb;

	for (tb = 0; tb < DATA_DEV_SIZE; tb++) {
		block_t pb;

		r = thinp_metadata_insert(tpm, 0, tb, map + tb);
		if (r < 0)
			return r;

		/* check we can lookup straight away */
		r = thinp_metadata_lookup(tpm, 0, tb, 1, &pb);
		if (r < 0)
			return r;

		if (pb != map[tb])
			return -1;

		r = thinp_metadata_commit(tpm);
		if (r < 0)
			return r;
	}

	/* check we can lookup after a commit */
	for (tb = 0; tb < DATA_DEV_SIZE; tb++) {
		block_t pb;

		r = thinp_metadata_lookup(tpm, 0, tb, 1, &pb);
		if (r < 0) {
			printk(KERN_ALERT "thinp-metadata_lookup failed for block %u",
			       (unsigned) tb);
			return r;
		}

		if (pb != map[tb]) {
			printk(KERN_ALERT "unexpected mapping");
			return -1;
		}
	}

	printk(KERN_ALERT "%u insert/commit cycles",
	       DATA_DEV_SIZE);

	return 0;
}

static int check_accessors(struct thinp_metadata *tpm)
{
	int r;
	sector_t s;
	block_t b;

	r = thinp_metadata_get_data_block_size(tpm, 0, &s);
	if (r < 0) {
		printk(KERN_ALERT "get_data_block_size() failed");
		return r;
	}

	if (s != DATA_BLOCK_SIZE) {
		printk(KERN_ALERT "data block size incorrect");
		return -1;
	}

	r = thinp_metadata_get_data_dev_size(tpm, 0, &b);
	if (r < 0) {
		printk(KERN_ALERT "get_data_dev_size failed");
		return -1;
	}

	if (b != DATA_DEV_SIZE) {
		printk(KERN_ALERT "data dev size incorrect");
		return -1;
	}

	r = thinp_metadata_get_provisioned_blocks(tpm, 0, &b);
	if (r < 0) {
		printk(KERN_ALERT "data_first_free() failed");
		return -1;
	}

	if (b != 0) {
		printk(KERN_ALERT "data first free incorrect");
		return -1;
	}

	r = thinp_metadata_resize_data_dev(tpm, 0, 101);
	if (r < 0) {
		printk(KERN_ALERT "resize_data_dev() failed");
		return -1;
	}

	r = thinp_metadata_get_data_dev_size(tpm, 0, &b);
	if (r < 0) {
		printk(KERN_ALERT "get_data_dev_size failed(2)");
		return -1;
	}

	if (b != 101) {
		printk(KERN_ALERT "data dev size incorrect(2)");
		return -1;
	}

	return 0;
}

/*----------------------------------------------------------------*/

static int run_test(const char *name, test_fn fn)
{
	int r;
	struct thinp_metadata *tpm;
	struct block_device *bdev;
	int mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;
	bdev = blkdev_get_by_path("/dev/sdb", mode, &run_test);
	if (IS_ERR(bdev))
		return -1;

	tpm = thinp_metadata_create(bdev,
				    i_size_read(bdev->bd_inode) >> SECTOR_SHIFT,
				    DATA_BLOCK_SIZE,
				    DATA_DEV_SIZE);
	if (!tpm) {
		printk(KERN_ALERT "couldn't create tpm");
		return -1;
	}

	printk(KERN_ALERT "running %s ... ", name);
	r = fn(tpm);
	printk(r == 0 ? KERN_ALERT "pass\n" : KERN_ALERT "fail\n");

	thinp_metadata_close(tpm);
	blkdev_put(bdev, mode);
	return 0;
}

static int thinp_metadata_test_init(void)
{
	static struct {
		const char *name;
		test_fn fn;
	} table_[] = {
		{"empty transaction", check_empty_transaction},
		{"check multiple inserts within one transaction", check_insert_1_transaction},
		{"check 1 insert per transaction", check_insert_multi_transaction},
		{"checking accessor functions", check_accessors}
	};

	int i;

	for (i = 0; i < sizeof(table_) / sizeof(*table_); i++)
		run_test(table_[i].name, table_[i].fn);

	return 0;
}

static void thinp_metadata_test_exit(void)
{
}

module_init(thinp_metadata_test_init);
module_exit(thinp_metadata_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joe Thornber");
MODULE_DESCRIPTION("Test code for thin provisioning metadata code");

/*----------------------------------------------------------------*/

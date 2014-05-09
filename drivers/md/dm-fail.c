/*
 * Copyright (C) 2014 Red Hat UK.
 *
 * This file is released under the GPL.
 */

#include "dm.h"
#include <linux/module.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "fail"

struct fail_c {
	struct dm_dev *dev;
	sector_t start;
	unsigned fail_dir;
	atomic_t reads_failed;
	atomic_t writes_failed;
};

static int parse_directions(struct fail_c *fc, const char *str)
{
	fc->fail_dir = 0;
	while (*str) {
		switch (*str) {
		case 'r':
			fc->fail_dir |= READ;
			break;

		case 'w':
			fc->fail_dir |= WRITE;
			break;

		default:
			return -EINVAL;
		}

		str++;
	}

	return 0;
}

/*
 * <dev> <offset> <dirs>
 * where:
 *    <dirs> = [rw]+
 */
static int fail_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct fail_c *fc;
	unsigned long long tmp;
	char dummy;

	if (argc != 3) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	fc = kmalloc(sizeof(*fc), GFP_KERNEL);
	if (fc == NULL) {
		ti->error = "dm-fail: Cannot allocate context";
		return -ENOMEM;
	}

	if (sscanf(argv[1], "%llu%c", &tmp, &dummy) != 1) {
		ti->error = "dm-fail: Invalid device sector";
		goto bad;
	}
	fc->start = tmp;

	if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &fc->dev)) {
		ti->error = "dm-fail: Device lookup failed";
		goto bad;
	}

	if (parse_directions(fc, argv[2])) {
		ti->error = "dm-fail: Invalid io directions (should be [rw]*)";
		goto bad;
	}

	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->num_write_same_bios = 1;
	ti->private = fc;
	return 0;

      bad:
	kfree(fc);
	return -EINVAL;
}

static void fail_dtr(struct dm_target *ti)
{
	struct fail_c *fc = (struct fail_c *) ti->private;

	dm_put_device(ti, fc->dev);
	kfree(fc);
}

static sector_t fail_map_sector(struct dm_target *ti, sector_t bi_sector)
{
	struct fail_c *fc = ti->private;

	return fc->start + dm_target_offset(ti, bi_sector);
}

static int fail_map(struct dm_target *ti, struct bio *bio)
{
	struct fail_c *fc = ti->private;

	if (bio_data_dir(bio) & fc->fail_dir) {
		bio_io_error(bio);
		return DM_MAPIO_SUBMITTED;

	} else {
		bio->bi_bdev = fc->dev->bdev;
		if (bio_sectors(bio))
			bio->bi_iter.bi_sector = fail_map_sector(ti, bio->bi_iter.bi_sector);

		return DM_MAPIO_REMAPPED;
	}
}

static void fail_status(struct dm_target *ti, status_type_t type,
			  unsigned status_flags, char *result, unsigned maxlen)
{
	struct fail_c *fc = (struct fail_c *) ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:
		snprintf(result, maxlen, "%s %llu", fc->dev->name,
				(unsigned long long)fc->start);
		break;
	}
}

static int fail_ioctl(struct dm_target *ti, unsigned int cmd,
			unsigned long arg)
{
	struct fail_c *fc = (struct fail_c *) ti->private;
	struct dm_dev *dev = fc->dev;
	int r = 0;

	/*
	 * Only pass ioctls through if the device sizes match exactly.
	 */
	if (fc->start ||
	    ti->len != i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT)
		r = scsi_verify_blk_ioctl(NULL, cmd);

	return r ? : __blkdev_driver_ioctl(dev->bdev, dev->mode, cmd, arg);
}

static int fail_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
			struct bio_vec *biovec, int max_size)
{
	struct fail_c *fc = ti->private;
	struct request_queue *q = bdev_get_queue(fc->dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = fc->dev->bdev;
	bvm->bi_sector = fail_map_sector(ti, bvm->bi_sector);

	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int fail_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct fail_c *fc = ti->private;

	return fn(ti, fc->dev, fc->start, ti->len, data);
}

static struct target_type fail_target = {
	.name   = "fail",
	.version = {1, 2, 1},
	.module = THIS_MODULE,
	.ctr    = fail_ctr,
	.dtr    = fail_dtr,
	.map    = fail_map,
	.status = fail_status,
	.ioctl  = fail_ioctl,
	.merge  = fail_merge,
	.iterate_devices = fail_iterate_devices,
};

static int __init dm_fail_init(void)
{
	int r = dm_register_target(&fail_target);

	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

static void dm_fail_exit(void)
{
	dm_unregister_target(&fail_target);
}

module_init(dm_fail_init);
module_exit(dm_fail_exit);

MODULE_DESCRIPTION(DM_NAME " IO failure target");
MODULE_AUTHOR("Joe Thornber <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");

/*
 * Copyright (C) 2012 RedHat.
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

#define DM_MSG_PREFIX "fake-discard"

struct fake_discard {
	struct dm_dev *dev;
	sector_t offset;

	bool supports_discard;
	bool discard_zeroes_data;

	unsigned discard_granularity;
	unsigned max_discard_sectors;
};

/*----------------------------------------------------------------*/

static int parse_features(struct dm_arg_set *as, struct fake_discard *fd,
			  struct dm_target *ti)
{
	int r;
	unsigned argc;
	const char *arg_name;

	static struct dm_arg _args[] = {
		{0, 2, "Invalid number of feature arguments"}
	};

	fd->supports_discard = true;
	fd->discard_zeroes_data = false;

	if (!as->argc)
		return 0;

	r = dm_read_arg_group(_args, as, &argc, &ti->error);
	if (r)
		return r;

	while (argc && !r) {
		arg_name = dm_shift_arg(as);
		argc--;

		if (!strcasecmp(arg_name, "no_discard_support"))
			fd->supports_discard = false;

		else if (!strcasecmp(arg_name, "discard_zeroes_data"))
			fd->discard_zeroes_data = true;

		else {
			ti->error = "Unrecognised feature requested";
			r = -EINVAL;
			break;
		}
	}

	return r;
}

/*
 * fake-discard <dev path>
 *              <offset>
 *              <granularity>
 *              <max discard sectors>
 *              [<#feature args> <arg>*]
 *
 * Optional feature arguments are:
 *	        no_discard_support
 *              discard_zeroes_data
 */
static int discard_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct fake_discard *fd;
	unsigned long long tmp;
	struct dm_arg_set as;
	char dummy;

	if (argc < 4) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	fd = kmalloc(sizeof(*fd), GFP_KERNEL);
	if (!fd) {
		ti->error = "out of memory";
		return -ENOMEM;
	}

	if (sscanf(argv[1], "%llu%c", &tmp, &dummy) != 1) {
		ti->error = "Invalid offset sector";
		goto bad;
	}
	fd->offset = tmp;

	if (sscanf(argv[2], "%u%c", &fd->discard_granularity, &dummy) != 1) {
		ti->error = "Invalid discard granularity";
		goto bad;
	}

	if (!is_power_of_2(fd->discard_granularity)) {
		ti->error = "Discard granularity must be a power of 2";
		goto bad;
	}

	if (sscanf(argv[3], "%u%c", &fd->max_discard_sectors, &dummy) != 1) {
		ti->error = "Invalid max discard sectors";
		goto bad;
	}

	if (fd->discard_granularity > fd->max_discard_sectors) {
		ti->error = "Discard granularity cannot be larger than max discard sectors";
		goto bad;
	}

	as.argc = argc;
	as.argv = argv;
	dm_consume_args(&as, 4);
	if (parse_features(&as, fd, ti))
		goto bad;

	if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &fd->dev)) {
		ti->error = "dm-linear: Device lookup failed";
		goto bad;
	}

	if (fd->supports_discard) {
		ti->discards_supported = true;
		ti->discards_unsupported = false;
		ti->num_discard_requests = 1;
	} else {
		ti->discards_supported = false;
		ti->discards_unsupported = true;
		ti->num_discard_requests = 0;
	}

	if (fd->discard_zeroes_data) {
		ti->pretend_discard_zeroes_data = true;
		ti->discard_zeroes_data_unsupported = false;
	} else {
		ti->pretend_discard_zeroes_data = false;
		ti->discard_zeroes_data_unsupported = true;
	}

	ti->split_discard_requests = true;
	ti->num_flush_requests = 1;
	ti->private = fd;

	return 0;

bad:
	kfree(fd);
	return -EINVAL;
}

static void discard_dtr(struct dm_target *ti)
{
	struct fake_discard *fd = ti->private;

	dm_put_device(ti, fd->dev);
	kfree(fd);
}

static int discard_map(struct dm_target *ti, struct bio *bio,
		       union map_info *map_context)
{
	struct fake_discard *fd = ti->private;

	if (bio->bi_rw & REQ_DISCARD) {
		if (fd->supports_discard) {
			bio_endio(bio, 0);
			return DM_MAPIO_SUBMITTED;
		} else
			bio_endio(bio, -ENOTSUPP);
	} else {
		bio->bi_bdev = fd->dev->bdev;
		bio->bi_sector = dm_target_offset(ti, bio->bi_sector) + fd->offset;
	}

	return DM_MAPIO_REMAPPED;
}

static int discard_status(struct dm_target *ti, status_type_t type,
			  unsigned status_flags, char *result, unsigned maxlen)
{
	struct fake_discard *fd = ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:
		snprintf(result, maxlen, "%s %llu %u %u %u",
			 fd->dev->name,
			 (unsigned long long) fd->offset,
			 fd->discard_granularity,
			 fd->max_discard_sectors,
			 fd->discard_zeroes_data);
		break;
	}

	return 0;
}

static int discard_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
			 struct bio_vec *biovec, int max_size)
{
	struct fake_discard *fd = ti->private;
	struct request_queue *q = bdev_get_queue(fd->dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = fd->dev->bdev;
	bvm->bi_sector = dm_target_offset(ti, bvm->bi_sector) + fd->offset;

	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static int discard_iterate_devices(struct dm_target *ti,
				   iterate_devices_callout_fn fn, void *data)
{
	struct fake_discard *fd = ti->private;

	return fn(ti, fd->dev, fd->offset, ti->len, data);
}

static void discard_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct fake_discard *fd = ti->private;

	limits->discard_granularity = fd->discard_granularity;
	limits->max_discard_sectors = fd->max_discard_sectors;
}

static struct target_type fake_discard_target = {
	.name   = "fake-discard",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr    = discard_ctr,
	.dtr    = discard_dtr,
	.map    = discard_map,
	.status = discard_status,
	.merge  = discard_merge,
	.iterate_devices = discard_iterate_devices,
	.io_hints = discard_io_hints,
};

static int __init dm_discard_init(void)
{
	int r = dm_register_target(&fake_discard_target);

	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

static void dm_discard_exit(void)
{
	dm_unregister_target(&fake_discard_target);
}

module_init(dm_discard_init);
module_exit(dm_discard_exit);

MODULE_DESCRIPTION(DM_NAME " fake discard target");
MODULE_AUTHOR("Joe Thornber <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");

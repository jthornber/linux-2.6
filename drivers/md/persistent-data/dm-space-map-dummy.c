#include "dm-space-map-staged.h"

/*----------------------------------------------------------------*/

struct sm_dummy {
	dm_block_t nr_blocks;
};

static void sm_dummy_destroy(struct dm_space_map *sm)
{
	kfree(sm->context);
	kfree(sm);
}

static int sm_dummy_get_nr_blocks(void *context, dm_block_t *count)
{
	struct sm_dummy *sm = (struct sm_dummy *) context;
	*count = sm->nr_blocks;
	return 0;
}

static int sm_dummy_get_count(void *context, dm_block_t b, uint32_t *result)
{
	*result = 0;
	return 0;
}

static int sm_dummy_set_count(void *context, dm_block_t b, uint32_t count)
{
	BUG_ON(1);
	return -1;
}

static int sm_dummy_get_free_in_range(void *context, dm_block_t low,
				      dm_block_t high, dm_block_t *b)
{
	*b = low;
	return 0;
}

static int sm_dummy_get_free(void *context, dm_block_t *b)
{
	BUG_ON(1);
	return -1;
}

static int sm_dummy_root_size(void *context, size_t *result)
{
	BUG_ON(1);
	return -1;
}

static int sm_dummy_copy_root(void *context, void *copy_to_here, size_t len)
{
	BUG_ON(1);
	return -1;
}

static int sm_dummy_commit(void *context)
{
	BUG_ON(1);
	return -1;
}


static struct dm_space_map_ops ops_ = {
	.destroy = sm_dummy_destroy,
	.get_nr_blocks = sm_dummy_get_nr_blocks,
	.get_nr_free = sm_dummy_get_nr_blocks, /* dummy can't allocate */
	.get_count = sm_dummy_get_count,
	.set_count = sm_dummy_set_count,
	.get_free = sm_dummy_get_free,
	.get_free_in_range = sm_dummy_get_free_in_range,
	.root_size = sm_dummy_root_size,
	.copy_root = sm_dummy_copy_root,
	.commit = sm_dummy_commit,
};

struct dm_space_map *dm_sm_dummy_create(dm_block_t nr_blocks)
{
	struct dm_space_map *sm = NULL;
	struct sm_dummy *smc;

	smc = kmalloc(sizeof(*smc), GFP_KERNEL);
	if (smc) {
		smc->nr_blocks = nr_blocks;
		sm = kmalloc(sizeof(*sm), GFP_KERNEL);
		if (!sm) {
			kfree(smc);
		} else {
			sm->ops = &ops_;
			sm->context = smc;
		}
	}

	return sm;
}
EXPORT_SYMBOL_GPL(dm_sm_dummy_create);

/*----------------------------------------------------------------*/

#include "dm-space-map-core.h"

#include <linux/export.h>

/*----------------------------------------------------------------*/

struct sm_core {
	struct dm_space_map sm;
	dm_block_t nr;
	dm_block_t nr_free;
	dm_block_t maybe_first_free;
	uint32_t counts[0];
};

static void sm_core_destroy(struct dm_space_map *sm)
{
	kfree(sm);
}

static int sm_core_get_nr_blocks(struct dm_space_map *sm, dm_block_t *count)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	*count = smc->nr;
	return 0;
}

static int sm_core_get_nr_free(struct dm_space_map *sm, dm_block_t *count)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	*count = smc->nr_free;
	return 0;
}

static int sm_core_new_block(struct dm_space_map *sm, dm_block_t *b)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	dm_block_t i;

	for (i = smc->maybe_first_free; i < smc->nr; i++) {
		if (smc->counts[i] == 0) {
			smc->counts[i] = 1;
			*b = i;
			smc->maybe_first_free = i + 1;
			smc->nr_free--;
			return 0;
		}
	}

	return -ENOSPC;
}

static int sm_core_inc_block(struct dm_space_map *sm, dm_block_t b)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	if (b >= smc->nr)
		return -EINVAL;

	if (!smc->counts[b]++)
		smc->nr_free--;

	return 0;
}

static int sm_core_dec_block(struct dm_space_map *sm, dm_block_t b)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	if (b >= smc->nr)
		return -EINVAL;

	BUG_ON(smc->counts[b] == 0);
	smc->counts[b]--;

	if (smc->counts[b] == 0) {
		smc->nr_free++;
		if (smc->maybe_first_free > b)
			smc->maybe_first_free = b;
	}

	return 0;
}

static int sm_core_get_count(struct dm_space_map *sm, dm_block_t b, uint32_t *result)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);

	if (b >= smc->nr)
		return -EINVAL;

	*result = smc->counts[b];
	return 0;
}

static int sm_core_count_more_than_one(struct dm_space_map *sm, dm_block_t b, int *result)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);

	*result = smc->counts[b] > 1;
	return 0;
}

static int sm_core_set_count(struct dm_space_map *sm, dm_block_t b, uint32_t count)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);

	if (b >= smc->nr)
		return -EINVAL;

	if (count == 0) {
		smc->nr_free++;
		if (smc->maybe_first_free > b)
			smc->maybe_first_free = b;
	}

	smc->counts[b] = count;
	return 0;
}

static int sm_core_commit(struct dm_space_map *sm)
{
	return 0;
}

/*----------------------------------------------------------------*/

static struct dm_space_map ops_ = {
	.destroy = sm_core_destroy,
	.get_nr_blocks = sm_core_get_nr_blocks,
	.get_nr_free = sm_core_get_nr_free,
	.inc_block = sm_core_inc_block,
	.dec_block = sm_core_dec_block,
	.new_block = sm_core_new_block,
	.get_count = sm_core_get_count,
	.count_is_more_than_one = sm_core_count_more_than_one,
	.set_count = sm_core_set_count,
	.commit = sm_core_commit
};

struct dm_space_map *dm_sm_core_create(dm_block_t nr_blocks)
{
	size_t array_size = nr_blocks * sizeof(uint32_t);
	struct sm_core *smc;

	smc = kmalloc(sizeof(*smc) + array_size, GFP_KERNEL);
	if (smc) {
		memcpy(&smc->sm, &ops_, sizeof(smc->sm));
		smc->nr = nr_blocks;
		smc->nr_free = nr_blocks;
		smc->maybe_first_free = 0;
		memset(smc->counts, 0, array_size);
	}

	return &smc->sm;
}
EXPORT_SYMBOL_GPL(dm_sm_core_create);

/*----------------------------------------------------------------*/

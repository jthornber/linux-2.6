#include "dm-space-map-core.h"

/*----------------------------------------------------------------*/

struct sm_core {
	dm_block_t nr;
	dm_block_t maybe_first_free;
	uint32_t counts[0];
};

static void destroy(void *context)
{
	struct sm_core *sm = (struct sm_core *) context;
	kfree(sm);
}

static int get_nr_blocks(void *context, dm_block_t *count)
{
	struct sm_core *sm = (struct sm_core *) context;
	*count = sm->nr;
	return 0;
}

static int get_free(void *context, dm_block_t *b)
{
	struct sm_core *sm = (struct sm_core *) context;
	dm_block_t i;

	for (i = sm->maybe_first_free; i < sm->nr; i++) {
		if (sm->counts[i] == 0) {
			*b = i;
			return 0;
		}
	}

	return -ENOSPC;
}

static int get_free_in_range(void *context, dm_block_t low, dm_block_t high, dm_block_t *b)
{
	struct sm_core *sm = (struct sm_core *) context;
	dm_block_t i;

	low = max(low, sm->maybe_first_free);
	high = min(high, sm->nr);

	for (i = low; i < high; i++) {
		if (sm->counts[i] == 0) {
			*b = i;
			return 0;
		}
	}

	return -ENOSPC;
}

static int new_block(void *context, dm_block_t *b)
{
	struct sm_core *sm = (struct sm_core *) context;
	dm_block_t i;

	for (i = sm->maybe_first_free; i < sm->nr; i++) {
		if (sm->counts[i] == 0) {
			sm->counts[i] = 1;
			*b = i;
			sm->maybe_first_free = i + 1;
			return 0;
		}
	}

	return -ENOSPC;
}

static int inc_block(void *context, dm_block_t b)
{
	struct sm_core *sm = (struct sm_core *) context;
	if (b >= sm->nr)
		return -EINVAL;

	sm->counts[b]++;
	return 0;
}

static int dec_block(void *context, dm_block_t b)
{
	struct sm_core *sm = (struct sm_core *) context;
	if (b >= sm->nr)
		return -EINVAL;

	BUG_ON(sm->counts[b] == 0);
	sm->counts[b]--;

	if (sm->counts[b] == 0 && sm->maybe_first_free > b)
		sm->maybe_first_free = b;

	return 0;
}

static int get_count(void *context, dm_block_t b, uint32_t *result)
{
	struct sm_core *sm = (struct sm_core *) context;
	if (b >= sm->nr)
		return -EINVAL;

	*result = sm->counts[b];
	return 0;
}

static int set_count(void *context, dm_block_t b, uint32_t count)
{
	struct sm_core *sm = (struct sm_core *) context;
	if (b >= sm->nr)
		return -EINVAL;

	if (count == 0 && sm->maybe_first_free > b)
		sm->maybe_first_free = b;

	sm->counts[b] = count;
	return 0;
}

static int commit(void *context)
{
	return 0;
}

/*----------------------------------------------------------------*/

static struct dm_space_map_ops ops_ = {
	.destroy = destroy,
	.get_nr_blocks = get_nr_blocks,
	.get_free = get_free,
	.get_free_in_range = get_free_in_range,
	.inc_block = inc_block,
	.dec_block = dec_block,
	.new_block = new_block,
	.get_count = get_count,
	.set_count = set_count,
	.commit = commit
};

struct dm_space_map *dm_sm_core_create(dm_block_t nr_blocks)
{
	struct dm_space_map *sm = NULL;
	size_t array_size = nr_blocks * sizeof(uint32_t);
	struct sm_core *smc = kmalloc(sizeof(*smc) + array_size, GFP_KERNEL);
	if (smc) {
		smc->nr = nr_blocks;
		smc->maybe_first_free = 0;
		memset(smc->counts, 0, array_size);

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
EXPORT_SYMBOL_GPL(dm_sm_core_create);

/*----------------------------------------------------------------*/

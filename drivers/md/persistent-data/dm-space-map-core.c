#include "dm-space-map-core.h"

#include <linux/spinlock.h>

/*----------------------------------------------------------------*/

struct sm_core {
	struct dm_space_map sm;
	spinlock_t lock;
	dm_block_t nr;
	dm_block_t nr_free;
	dm_block_t maybe_first_free;
	uint32_t *counts;
};

static void sm_core_destroy(struct dm_space_map *sm)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	kfree(smc->counts);
	kfree(smc);
}

static int sm_core_extend(struct dm_space_map *sm, dm_block_t extra_blocks)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	unsigned long flags;
	uint32_t *old, *new = kmalloc(sizeof(*new) * (smc->nr + extra_blocks), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	spin_lock_irqsave(&smc->lock, flags);
	memset(new, 0, sizeof(*new) * (smc->nr + extra_blocks));
	memcpy(new, smc->counts, sizeof(*new) * smc->nr);
	old = smc->counts;
	smc->counts = new;
	smc->nr += extra_blocks;
	spin_unlock_irqrestore(&smc->lock, flags);

	kfree(old);
	printk(KERN_ALERT "core_sm extended to %u\n", (unsigned) smc->nr);

	return 0;
}

static int sm_core_get_nr_blocks(struct dm_space_map *sm, dm_block_t *count)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	unsigned long flags;
	spin_lock_irqsave(&smc->lock, flags);
	*count = smc->nr;
	spin_unlock_irqrestore(&smc->lock, flags);

	return 0;
}

static int sm_core_get_nr_free(struct dm_space_map *sm, dm_block_t *count)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	unsigned long flags;
	spin_lock_irqsave(&smc->lock, flags);
	*count = smc->nr_free;
	spin_unlock_irqrestore(&smc->lock, flags);
	return 0;
}

static int sm_core_new_block(struct dm_space_map *sm, dm_block_t *b)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	unsigned long flags;
	dm_block_t i;

	spin_lock_irqsave(&smc->lock, flags);
	for (i = smc->maybe_first_free; i < smc->nr; i++) {
		if (smc->counts[i] == 0) {
			smc->counts[i] = 1;
			*b = i;
			smc->maybe_first_free = i + 1;
			smc->nr_free--;
			spin_unlock_irqrestore(&smc->lock, flags);
			return 0;
		}
	}
	spin_unlock_irqrestore(&smc->lock, flags);

	return -ENOSPC;
}

static int sm_core_inc_block(struct dm_space_map *sm, dm_block_t b)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	unsigned long flags;

	spin_lock_irqsave(&smc->lock, flags);
	if (b >= smc->nr) {
		spin_unlock_irqrestore(&smc->lock, flags);
		return -EINVAL;
	}

	if (!smc->counts[b]++)
		smc->nr_free--;

	spin_unlock_irqrestore(&smc->lock, flags);
	return 0;
}

static int sm_core_dec_block(struct dm_space_map *sm, dm_block_t b)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	unsigned long flags;

	spin_lock_irqsave(&smc->lock, flags);
	if (b >= smc->nr) {
		spin_unlock_irqrestore(&smc->lock, flags);
		return -EINVAL;
	}

	BUG_ON(smc->counts[b] == 0);
	smc->counts[b]--;

	if (smc->counts[b] == 0) {
		smc->nr_free++;
		if (smc->maybe_first_free > b)
			smc->maybe_first_free = b;
	}
	spin_unlock_irqrestore(&smc->lock, flags);
	return 0;
}

static int sm_core_get_count(struct dm_space_map *sm, dm_block_t b, uint32_t *result)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	unsigned long flags;

	spin_lock_irqsave(&smc->lock, flags);
	if (b >= smc->nr) {
		spin_unlock_irqrestore(&smc->lock, flags);
		return -EINVAL;
	}

	*result = smc->counts[b];
	spin_unlock_irqrestore(&smc->lock, flags);
	return 0;
}

static int sm_core_count_more_than_one(struct dm_space_map *sm, dm_block_t b, int *result)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	unsigned long flags;
	spin_lock_irqsave(&smc->lock, flags);
	*result = smc->counts[b] > 1;
	spin_unlock_irqrestore(&smc->lock, flags);
	return 0;
}

static int sm_core_set_count(struct dm_space_map *sm, dm_block_t b, uint32_t count)
{
	struct sm_core *smc = container_of(sm, struct sm_core, sm);
	unsigned long flags;

	spin_lock_irqsave(&smc->lock, flags);
	if (b >= smc->nr) {
		spin_unlock_irqrestore(&smc->lock, flags);
		return -EINVAL;
	}

	if (count == 0) {
		smc->nr_free++;
		if (smc->maybe_first_free > b)
			smc->maybe_first_free = b;
	}

	smc->counts[b] = count;
	spin_unlock_irqrestore(&smc->lock, flags);
	return 0;
}

static int sm_core_commit(struct dm_space_map *sm)
{
	return 0;
}

static int sm_core_root_size(struct dm_space_map *sm, size_t *result)
{
        *result = 8;
        return 0;
}

static int sm_core_copy_root(struct dm_space_map *sm, void *dest, size_t len)
{
        return 0;
}

/*----------------------------------------------------------------*/

static struct dm_space_map ops_ = {
	.destroy = sm_core_destroy,
	.extend = sm_core_extend,
	.get_nr_blocks = sm_core_get_nr_blocks,
	.get_nr_free = sm_core_get_nr_free,
	.inc_block = sm_core_inc_block,
	.dec_block = sm_core_dec_block,
	.new_block = sm_core_new_block,
	.get_count = sm_core_get_count,
	.count_is_more_than_one = sm_core_count_more_than_one,
	.set_count = sm_core_set_count,
	.commit = sm_core_commit,
        .root_size = sm_core_root_size,
        .copy_root = sm_core_copy_root
};

struct dm_space_map *dm_sm_core_create(dm_block_t nr_blocks)
{
	size_t array_size = nr_blocks * sizeof(uint32_t);
	struct sm_core *smc;

	smc = kmalloc(sizeof(*smc), GFP_KERNEL);
	if (smc) {
		memcpy(&smc->sm, &ops_, sizeof(smc->sm));
		spin_lock_init(&smc->lock);
		smc->nr = nr_blocks;
		smc->nr_free = nr_blocks;
		smc->maybe_first_free = 0;
		smc->counts = kmalloc(array_size, GFP_KERNEL);
		memset(smc->counts, 0, array_size);
	}

	return &smc->sm;
}
EXPORT_SYMBOL_GPL(dm_sm_core_create);

/*----------------------------------------------------------------*/

#include "dm-thin-metadata.h"

#include <linux/device-mapper.h>

/*----------------------------------------------------------------*/

struct dm_pool_metadata {
	spinlock_t lock;

	sector_t block_size;
	dm_block_t nr_blocks;
	dm_block_t next_free;

	uint32_t *mappings;
};

struct dm_thin_device {
	struct dm_pool_metadata *pmd;
	dm_thin_id id;
};

struct dm_pool_metadata *dm_pool_metadata_open(struct block_device *bdev,
					       sector_t data_block_size)
{
	struct dm_pool_metadata *pmd = kmalloc(sizeof(*pmd), GFP_KERNEL);

	if (pmd) {
		spin_lock_init(&pmd->lock);
		pmd->block_size = data_block_size;
		pmd->nr_blocks = 0;
		pmd->next_free = 0;

		pmd->mappings = NULL;
	}

	return pmd;
}

int dm_pool_metadata_close(struct dm_pool_metadata *pmd)
{
	kfree(pmd);
	return 0;
}

int dm_pool_rebind_metadata_device(struct dm_pool_metadata *pmd,
				   struct block_device *bdev)
{
	return 0;
}

int dm_pool_create_thin(struct dm_pool_metadata *pmd, dm_thin_id dev)
{
	return 0;
}

int dm_pool_create_snap(struct dm_pool_metadata *pmd, dm_thin_id dev,
			dm_thin_id origin)
{
	BUG_ON(1);
	return -EINVAL;
}

int dm_pool_delete_thin_device(struct dm_pool_metadata *pmd,
			       dm_thin_id dev)
{
	BUG_ON(1);
	return -EINVAL;
}

int dm_pool_trim_thin_device(struct dm_pool_metadata *pmd, dm_thin_id dev,
			     sector_t new_size)
{
	BUG_ON(1);
	return -EINVAL;
}

int dm_pool_commit_metadata(struct dm_pool_metadata *pmd)
{
	return 0;
}

int dm_pool_set_metadata_transaction_id(struct dm_pool_metadata *pmd,
					uint64_t current_id,
					uint64_t new_id)
{
	return 0;
}

int dm_pool_get_metadata_transaction_id(struct dm_pool_metadata *pmd,
					uint64_t *result)
{
	*result = 0;
	return 0;
}

int dm_pool_hold_metadata_root(struct dm_pool_metadata *pmd)
{
	return 0;
}

int dm_pool_get_held_metadata_root(struct dm_pool_metadata *pmd,
				   dm_block_t *result)
{
	*result = 0;
	return 0;
}

int dm_pool_open_thin_device(struct dm_pool_metadata *pmd, dm_thin_id dev,
			     struct dm_thin_device **result)
{
	struct dm_thin_device *td = kmalloc(sizeof(*td), GFP_KERNEL);
	if (!td)
		return -ENOMEM;

	td->pmd = pmd;
	td->id = dev;
	*result = td;
	return 0;
}

int dm_pool_close_thin_device(struct dm_thin_device *td)
{
	kfree(td);
	return 0;
}

dm_thin_id dm_thin_dev_id(struct dm_thin_device *td)
{
	return td->id;
}

int dm_thin_find_block(struct dm_thin_device *td, dm_block_t block,
		       int can_block, struct dm_thin_lookup_result *result)
{
	int r = 0;
	unsigned long flags;
	struct dm_pool_metadata *pmd = td->pmd;
	uint32_t v;

	spin_lock_irqsave(&pmd->lock, flags);
	BUG_ON(block >= pmd->nr_blocks);
	v = pmd->mappings[block];
	if (!(v & 1))
		r = -ENODATA;
	else {
		result->block = v >> 1;
		result->shared = 0;
	}
	spin_unlock_irqrestore(&pmd->lock, flags);

	return r;
}

/*
 * Obtain an unused block.
 */
int dm_pool_alloc_data_block(struct dm_pool_metadata *pmd, dm_block_t *result)
{
	int r = 0;
	unsigned long flags;

	spin_lock_irqsave(&pmd->lock, flags);
	if (pmd->next_free == pmd->nr_blocks)
		r = -ENOMEM;
	else
		*result = pmd->next_free++;
	spin_unlock_irqrestore(&pmd->lock, flags);

	return r;
}

int dm_thin_insert_block(struct dm_thin_device *td, dm_block_t block,
			 dm_block_t data_block)
{
	unsigned long flags;
	struct dm_pool_metadata *pmd = td->pmd;

	/*
	 * FIXME: is it worth checking the same block isn't being inserted
	 * twice?
	 */
	spin_lock_irqsave(&pmd->lock, flags);
	BUG_ON(block >= pmd->nr_blocks);
	td->pmd->mappings[block] = (data_block << 1) | 1;
	spin_unlock_irqrestore(&pmd->lock, flags);

	return 0;
}

int dm_thin_remove_block(struct dm_thin_device *td, dm_block_t block)
{
	BUG_ON(1);
	return -EINVAL;
}

int dm_thin_get_highest_mapped_block(struct dm_thin_device *td,
				     dm_block_t *highest_mapped)
{
	*highest_mapped = 0;
	return 0;
}

int dm_thin_get_mapped_count(struct dm_thin_device *td, dm_block_t *result)
{
	unsigned long flags;
	struct dm_pool_metadata *pmd = td->pmd;

	spin_lock_irqsave(&pmd->lock, flags);
	*result = td->pmd->next_free;
	spin_unlock_irqrestore(&pmd->lock, flags);

	return 0;
}

int dm_pool_get_free_block_count(struct dm_pool_metadata *pmd,
				 dm_block_t *result)
{
	unsigned long flags;

	spin_lock_irqsave(&pmd->lock, flags);
	*result = pmd->nr_blocks - pmd->next_free;
	spin_unlock_irqrestore(&pmd->lock, flags);

	return 0;
}

int dm_pool_get_free_metadata_block_count(struct dm_pool_metadata *pmd,
					  dm_block_t *result)
{
	*result = 1000;
	return 0;
}

int dm_pool_get_data_block_size(struct dm_pool_metadata *pmd, sector_t *result)
{
	unsigned long flags;

	spin_lock_irqsave(&pmd->lock, flags);
	*result = pmd->block_size;
	spin_unlock_irqrestore(&pmd->lock, flags);

	return 0;
}

int dm_pool_get_data_dev_size(struct dm_pool_metadata *pmd, dm_block_t *result)
{
	unsigned long flags;

	spin_lock_irqsave(&pmd->lock, flags);
	*result = pmd->nr_blocks;
	spin_unlock_irqrestore(&pmd->lock, flags);

	return 0;
}

int dm_pool_resize_data_dev(struct dm_pool_metadata *pmd, dm_block_t new_size)
{
	uint32_t *mappings = kzalloc(sizeof(*mappings) * new_size, GFP_KERNEL);
	if (!mappings)
		return -ENOMEM;

	if (pmd->mappings) {
		memcpy(mappings, pmd->mappings, sizeof(*mappings) * min(new_size, pmd->nr_blocks));
		kfree(pmd);
	}

	pmd->mappings = mappings;
	pmd->nr_blocks = new_size;
	printk(KERN_ALERT "resized to %llu blocks\n", new_size);

	return 0;
}

/*----------------------------------------------------------------*/

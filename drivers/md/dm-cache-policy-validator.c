#include "dm-cache-policy-internal.h"
#include "dm-cache-policy.h"

#include <linux/module.h>
#include <linux/vmalloc.h>

#define DM_MSG_PREFIX "cache-validator"

/*----------------------------------------------------------------*/

struct validator_work {
	struct list_head list;
	struct policy_work *work;
};

struct validator {
	struct dm_cache_policy policy;

	dm_cblock_t cache_size;
	unsigned long *alloc;
	unsigned long *cblock_pending;
	dm_oblock_t *mapping;

	dm_oblock_t origin_size;
	unsigned long *oblock_in_cache;
	unsigned long *oblock_pending;

	struct list_head work;

	struct dm_cache_policy *wrappee;
};

static void *check_ptr(void *ptr)
{
	BUG_ON(!ptr);
	return ptr;
}

static void validator_create(struct validator *v, dm_cblock_t cblocks,
			     dm_oblock_t oblocks, struct dm_cache_policy *wrappee)
{
	v->cache_size = cblocks;
	v->alloc = check_ptr(alloc_bitset(from_cblock(cblocks)));
	v->cblock_pending = check_ptr(alloc_bitset(from_cblock(cblocks)));
	v->mapping = check_ptr(vzalloc(sizeof(*v->mapping) * from_cblock(cblocks)));

	v->origin_size = oblocks;
	v->oblock_in_cache = check_ptr(alloc_bitset(from_oblock(oblocks)));
	v->oblock_pending = check_ptr(alloc_bitset(from_oblock(oblocks)));

	INIT_LIST_HEAD(&v->work);
	v->wrappee = wrappee;
}

static struct validator *to_validator(struct dm_cache_policy *p)
{
	return container_of(p, struct validator, policy);
}

static bool oblock_in_cache(struct validator *v, dm_oblock_t oblock)
{
	return test_bit(from_oblock(oblock), v->oblock_in_cache);
}

static bool cblock_contains(struct validator *v, dm_cblock_t cblock,
			    dm_oblock_t oblock)
{
	return v->mapping[from_cblock(cblock)] == oblock;
}

static bool background_work(struct validator *v, dm_cblock_t cblock, dm_oblock_t oblock)
{
	struct validator_work *w;

	list_for_each_entry (w, &v->work, list) {
		if (w->work->cblock == cblock)
			BUG_ON (w->work->oblock != oblock);
		return true;
	}

	return false;
}

static void save_background_work(struct validator *v, struct policy_work *work)
{
	struct validator_work *w = kmalloc(sizeof(*w), GFP_NOWAIT);
	w->work = work;
	list_add(&w->list, &v->work);
}

static void remove_background_work(struct validator *v, struct policy_work *work, bool success)
{
	struct validator_work *w;

	list_for_each_entry (w, &v->work, list) {
		if (w->work == work) {
			list_del(&w->list);
			kfree(w);
			return;
		}
	}

	BUG();
}

static void set_dirty(struct validator *v, dm_cblock_t cblock)
{
	// FIXME: finish
}

static void clear_dirty(struct validator *v, dm_cblock_t cblock)
{
	// FIXME: finish
}

static void set_mapping(struct validator *v, dm_oblock_t oblock, dm_cblock_t cblock)
{
	set_bit(from_cblock(cblock), v->alloc);
	v->mapping[from_cblock(cblock)] = oblock;
	set_bit(from_oblock(oblock), v->oblock_in_cache);
}

static void clear_mapping(struct validator *v, dm_oblock_t oblock, dm_cblock_t cblock)
{
	clear_bit(from_cblock(cblock), v->alloc);
	clear_bit(from_oblock(oblock), v->oblock_in_cache);
}

static unsigned residency(struct validator *v)
{
	// FIXME: finish
	return 0;
}

/*----------------------------------------------------------------*/

static void v_destroy(struct dm_cache_policy *p)
{
	struct validator *v = to_validator(p);
	free_bitset(v->alloc);
	free_bitset(v->cblock_pending);
	vfree(v->mapping);
	free_bitset(v->oblock_in_cache);
	free_bitset(v->oblock_pending);
	kfree(v);
}

static int v_lookup(struct dm_cache_policy *p, dm_oblock_t oblock, dm_cblock_t *cblock,
		    int data_dir, bool fast_copy, bool *background_queued)
{
	int r;
	struct validator *v = to_validator(p);

	r = policy_lookup(v->wrappee, oblock, cblock,
			  data_dir, fast_copy, background_queued);
	if (r) {
		if (r == -ENOENT)
			BUG_ON(oblock_in_cache(v, oblock));
	} else {
		BUG_ON(!cblock_contains(v, *cblock, oblock));
		if (background_queued && *background_queued)
			BUG_ON(!background_work(v, *cblock, oblock));
	}

	return r;
}

static int v_lookup_with_work(struct dm_cache_policy *p,
			      dm_oblock_t oblock, dm_cblock_t *cblock,
			      int data_dir, bool fast_copy,
			      struct policy_work **work)
{
	int r;
	struct validator *v = to_validator(p);

	r = policy_lookup_with_work(v->wrappee, oblock, cblock,
				    data_dir, fast_copy, work);

	if (r) {
		if (r == -ENOENT)
			BUG_ON(oblock_in_cache(v, oblock));
		else
			return r;
	}

	BUG_ON(!cblock_contains(v, *cblock, oblock));

	if (work && *work)
		save_background_work(v, *work);

	return r;
}

static int v_get_background_work(struct dm_cache_policy *p, bool idle,
				 struct policy_work **result)
{
	int r;
	struct validator *v = to_validator(p);

	r = policy_get_background_work(v->wrappee, idle, result);
	if (r == -ENODATA)
		return r;

	save_background_work(v, *result);
	return 0;
}

static void v_complete_background_work(struct dm_cache_policy *p,
				       struct policy_work *work,
				       bool success)
{
	struct validator *v = to_validator(p);
	remove_background_work(v, work, success);
	switch (work->op) {
	case POLICY_PROMOTE:
		set_mapping(v, work->oblock, work->cblock);
		set_dirty(v, work->cblock);
		break;

	case POLICY_DEMOTE:
		clear_mapping(v, work->oblock, work->cblock);
		break;

	case POLICY_WRITEBACK:
		clear_dirty(v, work->cblock);
		break;
	}
	policy_complete_background_work(v->wrappee, work, success);
}

static void v_set_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	struct validator *v = to_validator(p);
//	set_dirty(v, oblock);
	policy_set_dirty(v->wrappee, oblock);
}

static void v_clear_dirty(struct dm_cache_policy *p, dm_oblock_t oblock)
{
	struct validator *v = to_validator(p);
//	clear_dirty(v, oblock);
	policy_clear_dirty(v->wrappee, oblock);
}

static int v_load_mapping(struct dm_cache_policy *p, dm_oblock_t oblock,
			dm_cblock_t cblock, uint32_t hint, bool hint_valid)
{
	struct validator *v = to_validator(p);
	set_mapping(v, oblock, cblock);
	return policy_load_mapping(v->wrappee, oblock, cblock, hint, hint_valid);
}

static uint32_t v_get_hint(struct dm_cache_policy *p, dm_cblock_t cblock)
{
	struct validator *v = to_validator(p);
	return policy_get_hint(v->wrappee, cblock);
}

static dm_cblock_t v_residency(struct dm_cache_policy *p)
{
	struct validator *v = to_validator(p);
	dm_cblock_t r = policy_residency(v->wrappee);
//	BUG_ON(r != residency(v));
	return r;
}

static void v_tick(struct dm_cache_policy *p, bool can_block)
{
	struct validator *v = to_validator(p);
	policy_tick(v->wrappee, can_block);
}
#if 0
static int v_emit_config_values(struct dm_cache_policy *p, char *result,
				 unsigned maxlen, ssize_t *sz_ptr)
{
	struct validator *v = to_validator(p);
	return policy_emit_config_values(v->wrappee, result, maxlen, sz_ptr);
}

static int set_config_value(struct dm_cache_policy *p,
			    const char *key, const char *value)
{
	struct validator *v = to_validator(p);
	return policy_set_config_value(v->wrappee, key, value);
}
#endif
static void init_policy_functions(struct dm_cache_policy *p)
{
	p->destroy = v_destroy;
	p->lookup = v_lookup;
	p->lookup_with_work = v_lookup_with_work;
//        p->has_background_work = v_has_background_work;
	p->get_background_work = v_get_background_work;
	p->complete_background_work = v_complete_background_work;
	p->set_dirty = v_set_dirty;
	p->clear_dirty = v_clear_dirty;
	p->load_mapping = v_load_mapping;
	p->get_hint = v_get_hint;
	p->residency = v_residency;
	p->tick = v_tick;
}

static struct dm_cache_policy *create_validator_policy(dm_cblock_t cache_size,
						       sector_t origin_size,
						       sector_t cache_block_size)
{
	struct validator *v = check_ptr(kzalloc(sizeof(*v), GFP_KERNEL));

	struct dm_cache_policy *wrappee = dm_cache_policy_create(
			"smq", cache_size, origin_size, cache_block_size);
	validator_create(v, cache_size, to_oblock(dm_div_up(origin_size, cache_block_size)), wrappee);
	init_policy_functions(&v->policy);

	return &v->policy;
}

/*----------------------------------------------------------------*/

static struct dm_cache_policy_type validator_policy_type = {
	.name = "validator",
	.version = {1, 0, 0},
	.hint_size = 4,
	.owner = THIS_MODULE,
	.create = create_validator_policy
};

static int __init validator_init(void)
{
	int r;

	r = dm_cache_policy_register(&validator_policy_type);
	if (r) {
		DMERR("register failed %d", r);
		return -ENOMEM;
	}

	return 0;
}

static void __exit validator_exit(void)
{
	dm_cache_policy_unregister(&validator_policy_type);
}

module_init(validator_init);
module_exit(validator_exit);

MODULE_AUTHOR("Joe Thornber <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("validator cache policy");

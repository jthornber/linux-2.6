/*
 * Copyright (C) 2011 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */
#include "dm-block-manager.h"
#include "dm-persistent-data-internal.h"

#include <linux/dm-io.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rwsem.h>
#include <linux/device-mapper.h>
#include <linux/dm-bufio.h>

#define DM_MSG_PREFIX "block manager"

/*----------------------------------------------------------------*/

dm_block_t dm_block_location(struct dm_block *b)
{
	return dm_bufio_get_block_number(b);
}
EXPORT_SYMBOL_GPL(dm_block_location);

void *dm_block_data(struct dm_block *b)
{
	return dm_bufio_get_block_data(b);
}
EXPORT_SYMBOL_GPL(dm_block_data);

struct buffer_aux {
	struct dm_block_validator *validator;
	struct rw_semaphore lock;
	int write_locked;
};

static void dm_block_manager_alloc_callback(struct dm_buffer *buf)
{
	struct buffer_aux *aux = dm_bufio_get_aux_data(buf);
	aux->validator = NULL;
	init_rwsem(&aux->lock);
}

static void dm_block_manager_write_callback(struct dm_buffer *buf)
{
	struct buffer_aux *aux = dm_bufio_get_aux_data(buf);
	if (aux->validator) {
		aux->validator->prepare_for_write(aux->validator, buf,
			 dm_bufio_get_block_size(dm_bufio_get_client(buf)));
 	}
}

/*----------------------------------------------------------------
 * Public interface
 *--------------------------------------------------------------*/
struct dm_block_manager *dm_block_manager_create(struct block_device *bdev,
						 unsigned block_size,
						 unsigned cache_size,
						 unsigned max_held_per_thread)
{
	return dm_bufio_client_create(bdev, block_size, max_held_per_thread,
				      sizeof(struct buffer_aux),
				      dm_block_manager_alloc_callback,
				      dm_block_manager_write_callback);
}
EXPORT_SYMBOL_GPL(dm_block_manager_create);

void dm_block_manager_destroy(struct dm_block_manager *bm)
{
	return dm_bufio_client_destroy(bm);
}
EXPORT_SYMBOL_GPL(dm_block_manager_destroy);

unsigned dm_bm_block_size(struct dm_block_manager *bm)
{
	return dm_bufio_get_block_size(bm);
}
EXPORT_SYMBOL_GPL(dm_bm_block_size);

dm_block_t dm_bm_nr_blocks(struct dm_block_manager *bm)
{
	return dm_bufio_get_device_size(bm);
}

static int dm_bm_validate_buffer(struct dm_block_manager *bm,
				 struct dm_buffer *buf,
				 struct buffer_aux *aux,
				 struct dm_block_validator *v)
{
	if (unlikely(!aux->validator)) {
		int r;
		if (!v)
			return 0;
		r = v->check(v, buf, dm_bufio_get_block_size(bm));
		if (unlikely(r))
			return r;
		aux->validator = v;
	} else {
		if (unlikely(aux->validator != v)) {
			DMERR("validator mismatch (old=%s vs new=%s) for block %llu",
				aux->validator->name, v ? v->name : "NULL",
				(unsigned long long)
					dm_bufio_get_block_number(buf));
			return -EINVAL;
 		}
	}

	return 0;
}
int dm_bm_read_lock(struct dm_block_manager *bm, dm_block_t b,
		    struct dm_block_validator *v,
		    struct dm_block **result)
{
	struct buffer_aux *aux;
	void *p;
	int r;

	p = dm_bufio_read(bm, b, result);
	if (unlikely(IS_ERR(p)))
		return PTR_ERR(p);

	aux = dm_bufio_get_aux_data(*result);
	down_read(&aux->lock);
	aux->write_locked = 0;

	r = dm_bm_validate_buffer(bm, *result, aux, v);
	if (unlikely(r)) {
		up_read(&aux->lock);
		dm_bufio_release(*result);
		return r;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(dm_bm_read_lock);

int dm_bm_write_lock(struct dm_block_manager *bm,
		     dm_block_t b, struct dm_block_validator *v,
		     struct dm_block **result)
{
	struct buffer_aux *aux;
	void *p;
	int r;

	p = dm_bufio_read(bm, b, result);
	if (unlikely(IS_ERR(p)))
		return PTR_ERR(p);

	aux = dm_bufio_get_aux_data(*result);
	down_write(&aux->lock);
	aux->write_locked = 1;

	r = dm_bm_validate_buffer(bm, *result, aux, v);
	if (unlikely(r)) {
		up_write(&aux->lock);
		dm_bufio_release(*result);
		return r;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(dm_bm_write_lock);

int dm_bm_read_try_lock(struct dm_block_manager *bm,
			dm_block_t b, struct dm_block_validator *v,
			struct dm_block **result)
{
	struct buffer_aux *aux;
	void *p;
	int r;

	p = dm_bufio_get(bm, b, result);
	if (unlikely(IS_ERR(p)))
		return PTR_ERR(p);
	if (unlikely(!p))
		return -EWOULDBLOCK;

	aux = dm_bufio_get_aux_data(*result);
	if (unlikely(!down_read_trylock(&aux->lock))) {
		dm_bufio_release(*result);
		return -EWOULDBLOCK;
	}
	aux->write_locked = 0;

	r = dm_bm_validate_buffer(bm, *result, aux, v);
	if (unlikely(r)) {
		up_read(&aux->lock);
		dm_bufio_release(*result);
		return r;
	}
	return 0;
}

int dm_bm_write_lock_zero(struct dm_block_manager *bm,
			  dm_block_t b, struct dm_block_validator *v,
			  struct dm_block **result)
{
	struct buffer_aux *aux;
	void *p;

	p = dm_bufio_new(bm, b, result);
	if (unlikely(IS_ERR(p)))
		return PTR_ERR(p);

	memset(p, 0, dm_bm_block_size(bm));

	aux = dm_bufio_get_aux_data(*result);
	down_write(&aux->lock);
	aux->write_locked = 1;
	aux->validator = v;

	return 0;
}

int dm_bm_unlock(struct dm_block *b)
{
	struct buffer_aux *aux;
	aux = dm_bufio_get_aux_data(b);

	if (aux->write_locked) {
		dm_bufio_mark_buffer_dirty(b);
		up_write(&aux->lock);
	} else {
		up_read(&aux->lock);
	}

	dm_bufio_release(b);

	return 0;
}
EXPORT_SYMBOL_GPL(dm_bm_unlock);

int dm_bm_flush_and_unlock(struct dm_block_manager *bm,
			   struct dm_block *superblock)
{
	int r;

	r = dm_bufio_write_dirty_buffers(bm);
	if (unlikely(r))
		return r;
	r = dm_bufio_issue_flush(bm);
	if (unlikely(r))
		return r;

	dm_bm_unlock(superblock);

	r = dm_bufio_write_dirty_buffers(bm);
	if (unlikely(r))
		return r;
	r = dm_bufio_issue_flush(bm);
	if (unlikely(r))
		return r;

	return 0;
}

int dm_bm_rebind_block_device(struct dm_block_manager *bm,
			      struct block_device *bdev)
{
	/*
	 * !!! FIXME: remove this. It is supposedly unused.
	 */
	return 0;
}
EXPORT_SYMBOL_GPL(dm_bm_rebind_block_device);

/*----------------------------------------------------------------*/

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joe Thornber <dm-devel@redhat.com>");
MODULE_DESCRIPTION("Immutable metadata library for dm");

/*----------------------------------------------------------------*/

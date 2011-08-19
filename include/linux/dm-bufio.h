/*
 * Copyright (C) 2009 Red Hat Czech, s.r.o.
 *
 * Mikulas Patocka <mpatocka@redhat.com>
 *
 * This file is released under the GPL.
 */

#ifndef DM_BUFIO_H
#define DM_BUFIO_H

/*
 * dm_bufio_client_create --- create a buffered IO cache on a given device
 * dm_bufio_client_destroy --- release a buffered IO cache
 *
 * dm_bufio_read --- read a given block from disk. Returns pointer to data.
 *	Returns a pointer to dm_buffer that can be used to release the buffer
 *	or to make it dirty.
 * dm_bufio_get --- like dm_bufio_read, but return buffer from cache, don't read
 *	it. If the buffer is not in the cache, return NULL.
 * dm_bufio_new --- like dm_bufio_read, but don't read anything from the disk.
 *	It is expected that the caller initializes the buffer and marks it
 *	dirty.
 * dm_bufio_release --- release a reference obtained with dm_bufio_read or
 *	dm_bufio_new. The data pointer and dm_buffer pointer is no longer valid
 *	after this call.
 *
 * WARNING: to avoid deadlocks, the thread can hold at most one buffer. Multiple
 *	threads can hold each one buffer simultaneously.
 *
 * dm_bufio_mark_buffer_dirty --- mark a buffer dirty. It should be called after
 *	the buffer is modified.
 * dm_bufio_write_dirty_buffers --- write all dirty buffers. Guarantees that all
 *	dirty buffers created prior to this call are on disk when this call
 *	exits.
 * dm_bufio_issue_flush --- send an empty write barrier to the device to flush
 *	hardware disk cache.
 *
 * In case of memory pressure, the buffer may be written after
 *	dm_bufio_mark_buffer_dirty, but before dm_bufio_write_dirty_buffers.
 *	So dm_bufio_write_dirty_buffers guarantees that the buffer is on-disk
 *	but the actual writing may occur earlier.
 *
 * dm_bufio_release_move --- like dm_bufio_release but also move the buffer to
 *	the new block. dm_bufio_write_dirty_buffers is needed to commit the new
 *	block.
 * dm_bufio_drop_buffers --- clear all buffers.
 */

struct dm_bufio_client;
struct dm_buffer;

void *dm_bufio_get(struct dm_bufio_client *c, sector_t block,
		   struct dm_buffer **bp);
void *dm_bufio_read(struct dm_bufio_client *c, sector_t block,
		    struct dm_buffer **bp);
void *dm_bufio_new(struct dm_bufio_client *c, sector_t block,
		   struct dm_buffer **bp);
void dm_bufio_release(struct dm_buffer *b);

void dm_bufio_mark_buffer_dirty(struct dm_buffer *b);
void dm_bufio_write_dirty_buffers_async(struct dm_bufio_client *c);
int dm_bufio_write_dirty_buffers(struct dm_bufio_client *c);
int dm_bufio_issue_flush(struct dm_bufio_client *c);

void dm_bufio_release_move(struct dm_buffer *b, sector_t new_block);

unsigned dm_bufio_get_block_size(struct dm_bufio_client *c);
sector_t dm_bufio_get_device_size(struct dm_bufio_client *c);
sector_t dm_bufio_get_block_number(struct dm_buffer *b);
void *dm_bufio_get_block_data(struct dm_buffer *b);
void *dm_bufio_get_aux_data(struct dm_buffer *b);
struct dm_bufio_client *dm_bufio_get_client(struct dm_buffer *b);

struct dm_bufio_client *
dm_bufio_client_create(struct block_device *bdev, unsigned block_size,
		       unsigned reserved_buffers, unsigned aux_size,
		       void (*alloc_callback)(struct dm_buffer *),
		       void (*write_callback)(struct dm_buffer *));
void dm_bufio_client_destroy(struct dm_bufio_client *c);
void dm_bufio_drop_buffers(struct dm_bufio_client *c);

#endif

/*
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */
#ifndef _LINUX_DM_BITSET_H
#define _LINUX_DM_BITSET_H

#include "dm-array.h"

struct dm_bitset;

struct dm_bitset *dm_bitset_create(struct dm_transaction_manager *tm,
				   dm_block_t *root);
int dm_bitset_resize(struct dm_bitset *bitset, uint32_t new_nr_entries,
		     dm_block_t *new_root, bool zero);
void dm_bitset_destroy(struct dm_bitset *bitset);

void dm_bitset_set_bit(uint64_t index, struct dm_bitset *bitset);
void dm_bitset_clear_bit(uint64_t index, struct dm_bitset *bitset);
int dm_bitset_test_bit(uint64_t index, struct dm_bitset *bitset);

#endif

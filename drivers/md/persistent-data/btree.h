#ifndef SNAPSHOTS_BTREE_H
#define SNAPSHOTS_BTREE_H

#include "transaction-manager.h"

/*----------------------------------------------------------------*/

/*
 * Manipulates hierarchical B+ trees with 64bit keys and 64bit values.  No
 * assumptions about the meanings of the keys or values are made.
 */


/*
 * The btree has no idea what the values stored actually are.  This leads
 * to problems with reference counts when sharing is occuring.  So we have
 * to pass in a function to adjust reference counts to many of the btree
 * functions.  Often the leaves are simply block ids, so here's a standard
 * function for that case.
 */
typedef void (*count_adjust_fn)(struct transaction_manager *tm, void *value, int32_t count_delta);
void value_is_block(struct transaction_manager *tm, void *value, int32_t delta);
void value_is_meaningless(struct transaction_manager *tm, void *value, int32_t delta);

typedef int (*equal_fn)(void *value1, void *value2);

struct btree_info {
	struct transaction_manager *tm;
	unsigned levels;	/* number of nested btrees */
	uint32_t value_size;
	count_adjust_fn adjust;
	equal_fn eq;
};

/* Set up an empty tree.  O(1). */
int btree_empty(struct btree_info *info, block_t *root);

/* Delete a tree.  O(n) - this is the slow one! */
int btree_del(struct btree_info *info, block_t root);

/*
 * All the lookup functions return -ENODATA if the key cannot be found.
 */

/* Tries to find a key that matches exactly.  O(ln(n)) */
/* FIXME: rename this to plain btree_looup */
int
btree_lookup_equal(struct btree_info *info,
		   block_t root, uint64_t *keys,
		   void *value);

/*
 * Find the greatest key that is less than or equal to that requested.  A
 * ENODATA result indicates the key would appear in front of all (possibly
 * zero) entries.  O(ln(n))
 */
int
btree_lookup_le(struct btree_info *info,
		block_t root, uint64_t *keys,
		uint64_t *rkey, void *value);

/*
 * Find the least key that is greater than or equal to that requested.
 * ENODATA indicates all the keys are below.  O(ln(n))
 */
int
btree_lookup_ge(struct btree_info *info,
		block_t root, uint64_t *keys,
		uint64_t *rkey, void *value);

/*
 * Insertion (or overwrite an existing value).
 * O(ln(n))
 */
int btree_insert(struct btree_info *info,
		 block_t root, uint64_t *keys, void *value,
		 block_t *new_root);

/* Remove a key if present.  This doesn't remove empty sub trees.  Normally
 * subtrees represent a separate entity, like a snapshot map, so this is
 * correct behaviour.
 * O(ln(n)).
 */
int btree_remove(struct btree_info *info,
		 block_t root, uint64_t *keys,
		 block_t *new_root);

/* Clone a tree. O(1) */
int btree_clone(struct btree_info *info,
		block_t root,
		block_t *clone);

/*----------------------------------------------------------------*/

#endif

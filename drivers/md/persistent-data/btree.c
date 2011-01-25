#include "btree-internal.h"
#include "space-map.h"

/*----------------------------------------------------------------
 * Array manipulation
 *--------------------------------------------------------------*/
static void array_insert(void *base, size_t elt_size, unsigned nr_elts,
			 unsigned index, void *elt)
{
	if (index < nr_elts)
		memmove(base + (elt_size * (index + 1)),
			base + (elt_size * index),
			(nr_elts - index) * elt_size);
	memcpy(base + (elt_size * index), elt, elt_size);
}

/*----------------------------------------------------------------*/

/* makes the assumption that no two keys are the same. */
static int bsearch(struct node *n, uint64_t key, int want_hi)
{
	int lo = -1, hi = __le32_to_cpu(n->header.nr_entries);
	while(hi - lo > 1) {
		int mid = lo + ((hi - lo) / 2);
		uint64_t mid_key = __le64_to_cpu(n->keys[mid]);

		if (mid_key == key)
			return mid;

		if (mid_key < key)
			lo = mid;
		else
			hi = mid;
	}

	return want_hi ? hi : lo;
}

static int lower_bound(struct node *n, uint64_t key)
{
	return bsearch(n, key, 0);
}

static int upper_bound(struct node *n, uint64_t key)
{
	return bsearch(n, key, 1);
}

void inc_children(struct btree_info *info, struct node *n, count_adjust_fn fn)
{
	unsigned i;
	if (__le32_to_cpu(n->header.flags) & INTERNAL_NODE)
		for (i = 0; i < __le32_to_cpu(n->header.nr_entries); i++)
			tm_inc(info->tm, value64(n, i));
	else
		for (i = 0; i < __le32_to_cpu(n->header.nr_entries); i++)
			fn(info->tm, value_ptr(n, i, info->value_size), 1);
}

void insert_at(size_t value_size,
	       struct node *node, unsigned index, uint64_t key, void *value)
{
	BUG_ON(index > __le32_to_cpu(node->header.nr_entries) ||
	       index >= __le32_to_cpu(node->header.max_entries));

	array_insert(node->keys, sizeof(*node->keys),
		     __le32_to_cpu(node->header.nr_entries), index, &key);
	array_insert(value_base(node), value_size, __le32_to_cpu(node->header.nr_entries),
		     index, value);
	node->header.nr_entries = __cpu_to_le32(__le32_to_cpu(node->header.nr_entries) + 1);
}

/*----------------------------------------------------------------*/

uint32_t calc_max_entries(size_t value_size, size_t block_size)
{
	uint32_t n;
	size_t elt_size = sizeof(uint64_t) + value_size;
	block_size -= sizeof(struct node_header);
	n = block_size / elt_size;
	if (n % 2 == 0)
		--n;
	return n;
}

int btree_empty(struct btree_info *info, block_t *root)
{
	int r;
	struct block *b;
	struct node *n;

	r = bn_new_block(info, &b);
	if (r < 0)
		return r;

	n = (struct node *) block_data(b);
	memset(n, 0, bm_block_size(tm_get_bm(info->tm)));
	n->header.flags = __cpu_to_le32(LEAF_NODE);
	n->header.nr_entries = __cpu_to_le32(0);
	n->header.max_entries =
		__cpu_to_le32(
			calc_max_entries(info->value_size,
					 bm_block_size(tm_get_bm(info->tm))));
	n->header.magic = __cpu_to_le32(BTREE_NODE_MAGIC);

	*root = block_location(b);
	return bn_unlock(info, b);
}
EXPORT_SYMBOL_GPL(btree_empty);

#if 0
/*
 * A simple recursive implementation of tree deletion, we'll need to use an
 * iterative walk before we move this into the kernel.
 */
int btree_del_(struct btree_info *info, block_t root, unsigned level)
{
	struct node *n;
	uint32_t ref_count = tm_ref(info->tm, root);

	if (ref_count == 1) {
		unsigned i;

		/*
		 * We know this node isn't shared, so we can get away with
		 * just a read lock.
		 */
		if (!tm_read_lock(info->tm, root, (void **) &n))
			abort();

		if (n->header.flags & INTERNAL_NODE) {
			for (i = 0; i < n->header.nr_entries; i++)
				if (!btree_del_(info, value64(n, i), level))
					return 0;

		} else if (level < (info->levels - 1)) {
			for (i = 0; i < n->header.nr_entries; i++)
				if (!btree_del_(info, value64(n, i), level + 1))
					return 0;

		} else
			for (i = 0; i < n->header.nr_entries; i++)
				info->adjust(info->tm, value_ptr(n, i, info->value_size), -1);

		if (!tm_read_unlock(info->tm, root))
			abort();
	}

	tm_dec(info->tm, root);
	return 1;
}

int btree_del(struct btree_info *info, block_t root)
{
	return btree_del_(info, root, 0);
}
#endif

static int
btree_lookup_raw(struct ro_spine *s, block_t block, uint64_t key, int (*search_fn)(struct node *, uint64_t),
		 uint64_t *result_key, void *v, size_t value_size)
{
	int i, r;

	do {
		r = ro_step(s, block);
		if (r < 0)
			return r;

		i = search_fn(ro_node(s), key);
		if (i < 0 || i >= __le32_to_cpu(ro_node(s)->header.nr_entries))
			return -ENODATA;

		if (__le32_to_cpu(ro_node(s)->header.flags) & INTERNAL_NODE)
			block = value64(ro_node(s), i);

        } while (!(__le32_to_cpu(ro_node(s)->header.flags) & LEAF_NODE));

	*result_key = __le64_to_cpu(ro_node(s)->keys[i]);
	memcpy(v, value_ptr(ro_node(s), i, value_size), value_size);
	return 0;
}

int
btree_lookup_equal(struct btree_info *info,
		   block_t root, uint64_t *keys,
		   void *value)
{
	unsigned level, last_level = info->levels - 1;
	int r;
	uint64_t rkey;
	__le64 internal_value;
	struct ro_spine spine;

	init_ro_spine(&spine, info);
	for (level = 0; level < info->levels; level++) {
		r = btree_lookup_raw(&spine, root, keys[level], lower_bound, &rkey,
				     level == last_level ? value : &internal_value,
				     level == last_level ? info->value_size : sizeof(uint64_t));

		if (r == 0) {
			if (rkey != keys[level]) {
				exit_ro_spine(&spine);
				return -ENODATA;
			}
		} else {
			exit_ro_spine(&spine);
			return r;
		}

		root = __le64_to_cpu(internal_value);
	}

	exit_ro_spine(&spine);
	return r;
}
EXPORT_SYMBOL_GPL(btree_lookup_equal);

int
btree_lookup_le(struct btree_info *info,
		block_t root, uint64_t *keys,
		uint64_t *key, void *value)
{
	unsigned level, last_level = info->levels - 1;
	int r;
	__le64 internal_value;

	struct ro_spine spine;

	init_ro_spine(&spine, info);
	for (level = 0; level < info->levels; level++) {
		r = btree_lookup_raw(&spine, root, keys[level], lower_bound, key,
				     level == last_level ? value : &internal_value,
				     level == last_level ? info->value_size : sizeof(uint64_t));

		if (r != 0) {
			exit_ro_spine(&spine);
			return r;
		}

		root = __le64_to_cpu(internal_value);
	}

	exit_ro_spine(&spine);
	return r;
}
EXPORT_SYMBOL_GPL(btree_lookup_le);

int
btree_lookup_ge(struct btree_info *info,
		block_t root, uint64_t *keys,
		uint64_t *key, void *value)
{
	unsigned level, last_level = info->levels - 1;
	int r;
        __le64 internal_value;
	struct ro_spine spine;

	init_ro_spine(&spine, info);
	for (level = 0; level < info->levels; level++) {
		r = btree_lookup_raw(&spine, root, keys[level], upper_bound, key,
				     level == last_level ? value : &internal_value,
				     level == last_level ? info->value_size : sizeof(uint64_t));
		if (r != 0) {
			exit_ro_spine(&spine);
			return r;
		}

		root = __le64_to_cpu(internal_value);
	}

	exit_ro_spine(&spine);
	return r;
}
EXPORT_SYMBOL_GPL(btree_lookup_ge);

/*
 * Splits a node by creating a sibling node and shifting half the nodes
 * contents across.  Assumes there is a parent node, and it has room for
 * another child.
 *
 * Before:
 *        +--------+
 *        | Parent |
 *        +--------+
 *	     |
 *           v
 *      +----------+
 *	| A ++++++ |
 *	+----------+
 *
 *
 * After:
 *              +--------+
 *       	| Parent |
 *	        +--------+
 *       	  |    	|
 *	          v     +------+
 *          +---------+	       |
 *          | A* +++  |	       v
 *          +---------+	  +-------+
 *		          | B +++ |
 *		          +-------+
 *
 * Where A* is a shadow of A.
 */
static int btree_split_sibling(struct shadow_spine *s, block_t root,
			       unsigned parent_index, uint64_t key)
{
	int ret;
	size_t size;
	unsigned nr_left, nr_right;
	struct block *left, *right, *parent;
	struct node *l, *r;

	left = shadow_current(s);
	BUG_ON(!left);

	ret = bn_new_block(s->info, &right);
	if (ret < 0)
		return ret;

	l = to_node(left);
	r = (struct node *) block_data(right);

	nr_left = __le32_to_cpu(l->header.nr_entries) / 2;
	nr_right = __le32_to_cpu(l->header.nr_entries) - nr_left;

	l->header.nr_entries = __cpu_to_le32(nr_left);

	r->header.flags = l->header.flags;
	r->header.nr_entries = __cpu_to_le32(nr_right);
	r->header.max_entries = l->header.max_entries;
	r->header.magic = __cpu_to_le32(BTREE_NODE_MAGIC);
	memcpy(r->keys, l->keys + nr_left, nr_right * sizeof(r->keys[0]));

	size = __le32_to_cpu(l->header.flags) & INTERNAL_NODE ? sizeof(uint64_t) : s->info->value_size;
	memcpy(value_ptr(r, 0, size), value_ptr(l, nr_left, size), size * nr_right);

	/* Patch up the parent */
	parent = shadow_parent(s);
	BUG_ON(!parent);
	{
		struct node *p = to_node(parent);
		__le64 location = __cpu_to_le64(block_location(left));
		memcpy(value_ptr(p, parent_index, sizeof(__le64)),
		       &location, sizeof(__le64));

		location = __cpu_to_le64(block_location(right));
		insert_at(sizeof(__le64), p, parent_index + 1, __le64_to_cpu(r->keys[0]), &location);

	}

	if (key < __le64_to_cpu(r->keys[0])) {
		bn_unlock(s->info, right);
		s->nodes[1] = left;
	} else {
		bn_unlock(s->info, left);
		s->nodes[1] = right;
	}

	return 0;
}

/*
 * Splits a node by creating two new children beneath the given node.
 *
 * Before:
 *	  +----------+
 *        | A ++++++ |
 *        +----------+
 *
 *
 * After:
 * 	+------------+
 *	| A (shadow) |
 *	+------------+
 *          |   |
 *   +------+   +----+
 *   | 	   	     |
 *   v	 	     v
 * +-------+	 +-------+
 * | B +++ |	 | C +++ |
 * +-------+ 	 +-------+
 */
static int btree_split_beneath(struct shadow_spine *s, block_t root, uint64_t key)
{
	int ret;
	size_t size;
	unsigned nr_left, nr_right;
	struct block *left, *right, *new_parent;
	struct node *p, *l, *r;

	new_parent = shadow_current(s);
	BUG_ON(!new_parent);

	ret = bn_new_block(s->info, &left);
	if (ret < 0)
		return ret;

	ret = bn_new_block(s->info, &right);
	if (ret < 0) {
		/* FIXME: put left */
		return ret;
	}

	p = to_node(new_parent);
	l = (struct node *) block_data(left);
	r = (struct node *) block_data(right);

	nr_left = __le32_to_cpu(p->header.nr_entries) / 2;
	nr_right = __le32_to_cpu(p->header.nr_entries) - nr_left;

	l->header.flags = p->header.flags;
	l->header.nr_entries = __cpu_to_le32(nr_left);
	l->header.max_entries = p->header.max_entries;
	l->header.magic = __cpu_to_le32(BTREE_NODE_MAGIC);

	r->header.flags = p->header.flags;
	r->header.nr_entries = __cpu_to_le32(nr_right);
	r->header.max_entries = p->header.max_entries;
	r->header.magic = __cpu_to_le32(BTREE_NODE_MAGIC);

	memcpy(l->keys, p->keys, nr_left * sizeof(p->keys[0]));
	memcpy(r->keys, p->keys + nr_left, nr_right * sizeof(p->keys[0]));

	size = __le32_to_cpu(p->header.flags) & INTERNAL_NODE ? sizeof(__le64) : s->info->value_size;
	memcpy(value_ptr(l, 0, size), value_ptr(p, 0, size), nr_left * size);
	memcpy(value_ptr(r, 0, size), value_ptr(p, nr_left, size), nr_right * size);

	/* new_parent should just point to l and r now */
	p->header.flags = __cpu_to_le32(INTERNAL_NODE);
	p->header.nr_entries = __cpu_to_le32(2);
	{
		__le64 val = __cpu_to_le64(block_location(left));
		p->keys[0] = l->keys[0];
		memcpy(value_ptr(p, 0, sizeof(__le64)), &val, sizeof(__le64));

		val = __cpu_to_le64(block_location(right));
		p->keys[1] = r->keys[0];
		memcpy(value_ptr(p, 1, sizeof(__le64)), &val, sizeof(__le64));
	}

	/* rejig the spine.  This is ugly, since it knows too much about the spine */
	if (s->nodes[0] != new_parent) {
		bn_unlock(s->info, s->nodes[0]);
		s->nodes[0] = new_parent;
	}
	if (key < __le64_to_cpu(r->keys[0])) {
		bn_unlock(s->info, right);
		s->nodes[1] = left;
	} else {
		bn_unlock(s->info, left);
		s->nodes[1] = right;
	}
	s->count = 2;

	return 0;
}

static int btree_insert_raw(struct shadow_spine *s,
			    block_t root, count_adjust_fn fn, uint64_t key,
			    unsigned *index)
{
        int r, i = *index, inc, top = 1;
	struct node *node;

	for (;;) {
		r = shadow_step(s, root, fn, &inc);
		if (r < 0) {
			/* FIXME: unpick any allocations */
			return r;
		}

		/* We have to patch up the parent node, ugly, but I don't
		 * see a way to do this automatically as part of the spine
		 * op. */
		if (shadow_parent(s) && i >= 0) { /* FIXME: second clause unness. */
			__le64 location = __cpu_to_le64(block_location(shadow_current(s)));
			memcpy(value_ptr(to_node(shadow_parent(s)), i, sizeof(uint64_t)),
			       &location, sizeof(__le64));
		}

		BUG_ON(!shadow_current(s));
		node = to_node(shadow_current(s));

		if (node->header.nr_entries == node->header.max_entries) {
			if (top)
				r = btree_split_beneath(s, root, key);
			else
				r = btree_split_sibling(s, root, i, key);

			if (r < 0) {
				/* FIXME: back out allocations */
				return r;
			}
		}

		BUG_ON(!shadow_current(s));
		node = to_node(shadow_current(s));

		i = lower_bound(node, key);

		if (__le32_to_cpu(node->header.flags) & LEAF_NODE)
			break;

		if (i < 0) {
			/* change the bounds on the lowest key */
			node->keys[0] = __cpu_to_le64(key);
			i = 0;
		}

		root = value64(node, i);
		top = 0;
        }

	if (i < 0 || __le64_to_cpu(node->keys[i]) != key)
		i++;

	/* we're about to overwrite this value, so undo the increment for it */
	/* FIXME: shame that inc information is leaking outside the spine.
	 * Plus inc is just plain wrong in the event of a split */
	if (__le64_to_cpu(node->keys[i]) == key && inc)
		fn(s->info->tm, value_ptr(node, i, s->info->value_size), -1);

	*index = i;
	return 0;
}

int btree_insert(struct btree_info *info, block_t root,
		 uint64_t *keys, void *value,
		 block_t *new_root)
{
	int r, need_insert;
	unsigned level, index = -1, last_level = info->levels - 1;
	block_t *block = &root;
	struct shadow_spine spine;
	struct node *n;

	init_shadow_spine(&spine, info);

	for (level = 0; level < info->levels; level++) {
		r = btree_insert_raw(&spine, *block,
				     level == last_level ? info->adjust : value_is_block,
				     keys[level], &index);
		if (r < 0) {
			exit_shadow_spine(&spine);
			/* FIXME: avoid block leaks */
			return r;
		}

		BUG_ON(!shadow_current(&spine));
		n = to_node(shadow_current(&spine));
		need_insert = ((index >= __le32_to_cpu(n->header.nr_entries)) ||
			       (__le64_to_cpu(n->keys[index]) != keys[level]));

		if (level == last_level) {
			if (need_insert)
				insert_at(info->value_size, n, index, keys[level], value);
			else {
				if (!info->eq || !info->eq(value_ptr(n, index, info->value_size),
							   value))
					info->adjust(info->tm,
						     value_ptr(n, index, info->value_size), -1);
				memcpy(value_ptr(n, index, info->value_size),
				       value, info->value_size);
			}
		} else {
			if (need_insert) {
				block_t new_tree;
				r = btree_empty(info, &new_tree);
				if (r < 0) {
					/* FIXME: avoid block leaks */
					exit_shadow_spine(&spine);
					return r;
				}

				insert_at(sizeof(uint64_t), n, index, keys[level], &new_tree);
			}
		}

		if (level < last_level)
			block = value_ptr(n, index, sizeof(uint64_t));
	}

	*new_root = shadow_root(&spine);
	exit_shadow_spine(&spine);
	return 0;
}
EXPORT_SYMBOL_GPL(btree_insert);

/*----------------------------------------------------------------*/

int btree_clone(struct btree_info *info, block_t root, block_t *clone)
{
	int r;
	struct block *b, *orig_b;
	struct node *b_node, *orig_node;

	/* Copy the root node */
	r = bn_new_block(info, &b);
	if (r < 0)
		return r;

	r = tm_read_lock(info->tm, root, &orig_b);
	if (r < 0) {
		block_t location = block_location(b);
		bn_unlock(info, b);
		tm_dec(info->tm, location);
	}

	*clone = block_location(b);
	b_node = (struct node *) block_data(b);
	orig_node = to_node(orig_b);

	memcpy(b_node, orig_node, bm_block_size(tm_get_bm(info->tm)));
	tm_unlock(info->tm, orig_b);
	inc_children(info, b_node, info->adjust);
	tm_unlock(info->tm, b);

	return 0;
}
EXPORT_SYMBOL_GPL(btree_clone);

void value_is_block(struct transaction_manager *tm, void *value, int32_t delta)
{
	block_t b = __le64_to_cpu(*((__le64 *) value));
	while (delta < 0) {
		tm_dec(tm, b);
		delta++;
	}

	while (delta > 0) {
		tm_inc(tm, b);
		delta--;
	}
}
EXPORT_SYMBOL_GPL(value_is_block);

void value_is_meaningless(struct transaction_manager *tm, void *value, int32_t delta)
{
}
EXPORT_SYMBOL_GPL(value_is_meaningless);

/*----------------------------------------------------------------*/

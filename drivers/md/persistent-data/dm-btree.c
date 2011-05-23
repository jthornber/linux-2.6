#include "dm-btree-internal.h"
#include "dm-space-map.h"

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

int lower_bound(struct node *n, uint64_t key)
{
	return bsearch(n, key, 0);
}

int upper_bound(struct node *n, uint64_t key)
{
	return bsearch(n, key, 1);
}

void inc_children(struct dm_transaction_manager *tm, struct node *n,
		  struct dm_btree_value_type *vt)
{
	unsigned i;
	uint32_t nr_entries = __le32_to_cpu(n->header.nr_entries);

	if (__le32_to_cpu(n->header.flags) & INTERNAL_NODE)
		for (i = 0; i < nr_entries; i++)
			dm_tm_inc(tm, value64(n, i));
	else if (vt->copy)
		for (i = 0; i < nr_entries; i++)
			vt->copy(vt->context,
				 value_ptr(n, i, vt->size));
}

void insert_at(size_t value_size, struct node *node, unsigned index,
	       uint64_t key, void *value)
{
	uint32_t nr_entries = __le32_to_cpu(node->header.nr_entries);

	BUG_ON(index > nr_entries ||
	       index >= __le32_to_cpu(node->header.max_entries));

	array_insert(node->keys, sizeof(*node->keys), nr_entries, index, &key);
	array_insert(value_base(node), value_size, nr_entries, index, value);
	node->header.nr_entries = __cpu_to_le32(nr_entries + 1);
}

/*----------------------------------------------------------------*/

/*
 * We want 3n entries (for some n).  This works more nicely for repeated
 * insert remove loops than (2n + 1).
 */
uint32_t calc_max_entries(size_t value_size, size_t block_size)
{
	uint32_t total, n;
	size_t elt_size = sizeof(uint64_t) + value_size; /* key + value */

	block_size -= sizeof(struct node_header);
	total = block_size / elt_size;
	n = total / 3;		/* rounds down */

	return 3 * n;
}

int dm_btree_empty(struct dm_btree_info *info, dm_block_t *root)
{
	int r;
	struct dm_block *b;
	struct node *n;
	size_t block_size;
	uint32_t max_entries;

	r = bn_new_block(info, &b);
	if (r < 0)
		return r;

	block_size = dm_bm_block_size(dm_tm_get_bm(info->tm));
	max_entries = calc_max_entries(info->value_type.size, block_size);

	n = (struct node *) dm_block_data(b);
	memset(n, 0, block_size);
	n->header.flags = __cpu_to_le32(LEAF_NODE);
	n->header.nr_entries = __cpu_to_le32(0);
	n->header.max_entries =	__cpu_to_le32(max_entries);
	n->header.magic = __cpu_to_le32(BTREE_NODE_MAGIC);

	*root = dm_block_location(b);
	return bn_unlock(info, b);
}
EXPORT_SYMBOL_GPL(dm_btree_empty);

/*----------------------------------------------------------------*/

/*
 * Deletion uses a recursive algorithm, since we have limited stack space
 * we explicitly manage our own stack on the heap.
 */
#define MAX_SPINE_DEPTH 64
struct frame {
	struct dm_block *b;
	struct node *n;
	unsigned level;
	unsigned nr_children;
	unsigned current_child;
};

struct del_stack {
	struct dm_transaction_manager *tm;
	int top;
	struct frame spine[MAX_SPINE_DEPTH];
};

static void top_frame(struct del_stack *s, struct frame **f)
{
	BUG_ON(s->top < 0);
	*f = s->spine + s->top;
}

static int unprocessed_frames(struct del_stack *s)
{
	return s->top >= 0;
}

static int push_frame(struct del_stack *s, dm_block_t b, unsigned level)
{
	int r;
	uint32_t ref_count;

	BUG_ON(s->top >= MAX_SPINE_DEPTH);

	r = dm_tm_ref(s->tm, b, &ref_count);
	if (r)
		return r;

	if (ref_count > 1) {
		/*
		 * This is a shared node, so we can just decrement it's
		 * reference counter and leave the children.
		 */
		dm_tm_dec(s->tm, b);

	} else {
		struct frame *f = s->spine + ++s->top;

		r = dm_tm_read_lock(s->tm, b, &f->b);
		if (!r) {
			s->top--;
			return r;
		}

		f->n = to_node(f->b);
		f->level = level;
		f->nr_children = __le32_to_cpu(f->n->header.nr_entries);
		f->current_child = 0;
	}

	return 0;
}

static void pop_frame(struct del_stack *s)
{
	struct frame *f = s->spine + s->top--;

	dm_tm_dec(s->tm, dm_block_location(f->b));
	dm_tm_unlock(s->tm, f->b);
}

int dm_btree_del(struct dm_btree_info *info, dm_block_t root)
{
	struct del_stack *s;

	s = kmalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	s->tm = info->tm;
	s->top = -1;

	push_frame(s, root, 1);
	while (unprocessed_frames(s)) {
		int r;
		uint32_t flags;
		struct frame *f;
		dm_block_t b;

		top_frame(s, &f);

		if (f->current_child >= f->nr_children)
			pop_frame(s);

		flags = __le32_to_cpu(f->n->header.flags);
		if (flags & INTERNAL_NODE) {
			b = value64(f->n, f->current_child);
			f->current_child++;
			r = push_frame(s, b, f->level);
			if (r)
				goto bad;

		} else if (f->level != info->levels) {
			b = value64(f->n, f->current_child);
			f->current_child++;
			r = push_frame(s, b, f->level + 1);
			if (r)
				goto bad;

		} else {
			if (info->value_type.del) {
				unsigned i;

				for (i = 0; i < f->nr_children; i++)
					info->value_type.del(info->value_type.context,
							     value_ptr(f->n, i, info->value_type.size));
			}
			f->current_child = f->nr_children;
		}
	}

	return 0;

bad:
	/* what happens if we've deleted half a tree? */
	return -1; /* FIXME: return error code rather than -1? */
}
EXPORT_SYMBOL_GPL(dm_btree_del);

/*----------------------------------------------------------------*/

static int btree_lookup_raw(struct ro_spine *s, dm_block_t block, uint64_t key,
			    int (*search_fn)(struct node *, uint64_t),
			    uint64_t *result_key, void *v, size_t value_size)
{
	int i, r;
	uint32_t flags, nr_entries;

	do {
		r = ro_step(s, block);
		if (r < 0)
			return r;

		i = search_fn(ro_node(s), key);

		flags = __le32_to_cpu(ro_node(s)->header.flags);
		nr_entries = __le32_to_cpu(ro_node(s)->header.nr_entries);
		if (i < 0 || i >= nr_entries)
			return -ENODATA;

		if (flags & INTERNAL_NODE)
			block = value64(ro_node(s), i);

        } while (!(flags & LEAF_NODE));

	*result_key = __le64_to_cpu(ro_node(s)->keys[i]);
	memcpy(v, value_ptr(ro_node(s), i, value_size), value_size);

	return 0;
}

int dm_btree_lookup(struct dm_btree_info *info, dm_block_t root,
		    uint64_t *keys, void *value)
{
	unsigned level, last_level = info->levels - 1;
	int r;
	uint64_t rkey;
	__le64 internal_value;
	struct ro_spine spine;

	init_ro_spine(&spine, info);
	for (level = 0; level < info->levels; level++) {
		size_t size;
		void *value_p;

		if (level == last_level) {
			value_p = value;
			size = info->value_type.size;

		} else {
			value_p = &internal_value;
			size = sizeof(uint64_t);
		}

		r = btree_lookup_raw(&spine, root, keys[level],
				     lower_bound, &rkey,
				     value_p, size);

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
EXPORT_SYMBOL_GPL(dm_btree_lookup);

int dm_btree_lookup_le(struct dm_btree_info *info, dm_block_t root,
		       uint64_t *keys, uint64_t *key, void *value)
{
	unsigned level, last_level = info->levels - 1;
	int r;
	__le64 internal_value;
	struct ro_spine spine;

	init_ro_spine(&spine, info);
	for (level = 0; level < info->levels; level++) {
		size_t size;
		void *value_p;

		if (level == last_level) {
			value_p = value;
			size = info->value_type.size;

		} else {
			value_p = &internal_value;
			size = sizeof(uint64_t);
		}

		r = btree_lookup_raw(&spine, root, keys[level],
				     lower_bound, key,
				     value_p, size);

		if (r != 0) {
			exit_ro_spine(&spine);
			return r;
		}

		root = __le64_to_cpu(internal_value);
	}
	exit_ro_spine(&spine);

	return r;
}
EXPORT_SYMBOL_GPL(dm_btree_lookup_le);

int dm_btree_lookup_ge(struct dm_btree_info *info, dm_block_t root,
		       uint64_t *keys, uint64_t *key, void *value)
{
	unsigned level, last_level = info->levels - 1;
	int r;
        __le64 internal_value;
	struct ro_spine spine;

	init_ro_spine(&spine, info);
	for (level = 0; level < info->levels; level++) {
		size_t size;
		void *value_p;

		if (level == last_level) {
			value_p = value;
			size = info->value_type.size;

		} else {
			value_p = &internal_value;
			size = sizeof(uint64_t);
		}

		r = btree_lookup_raw(&spine, root, keys[level],
				     upper_bound, key,
				     value_p, size);

		if (r != 0) {
			exit_ro_spine(&spine);
			return r;
		}

		root = __le64_to_cpu(internal_value);
	}
	exit_ro_spine(&spine);

	return r;
}
EXPORT_SYMBOL_GPL(dm_btree_lookup_ge);

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
static int btree_split_sibling(struct shadow_spine *s, dm_block_t root,
			       unsigned parent_index, uint64_t key)
{
	int ret;
	size_t size;
	unsigned nr_left, nr_right;
	struct dm_block *left, *right, *parent;
	struct node *l, *r, *p;
	__le64 location;

	left = shadow_current(s);
	BUG_ON(!left);

	ret = bn_new_block(s->info, &right);
	if (ret < 0)
		return ret;

	l = to_node(left);
	r = (struct node *) dm_block_data(right);

	nr_left = __le32_to_cpu(l->header.nr_entries) / 2;
	nr_right = __le32_to_cpu(l->header.nr_entries) - nr_left;

	l->header.nr_entries = __cpu_to_le32(nr_left);

	r->header.flags = l->header.flags;
	r->header.nr_entries = __cpu_to_le32(nr_right);
	r->header.max_entries = l->header.max_entries;
	r->header.magic = __cpu_to_le32(BTREE_NODE_MAGIC);
	memcpy(r->keys, l->keys + nr_left, nr_right * sizeof(r->keys[0]));

	size = __le32_to_cpu(l->header.flags) & INTERNAL_NODE ?
		sizeof(uint64_t) : s->info->value_type.size;
	memcpy(value_ptr(r, 0, size), value_ptr(l, nr_left, size),
	       size * nr_right);

	/* Patch up the parent */
	parent = shadow_parent(s);
	BUG_ON(!parent);

	p = to_node(parent);
	location = __cpu_to_le64(dm_block_location(left));
	memcpy(value_ptr(p, parent_index, sizeof(__le64)),
	       &location, sizeof(__le64));

	location = __cpu_to_le64(dm_block_location(right));
	insert_at(sizeof(__le64), p, parent_index + 1,
		  __le64_to_cpu(r->keys[0]), &location);

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
static int btree_split_beneath(struct shadow_spine *s, dm_block_t root, uint64_t key)
{
	int ret;
	size_t size;
	unsigned nr_left, nr_right;
	struct dm_block *left, *right, *new_parent;
	struct node *p, *l, *r;
	__le64 val;

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
	l = (struct node *) dm_block_data(left);
	r = (struct node *) dm_block_data(right);

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

	size = __le32_to_cpu(p->header.flags) & INTERNAL_NODE ?
		sizeof(__le64) : s->info->value_type.size;
	memcpy(value_ptr(l, 0, size), value_ptr(p, 0, size), nr_left * size);
	memcpy(value_ptr(r, 0, size), value_ptr(p, nr_left, size), nr_right * size);

	/* new_parent should just point to l and r now */
	p->header.flags = __cpu_to_le32(INTERNAL_NODE);
	p->header.nr_entries = __cpu_to_le32(2);

	val = __cpu_to_le64(dm_block_location(left));
	p->keys[0] = l->keys[0];
	memcpy(value_ptr(p, 0, sizeof(__le64)), &val, sizeof(__le64));

	val = __cpu_to_le64(dm_block_location(right));
	p->keys[1] = r->keys[0];
	memcpy(value_ptr(p, 1, sizeof(__le64)), &val, sizeof(__le64));

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

static int btree_insert_raw(struct shadow_spine *s, dm_block_t root,
			    struct dm_btree_value_type *vt,
			    uint64_t key, unsigned *index)
{
        int r, i = *index, inc, top = 1;
	struct node *node;

	for (;;) {
		r = shadow_step(s, root, vt, &inc); /* FIXME: why is @inc never looked at? */
		if (r < 0) {
			/* FIXME: unpick any allocations */
			return r;
		}

		/*
		 * We have to patch up the parent node, ugly, but I don't
		 * see a way to do this automatically as part of the spine
		 * op.
		 */
		if (shadow_parent(s) && i >= 0) { /* FIXME: second clause unness. */
			__le64 location = __cpu_to_le64(dm_block_location(shadow_current(s)));
			memcpy(value_ptr(to_node(shadow_parent(s)), i, sizeof(uint64_t)),
			       &location, sizeof(__le64));
		}

		BUG_ON(!shadow_current(s));
		node = to_node(shadow_current(s));
#if 0
		/* FIXME: put this in */
		if (inc)
			inc_children(info->tm, node, &info->value_type);
#endif

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
		if (vt->del)
			vt->del(vt->context, value_ptr(node, i, vt->size));

	*index = i;
	return 0;
}

int dm_btree_insert(struct dm_btree_info *info, dm_block_t root,
		    uint64_t *keys, void *value, dm_block_t *new_root)
{
	int r, need_insert;
	unsigned level, index = -1, last_level = info->levels - 1;
	dm_block_t *block = &root;
	struct shadow_spine spine;
	struct node *n;
	struct dm_btree_value_type internal_type;

	internal_type.context = NULL;
	internal_type.size = sizeof(__le64);
	internal_type.copy = NULL;
	internal_type.del = NULL;
	internal_type.equal = NULL;

	init_shadow_spine(&spine, info);

	for (level = 0; level < info->levels; level++) {
		r = btree_insert_raw(&spine, *block,
				     (level == last_level ?
				      &info->value_type : &internal_type),
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
				insert_at(info->value_type.size, n, index,
					  keys[level], value);
			else {
				if (info->value_type.del &&
				    (!info->value_type.equal ||
				     !info->value_type.equal(
					     info->value_type.context,
					     value_ptr(n, index, info->value_type.size),
					     value))) {
					info->value_type.del(info->value_type.context,
					     value_ptr(n, index, info->value_type.size));
				}
				memcpy(value_ptr(n, index, info->value_type.size),
				       value, info->value_type.size);
			}
		} else {
			if (need_insert) {
				dm_block_t new_tree;
				r = dm_btree_empty(info, &new_tree);
				if (r < 0) {
					/* FIXME: avoid block leaks */
					exit_shadow_spine(&spine);
					return r;
				}

				insert_at(sizeof(uint64_t), n, index,
					  keys[level], &new_tree);
			}
		}

		if (level < last_level)
			block = value_ptr(n, index, sizeof(uint64_t));
	}

	*new_root = shadow_root(&spine);
	exit_shadow_spine(&spine);

	return 0;
}
EXPORT_SYMBOL_GPL(dm_btree_insert);

/*----------------------------------------------------------------*/

int dm_btree_clone(struct dm_btree_info *info, dm_block_t root,
		   dm_block_t *clone)
{
	int r;
	struct dm_block *b, *orig_b;
	struct node *b_node, *orig_node;

	/* Copy the root node */
	r = bn_new_block(info, &b);
	if (r < 0)
		return r;

	r = dm_tm_read_lock(info->tm, root, &orig_b);
	if (r < 0) {
		dm_block_t location = dm_block_location(b);

		bn_unlock(info, b);
		dm_tm_dec(info->tm, location);
	}

	*clone = dm_block_location(b);
	b_node = (struct node *) dm_block_data(b);
	orig_node = to_node(orig_b);

	memcpy(b_node, orig_node,
	       dm_bm_block_size(dm_tm_get_bm(info->tm)));
	dm_tm_unlock(info->tm, orig_b);
	inc_children(info->tm, b_node, &info->value_type);
	dm_tm_unlock(info->tm, b);

	return 0;
}
EXPORT_SYMBOL_GPL(dm_btree_clone);

/*----------------------------------------------------------------*/

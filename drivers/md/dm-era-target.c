#include "dm.h"
#include "persistent-data/dm-transaction-manager.h"
#include "persistent-data/dm-bitset.h"
#include "persistent-data/dm-space-map.h"

#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/init.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#define DM_MSG_PREFIX "era"

#define SUPERBLOCK_LOCATION 0
#define SUPERBLOCK_MAGIC 2126579579
#define SUPERBLOCK_CSUM_XOR 146538381
#define MIN_ERA_VERSION 1
#define MAX_ERA_VERSION 1
#define INVALID_BLOOM_ROOT SUPERBLOCK_LOCATION

/*----------------------------------------------------------------
 * Bloom filter
 *--------------------------------------------------------------*/
#define ERA_DIVIDER 20

#define BLOOM_MIN_SHIFT 10
#define BLOOM_MAX_SHIFT 30

struct bloom_metadata {
	// FIXME: change nr blocks to 64bit
	uint32_t nr_blocks;
	uint32_t nr_bits;
	atomic64_t nr_set;

	dm_block_t root;
};

struct bloom_filter {
	struct bloom_metadata md;

	unsigned mask;
	unsigned long *bits;
};

/*
 * This does not free off the on disk bitset as this will normally be done
 * after digesting into the era array.
 */
static void filter_free(struct bloom_filter *f)
{
	vfree(f->bits);
}

static int setup_on_disk_bitset(struct dm_disk_bitset *info,
				unsigned nr_bits, dm_block_t *root)
{
	int r;

	r = dm_bitset_empty(info, root);
	if (r)
		return r;

	return dm_bitset_resize(info, *root, 0, nr_bits, false, root);
}

static unsigned calc_bloom_filter_size(unsigned nr_changes)
{
	unsigned shift = BLOOM_MIN_SHIFT;
	unsigned target = nr_changes * 16;

	while ((shift < BLOOM_MAX_SHIFT) && ((1u << shift) < target))
		shift++;

	return 1 << shift;
}

static size_t bitset_size(unsigned nr_bits)
{
	return sizeof(unsigned long) * dm_div_up(nr_bits, BITS_PER_LONG);
}

/*
 * Allocates memory for the in core bitset.
 */
static int filter_alloc(struct bloom_filter *f, dm_block_t nr_blocks)
{
	unsigned nr_bits;

	nr_bits = nr_blocks;
	do_div(nr_bits, ERA_DIVIDER);
	nr_bits = calc_bloom_filter_size((unsigned) nr_bits);
	f->md.nr_blocks = nr_blocks;
	f->md.nr_bits = nr_bits;
	f->md.root = INVALID_BLOOM_ROOT;
	atomic64_set(&f->md.nr_set, 0);

	f->mask = nr_bits - 1;
	f->bits = vzalloc(bitset_size(nr_bits));
	if (!f->bits) {
		DMERR("%s: couldn't allocate in memory bitset", __func__);
		return -ENOMEM;
	}

	return 0;
}

/*
 * Wipes the in-core bitset, and creates a new on disk bitset.
 */
static void check_disk_all_zeroes(struct dm_disk_bitset *info,
				  struct bloom_filter *f)
{
	int r;
	bool v;
	unsigned i;

	for (i = 0; i < f->md.nr_bits; i++) {
		r = dm_bitset_test_bit(info, f->md.root, i, &f->md.root, &v);
		if (r)
			BUG();

		if (v)
			pr_alert("bitset init failed, bit %u is set\n", i);
	}
}

static int filter_init(struct dm_disk_bitset *info, struct bloom_filter *f)
{
	int r;

	memset(f->bits, 0, bitset_size(f->md.nr_bits));
	atomic64_set(&f->md.nr_set, 0);

	r = setup_on_disk_bitset(info, f->md.nr_bits, &f->md.root);
	if (r) {
		DMERR("%s: setup_on_disk_bitset failed", __func__);
		return r;
	}

	check_disk_all_zeroes(info, f);

	return 0;
}

#define MULTIPLIER 0x9e37fffffffc0001UL
#define BIT_SHIFT 18

static uint32_t hash1(dm_block_t b)
{
	return (b * MULTIPLIER) >> BIT_SHIFT;
}

static uint32_t hash2(dm_block_t b)
{
	uint32_t n = b;

	n = n ^ (n >> 16);
	n = n * 0x85ebca6bu;
	n = n ^ (n >> 13);
	n = n * 0xc2b2ae35u;
	n = n ^ (n >> 16);

	return n;
}

static bool filter_marked(struct bloom_filter *f, dm_block_t block)
{
	unsigned p;
	uint32_t h1, h2;

	h1 = hash1(block) & f->mask;
	if (!test_bit(h1, f->bits))
		return false;

	h2 = hash2(block) & f->mask;
	for (p = 1; p < 6; p++) {
		h1 = (h1 + h2) & f->mask;
		h2 = (h2 + p) & f->mask;

		if (!test_bit(h1, f->bits))
			return false;
	}

	return true;
}

static int filter_marked_on_disk(struct dm_disk_bitset *info,
				 struct bloom_metadata *m, dm_block_t block,
				 bool *result)
{
	int r;
	unsigned p;
	uint32_t h1, h2;
	uint32_t mask = m->nr_bits - 1;

	h1 = hash1(block) & mask;

	/*
	 * The bitset was flushed when it was archived, so we know there'll
	 * be no change to the root.
	 */
	r = dm_bitset_test_bit(info, m->root, h1, &m->root, result);
	if (r) {
		DMERR("%s: dm_bitset_test_bit failed", __func__);
		return r;
	}

	if (!*result)
		return 0;

	h2 = hash2(block) & mask;
	for (p = 1; p < 6; p++) {
		h1 = (h1 + h2) & mask;
		h2 = (h2 + p) & mask;

		r = dm_bitset_test_bit(info, m->root, h1, &m->root, result);
		if (r) {
			DMERR("%s: dm_bitset_test_bit failed", __func__);
			return r;
		}

		if (!*result)
			return 0;
	}

	return 0;
}

static int set_bloom_bit(struct dm_disk_bitset *info,
			 struct bloom_filter *f, unsigned bit)
{
	int r;

	if (!test_and_set_bit(bit, f->bits)) {
		r = dm_bitset_set_bit(info, f->md.root, bit, &f->md.root);
		if (r)
			return r;

		atomic64_inc(&f->md.nr_set);
	}

	return 0;
}

static int filter_mark(struct dm_disk_bitset *info,
		       struct bloom_filter *f, uint32_t block)
{
	int r;
	unsigned p;
	uint32_t h1, h2;

	h1 = hash1(block) & f->mask;
	r = set_bloom_bit(info, f, h1);
	if (r)
		return r;

	h2 = hash2(block) & f->mask;
	for (p = 1; p < 6; p++) {
		h1 = (h1 + h2) & f->mask;
		h2 = (h2 + p) & f->mask;

		r = set_bloom_bit(info, f, h1);
		if (r)
			return r;
	}

	{
		bool result;

		BUG_ON(!filter_marked(f, block));
		r = filter_marked_on_disk(info, &f->md, block, &result);
		BUG_ON(r);
		BUG_ON(!result);
	}

	return 0;
}

static int filter_full(struct bloom_filter *f)
{
	return atomic64_read(&f->md.nr_set) > (f->md.nr_bits / 2);
}

/*----------------------------------------------------------------
 * On disk metadata layout
 *--------------------------------------------------------------*/
#define SPACE_MAP_ROOT_SIZE 128
#define UUID_LEN 16

struct bloom_disk {
	__le32 nr_blocks;
	__le32 nr_bits;
	__le32 nr_set;
	__le64 root;

	// FIXME: we should store the hash fns and nr probes
} __packed;

struct superblock_disk {
	__le32 csum;
	__le32 flags;
	__le64 blocknr;

	__u8 uuid[UUID_LEN];
	__le64 magic;
	__le32 version;

	__u8 metadata_space_map_root[SPACE_MAP_ROOT_SIZE];

	__le32 data_block_size;
	__le32 metadata_block_size;
	__le32 nr_blocks;

	__le32 current_era;
	struct bloom_disk current_bloom;

	/*
	 * Only these two fields are valid within the metadata snapshot.
	 */
	__le64 bloom_tree_root;
	__le64 era_array_root;
} __packed;

/*----------------------------------------------------------------
 * Superblock validation
 *--------------------------------------------------------------*/
static void sb_prepare_for_write(struct dm_block_validator *v,
				 struct dm_block *b,
				 size_t sb_block_size)
{
	struct superblock_disk *disk = dm_block_data(b);

        disk->blocknr = cpu_to_le64(dm_block_location(b));
        disk->csum = cpu_to_le32(dm_bm_checksum(&disk->flags,
						sb_block_size - sizeof(__le32),
						SUPERBLOCK_CSUM_XOR));
}

static int check_metadata_version(struct superblock_disk *disk)
{
	uint32_t metadata_version = le32_to_cpu(disk->version);
	if (metadata_version < MIN_ERA_VERSION || metadata_version > MAX_ERA_VERSION) {
		DMERR("Era metadata version %u found, but only versions between %u and %u supported.",
		      metadata_version, MIN_ERA_VERSION, MAX_ERA_VERSION);
		return -EINVAL;
	}

	return 0;
}

static int sb_check(struct dm_block_validator *v,
		    struct dm_block *b,
		    size_t sb_block_size)
{
	struct superblock_disk *disk = dm_block_data(b);
	__le32 csum_le;

	if (dm_block_location(b) != le64_to_cpu(disk->blocknr)) {
		DMERR("sb_check failed: blocknr %llu: wanted %llu",
		      le64_to_cpu(disk->blocknr),
		      (unsigned long long)dm_block_location(b));
		return -ENOTBLK;
	}

	if (le64_to_cpu(disk->magic) != SUPERBLOCK_MAGIC) {
		DMERR("sb_check failed: magic %llu: wanted %llu",
		      le64_to_cpu(disk->magic),
		      (unsigned long long) SUPERBLOCK_MAGIC);
		return -EILSEQ;
	}

	csum_le = cpu_to_le32(dm_bm_checksum(&disk->flags,
					     sb_block_size - sizeof(__le32),
					     SUPERBLOCK_CSUM_XOR));
	if (csum_le != disk->csum) {
		DMERR("sb_check failed: csum %u: wanted %u",
		      le32_to_cpu(csum_le), le32_to_cpu(disk->csum));
		return -EILSEQ;
	}

	return check_metadata_version(disk);
}

static struct dm_block_validator sb_validator = {
	.name = "superblock",
	.prepare_for_write = sb_prepare_for_write,
	.check = sb_check
};

/*----------------------------------------------------------------
 * Low level metadata handling
 *--------------------------------------------------------------*/
#define METADATA_BLOCK_SIZE 4096
#define METADATA_CACHE_SIZE 64
#define MAX_CONCURRENT_LOCKS 5

struct era_metadata {
	struct block_device *bdev;
	struct dm_block_manager *bm;
	struct dm_space_map *sm;
	struct dm_transaction_manager *tm;

	dm_block_t block_size;
	uint32_t nr_blocks;

	atomic64_t current_era;

	/*
	 * We preallocate 2 bloom filters.  When an era rolls over we
	 * switch between them. This means the allocation is done at
	 * preresume time, rather than on the io path.
	 */
	struct bloom_filter blooms[2];
	struct bloom_filter *current_bloom;

	dm_block_t bloom_tree_root;
	dm_block_t era_array_root;

	struct dm_disk_bitset bitset_info;
	struct dm_btree_info bloom_tree_info;
	struct dm_array_info era_array_info;

	dm_block_t metadata_snap;
};

static int superblock_read_lock(struct era_metadata *md,
				struct dm_block **sblock)
{
	return dm_bm_read_lock(md->bm, SUPERBLOCK_LOCATION,
			       &sb_validator, sblock);
}

static int superblock_lock_zero(struct era_metadata *md,
				struct dm_block **sblock)
{
	return dm_bm_write_lock_zero(md->bm, SUPERBLOCK_LOCATION,
				     &sb_validator, sblock);
}

static int superblock_lock(struct era_metadata *md,
			   struct dm_block **sblock)
{
	return dm_bm_write_lock(md->bm, SUPERBLOCK_LOCATION,
				&sb_validator, sblock);
}

// FIXME: duplication with cache and thin
static int superblock_all_zeroes(struct dm_block_manager *bm, bool *result)
{
	int r;
	unsigned i;
	struct dm_block *b;
	__le64 *data_le, zero = cpu_to_le64(0);
	unsigned sb_block_size = dm_bm_block_size(bm) / sizeof(__le64);

	/*
	 * We can't use a validator here - it may be all zeroes.
	 */
	r = dm_bm_read_lock(bm, SUPERBLOCK_LOCATION, NULL, &b);
	if (r)
		return r;

	data_le = dm_block_data(b);
	*result = true;
	for (i = 0; i < sb_block_size; i++) {
		if (data_le[i] != zero) {
			*result = false;
			break;
		}
	}

	return dm_bm_unlock(b);
}

/*----------------------------------------------------------------*/

static void bf_pack(const struct bloom_metadata *core, struct bloom_disk *disk)
{
	disk->nr_blocks = cpu_to_le32(core->nr_blocks);
	disk->nr_bits = cpu_to_le32(core->nr_bits);
	disk->nr_set = cpu_to_le32(atomic64_read(&core->nr_set));
	disk->root = cpu_to_le64(core->root);
}

static void bf_unpack(const struct bloom_disk *disk, struct bloom_metadata *core)
{
	core->nr_blocks = le32_to_cpu(disk->nr_blocks);
	core->nr_bits = le32_to_cpu(disk->nr_bits);
	atomic64_set(&core->nr_set, le32_to_cpu(disk->nr_set));
	core->root = le64_to_cpu(disk->root);
}

static void bf_inc(void *context, const void *value)
{
	struct era_metadata *md = context;
	struct bloom_disk bd;
	dm_block_t b;

	memcpy(&bd, value, sizeof(bd));
	b = le64_to_cpu(bd.root);

	dm_tm_inc(md->tm, b);
}

static void bf_dec(void *context, const void *value)
{
	struct era_metadata *md = context;
	struct bloom_disk bd;
	dm_block_t b;

	memcpy(&bd, value, sizeof(bd));
	b = le64_to_cpu(bd.root);

	dm_bitset_del(&md->bitset_info, b);
}

static int bf_eq(void *context, const void *value1, const void *value2)
{
	return !memcmp(value1, value2, sizeof(struct bloom_metadata));
}

/*----------------------------------------------------------------*/

static void setup_bloom_tree_info(struct era_metadata *md)
{
	struct dm_btree_value_type *vt = &md->bloom_tree_info.value_type;
	md->bloom_tree_info.tm = md->tm;
	md->bloom_tree_info.levels = 1;
	vt->context = md;
	vt->size = sizeof(struct bloom_disk);
	vt->inc = bf_inc;
	vt->dec = bf_dec;
	vt->equal = bf_eq;
}

static void setup_era_array_info(struct era_metadata *md)

{
	struct dm_btree_value_type vt;
	vt.context = NULL;
	vt.size = sizeof(__le32);
	vt.inc = NULL;
	vt.dec = NULL;
	vt.equal = NULL;

	dm_array_info_init(&md->era_array_info, md->tm, &vt);
}

static void setup_infos(struct era_metadata *md)
{
	dm_disk_bitset_init(md->tm, &md->bitset_info);
	setup_bloom_tree_info(md);
	setup_era_array_info(md);
}

/*----------------------------------------------------------------*/

static int create_fresh_metadata(struct era_metadata *md)
{
	int r;

	r = dm_tm_create_with_sm(md->bm, SUPERBLOCK_LOCATION,
				 &md->tm, &md->sm);
	if (r < 0) {
		DMERR("dm_tm_create_with_sm failed");
		return r;
	}

	setup_infos(md);

	r = dm_btree_empty(&md->bloom_tree_info, &md->bloom_tree_root);
	if (r) {
		DMERR("couldn't create new bloom tree");
		return r;
	}

	r = dm_array_empty(&md->era_array_info, &md->era_array_root);
	if (r) {
		DMERR("couldn't create era array");
		return r;
	}

	return 0;
}

/*
 * Writes a superblock, including the static fields that don't get updated
 * with every commit (possible optimisation here).  'md' should be fully
 * constructed when this is called.
 */
static int prepare_superblock(struct era_metadata *md, struct superblock_disk *disk)
{
	int r;
	size_t metadata_len;

	disk->magic = cpu_to_le64(SUPERBLOCK_MAGIC);
	disk->flags = cpu_to_le32(0ul);

	// FIXME: can't keep blanking the uuid
	memset(disk, 0, sizeof(disk->uuid));
	disk->version = cpu_to_le32(MAX_ERA_VERSION);

	r = dm_sm_root_size(md->sm, &metadata_len);
	if (r < 0)
		return r;

	r = dm_sm_copy_root(md->sm, &disk->metadata_space_map_root,
			    metadata_len);
	if (r < 0)
		return r;

	disk->data_block_size = cpu_to_le32(md->block_size);
	disk->metadata_block_size = cpu_to_le32(METADATA_BLOCK_SIZE >> SECTOR_SHIFT);
	disk->nr_blocks = cpu_to_le32(md->nr_blocks);
	disk->current_era = cpu_to_le32(atomic64_read(&md->current_era));

	bf_pack(&md->current_bloom->md, &disk->current_bloom);
	disk->bloom_tree_root = cpu_to_le64(md->bloom_tree_root);
	disk->era_array_root = cpu_to_le64(md->era_array_root);

	return 0;
}

static int write_superblock(struct era_metadata *md)
{
	int r;
	struct dm_block *sblock;
	struct superblock_disk *disk;

	r = superblock_lock_zero(md, &sblock);
	if (r)
		return r;

	disk = dm_block_data(sblock);
	r = prepare_superblock(md, disk);
	if (r) {
		DMERR("%s: prepare_superblock failed", __func__);
		dm_bm_unlock(sblock); /* FIXME: does this commit? */
		return r;
	}

	return dm_tm_commit(md->tm, sblock);
}

/*
 * Assumes block_size and the infos are set.
 */
static int format_metadata(struct era_metadata *md)
{
	int r;

	r = create_fresh_metadata(md);
	if (r)
		return r;

	r = write_superblock(md);
	if (r)
		return r;

	return 0;
}

static int open_metadata(struct era_metadata *md)
{
	int r;
	struct dm_block *sblock;
	struct superblock_disk *disk;

	r = superblock_read_lock(md, &sblock);
	if (r) {
		DMERR("couldn't read_lock superblock");
		return r;
	}

	disk = dm_block_data(sblock);
	r = dm_tm_open_with_sm(md->bm, SUPERBLOCK_LOCATION,
			       disk->metadata_space_map_root,
			       sizeof(disk->metadata_space_map_root),
			       &md->tm, &md->sm);
	if (r) {
		DMERR("dm_tm_open_with_sm failed");
		goto bad;
	}

	setup_infos(md);

	return dm_bm_unlock(sblock);

bad:
	dm_bm_unlock(sblock);
	return r;
}

static int open_or_format_metadata(struct era_metadata *md,
				   bool may_format)
{
	int r;
	bool unformatted = false;

	r = superblock_all_zeroes(md->bm, &unformatted);
	if (r)
		return r;

	if (unformatted)
		return may_format ? format_metadata(md) : -EPERM;

	return open_metadata(md);
}

static int create_persistent_data_objects(struct era_metadata *md, bool may_format)
{
	int r;

	md->bm = dm_block_manager_create(md->bdev, METADATA_BLOCK_SIZE,
					 METADATA_CACHE_SIZE,
					 MAX_CONCURRENT_LOCKS);
	if (IS_ERR(md->bm)) {
		DMERR("could not create block manager");
		return PTR_ERR(md->bm);
	}

	r = open_or_format_metadata(md, may_format);
	if (r)
		dm_block_manager_destroy(md->bm);

	return r;
}

static void destroy_persistent_data_objects(struct era_metadata *md)
{
	dm_sm_destroy(md->sm);
	dm_tm_destroy(md->tm);
	dm_block_manager_destroy(md->bm);
}

/*
 * This waits until all era_map threads have picked up the new filter.
 */
static void swap_filter(struct era_metadata *md, struct bloom_filter *new_filter)
{
	rcu_assign_pointer(md->current_bloom, new_filter);
	synchronize_rcu();
}

/*----------------------------------------------------------------
 * High level metadata interface.  Target methods should use these, and not
 * the lower level ones.
 *--------------------------------------------------------------*/
static struct era_metadata *metadata_open(struct block_device *bdev,
					  sector_t block_size,
					  bool may_format)
{
	int r;
	struct era_metadata *md = kzalloc(sizeof(*md), GFP_KERNEL);

	if (!md)
		return NULL;

	md->bdev = bdev;
	md->block_size = block_size;

	md->blooms[0].md.root = INVALID_BLOOM_ROOT;
	md->blooms[1].md.root = INVALID_BLOOM_ROOT;
	md->current_bloom = &md->blooms[0];

	r = create_persistent_data_objects(md, may_format);
	if (r) {
		kfree(md);
		return ERR_PTR(r);
	}

	return md;
}

static void metadata_close(struct era_metadata *md)
{
	destroy_persistent_data_objects(md);
	kfree(md);
}

static int metadata_resize(struct era_metadata *md, void *arg)
{
	int r;
	dm_block_t *new_size = arg;
	__le32 value;

	filter_free(&md->blooms[0]);
	filter_free(&md->blooms[1]);

	r = filter_alloc(&md->blooms[0], *new_size);
	if (r) {
		DMERR("%s: filter_alloc failed for bloom 0", __func__);
		return r;
	}

	r = filter_alloc(&md->blooms[1], *new_size);
	if (r) {
		DMERR("%s: filter_alloc failed for bloom 1", __func__);
		return r;
	}

	value = cpu_to_le32(0u);
	__dm_bless_for_disk(&value);
	r = dm_array_resize(&md->era_array_info, md->era_array_root,
			    md->nr_blocks, *new_size,
			    &value, &md->era_array_root);
	if (r) {
		DMERR("%s: dm_array_resize failed", __func__);
		return r;
	}

	md->nr_blocks = *new_size;
	return 0;
}

static uint32_t metadata_current_era(struct era_metadata *md)
{
	return (uint32_t) atomic64_read(&md->current_era);
}

static void check_core_and_disk_bitsets_match(unsigned era,
					      struct dm_disk_bitset *info,
					      struct bloom_filter *f)
{
	int r;
	bool v1, v2;
	unsigned i;

	for (i = 0; i < f->md.nr_bits; i++) {
		v1 = test_bit(i, f->bits);
		r = dm_bitset_test_bit(info, f->md.root, i, &f->md.root, &v2);
		if (r)
			BUG();

		if (v1 != v2)
			pr_alert("bits disagree in era %u, bit = %u, core = %d, disk = %d\n",
				 era, i, v1, v2);
	}
}

static int metadata_era_archive(struct era_metadata *md)
{
	int r;
	uint64_t keys[1];
	struct bloom_disk value;

	check_core_and_disk_bitsets_match(atomic64_read(&md->current_era), &md->bitset_info, md->current_bloom);

	r = dm_bitset_flush(&md->bitset_info, md->current_bloom->md.root, &md->current_bloom->md.root);
	if (r) {
		DMERR("%s: dm_bitset_flush failed", __func__);
		return r;
	}

	bf_pack(&md->current_bloom->md, &value);
	md->current_bloom->md.root = INVALID_BLOOM_ROOT;

	keys[0] = atomic64_read(&md->current_era);
	__dm_bless_for_disk(&value);
	r = dm_btree_insert(&md->bloom_tree_info, md->bloom_tree_root, keys, &value, &md->bloom_tree_root);
	if (r) {
		DMERR("%s: couldn't insert era into btree", __func__);
		// FIXME: fail mode
		return r;
	}

	return 0;
}

static struct bloom_filter *next_filter(struct era_metadata *md)
{
	return (md->current_bloom == &md->blooms[0]) ? &md->blooms[1] : &md->blooms[0];
}

static int metadata_new_era(struct era_metadata *md)
{
	int r;
	struct bloom_filter *new_filter = next_filter(md);

	r = filter_init(&md->bitset_info, new_filter);
	if (r) {
		DMERR("%s: filter_init failed", __func__);
		return r;
	}

	swap_filter(md, new_filter);
	atomic64_inc(&md->current_era);

	return 0;
}

static int metadata_era_rollover(struct era_metadata *md)
{
	int r;

	if (md->current_bloom->md.root != INVALID_BLOOM_ROOT) {
		r = metadata_era_archive(md);
		if (r) {
			DMERR("%s: metadata_archive_era failed", __func__);
			// FIXME: fail mode?
			return r;
		}
	}

	r = metadata_new_era(md);
	if (r) {
		DMERR("%s: new era failed", __func__);
		// FIXME: fail mode
		return r;
	}

	return 0;
}

static int metadata_mark(struct era_metadata *md, dm_block_t block)
{
	if (filter_full(md->current_bloom))
		metadata_era_rollover(md);

	return filter_mark(&md->bitset_info, md->current_bloom, block);
}

static bool metadata_current_marked(struct era_metadata *md, dm_block_t block)
{
	bool r;
	struct bloom_filter *f;

	rcu_read_lock();
	f = rcu_dereference(md->current_bloom);
	r = filter_marked(f, block);
	rcu_read_unlock();

	return r;
}

static int metadata_commit(struct era_metadata *md)
{
	int r;
	struct dm_block *sblock;

	if (md->current_bloom->md.root != SUPERBLOCK_LOCATION) {
		r = dm_bitset_flush(&md->bitset_info, md->current_bloom->md.root, &md->current_bloom->md.root);
		if (r) {
			DMERR("%s: bitset flush failed", __func__);
			return r;
		}
	}

	r = dm_tm_pre_commit(md->tm);
	if (r) {
		DMERR("%s: pre commit failed", __func__);
		return r;
	}

	r = superblock_lock(md, &sblock);
	if (r) {
		DMERR("%s: superblock lock failed", __func__);
		return r;
	}

	r = prepare_superblock(md, dm_block_data(sblock));
	if (r) {
		DMERR("%s: prepare_superblock failed", __func__);
		dm_bm_unlock(sblock); /* FIXME: does this commit? */
		return r;
	}

	return dm_tm_commit(md->tm, sblock);
}

static int metadata_checkpoint(struct era_metadata *md)
{
	/*
	 * For now we just rollover, but later I want to put a check in to
	 * avoid this if the filter is still pretty fresh.
	 */
	return metadata_era_rollover(md);
}

/*
 * Metadata snapshots allow userland to access era data.
 */
static int metadata_take_snap(struct era_metadata *md)
{
	int r, inc;
	struct dm_block *clone;

	if (md->metadata_snap != SUPERBLOCK_LOCATION) {
		DMERR("asked to take a metadata snapshot when one already exists");
		return -EINVAL;
	}

	r = metadata_era_rollover(md);
	if (r) {
		DMERR("%s: era rollover failed", __func__);
		return r;
	}

	r = metadata_commit(md);
	if (r) {
		DMERR("%s: pre commit failed", __func__);
		return r;
	}

	r = dm_sm_inc_block(md->sm, SUPERBLOCK_LOCATION);
	if (r) {
		DMERR("%s: couldn't increment superblock", __func__);
		return r;
	}

	r = dm_tm_shadow_block(md->tm, SUPERBLOCK_LOCATION, &sb_validator, &clone, &inc);
	if (r) {
		DMERR("%s: couldn't shadow superblock", __func__);
		dm_sm_dec_block(md->sm, SUPERBLOCK_LOCATION);
		return r;
	}
	BUG_ON(!inc);

	r = dm_sm_inc_block(md->sm, md->bloom_tree_root);
	if (r) {
		DMERR("%s: couldn't inc bloom tree root", __func__);
		dm_tm_unlock(md->tm, clone);
		return r;
	}

	r = dm_sm_inc_block(md->sm, md->era_array_root);
	if (r) {
		DMERR("%s: couldn't inc era tree root", __func__);
		dm_sm_dec_block(md->sm, md->bloom_tree_root);
		dm_tm_unlock(md->tm, clone);
		return r;
	}

	md->metadata_snap = dm_block_location(clone);

	r = dm_tm_unlock(md->tm, clone);
	if (r) {
		DMERR("%s: couldn't unlock clone", __func__);
		md->metadata_snap = SUPERBLOCK_LOCATION;
		return r;
	}

	return 0;
}

static dm_block_t metadata_snap_root(struct era_metadata *md)
{
	return md->metadata_snap;
}

static int metadata_drop_snap(struct era_metadata *md)
{
	int r;
	dm_block_t location;
	struct dm_block *clone;
	struct superblock_disk *disk;

	if (md->metadata_snap == SUPERBLOCK_LOCATION) {
		DMERR("%s: no snap to drop", __func__);
		return -EINVAL;
	}

	r = dm_tm_read_lock(md->tm, md->metadata_snap, &sb_validator, &clone);
	if (r) {
		DMERR("%s: couldn't read lock superblock clone", __func__);
		return r;
	}

	/*
	 * Whatever happens now we'll commit with no record of the metadata
	 * snap.
	 */
	md->metadata_snap = SUPERBLOCK_LOCATION;

	disk = dm_block_data(clone);
	r = dm_btree_del(&md->bloom_tree_info, le64_to_cpu(disk->bloom_tree_root));
	if (r) {
		DMERR("%s: error deleting bloom tree clone", __func__);
		dm_tm_unlock(md->tm, clone);
		return r;
	}

	r = dm_array_del(&md->era_array_info, le64_to_cpu(disk->era_array_root));
	if (r) {
		DMERR("%s: error deleting era array clone", __func__);
		dm_tm_unlock(md->tm, clone);
		return r;
	}

	location = dm_block_location(clone);
	dm_tm_unlock(md->tm, clone);

	return dm_sm_dec_block(md->sm, location);
}

/*----------------------------------------------------------------
 * Goes through the archived bloom filters one by one transcribing them to
 * the era array.
 *
 * FIXME: This should be run in a background thread at low priority.
 *--------------------------------------------------------------*/
static int metadata_digest_once(struct era_metadata *md)
{
	int r;
	bool marked;
	uint64_t key;
	unsigned nr, b;
	struct bloom_disk disk;
	struct bloom_metadata bloom;
	__le32 value;
	struct dm_disk_bitset info;

	/*
	 * We initialise another bitset info to avoid any caching side
	 * effects with the previous one.
	 */
	dm_disk_bitset_init(md->tm, &info);

	r = dm_btree_find_lowest_key(&md->bloom_tree_info, md->bloom_tree_root, &key);
	if (r < 0)
		return r;

	r = dm_btree_lookup(&md->bloom_tree_info, md->bloom_tree_root, &key, &disk);
	if (r) {
		if (r != -ENODATA)
			DMERR("%s: dm_btree_lookup failed", __func__);
		return r;
	}

	bf_unpack(&disk, &bloom);
	pr_alert("digesting era %u\n", (unsigned) key);
	value = cpu_to_le32(key);

	nr = min(bloom.nr_blocks, md->nr_blocks);
	for (b = 0; b < nr; b++) {
		r = filter_marked_on_disk(&info, &bloom, b, &marked);
		if (r) {
			DMERR("%s: filter_marked_on_disk failed", __func__);
			return r;
		}

		if (marked) {
			__dm_bless_for_disk(&value);
			r = dm_array_set_value(&md->era_array_info, md->era_array_root,
					       b, &value, &md->era_array_root);
			if (r) {
				DMERR("%s: dm_array_set_value failed", __func__);
				return r;
			}
		}
	}

	r = dm_btree_remove(&md->bloom_tree_info, md->bloom_tree_root, &key, &md->bloom_tree_root);
	if (r) {
		DMERR("%s: dm_btree_remove failed", __func__);
		return r;
	}

	return 0;
}

static int metadata_digest(struct era_metadata *md)
{
	int r;

	pr_alert("starting digest process\n");
	while (!(r = metadata_digest_once(md)))
		;
	pr_alert("finished digest\n");
	return r == -ENODATA ? 0 : r;
}

/*----------------------------------------------------------------*/

struct era {
	struct dm_target *ti;
	struct dm_target_callbacks callbacks;

	struct dm_dev *metadata_dev;
	struct dm_dev *origin_dev;

	uint32_t block_size;
	dm_block_t nr_blocks;
	unsigned sectors_per_block_shift;
	struct era_metadata *md;

	struct workqueue_struct *wq;
	struct work_struct worker;

	spinlock_t deferred_lock;
	struct bio_list deferred_bios;

	spinlock_t rpc_lock;
	struct list_head rpc_calls;
};

struct rpc {
	struct list_head list;

	int (*fn0)(struct era_metadata *);
	int (*fn1)(struct era_metadata *, void *);
	void *arg;
	int result;

	wait_queue_head_t wait;
	atomic_t complete;
};

/*----------------------------------------------------------------
 * Remapping.
 *---------------------------------------------------------------*/
static dm_block_t get_block(struct era *era, struct bio *bio)
{
	return bio->bi_sector >> era->sectors_per_block_shift;
}

static void remap_to_origin(struct era *era, struct bio *bio)
{
	bio->bi_bdev = era->origin_dev->bdev;
}

/*----------------------------------------------------------------
 * Worker thread
 *--------------------------------------------------------------*/
static void wake_worker(struct era *era)
{
	queue_work(era->wq, &era->worker);
}

static void process_deferred_bios(struct era *era)
{
	int r;
	unsigned long flags;
	struct bio_list deferred_bios, marked_bios;
	struct bio *bio;
	bool commit_needed = false;
	bool failed = false;

	bio_list_init(&deferred_bios);
	bio_list_init(&marked_bios);

	spin_lock_irqsave(&era->deferred_lock, flags);
	bio_list_merge(&deferred_bios, &era->deferred_bios);
	bio_list_init(&era->deferred_bios);
	spin_unlock_irqrestore(&era->deferred_lock, flags);

	while ((bio = bio_list_pop(&deferred_bios))) {
		r = metadata_mark(era->md, get_block(era, bio));
		if (r) {
			/*
			 * This is bad news, we need to rollback.
			 */
			// FIXME: finish
			failed = true;
		}

		bio_list_add(&marked_bios, bio);
		commit_needed = true;
	}

	if (commit_needed) {
		r = metadata_commit(era->md);
		if (r)
			failed = true;
	}

	if (failed) {
		while ((bio = bio_list_pop(&marked_bios)))
			bio_io_error(bio);
	} else {
		while ((bio = bio_list_pop(&marked_bios)))
			generic_make_request(bio);
	}
}

static void process_rpc_calls(struct era *era)
{
	int r;
	bool need_commit = false;
	struct list_head calls;
	struct rpc *rpc, *tmp;

	INIT_LIST_HEAD(&calls);
	spin_lock(&era->rpc_lock);
	list_splice_init(&era->rpc_calls, &calls);
	spin_unlock(&era->rpc_lock);

	list_for_each_entry_safe (rpc, tmp, &calls, list) {
		rpc->result = rpc->fn0 ? rpc->fn0(era->md) : rpc->fn1(era->md, rpc->arg);
		need_commit = true;
	}

	if (need_commit) {
		r = metadata_commit(era->md);
		if (r)
			list_for_each_entry_safe (rpc, tmp, &calls, list)
				rpc->result = r;
	}

	list_for_each_entry_safe (rpc, tmp, &calls, list) {
		atomic_set(&rpc->complete, 1);
		wake_up(&rpc->wait);
	}
}

static void do_work(struct work_struct *ws)
{
	struct era *era = container_of(ws, struct era, worker);
	process_deferred_bios(era);
	process_rpc_calls(era);
}

static void defer_bio(struct era *era, struct bio *bio)
{
	spin_lock(&era->deferred_lock);
	bio_list_add(&era->deferred_bios, bio);
	spin_unlock(&era->deferred_lock);

	wake_worker(era);
}

/*
 * Make an rpc call to the worker to change the metadata.
 */
static int perform_rpc(struct era *era, struct rpc *rpc)
{
	rpc->result = 0;
	init_waitqueue_head(&rpc->wait);
	atomic_set(&rpc->complete, 0);

	spin_lock(&era->rpc_lock);
	list_add(&rpc->list, &era->rpc_calls);
	spin_unlock(&era->rpc_lock);

	wake_worker(era);
	wait_event(rpc->wait, atomic_read(&rpc->complete));

	return rpc->result;
}

static int in_worker0(struct era *era, int (*fn)(struct era_metadata *))
{
	struct rpc rpc;
	rpc.fn0 = fn;
	rpc.fn1 = NULL;

	return perform_rpc(era, &rpc);
}

static int in_worker1(struct era *era, int (*fn)(struct era_metadata *, void *), void *arg)
{
	struct rpc rpc;
	rpc.fn0 = NULL;
	rpc.fn1 = fn;
	rpc.arg = arg;

	return perform_rpc(era, &rpc);
}

/*
 * This assumes no more wake-worker calls are going to be made (a safe
 * assumption if we're in post suspend).
 */
static void stop_worker(struct era *era)
{
	/*
	 * FIXME: we kick off an expensive, synchronous digest here.  It
	 * should really run with low priority all the time.
	 */
	in_worker0(era, metadata_digest);
	flush_workqueue(era->wq);
}

/*----------------------------------------------------------------
 * Target methods
 *--------------------------------------------------------------*/
static int dev_is_congested(struct dm_dev *dev, int bdi_bits)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);
	return bdi_congested(&q->backing_dev_info, bdi_bits);
}

static int era_is_congested(struct dm_target_callbacks *cb, int bdi_bits)
{
	struct era *era = container_of(cb, struct era, callbacks);
	return dev_is_congested(era->origin_dev, bdi_bits);
}

static void era_destroy(struct era *era)
{
	metadata_close(era->md);

	if (era->wq)
		destroy_workqueue(era->wq);

	if (era->origin_dev)
		dm_put_device(era->ti, era->origin_dev);

	if (era->metadata_dev)
		dm_put_device(era->ti, era->metadata_dev);

	kfree(era);
}

static dm_block_t calc_nr_blocks(struct era *era)
{
	return dm_sector_div_up(era->ti->len, era->block_size);
}

/*
 * <metadata dev> <data dev> <data block size (sectors)>
 */
static int era_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	int r;
	char dummy;
	struct era *era;
	struct era_metadata *md;

	if (argc != 3) {
		ti->error = "Invalid argument count";
		return -EINVAL;
	}

	era = kzalloc(sizeof(*era), GFP_KERNEL);
	if (!era) {
		ti->error = "Error allocating era structure";
		return -ENOMEM;
	}

	era->ti = ti;

	r = dm_get_device(ti, argv[0], FMODE_READ | FMODE_WRITE, &era->metadata_dev);
	if (r) {
		ti->error = "Error opening metadata device";
		era_destroy(era);
		return -EINVAL;
	}

	r = dm_get_device(ti, argv[1], FMODE_READ | FMODE_WRITE, &era->origin_dev);
	if (r) {
		ti->error = "Error opening data device";
		era_destroy(era);
		return -EINVAL;
	}

	r = sscanf(argv[2], "%u%c", &era->block_size, &dummy);
	if (r != 1) {
		ti->error = "Error parsing block size";
		era_destroy(era);
		return -EINVAL;
	}
	era->sectors_per_block_shift = __ffs(era->block_size);

	r = dm_set_target_max_io_len(ti, era->block_size);
	if (r) {
		ti->error = "could not set max io len";
		era_destroy(era);
		return -EINVAL;
	}

	md = metadata_open(era->metadata_dev->bdev, era->block_size, true);
	if (IS_ERR(md)) {
		ti->error = "Error reading metadata";
		era_destroy(era);
		return PTR_ERR(md);
	}
	era->md = md;

	era->nr_blocks = calc_nr_blocks(era);

	r = metadata_resize(era->md, &era->nr_blocks);
	if (r){
		ti->error = "couldn't resize metadata";
		era_destroy(era);
		return -ENOMEM;
	}

	era->wq = alloc_ordered_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!era->wq) {
		ti->error = "could not create workqueue for metadata object";
		era_destroy(era);
		return -ENOMEM;
	}
	INIT_WORK(&era->worker, do_work);

	spin_lock_init(&era->deferred_lock);
	bio_list_init(&era->deferred_bios);

	spin_lock_init(&era->rpc_lock);
	INIT_LIST_HEAD(&era->rpc_calls);

	ti->private = era;
	ti->num_flush_bios = 1;
	ti->flush_supported = true;

	ti->num_discard_bios = 1;
	ti->discards_supported = true;
	era->callbacks.congested_fn = era_is_congested;
	dm_table_add_target_callbacks(ti->table, &era->callbacks);

	return 0;
}

static void era_dtr(struct dm_target *ti)
{
	era_destroy(ti->private);
}

static int era_map(struct dm_target *ti, struct bio *bio)
{
	struct era *era = ti->private;
	dm_block_t block = get_block(era, bio);

	/*
	 * All bios get remapped to the origin device.  We do this now, but
	 * it may not get issued until later.  Depending on whether the
	 * block is marked in this era.
	 */
	remap_to_origin(era, bio);

	if (bio_data_dir(bio) == WRITE &&
	    !metadata_current_marked(era->md, block)) {
		defer_bio(era, bio);
		return DM_MAPIO_SUBMITTED;
	}

	return DM_MAPIO_REMAPPED;
}

static void era_postsuspend(struct dm_target *ti)
{
	int r;
	struct era *era = ti->private;

	r = in_worker0(era, metadata_era_archive);
	if (r) {
		DMERR("%s: couldn't archive current era", __func__);
		// FIXME fail mode ?
	}

	stop_worker(era);
}

static int era_preresume(struct dm_target *ti)
{
	int r;
	struct era *era = ti->private;
	dm_block_t new_size = calc_nr_blocks(era);

	if (era->nr_blocks != new_size) {
		r = in_worker1(era, metadata_resize, &new_size);
		if (r)
			return r;

		era->nr_blocks = new_size;
	}

	r = in_worker0(era, metadata_new_era);
	if (r) {
		DMERR("%s: metadata_era_rollover failed", __func__);
		return r;
	}

	return 0;
}

/*
 * Status format:
 *
 * <current era> <metadata snap root|->
 * FIXME: need to show metadata free space
 */
static void era_status(struct dm_target *ti, status_type_t type,
		       unsigned status_flags, char *result, unsigned maxlen)
{
	struct era *era = ti->private;
	ssize_t sz = 0;
	dm_block_t snap;
	char buf[BDEVNAME_SIZE];

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%u", (unsigned) metadata_current_era(era->md));

		snap = metadata_snap_root(era->md);
		if (snap != SUPERBLOCK_LOCATION)
			DMEMIT(" %llu", snap);
		else
			DMEMIT(" -");
		break;

	case STATUSTYPE_TABLE:
		format_dev_t(buf, era->metadata_dev->bdev->bd_dev);
		DMEMIT("%s ", buf);
		format_dev_t(buf, era->origin_dev->bdev->bd_dev);
		DMEMIT("%s %u", buf, era->block_size);
		break;
	}

	return;
}

static int era_message(struct dm_target *ti, unsigned argc, char **argv)
{
	struct era *era = ti->private;

	if (argc != 1) {
		DMERR("incorrect number of message arguments");
		return -EINVAL;
	}

	if (!strcasecmp(argv[0], "checkpoint"))
		return in_worker0(era, metadata_checkpoint);

	if (!strcasecmp(argv[0], "take_metadata_snap"))
		return in_worker0(era, metadata_take_snap);

	if (!strcasecmp(argv[0], "drop_metadata_snap"))
		return in_worker0(era, metadata_drop_snap);

	DMERR("unsupported message '%s'", argv[0]);
	return -EINVAL;
}

static sector_t get_dev_size(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

static int era_iterate_devices(struct dm_target *ti,
			       iterate_devices_callout_fn fn, void *data)
{
	struct era *era = ti->private;
	return fn(ti, era->origin_dev, 0, get_dev_size(era->origin_dev), data);
}

static int era_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
		     struct bio_vec *biovec, int max_size)
{
	struct era *era = ti->private;
	struct request_queue *q = bdev_get_queue(era->origin_dev->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	bvm->bi_bdev = era->origin_dev->bdev;

	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
}

static void era_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct era *era = ti->private;
	uint64_t io_opt_sectors = limits->io_opt >> SECTOR_SHIFT;

	/*
	 * If the system-determined stacked limits are compatible with the
	 * cache's blocksize (io_opt is a factor) do not override them.
	 */
	if (io_opt_sectors < era->block_size ||
	    do_div(io_opt_sectors, era->block_size)) {
		blk_limits_io_min(limits, 0);
		blk_limits_io_opt(limits, era->block_size << SECTOR_SHIFT);
	}
}

/*----------------------------------------------------------------*/

static struct target_type era_target = {
	.name = "era",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = era_ctr,
	.dtr = era_dtr,
	.map = era_map,
	.postsuspend = era_postsuspend,
	.preresume = era_preresume,
	.status = era_status,
	.message = era_message,
	.iterate_devices = era_iterate_devices,
	.merge = era_merge,
	.io_hints = era_io_hints
};

static int __init dm_era_init(void)
{
	int r;

	r = dm_register_target(&era_target);
	if (r) {
		DMERR("era target registration failed: %d", r);
		return r;
	}

	return 0;
}

static void __exit dm_era_exit(void)
{
	dm_unregister_target(&era_target);
}

module_init(dm_era_init);
module_exit(dm_era_exit);

MODULE_DESCRIPTION(DM_NAME " era target");
MODULE_AUTHOR("Joe Thornber <ejt@redhat.com>");
MODULE_LICENSE("GPL");

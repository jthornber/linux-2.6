obj-$(CONFIG_DM_PERSISTENT_DATA) += dm-persistent-data.o
dm-persistent-data-objs := \
	dm-block-manager.o \
	dm-space-map-core.o \
	dm-space-map-disk.o \
	dm-space-map-metadata.o \
	dm-transaction-manager.o \
	dm-btree.o \
	dm-btree-remove.o \
	dm-btree-spine.o

obj-$(CONFIG_DM_PERSISTENT_DATA_BM_TESTS) += block-manager-test.o
obj-$(CONFIG_DM_PERSISTENT_DATA_TM_TESTS) += transaction-manager-test.o
obj-$(CONFIG_DM_PERSISTENT_DATA_BTREE_TESTS) += btree-test.o
obj-$(CONFIG_DM_PERSISTENT_DATA_SPACE_MAP_TESTS) += space-map-test.o

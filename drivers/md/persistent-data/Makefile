obj-$(CONFIG_DM_PERSISTENT_DATA) += persistent-data.o
persistent-data-objs := \
	block-manager.o \
	pd-module.o \
	space-map-core.o \
	space-map-disk.o \
	space-map-staged.o \
	space-map-dummy.o \
	transaction-manager.o \
	btree.o \
	btree-spine.o

obj-$(CONFIG_DM_BLOCK_MANAGER_TEST) += \
	block-manager-test.o

obj-$(CONFIG_DM_SPACE_MAP_TEST) += \
	space-map-test.o

obj-$(CONFIG_DM_TRANSACTION_MANAGER_TEST) += \
	transaction-manager-test.o

obj-$(CONFIG_DM_BTREE_TEST) += \
	btree-test.o

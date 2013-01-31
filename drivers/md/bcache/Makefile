
obj-$(CONFIG_BCACHE)	+= bcache.o

bcache-y		:= alloc.o btree.o bset.o io.o journal.o writeback.o\
	movinggc.o request.o super.o sysfs.o debug.o util.o trace.o stats.o closure.o

CFLAGS_alloc.o		+= -std=gnu99
CFLAGS_btree.o		+= -std=gnu99
CFLAGS_bset.o		+= -std=gnu99
CFLAGS_journal.o	+= -std=gnu99
CFLAGS_movinggc.o	+= -std=gnu99
CFLAGS_request.o	+= -std=gnu99 -Iblock
CFLAGS_super.o		+= -std=gnu99
CFLAGS_debug.o		+= -std=gnu99

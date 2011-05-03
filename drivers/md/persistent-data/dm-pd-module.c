#include <linux/init.h>
#include <linux/module.h>

static int dm_persistent_data_init(void)
{
	return 0;
}

static void dm_persistent_data_exit(void)
{
}

module_init(dm_persistent_data_init);
module_exit(dm_persistent_data_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joe Thornber");
MODULE_DESCRIPTION("Immutable metadata library for dm");

#include <linux/init.h>
#include <linux/module.h>

static int persistent_data_init(void)
{
	return 0;
}

static void persistent_data_exit(void)
{
}

module_init(persistent_data_init);
module_exit(persistent_data_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joe Thornber");
MODULE_DESCRIPTION("Immutable metadata library for dm");

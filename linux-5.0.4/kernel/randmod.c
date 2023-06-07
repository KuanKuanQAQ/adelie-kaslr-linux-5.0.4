#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <linux/slab.h>

#define STAT_PRINT_PERIOD 5 /* seconds */
#define MAX_MODULES	10

static struct module *module_mod[MAX_MODULES] = {NULL};
static char *module_names[MAX_MODULES] = {NULL};
static int modules_num = 0;
module_param_array(module_names, charp, &modules_num, 0000);
MODULE_PARM_DESC(module_names, "Name(s) of module(s) to re-randomize");

static int manual_unmap = false;
module_param(manual_unmap, int, 0);
MODULE_PARM_DESC(manual_unmap, "Unmap old memory after relocation?");

static int randomize_stack = true;
module_param(randomize_stack, int, 0);
MODULE_PARM_DESC(randomize_stack, "Re-Randomize Stack?");

static int rand_period = 20;
module_param(rand_period, int, 0);
MODULE_PARM_DESC(rand_period, "Randomization Period in ms");

static struct workqueue_struct *my_wq = NULL;

typedef struct {
    struct delayed_work my_work;
    void *address;
} UnmapWork;

static void delayed_unmap_cb(struct work_struct *work)
{
    UnmapWork *my_work = (UnmapWork *)work;

	printk("Manual Memory Freed %lx\n", (unsigned long) my_work->address);
	unmap_module(my_work->address, 0, 0);

	kfree( (void *)work );
}

int delayed_unmap(void *address, int delay)
{
	UnmapWork *work = kzalloc(sizeof(*work), GFP_KERNEL);
	if(!work)
		return -1;

	work->address = address;
	INIT_DELAYED_WORK((struct delayed_work *)work, delayed_unmap_cb);
	queue_delayed_work(my_wq, (struct delayed_work *)work, msecs_to_jiffies(delay));
	
	return 0;
}

static int find_modules(int num, char **names, struct module **mods)
{
	int i;
	int err = 0;

	for(i=0; i<num; i++) {
		struct module *mod = find_module(names[i]);
		if (mod == NULL || !is_randomizable_module(mod)) {
			err++;
			mods[i] = NULL;
		} else {
			mods[i] = mod;
		}
	}

	return err;
}

int randomize(struct module *mod)
{
	void *oldAddr, *newAddr;

	oldAddr = mod->core_layout.base;

	newAddr = module_rerandomize(mod);
	if(newAddr == NULL || newAddr != mod->core_layout.base)
		return -1;

	if(manual_unmap){
		delayed_unmap(oldAddr, manual_unmap);
	}

	return 0;
}


static struct task_struct *kthread = NULL;
int work_func(void *args)
{
	int ret, i;
	unsigned long min = 1000LU * rand_period;
	unsigned long max = min + 500;
	time64_t time = ktime_get_seconds();

	printk("Randomize: kthread started\n");
	do{
#ifdef CONFIG_X86_MODULE_RERANDOMIZE_STACK
		if(randomize_stack)
			module_rerandomize_stack();
#endif

		for (i=0; i<modules_num; i++) {
			ret = randomize(module_mod[i]);
			if(ret) break;
		}

		if(ret) {
			pr_err("Error Randomizing\n");
			break;
		} else {
			profile_rand.count_rand++;
		}

		if(rand_period == 0)
			break;

		if(rand_period > 20) {
			msleep(rand_period);
		} else {
			usleep_range(min, max);
		}

		/* Periodically print the statistics */
		if (time < ktime_get_seconds()) {
			time = ktime_get_seconds() + STAT_PRINT_PERIOD;
			print_profile_rand();
		}
	}while(!kthread_should_stop());

	printk("Randomize: kthread stopped\n");
	print_profile_rand();
	kthread = NULL;

	return 0;
}


int init_module(void){
	int err, i;

	init_profile_rand();

	printk("Module Name(s): ");
	for (i=0; i<modules_num; i++) {
		printk(KERN_CONT "%s ", module_names[i]);
	}
	printk("Stack Randomization: %d\n", randomize_stack);
	printk("Period: %d\n", rand_period);
	printk("Manual Unmap: %d\n", manual_unmap);

	if (modules_num == 0) {
		pr_err("No module specified\n");
		return -1;
	}

	err = find_modules(modules_num, module_names, module_mod);

	if (err) {
		printk("ERROR Following modules not found or can't be randomized: \n");
		for (i=0; i<modules_num; i++) {
			if (module_mod[i] == NULL)
				printk(KERN_CONT "%s ", module_names[i]);
		}
		pr_err("Stopping\n");
		return -1;
	}

	/* Init WorkQueue */
	if(manual_unmap){
		my_wq = create_workqueue("unmap_queue");
	
		if(!my_wq){
			pr_err("Could not create workqueue\n");
			return -1;
		}
	}

	/* Start worker kthread */
	kthread = kthread_run(work_func, NULL, "randomizer");
	if(kthread == ERR_PTR(-ENOMEM)){
		pr_err("Could not run kthread\n");
		return -1;
	}

	return 0;
}

void cleanup_module(void){
	if(kthread){
		kthread_stop(kthread);
	}

	if(manual_unmap){
		/* allow delayed unmap */
		mdelay(manual_unmap);
		mdelay(500);

		if(my_wq){
			flush_workqueue( my_wq );
			destroy_workqueue( my_wq );
		}
	}
}

MODULE_AUTHOR("Hassan Nadeem <hnadeem@vt.edu>");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("0.1");

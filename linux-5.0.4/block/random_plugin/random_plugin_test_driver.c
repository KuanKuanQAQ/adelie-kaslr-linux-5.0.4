#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/pci.h>

MODULE_INFO(randomizable, "Y");

// 变量
//SPECIAL_VAR(int* global_data_pointer);
int* global_data_pointer;
int global_data = 11; // 数据段的数据

// 函数指针
void (*global_function_pointer)(void);

/* -----------本地栈指针随机化，执行过程中栈不释放，所以不会有问题 --------- */
void local_random_data_pointer_call(int * local_pointer) {
    // 等待执行随机化
    mdelay(10000);
    printk("%s %d local_pinter value: %lx local_pointer_addr: %lx value: %d\n", 
        __FUNCTION__, __LINE__, local_pointer, &local_pointer, *local_pointer);
}
void local_random_data_pointer(void) {
    int local_data = 10;  // 栈中的数据
    int* local_pointer =  &local_data;

    // 通过栈传递指针，查看随机化后内容
    local_random_data_pointer_call(local_pointer);
}

/* -----------全局数据指针，是否被随机化，以及是否正确 --------- */
extern int kswapd_run(int nid);
void global_random_data_pointer(void) {
    global_data_pointer = &global_data;

    // 等待随机化然后查看内容
    int num = 10;
    int i = num;
    while(i--) {
        mdelay(2000);
        printk("%s %d global data value: %lx addr %lx\n", 
            __FUNCTION__, __LINE__, global_data, &global_data);
        printk("%s %d global data pointer value: %lx addr %lx, value %d\n", 
            __FUNCTION__, __LINE__, global_data_pointer, &global_data_pointer, *global_data_pointer);
    }
}

/* ----------- 本地函数指针，执行过程中代码段不释放，所以不会有问题 --------*/

void random_function(void) {
    printk("%s %d random function addr:%lx\n", __FUNCTION__, __LINE__, &random_function);
}

void local_random_function_pointer_call(void (*func)(void)) {
    func();
}

void local_random_function_pointer(void) {
    printk("start local_random_function_pointer_call");
    void (*local_function_pointer)(void) = &random_function;
    mdelay(2000);
    local_random_function_pointer_call(local_function_pointer);
}

/* ----------- 全局函数指针，执行过程中代码段不释放，所以不会有问题 --------*/
// 全局函数指针，在随机化的时候，并发调用会有什么问题
void global_random_function_pointer(void) {
    // 对全局变量赋值
    printk("start global_random_function_pointer_call");
    global_function_pointer = &random_function;
    int i = 1;
    while(i--) {
        mdelay(2000);
        global_function_pointer();
        printk("%s %d global function pointer value: %lx addr %lx\n", __FUNCTION__, __LINE__, global_function_pointer, &global_function_pointer);
    }
}

void init_entry(void) {
    printk("**************** init_entry ******************");
    local_random_data_pointer();
    global_random_data_pointer();

    local_random_function_pointer();
    global_random_function_pointer();
    printk("***************** init_entry end *****************");
}

void check_entry(void) {
    // 检查全局变量
    printk("**************** check_entry ******************");
    mdelay(10000);
    printk("%s %d global data pointer addr %lx global_data addr %lx\n", 
        __FUNCTION__, __LINE__,  &global_data_pointer, &global_data);
    printk("%s %d global data pointer value: %lx\n", 
        __FUNCTION__, __LINE__, global_data_pointer);
    printk("%s %d global data pointer point value %d\n", 
        __FUNCTION__, __LINE__,*global_data_pointer);

    // 执行global_function_pointer, 查看其随机化的位置以及是否正确
    global_function_pointer();
    printk("**************** check_entry end ******************");
}

struct Rerandom_Driver rerandom_plugin_driver_struct = {
};

extern void register_rerandom_driver(struct Rerandom_Driver* driver);
static int __init random_plugin_test_driver_init(void) {
    rerandom_plugin_driver_struct.name = "rerandom_plugin_test";
    rerandom_plugin_driver_struct.init_entry = &init_entry;
    rerandom_plugin_driver_struct.check_entry = &check_entry;

    register_rerandom_driver(&rerandom_plugin_driver_struct);
    return 0;
}
module_init(random_plugin_test_driver_init);

static void __exit random_plugin_test_driver_exit(void) {
    rerandom_plugin_driver_struct.name = "rerandom_plugin_test";
    rerandom_plugin_driver_struct.init_entry = &init_entry;
    rerandom_plugin_driver_struct.check_entry = &check_entry;
    return;
}
module_exit(random_plugin_test_driver_exit);
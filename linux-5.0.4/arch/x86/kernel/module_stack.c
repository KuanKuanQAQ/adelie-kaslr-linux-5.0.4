#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/moduleloader.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/kasan.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/random.h>

#include "../../../kernel/smr/lfsmr.h"


#ifdef CONFIG_X86_MODULE_RERANDOMIZE
#ifdef CONFIG_X86_MODULE_RERANDOMIZE_STACK
#define MODULE_STACK_SIZE	(THREAD_SIZE)
#define NUM_STACKS_PER_CPU	5

struct stack_node {
	struct stack_node *next;
	u64 ver;
	u8 _stack[MODULE_STACK_SIZE - 8]; /* -8 is for stack alignment */
	u64 stack[0];
} __packed;

struct stack_head {
	struct stack_node *head;
	union {
		struct {
			u64 size:8;
			u64 ver:8;
			u64 aba:48;
		};
		u64 stamp;
	};
} __aligned(16);

static DEFINE_PER_CPU(struct stack_head, module_cpu_stack);
static DEFINE_PER_CPU(struct stack_head, module_stack_trash);

static struct stack_head __my_load(struct stack_head *head_ptr, memory_order order)
{
	lfatomic_big_t temp = __lfaba_load((_Atomic(lfatomic_big_t) *)head_ptr, order);

	return *((struct stack_head *)&temp);
}

static bool __my_cmpxchg(struct stack_head *obj, struct stack_head *expected, struct stack_head desired, memory_order succ, memory_order fail)
{
	_Atomic(lfatomic_big_t) *_obj = (_Atomic(lfatomic_big_t) *) obj;
	lfatomic_big_t *_expected = (lfatomic_big_t *) expected;
	lfatomic_big_t _desired = *((lfatomic_big_t *)&desired);

	return __lfaba_cmpxchg_weak(_obj, _expected, _desired, succ, fail);
}


static int module_push_stack(struct stack_node *node, struct stack_head *head_ptr, bool verify_ver)
{
	struct stack_head new_head, head = __my_load(head_ptr, memory_order_acquire);

	do {
		if(verify_ver && node->ver != head.ver)
			return -1;

		node->next = head.head;
		new_head = (struct stack_head) {
				.head = node,
				.aba = head.aba + 1,
				.size = head.size + 1,
				.ver = head.ver,
			};
	} while (!__my_cmpxchg(head_ptr, &head, new_head, memory_order_acq_rel, memory_order_acquire));

	return 0;
}

static struct stack_node * module_pop_stack(struct stack_head *head_ptr)
{
	struct stack_node *node;
	struct stack_head new_head, head = __my_load(head_ptr, memory_order_acquire);

	do {
		node = head.head;
		if(node == NULL) return NULL;
		node->ver = head.ver;
		new_head = (struct stack_head) {
				.head = node->next,
				.aba = head.aba + 1,
				.size = head.size - 1,
				.ver = head.ver,
			};
	} while (!__my_cmpxchg(head_ptr, &head, new_head, memory_order_acq_rel, memory_order_acquire));

	return node;
}

static void module_push_stack_this_cpu(struct stack_node *node)
{
	struct stack_head *head_ptr = this_cpu_ptr(&module_cpu_stack);
	if (module_push_stack(node, head_ptr, true)) {
		module_push_stack(node, this_cpu_ptr(&module_stack_trash), false);
		// printk("Stack Trashed\n");
	}
}

static struct stack_node * module_pop_stack_this_cpu(void)
{
	struct stack_head *head_ptr = this_cpu_ptr(&module_cpu_stack);
	return module_pop_stack(head_ptr);
}


static struct stack_node * module_alloc_stack_node(void)
{
	struct stack_node *node = kmalloc(sizeof(*node), GFP_ATOMIC);
	u64 stack_addr = (u64)node->stack;

	if(node == NULL) {
		pr_err("Out of memory\n");
		BUG();
	}else if(stack_addr+8 != ALIGN(stack_addr, 16)) {
		printp(stack_addr);
		pr_err("Stack not alligned properly\n");
	}

	profile_rand.count_stack_alloc++;

	return node;
}

static void module_free_stack_node(struct stack_node *node)
{
	// printk("Stack Freed\n");
	kfree(node);
	profile_rand.count_stack_free++;
}

static void populate_stacks(struct stack_head *head_ptr)
{
	int i;
	struct stack_node *node;

	for(i=0; i<NUM_STACKS_PER_CPU; i++) {
		node = module_alloc_stack_node();
		module_push_stack(node, head_ptr, false);
	}
}

void module_stack_empty_trash(void)
{
	int cpu;
	struct stack_head *head_ptr;
	struct stack_node *node;

	for_each_possible_cpu(cpu) {
		head_ptr = per_cpu_ptr(&module_stack_trash, cpu);
	
		do {
			node = module_pop_stack(head_ptr);
			if(node) {
				module_free_stack_node(node);
			}
		} while(node);
	}
}
EXPORT_SYMBOL_GPL(module_stack_empty_trash);

void module_init_stacks(void)
{
	module_rerandomize_stack();
}

void module_rerandomize_stack(void)
{
	int cpu;
	struct stack_head head, new_head;
	struct stack_head *head_ptr;
	struct stack_node *node;

	for_each_possible_cpu(cpu) {
		new_head = (struct stack_head) {
				.head = NULL,
				.stamp = 0,
		};
		populate_stacks(&new_head);
		head_ptr = per_cpu_ptr(&module_cpu_stack, cpu);
		head = __my_load(head_ptr, memory_order_acquire);

		do {
			new_head.aba = head.aba + 1;
			new_head.ver = head.ver + 1;
		} while (!__my_cmpxchg(head_ptr, &head, new_head, memory_order_acq_rel, memory_order_acquire));

		/* Empty old stacks into trash */
		do {
			node = module_pop_stack(&head);
			if(node) {
				module_push_stack(node, per_cpu_ptr(&module_stack_trash, cpu), false);
			}
		} while(node);
	}
}
EXPORT_SYMBOL_GPL(module_rerandomize_stack);

/*
// Helper functions for debugging
static void* getsp(void)
{
    void *sp;
    asm( "mov %%rsp, %0" : "=rm" ( sp ));
    return sp;
}

void __attribute__((naked)) fuck_with_registers(void){
    asm ("mov $0xDEADBAADDEADBAAD, %rax");
    asm ("mov $0xDEADBAADDEADBAAD, %rdi");
    asm ("mov $0xDEADBAADDEADBAAD, %rsi");
    asm ("mov $0xDEADBAADDEADBAAD, %rdx");
    asm ("mov $0xDEADBAADDEADBAAD, %rcx");
    asm ("mov $0xDEADBAADDEADBAAD, %r8");
    asm ("mov $0xDEADBAADDEADBAAD, %r9");
    asm ("mov $0xDEADBAADDEADBAAD, %r10");
    asm ("mov $0xDEADBAADDEADBAAD, %r11");
    asm ("ret");
}
*/

void module_offer_stack(void *stack)
{
	struct stack_node *node = container_of(stack, struct stack_node, stack);

	module_push_stack_this_cpu(node);
}
EXPORT_SYMBOL_GPL(module_offer_stack);

void *module_get_stack(void)
{
	struct stack_node *node;

	node = module_pop_stack_this_cpu();

	if(node == NULL) {
		/* Just a warning. May cause performance penalty
		if stack is allocated in wrappers too frequently */
		pr_err_once("Dynamic Stack Allocation Warning!!!\n");
		node = module_alloc_stack_node();
	}

	return node->stack;
}
EXPORT_SYMBOL_GPL(module_get_stack);
#endif
#endif

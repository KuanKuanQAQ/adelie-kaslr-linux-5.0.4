/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MODULE_H
#define _ASM_X86_MODULE_H

#include <asm-generic/module.h>
#include <asm/orc_types.h>
#include <asm/asm.h>
#include <smr/smr.h>

#ifdef CONFIG_X86_MODULE_RERANDOMIZE

void init_profile_rand(void);
void print_profile_rand(void);
struct Profile_Rand {
	u64 count_rand;
	u64 count_smr_retire;
	u64 count_smr_free;
	u64 count_stack_alloc;
	u64 count_stack_free;
};
extern struct Profile_Rand profile_rand;

void *module_rerandomize(struct module *mod);
void module_unmap(struct module *mod, void *addr);

#ifdef CONFIG_X86_MODULE_RERANDOMIZE_STACK
void module_init_stacks(void);
void module_rerandomize_stack(void);
void module_stack_empty_trash(void);
void * module_get_stack(void);
void module_offer_stack(void *);
#endif /* CONFIG_X86_MODULE_RERANDOMIZE_STACK */

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define printp(x) printk("(%s.%03d): " #x " = 0x%lx\n", __FILENAME__, __LINE__, (unsigned long)(x))
#define INC_BY_DELTA(x, delta) ( x = (typeof((x))) ((unsigned long)(x) + (unsigned long)(delta)) )


/* Places the variable in a special section
 * Makes visibility default */
#define SPECIAL_VAR(x) x __attribute__ ((section (".fixed.data")))
#define SPECIAL_CONST_VAR(x) x __attribute__ ((section (".fixed.rodata")))


#define SPECIAL_FUNCTION_PROTO(ret, name, args...)  \
	noinline ret __attribute__ ((section (".fixed.text"))) __attribute__((naked)) name(args)

#ifdef CONFIG_X86_MODULE_RERANDOMIZE_STACK
#define MOD_GET_STACK()                                 \
	asm (_ASM_CALL(module_get_stack));              \
	asm ("mov %rax, %rsp")
#define MOD_OFFER_STACK()                               \
	asm ("mov %rsp, %rdi");                         \
	asm ("lea -0x40(%rbp), %rsp")
#define MOD_OFFER_STACK_CALL()                          \
	asm (_ASM_CALL(module_offer_stack))
#else
#define MOD_GET_STACK()
#define MOD_OFFER_STACK()
#define MOD_OFFER_STACK_CALL()
#endif

#define SPECIAL_FUNCTION(ret, name, args...) \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wreturn-type\"") \
_Pragma("GCC diagnostic ignored \"-Wattributes\"") \
ret __attribute__ ((visibility("hidden"))) name## _ ##real(args);\
SPECIAL_FUNCTION_PROTO(ret, name, args) {               \
	/* Save base pointer */                         \
	asm ("push %rbp");                              \
	asm ("mov %rsp, %rbp");                         \
	/* Save Args */                                 \
	asm ("push %rdi");                              \
	asm ("push %rsi");                              \
	asm ("push %rdx");                              \
	asm ("push %rcx");                              \
	asm ("push %r8");                               \
	asm ("push %r9");                               \
	/* Call smr_enter save return */                \
	asm (_ASM_CALL(smr_enter));                     \
	asm ("push %rax");                              \
	asm ("push %rdx");                              \
	/* Get new stack */                             \
	MOD_GET_STACK();                                \
	/* Restore Args*/                               \
	asm ("mov -0x30(%rbp), %r9");                   \
	asm ("mov -0x28(%rbp), %r8");                   \
	asm ("mov -0x20(%rbp), %rcx");                  \
	asm ("mov -0x18(%rbp), %rdx");                  \
	asm ("mov -0x10(%rbp), %rsi");                  \
	asm ("mov -0x8(%rbp), %rdi");                   \
	asm (_ASM_CALL(name## _ ##real));               \
	/* Restore old stack */                         \
	MOD_OFFER_STACK();                              \
	asm ("mov %rax, %rbp");                         \
	MOD_OFFER_STACK_CALL();                         \
	/* Prepare smr_leave args */                    \
	asm ("pop %rsi");                               \
	asm ("pop %rdi");                               \
	asm ("add $48, %rsp");				\
	asm (_ASM_CALL(smr_leave));                     \
	asm ("mov %rbp, %rax");                         \
	/* Restore base pointer */                      \
	asm ("pop %rbp");                               \
	asm ("ret");                                    \
} \
_Pragma("GCC diagnostic pop") \
ret name## _ ##real(args)
#else /* !CONFIG_X86_MODULE_RERANDOMIZE */
#define SPECIAL_VAR(x) x
#define SPECIAL_CONST_VAR(x) x
#define SPECIAL_FUNCTION_PROTO(ret, name, args...) ret name (args)
#define SPECIAL_FUNCTION(ret, name, args...) ret name (args)
#endif /* CONFIG_X86_MODULE_RERANDOMIZE */

extern const char __THUNK_FOR_PLT[];
extern const unsigned int __THUNK_FOR_PLT_SIZE;

#define PLT_ENTRY_ALIGNMENT	16
struct plt_entry {
#ifdef CONFIG_RETPOLINE
	u8 mov_ins[3];
	u32 rel_addr;
	u8 thunk[0];
#else
	u16 jmp_ins;
	u32 rel_addr;
#endif
} __packed __aligned(PLT_ENTRY_ALIGNMENT);

struct mod_sec {
	struct elf64_shdr	*got;
	struct elf64_shdr	*plt;
	int			got_num_entries;
	int			got_max_entries;
	int			plt_num_entries;
	int			plt_max_entries;
};

struct mod_arch_specific {
#ifdef CONFIG_UNWINDER_ORC
	unsigned int num_orcs;
	int *orc_unwind_ip;
	struct orc_entry *orc_unwind;
#endif
	struct mod_sec	core;
	struct mod_sec	rand;
	struct mod_sec	fixed;
	struct mod_sec	fixed_rand;
};

#ifdef CONFIG_X86_64
/* X86_64 does not define MODULE_PROC_FAMILY */
#elif defined CONFIG_M486
#define MODULE_PROC_FAMILY "486 "
#elif defined CONFIG_M586
#define MODULE_PROC_FAMILY "586 "
#elif defined CONFIG_M586TSC
#define MODULE_PROC_FAMILY "586TSC "
#elif defined CONFIG_M586MMX
#define MODULE_PROC_FAMILY "586MMX "
#elif defined CONFIG_MCORE2
#define MODULE_PROC_FAMILY "CORE2 "
#elif defined CONFIG_MATOM
#define MODULE_PROC_FAMILY "ATOM "
#elif defined CONFIG_M686
#define MODULE_PROC_FAMILY "686 "
#elif defined CONFIG_MPENTIUMII
#define MODULE_PROC_FAMILY "PENTIUMII "
#elif defined CONFIG_MPENTIUMIII
#define MODULE_PROC_FAMILY "PENTIUMIII "
#elif defined CONFIG_MPENTIUMM
#define MODULE_PROC_FAMILY "PENTIUMM "
#elif defined CONFIG_MPENTIUM4
#define MODULE_PROC_FAMILY "PENTIUM4 "
#elif defined CONFIG_MK6
#define MODULE_PROC_FAMILY "K6 "
#elif defined CONFIG_MK7
#define MODULE_PROC_FAMILY "K7 "
#elif defined CONFIG_MK8
#define MODULE_PROC_FAMILY "K8 "
#elif defined CONFIG_MELAN
#define MODULE_PROC_FAMILY "ELAN "
#elif defined CONFIG_MCRUSOE
#define MODULE_PROC_FAMILY "CRUSOE "
#elif defined CONFIG_MEFFICEON
#define MODULE_PROC_FAMILY "EFFICEON "
#elif defined CONFIG_MWINCHIPC6
#define MODULE_PROC_FAMILY "WINCHIPC6 "
#elif defined CONFIG_MWINCHIP3D
#define MODULE_PROC_FAMILY "WINCHIP3D "
#elif defined CONFIG_MCYRIXIII
#define MODULE_PROC_FAMILY "CYRIXIII "
#elif defined CONFIG_MVIAC3_2
#define MODULE_PROC_FAMILY "VIAC3-2 "
#elif defined CONFIG_MVIAC7
#define MODULE_PROC_FAMILY "VIAC7 "
#elif defined CONFIG_MGEODEGX1
#define MODULE_PROC_FAMILY "GEODEGX1 "
#elif defined CONFIG_MGEODE_LX
#define MODULE_PROC_FAMILY "GEODE "
#else
#error unknown processor family
#endif

#ifdef CONFIG_X86_32
# define MODULE_ARCH_VERMAGIC MODULE_PROC_FAMILY
#endif

#endif /* _ASM_X86_MODULE_H */

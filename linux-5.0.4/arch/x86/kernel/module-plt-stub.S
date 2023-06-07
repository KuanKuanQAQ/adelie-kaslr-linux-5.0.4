/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/stringify.h>
#include <linux/linkage.h>
#include <asm/dwarf2.h>
#include <asm/cpufeatures.h>
#include <asm/alternative-asm.h>
#include <asm/export.h>
#include <asm/nospec-branch.h>

/* The following code is used for PLT generation only
   and should never be executed directly. */
.section .rodata
.globl __THUNK_FOR_PLT
.globl __THUNK_FOR_PLT_SIZE
__THUNK_FOR_PLT:
#ifdef CONFIG_RETPOLINE
	movq 0(%rip), %rax
	JMP_NOSPEC %rax
#else
	jmpq   *0(%rip)
#endif
__THUNK_FOR_PLT_SIZE: .long . - __THUNK_FOR_PLT

/*  Kernel module help for x86.
    Copyright (C) 2001 Rusty Russell.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/moduleloader.h>
#include <linux/elf.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/kasan.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/jump_label.h>
#include <linux/random.h>
#include <linux/sort.h>

#include <asm/text-patching.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/setup.h>
#include <asm/unwind.h>
#include <asm/insn.h>
#include "../../../kernel/smr/lfsmr.h"

struct Profile_Rand profile_rand;
EXPORT_SYMBOL(profile_rand);

void init_profile_rand(void)
{
	memset(&profile_rand, 0, sizeof(profile_rand));
}
EXPORT_SYMBOL(init_profile_rand);

void print_profile_rand(void)
{
	printk("-----\n");
	printk("Randomized %llu times\n", profile_rand.count_rand);

	printk("SMR Retire: %llu\n", profile_rand.count_smr_retire);
	printk("SMR Free: %llu\n", profile_rand.count_smr_free);
	printk("SMR Delta: %llu\n", profile_rand.count_smr_retire - profile_rand.count_smr_free);

	printk("Stack Alloc: %llu\n", profile_rand.count_stack_alloc);
	printk("Stack Free: %llu\n", profile_rand.count_stack_free);
	printk("Stack Delta: %llu\n", profile_rand.count_stack_alloc - profile_rand.count_stack_free);
}
EXPORT_SYMBOL(print_profile_rand);

static unsigned int module_plt_size;

static int apply_relocate_add__(Elf64_Shdr *sechdrs,
		   const char *strtab,
		   unsigned int symindex,
		   unsigned int relsec,
		   struct module *me,
		   bool check);

#if 0
#define DEBUGP(fmt, ...)				\
	printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#else
#define DEBUGP(fmt, ...)				\
do {							\
	if (0)						\
		printk(KERN_DEBUG fmt, ##__VA_ARGS__);	\
} while (0)
#endif

#ifdef CONFIG_RANDOMIZE_BASE
static unsigned long module_load_offset;

/* Mutex protects the module_load_offset. */
static DEFINE_MUTEX(module_kaslr_mutex);

static unsigned long int get_module_load_offset(void)
{
	if (kaslr_enabled()) {
		mutex_lock(&module_kaslr_mutex);
		/*
		 * Recalculate the module_load_offset only when
		 * rerandomization is enabled.
		 */
#ifndef CONFIG_X86_MODULE_RERANDOMIZE
		if (module_load_offset == 0)
#endif
			module_load_offset =
				(get_random_int() % 1024 + 1) * PAGE_SIZE;
		mutex_unlock(&module_kaslr_mutex);
	}
	return module_load_offset;
}
#else
static unsigned long int get_module_load_offset(void)
{
	return 0;
}
#endif

#ifdef CONFIG_X86_PIE
static u64 find_got_kernel_entry(Elf64_Sym *sym, const Elf64_Rela *rela)
{
	u64 *pos;

	for (pos = (u64 *)__start_got; pos < (u64 *)__end_got; pos++) {
		if (*pos == sym->st_value)
			return (u64)pos + rela->r_addend;
	}

	return 0;
}
#else
static u64 find_got_kernel_entry(Elf64_Sym *sym, const Elf64_Rela *rela)
{
	return 0;
}
#endif

static inline bool is_local_symbol(Elf64_Sym *sym)
{
	return sym->st_shndx != SHN_UNDEF;
}

#ifdef CONFIG_X86_MODULE_RERANDOMIZE
static void module_print_addresses(struct module *mod);

static char *module_get_section_name(struct module *mod, unsigned int shnum)
{
	if (shnum == SHN_UNDEF || shnum > mod->klp_info->hdr.e_shnum)
		return "";

	return mod->klp_info->secstrings +
				mod->klp_info->sechdrs[shnum].sh_name;
}

bool module_is_fixed_section_name(const char *sname){
	return (strstarts(sname, ".fixed")
			|| strstarts(sname, ".gnu.linkonce.this_module")
			|| strstarts(sname, "__param")
//			|| strstarts(sname, ".rodata")
			|| strstarts(sname, ".data.rel.ro")
		);
}

bool module_is_fixed_section(struct module *mod, unsigned int shnum)
{
	char *sname;

	if (!is_randomizable_module(mod))
		return false;

	if (shnum == SHN_UNDEF || shnum > mod->klp_info->hdr.e_shnum)
		return true;

	sname = mod->klp_info->secstrings +
				mod->klp_info->sechdrs[shnum].sh_name;

	return module_is_fixed_section_name(sname);
}

static inline bool is_rand_symbol(struct module *mod, Elf64_Sym *sym)
{
	if (!is_randomizable_module(mod) || !is_local_symbol(sym))
		return false;

	return !module_is_fixed_section(mod, sym->st_shndx);
}

static unsigned int nullify_relocations_rel(unsigned int relsec, struct module *mod)
{
	unsigned int i;
	Elf_Shdr *sechdrs = mod->klp_info->sechdrs;
	Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr;
	unsigned int symindex = mod->klp_info->symndx;
	unsigned int symsec;
	bool isSecFixed = module_is_fixed_section(mod, mod->klp_info->sechdrs[relsec].sh_info);
	bool isSymFixed;
	Elf64_Sym *sym;
	int relocations_removed = 0;
	char *sname = module_get_section_name(mod, relsec);

	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		sym = (Elf64_Sym *)sechdrs[symindex].sh_addr
			+ ELF64_R_SYM(rel[i].r_info);
		symsec = sym->st_shndx;
		isSymFixed = module_is_fixed_section(mod, symsec);

		switch (ELF64_R_TYPE(rel[i].r_info)) {
		case R_X86_64_64:
			if (isSymFixed)
				goto remove_relocation;
			else
				break;
		case R_X86_64_PC64:
		case R_X86_64_PC32:
			if (isSecFixed ^ isSymFixed) {
				/* In different sections */
				pr_err("Found un-randomizable PCxx relocation in %s, type %d, symbol num %d\n",
						sname, (int)ELF64_R_TYPE(rel[i].r_info), (int)ELF64_R_SYM(rel[i].r_info));
				break;
			}
		case R_X86_64_REX_GOTPCRELX:
		case R_X86_64_GOTPCRELX:
		case R_X86_64_GOTPCREL:
		case R_X86_64_PLT32:
		case R_X86_64_NONE:
remove_relocation:
			relocations_removed++;
			rel[i].r_info = 0;
			break;
		}
	}

	return relocations_removed;
}

/* Remove relocation that are not needed in the
 * re-randomization process */
static void nullify_relocations(struct module *mod)
{
	unsigned int i, infosec;
	char *sname;

	printk("%s: nullify_relocations\n", mod->name);

	for (i = 1; i < mod->klp_info->hdr.e_shnum; i++) {
		if(mod->klp_info->sechdrs[i].sh_type != SHT_RELA)
			continue;

		infosec = mod->klp_info->sechdrs[i].sh_info;
		sname = module_get_section_name(mod, i);

		/* Not a valid relocation section */
		if (infosec >= mod->klp_info->hdr.e_shnum
			  /* init sections are not used anymore */
			  || strstarts(sname, ".rela.init")
			  || strstarts(sname, ".rela.altinstructions")
			  /* Livepatch relocation sections are applied by livepatch */
			  || mod->klp_info->sechdrs[i].sh_flags & SHF_RELA_LIVEPATCH
			  /* Don't bother with non-allocated sections */
			  || !(mod->klp_info->sechdrs[infosec].sh_flags & SHF_ALLOC)) {
			printk("%s nullified\n", sname);
			mod->klp_info->sechdrs[i].sh_type = SHT_NULL;
		} else {
			unsigned int total_relocations =
					mod->klp_info->sechdrs[i].sh_size / sizeof(Elf64_Rela);
			unsigned int relocations_removed =
					nullify_relocations_rel(i, mod);
			if (total_relocations == relocations_removed) {
				printk("%s nullified\n", sname);
				mod->klp_info->sechdrs[i].sh_type = SHT_NULL;
			} else {
				printk("%s relocations removed = %d/%d\n", sname, relocations_removed, total_relocations);
			}
		}

	}
}

int module_arch_preinit(struct module *mod)
{
	Elf_Shdr *sechdrs;
	char *secstrings;
	unsigned int i;

	if (!is_randomizable_module(mod)) return 0;

	sechdrs = mod->klp_info->sechdrs;
	secstrings = mod->klp_info->secstrings;

	mod->arch.rand.got = mod->arch.fixed.got = mod->arch.fixed_rand.got = NULL;
	mod->arch.rand.plt = mod->arch.fixed.plt = mod->arch.fixed_rand.plt = NULL;

	/* Find GOTs and PLTs */
	for (i = 0; i < mod->klp_info->hdr.e_shnum; i++) {
		if (!strcmp(secstrings + sechdrs[i].sh_name, ".got.rand")) {
			mod->arch.rand.got = sechdrs + i;
		} else if (!strcmp(secstrings + sechdrs[i].sh_name, ".fixed.got")) {
			mod->arch.fixed.got = sechdrs + i;
		} else if (!strcmp(secstrings + sechdrs[i].sh_name, ".fixed.got.rand")) {
			mod->arch.fixed_rand.got = sechdrs + i;
		} else if (!strcmp(secstrings + sechdrs[i].sh_name, ".plt.rand")) {
			mod->arch.rand.plt = sechdrs + i;
		} else if (!strcmp(secstrings + sechdrs[i].sh_name, ".fixed.plt")) {
			mod->arch.fixed.plt = sechdrs + i;
		} else if (!strcmp(secstrings + sechdrs[i].sh_name, ".fixed.plt.rand")) {
			mod->arch.fixed_rand.plt = sechdrs + i;
		}
	}

	if (!mod->arch.rand.got || !mod->arch.fixed.got || !mod->arch.fixed_rand.got || !mod->arch.fixed.plt || !mod->arch.fixed_rand.plt || !mod->arch.rand.plt)
		return -ENOEXEC;

	module_disable_ro(mod);
	nullify_relocations(mod);
	module_enable_ro(mod, false);

	/* TODO: Remove */
//	module_print_addresses(mod);

	return 0;
}

static void module_reapply_relocations(struct module *mod, unsigned long delta)
{
	unsigned int i;

	for (i = 1; i < mod->klp_info->hdr.e_shnum; i++) {
		if(mod->klp_info->sechdrs[i].sh_type != SHT_RELA)
			continue;

		apply_relocate_add__(mod->klp_info->sechdrs, mod->kallsyms->strtab,
			mod->klp_info->symndx, i, mod, false);
	}
}

/* Update all randomized symbols in the symbol table. */
static void module_update_symbols(struct module *mod, unsigned long delta)
{
	unsigned int i;
	Elf64_Shdr *sym_sechdr = mod->klp_info->sechdrs + mod->klp_info->symndx;
	Elf64_Sym *syms = (Elf64_Sym *)sym_sechdr->sh_addr;
	unsigned int num_syms = sym_sechdr->sh_size / sizeof(*syms);

	for (i = 0; i < num_syms; i++) {
		if (is_rand_symbol(mod, &syms[i])) {
//			printk("  i=%u, sec=%u\n", i, syms[i].st_shndx);
			INC_BY_DELTA(syms[i].st_value, delta);
		}
	}
}

/* Update all symbols in GOT
 * GOT should only contain randomized symbols */
static void module_update_got(struct module *mod, struct mod_sec *gotsec,
		unsigned long delta, unsigned long table_delta)
{
	unsigned int i;
	u64 *got_new = (u64*)gotsec->got->sh_addr;
	u64 *got_old = (u64*)(gotsec->got->sh_addr - table_delta);

	for(i=0; i < gotsec->got_num_entries; i++){
		got_new[i] = got_old[i] + delta;
	}
}

static void module_print_addresses(struct module *mod)
{
	unsigned int i;

	printk("core_layout.base  = 0x%lx | 0x%x\n",
			(unsigned long)mod->core_layout.base, mod->core_layout.size);
	printk("fixed_layout.base = 0x%lx | 0x%x\n",
			(unsigned long)mod->fixed_layout.base,mod->fixed_layout.size);
	printk("init_layout.base  = 0x%lx | 0x%x\n",
			(unsigned long)mod->init_layout.base, mod->init_layout.size);

	for (i = 1; i < mod->klp_info->hdr.e_shnum; i++) {
		printk("%s\t= 0x%llx | 0x%llx\n", mod->klp_info->secstrings +
				mod->klp_info->sechdrs[i].sh_name, mod->klp_info->sechdrs[i].sh_addr,
				mod->klp_info->sechdrs[i].sh_size);
	}
}

//#define printp(x) printk("%d." #x " = 0x%lx\n", __LINE__, (unsigned long)x)

void *module_newmap(struct module *mod, void *addr, unsigned long size)
{
	void *new_addr;
	struct mod_sec *gotsec = &mod->arch.rand;
	unsigned long got_addr = gotsec->got->sh_addr;
	unsigned long got_size = gotsec->got->sh_size;

//	printp(addr);
//	printp(got_addr);
//	printp(size);
//	printp(got_size);

	got_size = 0; // todo: remove
	new_addr = remap_module((unsigned long)addr, size, got_addr, got_size,
				    MODULE_ALIGN,
				    MODULES_VADDR + get_module_load_offset(),
				    MODULES_END, GFP_KERNEL,
				    PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
				    __builtin_return_address(0));

//	new_addr = module_alloc(size);
//	memcpy(new_addr, addr, size);

	return new_addr;
}

void module_unmap(struct module *mod, void *addr)
{
	struct mod_sec *gotsec = &mod->arch.rand;
	void *got_addr = gotsec->got->sh_addr -
			(unsigned long) mod->core_layout.base + addr;
	unsigned long got_size = gotsec->got->sh_size;

	// printk("Memory Freed %lx\n", (unsigned long) addr);

	got_size = 0; // todo: remove
	unmap_module(addr, got_addr, got_size);
//	vfree(addr);
}

void *module_rerandomize(struct module *mod)
{
	unsigned long delta;
	void *new_addr;
	unsigned long size = mod->core_layout.size;
	void *addr = mod->core_layout.base;

	if(!is_randomizable_module(mod)) return NULL;

	new_addr = module_newmap(mod, addr, size);
	if(new_addr == NULL) {
		return NULL;
	}

	// Clear permission of old address space
	module_disable_ro(mod);
	module_disable_nx(mod);

	delta = (unsigned long) (new_addr - addr);
//	printk("delta = %ld = %lu = 0x%lx\n", delta, delta, delta);

	// Update kernel's pointer to this module
	update_module_ref(mod, delta);

	// Set permission of new address space
	module_enable_nx(mod);

//	module_print_addresses(mod);

	module_disable_ro(mod);
	module_update_symbols(mod, delta);
	module_update_got(mod, &mod->arch.rand, delta, delta);
	module_reapply_relocations(mod, delta);
	module_update_got(mod, &mod->arch.fixed_rand, delta, 0);
	module_enable_ro(mod, true);

	if (mod->rerandomize)
		mod->rerandomize(delta);

	smr_retire(mod, addr);

	return new_addr;
}
EXPORT_SYMBOL_GPL(module_rerandomize);

#else /* !CONFIG_X86_MODULE_RERANDOMIZE */
static inline bool is_rand_symbol(struct module *mod, Elf64_Sym *sym)
{
	return false;
}
#endif

static struct mod_sec * find_mod_sec(struct module *mod, unsigned int infosec,
		const Elf64_Rela *rela, Elf64_Sym *sym)
{
	struct mod_sec *sec = NULL;
	bool fixed = module_is_fixed_section(mod, infosec);

	if (is_rand_symbol(mod, sym)) {
		sec = fixed ? &mod->arch.fixed_rand : &mod->arch.rand;
	} else {
		sec = fixed ? &mod->arch.fixed : &mod->arch.core;
	}

	return sec;
}

static u64 module_emit_got_entry(struct module *mod, void *loc,
		unsigned int infosec, const Elf64_Rela *rela, Elf64_Sym *sym)
{
	struct mod_sec *gotsec = find_mod_sec(mod, infosec, rela, sym);
	u64 *got = (u64 *)gotsec->got->sh_addr;
	int i = gotsec->got_num_entries;
	u64 ret;

	/* Check if we can use the kernel GOT */
	ret = find_got_kernel_entry(sym, rela);
	if (ret)
		return ret;

	got[i] = sym->st_value;

	/*
	 * Check if the entry we just created is a duplicate. Given that the
	 * relocations are sorted, this will be the last entry we allocated.
	 * (if one exists).
	 */
	if (i > 0 && got[i] == got[i - 1]) {
		ret = (u64)&got[i - 1];
	} else {
		gotsec->got_num_entries++;
		BUG_ON(gotsec->got_num_entries > gotsec->got_max_entries);
		ret = (u64)&got[i];
	}

	return ret;
}

static bool plt_entries_equal(const struct plt_entry *a,
				     const struct plt_entry *b)
{
	void *a_val, *b_val;

	a_val = (void *)a + (s64)a->rel_addr;
	b_val = (void *)b + (s64)b->rel_addr;

	return a_val == b_val;
}

static void get_plt_entry(struct plt_entry *plt_entry,
		struct module *mod, void *loc, unsigned int infosec,
		const Elf64_Rela *rela, Elf64_Sym *sym)
{
	u64 abs_val = module_emit_got_entry(mod, loc, infosec, rela, sym);
	u32 rel_val = abs_val - (u64)&plt_entry->rel_addr
			- sizeof(plt_entry->rel_addr);

	memcpy(plt_entry, __THUNK_FOR_PLT, __THUNK_FOR_PLT_SIZE);
	plt_entry->rel_addr = rel_val;
}

static u64 module_emit_plt_entry(struct module *mod, void *loc,
		unsigned int infosec, const Elf64_Rela *rela, Elf64_Sym *sym)
{
	struct mod_sec *pltsec = find_mod_sec(mod, infosec, rela, sym);
	int i = pltsec->plt_num_entries;
	void *plt = (void *)pltsec->plt->sh_addr + (u64)i * module_plt_size;
	get_plt_entry(plt, mod, loc, infosec, rela, sym);

	/*
	 * Check if the entry we just created is a duplicate. Given that the
	 * relocations are sorted, this will be the last entry we allocated.
	 * (if one exists).
	 */
	if (i > 0 && plt_entries_equal(plt, plt - module_plt_size))
		return (u64)(plt - module_plt_size);

	pltsec->plt_num_entries++;
	BUG_ON(pltsec->plt_num_entries > pltsec->plt_max_entries);

	return (u64)plt;
}

#define cmp_3way(a, b)	((a) < (b) ? -1 : (a) > (b))

static int cmp_rela(const void *a, const void *b)
{
	const Elf64_Rela *x = a, *y = b;
	int i;

	/* sort by type, symbol index and addend */
	i = cmp_3way(ELF64_R_TYPE(x->r_info), ELF64_R_TYPE(y->r_info));
	if (i == 0)
		i = cmp_3way(ELF64_R_SYM(x->r_info), ELF64_R_SYM(y->r_info));
	if (i == 0)
		i = cmp_3way(x->r_addend, y->r_addend);
	return i;
}

static bool duplicate_rel(const Elf64_Rela *rela, int num)
{
	/*
	 * Entries are sorted by type, symbol index and addend. That means
	 * that, if a duplicate entry exists, it must be in the preceding
	 * slot.
	 */
	return num > 0 && cmp_rela(rela + num, rela + num - 1) == 0;
}

struct GOT_PLT_Count {
	unsigned long got;
	unsigned long got_rand;
	unsigned long fixed_got;
	unsigned long fixed_got_rand;
	unsigned long plt;
	unsigned long plt_rand;
	unsigned long fixed_plt;
	unsigned long fixed_plt_rand;
};

static void count_gots_plts(struct GOT_PLT_Count *counter,
		Elf64_Sym *syms, Elf64_Rela *rela, int num,
		bool fixed, struct module *mod)
{
	Elf64_Sym *s;
	int i;

	for (i = 0; i < num; i++) {
		switch (ELF64_R_TYPE(rela[i].r_info)) {
		case R_X86_64_PLT32:
		case R_X86_64_REX_GOTPCRELX:
		case R_X86_64_GOTPCRELX:
		case R_X86_64_GOTPCREL:
			s = syms + ELF64_R_SYM(rela[i].r_info);

			/*
			 * Use the kernel GOT when possible, else reserve a
			 * custom one for this module.
			 */
			if (!duplicate_rel(rela, i) &&
			    !find_got_kernel_entry(s, rela + i)) {
				if (is_rand_symbol(mod, s)) {
					if (fixed)
						counter->fixed_got_rand++;
					else
						counter->got_rand++;
				} else {
					if (fixed)
						counter->fixed_got++;
					else
						counter->got++;
				}

				if (ELF64_R_TYPE(rela[i].r_info) ==
				    R_X86_64_PLT32) {
					if (is_rand_symbol(mod, s)) {
						if (fixed)
							counter->fixed_plt_rand++;
						else
							counter->plt_rand++;
					} else {
						if (fixed)
							counter->fixed_plt++;
						else
							counter->plt++;
					}
				}
			}
			break;
		}
	}
}


/*
 * call *foo@GOTPCREL(%rip) ---> call foo nop
 * jmp *foo@GOTPCREL(%rip)  ---> jmp foo nop
 */
static int do_relax_GOTPCRELX(Elf64_Rela *rel, void *loc)
{
	struct insn insn;
	void *ins_addr = loc - 2;

	kernel_insn_init(&insn, ins_addr, MAX_INSN_SIZE);
	insn_get_length(&insn);

	/* 1 byte for opcode, 1 byte for modrm, 4 bytes for m32 */
	if (insn.length != 6 || insn.opcode.value != 0xFF)
		return -1;

	switch (insn.modrm.value) {
	case 0x15: /* CALL */
		*(u8 *)ins_addr = 0xe8;
		break;
	case 0x25: /* JMP */
		*(u8 *)ins_addr = 0xe9;
		break;
	default:
		return -1;
	}
	memset(ins_addr + 1, 0, 4);
	*((u8 *)ins_addr + 5) = 0x90; /* NOP */

	/* Update the relocation */
	rel->r_info &= ~ELF64_R_TYPE(~0LU);
	rel->r_info |= R_X86_64_PC32;
	rel->r_offset--;

	return 0;
}


/*
 * mov foo@GOTPCREL(%rip), %reg ---> lea foo(%rip), %reg
 * */
static int do_relax_REX_GOTPCRELX(Elf64_Rela *rel, void *loc)
{
	struct insn insn;
	void *ins_addr = loc - 3;

	kernel_insn_init(&insn, ins_addr, MAX_INSN_SIZE);
	insn_get_length(&insn);

	/* 1 byte for REX, 1 byte for opcode, 1 byte for modrm,
	 * 4 bytes for m32.
	 */
	if (insn.length != 7)
		return -1;

	/* Not the MOV instruction, could be ADD, SUB etc. */
	if (insn.opcode.value != 0x8b)
		return 0;
	*((u8 *)ins_addr + 1) = 0x8d; /* LEA */

	/* Update the relocation. */
	rel->r_info &= ~ELF64_R_TYPE(~0LU);
	rel->r_info |= R_X86_64_PC32;

	return 0;
}

static int apply_relaxations(Elf_Ehdr *ehdr, Elf_Shdr *sechdrs,
			     struct module *mod)
{
	Elf64_Sym *syms = NULL;
	int i, j;

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (sechdrs[i].sh_type == SHT_SYMTAB)
			syms = (Elf64_Sym *)sechdrs[i].sh_addr;
	}

	if (!syms) {
		pr_err("%s: module symtab section missing\n", mod->name);
		return -ENOEXEC;
	}

	for (i = 0; i < ehdr->e_shnum; i++) {
		Elf64_Rela *rels = (void *)ehdr + sechdrs[i].sh_offset;
		bool isSecFixed;

		if (sechdrs[i].sh_type != SHT_RELA)
			continue;

		isSecFixed = module_is_fixed_section(mod, sechdrs[i].sh_info);

		for (j = 0; j < sechdrs[i].sh_size / sizeof(*rels); j++) {
			Elf64_Rela *rel = &rels[j];
			Elf64_Sym *sym = &syms[ELF64_R_SYM(rel->r_info)];
			void *loc = (void *)sechdrs[sechdrs[i].sh_info].sh_addr
					+ rel->r_offset;
			bool isSymFixed = module_is_fixed_section(mod, sym->st_shndx);

			if (is_local_symbol(sym) && isSecFixed == isSymFixed) {
				switch (ELF64_R_TYPE(rel->r_info)) {
				case R_X86_64_GOTPCRELX:
					if (do_relax_GOTPCRELX(rel, loc))
						BUG();
					break;
				case R_X86_64_REX_GOTPCRELX:
					if (do_relax_REX_GOTPCRELX(rel, loc))
						BUG();
					break;
				case R_X86_64_PLT32:
					rel->r_info &= ~ELF64_R_TYPE(~0LU);
					rel->r_info |= R_X86_64_PC32;
					break;
				case R_X86_64_GOTPCREL:
					/* cannot be relaxed, ignore it */
					break;
				}
			}
		}
	}

	return 0;
}

static void init_got_sec_hdr(struct elf64_shdr *got, Elf64_Xword size)
{
	got->sh_type = SHT_NOBITS;
	got->sh_flags = SHF_ALLOC;
	got->sh_addralign = L1_CACHE_BYTES;
	got->sh_size = size;
}

static void init_plt_sec_hdr(struct elf64_shdr *plt, Elf64_Xword size)
{
	plt->sh_type = SHT_NOBITS;
	plt->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
	plt->sh_addralign = L1_CACHE_BYTES;
	plt->sh_size = size;
}

/*
 * Generate GOT entries for GOTPCREL relocations that do not exists in the
 * kernel GOT. Based on arm64 module-plts implementation.
 */
int module_frob_arch_sections(Elf_Ehdr *ehdr, Elf_Shdr *sechdrs,
			      char *secstrings, struct module *mod)
{
	struct GOT_PLT_Count counter;
	Elf_Shdr *symtab = NULL;
	Elf64_Sym *syms = NULL;
	char *strings, *name;
	int i, got_idx = -1;

	/* Init all members to zero */
	memset(&counter, 0, sizeof(counter));

	// TODO: allow for randomizable after testing
	//if (!is_randomizable_module(mod))
	apply_relaxations(ehdr, sechdrs, mod);

	/*
	 * Find the empty .got and .plt sections so we can expand it
	 * to store the GOT and PLT entries.
	 * Record the symtab address as well.
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(secstrings + sechdrs[i].sh_name, ".got")) {
			got_idx = i;
			mod->arch.core.got = sechdrs + i;
		} else if (!strcmp(secstrings + sechdrs[i].sh_name, ".got.rand")) {
			mod->arch.rand.got = sechdrs + i;
		} else if (!strcmp(secstrings + sechdrs[i].sh_name, ".fixed.got")) {
			mod->arch.fixed.got = sechdrs + i;
		} else if (!strcmp(secstrings + sechdrs[i].sh_name, ".fixed.got.rand")) {
			mod->arch.fixed_rand.got = sechdrs + i;
		} else if (!strcmp(secstrings + sechdrs[i].sh_name, ".plt")) {
			mod->arch.core.plt = sechdrs + i;
		} else if (!strcmp(secstrings + sechdrs[i].sh_name, ".plt.rand")) {
			mod->arch.rand.plt = sechdrs + i;
		} else if (!strcmp(secstrings + sechdrs[i].sh_name, ".fixed.plt")) {
			mod->arch.fixed.plt = sechdrs + i;
		} else if (!strcmp(secstrings + sechdrs[i].sh_name, ".fixed.plt.rand")) {
			mod->arch.fixed_rand.plt = sechdrs + i;
		} else if (sechdrs[i].sh_type == SHT_SYMTAB) {
			symtab = sechdrs + i;
			syms = (Elf64_Sym *)symtab->sh_addr;
		}
	}

	if (!mod->arch.core.got || !mod->arch.rand.got || !mod->arch.fixed.got || !mod->arch.fixed_rand.got) {
		pr_err("%s: module GOT section(s) missing\n", mod->name);
		return -ENOEXEC;
	}
	if (!mod->arch.core.plt || !mod->arch.rand.plt || !mod->arch.fixed.plt || !mod->arch.fixed_rand.plt) {
		pr_err("%s: module PLT section missing\n", mod->name);
		return -ENOEXEC;
	}
	if (!syms) {
		pr_err("%s: module symtab section missing\n", mod->name);
		return -ENOEXEC;
	}

	for (i = 0; i < ehdr->e_shnum; i++) {
		Elf64_Rela *rels = (void *)ehdr + sechdrs[i].sh_offset;
		int numrels = sechdrs[i].sh_size / sizeof(Elf64_Rela);
		unsigned int infosec = sechdrs[i].sh_info;

		if (sechdrs[i].sh_type != SHT_RELA)
			continue;

		/* sort by type, symbol index and addend */
		sort(rels, numrels, sizeof(Elf64_Rela), cmp_rela, NULL);

		count_gots_plts(&counter, syms, rels, numrels,
				module_is_fixed_section(mod, infosec), mod);
	}

	if (is_randomizable_module(mod)){
		printk("counter.got = %lu\n", counter.got);
		printk("counter.fixed_got = %lu\n", counter.fixed_got);
		printk("counter.got_rand = %lu\n", counter.got_rand);
		printk("counter.fixed_got_rand = %lu\n", counter.fixed_got_rand);
		printk("counter.plt = %lu\n", counter.plt);
		printk("counter.plt_rand = %lu\n", counter.plt_rand);
		printk("counter.fixed_plt = %lu\n", counter.fixed_plt);
		printk("counter.fixed_plt_rand = %lu\n", counter.fixed_plt_rand);
	}

	init_got_sec_hdr(mod->arch.core.got, (counter.got + 1) * sizeof(u64));
	mod->arch.core.got_num_entries = 0;
	mod->arch.core.got_max_entries = counter.got;

	init_got_sec_hdr(mod->arch.rand.got, (counter.got_rand + 1) * sizeof(u64));
	mod->arch.rand.got_num_entries = 0;
	mod->arch.rand.got_max_entries = counter.got_rand;

	init_got_sec_hdr(mod->arch.fixed.got, (counter.fixed_got + 1) * sizeof(u64));
	mod->arch.fixed.got_num_entries = 0;
	mod->arch.fixed.got_max_entries = counter.fixed_got;

	init_got_sec_hdr(mod->arch.fixed_rand.got, (counter.fixed_got_rand + 1) * sizeof(u64));
	mod->arch.fixed_rand.got_num_entries = 0;
	mod->arch.fixed_rand.got_max_entries = counter.fixed_got_rand;

#ifdef CONFIG_X86_MODULE_RERANDOMIZE
	mod->arch.rand.got->sh_size = PAGE_ALIGN(mod->arch.rand.got->sh_size);
	mod->arch.fixed_rand.got->sh_size = PAGE_ALIGN(mod->arch.fixed_rand.got->sh_size);
#endif

	module_plt_size = ALIGN(__THUNK_FOR_PLT_SIZE, PLT_ENTRY_ALIGNMENT);
	init_plt_sec_hdr(mod->arch.core.plt, (counter.plt + 1) * module_plt_size);
	mod->arch.core.plt_num_entries = 0;
	mod->arch.core.plt_max_entries = counter.plt;

	init_plt_sec_hdr(mod->arch.rand.plt, (counter.plt_rand + 1) * module_plt_size);
	mod->arch.rand.plt_num_entries = 0;
	mod->arch.rand.plt_max_entries = counter.plt_rand;

	init_plt_sec_hdr(mod->arch.fixed.plt, (counter.fixed_plt + 1) * module_plt_size);
	mod->arch.fixed.plt_num_entries = 0;
	mod->arch.fixed.plt_max_entries = counter.fixed_plt;

	init_plt_sec_hdr(mod->arch.fixed_rand.plt, (counter.fixed_plt_rand + 1) * module_plt_size);
	mod->arch.fixed_rand.plt_num_entries = 0;
	mod->arch.fixed_rand.plt_max_entries = counter.fixed_plt_rand;

	strings = (void *) ehdr + sechdrs[symtab->sh_link].sh_offset;
	for (i = 0; i < symtab->sh_size/sizeof(Elf_Sym); i++) {
		if (syms[i].st_shndx != SHN_UNDEF)
			continue;
		name = strings + syms[i].st_name;
		if (!strcmp(name, "_GLOBAL_OFFSET_TABLE_")) {
			syms[i].st_shndx = got_idx;
			break;
		}
	}
	return 0;
}

void *module_alloc(unsigned long size)
{
	void *p;

	if (PAGE_ALIGN(size) > MODULES_LEN)
		return NULL;

	p = __vmalloc_node_range(size, MODULE_ALIGN,
				    MODULES_VADDR + get_module_load_offset(),
				    MODULES_END, GFP_KERNEL,
				    PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
				    __builtin_return_address(0));
	if (p && (kasan_module_alloc(p, size) < 0)) {
		vfree(p);
		return NULL;
	}

	return p;
}

#ifdef CONFIG_X86_32
int apply_relocate(Elf32_Shdr *sechdrs,
		   const char *strtab,
		   unsigned int symindex,
		   unsigned int relsec,
		   struct module *me)
{
	unsigned int i;
	Elf32_Rel *rel = (void *)sechdrs[relsec].sh_addr;
	Elf32_Sym *sym;
	uint32_t *location;

	DEBUGP("Applying relocate section %u to %u\n",
	       relsec, sechdrs[relsec].sh_info);
	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* This is where to make the change */
		location = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr
			+ rel[i].r_offset;
		/* This is the symbol it is referring to.  Note that all
		   undefined symbols have been resolved.  */
		sym = (Elf32_Sym *)sechdrs[symindex].sh_addr
			+ ELF32_R_SYM(rel[i].r_info);

		switch (ELF32_R_TYPE(rel[i].r_info)) {
		case R_386_32:
			/* We add the value into the location given */
			*location += sym->st_value;
			break;
		case R_386_PC32:
			/* Add the value, subtract its position */
			*location += sym->st_value - (uint32_t)location;
			break;
		default:
			pr_err("%s: Unknown relocation: %u\n",
			       me->name, ELF32_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}
	}
	return 0;
}
#else /*X86_64*/

int check_relocation_pic_safe(Elf64_Rela *rel, Elf64_Sym *sym,
		   const char *strtab, struct module *mod)
{
	bool isLocalSym = is_local_symbol(sym);

	switch (ELF64_R_TYPE(rel->r_info)) {
	case R_X86_64_32:
	case R_X86_64_32S:
	case R_X86_64_PC32:
		if (!isLocalSym)
			goto fail;
		break;
	}

	return 0;

fail:
	pr_err("Non PIC Relocation in `%s', relocation type %d, symbol %s\n",
		mod->name, (int)ELF64_R_TYPE(rel->r_info), &strtab[sym->st_name]);
	return -1;
}

int apply_relocate_add(Elf64_Shdr *sechdrs,
		   const char *strtab,
		   unsigned int symindex,
		   unsigned int relsec,
		   struct module *me){
	return apply_relocate_add__(sechdrs, strtab, symindex, relsec, me, true);
}

static int apply_relocate_add__(Elf64_Shdr *sechdrs,
		   const char *strtab,
		   unsigned int symindex,
		   unsigned int relsec,
		   struct module *me,
		   bool check)
{
	unsigned int i;
	Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr;
	unsigned int infosec = sechdrs[relsec].sh_info;
	Elf64_Sym *sym;
	void *loc;
	u64 val;

	check = 0;

	DEBUGP("Applying relocate section %u to %u\n",
	       relsec, sechdrs[relsec].sh_info);
	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* This is where to make the change */
		loc = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr
			+ rel[i].r_offset;

		/* This is the symbol it is referring to.  Note that all
		   undefined symbols have been resolved.  */
		sym = (Elf64_Sym *)sechdrs[symindex].sh_addr
			+ ELF64_R_SYM(rel[i].r_info);

#ifdef CONFIG_X86_PIC
		if (check)
			BUG_ON(check_relocation_pic_safe(&rel[i], sym, strtab, me));
#endif

		DEBUGP("type %d st_value %Lx r_addend %Lx loc %Lx\n",
		       (int)ELF64_R_TYPE(rel[i].r_info),
		       sym->st_value, rel[i].r_addend, (u64)loc);

		val = sym->st_value + rel[i].r_addend;

		switch (ELF64_R_TYPE(rel[i].r_info)) {
		case R_X86_64_NONE:
			break;
		case R_X86_64_GOTOFF64:
			val -= me->arch.core.got->sh_addr;
			/* fallthrough */
		case R_X86_64_64:
			if (check && *(u64 *)loc != 0)
				goto invalid_relocation;
			*(u64 *)loc = val;
			break;
		case R_X86_64_32:
			if (check && *(u32 *)loc != 0)
				goto invalid_relocation;
			*(u32 *)loc = val;
			if (val != *(u32 *)loc)
				goto overflow;
			break;
		case R_X86_64_32S:
			if (check && *(s32 *)loc != 0)
				goto invalid_relocation;
			*(s32 *)loc = val;
			if ((s64)val != *(s32 *)loc)
				goto overflow;
			break;
		case R_X86_64_PLT32:
			val = module_emit_plt_entry(me, loc, infosec, rel + i,
			    sym) + rel[i].r_addend;
			goto pc32_reloc;
		case R_X86_64_REX_GOTPCRELX:
		case R_X86_64_GOTPCRELX:
		case R_X86_64_GOTPCREL:
			val = module_emit_got_entry(me, loc, infosec, rel + i,
			    sym) + rel[i].r_addend;
			/* fallthrough */
		case R_X86_64_GOTPC32:
			/* symbol = _GLOBAL_OFFSET_TABLE_ */
		case R_X86_64_PC32:
pc32_reloc:
			if (check && *(u32 *)loc != 0)
				goto invalid_relocation;
			val -= (u64)loc;
			*(u32 *)loc = val;
			if ((IS_ENABLED(CONFIG_X86_PIE) ||
				IS_ENABLED(CONFIG_X86_PIC)) &&
			    (s64)val != *(s32 *)loc)
				goto overflow;
			break;
		case R_X86_64_PC64:
			if (check && *(u64 *)loc != 0)
				goto invalid_relocation;
			val -= (u64)loc;
			*(u64 *)loc = val;
			break;
		default:
			pr_err("%s: Unknown rela relocation: %llu\n",
			       me->name, ELF64_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}
	}
	return 0;

invalid_relocation:
	pr_err("x86/modules: Skipping invalid relocation target, existing value is nonzero for type %d, loc %p, val %Lx\n",
	       (int)ELF64_R_TYPE(rel[i].r_info), loc, val);
	return -ENOEXEC;

overflow:
	pr_err("overflow in relocation type %d val %Lx\n",
	       (int)ELF64_R_TYPE(rel[i].r_info), val);
	pr_err("`%s' likely too far from the kernel\n", me->name);
	return -ENOEXEC;
}
#endif

int module_finalize(const Elf_Ehdr *hdr,
		    const Elf_Shdr *sechdrs,
		    struct module *me)
{
	const Elf_Shdr *s, *text = NULL, *alt = NULL, *locks = NULL,
		*para = NULL, *orc = NULL, *orc_ip = NULL;
	char *secstrings = (void *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;

	for (s = sechdrs; s < sechdrs + hdr->e_shnum; s++) {
		if (!strcmp(".text", secstrings + s->sh_name))
			text = s;
		if (!strcmp(".altinstructions", secstrings + s->sh_name))
			alt = s;
		if (!strcmp(".smp_locks", secstrings + s->sh_name))
			locks = s;
		if (!strcmp(".parainstructions", secstrings + s->sh_name))
			para = s;
		if (!strcmp(".orc_unwind", secstrings + s->sh_name))
			orc = s;
		if (!strcmp(".orc_unwind_ip", secstrings + s->sh_name))
			orc_ip = s;
	}

	if (alt) {
		/* patch .altinstructions */
		void *aseg = (void *)alt->sh_addr;
		apply_alternatives(aseg, aseg + alt->sh_size);
	}
	if (locks && text) {
		void *lseg = (void *)locks->sh_addr;
		void *tseg = (void *)text->sh_addr;
		alternatives_smp_module_add(me, me->name,
					    lseg, lseg + locks->sh_size,
					    tseg, tseg + text->sh_size);
	}

	if (para) {
		void *pseg = (void *)para->sh_addr;
		apply_paravirt(pseg, pseg + para->sh_size);
	}

	/* make jump label nops */
	jump_label_apply_nops(me);

	if (orc && orc_ip)
		unwind_module_init(me, (void *)orc_ip->sh_addr, orc_ip->sh_size,
				   (void *)orc->sh_addr, orc->sh_size);

	return 0;
}

void module_arch_cleanup(struct module *mod)
{
	alternatives_smp_module_del(mod);
}

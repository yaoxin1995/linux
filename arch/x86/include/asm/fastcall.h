// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_FASTCALL_H
#define _ASM_X86_FASTCALL_H
#include <asm/page_types.h>

#ifndef __ASSEMBLER__
#include <linux/mm_types.h>

#ifdef CONFIG_FASTCALL

#define NR_ENTRIES 50

#define HIDEN_REGION_FLAG (VM_READ | VM_MAYREAD | VM_MAYWRITE | VM_WRITE | VM_LOCKED | VM_IO)
#define FCE_REGION_FLAG  (VM_READ | VM_MAYREAD | VM_EXEC | VM_MAYEXEC)
#define EXECONLY_REGION_FLAG  (VM_EXEC | VM_MAYEXEC)

#define FASTCALL_GPF GFP_HIGHUSER

struct fastcall_entry {
    unsigned long fce_region_addr;
    unsigned long hidden_region_addr;
    unsigned long exect_region_addr;
	
};

struct fastcall_table {
	struct fastcall_entry entries[NR_ENTRIES];
    size_t entries_size;
	struct mutex mutex;
};

extern struct fastcall_table *fc_table;

extern unsigned long fce_regions_creation( struct page **, int , struct page **, int, unsigned long);
extern int hidden_region_creatrion(unsigned long, struct page **, int, unsigned long);
extern unsigned long get_randomized_address(unsigned long len);
#endif /* CONFIG_FASTCALL */
#endif /* __ASSEMBLER__ */
#endif /* _ASM_X86_FASTCALL_H */
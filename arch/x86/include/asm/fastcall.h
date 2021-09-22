// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_FASTCALL_H
#define _ASM_X86_FASTCALL_H
#include <asm/page_types.h>

#ifndef __ASSEMBLER__
#include <linux/mm_types.h>

#ifdef CONFIG_FASTCALL

#define NR_ENTRIES 50
#define NR_HIDDEN_REGION 10
#define MOV_SLOT_SIZE 15
#define MOV_SLOT_OFFSET 2


#define HIDEN_REGION_FLAG (VM_READ | VM_MAYREAD | VM_MAYWRITE | VM_WRITE | VM_LOCKED | VM_IO |VM_DONTCOPY)
#define FCE_REGION_FLAG  (VM_READ | VM_MAYREAD | VM_EXEC | VM_MAYEXEC | VM_DONTCOPY)
#define SECRET_REGION_FLAG  (VM_EXEC | VM_MAYEXEC|VM_DONTCOPY)

#define FASTCALL_GPF GFP_HIGHUSER

struct fastcall_entry {
    unsigned long fce_region_addr;
    unsigned long hidden_region_addrs[NR_HIDDEN_REGION];
    unsigned long secret_region_addr;
    int nr_hidden_region_current;
    int max_hidden_region;
	
};

struct fastcall_table {
	struct fastcall_entry entries[NR_ENTRIES];
    int entries_size;
	struct mutex mutex;
};

extern struct fastcall_table *fc_table;

extern const struct vm_special_mapping fastcall_hidden_pages_mapping;

extern const struct vm_special_mapping fastcall_pages_mapping;

extern unsigned long fce_regions_creation( struct page **, int , struct page **, int, unsigned long, int);
extern unsigned long hidden_region_creation(unsigned long, struct page **, int, struct page *);
extern struct fastcall_entry *find_entry(unsigned long);
extern int fsc_unregistration(unsigned long);

static inline bool in_fastcall_hidden_region(unsigned long start, size_t len)
{
	return start >= TASK_SIZE_MAX && start < HIDDEN_REGION_MAX &&
	       len <= HIDDEN_REGION_MAX - start;
}

#else

static inline bool in_fastcall_hidden_region(unsigned long start, size_t len)
{
	return false;
}
#endif /* CONFIG_FASTCALL */
#endif /* __ASSEMBLER__ */
#endif /* _ASM_X86_FASTCALL_H */
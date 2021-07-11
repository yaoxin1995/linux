// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_FASTCALL_H
#define _ASM_X86_FASTCALL_H
#include <asm/page_types.h>

#ifndef __ASSEMBLER__
#include <linux/mm_types.h>

#ifdef CONFIG_FASTCALL

extern int fastcall_register(unsigned long __user);
#endif /* CONFIG_FASTCALL */
#endif /* __ASSEMBLER__ */
#endif /* _ASM_X86_FASTCALL_H */
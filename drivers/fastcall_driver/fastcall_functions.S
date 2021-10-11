// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_functions.S - example fastcall functions
 *
 * They are mapped to user space and executed by the fastcall system call.
 */

#include <linux/linkage.h>
#include <asm/unwind_hints.h>
#include <asm/segment.h>
#include <asm/alternative-asm.h>
#include <asm/cpufeatures.h>
#include <asm-generic/errno-base.h>
#include <asm/smap.h>
#include <asm/fastcall.h>


.text
/*
 * fce_functions_start/_end - example fastcall entry function example
 *
 * They are mapped to fastcall call entry region and executed by the fastcall system call.
 */

SYM_INNER_LABEL(fce_region_start, SYM_L_GLOBAL)

SYM_FUNC_START(fce_function)

    # we can't use absolute address hier, since the absolute address is caculated at compile time--> we need relative jump just like jump in dynamic lib
    # lea sr_function(%rip), %rdi # get absolut address of secret_region_function
    jmp sr_function
SYM_INNER_LABEL(goto_fce_func_1, SYM_L_GLOBAL)
    # jmp goto_second_mov
SYM_INNER_LABEL(goto_fce_func_2, SYM_L_GLOBAL)
    # jmp goto_third_mov
SYM_INNER_LABEL(goto_fce_func_3, SYM_L_GLOBAL)
    # jmp goto_fourth_mov
SYM_INNER_LABEL(goto_fce_func_4, SYM_L_GLOBAL)    
    movq $2, %rax
    ret
SYM_FUNC_END(fce_function)

SYM_INNER_LABEL(fce_region_end, SYM_L_GLOBAL)

. = PAGE_SIZE

/*
 * secret_functions_start/_end - example secret function example
 *
 * They are mapped to secret region and called by the fastcall entry function.
 */

SYM_INNER_LABEL(secret_region_start, SYM_L_GLOBAL)
/*
* SYM_CODE_START is not normal c like function -> don't obey the c calling convention
*/  
SYM_CODE_START(sr_function)
    movq $0x7FFFFFFFFFFF, %rax
    jmp goto_fce_func_1
SYM_INNER_LABEL(goto_second_mov, SYM_L_GLOBAL)
    movq $0x7FFFFFFFFFFF, %rsi
    jmp goto_fce_func_2
SYM_INNER_LABEL(goto_third_mov, SYM_L_GLOBAL)
    movq $0x7FFFFFFFFFFF, %rcx
    jmp goto_fce_func_3
SYM_INNER_LABEL(goto_fourth_mov, SYM_L_GLOBAL)
    movq $0x7FFFFFFFFFFF, %rdx
    jmp goto_fce_func_4
SYM_CODE_END(sr_function)


SYM_INNER_LABEL(secret_region_end, SYM_L_GLOBAL)




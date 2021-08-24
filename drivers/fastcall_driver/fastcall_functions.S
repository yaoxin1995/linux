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
    movq $1, %rax
    # we can't use absolute address hier, since the absolute address is caculated at compile time--> we need relative jump just like jump in dynamic lib
    # lea sr_function(%rip), %rdi # get absolut address of secret_region_function
    jmp sr_function
SYM_INNER_LABEL(goto_fce_func, SYM_L_GLOBAL)
    cmpq  $10, %rdx
    je corret_result    # IF correctly jump back from sr_function return 1, otherwise return 2
    movq $2, %rax
    ret
corret_result:
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
    movq $0x7FFFFFFFFFFF, %rdx
    movq $0x7FFFFFFFFFFF, %rsi 
    movq $0x7FFFFFFFFFFF, %rcx
    movq $0x7FFFFFFFFFFF, %rdx
    movq $0x7FFFFFFFFFFF, %rdx
    movq $0x7FFFFFFFFFFF, %rdx
    movq $10, %rdx
    jmp goto_fce_func
SYM_CODE_END(sr_function)


SYM_INNER_LABEL(secret_region_end, SYM_L_GLOBAL)




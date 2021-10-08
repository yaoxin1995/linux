// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2006 Andi Kleen, SUSE Labs.
 *
 * Fast user context implementation of getcpu()
 */

#include <linux/kernel.h>
#include <linux/getcpu.h>
#include <linux/time.h>
#include <asm/vgtod.h>

notrace long __vdso_getcounter(long counter)
{

	return counter;
}

long getcounter(long counter)__attribute__((weak, alias("__vdso_getcounter")));



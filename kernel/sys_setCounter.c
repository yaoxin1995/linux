// SPDX-License-Identifier: GPL-2.0
/**
 * Syscall that simply returns the long input argument counter
 */
#include <linux/syscalls.h>

SYSCALL_DEFINE1(setCounter, long, counter)
{
	return counter;
}

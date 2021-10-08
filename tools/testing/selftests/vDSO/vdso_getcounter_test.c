// SPDX-License-Identifier: GPL-2.0-only
/*
 * vdso_test_getcpu.c: Sample code to test parse_vdso.c and vDSO getcpu()
 *
 * Copyright (c) 2020 Arm Ltd
 */

#include <stdint.h>
#include <elf.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <sys/time.h>

#include "../kselftest.h"
#include "parse_vdso.h"

const char *version = "LINUX_2.6";
const char *name = "__vdso_getcounter";

struct getcpu_cache;
typedef long (*getcounter_t)(long);
#define msg 729L

int main(int argc, char **argv)
{
	unsigned long sysinfo_ehdr;
	//unsigned int cpu, node;
	getcounter_t getcounter;
	long ret;

	sysinfo_ehdr = getauxval(AT_SYSINFO_EHDR);
	if (!sysinfo_ehdr) {
		printf("AT_SYSINFO_EHDR is not present!\n");
		return KSFT_SKIP;
	}

	vdso_init_from_sysinfo_ehdr(getauxval(AT_SYSINFO_EHDR));

	getcounter = (getcounter_t)vdso_sym(version, name);
	if (!getcounter) {
		printf("Could not find %s\n", name);
		return KSFT_SKIP;
	}

	ret = getcounter(msg);

	if (ret != msg) {
		printf("Expect: %ld, find:%ld\n", msg, ret);
        return KSFT_FAIL;
	}
	printf("test pass\n");

	return 0;
} 
// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>

#include <sys/fcntl.h> 
#include <sys/stat.h>
#include <sys/ioctl.h>      
#include <unistd.h>     
#include <stdio.h>
#include <stdlib.h>
#include "../kselftest_harness.h"

#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)

struct mesg {
		size_t size;
		unsigned long address;
};
/*
 * Read the first byte of the fastcall table.
 */
void _read_table(void *address)
{
	printf("First byte of the fastcall table: 0x%x\n", *(char *)address);
}


/*
 * The fastcall table must not be unmapped.
 * munmap should result in an error.
 */
TEST(mmap_ioctl)
{
	int fd;
	int ret;

	printf("enter\n");

	void *address = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);

	ASSERT_NE(MAP_FAILED, address);

	struct mesg msg1 = {.size = PAGE_SIZE, .address= (unsigned long)address};

	_read_table(address);

	fd = open("/dev/fastcall-examples", O_RDONLY);
	if (fd < 0) {
		printf("Cannot open device file...\n");
	}
	ret = ioctl(fd, 0, &msg1);

	ASSERT_EQ(0, ret);
	_read_table(address);
}

TEST_HARNESS_MAIN
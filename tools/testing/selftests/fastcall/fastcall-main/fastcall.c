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
//#include "../kselftest_harness.h"

#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#define TEST ((char *)0x7ffffffe0000)
typedef int (*fc_ptr)(void);

struct mesg {
		unsigned long fce_region_address;
		unsigned long secret_region;
		unsigned long hidden_region[10];
};
/*
 * Read the first byte of the fastcall table.
 */
void _read_table(struct mesg *message)
{
	int i;

	printf("fce address: 0x%lx\n", message->fce_region_address);
	printf("secret region address: 0x%lx\n", message->secret_region);

	for (i = 0; i < 10; i++)
		printf("hidden region address: 0x%lx\n", message->hidden_region[i]);


}


/*
 * The fastcall table must not be unmapped.
 * munmap should result in an error.
 */
int main(int argc, char *argv[]) 
{
	int fd;
	int ret, fce_ret;
	struct mesg *message;
	fc_ptr fc_noop;

	message = malloc(sizeof(struct mesg));
	printf("enter\n");


	fd = open("/dev/fastcall-examples", O_RDONLY);
	if (fd < 0)
		printf("Cannot open device file...\n");

	ret = ioctl(fd, 0, message);

	fc_noop = (fc_ptr)message->fce_region_address;

	_read_table(message);
	fce_ret = fc_noop();


	if (fce_ret != 0)
        printf("test failed, return value %d\n",fce_ret);

	printf("First byte of the fastcall table: 0x%x\n", *TEST);

    return ret;
}
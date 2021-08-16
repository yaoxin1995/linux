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
typedef int (*fc_ptr)(void);

struct mesg {
		unsigned long yellow_address;
		unsigned long purple_address;
		unsigned long green_address;
};
/*
 * Read the first byte of the fastcall table.
 */
void _read_table(struct mesg *message)
{
	printf("First byte of yellow box: 0x%x\n", *(char *)message->yellow_address);
	printf("First byte of purple box: 0x%x\n", *(char *)message->purple_address);
	printf("First byte of green: 0x%x\n", *(char *)message->green_address);

}


/*
 * The fastcall table must not be unmapped.
 * munmap should result in an error.
 */
int main(int argc, char *argv[]) {
    int fd;
	int ret, fce_ret;
	struct mesg *message;
	fc_ptr fc_noop;

    message = malloc(sizeof(struct mesg));
	printf("enter\n");


	fd = open("/dev/fastcall-examples", O_RDONLY);
	if (fd < 0) {
		printf("Cannot open device file...\n");
	}
	ret = ioctl(fd, 0, message);

	fc_noop = (fc_ptr)message->yellow_address;

	_read_table(message);
	fce_ret = fc_noop();

	if( fce_ret == 2 ){
        printf("test failed");
    }

    return ret;
}
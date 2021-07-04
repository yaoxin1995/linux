// SPDX-License-Identifier: GPL-2.0
/*
 * The fastcall mechanism allows to register system call handlers 
 * that execute in a minimal kernel environment with reduced overhead.
 */

#include <linux/printk.h>
#include <linux/compiler_types.h>
#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <asm/fastcall.h>

#define NR_REQ 1
/*
 * setup_fastcall_yellow_page
 * - insert a variable to this page
 * - find the correspondent vma,change it to only readable
 */
int fastcall_register(unsigned long __user user_addr, unsiunsigned long len)
{
	struct page *pages[NR_REQ];
	int Nr_page = len/PAGE_SIZE;

	if (Nr_page != NR_REQ) {
		pr_info("fastcall register func: provided len argument invalid,must be page size");
		return -EINVAL;
	}
	pr_info("fastcall register func: fastcall_register func begin");
    // pin the page to memory and get page struc
	mmap_read_lock(current->mm);
	nr_gup = get_user_pages(user_addr, NR_REQ, FOLL_WRITE, pages, NULL);
	mmap_read_unlock(current->mm);
    // map the page to kernel using kmap and get the correspondent kernel vir. addr. of this page
	void *address = kmap(pages[0]);
    // write a int value at the begining of this page
	memset(address, 'F', PAGE_SIZE);
	pr_info("fastcall register func: set "F" to the maped page");
    // kunmap from kernel
	kunmap(pages[0]);
    // find vma of this page
    // change the vma to only readable
    // unpin the page
	set_page_dirty_lock(pages[0]);
	put_page(pages[0]);
	pr_info("fastcall register func: fastcall_register func end");
	return 0;
}
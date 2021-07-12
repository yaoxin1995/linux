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
#define FASTCALL_GPF GFP_HIGHUSER

struct mesg {
		unsigned long yellow_address;
		unsigned long purple_address;
		unsigned long green_address;
};

/*
 * fastcall_mremap - prohibit remap the fastcall yellow,green,puple pages
 */
static int fastcall_mremap(const struct vm_special_mapping *sm, struct vm_area_struct *new_vma)
{
	/* Invalid argument */
	return -EINVAL;
}

/*
 * fastcall_may_unmap - prohibit unmapping fastcall yellow,green,puple pages
 */
static int fastcall_may_unmap(const struct vm_special_mapping *sm,
			      struct vm_area_struct *vma)
{
	/* Permission denied */
	return -EACCES;
}

/*
 * fastcall_fault - every fault to this vma is invalid
 * fastcall pages are all mapped on fastcall registration.
 */
static vm_fault_t fastcall_fault(const struct vm_special_mapping *sm,
				 struct vm_area_struct *vma,
				 struct vm_fault *vmf)
{
	//VM_FAULT_SIGSEGV:	segmentation fault
	return VM_FAULT_SIGBUS;
}

/*
 * special mapping struct for yellow page
 */
static const struct vm_special_mapping fastcall_pages_mapping = {
	.name = "[fastcall_pages]",
	.mremap = fastcall_mremap,
	.may_unmap = fastcall_may_unmap,
	.fault = fastcall_fault,
};

/*
 * unmappable_mapping - a temporary mapping that allows boxs to be unmapped
 */
static const struct vm_special_mapping unmappable_mapping = {
	.name = "[fastcall_unmap]",
	.mremap = fastcall_mremap,
	.fault = fastcall_fault,
};


/*
 * unmap_function - unmap vma of boxes at this address
 */
static void unmap_function(unsigned long vma_start)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_start == vma_start)
			break;
	}

	if (WARN_ON(!vma))
		return;

	// Make do_munmap possible
	vma->vm_private_data = (void *)&unmappable_mapping;
	WARN_ON(do_munmap(mm, vma_start, vma->vm_end - vma->vm_start, NULL));
}

/*
 * Memory layout of the fastcall pages:
 *
 * 0xffffffffffffffff +--------------------+
 *                    | kernel space       |
 * 0xffff800000000000 +--------------------+
 *      non-canonical | hole               |
 *	   0x7fffffffffff +--------------------+
 *					  | rest of user space |
 *                    +--------------------+
 *           one page | purple (only exc.) |
 *   vma_purple_start +--------------------+
 *					  | yellow(read. exc.) |
 *   vma_yellow_start  +--------------------+
 *                    | rest of user space |
 *                0x0 +--------------------+
 *
 *
 * install_box_mapping - create and populate a mapping with proper flags for the box text pages
 *	- vma : readable, excutable
 *	- argument:
 *		- pages maped to this vam, pages could be single page or the start page of a physical
 *		  continuoes region
 *		- num: number of page in array pages
 *		- flags: vma flag, readeable, excutable etc.
 *		- start_address: start address of this vma
 *	- Return the pointer to the first address of the area.
 */
static unsigned long install_box_mapping(struct page *pages,
					      unsigned long num, unsigned long flags, unsigned long start_address)
{
	int err;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long len = num * PAGE_SIZE;
	unsigned long pfn;

	pr_info("install_box_mapping: function starts");
	vma = _install_special_mapping(mm, start_address, len, flags,
				       &fastcall_pages_mapping);
	if (IS_ERR(vma)) {
		pr_info("install_box_mapping: falied to allocat a vma for box, error code: %lu, flags: %lu, start address: %lu\n", (unsigned long)vma, flags, start_address);
		goto fail_insert_vma;
	}

	pfn = page_to_pfn(pages);
	down_write(&mm->mmap_lock);
	err = remap_pfn_range(vma, start_address, pfn, len, vma->vm_page_prot);
	if (err < 0) {
		pr_info("install_box_mapping: falied to insert pages to vma, error code: %lu, flags: %lu, start address: %lu, page acount:  %d\n", (unsigned long)vma, flags, start_address, num);
		goto fail_insert_page;
	}
	pr_info("install_box_mapping: function end with no bug\n");
	up_write(&mm->mmap_lock);
	return start_address;
fail_insert_vma:
	pr_info("install_box_mapping: function end with fail_insert_vma\n");
	up_write(&mm->mmap_lock);
	return (unsigned long)vma;
fail_insert_page:
	pr_info("install_box_mapping: function end with fail_insert_page\n");
	up_write(&mm->mmap_lock);
	unmap_function(start_address);
	return err;
}

/*
 * fastcall_register: install yellow- purple- green- box
 * - yellow page and purple page have consecutive addresses
 * - yellow box is readble and excutable and has 1 page size
 * - purple box is readble and excutable and has 1 page size
 * - green box is readble and writable and has 1 page size
 * - insert a variable to this page
 * - Argument:
 *		- user_addr: copy the adresses of 3 boxes to this address
 * - TODO : green page address should be randomized
 * - TODO: puple page should be only excutable
 * - TODO: get pages for yellow and purple from device
 * - TODO: device should determine the size of green box
 */
unsigned long fastcall_register(unsigned long __user user_addr)
{
	unsigned long ret;
	unsigned long yellow_start_adr;
	unsigned long purple_start_adr;
	unsigned long green_start_adr;
	// total length for yellow and purple box
	unsigned long len_yp = 2 * PAGE_SIZE;
	struct page *yellow_page;
	struct page *purple_page;
	struct page *green_page;
	struct mesg message;

	pr_info("fastcall_register: function starts\n");
	ret = 0;
	// find a proper virtual address region for yellow and purple box
	yellow_start_adr = get_unmapped_area(NULL, current->mm->start_stack, len_yp, 0, 0);
	if (IS_ERR_VALUE(yellow_start_adr)) {
		pr_info("fastcall_register: falied to find a unmapped area for yellow box, yellow_start_adr: %lu\n", yellow_start_adr);
		ret = yellow_start_adr;
		goto fail_get_free_vma_area;
	}

	purple_start_adr = yellow_start_adr + PAGE_SIZE;

	// TODO: the start address of green box should be randomized somehow
	green_start_adr = get_unmapped_area(NULL, current->mm->start_stack, PAGE_SIZE, 0, 0);
	if (IS_ERR_VALUE(green_start_adr)) {
		pr_info("fastcall_register: falied to find a unmapped area for green box, yellow_start_adr: %lu, green_start_adr: %lu\n", yellow_start_adr, green_start_adr);
		ret = green_start_adr;
		goto fail_get_free_vma_area;
	}

	yellow_page = alloc_pages(FASTCALL_GPF, 0);
	if (!yellow_page) {
		pr_info("fastcall_register: falied to allocate page for yellow box\n");
		ret = -ENOMEM;
		goto fail_allocat_page;
	}
	memset(page_address(yellow_page), 'B', PAGE_SIZE);

	ret = install_box_mapping(yellow_page, 1, VM_READ | VM_MAYREAD, yellow_start_adr);
	if (ret != yellow_start_adr) {
		pr_info("fastcall_register: falied to install yellow box mapping, ret = %lu, yellow_start_adr = %lu\n", ret, yellow_start_adr);
		goto fail_creat_vma;
	}

	purple_page = alloc_pages(FASTCALL_GPF, 0);
	if (!purple_page) {
		pr_info("fastcall_register: falied to allocate page for purple box\n");
		ret = -ENOMEM;
		goto fail_allocat_page;
	}
	memset(page_address(purple_page), 'A', PAGE_SIZE);

	//TODO: change it to VM_EXEC | VM_MAYEXEC
	ret = install_box_mapping(purple_page, 1, VM_READ | VM_MAYREAD, purple_start_adr);
	if (ret != purple_start_adr) {
		pr_info("fastcall_register: falied to install purple box mapping, ret = %lu, purple_start_adr = %lu\n", ret, purple_start_adr);
		goto fail_creat_vma;
	}

	green_page = alloc_pages(FASTCALL_GPF, 0);
	if (!green_page) {
		pr_info("fastcall_register: falied to allocate page for green box\n");
		ret = -ENOMEM;
		goto fail_allocat_page;
	}
	memset(page_address(green_page), 'F', PAGE_SIZE);

	ret = install_box_mapping(green_page, 1, VM_READ | VM_MAYREAD | VM_WRITE | VM_MAYWRITE, green_start_adr);
	if (ret != green_start_adr) {
		pr_info("fastcall_register: falied to install green box mapping,  ret = %lu, purple_start_adr = %lu\n", ret, green_start_adr);
		goto fail_creat_vma;
	}

	message.yellow_address = yellow_start_adr;
	message.purple_address = purple_start_adr;
	message.green_address = green_start_adr;
	if (copy_to_user((void *)user_addr, &message, sizeof(struct mesg))) {
		pr_info("fastcall_register: falied to copy message struct to user space,user_addr: %lu, yellow_address: %lu, purple_address: %lu, purple_address: %lu\n", user_addr, message.yellow_address, message.purple_address, message.green_address);
		ret = -EFAULT;
		goto fail_copy_user;
	}
	pr_info("fastcall_register: function end with no bug\n");
	return ret;

fail_get_free_vma_area:
	pr_info("fastcall_register: function end with fail_get_free_vma_area\n");
	return ret;
fail_allocat_page:
	pr_info("fastcall_register: function end with fail_allocat_page\n");
	return ret;
fail_creat_vma:
	pr_info("fastcall_register: function end with fail_creat_vma \n");
	return ret;
fail_copy_user:
	pr_info("fastcall_register: function end with fail_copy_user\n");
	return ret;

}
// SPDX-License-Identifier: GPL-2.0
/*
 * The fastcall mechanism allows to register system call handlers
 * that execute in a minimal kernel environment with reduced overhead.
 */

#include <linux/printk.h>
#include <linux/compiler_types.h>
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <asm/fastcall.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <asm/elf.h>

#include <asm/page_types.h>
#include <asm/page_64_types.h>



struct fastcall_table *fc_table;


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
 * unmap_region - unmap vma ,which incluce this address
 */
static void unmap_region(unsigned long vma_addr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_start <= vma_addr && vma->vm_end >= vma_addr)
			break;
	}

	if (WARN_ON(!vma))
		return;

	// Make do_munmap possible
	vma->vm_private_data = (void *)&unmappable_mapping;
	WARN_ON(do_munmap(mm, vma->vm_start, vma->vm_end - vma->vm_start, NULL));
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
 * region_mapping - create and populate a mapping with proper flags
 *	- argument:
 *		- pages maped to this vam, pages could be single page or the start page of a physical
 *		  continuoes region
 *		- num: number of page in array pages
 *		- flags: vma flag, readeable, excutable etc.
 *		- start_address: start address of this vma
 *	- Return the pointer to the first address of the area.
 */
static unsigned long region_mapping(struct page **pages, unsigned long num, unsigned long flags, unsigned long start_address)
{
	int err;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long len = num * PAGE_SIZE;

	pr_info("install_box_mapping: function starts");
    pr_info("install_box_mapping: function argument , start address: %lx num of pages: %lu\n", start_address, num);


	vma = _install_special_mapping(mm, start_address, len, flags, &fastcall_pages_mapping);
	if (IS_ERR(vma)) {
		pr_info("install_box_mapping: falied to allocat a vma for box, error code: %ld, flags: %lu, start address: %lx\n", PTR_ERR(vma), flags, start_address);
		goto fail_insert_vma;
	}

	err = vm_insert_pages(vma, start_address, pages, &num);
	if (err < 0) {
		pr_info("install_box_mapping: falied to insert pages to vma, error code: %lu, flags: %lu, start address: %lu, page acount:  %lu\n", (unsigned long)vma, flags, start_address, num);
		goto fail_insert_page;
	}
	pr_info("install_box_mapping: function end with no bug , return start address :%lx \n", start_address);

	return start_address;
fail_insert_vma:
	pr_info("install_box_mapping: function end with fail_insert_vma\n");
	return (unsigned long)vma;
fail_insert_page:
	pr_info("install_box_mapping: function end with fail_insert_page\n");
	unmap_region(start_address);
	return err;
}

/*
 * get_randomized_address: get random start address of a vma
 *	- len: the size of the vma
 */

unsigned long get_randomized_address(unsigned long len)
{
	struct vm_unmapped_area_info info;

	info.flags = 0;
	info.length = len;
	info.high_limit = DEFAULT_MAP_WINDOW;
	info.align_mask = 0;
	info.align_offset = 0;

	info.low_limit = PAGE_ALIGN((get_random_long() & ((1UL << (__VIRTUAL_MASK_SHIFT - 2)) - 1)));

	return vm_unmapped_area(&info);

}



/*
 * is_fce_address_valid: check if the fast call entry address valid
 * fce_address: fastcall entry address
 * return struct fastcall_entry*  if fce_address valid ,otherwise return null ptr
 * the other two regions (fce region and executable only region) should be created first
 */
struct fastcall_entry* is_fce_address_valid(unsigned long fce_address)
{
	struct fastcall_entry* ret = NULL;
	size_t i;

	pr_info("is_fce_address_valid: start \n");

	if (!fc_table || !fc_table->entries) {
		pr_info("is_fce_address_valid: table not initialized \n");
		goto fail_table_exist;
	}



	if (mutex_lock_killable(&fc_table->mutex)){
		pr_info("is_fce_address_valid: lock the table failed \n");
		goto fail_table_lock;
	}


	for (i = 0; i < NR_ENTRIES; i++) {

		struct fastcall_entry *entry = &fc_table->entries[i];

		if (entry->fce_region_addr == 0) {
			pr_info("is_fce_address_valid: can't find the corresponding entry in array entries \n");
			goto fail_find_valid_fce;
		}

		if (entry->fce_region_addr == fce_address) {
			pr_info("is_fce_address_valid: the corresponding entry in array entries is found \n");
			ret = entry;
			break;
		}
	}

fail_table_exist:
fail_table_lock:
fail_find_valid_fce:
	mutex_unlock(&fc_table->mutex);
	return ret;

}



/*
 * hidden_region_creatrion: create a hidden region mapping
 * fce_address: fastcall entry address
 * pages: array of page needed in this region
 * num: amount of entry in array pages
 * return 0 if everything all right
 * the other two regions (fce region and executable only region) should be created first
 */
int hidden_region_creatrion(unsigned long fce_address, struct page **pages, int num, unsigned long start_addr)
{
	unsigned long ret = 0;
	size_t fce_entries_size = fc_table->entries_size;
	//struct mm_struct *mm = current->mm;
	struct fastcall_entry *entry = &fc_table->entries[fce_entries_size];

	// if (mmap_write_lock_killable(mm))
	// 	return -EINTR;

	pr_info("hidden_region_creatrion: start \n");
	pr_info("hidden_region_creatrion: fce_address:%lx, page num: %d, start_addr %lx\n", fce_address, num, start_addr);
	if (!fc_table) {
		ret = -EINTR;
		pr_info("hidden_region_creatrion: fc_table not initialized,call fce_regions_creation first \n");
		goto fail_fac_address_invailid;
	}

	if(entry->fce_region_addr != fce_address){
		ret = -EINTR;
		pr_info("hidden_region_creatrion: fce_address invalid \n");
		goto fail_fac_address_invailid;
	}

	ret = region_mapping(pages, num, HIDEN_REGION_FLAG, start_addr);
	if (ret != start_addr) {
		pr_info("hidden_region_creatrion: falied to install hidden box,  ret = %lx, start_adr = %lx\n", ret, start_addr);
		ret = -ENOMEM;
		goto fail_creat_vma;
	}





	if (entry->hidden_region_addr != 0){
		pr_info("hidden_region_creatrion: hidden region already exist, unmap it!");
		unmap_region(entry->hidden_region_addr);
	}

	pr_info("hidden_region_creatrion: the start address of this region ret = %lx, fce_addr: %lx\n", ret, fce_address);

	entry->hidden_region_addr = ret;
	fc_table->entries_size++;
	ret = 0;



	pr_info("hidden_region_creatrion:region addresses in fc_table, fc_address:%lx \n", (fc_table->entries[fce_entries_size]).fce_region_addr);
	pr_info("hidden_region_creatrion:region addresses in fc_table, secret_adr:%lx \n", (fc_table->entries[fce_entries_size]).exect_region_addr);
	pr_info("hidden_region_creatrion:region addresses in fc_table, hidden_addr: %lx\n", (fc_table->entries[fce_entries_size]).hidden_region_addr);
	pr_info("hidden_region_creatrion:region addresses in fc_table, registered fastcall: %d\n", fc_table->entries_size);
	pr_info("hidden_region_creatrion:  function end with no bug\n");
fail_fac_address_invailid:
fail_creat_vma:
	// mmap_write_unlock(mm);
	return ret;
}



int initianlize_table(void)
{
	size_t i;


	pr_info("initianlize_table: function starts\n");
	fc_table = kmalloc(sizeof(struct fastcall_table), GFP_KERNEL);
	if (!fc_table) {
		pr_info("initianlize_table: failed to allocat memory for table\n");
		return -ENOMEM;
	}

	mutex_init(&fc_table->mutex);

	for (i = 0; i < NR_ENTRIES; i++) {
		fc_table->entries[i].fce_region_addr = 0;
		fc_table->entries[i].hidden_region_addr = 0;
		fc_table->entries[i].exect_region_addr = 0;
	}
	fc_table->entries_size = 0;

	pr_info("initianlize_table: function ends successfully \n");
	return 0;


}

/*
 * fce_regions_creation: install fastcall entry region and executative only region
 * - fastcall entry region and  xecutative only regione  have consecutive addresse
 * - fastcall entry region is readble and excutable and has "fce_pages_num" page size
 * - executative only region is excutable and has "exec_only_pages_num" page size
 * - log the address of fastcall entry and executative only region in "table"
 * - driver should call hidden_region_creatrion further to complete the registration process
 * - Argument:
 *		- user_addr: copy the adresses of 3 boxes to this address for test
 *		- fce_pages: pages for fastcall entry region
 *		- fce_pages_num: number of pages in  array fce_pages
 *		- exec_only_pages: pages for executative only region
 *		- exec_only_pages_num: number of pages in  array exec_only_pages
 *		- offset: offset of fast call function in fce_pages
 * - return the fastcall entry address if succeed
 * - TODO: puple page should be only excutable
 */
unsigned long fce_regions_creation( struct page **fce_pages, int fce_pages_num, struct page **secret_pages, \
int secret_pages_num, unsigned long offset)
{
	unsigned long ret;
	unsigned long fce_start_adr;
	unsigned long secret_start_adr;
	struct fastcall_entry *entry;


	pr_info("fce_regions_creation: function starts\n");
	ret = 0;

	if(!fc_table){
		initianlize_table();
	}

	//BUG_ON(fc_table->entries_size >= NR_ENTRIES);
	if(fc_table->entries_size >= NR_ENTRIES) {
		pr_info("fce_regions_creation: can't have more fastcall \n");
		goto fail_creat_fce;
	}

	// find a proper virtual address region for yellow and purple box
	fce_start_adr = get_unmapped_area(NULL, 0, (fce_pages_num + secret_pages_num) * PAGE_SIZE, 0, 0);
	if (IS_ERR_VALUE(fce_start_adr)) {
		pr_info("fce_regions_creation: falied to find a unmapped area for fce_region, exec_only_region: %lx\n", fce_start_adr);
		ret = fce_start_adr;
		goto fail_get_free_vma_area;
	}

	secret_start_adr = fce_start_adr + PAGE_SIZE * fce_pages_num;
	pr_info("fce_regions_creation: fce_start_adr: %lx, secret_start_adr: %lx fce_function_offset:%lx \n",\
	 fce_start_adr, secret_start_adr, offset);

	ret = region_mapping(fce_pages, fce_pages_num, FCE_REGION_FLAG, fce_start_adr);
	if (ret != fce_start_adr) {
		pr_info("fastcall_register: falied to install fce mapping, ret = %lx, fce_start_adr = %lx\n", ret, fce_start_adr);
		goto fail_creat_vma;
	}


	// fast call entry address
	fce_start_adr += offset;


	//TODO: change it to VM_EXEC | VM_MAYEXEC
	ret = region_mapping(secret_pages, secret_pages_num, FCE_REGION_FLAG, secret_start_adr);
	if (ret != secret_start_adr) {
		pr_info("fce_regions_creation: falied to install exec_only_pages mapping, ret = %lx, secret_start_adr = %lx\n", ret, secret_start_adr);
		goto fail_creat_vma;
	}

	entry = &fc_table->entries[fc_table->entries_size];

	//fc_table->entries_size++;

	entry->fce_region_addr = fce_start_adr;
	entry->exect_region_addr = secret_start_adr;
	pr_info("fce_regions_creation: entry->fce_region_addr: = %lx, entry->exect_region_addr  = %lx\n", \
	entry->fce_region_addr, entry->exect_region_addr);


	pr_info("fce_regions_creation: function end with no bug\n");
	ret = fce_start_adr;
	return ret;

fail_get_free_vma_area:
	pr_info("fce_regions_creation: function end with fail_get_free_vma_area\n");
	return ret;
fail_creat_vma:
	pr_info("fce_regions_creation: function end with fail_creat_vma \n");
	return ret;

fail_creat_fce:
	pr_info("fce_regions_creation: function end with fail_creat_fce, too many entrys \n");
	return ret;

}
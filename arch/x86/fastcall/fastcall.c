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
 * special mapping struct for fce and secret page
 */
static const struct vm_special_mapping fastcall_pages_mapping = {
	.name = "[fastcall_pages]",
	.mremap = fastcall_mremap,
	.may_unmap = fastcall_may_unmap,
	.fault = fastcall_fault,
};


/*
 * special mapping struct for hidden page
 */
const struct vm_special_mapping fastcall_hidden_pages_mapping = {
	.name = "[fastcall_hidden_pages]",
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

	pr_info("unmap_region: function starts");
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_start <= vma_addr && vma->vm_end >= vma_addr)
			break;
	}

	if (WARN_ON(!vma))
		return;

	// Make do_munmap possible
	vma->vm_private_data = (void *)&unmappable_mapping;
	WARN_ON(do_munmap(mm, vma->vm_start, vma->vm_end - vma->vm_start, NULL));
	pr_info("unmap_region: unmap_region finished, no bug");
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
static unsigned long region_mapping(struct page **pages, unsigned long num, unsigned long flags, unsigned long start_address, bool is_hidden_region)
{
	int err;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long len = num * PAGE_SIZE;

	pr_info("region_mapping: function starts");
    pr_info("region_mapping: function argument , start address: %lx num of pages: %lu\n", start_address, num);

	if (is_hidden_region)	
		vma = _install_special_mapping(mm, start_address, len, flags, &fastcall_hidden_pages_mapping);
	else
		vma = _install_special_mapping(mm, start_address, len, flags, &fastcall_pages_mapping);
	if (IS_ERR(vma)) {
		pr_info("region_mapping: falied to allocat a vma for box, error code: %ld, flags: %lu, start address: %lx\n", PTR_ERR(vma), flags, start_address);
		goto fail_insert_vma;
	}

	err = vm_insert_pages(vma, start_address, pages, &num);
	if (err < 0) {
		pr_info("region_mapping: falied to insert pages to vma, error code: %lu, flags: %lu, start address: %lu, page acount:  %lu\n", (unsigned long)vma, flags, start_address, num);
		goto fail_insert_page;
	}
	pr_info("region_mapping: function end with no bug , return start address :%lx \n", start_address);

	return start_address;
fail_insert_vma:
	pr_info("region_mapping: function end with fail_insert_vma\n");
	return (unsigned long)vma;
fail_insert_page:
	pr_info("region_mapping: function end with fail_insert_page\n");
	unmap_region(start_address);
	return err;
}

/*
 * get_randomized_address: get random start address of a vma
 *	- len: the size of the vma
 */

unsigned long get_randomized_address(unsigned long len, bool hidden_region)
{
	struct vm_unmapped_area_info info;

	info.flags = 0;
	info.length = len;
	info.high_limit = HIDDEN_REGION_MAX;
	info.low_limit = DEFAULT_MAP_WINDOW;
	info.align_mask = 0;
	info.align_offset = 0;

	if (hidden_region)
		info.low_limit +=
			PAGE_ALIGN((get_random_long() &
				    ((1UL << (__VIRTUAL_MASK_SHIFT - 2)) - 1)));
	else{
		info.high_limit = DEFAULT_MAP_WINDOW;
		info.low_limit =
			PAGE_ALIGN((get_random_long() &
		    	((1UL << (__VIRTUAL_MASK_SHIFT - 25)) - 1)));
	}


	return vm_unmapped_area(&info);

}



/*
 * find_entry: check if the fast call entry address valid
 * fce_address: fastcall entry address
 * return struct fastcall_entry*  if fce_address valid ,otherwise return null ptr
 */
struct fastcall_entry *find_entry(unsigned long fce_address)
{
	struct fastcall_entry *ret = NULL;
	size_t i;

	pr_info("find_entry: start \n");

	if (!fc_table || !fc_table->entries) {
		pr_info("find_entry: table not initialized \n");
		goto fail_table_exist;
	}



	// if (mutex_lock_killable(&fc_table->mutex)){
	// 	pr_info("is_fce_address_valid: lock the table failed \n");
	// 	goto fail_table_lock;
	// }


	for (i = 0; i < NR_ENTRIES; i++) {

		struct fastcall_entry *entry = &fc_table->entries[i];

		if (entry->fce_region_addr == fce_address) {
			pr_info("find_entry: the corresponding entry with fce_address %lx in array entries is found \n", fce_address);
			ret = entry;
			goto find_fce_address;
		}
	}

	pr_info("find_entry: can't find the corresponding entry in array entries with fce_address: %lx\n", fce_address);

fail_table_exist:
find_fce_address:
	//mutex_unlock(&fc_table->mutex);
	return ret;

}

/*
 * put_address_to_sr:  put hidden region address to secret region
 * index: index of mov instruction to overwrten
 * sr_page: secret page that contain mov instruction to be written to
 * hidden_address: hidden address of hidden region
 * return 0 if everything all right
 */

void put_address_to_sr(int index, struct page *sr_page, unsigned long hidden_address)
{

	char *sr_start_addr;
	unsigned long *start_overwritten_ptr;
		// overwriten dummy nummber on page secret
	sr_start_addr = (char*) kmap(sr_page);

	sr_start_addr = sr_start_addr + MOV_SLOT_SIZE * index + MOV_SLOT_OFFSET;

	start_overwritten_ptr = (unsigned long *) sr_start_addr;

	*start_overwritten_ptr = hidden_address;

	kunmap(sr_page);

}


/*
 * find_fastcall_vma - find the vma containing the fastcall pages
 */
static struct vm_area_struct *find_fc_vma(unsigned long address)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	pr_info("find_fc_vma: enter\n");
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_start <= address && vma->vm_end >= address)
			break;
	}

	// No fastcall mapping was found in the process.
	if (!vma) {
		pr_info("find_fc_vma: No fastcall mapping was found in the process.\n");
		BUG();
	}


	pr_info("find_fc_vma: end,find vma\n");
	return vma;

}


/*
 * delete_hidden_region - delete a hidden region in fast call entry
 */
int delete_hidden_region(unsigned long fce_address, unsigned long hr_address, struct page *sr_page)
{
	struct vm_area_struct *hr_vma;
	int i, index;
	struct fastcall_entry *entry;

	if (!mutex_trylock(&fc_table->mutex)) {
		pr_info("delete_hidden_region: fail_lock\n");
		goto fail_lock;
	}

	entry = find_entry(fce_address);
	if (!entry) {
		mutex_unlock(&fc_table->mutex);
		return -1;
	}

	for (i = 0; i < NR_HIDDEN_REGION; i++) {
		if (entry->hidden_region_addrs[i] == hr_address) {
			index = i;
			goto find_entry;
		}
	}
	mutex_unlock(&fc_table->mutex);
	return -1;
find_entry:

	if (sr_page != NULL)
		put_address_to_sr(index, sr_page, 0x7FFFFFFFFFFF);

	entry->hidden_region_addrs[i] = 0;
	entry->nr_hidden_region_current--;

	// delete the hidden region
	hr_vma = find_fc_vma(hr_address);
	zap_page_range(hr_vma, hr_address, (hr_vma->vm_end - hr_vma->vm_start) * PAGE_SIZE);
	unmap_region(hr_address);
	mutex_unlock(&fc_table->mutex);
	return 0;
fail_lock:
	return -1;

}





/*
 * hidden_region_creatrion: create a hidden region mapping
 * fce_address: fastcall entry address
 * pages: array of page needed in this region
 * num: amount of entry in array pages
 * return hidden region address if everything all right
 * the other two regions (fce region and executable only region) should be created first
 */
unsigned long hidden_region_creation(unsigned long fce_address, struct page **hr_pages, int hr_num, struct page *sr_page)
{
	unsigned long ret = -1;
	struct vm_area_struct *fce_vma, *sr_vma, *hr_vma;
	unsigned long hr_start_address;
	//struct mm_struct *mm = current->mm;
	struct fastcall_entry *entry = find_entry(fce_address);
	int index, i, j;

	if (!mutex_trylock(&fc_table->mutex)) {
		pr_info("fce_regions_creation: fail_lock\n");
		ret = -1;
		goto fail_lock;
	}

	if (!entry) {
		pr_info("hidden_region_creatrion: fce_address:0x%lx not valid\n", fce_address);
		goto invalid_fce_entry;
	}

	// if (mmap_write_lock_killable(mm))
	// 	return -EINTR;

	if (entry->nr_hidden_region_current >= NR_HIDDEN_REGION || entry->nr_hidden_region_current >=  entry->max_hidden_region) {
		pr_info("hidden_region_creatrion: entry with fce_address %lx can't have more hidden region\n", fce_address);
		goto invalid_fce_entry;
	}


	pr_info("hidden_region_creatrion: start \n");
	pr_info("hidden_region_creatrion: fce_address:%lx, hidden page number: %d\n", fce_address, hr_num);

	if (!fc_table) {
		ret = -EINTR;
		pr_info("hidden_region_creatrion: fc_table not initialized,call fce_regions_creation first \n");
		goto fail_fce_address_invailid;
	}


	hr_start_address = get_randomized_address(PAGE_SIZE, true);
	pr_info("fast_call_example: hidden_addr: %lx\n", hr_start_address);
	if (IS_ERR_VALUE(hr_start_address)) {
		pr_info("hidden_region_creatrion: falied to find a unmapped area for hidden box, fce_addr: %lx, hidden_addr: %lx\n", fce_address, hr_start_address);
		ret = -ENOMEM;
		goto fail_get_free_vma_area;
	}



	ret = region_mapping(hr_pages, hr_num, HIDEN_REGION_FLAG, hr_start_address, true);
	if (ret != hr_start_address) {
		pr_info("hidden_region_creatrion: falied to install hidden box,  ret = 0x%lx, start_adr = 0x%lx\n", ret, hr_start_address);
		ret = -ENOMEM;
		goto fail_creat_vma;
	}

	for (i = 0; i < NR_HIDDEN_REGION; i++) {
		if (entry->hidden_region_addrs[i] == 0) {
			index = i;
			break;
		}
	}

	put_address_to_sr(index, sr_page, hr_start_address);


	entry->hidden_region_addrs[index] = hr_start_address;

	if (entry->nr_hidden_region_current == 0)
		fc_table->entries_size++;

	entry->nr_hidden_region_current++;



	pr_info("hidden_region_creatrion: the start address of this region ret = 0x%lx, fce_addr: 0x%lx\n", ret, fce_address);


	pr_info("hidden_region_creatrion:region addresses in fc_table, fc_address:%lx \n", entry->fce_region_addr);
	pr_info("hidden_region_creatrion:region addresses in fc_table, secret_adr:%lx \n",entry->secret_region_addr);
	pr_info("hidden_region_creatrion:region addresses in fc_table, hidden_addr: %lx\n", entry->hidden_region_addrs[entry->nr_hidden_region_current-1]);
	pr_info("hidden_region_creatrion: current number of hidden region in entry: %d\n", entry->nr_hidden_region_current);


	pr_info("hidden_region_creatrion:region addresses in fc_table, registered fastcall: %d\n", fc_table->entries_size);
	pr_info("hidden_region_creatrion:  function end with no bug\n");

	ret = hr_start_address;

	mutex_unlock(&fc_table->mutex);
	return ret;


fail_creat_vma:
fail_get_free_vma_area:
	for (i = 0; i < NR_HIDDEN_REGION; i++) {
		if (!entry->hidden_region_addrs[i]) {
			hr_vma = find_fc_vma(entry->hidden_region_addrs[i]);
			zap_page_range(hr_vma, entry->hidden_region_addrs[i], (hr_vma->vm_end - hr_vma->vm_start) * PAGE_SIZE);
			unmap_region(entry->hidden_region_addrs[i]);
			entry->hidden_region_addrs[i] = 0;
		}
	}
	fce_vma = find_fc_vma(entry->fce_region_addr);
	zap_page_range(fce_vma, entry->fce_region_addr, (fce_vma->vm_end - fce_vma->vm_start) * PAGE_SIZE);
	unmap_region(entry->fce_region_addr);

	sr_vma = find_fc_vma(entry->secret_region_addr);
	zap_page_range(sr_vma, entry->secret_region_addr, (sr_vma->vm_end - sr_vma->vm_start) * PAGE_SIZE);
	unmap_region(entry->secret_region_addr);

	entry->fce_region_addr = 0;
	entry->secret_region_addr = 0;
	entry->nr_hidden_region_current = 0;
	entry->max_hidden_region = 0;

fail_fce_address_invailid:
invalid_fce_entry:
	mutex_unlock(&fc_table->mutex);
fail_lock:
	// mmap_write_unlock(mm);
	return ret;
}


/*
 * fsc_unregistration: unregister fastcall function
 */
int fsc_unregistration(unsigned long fce_address)
{
	unsigned long ret = 0;
	struct vm_area_struct *fce_vma, *sr_vma, *hr_vma;
	struct mm_struct *mm = current->mm;
	struct fastcall_entry *entry = find_entry(fce_address);
	int i;

	if (!mutex_trylock(&fc_table->mutex)){
		ret = -1;
		goto fail_lock;
	}

	if (mmap_write_lock_killable(mm)){
		ret = -1;
		goto fail_lock;
	}


	if (!entry) {
		pr_info("fsc_unregistration: fce_address:0x%lx not valid\n", fce_address);
		ret = -1;
		goto invalid_fce_entry;
	}

	for (i = 0; i < NR_HIDDEN_REGION; i++) {
		if (entry->hidden_region_addrs[i] != 0) {
			pr_info("fsc_unregistration: hidden_region_addrs:0x%lx \n", entry->hidden_region_addrs[i]);
			hr_vma = find_fc_vma(entry->hidden_region_addrs[i]);
			zap_page_range(hr_vma, entry->hidden_region_addrs[i], (hr_vma->vm_end - hr_vma->vm_start) * PAGE_SIZE);
			unmap_region(entry->hidden_region_addrs[i]);
			entry->hidden_region_addrs[i] = 0;
		}
	}
	pr_info("fsc_unregistration: hidden regions are deleted\n");
	fce_vma = find_fc_vma(entry->fce_region_addr);
	sr_vma = find_fc_vma(entry->secret_region_addr);

	zap_page_range(fce_vma, entry->fce_region_addr, (fce_vma->vm_end - fce_vma->vm_start) * PAGE_SIZE);
	zap_page_range(sr_vma, entry->secret_region_addr, (sr_vma->vm_end - sr_vma->vm_start) * PAGE_SIZE);

	unmap_region(entry->fce_region_addr);
	unmap_region(entry->secret_region_addr);

	entry->fce_region_addr = 0;
	entry->secret_region_addr = 0;


	fc_table->entries_size--;
	entry->nr_hidden_region_current = 0;
	entry->max_hidden_region = 0;

	pr_info("fsc_unregistration: end with no bug\n");


invalid_fce_entry:
	mutex_unlock(&fc_table->mutex);
	mmap_write_unlock(mm);
fail_lock:
	return ret;
}



// TO DO: initialize the tabel with VDSO
int initianlize_table(void)
{
	size_t i, j;


	pr_info("initianlize_table: function starts\n");
	fc_table = kmalloc(sizeof(struct fastcall_table), GFP_KERNEL);
	if (!fc_table) {
		pr_info("initianlize_table: failed to allocat memory for table\n");
		return -ENOMEM;
	}

	mutex_init(&fc_table->mutex);

	for (i = 0; i < NR_ENTRIES; i++) {
		fc_table->entries[i].fce_region_addr = 0;
		fc_table->entries[i].secret_region_addr = 0;
		fc_table->entries[i].max_hidden_region = 0;
		for (j = 0; j < NR_HIDDEN_REGION; j++)
			fc_table->entries[j].hidden_region_addrs[j] = 0;
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
unsigned long fce_regions_creation(struct page **fce_pages, int fce_pages_num, struct page **secret_pages,
int secret_pages_num, unsigned long offset, int max_hidden_region)
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

	if (!mutex_trylock(&fc_table->mutex)){
		pr_info("fce_regions_creation: fail_lock\n");
		ret = -1;
		goto fail_lock;
	}



	//BUG_ON(fc_table->entries_size >= NR_ENTRIES);
	if(fc_table->entries_size >= NR_ENTRIES) {
		pr_info("fce_regions_creation: can't have more fastcall \n");
		goto fail_creat_fce;
	}

	// find a proper virtual address region for yellow and purple box
	//fce_start_adr = get_unmapped_area(NULL, 0, (fce_pages_num + secret_pages_num) * PAGE_SIZE, 0, 0);
	fce_start_adr = get_randomized_address((fce_pages_num + secret_pages_num) * PAGE_SIZE, false);
	if (IS_ERR_VALUE(fce_start_adr)) {
		pr_info("fce_regions_creation: falied to find a unmapped area for fce_region, exec_only_region: %lx\n", fce_start_adr);
		ret = fce_start_adr;
		goto fail_get_free_vma_area;
	}

	secret_start_adr = fce_start_adr + PAGE_SIZE * fce_pages_num;
	pr_info("fce_regions_creation: fce_start_adr: %lx, secret_start_adr: %lx fce_function_offset:%lx \n",\
	 fce_start_adr, secret_start_adr, offset);

	ret = region_mapping(fce_pages, fce_pages_num, FCE_REGION_FLAG, fce_start_adr, false);
	if (ret != fce_start_adr) {
		pr_info("fastcall_register: falied to install fce mapping, ret = %lx, fce_start_adr = %lx\n", ret, fce_start_adr);
		goto fail_creat_vma;
	}


	// fast call entry address
	fce_start_adr += offset;


	//TODO: change it to VM_EXEC | VM_MAYEXEC
	ret = region_mapping(secret_pages, secret_pages_num, FCE_REGION_FLAG, secret_start_adr, false);
	if (ret != secret_start_adr) {
		pr_info("fce_regions_creation: falied to install exec_only_pages mapping, ret = %lx, secret_start_adr = %lx\n", ret, secret_start_adr);
		goto fail_creat_vma;
	}

	entry = find_entry(0);
	if (!entry) {
		pr_info("fce_regions_creation: can't creat fastcall entry anymore, there are too many\n");
		goto failed_find_entry;
	}

	//fc_table->entries_size++;

	entry->fce_region_addr = fce_start_adr;
	entry->secret_region_addr = secret_start_adr;
	entry->max_hidden_region = max_hidden_region;
	pr_info("fce_regions_creation: entry->fce_region_addr: = 0x%lx, entry->exect_region_addr  = 0x%lx\n", \
	entry->fce_region_addr, entry->secret_region_addr);


	pr_info("fce_regions_creation: function end with no bug\n");
	ret = fce_start_adr;
	mutex_unlock(&fc_table->mutex);
	return ret;

fail_lock:
	return ret;
fail_get_free_vma_area:
	mutex_unlock(&fc_table->mutex);
	pr_info("fce_regions_creation: function end with fail_get_free_vma_area\n");
	return ret;
fail_creat_vma:
	mutex_unlock(&fc_table->mutex);
	pr_info("fce_regions_creation: function end with fail_creat_vma \n");
	return ret;

fail_creat_fce:
	mutex_unlock(&fc_table->mutex);
	pr_info("fce_regions_creation: function end with fail_creat_fce, too many entrys \n");
failed_find_entry:
	unmap_region(fce_start_adr);
	unmap_region(secret_start_adr);
	return -1;

}
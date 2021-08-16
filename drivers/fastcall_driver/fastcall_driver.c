// SPDX-License-Identifier: GPL-2.0
/*
 * fastcall_examples.c - an example device driver which adds some fastcalls for testing and benchmarking
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <asm/pgtable.h>
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
#include <linux/minmax.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("An example device driver which adds some fastcalls for testing and benchmarking.");

#define FCE_DEVICE_NAME "fastcall-examples"
#define FCE_COMMAND_FASTCALL_REGISTRATION 0


/*
 * Function labels from fastcall_functions.S.
 */
const void fce_region_start(void);
const void fce_function(void);
const void fce_region_end(void);

const void secret_region_start(void);
const void sr_function(void);
const void secret_region_end(void);


/*
 * FCE_FUNCTION_SIZE - size of the fastcall function text segment in bytes
 */
#define FCE_FUNCTIONS_SIZE                                                     \
	((unsigned long)(fce_region_end - fce_region_start))
#define NR_FCE_PAGES ((FCE_FUNCTIONS_SIZE - 1) / PAGE_SIZE + 1)


/*
 * SR_FUNCTIONS_SIZE - size of the secret function text segment in bytes
 */
#define SR_FUNCTIONS_SIZE                                                     \
	((unsigned long)(secret_region_end - secret_region_start))
#define NR_SR_PAGES ((SR_FUNCTIONS_SIZE - 1) / PAGE_SIZE + 1)


static dev_t fce_dev;
static struct cdev *fce_cdev;
static struct class *fce_class;
static struct device *fce_device;
static struct page *fce_pages[1];
static struct page *sr_pages[1];





struct mesg {
		unsigned long fce_reg_addr;
		unsigned long secret_reg_addr;
		unsigned long hidden_reg_addr;
};


static unsigned long function_offset(const void (*fn)(void))
{
	return (fn - fce_region_start);
}


int fast_call_example(unsigned long __user user_address){
	struct page *hidden_pages[1];
	struct mm_struct *mm = current->mm;
	unsigned long fce_addr;
	unsigned long hidden_addr;
	unsigned long secret_addr;
	struct fastcall_entry *entry;
	int index;
	struct mesg message;
	int ret = 0;
	unsigned long test_value = 17132393680896;
	char *kernel_sr_addr = (char*)kmap(sr_pages[0]);
	unsigned long *test_pointer;

	if (mmap_write_lock_killable(mm))
		return -EINTR;
	test_pointer = (unsigned long *)(kernel_sr_addr+2);

	pr_info("fast_call_example: test_pointer address: %p, kernel_sr_addr: %p\n", (void *) test_pointer, (void *)kernel_sr_addr);
	*test_pointer = test_value;
	pr_info("fast_call_example: value of test_pointer : 0x%lx\n", *test_pointer);
	kunmap(sr_pages[0]);



	hidden_pages[0] = alloc_pages(FASTCALL_GPF, 0);

	memset(page_address(hidden_pages[0]), 'D', PAGE_SIZE);


	pr_info("fast_call_example: fastcall function offset: %lx\n", function_offset(fce_function));
	fce_addr = fce_regions_creation(fce_pages, 1, sr_pages, 1, function_offset(fce_function));
	if (IS_ERR((int)fce_addr) || fce_addr < 0 || IS_ERR_VALUE(fce_addr)) {
		pr_info("fast_call_example: falied to call fce_regions_creation, fce_addr = %lx\n", fce_addr);
		ret = -ENOMEM;
		goto fail_fce_creation;
	}

	hidden_addr = get_randomized_address(PAGE_SIZE);
	pr_info("fast_call_example: hidden_addr: %lx\n", hidden_addr);
	if (IS_ERR_VALUE(hidden_addr)) {
		pr_info("fast_call_example: falied to find a unmapped area for hidden box, fce_addr: %lx, hidden_addr: %lx\n", fce_addr, hidden_addr);
		ret = -ENOMEM;
		goto fail_get_free_vma_area;
	}



	ret = hidden_region_creatrion(fce_addr, hidden_pages, 1, hidden_addr);
	if (ret != 0) {
		pr_info("fast_call_example: hidden_region_creatrion falied ,ret = %lx\n", ret);
		ret = -ENOMEM;
		goto fail_creation_hidden_region;
	}

	index = fc_table->entries_size -1;

	entry = &fc_table->entries[index];
	if(!entry){
		pr_info("fast_call_example: can't get the entry for the system call\n");
		ret = -EINTR;
		goto fail_get_entry;
	}

	pr_info("fast_call_example: regions address of fastcall, fce_region:%lx, secrect_region:%lx, hidden_region:%lx\n", \
	entry->fce_region_addr, entry->exect_region_addr,  entry->hidden_region_addr);

	if(entry->fce_region_addr != fce_addr){
		pr_info("fast_call_example: fce_address diffrent ,fce_addr in driver: %lx, fce_addr in table: %lx \n", fce_addr, entry->fce_region_addr);
		ret = -EINTR;
		goto fail_addr_same;
	}

	

	if(entry->hidden_region_addr != hidden_addr){
		pr_info("fast_call_example: hidden_addr diffrent ,hidden_addr in driver: %lx, hidden_addr in table: %lx \n", hidden_addr, entry->hidden_region_addr);
		ret = -EINTR;
		goto fail_addr_same;
	}

	message.fce_reg_addr = fce_addr;
	message.hidden_reg_addr = hidden_addr;
	message.secret_reg_addr = entry->exect_region_addr;

	if (copy_to_user((void *)user_address, &message, sizeof(struct mesg))) {
		pr_info("fast_call_example: falied to copy message struct to user space,user_addr: %lx, fce_reg_addr: %lx, hidden_reg_addr: %lx, secret_reg_addr: %lx\n", user_address, message.fce_reg_addr, message.hidden_reg_addr, message.secret_reg_addr);
		ret = -EFAULT;
		goto fail_copy_user;
	}

fail_fce_creation:
fail_get_free_vma_area:
fail_creation_hidden_region:
fail_get_entry:
fail_addr_same:
fail_copy_user:
	mmap_write_unlock(mm);
	return ret;

}


/*
 * fce_open() - open the device
 * TODO: remove if it stays empty
 */
static int fce_open(struct inode *inode, struct file *file)
{
	// TODO decide if only device should only be opened writable
	// if (!(file->f_mode & FMODE_WRITE)) {
	// return -EACCES;
	// }

	return 0;
}

static long fce_ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	long ret = -EINVAL;

	switch (cmd) {
	case FCE_COMMAND_FASTCALL_REGISTRATION:
		pr_info("fce_ioctl: the cmd is FCE_COMMAND_FASTCALL_REGISTRATION\n");
		pr_info("fce_ioctl: user address: %lu\n", args);

		ret = fast_call_example(args);
		pr_info("fce_ioctl: fce_ioctl ended with ret: %lu\n", ret);
		break;
	default:
		pr_info("fce_ioctl: the input cmd didn't get any match\n");
		ret = -1;
	}

	return ret;
}

/*
 * fce_init() - initialize this module
 * Add one "fastcall-examples" character device.
 */
static int __init fce_init(void)
{

	int result, fce_page_id, sr_page_id;
	size_t fce_count, sr_count;
	void *fce_addr, *sr_addr;

	// TODO implement close to unregister fastcalls
	static struct file_operations fops = { .owner = THIS_MODULE,
					       .open = fce_open,
					       .unlocked_ioctl = fce_ioctl };


	// Allocate pages for example function and copy them
	BUG_ON(NR_FCE_PAGES != sizeof(fce_pages) / sizeof(struct page *));
	for (fce_page_id = 0; fce_page_id < NR_FCE_PAGES; fce_page_id++) {
		fce_pages[fce_page_id] = alloc_page(FASTCALL_GPF);
		if (!fce_pages[fce_page_id]) {
			pr_warn("fce: can't allocate function page");
			result = -ENOMEM;
			goto fail_fce_page_alloc;
		}
		fce_addr = kmap(fce_pages[fce_page_id]);
		fce_count = min(FCE_FUNCTIONS_SIZE - fce_page_id * PAGE_SIZE, PAGE_SIZE);
		memcpy(fce_addr, fce_region_start, fce_count);
		kunmap(fce_pages[fce_page_id]);
	}


		// Allocate pages for example function and copy them
	BUG_ON(NR_SR_PAGES != sizeof(sr_pages) / sizeof(struct page *));
	for (sr_page_id = 0; sr_page_id < NR_SR_PAGES; sr_page_id++) {
		sr_pages[sr_page_id] = alloc_page(FASTCALL_GPF);
		if (!sr_pages[sr_page_id]) {
			pr_warn("sr: can't allocate function page");
			result = -ENOMEM;
			goto fail_sr_page_alloc;
		}
		sr_addr = kmap(sr_pages[sr_page_id]);
		sr_count = min(SR_FUNCTIONS_SIZE - sr_page_id * PAGE_SIZE, PAGE_SIZE);
		memcpy(sr_addr, secret_region_start, sr_count);
		kunmap(sr_pages[sr_page_id]);
	}

	// Allocate one character device number with dynamic major number
	result = alloc_chrdev_region(&fce_dev, 0, 1, FCE_DEVICE_NAME);
	if (result < 0) {
		pr_warn("fce: can't allocate chrdev region");
		goto fail_chrdev;
	}

	// Allocate character device struct
	fce_cdev = cdev_alloc();
	if (fce_cdev == NULL) {
		pr_warn("fce: can't allocate struct cdev");
		result = -ENOMEM;
		goto fail_cdev_alloc;
	}
	fce_cdev->owner = THIS_MODULE;
	fce_cdev->ops = &fops;

	// Add the character device to the kernel
	result = cdev_add(fce_cdev, fce_dev, 1);
	if (result < 0) {
		pr_warn("fce: can't add character device");
		goto fail_cdev_add;
	}

	// Create a class for this device
	fce_class = class_create(THIS_MODULE, FCE_DEVICE_NAME);
	if (IS_ERR_VALUE(fce_class)) {
		pr_warn("fce: can't create class");
		result = PTR_ERR(fce_class);
		goto fail_class_create;
	}

	// Create a device so it can be linked in /dev/
	fce_device = device_create(fce_class, NULL, fce_dev, NULL, FCE_DEVICE_NAME);
	if (IS_ERR_VALUE(fce_device)) {
		pr_warn("fce: can't create device");
		result = PTR_ERR(fce_device);
		goto fail_device_create;
	}

	return 0;

	// Error handing
fail_device_create:
	class_destroy(fce_class);
fail_class_create:
fail_cdev_add:
	cdev_del(fce_cdev);
fail_cdev_alloc:
	unregister_chrdev_region(fce_dev, 1);

fail_sr_page_alloc:
	for (sr_page_id--; sr_page_id >= 0; sr_page_id--)
		__free_page(sr_pages[sr_page_id]);

fail_fce_page_alloc:
	for (fce_page_id--; fce_page_id >= 0; fce_page_id--)
		__free_page(fce_pages[fce_page_id]);


	return result;
fail_chrdev:
	return result;
}

static void __exit fce_exit(void)
{
	device_destroy(fce_class, fce_dev);
	class_destroy(fce_class);
	cdev_del(fce_cdev);
	unregister_chrdev_region(fce_dev, 1);
}

module_init(fce_init);
module_exit(fce_exit);
/*
 * kexec.c - kexec system call
 * Copyright (C) 2002-2004 Eric Biederman  <ebiederm@xmission.com>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <linux/capability.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/kexec.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/highmem.h>
#include <linux/syscalls.h>
#include <linux/reboot.h>
#include <linux/ioport.h>
#include <linux/hardirq.h>
#include <linux/elf.h>
#include <linux/elfcore.h>
#include <generated/utsrelease.h>
#include <linux/utsname.h>
#include <linux/numa.h>
#include <linux/suspend.h>
#include <linux/device.h>
#include <linux/freezer.h>
#include <linux/pm.h>
#include <linux/cpu.h>
#include <linux/console.h>
#include <linux/vmalloc.h>
#include <linux/swap.h>
#include <linux/syscore_ops.h>
#include <linux/delay.h>

#include <asm/page.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/system.h>
#include <asm/sections.h>
#include <linux/compiler.h>

#include <linux/module.h>	/* Specifically, a module */
#include <linux/cdev.h>

#include <linux/printk.h>

/* Syscall table */
void **sys_call_table;

/* original and new reboot syscall */
//asmlinkage long (*original_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg);
//extern asmlinkage long reboot(int magic1, int magic2, unsigned int cmd, void __user *arg);

#ifdef KEXEC_FLAGS
#undef KEXEC_FLAGS
#define KEXEC_FLAGS    (KEXEC_ON_CRASH | KEXEC_PRESERVE_CONTEXT | KEXEC_HARDBOOT)
#endif

/* KEXEC SYSFS */

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/init.h>

#define KERNEL_ATTRR_RO(_name) \
static struct kobj_attribute _name##_attr = __ATTR_RO(_name)

#define KERNEL_ATTRR_RW(_name) \
static struct kobj_attribute _name##_attr = \
	__ATTR(_name, 0644, _name##_show, _name##_store)

static ssize_t kexec_loaded_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!kexec_image);
}
KERNEL_ATTRR_RO(kexec_loaded);

static ssize_t kexec_crash_loaded_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!kexec_crash_image);
}
KERNEL_ATTRR_RO(kexec_crash_loaded);

static ssize_t kexec_crash_size_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%zu\n", crash_get_memory_size());
}
static ssize_t kexec_crash_size_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	unsigned long cnt;
	int ret;

	if (strict_strtoul(buf, 0, &cnt))
		return -EINVAL;

	ret = crash_shrink_memory(cnt);
	return ret < 0 ? ret : count;
}
KERNEL_ATTRR_RW(kexec_crash_size);

static ssize_t vmcoreinfo_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%lx %x\n",
		       paddr_vmcoreinfo_note(),
		       (unsigned int)vmcoreinfo_max_size);
}
KERNEL_ATTRR_RO(vmcoreinfo);

static struct attribute *attrs[] = {
	&kexec_loaded_attr.attr,
	&kexec_crash_loaded_attr.attr,
	&kexec_crash_size_attr.attr,
	&vmcoreinfo_attr.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static struct kobject *ksysfs_for_kexec;

static int __init ksysfs_for_kexec_init(void)
{
	int error = 0;

	ksysfs_for_kexec = kobject_get(kernel_kobj);

	if (!ksysfs_for_kexec) {
		printk("Kexec: Failed to get kernel sysfs!\n");
		error = -1;
		goto exit;
	}

	error = sysfs_create_group(ksysfs_for_kexec, &attr_group);
	if (error)
		printk("Kexec: failed to create sysfs interfaces!\n");
	else
		printk("Kexec: sysfs interfaces created sucesfully.\n");

exit:
	return error;
}

/* KEXEC SYSFS END */

/* KEXEC HARDBOOT ATAGS SPACE */

/*
 * Procedures for maintaining information about logical memory blocks.
 *
 * Peter Bergner, IBM Corp.	June 2001.
 * Copyright (C) 2001 Peter Bergner.
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/poison.h>
#include <linux/pfn.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/memblock.h>

struct memblock memblock __initdata_memblock;

int memblock_debug __initdata_memblock;
int memblock_can_resize __initdata_memblock;
static struct memblock_region memblock_memory_init_regions[INIT_MEMBLOCK_REGIONS + 1] __initdata_memblock;
static struct memblock_region memblock_reserved_init_regions[INIT_MEMBLOCK_REGIONS + 1] __initdata_memblock;

/* inline so we don't get a warning when pr_debug is compiled out */
static inline const char *memblock_type_name(struct memblock_type *type)
{
	if (type == &memblock.memory)
		return "memory";
	else if (type == &memblock.reserved)
		return "reserved";
	else
		return "unknown";
}

/*
 * Address comparison utilities
 */

static phys_addr_t __init_memblock memblock_align_down(phys_addr_t addr, phys_addr_t size)
{
	return addr & ~(size - 1);
}

static phys_addr_t __init_memblock memblock_align_up(phys_addr_t addr, phys_addr_t size)
{
	return (addr + (size - 1)) & ~(size - 1);
}

static unsigned long __init_memblock memblock_addrs_overlap(phys_addr_t base1, phys_addr_t size1,
				       phys_addr_t base2, phys_addr_t size2)
{
	return ((base1 < (base2 + size2)) && (base2 < (base1 + size1)));
}

long __init_memblock memblock_overlaps_region(struct memblock_type *type, phys_addr_t base, phys_addr_t size)
{
	unsigned long i;

	for (i = 0; i < type->cnt; i++) {
		phys_addr_t rgnbase = type->regions[i].base;
		phys_addr_t rgnsize = type->regions[i].size;
		if (memblock_addrs_overlap(base, size, rgnbase, rgnsize))
			break;
	}

	return (i < type->cnt) ? i : -1;
}

/*
 * Find, allocate, deallocate or reserve unreserved regions. All allocations
 * are top-down.
 */

static phys_addr_t __init_memblock memblock_find_region(phys_addr_t start, phys_addr_t end,
					  phys_addr_t size, phys_addr_t align)
{
	phys_addr_t base, res_base;
	long j;

	/* In case, huge size is requested */
	if (end < size)
		return MEMBLOCK_ERROR;

	base = memblock_align_down((end - size), align);

	/* Prevent allocations returning 0 as it's also used to
	 * indicate an allocation failure
	 */
	if (start == 0)
		start = PAGE_SIZE;

	while (start <= base) {
		j = memblock_overlaps_region(&memblock.reserved, base, size);
		if (j < 0)
			return base;
		res_base = memblock.reserved.regions[j].base;
		if (res_base < size)
			break;
		base = memblock_align_down(res_base - size, align);
	}

	return MEMBLOCK_ERROR;
}

static phys_addr_t __init_memblock memblock_find_base(phys_addr_t size,
			phys_addr_t align, phys_addr_t start, phys_addr_t end)
{
	long i;

	BUG_ON(0 == size);

	/* Pump up max_addr */
	if (end == MEMBLOCK_ALLOC_ACCESSIBLE)
		end = memblock.current_limit;

	/* We do a top-down search, this tends to limit memory
	 * fragmentation by keeping early boot allocs near the
	 * top of memory
	 */
	for (i = memblock.memory.cnt - 1; i >= 0; i--) {
		phys_addr_t memblockbase = memblock.memory.regions[i].base;
		phys_addr_t memblocksize = memblock.memory.regions[i].size;
		phys_addr_t bottom, top, found;

		if (memblocksize < size)
			continue;
		if ((memblockbase + memblocksize) <= start)
			break;
		bottom = max(memblockbase, start);
		top = min(memblockbase + memblocksize, end);
		if (bottom >= top)
			continue;
		found = memblock_find_region(bottom, top, size, align);
		if (found != MEMBLOCK_ERROR)
			return found;
	}
	return MEMBLOCK_ERROR;
}

/*
 * Find a free area with specified alignment in a specific range.
 */
u64 __init_memblock memblock_find_in_range(u64 start, u64 end, u64 size, u64 align)
{
	return memblock_find_base(size, align, start, end);
}

/*
 * Free memblock.reserved.regions
 */
int __init_memblock memblock_free_reserved_regions(void)
{
	if (memblock.reserved.regions == memblock_reserved_init_regions)
		return 0;

	return memblock_free(__pa(memblock.reserved.regions),
		 sizeof(struct memblock_region) * memblock.reserved.max);
}

/*
 * Reserve memblock.reserved.regions
 */
int __init_memblock memblock_reserve_reserved_regions(void)
{
	if (memblock.reserved.regions == memblock_reserved_init_regions)
		return 0;

	return memblock_reserve(__pa(memblock.reserved.regions),
		 sizeof(struct memblock_region) * memblock.reserved.max);
}

static void __init_memblock memblock_remove_region(struct memblock_type *type, unsigned long r)
{
	unsigned long i;

	for (i = r; i < type->cnt - 1; i++) {
		type->regions[i].base = type->regions[i + 1].base;
		type->regions[i].size = type->regions[i + 1].size;
	}
	type->cnt--;

	/* Special case for empty arrays */
	if (type->cnt == 0) {
		type->cnt = 1;
		type->regions[0].base = 0;
		type->regions[0].size = 0;
	}
}

/* Defined below but needed now */
static long memblock_add_region(struct memblock_type *type, phys_addr_t base, phys_addr_t size);

/*
 * chicken and egg problem: delay the per-cpu array allocation
 * until the general caches are up.
 */
static enum {
	NONE,
	PARTIAL_AC,
	PARTIAL_L3,
	EARLY,
	FULL
} g_cpucache_up;

/*
 * used by boot code to determine if it can use slab based allocator
 */
int slab_is_available_k(void)
{
	return g_cpucache_up >= EARLY;
}

static int __init_memblock memblock_double_array(struct memblock_type *type)
{
	struct memblock_region *new_array, *old_array;
	phys_addr_t old_size, new_size, addr;
	int use_slab = slab_is_available_k();

	/* We don't allow resizing until we know about the reserved regions
	 * of memory that aren't suitable for allocation
	 */
	if (!memblock_can_resize)
		return -1;

	/* Calculate new doubled size */
	old_size = type->max * sizeof(struct memblock_region);
	new_size = old_size << 1;

	/* Try to find some space for it.
	 *
	 * WARNING: We assume that either slab_is_available() and we use it or
	 * we use MEMBLOCK for allocations. That means that this is unsafe to use
	 * when bootmem is currently active (unless bootmem itself is implemented
	 * on top of MEMBLOCK which isn't the case yet)
	 *
	 * This should however not be an issue for now, as we currently only
	 * call into MEMBLOCK while it's still active, or much later when slab is
	 * active for memory hotplug operations
	 */
	if (use_slab) {
		new_array = kmalloc(new_size, GFP_KERNEL);
		addr = new_array == NULL ? MEMBLOCK_ERROR : __pa(new_array);
	} else
		addr = memblock_find_base(new_size, sizeof(phys_addr_t), 0, MEMBLOCK_ALLOC_ACCESSIBLE);
	if (addr == MEMBLOCK_ERROR) {
		pr_err("memblock: Failed to double %s array from %ld to %ld entries !\n",
		       memblock_type_name(type), type->max, type->max * 2);
		return -1;
	}
	new_array = __va(addr);

	memblock_dbg("memblock: %s array is doubled to %ld at [%#010llx-%#010llx]",
		 memblock_type_name(type), type->max * 2, (u64)addr, (u64)addr + new_size - 1);

	/* Found space, we now need to move the array over before
	 * we add the reserved region since it may be our reserved
	 * array itself that is full.
	 */
	memcpy(new_array, type->regions, old_size);
	memset(new_array + type->max, 0, old_size);
	old_array = type->regions;
	type->regions = new_array;
	type->max <<= 1;

	/* If we use SLAB that's it, we are done */
	if (use_slab)
		return 0;

	/* Add the new reserved region now. Should not fail ! */
	BUG_ON(memblock_add_region(&memblock.reserved, addr, new_size));

	/* If the array wasn't our static init one, then free it. We only do
	 * that before SLAB is available as later on, we don't know whether
	 * to use kfree or free_bootmem_pages(). Shouldn't be a big deal
	 * anyways
	 */
	if (old_array != memblock_memory_init_regions &&
	    old_array != memblock_reserved_init_regions)
		memblock_free(__pa(old_array), old_size);

	return 0;
}

extern int __init_memblock __weak memblock_memory_can_coalesce(phys_addr_t addr1, phys_addr_t size1,
					  phys_addr_t addr2, phys_addr_t size2)
{
	return 1;
}

static long __init_memblock memblock_add_region(struct memblock_type *type,
						phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size;
	int i, slot = -1;

	/* First try and coalesce this MEMBLOCK with others */
	for (i = 0; i < type->cnt; i++) {
		struct memblock_region *rgn = &type->regions[i];
		phys_addr_t rend = rgn->base + rgn->size;

		/* Exit if there's no possible hits */
		if (rgn->base > end || rgn->size == 0)
			break;

		/* Check if we are fully enclosed within an existing
		 * block
		 */
		if (rgn->base <= base && rend >= end)
			return 0;

		/* Check if we overlap or are adjacent with the bottom
		 * of a block.
		 */
		if (base < rgn->base && end >= rgn->base) {
			/* If we can't coalesce, create a new block */
			if (!memblock_memory_can_coalesce(base, size,
							  rgn->base,
							  rgn->size)) {
				/* Overlap & can't coalesce are mutually
				 * exclusive, if you do that, be prepared
				 * for trouble
				 */
				WARN_ON(end != rgn->base);
				goto new_block;
			}
			/* We extend the bottom of the block down to our
			 * base
			 */
			rgn->base = base;
			rgn->size = rend - base;

			/* Return if we have nothing else to allocate
			 * (fully coalesced)
			 */
			if (rend >= end)
				return 0;

			/* We continue processing from the end of the
			 * coalesced block.
			 */
			base = rend;
			size = end - base;
		}

		/* Now check if we overlap or are adjacent with the
		 * top of a block
		 */
		if (base <= rend && end >= rend) {
			/* If we can't coalesce, create a new block */
			if (!memblock_memory_can_coalesce(rgn->base,
							  rgn->size,
							  base, size)) {
				/* Overlap & can't coalesce are mutually
				 * exclusive, if you do that, be prepared
				 * for trouble
				 */
				WARN_ON(rend != base);
				goto new_block;
			}
			/* We adjust our base down to enclose the
			 * original block and destroy it. It will be
			 * part of our new allocation. Since we've
			 * freed an entry, we know we won't fail
			 * to allocate one later, so we won't risk
			 * losing the original block allocation.
			 */
			size += (base - rgn->base);
			base = rgn->base;
			memblock_remove_region(type, i--);
		}
	}

	/* If the array is empty, special case, replace the fake
	 * filler region and return
	 */
	if ((type->cnt == 1) && (type->regions[0].size == 0)) {
		type->regions[0].base = base;
		type->regions[0].size = size;
		return 0;
	}

 new_block:
	/* If we are out of space, we fail. It's too late to resize the array
	 * but then this shouldn't have happened in the first place.
	 */
	if (WARN_ON(type->cnt >= type->max))
		return -1;

	/* Couldn't coalesce the MEMBLOCK, so add it to the sorted table. */
	for (i = type->cnt - 1; i >= 0; i--) {
		if (base < type->regions[i].base) {
			type->regions[i+1].base = type->regions[i].base;
			type->regions[i+1].size = type->regions[i].size;
		} else {
			type->regions[i+1].base = base;
			type->regions[i+1].size = size;
			slot = i + 1;
			break;
		}
	}
	if (base < type->regions[0].base) {
		type->regions[0].base = base;
		type->regions[0].size = size;
		slot = 0;
	}
	type->cnt++;

	/* The array is full ? Try to resize it. If that fails, we undo
	 * our allocation and return an error
	 */
	if (type->cnt == type->max && memblock_double_array(type)) {
		BUG_ON(slot < 0);
		memblock_remove_region(type, slot);
		return -1;
	}

	return 0;
}

long __init_memblock memblock_add(phys_addr_t base, phys_addr_t size)
{
	return memblock_add_region(&memblock.memory, base, size);

}

static long __init_memblock __memblock_remove(struct memblock_type *type,
					      phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size;
	int i;

	/* Walk through the array for collisions */
	for (i = 0; i < type->cnt; i++) {
		struct memblock_region *rgn = &type->regions[i];
		phys_addr_t rend = rgn->base + rgn->size;

		/* Nothing more to do, exit */
		if (rgn->base > end || rgn->size == 0)
			break;

		/* If we fully enclose the block, drop it */
		if (base <= rgn->base && end >= rend) {
			memblock_remove_region(type, i--);
			continue;
		}

		/* If we are fully enclosed within a block
		 * then we need to split it and we are done
		 */
		if (base > rgn->base && end < rend) {
			rgn->size = base - rgn->base;
			if (!memblock_add_region(type, end, rend - end))
				return 0;
			/* Failure to split is bad, we at least
			 * restore the block before erroring
			 */
			rgn->size = rend - rgn->base;
			WARN_ON(1);
			return -1;
		}

		/* Check if we need to trim the bottom of a block */
		if (rgn->base < end && rend > end) {
			rgn->size -= end - rgn->base;
			rgn->base = end;
			break;
		}

		/* And check if we need to trim the top of a block */
		if (base < rend)
			rgn->size -= rend - base;

	}
	return 0;
}

long __init_memblock memblock_remove(phys_addr_t base, phys_addr_t size)
{
	return __memblock_remove(&memblock.memory, base, size);
}

long __init_memblock memblock_free(phys_addr_t base, phys_addr_t size)
{
	return __memblock_remove(&memblock.reserved, base, size);
}

long __init_memblock memblock_reserve(phys_addr_t base, phys_addr_t size)
{
	struct memblock_type *_rgn = &memblock.reserved;

	BUG_ON(0 == size);

	return memblock_add_region(_rgn, base, size);
}

phys_addr_t __init __memblock_alloc_base(phys_addr_t size, phys_addr_t align, phys_addr_t max_addr)
{
	phys_addr_t found;

	/* We align the size to limit fragmentation. Without this, a lot of
	 * small allocs quickly eat up the whole reserve array on sparc
	 */
	size = memblock_align_up(size, align);

	found = memblock_find_base(size, align, 0, max_addr);
	if (found != MEMBLOCK_ERROR &&
	    !memblock_add_region(&memblock.reserved, found, size))
		return found;

	return 0;
}

phys_addr_t __init memblock_alloc_base(phys_addr_t size, phys_addr_t align, phys_addr_t max_addr)
{
	phys_addr_t alloc;

	alloc = __memblock_alloc_base(size, align, max_addr);

	if (alloc == 0)
		panic("ERROR: Failed to allocate 0x%llx bytes below 0x%llx.\n",
		      (unsigned long long) size, (unsigned long long) max_addr);

	return alloc;
}

phys_addr_t __init memblock_alloc(phys_addr_t size, phys_addr_t align)
{
	return memblock_alloc_base(size, align, MEMBLOCK_ALLOC_ACCESSIBLE);
}


/*
 * Additional node-local allocators. Search for node memory is bottom up
 * and walks memblock regions within that node bottom-up as well, but allocation
 * within an memblock region is top-down. XXX I plan to fix that at some stage
 *
 * WARNING: Only available after early_node_map[] has been populated,
 * on some architectures, that is after all the calls to add_active_range()
 * have been done to populate it.
 */

phys_addr_t __weak __init memblock_nid_range(phys_addr_t start, phys_addr_t end, int *nid)
{
#ifdef CONFIG_ARCH_POPULATES_NODE_MAP
	/*
	 * This code originates from sparc which really wants use to walk by addresses
	 * and returns the nid. This is not very convenient for early_pfn_map[] users
	 * as the map isn't sorted yet, and it really wants to be walked by nid.
	 *
	 * For now, I implement the inefficient method below which walks the early
	 * map multiple times. Eventually we may want to use an ARCH config option
	 * to implement a completely different method for both case.
	 */
	unsigned long start_pfn, end_pfn;
	int i;

	for (i = 0; i < MAX_NUMNODES; i++) {
		get_pfn_range_for_nid(i, &start_pfn, &end_pfn);
		if (start < PFN_PHYS(start_pfn) || start >= PFN_PHYS(end_pfn))
			continue;
		*nid = i;
		return min(end, PFN_PHYS(end_pfn));
	}
#endif
	*nid = 0;

	return end;
}

static phys_addr_t __init memblock_alloc_nid_region(struct memblock_region *mp,
					       phys_addr_t size,
					       phys_addr_t align, int nid)
{
	phys_addr_t start, end;

	start = mp->base;
	end = start + mp->size;

	start = memblock_align_up(start, align);
	while (start < end) {
		phys_addr_t this_end;
		int this_nid;

		this_end = memblock_nid_range(start, end, &this_nid);
		if (this_nid == nid) {
			phys_addr_t ret = memblock_find_region(start, this_end, size, align);
			if (ret != MEMBLOCK_ERROR &&
			    !memblock_add_region(&memblock.reserved, ret, size))
				return ret;
		}
		start = this_end;
	}

	return MEMBLOCK_ERROR;
}

phys_addr_t __init memblock_alloc_nid(phys_addr_t size, phys_addr_t align, int nid)
{
	struct memblock_type *mem = &memblock.memory;
	int i;

	BUG_ON(0 == size);

	/* We align the size to limit fragmentation. Without this, a lot of
	 * small allocs quickly eat up the whole reserve array on sparc
	 */
	size = memblock_align_up(size, align);

	/* We do a bottom-up search for a region with the right
	 * nid since that's easier considering how memblock_nid_range()
	 * works
	 */
	for (i = 0; i < mem->cnt; i++) {
		phys_addr_t ret = memblock_alloc_nid_region(&mem->regions[i],
					       size, align, nid);
		if (ret != MEMBLOCK_ERROR)
			return ret;
	}

	return 0;
}

phys_addr_t __init memblock_alloc_try_nid(phys_addr_t size, phys_addr_t align, int nid)
{
	phys_addr_t res = memblock_alloc_nid(size, align, nid);

	if (res)
		return res;
	return memblock_alloc_base(size, align, MEMBLOCK_ALLOC_ANYWHERE);
}


/*
 * Remaining API functions
 */

/* You must call memblock_analyze() before this. */
phys_addr_t __init memblock_phys_mem_size(void)
{
	return memblock.memory_size;
}

phys_addr_t __init_memblock memblock_end_of_DRAM(void)
{
	int idx = memblock.memory.cnt - 1;

	return (memblock.memory.regions[idx].base + memblock.memory.regions[idx].size);
}

/* You must call memblock_analyze() after this. */
void __init memblock_enforce_memory_limit(phys_addr_t memory_limit)
{
	unsigned long i;
	phys_addr_t limit;
	struct memblock_region *p;

	if (!memory_limit)
		return;

	/* Truncate the memblock regions to satisfy the memory limit. */
	limit = memory_limit;
	for (i = 0; i < memblock.memory.cnt; i++) {
		if (limit > memblock.memory.regions[i].size) {
			limit -= memblock.memory.regions[i].size;
			continue;
		}

		memblock.memory.regions[i].size = limit;
		memblock.memory.cnt = i + 1;
		break;
	}

	memory_limit = memblock_end_of_DRAM();

	/* And truncate any reserves above the limit also. */
	for (i = 0; i < memblock.reserved.cnt; i++) {
		p = &memblock.reserved.regions[i];

		if (p->base > memory_limit)
			p->size = 0;
		else if ((p->base + p->size) > memory_limit)
			p->size = memory_limit - p->base;

		if (p->size == 0) {
			memblock_remove_region(&memblock.reserved, i);
			i--;
		}
	}
}

static int __init_memblock memblock_search(struct memblock_type *type, phys_addr_t addr)
{
	unsigned int left = 0, right = type->cnt;

	do {
		unsigned int mid = (right + left) / 2;

		if (addr < type->regions[mid].base)
			right = mid;
		else if (addr >= (type->regions[mid].base +
				  type->regions[mid].size))
			left = mid + 1;
		else
			return mid;
	} while (left < right);
	return -1;
}

int __init memblock_is_reserved(phys_addr_t addr)
{
	return memblock_search(&memblock.reserved, addr) != -1;
}

int __init_memblock memblock_is_memory(phys_addr_t addr)
{
	return memblock_search(&memblock.memory, addr) != -1;
}

int __init_memblock memblock_is_region_memory(phys_addr_t base, phys_addr_t size)
{
	int idx = memblock_search(&memblock.memory, base);

	if (idx == -1)
		return 0;
	return memblock.memory.regions[idx].base <= base &&
		(memblock.memory.regions[idx].base +
		 memblock.memory.regions[idx].size) >= (base + size);
}

int __init_memblock memblock_is_region_reserved(phys_addr_t base, phys_addr_t size)
{
	return memblock_overlaps_region(&memblock.reserved, base, size) >= 0;
}


void __init_memblock memblock_set_current_limit(phys_addr_t limit)
{
	memblock.current_limit = limit;
}

static void __init_memblock memblock_dump(struct memblock_type *region, char *name)
{
	unsigned long long base, size;
	int i;

	pr_info(" %s.cnt  = 0x%lx\n", name, region->cnt);

	for (i = 0; i < region->cnt; i++) {
		base = region->regions[i].base;
		size = region->regions[i].size;

		pr_info(" %s[%#x]\t[%#016llx-%#016llx], %#llx bytes\n",
		    name, i, base, base + size - 1, size);
	}
}

void __init_memblock memblock_dump_all(void)
{
	if (!memblock_debug)
		return;

	pr_info("MEMBLOCK configuration:\n");
	pr_info(" memory size = 0x%llx\n", (unsigned long long)memblock.memory_size);

	memblock_dump(&memblock.memory, "memory");
	memblock_dump(&memblock.reserved, "reserved");
}

void __init memblock_analyze(void)
{
	int i;

	/* Check marker in the unused last array entry */
	WARN_ON(memblock_memory_init_regions[INIT_MEMBLOCK_REGIONS].base
		!= (phys_addr_t)RED_INACTIVE);
	WARN_ON(memblock_reserved_init_regions[INIT_MEMBLOCK_REGIONS].base
		!= (phys_addr_t)RED_INACTIVE);

	memblock.memory_size = 0;

	for (i = 0; i < memblock.memory.cnt; i++)
		memblock.memory_size += memblock.memory.regions[i].size;

	/* We allow resizing from there */
	memblock_can_resize = 1;
}

void __init memblock_init(void)
{
	static int init_done __initdata = 0;

	if (init_done)
		return;
	init_done = 1;

	/* Hookup the initial arrays */
	memblock.memory.regions	= memblock_memory_init_regions;
	memblock.memory.max		= INIT_MEMBLOCK_REGIONS;
	memblock.reserved.regions	= memblock_reserved_init_regions;
	memblock.reserved.max	= INIT_MEMBLOCK_REGIONS;

	/* Write a marker in the unused last array entry */
	memblock.memory.regions[INIT_MEMBLOCK_REGIONS].base = (phys_addr_t)RED_INACTIVE;
	memblock.reserved.regions[INIT_MEMBLOCK_REGIONS].base = (phys_addr_t)RED_INACTIVE;

	/* Create a dummy zero size MEMBLOCK which will get coalesced away later.
	 * This simplifies the memblock_add() code below...
	 */
	memblock.memory.regions[0].base = 0;
	memblock.memory.regions[0].size = 0;
	memblock.memory.cnt = 1;

	/* Ditto. */
	memblock.reserved.regions[0].base = 0;
	memblock.reserved.regions[0].size = 0;
	memblock.reserved.cnt = 1;

	memblock.current_limit = MEMBLOCK_ALLOC_ANYWHERE;
}

memblock_debug = 1;

#if defined(CONFIG_DEBUG_FS) && !defined(ARCH_DISCARD_MEMBLOCK)

static int memblock_debug_show(struct seq_file *m, void *private)
{
	struct memblock_type *type = m->private;
	struct memblock_region *reg;
	int i;

	for (i = 0; i < type->cnt; i++) {
		reg = &type->regions[i];
		seq_printf(m, "%4d: ", i);
		if (sizeof(phys_addr_t) == 4)
			seq_printf(m, "0x%08lx..0x%08lx\n",
				   (unsigned long)reg->base,
				   (unsigned long)(reg->base + reg->size - 1));
		else
			seq_printf(m, "0x%016llx..0x%016llx\n",
				   (unsigned long long)reg->base,
				   (unsigned long long)(reg->base + reg->size - 1));

	}
	return 0;
}

static int memblock_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, memblock_debug_show, inode->i_private);
}

static const struct file_operations memblock_debug_fops = {
	.open = memblock_debug_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int __init memblock_init_debugfs(void)
{
	struct dentry *root = debugfs_create_dir("memblock", NULL);
	if (!root)
		return -ENXIO;
	debugfs_create_file("memory", S_IRUGO, root, &memblock.memory, &memblock_debug_fops);
	debugfs_create_file("reserved", S_IRUGO, root, &memblock.reserved, &memblock_debug_fops);

	return 0;
}
__initcall(memblock_init_debugfs);

#endif /* CONFIG_DEBUG_FS */

#include <linux/platform_device.h>
#include <linux/memblock.h>
#ifdef CONFIG_KEXEC_HARDBOOT
/*
	cat /proc/iomem
	00000000-05ffffff : System RAM
	00058000-008aae43 : Kernel text
	008ac000-00ed44c7 : Kernel data
	06000000-06efffff : db8500-trace-area
	08000000-09ffffff : System RAM
	0e800000-1fefffff : System RAM
	1ffe0000-1fffffff : ram_console
	40010000-400107ff : lcpa
	40010000-400107ff : dma40 I/O lcpa
	40080000-40081fff : lcla_esram
	80004000-80004fff : nmk-i2c.0
*/
#define KEXEC_HARDBOOT_START	0x1FF00000
#define KEXEC_HARDBOOT_SIZE	(0x1FFE0000 - KEXEC_HARDBOOT_START)

static struct resource kexec_hardboot_resources[] = {
	[0] = {
		.start  = KEXEC_HARDBOOT_START,
		.end    = KEXEC_HARDBOOT_START + KEXEC_HARDBOOT_SIZE - 1,
		.flags  = IORESOURCE_MEM,
	},
};

static struct platform_device kexec_hardboot_device = {
	.name	= "kexec_hardboot",
	.id	= -1,
};

static void kexec_hardboot_reserve(void) {
	memblock_init();

	if (memblock_reserve(KEXEC_HARDBOOT_START, KEXEC_HARDBOOT_SIZE)) {
		printk(KERN_ERR "Failed to reserve memory for KEXEC_HARDBOOT: "
				 "with size 0x%X at 0x%.8X\n",
				 KEXEC_HARDBOOT_SIZE, KEXEC_HARDBOOT_START);
		return;
	}
	else
		printk("Kexec hardboot mem space with size 0x%X at 0x%.8X allocated successful.\n",
				 KEXEC_HARDBOOT_SIZE, KEXEC_HARDBOOT_START);

	memblock_free(KEXEC_HARDBOOT_START, KEXEC_HARDBOOT_SIZE);
	memblock_remove(KEXEC_HARDBOOT_START, KEXEC_HARDBOOT_SIZE);

	kexec_hardboot_device.num_resources  = ARRAY_SIZE(kexec_hardboot_resources);
	kexec_hardboot_device.resource       = kexec_hardboot_resources;
}

static struct platform_device *kexec_devs[] = {
	&kexec_hardboot_device,
};
#endif

/* KEXEC HARDBOOT ATAGS SPACE END */

int cpu_architecture(void)
{
	int cpu_arch = CPU_ARCH_ARMv7;

	return cpu_arch;
}

/* Per cpu memory for storing cpu states in case of system crash. */
note_buf_t __percpu *crash_notes;

/* vmcoreinfo stuff */
static unsigned char vmcoreinfo_data[VMCOREINFO_BYTES];
u32 vmcoreinfo_note[VMCOREINFO_NOTE_SIZE/4];
size_t vmcoreinfo_size;
size_t vmcoreinfo_max_size = sizeof(vmcoreinfo_data);

ATOMIC_NOTIFIER_HEAD(crash_percpu_notifier_list);

/* Location of the reserved area for the crash kernel */
struct resource crashk_res = {
	.name  = "Crash kernel",
	.start = 0,
	.end   = 0,
	.flags = IORESOURCE_BUSY | IORESOURCE_MEM
};

int panic_on_oops;

int kexec_should_crash(struct task_struct *p)
{
	if (in_interrupt() || !p->pid || is_global_init(p) || panic_on_oops)
		return 1;
	return 0;
}

/*
 * When kexec transitions to the new kernel there is a one-to-one
 * mapping between physical and virtual addresses.  On processors
 * where you can disable the MMU this is trivial, and easy.  For
 * others it is still a simple predictable page table to setup.
 *
 * In that environment kexec copies the new kernel to its final
 * resting place.  This means I can only support memory whose
 * physical address can fit in an unsigned long.  In particular
 * addresses where (pfn << PAGE_SHIFT) > ULONG_MAX cannot be handled.
 * If the assembly stub has more restrictive requirements
 * KEXEC_SOURCE_MEMORY_LIMIT and KEXEC_DEST_MEMORY_LIMIT can be
 * defined more restrictively in <asm/kexec.h>.
 *
 * The code for the transition from the current kernel to the
 * the new kernel is placed in the control_code_buffer, whose size
 * is given by KEXEC_CONTROL_PAGE_SIZE.  In the best case only a single
 * page of memory is necessary, but some architectures require more.
 * Because this memory must be identity mapped in the transition from
 * virtual to physical addresses it must live in the range
 * 0 - TASK_SIZE, as only the user space mappings are arbitrarily
 * modifiable.
 *
 * The assembly stub in the control code buffer is passed a linked list
 * of descriptor pages detailing the source pages of the new kernel,
 * and the destination addresses of those source pages.  As this data
 * structure is not used in the context of the current OS, it must
 * be self-contained.
 *
 * The code has been made to work with highmem pages and will use a
 * destination page in its final resting place (if it happens
 * to allocate it).  The end product of this is that most of the
 * physical address space, and most of RAM can be used.
 *
 * Future directions include:
 *  - allocating a page table with the control code buffer identity
 *    mapped, to simplify machine_kexec and make kexec_on_panic more
 *    reliable.
 */

/*
 * KIMAGE_NO_DEST is an impossible destination address..., for
 * allocating pages whose destination address we do not care about.
 */
#define KIMAGE_NO_DEST (-1UL)

static int kimage_is_destination_range(struct kimage *image,
				       unsigned long start, unsigned long end);
static struct page *kimage_alloc_page(struct kimage *image,
				       gfp_t gfp_mask,
				       unsigned long dest);

static int do_kimage_alloc(struct kimage **rimage, unsigned long entry,
	                    unsigned long nr_segments,
                            struct kexec_segment __user *segments)
{
	size_t segment_bytes;
	struct kimage *image;
	unsigned long i;
	int result;

	/* Allocate a controlling structure */
	result = -ENOMEM;
	image = kzalloc(sizeof(*image), GFP_KERNEL);
	if (!image)
		goto out;

	image->head = 0;
	image->entry = &image->head;
	image->last_entry = &image->head;
	image->control_page = ~0; /* By default this does not apply */
	image->start = entry;
	image->type = KEXEC_TYPE_DEFAULT;

	/* Initialize the list of control pages */
	INIT_LIST_HEAD(&image->control_pages);

	/* Initialize the list of destination pages */
	INIT_LIST_HEAD(&image->dest_pages);

	/* Initialize the list of unusable pages */
	INIT_LIST_HEAD(&image->unuseable_pages);

	/* Read in the segments */
	image->nr_segments = nr_segments;
	segment_bytes = nr_segments * sizeof(*segments);
	result = copy_from_user(image->segment, segments, segment_bytes);
	if (result) {
		result = -EFAULT;
		goto out;
	}

	/*
	 * Verify we have good destination addresses.  The caller is
	 * responsible for making certain we don't attempt to load
	 * the new image into invalid or reserved areas of RAM.  This
	 * just verifies it is an address we can use.
	 *
	 * Since the kernel does everything in page size chunks ensure
	 * the destination addresses are page aligned.  Too many
	 * special cases crop of when we don't do this.  The most
	 * insidious is getting overlapping destination addresses
	 * simply because addresses are changed to page size
	 * granularity.
	 */
	result = -EADDRNOTAVAIL;
	for (i = 0; i < nr_segments; i++) {
		unsigned long mstart, mend;

		mstart = image->segment[i].mem;
		mend   = mstart + image->segment[i].memsz;
		if ((mstart & ~PAGE_MASK) || (mend & ~PAGE_MASK))
			goto out;
		if (mend >= KEXEC_DESTINATION_MEMORY_LIMIT)
			goto out;
	}

	/* Verify our destination addresses do not overlap.
	 * If we alloed overlapping destination addresses
	 * through very weird things can happen with no
	 * easy explanation as one segment stops on another.
	 */
	result = -EINVAL;
	for (i = 0; i < nr_segments; i++) {
		unsigned long mstart, mend;
		unsigned long j;

		mstart = image->segment[i].mem;
		mend   = mstart + image->segment[i].memsz;
		for (j = 0; j < i; j++) {
			unsigned long pstart, pend;
			pstart = image->segment[j].mem;
			pend   = pstart + image->segment[j].memsz;
			/* Do the segments overlap ? */
			if ((mend > pstart) && (mstart < pend))
				goto out;
		}
	}

	/* Ensure our buffer sizes are strictly less than
	 * our memory sizes.  This should always be the case,
	 * and it is easier to check up front than to be surprised
	 * later on.
	 */
	result = -EINVAL;
	for (i = 0; i < nr_segments; i++) {
		if (image->segment[i].bufsz > image->segment[i].memsz)
			goto out;
	}

	result = 0;
out:
	if (result == 0)
		*rimage = image;
	else
		kfree(image);

	return result;

}

static int kimage_normal_alloc(struct kimage **rimage, unsigned long entry,
				unsigned long nr_segments,
				struct kexec_segment __user *segments)
{
	int result;
	struct kimage *image;

	/* Allocate and initialize a controlling structure */
	image = NULL;
	result = do_kimage_alloc(&image, entry, nr_segments, segments);
	if (result)
		goto out;

	*rimage = image;

	/*
	 * Find a location for the control code buffer, and add it
	 * the vector of segments so that it's pages will also be
	 * counted as destination pages.
	 */
	result = -ENOMEM;
	image->control_code_page = kimage_alloc_control_pages(image,
					   get_order(KEXEC_CONTROL_PAGE_SIZE));
	if (!image->control_code_page) {
		printk(KERN_ERR "Could not allocate control_code_buffer\n");
		goto out;
	}

	image->swap_page = kimage_alloc_control_pages(image, 0);
	if (!image->swap_page) {
		printk(KERN_ERR "Could not allocate swap buffer\n");
		goto out;
	}

	result = 0;
 out:
	if (result == 0)
		*rimage = image;
	else
		kfree(image);

	return result;
}

static int kimage_crash_alloc(struct kimage **rimage, unsigned long entry,
				unsigned long nr_segments,
				struct kexec_segment __user *segments)
{
	int result;
	struct kimage *image;
	unsigned long i;

	image = NULL;
	/* Verify we have a valid entry point */
	if ((entry < crashk_res.start) || (entry > crashk_res.end)) {
		result = -EADDRNOTAVAIL;
		goto out;
	}

	/* Allocate and initialize a controlling structure */
	result = do_kimage_alloc(&image, entry, nr_segments, segments);
	if (result)
		goto out;

	/* Enable the special crash kernel control page
	 * allocation policy.
	 */
	image->control_page = crashk_res.start;
	image->type = KEXEC_TYPE_CRASH;

	/*
	 * Verify we have good destination addresses.  Normally
	 * the caller is responsible for making certain we don't
	 * attempt to load the new image into invalid or reserved
	 * areas of RAM.  But crash kernels are preloaded into a
	 * reserved area of ram.  We must ensure the addresses
	 * are in the reserved area otherwise preloading the
	 * kernel could corrupt things.
	 */
	result = -EADDRNOTAVAIL;
	for (i = 0; i < nr_segments; i++) {
		unsigned long mstart, mend;

		mstart = image->segment[i].mem;
		mend = mstart + image->segment[i].memsz - 1;
		/* Ensure we are within the crash kernel limits */
		if ((mstart < crashk_res.start) || (mend > crashk_res.end))
			goto out;
	}

	/*
	 * Find a location for the control code buffer, and add
	 * the vector of segments so that it's pages will also be
	 * counted as destination pages.
	 */
	result = -ENOMEM;
	image->control_code_page = kimage_alloc_control_pages(image,
					   get_order(KEXEC_CONTROL_PAGE_SIZE));
	if (!image->control_code_page) {
		printk(KERN_ERR "Could not allocate control_code_buffer\n");
		goto out;
	}

	result = 0;
out:
	if (result == 0)
		*rimage = image;
	else
		kfree(image);

	return result;
}

static int kimage_is_destination_range(struct kimage *image,
					unsigned long start,
					unsigned long end)
{
	unsigned long i;

	for (i = 0; i < image->nr_segments; i++) {
		unsigned long mstart, mend;

		mstart = image->segment[i].mem;
		mend = mstart + image->segment[i].memsz;
		if ((end > mstart) && (start < mend))
			return 1;
	}

	return 0;
}

static struct page *kimage_alloc_pages(gfp_t gfp_mask, unsigned int order)
{
	struct page *pages;

	pages = alloc_pages(gfp_mask, order);
	if (pages) {
		unsigned int count, i;
		pages->mapping = NULL;
		set_page_private(pages, order);
		count = 1 << order;
		for (i = 0; i < count; i++)
			SetPageReserved(pages + i);
	}

	return pages;
}

static void kimage_free_pages(struct page *page)
{
	unsigned int order, count, i;

	order = page_private(page);
	count = 1 << order;
	for (i = 0; i < count; i++)
		ClearPageReserved(page + i);
	__free_pages(page, order);
}

static void kimage_free_page_list(struct list_head *list)
{
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, list) {
		struct page *page;

		page = list_entry(pos, struct page, lru);
		list_del(&page->lru);
		kimage_free_pages(page);
	}
}

static struct page *kimage_alloc_normal_control_pages(struct kimage *image,
							unsigned int order)
{
	/* Control pages are special, they are the intermediaries
	 * that are needed while we copy the rest of the pages
	 * to their final resting place.  As such they must
	 * not conflict with either the destination addresses
	 * or memory the kernel is already using.
	 *
	 * The only case where we really need more than one of
	 * these are for architectures where we cannot disable
	 * the MMU and must instead generate an identity mapped
	 * page table for all of the memory.
	 *
	 * At worst this runs in O(N) of the image size.
	 */
	struct list_head extra_pages;
	struct page *pages;
	unsigned int count;

	count = 1 << order;
	INIT_LIST_HEAD(&extra_pages);

	/* Loop while I can allocate a page and the page allocated
	 * is a destination page.
	 */
	do {
		unsigned long pfn, epfn, addr, eaddr;

		pages = kimage_alloc_pages(GFP_KERNEL, order);
		if (!pages)
			break;
		pfn   = page_to_pfn(pages);
		epfn  = pfn + count;
		addr  = pfn << PAGE_SHIFT;
		eaddr = epfn << PAGE_SHIFT;
		if ((epfn >= (KEXEC_CONTROL_MEMORY_LIMIT >> PAGE_SHIFT)) ||
			      kimage_is_destination_range(image, addr, eaddr)) {
			list_add(&pages->lru, &extra_pages);
			pages = NULL;
		}
	} while (!pages);

	if (pages) {
		/* Remember the allocated page... */
		list_add(&pages->lru, &image->control_pages);

		/* Because the page is already in it's destination
		 * location we will never allocate another page at
		 * that address.  Therefore kimage_alloc_pages
		 * will not return it (again) and we don't need
		 * to give it an entry in image->segment[].
		 */
	}
	/* Deal with the destination pages I have inadvertently allocated.
	 *
	 * Ideally I would convert multi-page allocations into single
	 * page allocations, and add everything to image->dest_pages.
	 *
	 * For now it is simpler to just free the pages.
	 */
	kimage_free_page_list(&extra_pages);

	return pages;
}

static struct page *kimage_alloc_crash_control_pages(struct kimage *image,
						      unsigned int order)
{
	/* Control pages are special, they are the intermediaries
	 * that are needed while we copy the rest of the pages
	 * to their final resting place.  As such they must
	 * not conflict with either the destination addresses
	 * or memory the kernel is already using.
	 *
	 * Control pages are also the only pags we must allocate
	 * when loading a crash kernel.  All of the other pages
	 * are specified by the segments and we just memcpy
	 * into them directly.
	 *
	 * The only case where we really need more than one of
	 * these are for architectures where we cannot disable
	 * the MMU and must instead generate an identity mapped
	 * page table for all of the memory.
	 *
	 * Given the low demand this implements a very simple
	 * allocator that finds the first hole of the appropriate
	 * size in the reserved memory region, and allocates all
	 * of the memory up to and including the hole.
	 */
	unsigned long hole_start, hole_end, size;
	struct page *pages;

	pages = NULL;
	size = (1 << order) << PAGE_SHIFT;
	hole_start = (image->control_page + (size - 1)) & ~(size - 1);
	hole_end   = hole_start + size - 1;
	while (hole_end <= crashk_res.end) {
		unsigned long i;

		if (hole_end > KEXEC_CONTROL_MEMORY_LIMIT)
			break;
		if (hole_end > crashk_res.end)
			break;
		/* See if I overlap any of the segments */
		for (i = 0; i < image->nr_segments; i++) {
			unsigned long mstart, mend;

			mstart = image->segment[i].mem;
			mend   = mstart + image->segment[i].memsz - 1;
			if ((hole_end >= mstart) && (hole_start <= mend)) {
				/* Advance the hole to the end of the segment */
				hole_start = (mend + (size - 1)) & ~(size - 1);
				hole_end   = hole_start + size - 1;
				break;
			}
		}
		/* If I don't overlap any segments I have found my hole! */
		if (i == image->nr_segments) {
			pages = pfn_to_page(hole_start >> PAGE_SHIFT);
			break;
		}
	}
	if (pages)
		image->control_page = hole_end;

	return pages;
}


struct page *kimage_alloc_control_pages(struct kimage *image,
					 unsigned int order)
{
	struct page *pages = NULL;

	switch (image->type) {
	case KEXEC_TYPE_DEFAULT:
		pages = kimage_alloc_normal_control_pages(image, order);
		break;
	case KEXEC_TYPE_CRASH:
		pages = kimage_alloc_crash_control_pages(image, order);
		break;
	}

	return pages;
}

static int kimage_add_entry(struct kimage *image, kimage_entry_t entry)
{
	if (*image->entry != 0)
		image->entry++;

	if (image->entry == image->last_entry) {
		kimage_entry_t *ind_page;
		struct page *page;

		page = kimage_alloc_page(image, GFP_KERNEL, KIMAGE_NO_DEST);
		if (!page)
			return -ENOMEM;

		ind_page = page_address(page);
		*image->entry = virt_to_phys(ind_page) | IND_INDIRECTION;
		image->entry = ind_page;
		image->last_entry = ind_page +
				      ((PAGE_SIZE/sizeof(kimage_entry_t)) - 1);
	}
	*image->entry = entry;
	image->entry++;
	*image->entry = 0;

	return 0;
}

static int kimage_set_destination(struct kimage *image,
				   unsigned long destination)
{
	int result;

	destination &= PAGE_MASK;
	result = kimage_add_entry(image, destination | IND_DESTINATION);
	if (result == 0)
		image->destination = destination;

	return result;
}


static int kimage_add_page(struct kimage *image, unsigned long page)
{
	int result;

	page &= PAGE_MASK;
	result = kimage_add_entry(image, page | IND_SOURCE);
	if (result == 0)
		image->destination += PAGE_SIZE;

	return result;
}


static void kimage_free_extra_pages(struct kimage *image)
{
	/* Walk through and free any extra destination pages I may have */
	kimage_free_page_list(&image->dest_pages);

	/* Walk through and free any unusable pages I have cached */
	kimage_free_page_list(&image->unuseable_pages);

}
static void kimage_terminate(struct kimage *image)
{
	if (*image->entry != 0)
		image->entry++;

	*image->entry = IND_DONE;
}

#define for_each_kimage_entry(image, ptr, entry) \
	for (ptr = &image->head; (entry = *ptr) && !(entry & IND_DONE); \
		ptr = (entry & IND_INDIRECTION)? \
			phys_to_virt((entry & PAGE_MASK)): ptr +1)

static void kimage_free_entry(kimage_entry_t entry)
{
	struct page *page;

	page = pfn_to_page(entry >> PAGE_SHIFT);
	kimage_free_pages(page);
}

static void kimage_free(struct kimage *image)
{
	kimage_entry_t *ptr, entry;
	kimage_entry_t ind = 0;

	if (!image)
		return;

	kimage_free_extra_pages(image);
	for_each_kimage_entry(image, ptr, entry) {
		if (entry & IND_INDIRECTION) {
			/* Free the previous indirection page */
			if (ind & IND_INDIRECTION)
				kimage_free_entry(ind);
			/* Save this indirection page until we are
			 * done with it.
			 */
			ind = entry;
		}
		else if (entry & IND_SOURCE)
			kimage_free_entry(entry);
	}
	/* Free the final indirection page */
	if (ind & IND_INDIRECTION)
		kimage_free_entry(ind);

	/* Handle any machine specific cleanup */
	machine_kexec_cleanup(image);

	/* Free the kexec control pages... */
	kimage_free_page_list(&image->control_pages);
	kfree(image);
}

static kimage_entry_t *kimage_dst_used(struct kimage *image,
					unsigned long page)
{
	kimage_entry_t *ptr, entry;
	unsigned long destination = 0;

	for_each_kimage_entry(image, ptr, entry) {
		if (entry & IND_DESTINATION)
			destination = entry & PAGE_MASK;
		else if (entry & IND_SOURCE) {
			if (page == destination)
				return ptr;
			destination += PAGE_SIZE;
		}
	}

	return NULL;
}

static struct page *kimage_alloc_page(struct kimage *image,
					gfp_t gfp_mask,
					unsigned long destination)
{
	/*
	 * Here we implement safeguards to ensure that a source page
	 * is not copied to its destination page before the data on
	 * the destination page is no longer useful.
	 *
	 * To do this we maintain the invariant that a source page is
	 * either its own destination page, or it is not a
	 * destination page at all.
	 *
	 * That is slightly stronger than required, but the proof
	 * that no problems will not occur is trivial, and the
	 * implementation is simply to verify.
	 *
	 * When allocating all pages normally this algorithm will run
	 * in O(N) time, but in the worst case it will run in O(N^2)
	 * time.   If the runtime is a problem the data structures can
	 * be fixed.
	 */
	struct page *page;
	unsigned long addr;

	/*
	 * Walk through the list of destination pages, and see if I
	 * have a match.
	 */
	list_for_each_entry(page, &image->dest_pages, lru) {
		addr = page_to_pfn(page) << PAGE_SHIFT;
		if (addr == destination) {
			list_del(&page->lru);
			return page;
		}
	}
	page = NULL;
	while (1) {
		kimage_entry_t *old;

		/* Allocate a page, if we run out of memory give up */
		page = kimage_alloc_pages(gfp_mask, 0);
		if (!page)
			return NULL;
		/* If the page cannot be used file it away */
		if (page_to_pfn(page) >
				(KEXEC_SOURCE_MEMORY_LIMIT >> PAGE_SHIFT)) {
			list_add(&page->lru, &image->unuseable_pages);
			continue;
		}
		addr = page_to_pfn(page) << PAGE_SHIFT;

		/* If it is the destination page we want use it */
		if (addr == destination)
			break;

		/* If the page is not a destination page use it */
		if (!kimage_is_destination_range(image, addr,
						  addr + PAGE_SIZE))
			break;

		/*
		 * I know that the page is someones destination page.
		 * See if there is already a source page for this
		 * destination page.  And if so swap the source pages.
		 */
		old = kimage_dst_used(image, addr);
		if (old) {
			/* If so move it */
			unsigned long old_addr;
			struct page *old_page;

			old_addr = *old & PAGE_MASK;
			old_page = pfn_to_page(old_addr >> PAGE_SHIFT);
			copy_highpage(page, old_page);
			*old = addr | (*old & ~PAGE_MASK);

			/* The old page I have found cannot be a
			 * destination page, so return it if it's
			 * gfp_flags honor the ones passed in.
			 */
			if (!(gfp_mask & __GFP_HIGHMEM) &&
			    PageHighMem(old_page)) {
				kimage_free_pages(old_page);
				continue;
			}
			addr = old_addr;
			page = old_page;
			break;
		}
		else {
			/* Place the page on the destination list I
			 * will use it later.
			 */
			list_add(&page->lru, &image->dest_pages);
		}
	}

	return page;
}

static int kimage_load_normal_segment(struct kimage *image,
					 struct kexec_segment *segment)
{
	unsigned long maddr;
	unsigned long ubytes, mbytes;
	int result;
	unsigned char __user *buf;

	result = 0;
	buf = segment->buf;
	ubytes = segment->bufsz;
	mbytes = segment->memsz;
	maddr = segment->mem;

	result = kimage_set_destination(image, maddr);
	if (result < 0)
		goto out;

	while (mbytes) {
		struct page *page;
		char *ptr;
		size_t uchunk, mchunk;

		page = kimage_alloc_page(image, GFP_HIGHUSER, maddr);
		if (!page) {
			result  = -ENOMEM;
			goto out;
		}
		result = kimage_add_page(image, page_to_pfn(page)
								<< PAGE_SHIFT);
		if (result < 0)
			goto out;

		ptr = kmap(page);
		/* Start with a clear page */
		clear_page(ptr);
		ptr += maddr & ~PAGE_MASK;
		mchunk = PAGE_SIZE - (maddr & ~PAGE_MASK);
		if (mchunk > mbytes)
			mchunk = mbytes;

		uchunk = mchunk;
		if (uchunk > ubytes)
			uchunk = ubytes;

		result = copy_from_user(ptr, buf, uchunk);
		kunmap(page);
		if (result) {
			result = -EFAULT;
			goto out;
		}
		ubytes -= uchunk;
		maddr  += mchunk;
		buf    += mchunk;
		mbytes -= mchunk;
	}
out:
	return result;
}

static int kimage_load_crash_segment(struct kimage *image,
					struct kexec_segment *segment)
{
	/* For crash dumps kernels we simply copy the data from
	 * user space to it's destination.
	 * We do things a page at a time for the sake of kmap.
	 */
	unsigned long maddr;
	unsigned long ubytes, mbytes;
	int result;
	unsigned char __user *buf;

	result = 0;
	buf = segment->buf;
	ubytes = segment->bufsz;
	mbytes = segment->memsz;
	maddr = segment->mem;
	while (mbytes) {
		struct page *page;
		char *ptr;
		size_t uchunk, mchunk;

		page = pfn_to_page(maddr >> PAGE_SHIFT);
		if (!page) {
			result  = -ENOMEM;
			goto out;
		}
		ptr = kmap(page);
		ptr += maddr & ~PAGE_MASK;
		mchunk = PAGE_SIZE - (maddr & ~PAGE_MASK);
		if (mchunk > mbytes)
			mchunk = mbytes;

		uchunk = mchunk;
		if (uchunk > ubytes) {
			uchunk = ubytes;
			/* Zero the trailing part of the page */
			memset(ptr + uchunk, 0, mchunk - uchunk);
		}
		result = copy_from_user(ptr, buf, uchunk);
		kexec_flush_icache_page(page);
		kunmap(page);
		if (result) {
			result = -EFAULT;
			goto out;
		}
		ubytes -= uchunk;
		maddr  += mchunk;
		buf    += mchunk;
		mbytes -= mchunk;
	}
out:
	return result;
}

static int kimage_load_segment(struct kimage *image,
				struct kexec_segment *segment)
{
	int result = -ENOMEM;

	switch (image->type) {
	case KEXEC_TYPE_DEFAULT:
		result = kimage_load_normal_segment(image, segment);
		break;
	case KEXEC_TYPE_CRASH:
		result = kimage_load_crash_segment(image, segment);
		break;
	}

	return result;
}

/*
 * Exec Kernel system call: for obvious reasons only root may call it.
 *
 * This call breaks up into three pieces.
 * - A generic part which loads the new kernel from the current
 *   address space, and very carefully places the data in the
 *   allocated pages.
 *
 * - A generic part that interacts with the kernel and tells all of
 *   the devices to shut down.  Preventing on-going dmas, and placing
 *   the devices in a consistent state so a later kernel can
 *   reinitialize them.
 *
 * - A machine specific part that includes the syscall number
 *   and the copies the image to it's final destination.  And
 *   jumps into the image at entry.
 *
 * kexec does not sync, or unmount filesystems so if you need
 * that to happen you need to do that yourself.
 */
struct kimage *kexec_image;
struct kimage *kexec_crash_image;

static DEFINE_MUTEX(kexec_mutex);

asmlinkage long kexec_load(unsigned long entry, unsigned long nr_segments,
				 struct kexec_segment __user *segments, unsigned long flags)
{
	struct kimage **dest_image, *image;
	int result, i;
	printk("Kexec: - Starting kexec_load...\n");

	/* We only trust the superuser with rebooting the system. */
	if (!capable(CAP_SYS_BOOT)) {
		printk("Kexec: - capable(CAP_SYS_BOOT) : '%d'\n",capable(CAP_SYS_BOOT));
		return -EPERM;
	}

	/*
	 * Verify we have a legal set of flags
	 * This leaves us room for future extensions.
	 */
	if ((flags & KEXEC_FLAGS) != (flags & ~KEXEC_ARCH_MASK))
		return -EINVAL;

	/* Verify we are on the appropriate architecture */
	if (((flags & KEXEC_ARCH_MASK) != KEXEC_ARCH) &&
		((flags & KEXEC_ARCH_MASK) != KEXEC_ARCH_DEFAULT)) {
		printk("Kexec: - Bad appropriate architecture \n");
		return -EINVAL;
	}

	/* Put an artificial cap on the number
	 * of segments passed to kexec_load.
	 */
	if (nr_segments > KEXEC_SEGMENT_MAX)
		return -EINVAL;

	image = NULL;
	result = 0;

	/* Because we write directly to the reserved memory
	 * region when loading crash kernels we need a mutex here to
	 * prevent multiple crash  kernels from attempting to load
	 * simultaneously, and to prevent a crash kernel from loading
	 * over the top of a in use crash kernel.
	 *
	 * KISS: always take the mutex.
	 */
	if (!mutex_trylock(&kexec_mutex))
		return -EBUSY;

	dest_image = &kexec_image;
	if (flags & KEXEC_ON_CRASH)
		dest_image = &kexec_crash_image;
	if (nr_segments > 0) {
		unsigned long i;

		/* Loading another kernel to reboot into */
		if ((flags & KEXEC_ON_CRASH) == 0)
			result = kimage_normal_alloc(&image, entry,
							nr_segments, segments);
		/* Loading another kernel to switch to if this one crashes */
		else if (flags & KEXEC_ON_CRASH) {
			/* Free any current crash dump kernel before
			 * we corrupt it.
			 */
			kimage_free(xchg(&kexec_crash_image, NULL));
			result = kimage_crash_alloc(&image, entry,
						     nr_segments, segments);
		}
		if (result)
			goto out;

		if (flags & KEXEC_PRESERVE_CONTEXT)
			image->preserve_context = 1;
#ifdef CONFIG_KEXEC_HARDBOOT
		if (flags & KEXEC_HARDBOOT)
			image->hardboot = 1;
#endif
		result = machine_kexec_prepare(image);
		if (result)
			goto out;

		for (i = 0; i < nr_segments; i++) {
			result = kimage_load_segment(image, &image->segment[i]);
			if (result)
				goto out;
		}
		kimage_terminate(image);
	}
	/* Install the new kernel, and  Uninstall the old */
	image = xchg(dest_image, image);

out:
	mutex_unlock(&kexec_mutex);
	kimage_free(image);

	printk("Kexec: - ---- kexec_load - result : '%d'\n",result );
/*
	for (i=0; i<0x10000; ++i) {
		printk("0x%.2X", readb(0x1FF00000 + i));
	}
*/
	return result;
}

#ifdef CONFIG_COMPAT
asmlinkage long compat_sys_kexec_load(unsigned long entry,
				unsigned long nr_segments,
				struct compat_kexec_segment __user *segments,
				unsigned long flags)
{
	struct compat_kexec_segment in;
	struct kexec_segment out, __user *ksegments;
	unsigned long i, result;

	/* Don't allow clients that don't understand the native
	 * architecture to do anything.
	 */
	if ((flags & KEXEC_ARCH_MASK) == KEXEC_ARCH_DEFAULT)
		return -EINVAL;

	if (nr_segments > KEXEC_SEGMENT_MAX)
		return -EINVAL;

	ksegments = compat_alloc_user_space(nr_segments * sizeof(out));
	for (i=0; i < nr_segments; i++) {
		result = copy_from_user(&in, &segments[i], sizeof(in));
		if (result)
			return -EFAULT;

		out.buf   = compat_ptr(in.buf);
		out.bufsz = in.bufsz;
		out.mem   = in.mem;
		out.memsz = in.memsz;

		result = copy_to_user(&ksegments[i], &out, sizeof(out));
		if (result)
			return -EFAULT;
	}

	return sys_kexec_load(entry, nr_segments, ksegments, flags);
}
#endif

void crash_kexec(struct pt_regs *regs)
{
	struct pt_regs fixed_regs;
	/* Take the kexec_mutex here to prevent sys_kexec_load
	 * running on one cpu from replacing the crash kernel
	 * we are using after a panic on a different cpu.
	 *
	 * If the crash kernel was not located in a fixed area
	 * of memory the xchg(&kexec_crash_image) would be
	 * sufficient.  But since I reuse the memory...
	 */
	if (mutex_trylock(&kexec_mutex)) {
		if (kexec_crash_image) {

			crash_setup_regs(&fixed_regs, regs);
			crash_save_vmcoreinfo();
			machine_crash_shutdown(&fixed_regs);
			machine_kexec(kexec_crash_image);
		}
#ifdef CONFIG_CRASH_SWRESET
		else {
			crash_setup_regs(&fixed_regs, regs);
			crash_save_vmcoreinfo();
			machine_crash_shutdown(&fixed_regs);
			machine_crash_swreset();
		}
#endif
		mutex_unlock(&kexec_mutex);
	}
}

size_t crash_get_memory_size(void)
{
	size_t size = 0;
	mutex_lock(&kexec_mutex);
	if (crashk_res.end != crashk_res.start)
		size = crashk_res.end - crashk_res.start + 1;
	mutex_unlock(&kexec_mutex);
	return size;
}

void __weak crash_free_reserved_phys_range(unsigned long begin,
					   unsigned long end)
{
	unsigned long addr;

	for (addr = begin; addr < end; addr += PAGE_SIZE) {
		ClearPageReserved(pfn_to_page(addr >> PAGE_SHIFT));
		init_page_count(pfn_to_page(addr >> PAGE_SHIFT));
		free_page((unsigned long)__va(addr));
		totalram_pages++;
	}
}

int crash_shrink_memory(unsigned long new_size)
{
	int ret = 0;
	unsigned long start, end;

	mutex_lock(&kexec_mutex);

	if (kexec_crash_image) {
		ret = -ENOENT;
		goto unlock;
	}
	start = crashk_res.start;
	end = crashk_res.end;

	if (new_size >= end - start + 1) {
		ret = -EINVAL;
		if (new_size == end - start + 1)
			ret = 0;
		goto unlock;
	}

	start = roundup(start, PAGE_SIZE);
	end = roundup(start + new_size, PAGE_SIZE);

	crash_free_reserved_phys_range(end, crashk_res.end);

	if ((start == end) && (crashk_res.parent != NULL))
		release_resource(&crashk_res);
	crashk_res.end = end - 1;

unlock:
	mutex_unlock(&kexec_mutex);
	return ret;
}

static u32 *append_elf_note(u32 *buf, char *name, unsigned type, void *data,
			    size_t data_len)
{
	struct elf_note note;

	note.n_namesz = strlen(name) + 1;
	note.n_descsz = data_len;
	note.n_type   = type;
	memcpy(buf, &note, sizeof(note));
	buf += (sizeof(note) + 3)/4;
	memcpy(buf, name, note.n_namesz);
	buf += (note.n_namesz + 3)/4;
	memcpy(buf, data, note.n_descsz);
	buf += (note.n_descsz + 3)/4;

	return buf;
}

static void final_note(u32 *buf)
{
	struct elf_note note;

	note.n_namesz = 0;
	note.n_descsz = 0;
	note.n_type   = 0;
	memcpy(buf, &note, sizeof(note));
}

void crash_save_cpu(struct pt_regs *regs, int cpu)
{
	struct elf_prstatus prstatus;
	u32 *buf;

	if ((cpu < 0) || (cpu >= nr_cpu_ids))
		return;

	/* Using ELF notes here is opportunistic.
	 * I need a well defined structure format
	 * for the data I pass, and I need tags
	 * on the data to indicate what information I have
	 * squirrelled away.  ELF notes happen to provide
	 * all of that, so there is no need to invent something new.
	 */
	buf = (u32*)per_cpu_ptr(crash_notes, cpu);
	if (!buf)
		return;
	memset(&prstatus, 0, sizeof(prstatus));
	prstatus.pr_pid = current->pid;
	elf_core_copy_kernel_regs(&prstatus.pr_reg, regs);
	buf = append_elf_note(buf, KEXEC_CORE_NOTE_NAME, NT_PRSTATUS,
		      	      &prstatus, sizeof(prstatus));
	final_note(buf);
}

/*
 * parsing the "crashkernel" commandline
 *
 * this code is intended to be called from architecture specific code
 */


/*
 * This function parses command lines in the format
 *
 *   crashkernel=ramsize-range:size[,...][@offset]
 *
 * The function returns 0 on success and -EINVAL on failure.
 */
static int __init parse_crashkernel_mem(char 			*cmdline,
					unsigned long long	system_ram,
					unsigned long long	*crash_size,
					unsigned long long	*crash_base)
{
	char *cur = cmdline, *tmp;

	/* for each entry of the comma-separated list */
	do {
		unsigned long long start, end = ULLONG_MAX, size;

		/* get the start of the range */
		start = memparse(cur, &tmp);
		if (cur == tmp) {
			pr_warning("crashkernel: Memory value expected\n");
			return -EINVAL;
		}
		cur = tmp;
		if (*cur != '-') {
			pr_warning("crashkernel: '-' expected\n");
			return -EINVAL;
		}
		cur++;

		/* if no ':' is here, than we read the end */
		if (*cur != ':') {
			end = memparse(cur, &tmp);
			if (cur == tmp) {
				pr_warning("crashkernel: Memory "
						"value expected\n");
				return -EINVAL;
			}
			cur = tmp;
			if (end <= start) {
				pr_warning("crashkernel: end <= start\n");
				return -EINVAL;
			}
		}

		if (*cur != ':') {
			pr_warning("crashkernel: ':' expected\n");
			return -EINVAL;
		}
		cur++;

		size = memparse(cur, &tmp);
		if (cur == tmp) {
			pr_warning("Memory value expected\n");
			return -EINVAL;
		}
		cur = tmp;
		if (size >= system_ram) {
			pr_warning("crashkernel: invalid size\n");
			return -EINVAL;
		}

		/* match ? */
		if (system_ram >= start && system_ram < end) {
			*crash_size = size;
			break;
		}
	} while (*cur++ == ',');

	if (*crash_size > 0) {
		while (*cur && *cur != ' ' && *cur != '@')
			cur++;
		if (*cur == '@') {
			cur++;
			*crash_base = memparse(cur, &tmp);
			if (cur == tmp) {
				pr_warning("Memory value expected "
						"after '@'\n");
				return -EINVAL;
			}
		}
	}

	return 0;
}

/*
 * That function parses "simple" (old) crashkernel command lines like
 *
 * 	crashkernel=size[@offset]
 *
 * It returns 0 on success and -EINVAL on failure.
 */
static int __init parse_crashkernel_simple(char 		*cmdline,
					   unsigned long long 	*crash_size,
					   unsigned long long 	*crash_base)
{
	char *cur = cmdline;

	*crash_size = memparse(cmdline, &cur);
	if (cmdline == cur) {
		pr_warning("crashkernel: memory value expected\n");
		return -EINVAL;
	}

	if (*cur == '@')
		*crash_base = memparse(cur+1, &cur);

	return 0;
}

/*
 * That function is the entry point for command line parsing and should be
 * called from the arch-specific code.
 */
int __init parse_crashkernel(char 		 *cmdline,
			     unsigned long long system_ram,
			     unsigned long long *crash_size,
			     unsigned long long *crash_base)
{
	char 	*p = cmdline, *ck_cmdline = NULL;
	char	*first_colon, *first_space;

	BUG_ON(!crash_size || !crash_base);
	*crash_size = 0;
	*crash_base = 0;

	/* find crashkernel and use the last one if there are more */
	p = strstr(p, "crashkernel=");
	while (p) {
		ck_cmdline = p;
		p = strstr(p+1, "crashkernel=");
	}

	if (!ck_cmdline)
		return -EINVAL;

	ck_cmdline += 12; /* strlen("crashkernel=") */

	/*
	 * if the commandline contains a ':', then that's the extended
	 * syntax -- if not, it must be the classic syntax
	 */
	first_colon = strchr(ck_cmdline, ':');
	first_space = strchr(ck_cmdline, ' ');
	if (first_colon && (!first_space || first_colon < first_space))
		return parse_crashkernel_mem(ck_cmdline, system_ram,
				crash_size, crash_base);
	else
		return parse_crashkernel_simple(ck_cmdline, crash_size,
				crash_base);

	return 0;
}



void crash_save_vmcoreinfo(void)
{
	u32 *buf;

	if (!vmcoreinfo_size)
		return;

	vmcoreinfo_append_str("CRASHTIME=%ld", get_seconds());

	buf = (u32 *)vmcoreinfo_note;

	buf = append_elf_note(buf, VMCOREINFO_NOTE_NAME, 0, vmcoreinfo_data,
			      vmcoreinfo_size);

	final_note(buf);
}

void vmcoreinfo_append_str(const char *fmt, ...)
{
	va_list args;
	char buf[0x50];
	int r;

	va_start(args, fmt);
	r = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (r + vmcoreinfo_size > vmcoreinfo_max_size)
		r = vmcoreinfo_max_size - vmcoreinfo_size;

	memcpy(&vmcoreinfo_data[vmcoreinfo_size], buf, r);

	vmcoreinfo_size += r;
}

/*
 * provide an empty default implementation here -- architecture
 * code may override this
 */
void __attribute__ ((weak)) arch_crash_save_vmcoreinfo(void)
{}

unsigned long __attribute__ ((weak)) paddr_vmcoreinfo_note(void)
{
	return __pa((unsigned long)(char *)&vmcoreinfo_note);
}

#if defined(CONFIG_MACH_U8500_LOTUS) || defined(CONFIG_MACH_U8500_PEPPER) || defined(CONFIG_MACH_U8500_NYPON) || defined(CONFIG_MACH_U8500_KUMQUAT)
void (*machine_shutdown_k)(void) = (void *)0xc006077c;
#else
#error please searh in cat /proc/kallsyms for machine_shutdown!! If you can not see offsets, than do echo 1 > /proc/sys/kernel/kptr_restrict
#endif
extern void kernel_restart_prepare_k(char *cmd);

/*
 * Move into place and start executing a preloaded standalone
 * executable.  If nothing was preloaded return an error.
 */
int kernel_kexec(void)
{
	int error = 0;

	if (!mutex_trylock(&kexec_mutex))
		return -EBUSY;
	if (!kexec_image) {
		error = -EINVAL;
		goto Unlock;
	}

#ifdef CONFIG_KEXEC_JUMP
	if (kexec_image->preserve_context) {
		mutex_lock(&pm_mutex);
		pm_prepare_console();
		error = freeze_processes();
		if (error) {
			error = -EBUSY;
			goto Restore_console;
		}
		suspend_console();
		error = dpm_suspend_start(PMSG_FREEZE);
		if (error)
			goto Resume_console;
		/* At this point, dpm_suspend_start() has been called,
		 * but *not* dpm_suspend_noirq(). We *must* call
		 * dpm_suspend_noirq() now.  Otherwise, drivers for
		 * some devices (e.g. interrupt controllers) become
		 * desynchronized with the actual state of the
		 * hardware at resume time, and evil weirdness ensues.
		 */
		error = dpm_suspend_noirq(PMSG_FREEZE);
		if (error)
			goto Resume_devices;
		error = disable_nonboot_cpus();
		if (error)
			goto Enable_cpus;
		local_irq_disable();
		error = syscore_suspend();
		if (error)
			goto Enable_irqs;
	} else
#endif
	{
		kernel_restart_prepare_k(NULL);
		printk(KERN_EMERG "Starting new kernel\n");
		machine_shutdown_k();
	}

	machine_kexec(kexec_image);

#ifdef CONFIG_KEXEC_JUMP
	if (kexec_image->preserve_context) {
		syscore_resume();
Enable_irqs:
		local_irq_enable();
Enable_cpus:
		enable_nonboot_cpus();
		dpm_resume_noirq(PMSG_RESTORE);
Resume_devices:
		dpm_resume_end(PMSG_RESTORE);
Resume_console:
		resume_console();
		thaw_processes();
Restore_console:
		pm_restore_console();
		mutex_unlock(&pm_mutex);
	}
#endif

Unlock:
	mutex_unlock(&kexec_mutex);
	return error;
}
/*
static void xperia_reboot(void) {
	asm(
		"ldr r0,soft_reset_addr\n\t"
		"	mov r1, #1\n\t"
		"	str r1, [r0]\n\t"
		"\n\t"
		"soft_reset_addr:\n\t"
		"	.word 0x80157228"
	);
}
*/
extern asmlinkage long kexec_call_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg);
/*
static void __exit kexec_module_cleanup(void) {
	sysfs_remove_group(kernel_kobj, &attr_group);
	printk("Kexec: sysfs interfaces removed sucesfully.\n");
}
*/
static int __init kexec_module_init(void)
{
	printk("Kexec: Starting kexec_module...\n");

	/* create kexec sysfs interfaces */
	ksysfs_for_kexec_init();

	/* alocate mem space for kexec hardboot atags */
	platform_add_devices(kexec_devs,
				ARRAY_SIZE(kexec_devs));
	kexec_hardboot_reserve();

	sys_call_table=(void **)0xc005f944;

	/* Set kexec_load() syscall. */
	sys_call_table[__NR_kexec_load]=kexec_load;

	/* Swap reboot() syscall and store original */
	//original_reboot=sys_call_table[__NR_reboot];
	//sys_call_table[__NR_reboot]=reboot;
	sys_call_table[__NR_reboot]=kexec_call_reboot;

	/* crash_notes_memory_init */
	/* Allocate memory for saving cpu registers. */
	crash_notes = alloc_percpu(note_buf_t);
	if (!crash_notes) {
		printk("Kexec: Memory allocation for saving cpu register"
			" states failed\n");
		return -ENOMEM;
	}

	VMCOREINFO_OSRELEASE(init_uts_ns.name.release);
	VMCOREINFO_PAGESIZE(PAGE_SIZE);

	VMCOREINFO_SYMBOL(init_uts_ns);
	VMCOREINFO_SYMBOL(node_online_map);

#ifndef CONFIG_NEED_MULTIPLE_NODES
	VMCOREINFO_SYMBOL(mem_map);
	VMCOREINFO_SYMBOL(contig_page_data);
#endif
#ifdef CONFIG_SPARSEMEM
	VMCOREINFO_SYMBOL(mem_section);
	VMCOREINFO_LENGTH(mem_section, NR_SECTION_ROOTS);
	VMCOREINFO_STRUCT_SIZE(mem_section);
	VMCOREINFO_OFFSET(mem_section, section_mem_map);
#endif
	VMCOREINFO_STRUCT_SIZE(page);
	VMCOREINFO_STRUCT_SIZE(pglist_data);
	VMCOREINFO_STRUCT_SIZE(zone);
	VMCOREINFO_STRUCT_SIZE(free_area);
	VMCOREINFO_STRUCT_SIZE(list_head);
	VMCOREINFO_SIZE(nodemask_t);
	VMCOREINFO_OFFSET(page, flags);
	VMCOREINFO_OFFSET(page, _count);
	VMCOREINFO_OFFSET(page, mapping);
	VMCOREINFO_OFFSET(page, lru);
	VMCOREINFO_OFFSET(pglist_data, node_zones);
	VMCOREINFO_OFFSET(pglist_data, nr_zones);
#ifdef CONFIG_FLAT_NODE_MEM_MAP
	VMCOREINFO_OFFSET(pglist_data, node_mem_map);
#endif
	VMCOREINFO_OFFSET(pglist_data, node_start_pfn);
	VMCOREINFO_OFFSET(pglist_data, node_spanned_pages);
	VMCOREINFO_OFFSET(pglist_data, node_id);
	VMCOREINFO_OFFSET(zone, free_area);
	VMCOREINFO_OFFSET(zone, vm_stat);
	VMCOREINFO_OFFSET(zone, spanned_pages);
	VMCOREINFO_OFFSET(free_area, free_list);
	VMCOREINFO_OFFSET(list_head, next);
	VMCOREINFO_OFFSET(list_head, prev);
	VMCOREINFO_OFFSET(vm_struct, addr);
	VMCOREINFO_LENGTH(zone.free_area, MAX_ORDER);
	VMCOREINFO_LENGTH(free_area.free_list, MIGRATE_TYPES);
	VMCOREINFO_NUMBER(NR_FREE_PAGES);
	VMCOREINFO_NUMBER(PG_lru);
	VMCOREINFO_NUMBER(PG_private);
	VMCOREINFO_NUMBER(PG_swapcache);

	arch_crash_save_vmcoreinfo();

	return 0;
}

module_init(kexec_module_init);
//module_exit(kexec_module_cleanup);

MODULE_LICENSE("GPL");

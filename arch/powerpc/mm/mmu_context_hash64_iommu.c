/*
 *  IOMMU helpers in MMU context.
 *
 *  Copyright (C) 2015 IBM Corp. <aik@ozlabs.ru>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 *
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/rculist.h>
#include <linux/vmalloc.h>
#include <linux/kref.h>
#include <asm/mmu_context.h>

struct mm_iommu_table_group_mem_t {
	struct list_head next;
	struct rcu_head rcu;
	struct kref kref;	/* one reference per VFIO container */
	atomic_t mapped;	/* number of currently mapped pages */
	u64 ua;			/* userspace address */
	u64 entries;		/* number of entries in hpas[] */
	u64 *hpas;		/* vmalloc'ed */
};

bool mm_iommu_preregistered(void)
{
	if (!current || !current->mm)
		return false;

	return !list_empty(&current->mm->context.iommu_group_mem_list);
}
EXPORT_SYMBOL_GPL(mm_iommu_preregistered);

long mm_iommu_alloc(unsigned long ua, unsigned long entries,
		struct mm_iommu_table_group_mem_t **pmem)
{
	struct mm_iommu_table_group_mem_t *mem;
	long i, j;
	struct page *page = NULL;

	list_for_each_entry_rcu(mem, &current->mm->context.iommu_group_mem_list,
			next) {
		if ((mem->ua == ua) && (mem->entries == entries))
			return -EBUSY;

		/* Overlap? */
		if ((mem->ua < (ua + (entries << PAGE_SHIFT))) &&
				(ua < (mem->ua + (mem->entries << PAGE_SHIFT))))
			return -EINVAL;
	}

	mem = kzalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem)
		return -ENOMEM;

	mem->hpas = vzalloc(entries * sizeof(mem->hpas[0]));
	if (!mem->hpas) {
		kfree(mem);
		return -ENOMEM;
	}

	for (i = 0; i < entries; ++i) {
		if (1 != get_user_pages_fast(ua + (i << PAGE_SHIFT),
					1/* pages */, 1/* iswrite */, &page)) {
			for (j = 0; j < i; ++j)
				put_page(pfn_to_page(
						mem->hpas[j] >> PAGE_SHIFT));
			vfree(mem->hpas);
			kfree(mem);
			return -EFAULT;
		}

		mem->hpas[i] = page_to_pfn(page) << PAGE_SHIFT;
	}

	kref_init(&mem->kref);
	atomic_set(&mem->mapped, 0);
	mem->ua = ua;
	mem->entries = entries;
	*pmem = mem;

	list_add_rcu(&mem->next, &current->mm->context.iommu_group_mem_list);

	return 0;
}
EXPORT_SYMBOL_GPL(mm_iommu_alloc);

static void mm_iommu_unpin(struct mm_iommu_table_group_mem_t *mem)
{
	long i;
	struct page *page = NULL;

	for (i = 0; i < mem->entries; ++i) {
		if (!mem->hpas[i])
			continue;

		page = pfn_to_page(mem->hpas[i] >> PAGE_SHIFT);
		if (!page)
			continue;

		put_page(page);
		mem->hpas[i] = 0;
	}
}

static void mm_iommu_free(struct rcu_head *head)
{
	struct mm_iommu_table_group_mem_t *mem = container_of(head,
			struct mm_iommu_table_group_mem_t, rcu);

	mm_iommu_unpin(mem);
	vfree(mem->hpas);
	kfree(mem);
}

static void mm_iommu_release(struct kref *kref)
{
	struct mm_iommu_table_group_mem_t *mem = container_of(kref,
			struct mm_iommu_table_group_mem_t, kref);

	list_del_rcu(&mem->next);
	call_rcu(&mem->rcu, mm_iommu_free);
}

struct mm_iommu_table_group_mem_t *mm_iommu_get(unsigned long ua,
		unsigned long entries)
{
	struct mm_iommu_table_group_mem_t *mem;

	list_for_each_entry_rcu(mem, &current->mm->context.iommu_group_mem_list,
			next) {
		if ((mem->ua == ua) && (mem->entries == entries)) {
			kref_get(&mem->kref);
			return mem;
		}
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(mm_iommu_get);

long mm_iommu_put(struct mm_iommu_table_group_mem_t *mem)
{
	if (atomic_read(&mem->mapped))
		return -EBUSY;

	kref_put(&mem->kref, mm_iommu_release);

	return 0;
}
EXPORT_SYMBOL_GPL(mm_iommu_put);

struct mm_iommu_table_group_mem_t *mm_iommu_lookup(unsigned long ua,
		unsigned long size)
{
	struct mm_iommu_table_group_mem_t *mem, *ret = NULL;

	list_for_each_entry_rcu_notrace(mem,
			&current->mm->context.iommu_group_mem_list,
			next) {
		if ((mem->ua <= ua) &&
				(ua + size <= mem->ua +
				 (mem->entries << PAGE_SHIFT))) {
			ret = mem;
			break;
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(mm_iommu_lookup);

long mm_iommu_ua_to_hpa(struct mm_iommu_table_group_mem_t *mem,
		unsigned long ua, unsigned long *hpa)
{
	const long entry = (ua - mem->ua) >> PAGE_SHIFT;
	u64 *va = &mem->hpas[entry];

	if (entry >= mem->entries)
		return -EFAULT;

	*hpa = *va | (ua & ~PAGE_MASK);

	return 0;
}
EXPORT_SYMBOL_GPL(mm_iommu_ua_to_hpa);

long mm_iommu_rm_ua_to_hpa(struct mm_iommu_table_group_mem_t *mem,
		unsigned long ua, unsigned long *hpa)
{
	const long entry = (ua - mem->ua) >> PAGE_SHIFT;
	void *va = &mem->hpas[entry];
	unsigned long *ra;

	if (entry >= mem->entries)
		return -EFAULT;

	ra = real_vmalloc_addr(va);
	if (!ra)
		return -EFAULT;

	*hpa = *ra | (ua & ~PAGE_MASK);

	return 0;
}
EXPORT_SYMBOL_GPL(mm_iommu_rm_ua_to_hpa);

long mm_iommu_mapped_update(struct mm_iommu_table_group_mem_t *mem, bool inc)
{
	long ret = 0;

	if (inc)
		atomic_inc(&mem->mapped);
	else
		ret = atomic_dec_if_positive(&mem->mapped);

	return ret;
}
EXPORT_SYMBOL_GPL(mm_iommu_mapped_update);

void mm_iommu_cleanup(mm_context_t *ctx)
{
	while (!list_empty(&ctx->iommu_group_mem_list)) {
		struct mm_iommu_table_group_mem_t *mem;

		mem = list_first_entry(&ctx->iommu_group_mem_list,
				struct mm_iommu_table_group_mem_t, next);
		mm_iommu_release(&mem->kref);
	}
}

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright 2010 Paul Mackerras, IBM Corp. <paulus@au1.ibm.com>
 * Copyright 2011 David Gibson, IBM Corporation <dwg@au1.ibm.com>
 * Copyright 2013 Alexey Kardashevskiy, IBM Corporation <aik@au1.ibm.com>
 */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/highmem.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/hugetlb.h>
#include <linux/list.h>
#include <linux/anon_inodes.h>
#include <linux/iommu.h>

#include <asm/tlbflush.h>
#include <asm/kvm_ppc.h>
#include <asm/kvm_book3s.h>
#include <asm/mmu-hash64.h>
#include <asm/mmu_context.h>
#include <asm/hvcall.h>
#include <asm/synch.h>
#include <asm/ppc-opcode.h>
#include <asm/kvm_host.h>
#include <asm/udbg.h>
#include <asm/iommu.h>
#include <asm/tce.h>

static long kvmppc_stt_npages(unsigned long size)
{
	return ALIGN(size * sizeof(u64), PAGE_SIZE) / PAGE_SIZE;
}

static long kvmppc_account_memlimit(long npages, bool inc)
{
	long ret = 0;
	const long bytes = sizeof(struct kvmppc_spapr_tce_table) +
			(abs(npages) * sizeof(struct page *));
	const long stt_pages = ALIGN(bytes, PAGE_SIZE) / PAGE_SIZE;

	if (!current || !current->mm)
		return ret; /* process exited */

	npages += stt_pages;

	down_write(&current->mm->mmap_sem);

	if (inc) {
		long locked, lock_limit;

		locked = current->mm->locked_vm + npages;
		lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
		if (locked > lock_limit && !capable(CAP_IPC_LOCK))
			ret = -ENOMEM;
		else
			current->mm->locked_vm += npages;
	} else {
		if (npages > current->mm->locked_vm)
			npages = current->mm->locked_vm;

		current->mm->locked_vm -= npages;
	}

	pr_debug("[%d] RLIMIT_MEMLOCK KVM %c%ld %ld/%ld%s\n", current->pid,
			inc ? '+' : '-',
			npages << PAGE_SHIFT,
			current->mm->locked_vm << PAGE_SHIFT,
			rlimit(RLIMIT_MEMLOCK),
			ret ? " - exceeded" : "");

	up_write(&current->mm->mmap_sem);

	return ret;
}

static void release_spapr_tce_table(struct rcu_head *head)
{
	struct kvmppc_spapr_tce_table *stt = container_of(head,
			struct kvmppc_spapr_tce_table, rcu);
	long i, npages = kvmppc_stt_npages(stt->size);
	struct kvmppc_spapr_tce_group *kg;

	for (i = 0; i < npages; i++)
		__free_page(stt->pages[i]);

	while (!list_empty(&stt->groups)) {
		kg = list_first_entry(&stt->groups,
				struct kvmppc_spapr_tce_group, next);
		list_del(&kg->next);
		kfree(kg);
	}

	kfree(stt);
}

static int kvm_spapr_tce_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct kvmppc_spapr_tce_table *stt = vma->vm_file->private_data;
	struct page *page;

	if (vmf->pgoff >= kvmppc_stt_npages(stt->size))
		return VM_FAULT_SIGBUS;

	page = stt->pages[vmf->pgoff];
	get_page(page);
	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct kvm_spapr_tce_vm_ops = {
	.fault = kvm_spapr_tce_fault,
};

static int kvm_spapr_tce_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &kvm_spapr_tce_vm_ops;
	return 0;
}

static int kvm_spapr_tce_release(struct inode *inode, struct file *filp)
{
	struct kvmppc_spapr_tce_table *stt = filp->private_data;
	struct kvmppc_spapr_tce_group *kg;

	list_del_rcu(&stt->list);

	list_for_each_entry_rcu(kg, &stt->groups, next)	{
		iommu_group_put(kg->refgrp);
		kg->refgrp = NULL;
	}

	kvm_put_kvm(stt->kvm);

	kvmppc_account_memlimit(kvmppc_stt_npages(stt->size), false);
	call_rcu(&stt->rcu, release_spapr_tce_table);

	return 0;
}

static const struct file_operations kvm_spapr_tce_fops = {
	.mmap           = kvm_spapr_tce_mmap,
	.release	= kvm_spapr_tce_release,
};

extern long kvm_spapr_tce_attach_iommu_group(struct kvm *kvm,
				unsigned long liobn,
				phys_addr_t start_addr,
				struct iommu_group *grp)
{
	struct kvmppc_spapr_tce_table *stt = NULL;
	struct iommu_table_group *table_group;
	long i;
	bool found = false;
	struct kvmppc_spapr_tce_group *kg;
	struct iommu_table *tbltmp;

	/* Check this LIOBN hasn't been previously allocated */
	list_for_each_entry_rcu(stt, &kvm->arch.spapr_tce_tables, list) {
		if (stt->liobn == liobn) {
			if ((stt->offset << stt->page_shift) != start_addr)
				return -EINVAL;

			found = true;
			break;
		}
	}

	if (!found)
		return -ENODEV;

	/* Find IOMMU group and table at @start_addr */
	table_group = iommu_group_get_iommudata(grp);
	if (!table_group)
		return -EFAULT;

	tbltmp = NULL;
	for (i = 0; i < IOMMU_TABLE_GROUP_MAX_TABLES; ++i) {
		struct iommu_table *tbl = table_group->tables[i];

		if (!tbl)
			continue;

		if ((tbl->it_page_shift == stt->page_shift) &&
				(tbl->it_offset == stt->offset)) {
			tbltmp = tbl;
			break;
		}
	}
	if (!tbltmp)
		return -ENODEV;

	list_for_each_entry_rcu(kg, &stt->groups, next) {
		if (kg->refgrp == grp)
			return -EBUSY;
		/*
		 * Check if the table is in the list already.
		 * We might be dealing with 2 cases here:
		 * 1) shared IOMMU table for IODA2 - all groups will have
		 * the same actual table which only needs to be updated once
		 * so @stt must have tbl==NULL
		 * 2) invidual IOMMU tables (IODA1, P5IOC2) - each group has
		 * its own table.
		 */
		if (kg->tbl && (kg->tbl->it_base == tbltmp->it_base))
			tbltmp = NULL;
	}

	kg = kzalloc(sizeof(*kg), GFP_KERNEL);
	kg->refgrp = grp;
	kg->tbl = tbltmp;
	list_add_rcu(&kg->next, &stt->groups);

	return 0;
}

long kvm_vm_ioctl_create_spapr_tce(struct kvm *kvm,
				   struct kvm_create_spapr_tce_64 *args)
{
	struct kvmppc_spapr_tce_table *stt = NULL;
	long npages, size;
	int ret = -ENOMEM;
	int i;

	if (!args->size)
		return -EINVAL;

	/* Check this LIOBN hasn't been previously allocated */
	list_for_each_entry(stt, &kvm->arch.spapr_tce_tables, list) {
		if (stt->liobn == args->liobn)
			return -EBUSY;
	}

	size = args->size;
	npages = kvmppc_stt_npages(size);
	ret = kvmppc_account_memlimit(npages, true);
	if (ret) {
		stt = NULL;
		goto fail;
	}

	stt = kzalloc(sizeof(*stt) + npages * sizeof(struct page *),
		      GFP_KERNEL);
	if (!stt)
		goto fail;

	stt->liobn = args->liobn;
	stt->page_shift = args->page_shift;
	stt->offset = args->offset;
	stt->size = size;
	stt->kvm = kvm;
	INIT_LIST_HEAD_RCU(&stt->groups);

	for (i = 0; i < npages; i++) {
		stt->pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!stt->pages[i])
			goto fail;
	}

	kvm_get_kvm(kvm);

	mutex_lock(&kvm->lock);
	list_add_rcu(&stt->list, &kvm->arch.spapr_tce_tables);

	mutex_unlock(&kvm->lock);

	return anon_inode_getfd("kvm-spapr-tce", &kvm_spapr_tce_fops,
				stt, O_RDWR | O_CLOEXEC);

fail:
	if (stt) {
		for (i = 0; i < npages; i++)
			if (stt->pages[i])
				__free_page(stt->pages[i]);

		kfree(stt);
	}
	return ret;
}

static long kvmppc_tce_iommu_mapped_dec(struct iommu_table *tbl,
		unsigned long entry)
{
	struct mm_iommu_table_group_mem_t *mem = NULL;
	const unsigned long pgsize = 1ULL << tbl->it_page_shift;
	unsigned long *pua = IOMMU_TABLE_USERSPACE_ENTRY(tbl, entry);

	if (!pua)
		return H_HARDWARE;

	mem = mm_iommu_lookup(*pua, pgsize);
	if (!mem)
		return H_HARDWARE;

	mm_iommu_mapped_dec(mem);

	*pua = 0;

	return H_SUCCESS;
}

static long kvmppc_tce_iommu_unmap(struct iommu_table *tbl,
		unsigned long entry)
{
	enum dma_data_direction dir = DMA_NONE;
	unsigned long hpa = 0;

	if (iommu_tce_xchg_rm(tbl, entry, &hpa, &dir))
		return H_HARDWARE;

	if (dir == DMA_NONE)
		return H_SUCCESS;

	return kvmppc_tce_iommu_mapped_dec(tbl, entry);
}

long kvmppc_tce_iommu_map(struct kvm *kvm, struct iommu_table *tbl,
		unsigned long entry, unsigned long gpa,
		enum dma_data_direction dir)
{
	unsigned long hpa, ua;
	struct mm_iommu_table_group_mem_t *mem;
	long ret;
	unsigned long *pua = IOMMU_TABLE_USERSPACE_ENTRY(tbl, entry);

	if (!pua)
		return H_HARDWARE;

	if (kvmppc_gpa_to_ua(kvm, gpa, &ua, NULL))
		return H_HARDWARE;

	mem = mm_iommu_lookup(ua, 1ULL << tbl->it_page_shift);
	if (!mem)
		return H_HARDWARE;

	if (mm_iommu_ua_to_hpa(mem, ua, &hpa))
		return H_HARDWARE;

	if (mm_iommu_mapped_inc(mem))
		return H_HARDWARE;

	ret = iommu_tce_xchg(tbl, entry, &hpa, &dir);
	if (ret) {
		mm_iommu_mapped_dec(mem);
		return H_TOO_HARD;
	}

	if (dir != DMA_NONE)
		kvmppc_tce_iommu_mapped_dec(tbl, entry);

	*pua = ua;

	return 0;
}

long kvmppc_h_put_tce_iommu(struct kvm_vcpu *vcpu,
		struct iommu_table *tbl,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce)
{
	long idx, ret = H_HARDWARE;
	const unsigned long entry = ioba >> tbl->it_page_shift;
	const unsigned long gpa = tce & ~(TCE_PCI_READ | TCE_PCI_WRITE);
	const enum dma_data_direction dir = iommu_tce_direction(tce);

	/* Clear TCE */
	if (dir == DMA_NONE) {
		if (iommu_tce_clear_param_check(tbl, ioba, 0, 1))
			return H_PARAMETER;

		return kvmppc_tce_iommu_unmap(tbl, entry);
	}

	/* Put TCE */
	if (iommu_tce_put_param_check(tbl, ioba, tce))
		return H_PARAMETER;

	idx = srcu_read_lock(&vcpu->kvm->srcu);
	ret = kvmppc_tce_iommu_map(vcpu->kvm, tbl, entry, gpa, dir);
	srcu_read_unlock(&vcpu->kvm->srcu, idx);

	return ret;
}

static long kvmppc_h_put_tce_indirect_iommu(struct kvm_vcpu *vcpu,
		struct iommu_table *tbl, unsigned long ioba,
		u64 __user *tces, unsigned long npages)
{
	unsigned long i, ret;
	const unsigned long entry = ioba >> tbl->it_page_shift;
	unsigned long tce, gpa;

	for (i = 0; i < npages; ++i) {
		gpa = be64_to_cpu(tces[i]) & ~(TCE_PCI_READ | TCE_PCI_WRITE);

		if (iommu_tce_put_param_check(tbl, ioba +
				(i << tbl->it_page_shift),
				be64_to_cpu(tces[i])))
			return H_PARAMETER;
	}

	for (i = 0; i < npages; ++i) {
		tce = be64_to_cpu(tces[i]);
		gpa = tce & ~(TCE_PCI_READ | TCE_PCI_WRITE);

		ret = kvmppc_tce_iommu_map(vcpu->kvm, tbl, entry + i, gpa,
				iommu_tce_direction(tce));
		if (ret)
			return ret;
	}

	return H_SUCCESS;
}

long kvmppc_h_stuff_tce_iommu(struct kvm_vcpu *vcpu,
		struct iommu_table *tbl,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_value, unsigned long npages)
{
	unsigned long i;
	const unsigned long entry = ioba >> tbl->it_page_shift;

	if (iommu_tce_clear_param_check(tbl, ioba, tce_value, npages))
		return H_PARAMETER;

	for (i = 0; i < npages; ++i)
		kvmppc_tce_iommu_unmap(tbl, entry + i);

	return H_SUCCESS;
}

long kvmppc_h_put_tce(struct kvm_vcpu *vcpu,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce)
{
	long ret;
	struct kvmppc_spapr_tce_table *stt;
	struct kvmppc_spapr_tce_group *kg;

	stt = kvmppc_find_table(vcpu, liobn);
	if (!stt)
		return H_TOO_HARD;

	ret = kvmppc_ioba_validate(stt, ioba, 1);
	if (ret)
		return ret;

	ret = kvmppc_tce_validate(stt, tce);
	if (ret)
		return ret;

	list_for_each_entry_rcu_notrace(kg, &stt->groups, next) {
		if (!kg->tbl)
			continue;
		ret = kvmppc_h_put_tce_iommu(vcpu, kg->tbl, liobn, ioba, tce);
		if (ret)
			return ret;
	}

	kvmppc_tce_put(stt, ioba >> stt->page_shift, tce);

	return H_SUCCESS;
}
EXPORT_SYMBOL_GPL(kvmppc_h_put_tce);

long kvmppc_h_put_tce_indirect(struct kvm_vcpu *vcpu,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_list, unsigned long npages)
{
	struct kvmppc_spapr_tce_table *stt;
	long i, ret = H_SUCCESS, idx;
	unsigned long entry, ua = 0;
	u64 __user *tces, tce;
	struct kvmppc_spapr_tce_group *kg;

	stt = kvmppc_find_table(vcpu, liobn);
	if (!stt)
		return H_TOO_HARD;

	entry = ioba >> stt->page_shift;
	/*
	 * SPAPR spec says that the maximum size of the list is 512 TCEs
	 * so the whole table fits in 4K page
	 */
	if (npages > 512)
		return H_PARAMETER;

	if (tce_list & ~IOMMU_PAGE_MASK_4K)
		return H_PARAMETER;

	ret = kvmppc_ioba_validate(stt, ioba, npages);
	if (ret)
		return ret;

	idx = srcu_read_lock(&vcpu->kvm->srcu);
	if (kvmppc_gpa_to_ua(vcpu->kvm, tce_list, &ua, NULL)) {
		ret = H_TOO_HARD;
		goto unlock_exit;
	}
	tces = (u64 *) ua;

	list_for_each_entry_rcu_notrace(kg, &stt->groups, next) {
		if (!kg->tbl)
			continue;
		ret = kvmppc_h_put_tce_indirect_iommu(vcpu,
				kg->tbl, ioba, tces, npages);
		if (ret)
			goto unlock_exit;
	}

	for (i = 0; i < npages; ++i) {
		if (get_user(tce, tces + i)) {
			ret = H_PARAMETER;
			goto unlock_exit;
		}
		tce = be64_to_cpu(tce);

		ret = kvmppc_tce_validate(stt, tce);
		if (ret)
			goto unlock_exit;

		kvmppc_tce_put(stt, entry + i, tce);
	}

unlock_exit:
	srcu_read_unlock(&vcpu->kvm->srcu, idx);

	return ret;
}
EXPORT_SYMBOL_GPL(kvmppc_h_put_tce_indirect);

long kvmppc_h_stuff_tce(struct kvm_vcpu *vcpu,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_value, unsigned long npages)
{
	struct kvmppc_spapr_tce_table *stt;
	long i, ret;
	struct kvmppc_spapr_tce_group *kg;

	stt = kvmppc_find_table(vcpu, liobn);
	if (!stt)
		return H_TOO_HARD;

	ret = kvmppc_ioba_validate(stt, ioba, npages);
	if (ret)
		return ret;

	ret = kvmppc_tce_validate(stt, tce_value);
	if (ret || (tce_value & (TCE_PCI_WRITE | TCE_PCI_READ)))
		return H_PARAMETER;

	list_for_each_entry_rcu_notrace(kg, &stt->groups, next) {
		if (!kg->tbl)
			continue;
		ret = kvmppc_h_stuff_tce_iommu(vcpu, kg->tbl, liobn, ioba,
				tce_value, npages);
		if (ret)
			return ret;
	}

	for (i = 0; i < npages; ++i, ioba += (1 << stt->page_shift))
		kvmppc_tce_put(stt, ioba >> stt->page_shift, tce_value);

	return H_SUCCESS;
}
EXPORT_SYMBOL_GPL(kvmppc_h_stuff_tce);

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
#include <linux/module.h>
#include <linux/iommu.h>
#include <linux/file.h>

#include <asm/tlbflush.h>
#include <asm/kvm_ppc.h>
#include <asm/kvm_book3s.h>
#include <asm/mmu-hash64.h>
#include <asm/hvcall.h>
#include <asm/synch.h>
#include <asm/ppc-opcode.h>
#include <asm/kvm_host.h>
#include <asm/udbg.h>
#include <asm/iommu.h>
#include <asm/tce.h>

#define ERROR_ADDR      ((void *)~(unsigned long)0x0)

void kvmppc_iommu_iommu_grp_init(struct kvm_arch *ka)
{
	spin_lock_init(&ka->iommu_grp_write_lock);
	hash_init(ka->iommu_grp_hash_tab);
}
EXPORT_SYMBOL_GPL(kvmppc_iommu_iommu_grp_init);

static void free_kvm_group(struct kvmppc_spapr_iommu_grp *kgrp)
{
	hlist_del_rcu(&kgrp->hash_node);
	iommu_group_put(kgrp->grp);
	kfree(kgrp);
}

void kvmppc_iommu_iommu_grp_cleanup(struct kvm_arch *ka)
{
	int bkt;
	struct kvmppc_spapr_iommu_grp *kgrp;
	struct hlist_node *tmp;

	spin_lock(&ka->iommu_grp_write_lock);
	hash_for_each_safe(ka->iommu_grp_hash_tab, bkt, tmp, kgrp, hash_node) {
		free_kvm_group(kgrp);
	}
	spin_unlock(&ka->iommu_grp_write_lock);
}
EXPORT_SYMBOL_GPL(kvmppc_iommu_iommu_grp_cleanup);

static void kvmdev_release_group_callback(struct kvm *kvm, unsigned long liobn)
{
	struct kvm_arch *ka = &kvm->arch;
	int bkt;
	struct kvmppc_spapr_iommu_grp *kgrp;
	struct hlist_node *tmp;

	spin_lock(&ka->iommu_grp_write_lock);
	hash_for_each_safe(ka->iommu_grp_hash_tab, bkt, tmp, kgrp, hash_node) {
		if (kgrp->liobn == liobn) {
			free_kvm_group(kgrp);
			break;
		}
	}
	spin_unlock(&ka->iommu_grp_write_lock);
}

struct iommu_group *find_group_by_liobn(struct kvm *kvm, unsigned long liobn)
{
	struct iommu_group *grp;
	struct kvmppc_spapr_iommu_grp *kgrp;
	const unsigned key = KVMPPC_SPAPR_IOMMU_GRP_HASH(liobn);

	hash_for_each_possible_rcu_notrace(kvm->arch.iommu_grp_hash_tab, kgrp,
			hash_node, key) {
		if (kgrp->liobn == liobn)
			return kgrp->grp;
	}

	grp = kvm_vfio_find_group_by_liobn(kvm, liobn,
			kvmdev_release_group_callback);
	if (IS_ERR(grp))
		return NULL;

	kgrp = kzalloc(sizeof(*kgrp), GFP_KERNEL);
	if (!kgrp)
		return NULL;

	kgrp->liobn = liobn;
	kgrp->grp = grp;
	hash_add_rcu(kvm->arch.iommu_grp_hash_tab, &kgrp->hash_node, key);

	return grp;
}

static long kvmppc_stt_npages(unsigned long window_size)
{
	return ALIGN((window_size >> SPAPR_TCE_SHIFT)
		     * sizeof(u64), PAGE_SIZE) / PAGE_SIZE;
}

static long kvmppc_account_memlimit(long npages, bool inc)
{
	long stt_pages = ALIGN(sizeof(struct kvmppc_spapr_tce_table) +
			(abs(npages) * sizeof(struct page *)), PAGE_SIZE);

	npages += stt_pages;
	if (inc)
		return try_increment_locked_vm(npages);

	decrement_locked_vm(npages);

	return 0;
}

static void release_spapr_tce_table(struct kvmppc_spapr_tce_table *stt)
{
	struct kvm *kvm = stt->kvm;
	int i;
	long npages = kvmppc_stt_npages(stt->window_size);

	mutex_lock(&kvm->lock);
	list_del(&stt->list);
	for (i = 0; i < npages; i++)
		__free_page(stt->pages[i]);
	kfree(stt);
	mutex_unlock(&kvm->lock);

	kvm_put_kvm(kvm);

	kvmppc_account_memlimit(npages, false);
}

static int kvm_spapr_tce_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct kvmppc_spapr_tce_table *stt = vma->vm_file->private_data;
	struct page *page;

	if (vmf->pgoff >= kvmppc_stt_npages(stt->window_size))
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

	release_spapr_tce_table(stt);
	return 0;
}

static const struct file_operations kvm_spapr_tce_fops = {
	.mmap           = kvm_spapr_tce_mmap,
	.release	= kvm_spapr_tce_release,
};

long kvm_vm_ioctl_create_spapr_tce(struct kvm *kvm,
				   struct kvm_create_spapr_tce *args)
{
	struct kvmppc_spapr_tce_table *stt = NULL;
	long npages;
	int ret = -ENOMEM;
	int i;

	/* Check this LIOBN hasn't been previously allocated */
	struct iommu_group *grp = NULL;
	grp = find_group_by_liobn(kvm, args->liobn);
	if (grp)
		return -EBUSY;

	npages = kvmppc_stt_npages(args->window_size);
	ret = kvmppc_account_memlimit(npages, true);
	if (ret)
		goto fail;

	stt = kzalloc(sizeof(*stt) + npages * sizeof(struct page *),
		      GFP_KERNEL);
	if (!stt)
		goto fail;

	stt->type = KVMPPC_TCET_EMULATED;
	stt->liobn = args->liobn;
	stt->window_size = args->window_size;
	stt->kvm = kvm;

	for (i = 0; i < npages; i++) {
		stt->pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!stt->pages[i])
			goto fail;
	}

	kvm_get_kvm(kvm);

	mutex_lock(&kvm->lock);
	list_add(&stt->list, &kvm->arch.spapr_tce_tables);

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

/*
 * Converts guest physical address to host virtual address.
 * Also returns host physical address which is to put to TCE table.
 */
static void __user *kvmppc_gpa_to_hva_and_get(struct kvm_vcpu *vcpu,
		unsigned long gpa, struct page **pg, unsigned long *phpa)
{
	unsigned long hva, gfn = gpa >> PAGE_SHIFT;
	struct kvm_memory_slot *memslot;
	const int is_write = !!(gpa & TCE_PCI_WRITE);
	int idx = srcu_read_lock(&vcpu->kvm->srcu);

	memslot = search_memslots(kvm_memslots(vcpu->kvm), gfn);
	if (!memslot) {
		srcu_read_unlock(&vcpu->kvm->srcu, idx);
		return ERROR_ADDR;
	}

	hva = __gfn_to_hva_memslot(memslot, gfn) | (gpa & ~PAGE_MASK);
	srcu_read_unlock(&vcpu->kvm->srcu, idx);

	if (get_user_pages_fast(hva & PAGE_MASK, 1, is_write, pg) != 1)
		return ERROR_ADDR;

	if (phpa)
		*phpa = __pa((unsigned long) page_address(*pg)) |
				(hva & ~PAGE_MASK);

	return (void *) hva;
}

long kvmppc_h_put_tce_iommu(struct kvm_vcpu *vcpu,
		struct iommu_group *grp,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce)
{
	struct page *pg = NULL;
	unsigned long hpa;
	void __user *hva;
	struct iommu_table *tbl = iommu_group_get_iommudata(grp);

	if (!tbl)
		return H_RESCINDED;

	/* Clear TCE */
	if (!(tce & (TCE_PCI_READ | TCE_PCI_WRITE))) {
		if (iommu_tce_clear_param_check(tbl, ioba, 0, 1))
			return H_PARAMETER;

		if (iommu_free_tces(tbl, ioba >> IOMMU_PAGE_SHIFT_4K,
				1, false))
			return H_HARDWARE;

		return H_SUCCESS;
	}

	/* Put TCE */

	/* Real mode referenced the page but hpte changed during this operation */
	if (vcpu->arch.tce_rm_fail == TCERM_GETPAGE) {
		put_page(pfn_to_page(vcpu->arch.tce_tmp_hpas[0] >> PAGE_SHIFT));
		/* And try again */
	}
	vcpu->arch.tce_rm_fail = TCERM_NONE;

	if (iommu_tce_put_param_check(tbl, ioba, tce))
		return H_PARAMETER;

	hva = kvmppc_gpa_to_hva_and_get(vcpu, tce, &pg, &hpa);
	if (hva == ERROR_ADDR)
		return H_HARDWARE;

	if (!iommu_tce_build(tbl, ioba >> IOMMU_PAGE_SHIFT_4K, &hpa, 1, false))
		return H_SUCCESS;

	if (pg)
		put_page(pg);

	return H_HARDWARE;
}

static long kvmppc_h_put_tce_indirect_iommu(struct kvm_vcpu *vcpu,
		struct iommu_group *grp, unsigned long ioba,
		unsigned long __user *tces, unsigned long npages)
{
	long i;
	struct iommu_table *tbl = iommu_group_get_iommudata(grp);

	if (!tbl)
		return H_RESCINDED;

	if (vcpu->arch.tce_rm_fail == TCERM_GETPAGE) {
		unsigned long tmp;
		if (get_user(tmp, tces + vcpu->arch.tce_tmp_num))
			return H_HARDWARE;
		put_page(pfn_to_page(tmp >> PAGE_SHIFT));
	}

	for (i = vcpu->arch.tce_tmp_num; i < npages; ++i) {
		struct page *pg = NULL;
		unsigned long gpa;
		void __user *hva;

		if (get_user(gpa, tces + i))
			return H_HARDWARE;

		if (iommu_tce_put_param_check(tbl, ioba +
					(i << IOMMU_PAGE_SHIFT_4K), gpa))
			return H_PARAMETER;

		hva = kvmppc_gpa_to_hva_and_get(vcpu, gpa, &pg,
				&vcpu->arch.tce_tmp_hpas[i]);
		if (hva == ERROR_ADDR)
			goto putpages_flush_exit;
	}

	if (!iommu_tce_build(tbl, ioba >> IOMMU_PAGE_SHIFT_4K,
			vcpu->arch.tce_tmp_hpas, npages, false))
		return H_SUCCESS;

putpages_flush_exit:
	for (--i; i >= 0; --i) {
		struct page *pg;
		pg = pfn_to_page(vcpu->arch.tce_tmp_hpas[i] >> PAGE_SHIFT);
		if (pg)
			put_page(pg);
	}

	return H_HARDWARE;
}

long kvmppc_h_stuff_tce_iommu(struct kvm_vcpu *vcpu,
		struct iommu_group *grp,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_value, unsigned long npages)
{
	struct iommu_table *tbl = iommu_group_get_iommudata(grp);
	unsigned long entry = ioba >> IOMMU_PAGE_SHIFT_4K;

	if (!tbl)
		return H_RESCINDED;

	if (iommu_tce_clear_param_check(tbl, ioba, tce_value, npages))
		return H_PARAMETER;

	if (iommu_free_tces(tbl, entry, npages, false))
		return H_HARDWARE;

	return H_SUCCESS;
}

long kvmppc_h_put_tce(struct kvm_vcpu *vcpu,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce)
{
	long ret;
	struct kvmppc_spapr_tce_table *tt;
	struct iommu_group *grp = NULL;

	tt = kvmppc_find_tce_table(vcpu->kvm, liobn);
	if (!tt) {
		grp = find_group_by_liobn(vcpu->kvm, liobn);
		if (!grp)
			return H_TOO_HARD;
	}

	if (grp)
		return kvmppc_h_put_tce_iommu(vcpu, grp, liobn, ioba, tce);

	/* Emulated IO */
	if (ioba >= tt->window_size)
		return H_PARAMETER;

	ret = kvmppc_tce_validate(tce);
	if (ret)
		return ret;

	kvmppc_tce_put(tt, ioba, tce);

	return H_SUCCESS;
}
EXPORT_SYMBOL_GPL(kvmppc_h_put_tce);

long kvmppc_h_put_tce_indirect(struct kvm_vcpu *vcpu,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_list, unsigned long npages)
{
	struct kvmppc_spapr_tce_table *tt;
	long i, ret = H_SUCCESS;
	unsigned long __user *tces;
	struct page *pg = NULL;
	struct iommu_group *grp = NULL;

	tt = kvmppc_find_tce_table(vcpu->kvm, liobn);
	if (!tt) {
		grp = find_group_by_liobn(vcpu->kvm, liobn);
		if (!grp)
			return H_TOO_HARD;
	}

	/*
	 * The spec says that the maximum size of the list is 512 TCEs
	 * so the whole table addressed resides in 4K page
	 */
	if (npages > 512)
		return H_PARAMETER;

	if (tce_list & ~IOMMU_PAGE_MASK_4K)
		return H_PARAMETER;

	if (tt && ((ioba + (npages << IOMMU_PAGE_SHIFT_4K)) > tt->window_size))
		return H_PARAMETER;

	tces = kvmppc_gpa_to_hva_and_get(vcpu, tce_list, &pg, NULL);
	if (tces == ERROR_ADDR)
		return H_TOO_HARD;

	if ((vcpu->arch.tce_rm_fail != TCERM_NONE) && pg)
		put_page(pg);

	if (vcpu->arch.tce_rm_fail == TCERM_PUTLISTPAGE)
		goto put_list_page_exit;

	if (grp) {
		ret = kvmppc_h_put_tce_indirect_iommu(vcpu,
				grp, ioba, tces, npages);
		goto put_list_page_exit;
	}

	/* Emulated IO */
	for (i = 0; i < npages; ++i) {
		if (get_user(vcpu->arch.tce_tmp_hpas[i], tces + i)) {
			ret = H_PARAMETER;
			goto put_list_page_exit;
		}

		ret = kvmppc_tce_validate(vcpu->arch.tce_tmp_hpas[i]);
		if (ret)
			goto put_list_page_exit;
	}

	for (i = 0; i < npages; ++i)
		kvmppc_tce_put(tt, ioba + (i << IOMMU_PAGE_SHIFT_4K),
				vcpu->arch.tce_tmp_hpas[i]);
put_list_page_exit:
	if (pg)
		put_page(pg);

	return ret;
}
EXPORT_SYMBOL_GPL(kvmppc_h_put_tce_indirect);

long kvmppc_h_stuff_tce(struct kvm_vcpu *vcpu,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_value, unsigned long npages)
{
	struct kvmppc_spapr_tce_table *tt;
	long i, ret;
	struct iommu_group *grp = NULL;

	tt = kvmppc_find_tce_table(vcpu->kvm, liobn);
	if (!tt) {
		grp = find_group_by_liobn(vcpu->kvm, liobn);
		if (!grp)
			return H_TOO_HARD;
	}

	if (grp)
		return kvmppc_h_stuff_tce_iommu(vcpu, grp, liobn, ioba,
				tce_value, npages);

	/* Emulated IO */
	if ((ioba + (npages << IOMMU_PAGE_SHIFT_4K)) > tt->window_size)
		return H_PARAMETER;

	ret = kvmppc_tce_validate(tce_value);
	if (ret || (tce_value & (TCE_PCI_WRITE | TCE_PCI_READ)))
		return H_PARAMETER;

	for (i = 0; i < npages; ++i, ioba += IOMMU_PAGE_SIZE_4K)
		kvmppc_tce_put(tt, ioba, tce_value);

	return H_SUCCESS;
}
EXPORT_SYMBOL_GPL(kvmppc_h_stuff_tce);

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
#include <asm/iommu.h>

#define TCES_PER_PAGE	(PAGE_SIZE / sizeof(u64))

/*
 * Finds a TCE table descriptor by LIOBN.
 *
 * WARNING: This will be called in real or virtual mode on HV KVM and virtual
 *          mode on PR KVM
 */
struct kvmppc_spapr_tce_table *kvmppc_find_table(struct kvm_vcpu *vcpu,
		unsigned long liobn)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvmppc_spapr_tce_table *stt;

	list_for_each_entry_rcu_notrace(stt, &kvm->arch.spapr_tce_tables, list)
		if (stt->liobn == liobn)
			return stt;

	return NULL;
}
EXPORT_SYMBOL_GPL(kvmppc_find_table);

/*
 * Validates IO address.
 *
 * WARNING: This will be called in real-mode on HV KVM and virtual
 *          mode on PR KVM
 */
long kvmppc_ioba_validate(struct kvmppc_spapr_tce_table *stt,
		unsigned long ioba, unsigned long npages)
{
	unsigned long mask = (1 << stt->page_shift) - 1;
	unsigned long idx = ioba >> stt->page_shift;

	if ((ioba & mask) || (idx < stt->offset) ||
			(stt->offset + stt->size + npages <= idx))
		return H_PARAMETER;

	return H_SUCCESS;
}
EXPORT_SYMBOL_GPL(kvmppc_ioba_validate);

/*
 * Validates TCE address.
 * At the moment flags and page mask are validated.
 * As the host kernel does not access those addresses (just puts them
 * to the table and user space is supposed to process them), we can skip
 * checking other things (such as TCE is a guest RAM address or the page
 * was actually allocated).
 *
 * WARNING: This will be called in real-mode on HV KVM and virtual
 *          mode on PR KVM
 */
long kvmppc_tce_validate(struct kvmppc_spapr_tce_table *stt, unsigned long tce)
{
	unsigned long mask = ((1 << stt->page_shift) - 1) &
			~(TCE_PCI_WRITE | TCE_PCI_READ);

	if (tce & mask)
		return H_PARAMETER;

	return H_SUCCESS;
}
EXPORT_SYMBOL_GPL(kvmppc_tce_validate);

/* Note on the use of page_address() in real mode,
 *
 * It is safe to use page_address() in real mode on ppc64 because
 * page_address() is always defined as lowmem_page_address()
 * which returns __va(PFN_PHYS(page_to_pfn(page))) which is arithmetial
 * operation and does not access page struct.
 *
 * Theoretically page_address() could be defined different
 * but either WANT_PAGE_VIRTUAL or HASHED_PAGE_VIRTUAL
 * should be enabled.
 * WANT_PAGE_VIRTUAL is never enabled on ppc32/ppc64,
 * HASHED_PAGE_VIRTUAL could be enabled for ppc32 only and only
 * if CONFIG_HIGHMEM is defined. As CONFIG_SPARSEMEM_VMEMMAP
 * is not expected to be enabled on ppc32, page_address()
 * is safe for ppc32 as well.
 *
 * WARNING: This will be called in real-mode on HV KVM and virtual
 *          mode on PR KVM
 */
static u64 *kvmppc_page_address(struct page *page)
{
#if defined(HASHED_PAGE_VIRTUAL) || defined(WANT_PAGE_VIRTUAL)
#error TODO: fix to avoid page_address() here
#endif
	return (u64 *) page_address(page);
}

/*
 * Handles TCE requests for emulated devices.
 * Puts guest TCE values to the table and expects user space to convert them.
 * Called in both real and virtual modes.
 * Cannot fail so kvmppc_tce_validate must be called before it.
 *
 * WARNING: This will be called in real-mode on HV KVM and virtual
 *          mode on PR KVM
 */
void kvmppc_tce_put(struct kvmppc_spapr_tce_table *stt,
		unsigned long idx, unsigned long tce)
{
	struct page *page;
	u64 *tbl;

	idx -= stt->offset;
	page = stt->pages[idx / TCES_PER_PAGE];
	tbl = kvmppc_page_address(page);

	tbl[idx % TCES_PER_PAGE] = tce;
}
EXPORT_SYMBOL_GPL(kvmppc_tce_put);

long kvmppc_gpa_to_ua(struct kvm *kvm, unsigned long gpa,
		unsigned long *ua, unsigned long **prmap)
{
	unsigned long gfn = gpa >> PAGE_SHIFT;
	struct kvm_memory_slot *memslot;

	memslot = search_memslots(kvm_memslots(kvm), gfn);
	if (!memslot)
		return -EINVAL;

	*ua = __gfn_to_hva_memslot(memslot, gfn) |
		(gpa & ~(PAGE_MASK | TCE_PCI_READ | TCE_PCI_WRITE));

#ifdef CONFIG_KVM_BOOK3S_HV_POSSIBLE
	if (prmap)
		*prmap = real_vmalloc_addr(&memslot->arch.rmap[
				gfn - memslot->base_gfn]);
#endif

	return 0;
}
EXPORT_SYMBOL_GPL(kvmppc_gpa_to_ua);

#ifdef CONFIG_KVM_BOOK3S_HV_POSSIBLE
static mm_context_t *kvmppc_mm_context(struct kvm_vcpu *vcpu)
{
	struct task_struct *task;

	task = vcpu->arch.run_task;
	if (unlikely(!task || !task->mm))
		return NULL;

	return &task->mm->context;
}

static inline bool kvmppc_preregistered(struct kvm_vcpu *vcpu)
{
	mm_context_t *mm = kvmppc_mm_context(vcpu);

	if (unlikely(!mm))
		return false;

	return mm_iommu_preregistered(mm);
}

static struct mm_iommu_table_group_mem_t *kvmppc_rm_iommu_lookup(
		struct kvm_vcpu *vcpu, unsigned long ua, unsigned long size)
{
	mm_context_t *mm = kvmppc_mm_context(vcpu);

	if (unlikely(!mm))
		return NULL;

	return mm_iommu_lookup_rm(mm, ua, size);
}

static long kvmppc_rm_tce_iommu_mapped_dec(struct kvm_vcpu *vcpu,
		struct iommu_table *tbl, unsigned long entry)
{
	struct mm_iommu_table_group_mem_t *mem = NULL;
	const unsigned long pgsize = 1ULL << tbl->it_page_shift;
	unsigned long *pua = IOMMU_TABLE_USERSPACE_ENTRY(tbl, entry);

	if (!pua)
		return H_SUCCESS;

	pua = real_vmalloc_addr(pua);
	if (!pua)
		return H_SUCCESS;

	mem = kvmppc_rm_iommu_lookup(vcpu, *pua, pgsize);
	if (!mem)
		return H_HARDWARE;

	mm_iommu_mapped_dec(mem);

	*pua = 0;

	return H_SUCCESS;
}

static long kvmppc_rm_tce_iommu_unmap(struct kvm_vcpu *vcpu,
		struct iommu_table *tbl, unsigned long entry)
{
	enum dma_data_direction dir = DMA_NONE;
	unsigned long hpa = 0;

	if (iommu_tce_xchg_rm(tbl, entry, &hpa, &dir))
		return H_HARDWARE;

	if (dir == DMA_NONE)
		return H_SUCCESS;

	return kvmppc_rm_tce_iommu_mapped_dec(vcpu, tbl, entry);
}

long kvmppc_rm_tce_iommu_map(struct kvm_vcpu *vcpu, struct iommu_table *tbl,
		unsigned long entry, unsigned long gpa,
		enum dma_data_direction dir)
{
	unsigned long hpa = 0, ua;
	struct mm_iommu_table_group_mem_t *mem;
	unsigned long *pua = IOMMU_TABLE_USERSPACE_ENTRY(tbl, entry);
	long ret;

	if (kvmppc_gpa_to_ua(vcpu->kvm, gpa, &ua, NULL))
		return H_HARDWARE;

	mem = kvmppc_rm_iommu_lookup(vcpu, ua, 1ULL << tbl->it_page_shift);
	if (!mem)
		return H_HARDWARE;

	if (mm_iommu_rm_ua_to_hpa(mem, ua, &hpa))
		return H_HARDWARE;

	pua = real_vmalloc_addr(pua);
	if (!pua)
		return H_HARDWARE;

	if (mm_iommu_mapped_inc(mem))
		return H_HARDWARE;

	ret = iommu_tce_xchg_rm(tbl, entry, &hpa, &dir);
	if (ret) {
		mm_iommu_mapped_dec(mem);
		return H_TOO_HARD;
	}

	if (dir != DMA_NONE)
		kvmppc_rm_tce_iommu_mapped_dec(vcpu, tbl, entry);

	*pua = ua;

	return 0;
}
EXPORT_SYMBOL_GPL(kvmppc_rm_tce_iommu_map);

static long kvmppc_rm_h_put_tce_iommu(struct kvm_vcpu *vcpu,
		struct iommu_table *tbl, unsigned long liobn,
		unsigned long ioba, unsigned long tce)
{
	const unsigned long entry = ioba >> tbl->it_page_shift;
	const unsigned long gpa = tce & ~(TCE_PCI_READ | TCE_PCI_WRITE);
	const enum dma_data_direction dir = iommu_tce_direction(tce);

	/* Clear TCE */
	if (dir == DMA_NONE) {
		if (iommu_tce_clear_param_check(tbl, ioba, 0, 1))
			return H_PARAMETER;

		return kvmppc_rm_tce_iommu_unmap(vcpu, tbl, entry);
	}

	/* Put TCE */
	if (iommu_tce_put_param_check(tbl, ioba, gpa))
		return H_PARAMETER;

	return kvmppc_rm_tce_iommu_map(vcpu, tbl, entry, gpa, dir);
}

static long kvmppc_rm_h_put_tce_indirect_iommu(struct kvm_vcpu *vcpu,
		struct iommu_table *tbl, unsigned long ioba,
		u64 *tces, unsigned long npages)
{
	unsigned long i, ret;
	const unsigned long entry = ioba >> tbl->it_page_shift;
	unsigned long tce, gpa;

	for (i = 0; i < npages; ++i) {
		gpa = be64_to_cpu(tces[i]) & ~(TCE_PCI_READ | TCE_PCI_WRITE);

		if (iommu_tce_put_param_check(tbl, ioba +
				(i << tbl->it_page_shift), gpa))
			return H_PARAMETER;
	}

	for (i = 0; i < npages; ++i) {
		tce = be64_to_cpu(tces[i]);
		gpa = tce & ~(TCE_PCI_READ | TCE_PCI_WRITE);

		ret = kvmppc_rm_tce_iommu_map(vcpu, tbl, entry + i, gpa,
				iommu_tce_direction(tce));
		if (ret)
			return ret;
	}

	return H_SUCCESS;
}

static long kvmppc_rm_h_stuff_tce_iommu(struct kvm_vcpu *vcpu,
		struct iommu_table *tbl,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_value, unsigned long npages)
{
	unsigned long i;
	const unsigned long entry = ioba >> tbl->it_page_shift;

	if (iommu_tce_clear_param_check(tbl, ioba, tce_value, npages))
		return H_PARAMETER;

	for (i = 0; i < npages; ++i)
		kvmppc_rm_tce_iommu_unmap(vcpu, tbl, entry + i);

	return H_SUCCESS;
}

long kvmppc_rm_h_put_tce(struct kvm_vcpu *vcpu, unsigned long liobn,
		unsigned long ioba, unsigned long tce)
{
	struct kvmppc_spapr_tce_table *stt = kvmppc_find_table(vcpu, liobn);
	long ret = H_TOO_HARD;
	struct kvmppc_spapr_tce_group *kg;

	/* udbg_printf("H_PUT_TCE(): liobn=0x%lx ioba=0x%lx, tce=0x%lx\n", */
	/* 	    liobn, ioba, tce); */

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
		ret = kvmppc_rm_h_put_tce_iommu(vcpu, kg->tbl,
				liobn, ioba, tce);
		if (ret)
			return ret;
	}

	kvmppc_tce_put(stt, ioba >> stt->page_shift, tce);

	return ret;
}

static long kvmppc_rm_ua_to_hpa(struct kvm_vcpu *vcpu,
		unsigned long ua, unsigned long *phpa)
{
	pte_t *ptep, pte;
	unsigned shift = 0;

	ptep = __find_linux_pte_or_hugepte(vcpu->arch.pgdir, ua, &shift);
	if (!ptep || !pte_present(*ptep))
		return -ENXIO;
	pte = *ptep;

	if (!shift)
		shift = PAGE_SHIFT;

	/* Avoid handling anything potentially complicated in realmode */
	if (shift > PAGE_SHIFT)
		return -EAGAIN;

	if (!pte_young(pte))
		return -EAGAIN;

	*phpa = (pte_pfn(pte) << PAGE_SHIFT) | (ua & ((1 << shift) - 1)) |
			(ua & ~PAGE_MASK);

	return 0;
}

long kvmppc_rm_h_put_tce_indirect(struct kvm_vcpu *vcpu,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_list,	unsigned long npages)
{
	struct kvmppc_spapr_tce_table *stt;
	long i, ret = H_SUCCESS;
	unsigned long tces, entry, ua = 0;
	unsigned long *rmap = NULL;

	stt = kvmppc_find_table(vcpu, liobn);
	if (!stt)
		return H_TOO_HARD;

	entry = ioba >> stt->page_shift;
	/*
	 * The spec says that the maximum size of the list is 512 TCEs
	 * so the whole table addressed resides in 4K page
	 */
	if (npages > 512)
		return H_PARAMETER;

	if (tce_list & ~IOMMU_PAGE_MASK_4K)
		return H_PARAMETER;

	ret = kvmppc_ioba_validate(stt, ioba, npages);
	if (ret)
		return ret;

	if (kvmppc_preregistered(vcpu)) {
		/*
		 * We get here if guest memory was pre-registered which
		 * is normally VFIO case and gpa->hpa translation does not
		 * depend on hpt.
		 */
		struct mm_iommu_table_group_mem_t *mem;
		struct kvmppc_spapr_tce_group *kg;

		if (kvmppc_gpa_to_ua(vcpu->kvm, tce_list, &ua, NULL))
			return H_TOO_HARD;

		mem = kvmppc_rm_iommu_lookup(vcpu, ua, IOMMU_PAGE_SIZE_4K);
		if (!mem || mm_iommu_rm_ua_to_hpa(mem, ua, &tces))
			return H_TOO_HARD;


		list_for_each_entry_rcu_notrace(kg, &stt->groups, next) {
			if (!kg->tbl)
				continue;
			ret = kvmppc_rm_h_put_tce_indirect_iommu(vcpu,
					kg->tbl, ioba, (u64 *)tces, npages);
			if (ret)
				return ret;
		}
	} else {
		/*
		 * This is emulated devices case.
		 * We do not require memory to be preregistered in this case
		 * so lock rmap and do __find_linux_pte_or_hugepte().
		 */
		if (kvmppc_gpa_to_ua(vcpu->kvm, tce_list, &ua, &rmap))
			return H_TOO_HARD;

		lock_rmap(rmap);
		if (kvmppc_rm_ua_to_hpa(vcpu, ua, &tces)) {
			ret = H_TOO_HARD;
			goto unlock_exit;
		}
	}

	for (i = 0; i < npages; ++i) {
		unsigned long tce = be64_to_cpu(((u64 *)tces)[i]);

		ret = kvmppc_tce_validate(stt, tce);
		if (ret)
			goto unlock_exit;

		kvmppc_tce_put(stt, entry + i, tce);
	}

unlock_exit:
	if (rmap)
		unlock_rmap(rmap);

	return ret;
}

long kvmppc_rm_h_stuff_tce(struct kvm_vcpu *vcpu,
		unsigned long liobn, unsigned long ioba,
		unsigned long tce_value, unsigned long npages)
{
	struct kvmppc_spapr_tce_table *stt;
	struct kvmppc_spapr_tce_group *kg;
	long i, ret;

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
		ret = kvmppc_rm_h_stuff_tce_iommu(vcpu, kg->tbl,
				liobn, ioba, tce_value, npages);
		if (ret)
			return ret;
	}

	for (i = 0; i < npages; ++i, ioba += (1 << stt->page_shift))
		kvmppc_tce_put(stt, ioba >> stt->page_shift, tce_value);

	return H_SUCCESS;
}

long kvmppc_h_get_tce(struct kvm_vcpu *vcpu, unsigned long liobn,
		      unsigned long ioba)
{
	struct kvmppc_spapr_tce_table *stt = kvmppc_find_table(vcpu, liobn);
	long ret = H_TOO_HARD;


	if (stt) {
		ret = kvmppc_ioba_validate(stt, ioba, 1);
		if (!ret) {
			unsigned long idx = (ioba >> stt->page_shift) -
				stt->offset;
			struct page *page = stt->pages[idx / TCES_PER_PAGE];
			u64 *tbl = (u64 *)page_address(page);

			vcpu->arch.gpr[4] = tbl[idx % TCES_PER_PAGE];
		}
	}


	return ret;
}
EXPORT_SYMBOL_GPL(kvmppc_h_get_tce);

#endif /* KVM_BOOK3S_HV_POSSIBLE */

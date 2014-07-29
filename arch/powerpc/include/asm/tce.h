/*
 * Copyright (C) 2001 Mike Corrigan & Dave Engebretsen, IBM Corporation
 * Rewrite, cleanup:
 * Copyright (C) 2004 Olof Johansson <olof@lixom.net>, IBM Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#ifndef _ASM_POWERPC_TCE_H
#define _ASM_POWERPC_TCE_H
#ifdef __KERNEL__

#include <asm/iommu.h>

/*
 * Tces come in two formats, one for the virtual bus and a different
 * format for PCI.  PCI TCEs can have hardware or software maintianed
 * coherency.
 */
#define TCE_VB			0
#define TCE_PCI			1
#define TCE_PCI_SWINV_CREATE	2
#define TCE_PCI_SWINV_FREE	4
#define TCE_PCI_SWINV_PAIR	8

/* TCE page size is 4096 bytes (1 << 12) */

#define TCE_SHIFT	12
#define TCE_PAGE_SIZE	(1 << TCE_SHIFT)

#define TCE_ENTRY_SIZE		8		/* each TCE is 64 bits */

#define TCE_RPN_MASK		0xfffffffffful  /* 40-bit RPN (4K pages) */
#define TCE_RPN_SHIFT		12
#define TCE_VALID		0x800		/* TCE valid */
#define TCE_ALLIO		0x400		/* TCE valid for all lpars */
#define TCE_PCI_WRITE		0x2		/* write from PCI allowed */
#define TCE_PCI_READ		0x1		/* read from PCI allowed */
#define TCE_VB_WRITE		0x1		/* write from VB allowed */

struct spapr_tce_iommu_group;

#define TCE_DEFAULT_WINDOW	~(0ULL)

struct spapr_tce_iommu_ops {
	struct iommu_table *(*get_table)(
			struct spapr_tce_iommu_group *data,
			phys_addr_t addr);
	void (*take_ownership)(struct spapr_tce_iommu_group *data,
			bool enable);

	/* Dynamic DMA window */
	/* Page size flags for ibm,query-pe-dma-window */
#define DDW_PGSIZE_4K       0x01
#define DDW_PGSIZE_64K      0x02
#define DDW_PGSIZE_16M      0x04
#define DDW_PGSIZE_32M      0x08
#define DDW_PGSIZE_64M      0x10
#define DDW_PGSIZE_128M     0x20
#define DDW_PGSIZE_256M     0x40
#define DDW_PGSIZE_16G      0x80
	long (*query)(struct spapr_tce_iommu_group *data,
			__u32 *windows_available,
			__u32 *page_size_mask);
	long (*create)(struct spapr_tce_iommu_group *data,
			__u32 page_shift,
			__u32 window_shift,
			struct iommu_table **ptbl);
	long (*remove)(struct spapr_tce_iommu_group *data,
			struct iommu_table *tbl);
	long (*reset)(struct spapr_tce_iommu_group *data);
};

struct spapr_tce_iommu_group {
	void *iommu_owner;
	struct spapr_tce_iommu_ops *ops;
};

#endif /* __KERNEL__ */
#endif /* _ASM_POWERPC_TCE_H */

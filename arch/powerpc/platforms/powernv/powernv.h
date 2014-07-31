#ifndef _POWERNV_H
#define _POWERNV_H

#ifdef CONFIG_SMP
extern void pnv_smp_init(void);
#else
static inline void pnv_smp_init(void) { }
#endif

/* Flags to indicate which of the CPU idle states are available for use */

#define IDLE_USE_NAP		(1UL << 0)
#define IDLE_USE_SLEEP		(1UL << 1)

extern unsigned int pnv_get_supported_cpuidle_states(void);

struct pci_dev;

#ifdef CONFIG_PCI
extern void pnv_pci_init(void);
extern void pnv_pci_shutdown(void);
extern int pnv_pci_dma_set_mask(struct pci_dev *pdev, u64 dma_mask);
#else
static inline void pnv_pci_init(void) { }
static inline void pnv_pci_shutdown(void) { }
static inline int pnv_pci_dma_set_mask(struct pci_dev *pdev, u64 dma_mask) { }
#endif

bool cpu_core_split_required(void);

extern void pnv_lpc_init(void);

#endif /* _POWERNV_H */

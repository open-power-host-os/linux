#if !defined(_TRACE_KVM_HV_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_HV_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm_hv
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace_hv

#define kvm_trace_symbol_exit \
	{0x100, "SYSTEM_RESET"}, \
	{0x200, "MACHINE_CHECK"}, \
	{0x300, "DATA_STORAGE"}, \
	{0x380, "DATA_SEGMENT"}, \
	{0x400, "INST_STORAGE"}, \
	{0x480, "INST_SEGMENT"}, \
	{0x500, "EXTERNAL"}, \
	{0x502, "EXTERNAL_HV"}, \
	{0x600, "ALIGNMENT"}, \
	{0x700, "PROGRAM"}, \
	{0x800, "FP_UNAVAIL"}, \
	{0x900, "DECREMENTER"}, \
	{0x980, "HV_DECREMENTER"}, \
	{0xc00, "SYSCALL"}, \
	{0xd00, "TRACE"}, \
	{0xe00, "H_DATA_STORAGE"}, \
	{0xe20, "H_INST_STORAGE"}, \
	{0xe40, "H_EMUL_ASSIST"}, \
	{0xf00, "PERFMON"}, \
	{0xf20, "ALTIVEC"}, \
	{0xf40, "VSX"}

#define kvm_trace_symbol_hcall \
	{0x04, "H_REMOVE"}, \
	{0x08, "H_ENTER"}, \
	{0x0c, "H_READ"}, \
	{0x10, "H_CLEAR_MOD"}, \
	{0x14, "H_CLEAR_REF"}, \
	{0x18, "H_PROTECT"}, \
	{0x1c, "H_GET_TCE"}, \
	{0x20, "H_PUT_TCE"}, \
	{0x24, "H_SET_SPRG0"}, \
	{0x28, "H_SET_DABR"}, \
	{0x2c, "H_PAGE_INIT"}, \
	{0x30, "H_SET_ASR"}, \
	{0x34, "H_ASR_ON"}, \
	{0x38, "H_ASR_OFF"}, \
	{0x3c, "H_LOGICAL_CI_LOAD"}, \
	{0x40, "H_LOGICAL_CI_STORE"}, \
	{0x44, "H_LOGICAL_CACHE_LOAD"}, \
	{0x48, "H_LOGICAL_CACHE_STORE"}, \
	{0x4c, "H_LOGICAL_ICBI"}, \
	{0x50, "H_LOGICAL_DCBF"}, \
	{0x54, "H_GET_TERM_CHAR"}, \
	{0x58, "H_PUT_TERM_CHAR"}, \
	{0x5c, "H_REAL_TO_LOGICAL"}, \
	{0x60, "H_HYPERVISOR_DATA"}, \
	{0x64, "H_EOI"}, \
	{0x68, "H_CPPR"}, \
	{0x6c, "H_IPI"}, \
	{0x70, "H_IPOLL"}, \
	{0x74, "H_XIRR"}, \
	{0x7c, "H_PERFMON"}, \
	{0x78, "H_MIGRATE_DMA"}, \
	{0xDC, "H_REGISTER_VPA"}, \
	{0xE0, "H_CEDE"}, \
	{0xE4, "H_CONFER"}, \
	{0xE8, "H_PROD"}, \
	{0xEC, "H_GET_PPP"}, \
	{0xF0, "H_SET_PPP"}, \
	{0xF4, "H_PURR"}, \
	{0xF8, "H_PIC"}, \
	{0xFC, "H_REG_CRQ"}, \
	{0x100, "H_FREE_CRQ"}, \
	{0x104, "H_VIO_SIGNAL"}, \
	{0x108, "H_SEND_CRQ"}, \
	{0x110, "H_COPY_RDMA"}, \
	{0x114, "H_REGISTER_LOGICAL_LAN"}, \
	{0x118, "H_FREE_LOGICAL_LAN"}, \
	{0x11C, "H_ADD_LOGICAL_LAN_BUFFER"}, \
	{0x120, "H_SEND_LOGICAL_LAN"}, \
	{0x124, "H_BULK_REMOVE"}, \
	{0x130, "H_MULTICAST_CTRL"}, \
	{0x134, "H_SET_XDABR"}, \
	{0x138, "H_STUFF_TCE"}, \
	{0x13C, "H_PUT_TCE_INDIRECT"}, \
	{0x14C, "H_CHANGE_LOGICAL_LAN_MAC"}, \
	{0x150, "H_VTERM_PARTNER_INFO"}, \
	{0x154, "H_REGISTER_VTERM"}, \
	{0x158, "H_FREE_VTERM"}, \
	{0x15C, "H_RESET_EVENTS"}, \
	{0x160, "H_ALLOC_RESOURCE"}, \
	{0x164, "H_FREE_RESOURCE"}, \
	{0x168, "H_MODIFY_QP"}, \
	{0x16C, "H_QUERY_QP"}, \
	{0x170, "H_REREGISTER_PMR"}, \
	{0x174, "H_REGISTER_SMR"}, \
	{0x178, "H_QUERY_MR"}, \
	{0x17C, "H_QUERY_MW"}, \
	{0x180, "H_QUERY_HCA"}, \
	{0x184, "H_QUERY_PORT"}, \
	{0x188, "H_MODIFY_PORT"}, \
	{0x18C, "H_DEFINE_AQP1"}, \
	{0x190, "H_GET_TRACE_BUFFER"}, \
	{0x194, "H_DEFINE_AQP0"}, \
	{0x198, "H_RESIZE_MR"}, \
	{0x19C, "H_ATTACH_MCQP"}, \
	{0x1A0, "H_DETACH_MCQP"}, \
	{0x1A4, "H_CREATE_RPT"}, \
	{0x1A8, "H_REMOVE_RPT"}, \
	{0x1AC, "H_REGISTER_RPAGES"}, \
	{0x1B0, "H_DISABLE_AND_GETC"}, \
	{0x1B4, "H_ERROR_DATA"}, \
	{0x1B8, "H_GET_HCA_INFO"}, \
	{0x1BC, "H_GET_PERF_COUNT"}, \
	{0x1C0, "H_MANAGE_TRACE"}, \
	{0x1D4, "H_FREE_LOGICAL_LAN_BUFFER"}, \
	{0x1E4, "H_QUERY_INT_STATE"}, \
	{0x1D8, "H_POLL_PENDING"}, \
	{0x244, "H_ILLAN_ATTRIBUTES"}, \
	{0x250, "H_MODIFY_HEA_QP"}, \
	{0x254, "H_QUERY_HEA_QP"}, \
	{0x258, "H_QUERY_HEA"}, \
	{0x25C, "H_QUERY_HEA_PORT"}, \
	{0x260, "H_MODIFY_HEA_PORT"}, \
	{0x264, "H_REG_BCMC"}, \
	{0x268, "H_DEREG_BCMC"}, \
	{0x26C, "H_REGISTER_HEA_RPAGES"}, \
	{0x270, "H_DISABLE_AND_GET_HEA"}, \
	{0x274, "H_GET_HEA_INFO"}, \
	{0x278, "H_ALLOC_HEA_RESOURCE"}, \
	{0x284, "H_ADD_CONN"}, \
	{0x288, "H_DEL_CONN"}, \
	{0x298, "H_JOIN"}, \
	{0x2A4, "H_VASI_STATE"}, \
	{0x2B0, "H_ENABLE_CRQ"}, \
	{0x2B8, "H_GET_EM_PARMS"}, \
	{0x2D0, "H_SET_MPP"}, \
	{0x2D4, "H_GET_MPP"}, \
	{0x2EC, "H_HOME_NODE_ASSOCIATIVITY"}, \
	{0x2F4, "H_BEST_ENERGY"}, \
	{0x2FC, "H_XIRR_X"}, \
	{0x300, "H_RANDOM"}, \
	{0x304, "H_COP"}, \
	{0x314, "H_GET_MPP_X"}, \
	{0x31C, "H_SET_MODE"}, \
	{0xf000, "H_RTAS"}

#define kvm_trace_symbol_kvmret \
	{0, "RESUME_GUEST"}, \
	{1, "RESUME_GUEST_NV"}, \
	{2, "RESUME_HOST"}, \
	{3, "RESUME_HOST_NV"}

#define kvm_trace_symbol_hcall_rc \
	{0, "H_SUCCESS"}, \
	{1, "H_BUSY"}, \
	{2, "H_CLOSED"}, \
	{3, "H_NOT_AVAILABLE"}, \
	{4, "H_CONSTRAINED"}, \
	{5, "H_PARTIAL"}, \
	{14, "H_IN_PROGRESS"}, \
	{15, "H_PAGE_REGISTERED"}, \
	{16, "H_PARTIAL_STORE"}, \
	{17, "H_PENDING"}, \
	{18, "H_CONTINUE"}, \
	{9900, "H_LONG_BUSY_START_RANGE"}, \
	{9900, "H_LONG_BUSY_ORDER_1_MSEC"}, \
	{9901, "H_LONG_BUSY_ORDER_10_MSEC"}, \
	{9902, "H_LONG_BUSY_ORDER_100_MSEC"}, \
	{9903, "H_LONG_BUSY_ORDER_1_SEC"}, \
	{9904, "H_LONG_BUSY_ORDER_10_SEC"}, \
	{9905, "H_LONG_BUSY_ORDER_100_SEC"}, \
	{9905, "H_LONG_BUSY_END_RANGE"}, \
	{9999, "H_TOO_HARD"}, \
	{-1, "H_HARDWARE"}, \
	{-2, "H_FUNCTION"}, \
	{-3, "H_PRIVILEGE"}, \
	{-4, "H_PARAMETER"}, \
	{-5, "H_BAD_MODE"}, \
	{-6, "H_PTEG_FULL"}, \
	{-7, "H_NOT_FOUND"}, \
	{-8, "H_RESERVED_DABR"}, \
	{-9, "H_NO_MEM"}, \
	{-10, "H_AUTHORITY"}, \
	{-11, "H_PERMISSION"}, \
	{-12, "H_DROPPED"}, \
	{-13, "H_SOURCE_PARM"}, \
	{-14, "H_DEST_PARM"}, \
	{-15, "H_REMOTE_PARM"}, \
	{-16, "H_RESOURCE"}, \
	{-17, "H_ADAPTER_PARM"}, \
	{-18, "H_RH_PARM"}, \
	{-19, "H_RCQ_PARM"}, \
	{-20, "H_SCQ_PARM"}, \
	{-21, "H_EQ_PARM"}, \
	{-22, "H_RT_PARM"}, \
	{-23, "H_ST_PARM"}, \
	{-24, "H_SIGT_PARM"}, \
	{-25, "H_TOKEN_PARM"}, \
	{-27, "H_MLENGTH_PARM"}, \
	{-28, "H_MEM_PARM"}, \
	{-29, "H_MEM_ACCESS_PARM"}, \
	{-30, "H_ATTR_PARM"}, \
	{-31, "H_PORT_PARM"}, \
	{-32, "H_MCG_PARM"}, \
	{-33, "H_VL_PARM"}, \
	{-34, "H_TSIZE_PARM"}, \
	{-35, "H_TRACE_PARM"}, \
	{-37, "H_MASK_PARM"}, \
	{-38, "H_MCG_FULL"}, \
	{-39, "H_ALIAS_EXIST"}, \
	{-40, "H_P_COUNTER"}, \
	{-41, "H_TABLE_FULL"}, \
	{-42, "H_ALT_TABLE"}, \
	{-43, "H_MR_CONDITION"}, \
	{-44, "H_NOT_ENOUGH_RESOURCES"}, \
	{-45, "H_R_STATE"}, \
	{-46, "H_RESCINDED"}, \
	{-55, "H_P2"}, \
	{-56, "H_P3"}, \
	{-57, "H_P4"}, \
	{-58, "H_P5"}, \
	{-59, "H_P6"}, \
	{-60, "H_P7"}, \
	{-61, "H_P8"}, \
	{-62, "H_P9"}, \
	{-64, "H_TOO_BIG"}, \
	{-68, "H_OVERLAP"}, \
	{-69, "H_INTERRUPT"}, \
	{-70, "H_BAD_DATA"}, \
	{-71, "H_NOT_ACTIVE"}, \
	{-72, "H_SG_LIST"}, \
	{-73, "H_OP_MODE"}, \
	{-74, "H_COP_HW"}, \
	{-256, "H_UNSUPPORTED_FLAG_START"}, \
	{-511, "H_UNSUPPORTED_FLAG_END"}, \
	{-9005, "H_MULTI_THREADS_ACTIVE"}, \
	{-9006, "H_OUTSTANDING_COP_OPS"}

TRACE_EVENT(kvm_guest_enter,
	TP_PROTO(struct kvm_vcpu *vcpu),
	TP_ARGS(vcpu),

	TP_STRUCT__entry(
		__field(int,		vcpu_id)
		__field(unsigned long,	pc)
		__field(unsigned long,  pending_exceptions)
		__field(u8,		ceded)
	),

	TP_fast_assign(
		__entry->vcpu_id	= vcpu->vcpu_id;
		__entry->pc		= kvmppc_get_pc(vcpu);
		__entry->ceded		= vcpu->arch.ceded;
		__entry->pending_exceptions  = vcpu->arch.pending_exceptions;
	),

	TP_printk("VCPU %d: pc=0x%lx pexcp=0x%lx ceded=%d",
			__entry->vcpu_id,
			__entry->pc,
			__entry->pending_exceptions, __entry->ceded)
);

TRACE_EVENT(kvm_guest_exit,
	TP_PROTO(struct kvm_vcpu *vcpu),
	TP_ARGS(vcpu),

	TP_STRUCT__entry(
		__field(int,		vcpu_id)
		__field(int,		trap)
		__field(unsigned long,	pc)
		__field(unsigned long,	msr)
		__field(u8,		ceded)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->trap	 = vcpu->arch.trap;
		__entry->ceded	 = vcpu->arch.ceded;
		__entry->pc	 = kvmppc_get_pc(vcpu);
		__entry->msr	 = vcpu->arch.shregs.msr;
	),

	TP_printk("VCPU %d: trap=%s pc=0x%lx msr=0x%lx, ceded=%d",
		__entry->vcpu_id,
		__print_symbolic(__entry->trap, kvm_trace_symbol_exit),
		__entry->pc, __entry->msr, __entry->ceded
	)
);

TRACE_EVENT(kvm_page_fault_enter,
	TP_PROTO(struct kvm_vcpu *vcpu, unsigned long *hptep,
		 struct kvm_memory_slot *memslot, unsigned long ea,
		 unsigned long dsisr),

	TP_ARGS(vcpu, hptep, memslot, ea, dsisr),

	TP_STRUCT__entry(
		__field(int,		vcpu_id	)
		__field(unsigned long,	hpte_v)
		__field(unsigned long,	hpte_r)
		__field(unsigned long,	gpte_r)
		__field(unsigned long,	ea)
		__field(u64,		base_gfn)
		__field(u32,		slot_flags)
		__field(u32,		dsisr)
	),

	TP_fast_assign(
		__entry->vcpu_id  = vcpu->vcpu_id;
		__entry->hpte_v	  = hptep[0];
		__entry->hpte_r	  = hptep[1];
		__entry->gpte_r	  = hptep[2];
		__entry->ea	  = ea;
		__entry->dsisr	  = dsisr;
		__entry->base_gfn = memslot ? memslot->base_gfn: -1UL;
		__entry->slot_flags = memslot ? memslot->flags: 0;
	),

	TP_printk("VCPU %d: hpte=0x%lx:0x%lx guest=0x%lx "
		  "ea=0x%lx,%x slot=0x%llx,0x%x",
		   __entry->vcpu_id,
		   __entry->hpte_v, __entry->hpte_r, __entry->gpte_r,
		   __entry->ea, __entry->dsisr,
		   __entry->base_gfn, __entry->slot_flags)
);

TRACE_EVENT(kvm_page_fault_exit,
	TP_PROTO(struct kvm_vcpu *vcpu, unsigned long *hptep, long ret),

	TP_ARGS(vcpu, hptep, ret),

	TP_STRUCT__entry(
		__field(int,		vcpu_id	)
		__field(unsigned long,	hpte_v)
		__field(unsigned long,	hpte_r)
		__field(long,		ret)
	),

	TP_fast_assign(
		__entry->vcpu_id  = vcpu->vcpu_id;
		__entry->hpte_v	= hptep[0];
		__entry->hpte_r	= hptep[1];
		__entry->ret = ret;
	),

	TP_printk("VCPU %d: hpte=0x%lx:0x%lx ret=0x%lx",
		   __entry->vcpu_id,
		   __entry->hpte_v, __entry->hpte_r, __entry->ret)
);

TRACE_EVENT(kvm_hcall_enter,
	TP_PROTO(struct kvm_vcpu *vcpu),

	TP_ARGS(vcpu),

	TP_STRUCT__entry(
		__field(int,		vcpu_id	)
		__field(unsigned long,	req)
		__field(unsigned long,	gpr4)
		__field(unsigned long,	gpr5)
		__field(unsigned long,	gpr6)
		__field(unsigned long,	gpr7)
	),

	TP_fast_assign(
		__entry->vcpu_id  = vcpu->vcpu_id;
		__entry->req   = kvmppc_get_gpr(vcpu, 3);
		__entry->gpr4  = kvmppc_get_gpr(vcpu, 4);
		__entry->gpr5  = kvmppc_get_gpr(vcpu, 5);
		__entry->gpr6  = kvmppc_get_gpr(vcpu, 6);
		__entry->gpr7  = kvmppc_get_gpr(vcpu, 7);
	),

	TP_printk("VCPU %d: hcall=%s GPR4-7=0x%lx,0x%lx,0x%lx,0x%lx",
		   __entry->vcpu_id,
		   __print_symbolic(__entry->req, kvm_trace_symbol_hcall),
		   __entry->gpr4, __entry->gpr5, __entry->gpr6, __entry->gpr7)
);

TRACE_EVENT(kvm_hcall_exit,
	TP_PROTO(struct kvm_vcpu *vcpu, int ret),

	TP_ARGS(vcpu, ret),

	TP_STRUCT__entry(
		__field(int,		vcpu_id	)
		__field(unsigned long,	ret)
		__field(unsigned long,	hcall_rc)
	),

	TP_fast_assign(
		__entry->vcpu_id  = vcpu->vcpu_id;
		__entry->ret	  = ret;
		__entry->hcall_rc = kvmppc_get_gpr(vcpu, 3);
	),

	TP_printk("VCPU %d: ret=%s hcall_rc=%s",
		   __entry->vcpu_id,
		   __print_symbolic(__entry->ret, kvm_trace_symbol_kvmret),
		   __print_symbolic(__entry->ret & RESUME_FLAG_HOST ?
					H_TOO_HARD : __entry->hcall_rc,
					kvm_trace_symbol_hcall_rc))
);

TRACE_EVENT(kvmppc_run_core,
	TP_PROTO(struct kvmppc_vcore *vc, int where),

	TP_ARGS(vc, where),

	TP_STRUCT__entry(
		__field(int,	n_runnable)
		__field(int,	runner_vcpu)
		__field(int,	where)
		__field(pid_t,	tgid)
	),

	TP_fast_assign(
		__entry->runner_vcpu	= vc->runner->vcpu_id;
		__entry->n_runnable	= vc->n_runnable;
		__entry->where		= where;
		__entry->tgid		= current->tgid;
	),

	TP_printk("%s runner_vcpu==%d runnable=%d tgid=%d",
		    __entry->where ? "Exit" : "Enter",
		    __entry->runner_vcpu, __entry->n_runnable, __entry->tgid)
);

TRACE_EVENT(kvmppc_vcore_blocked,
	TP_PROTO(struct kvmppc_vcore *vc, int where),

	TP_ARGS(vc, where),

	TP_STRUCT__entry(
		__field(int,	n_runnable)
		__field(int,	runner_vcpu)
		__field(int,	where)
		__field(pid_t,	tgid)
	),

	TP_fast_assign(
		__entry->runner_vcpu = vc->runner->vcpu_id;
		__entry->n_runnable  = vc->n_runnable;
		__entry->where       = where;
		__entry->tgid	     = current->tgid;
	),

	TP_printk("%s runner_vcpu=%d runnable=%d tgid=%d",
		   __entry->where ? "Exit" : "Enter",
		   __entry->runner_vcpu, __entry->n_runnable, __entry->tgid)
);

TRACE_EVENT(kvmppc_run_vcpu_enter,
	TP_PROTO(struct kvm_vcpu *vcpu),

	TP_ARGS(vcpu),

	TP_STRUCT__entry(
		__field(int,		vcpu_id	)
		__field(pid_t,		tgid)
	),

	TP_fast_assign(
		__entry->vcpu_id  = vcpu->vcpu_id;
		__entry->tgid	  = current->tgid;
	),

	TP_printk("VCPU %d: tgid=%d", __entry->vcpu_id, __entry->tgid)
);

TRACE_EVENT(kvmppc_run_vcpu_exit,
	TP_PROTO(struct kvm_vcpu *vcpu, struct kvm_run *run),

	TP_ARGS(vcpu, run),

	TP_STRUCT__entry(
		__field(int,		vcpu_id	)
		__field(int,		exit	)
		__field(int,		ret	)
	),

	TP_fast_assign(
		__entry->vcpu_id  = vcpu->vcpu_id;
		__entry->exit     = run->exit_reason;
		__entry->ret      = vcpu->arch.ret;
	),

	TP_printk("VCPU %d: exit=%d, ret=%d",
			__entry->vcpu_id, __entry->exit, __entry->ret)
);

#endif /* _TRACE_KVM_HV_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

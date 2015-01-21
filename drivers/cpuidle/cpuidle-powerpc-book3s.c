/*
 *  cpuidle-powerpc-book3s - idle state cpuidle driver.
 *  Adapted from drivers/idle/intel_idle.c and
 *  drivers/acpi/processor_idle.c
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/cpuidle.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/clockchips.h>
#include <linux/tick.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/of.h>

#include <asm/paca.h>
#include <asm/reg.h>
#include <asm/machdep.h>
#include <asm/firmware.h>
#include <asm/opal.h>
#include <asm/runlatch.h>
#include <asm/time.h>
#include <asm/plpar_wrappers.h>

#define MAX_POWERNV_IDLE_STATES	8

struct cpuidle_driver powerpc_book3s_idle_driver = {
	.name             = "powerpc_book3s_idle",
	.owner            = THIS_MODULE,
};

static int max_idle_state;
static struct cpuidle_state *cpuidle_state_table;

static int bc_cpu = -1;
static struct hrtimer *bc_hrtimer;
static int bc_hrtimer_initialized = 0;

/*
 * Bits to indicate if a cpu can enter deep idle where local timer gets
 * switched off.
 * BROADCAST_CPU_PRESENT : Enter deep idle since bc_cpu is assigned
 * BROADCAST_CPU_SELF	 : Do not enter deep idle since you are bc_cpu
 * BROADCAST_CPU_ABSENT	 : Do not enter deep idle since there is no bc_cpu,
 * 			   hence nominate yourself as bc_cpu
 * BROADCAST_CPU_ERROR	:  Do not enter deep idle since there is no bc_cpu
 *			   and the broadcast hrtimer could not be initialized.
 */
enum broadcast_cpu_status {
	BROADCAST_CPU_PRESENT,
	BROADCAST_CPU_SELF,
	BROADCAST_CPU_ERROR,
};

static inline void idle_loop_prolog(unsigned long *in_purr)
{
	*in_purr = mfspr(SPRN_PURR);
	/*
	 * Indicate to the HV that we are idle. Now would be
	 * a good time to find other work to dispatch.
	 */
	get_lppaca()->idle = 1;
}

static inline void idle_loop_epilog(unsigned long in_purr)
{
	get_lppaca()->wait_state_cycles += mfspr(SPRN_PURR) - in_purr;
	get_lppaca()->idle = 0;
}

static DEFINE_SPINLOCK(fastsleep_idle_lock);

static int snooze_loop(struct cpuidle_device *dev,
			struct cpuidle_driver *drv,
			int index)
{
	unsigned long in_purr = 0;

	if (firmware_has_feature(FW_FEATURE_SPLPAR))
		idle_loop_prolog(&in_purr);
	local_irq_enable();
	set_thread_flag(TIF_POLLING_NRFLAG);

	while (!need_resched()) {
		ppc64_runlatch_off();
		HMT_low();
		HMT_very_low();
	}

	HMT_medium();
	clear_thread_flag(TIF_POLLING_NRFLAG);
	smp_mb();

	if (firmware_has_feature(FW_FEATURE_SPLPAR))
		idle_loop_epilog(in_purr);

	return index;
}

static void check_and_cede_processor(void)
{
	/*
	 * Ensure our interrupt state is properly tracked,
	 * also checks if no interrupt has occurred while we
	 * were soft-disabled
	 */
	if (prep_irq_for_idle()) {
		cede_processor();
#ifdef CONFIG_TRACE_IRQFLAGS
		/* Ensure that H_CEDE returns with IRQs on */
		if (WARN_ON(!(mfmsr() & MSR_EE)))
			__hard_irq_enable();
#endif
	}
}

static int dedicated_cede_loop(struct cpuidle_device *dev,
				struct cpuidle_driver *drv,
				int index)
{
	unsigned long in_purr;

	idle_loop_prolog(&in_purr);
	get_lppaca()->donate_dedicated_cpu = 1;

	ppc64_runlatch_off();
	HMT_medium();
	check_and_cede_processor();

	get_lppaca()->donate_dedicated_cpu = 0;

	idle_loop_epilog(in_purr);

	return index;
}

static int shared_cede_loop(struct cpuidle_device *dev,
			struct cpuidle_driver *drv,
			int index)
{
	unsigned long in_purr;

	idle_loop_prolog(&in_purr);

	/*
	 * Yield the processor to the hypervisor.  We return if
	 * an external interrupt occurs (which are driven prior
	 * to returning here) or if a prod occurs from another
	 * processor. When returning here, external interrupts
	 * are enabled.
	 */
	check_and_cede_processor();

	idle_loop_epilog(in_purr);

	return index;
}

static int nap_loop(struct cpuidle_device *dev,
			struct cpuidle_driver *drv,
			int index)
{
	ppc64_runlatch_off();
	power7_idle();
	return index;
}

void broadcast_irq_entry(void)
{
	if (smp_processor_id() == bc_cpu)
		hrtimer_start(bc_hrtimer, ns_to_ktime(0), HRTIMER_MODE_REL_PINNED);
}

/* Functions supporting broadcasting in fastsleep */
static ktime_t get_next_bc_tick(void)
{
	u64 next_bc_ns;

	next_bc_ns = (tb_ticks_per_jiffy / tb_ticks_per_usec) * 1000;
	return ns_to_ktime(next_bc_ns);
}

static int restart_broadcast(struct clock_event_device *bc_evt)
{
	unsigned long flags;

	spin_lock_irqsave(&fastsleep_idle_lock, flags);
	bc_evt->event_handler(bc_evt);

	if (bc_evt->next_event.tv64 == KTIME_MAX)
		bc_cpu = -1;

	spin_unlock_irqrestore(&fastsleep_idle_lock, flags);
	return (bc_cpu != -1);
}

static enum hrtimer_restart handle_broadcast(struct hrtimer *hrtimer)
{
	struct clock_event_device *bc_evt = &bc_timer;
	ktime_t interval, next_bc_tick, now;

	if (!restart_broadcast(bc_evt))
		return HRTIMER_NORESTART;

	now = ktime_get();
	interval = ktime_sub(bc_evt->next_event, now);
	next_bc_tick = get_next_bc_tick();

	if (interval.tv64 < next_bc_tick.tv64)
		hrtimer_forward_now(hrtimer, interval);
	else
		hrtimer_forward_now(hrtimer, next_bc_tick);

	return HRTIMER_RESTART;
}

static enum broadcast_cpu_status can_enter_deep_idle(int cpu)
{
	if (bc_cpu != -1 && cpu != bc_cpu) {
		return BROADCAST_CPU_PRESENT;
	} else if (bc_cpu != -1 && cpu == bc_cpu) {
		return BROADCAST_CPU_SELF;
	} else {
		if (!bc_hrtimer_initialized) {
			bc_hrtimer = kmalloc(sizeof(*bc_hrtimer), GFP_NOWAIT);
			if (!bc_hrtimer)
				return BROADCAST_CPU_ERROR;
			hrtimer_init(bc_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
			bc_hrtimer->function = handle_broadcast;
			hrtimer_start(bc_hrtimer, get_next_bc_tick(),
				HRTIMER_MODE_REL_PINNED);
			bc_hrtimer_initialized = 1;
		} else {
			hrtimer_start(bc_hrtimer, get_next_bc_tick(), HRTIMER_MODE_REL_PINNED);
		}

		bc_cpu = cpu;
		return BROADCAST_CPU_SELF;
	}
}

/* Emulate sleep, with long nap.
 * During sleep, the core does not receive decrementer interrupts.
 * Emulate sleep using long nap with decrementers interrupts disabled.
 * This is an initial prototype to test the broadcast framework for ppc.
 */
static int fastsleep_loop(struct cpuidle_device *dev,
				struct cpuidle_driver *drv,
				int index)
{
	int cpu = dev->cpu;
	unsigned long old_lpcr = mfspr(SPRN_LPCR);
	unsigned long new_lpcr;
	unsigned long flags;
	int bc_cpu_status;

	/*
	 * Verify if snooze is the only valid cpuidle state
	 */
	if (!(powersave_nap > 0))
		return index;

	/* Wait until system is up; having nap active during
	 * smp init might throw off migration cost calibration.
	 */
	if (unlikely(system_state < SYSTEM_RUNNING))
 		return index;

	new_lpcr = old_lpcr;
	new_lpcr &= ~(LPCR_MER | LPCR_PECE); /* lpcr[mer] must be 0 */

	/* exit powersave upon external interrupt, but not decrementer
	 * interrupt, Emulate sleep.
	 */
	new_lpcr |= LPCR_PECE0;

	spin_lock_irqsave(&fastsleep_idle_lock, flags);
	bc_cpu_status = can_enter_deep_idle(cpu);

	if (bc_cpu_status == BROADCAST_CPU_PRESENT) {
		mtspr(SPRN_LPCR, new_lpcr);
		clockevents_notify(CLOCK_EVT_NOTIFY_BROADCAST_ENTER, &cpu);
		spin_unlock_irqrestore(&fastsleep_idle_lock, flags);
		power7_sleep();
		spin_lock_irqsave(&fastsleep_idle_lock, flags);
		clockevents_notify(CLOCK_EVT_NOTIFY_BROADCAST_EXIT, &cpu);
		spin_unlock_irqrestore(&fastsleep_idle_lock, flags);
	} else if (bc_cpu_status == BROADCAST_CPU_SELF) {
		new_lpcr |= LPCR_PECE1;
		mtspr(SPRN_LPCR, new_lpcr);
		spin_unlock_irqrestore(&fastsleep_idle_lock, flags);
		power7_nap();
	} else {
		spin_unlock_irqrestore(&fastsleep_idle_lock, flags);
	}

	mtspr(SPRN_LPCR, old_lpcr);
	return index;
}

/*
 * States for dedicated partition case.
 */
static struct cpuidle_state dedicated_states[] = {
	{ /* Snooze */
		.name = "snooze",
		.desc = "snooze",
		.flags = CPUIDLE_FLAG_TIME_VALID,
		.exit_latency = 0,
		.target_residency = 0,
		.enter = &snooze_loop },
	{ /* CEDE */
		.name = "CEDE",
		.desc = "CEDE",
		.flags = CPUIDLE_FLAG_TIME_VALID,
		.exit_latency = 10,
		.target_residency = 100,
		.enter = &dedicated_cede_loop },
};

/*
 * States for shared partition case.
 */
static struct cpuidle_state shared_states[] = {
	{ /* Shared Cede */
		.name = "Shared Cede",
		.desc = "Shared Cede",
		.flags = CPUIDLE_FLAG_TIME_VALID,
		.exit_latency = 0,
		.target_residency = 0,
		.enter = &shared_cede_loop },
};

static struct cpuidle_state powernv_states[MAX_POWERNV_IDLE_STATES] = {
	{ /* Snooze */
		.name = "snooze",
		.desc = "snooze",
		.flags = CPUIDLE_FLAG_TIME_VALID,
		.exit_latency = 0,
		.target_residency = 0,
		.enter = &snooze_loop },
};

void update_smt_snooze_delay(int cpu, int residency)
{
	struct cpuidle_driver *drv = cpuidle_get_driver();
	struct cpuidle_device *dev = per_cpu(cpuidle_devices, cpu);

	if (cpuidle_state_table != dedicated_states)
		return;

	if (residency < 0) {
		/* Disable the Nap state on that cpu */
		if (dev)
			dev->states_usage[1].disable = 1;
	} else
		if (drv)
			drv->states[1].target_residency = residency;
}

static int powerpc_book3s_cpuidle_add_cpu_notifier(struct notifier_block *n,
			unsigned long action, void *hcpu)
{
	int hotcpu = (unsigned long)hcpu;
	unsigned long flags;
	struct cpuidle_device *dev =
			per_cpu(cpuidle_devices, hotcpu);

	if (dev && cpuidle_get_driver()) {
		switch (action) {
		case CPU_ONLINE:
		case CPU_ONLINE_FROZEN:
			cpuidle_pause_and_lock();
			cpuidle_enable_device(dev);
			cpuidle_resume_and_unlock();
			break;

		case CPU_DYING:
		case CPU_DYING_FROZEN:
			spin_lock_irqsave(&fastsleep_idle_lock, flags);
			if (hotcpu == bc_cpu) {
				bc_cpu = -1;
				hrtimer_cancel(bc_hrtimer);
				if (!cpumask_empty(tick_get_broadcast_oneshot_mask())) {
					bc_cpu = cpumask_first(
							tick_get_broadcast_oneshot_mask());
					arch_send_tick_broadcast(cpumask_of(bc_cpu));
				}
			}
			spin_unlock_irqrestore(&fastsleep_idle_lock, flags);
			break;

		case CPU_DEAD:
		case CPU_DEAD_FROZEN:
			cpuidle_pause_and_lock();
			cpuidle_disable_device(dev);
			cpuidle_resume_and_unlock();
			break;

		default:
			return NOTIFY_DONE;
		}
	}
	return NOTIFY_OK;
}

static struct notifier_block setup_hotplug_notifier = {
	.notifier_call = powerpc_book3s_cpuidle_add_cpu_notifier,
};

static int powernv_add_idle_states(void)
{
	struct device_node *power_mgt;
	struct property *prop;
	int nr_idle_states = 1; /* Snooze */
	int dt_idle_states;
	u32 *flags;
	int i;

	/* Currently we have snooze statically defined */

	power_mgt = of_find_node_by_path("/ibm,opal/power-mgt");
	if (!power_mgt) {
		pr_warn("opal: PowerMgmt Node not found\n");
		return nr_idle_states;
	}

	prop = of_find_property(power_mgt, "ibm,cpu-idle-state-flags", NULL);
	if (!prop) {
		pr_warn("DT-PowerMgmt: missing ibm,cpu-idle-state-flags\n");
		return nr_idle_states;
	}

	dt_idle_states = prop->length / sizeof(u32);
	flags = (u32 *) prop->value;

	for (i = 0; i < dt_idle_states; i++) {

		if (flags[i] & OPAL_PM_NAP_ENABLED) {
			/* Add NAP state */
			strcpy(powernv_states[nr_idle_states].name, "Nap");
			strcpy(powernv_states[nr_idle_states].desc, "Nap");
			powernv_states[nr_idle_states].flags = CPUIDLE_FLAG_TIME_VALID;
			powernv_states[nr_idle_states].exit_latency = 10;
			powernv_states[nr_idle_states].target_residency = 100;
			powernv_states[nr_idle_states].enter = &nap_loop;
			nr_idle_states++;
		}

		if (flags[i] & OPAL_PM_SLEEP_ENABLED) {
			/* Add FASTSLEEP state */
			strcpy(powernv_states[nr_idle_states].name, "FastSleep");
			strcpy(powernv_states[nr_idle_states].desc, "FastSleep");
			powernv_states[nr_idle_states].flags = CPUIDLE_FLAG_TIME_VALID;
			powernv_states[nr_idle_states].exit_latency = 300;
			powernv_states[nr_idle_states].target_residency = 1000000;
			powernv_states[nr_idle_states].enter = &fastsleep_loop;
			nr_idle_states++;
		}
	}

	return nr_idle_states;
}

/*
 * powerpc_book3s_cpuidle_driver_init()
 */
static int powerpc_book3s_cpuidle_driver_init(void)
{
	int idle_state;
	struct cpuidle_driver *drv = &powerpc_book3s_idle_driver;

	drv->state_count = 0;
	for (idle_state = 0; idle_state < max_idle_state; ++idle_state) {

		/* is the state not enabled? */
		if (cpuidle_state_table[idle_state].enter == NULL)
			continue;

		drv->states[drv->state_count] =	/* structure copy */
			cpuidle_state_table[idle_state];

		drv->state_count += 1;
	}

	return 0;
}

/*
 * powerpc_book3s_idle_probe()
 * Choose state table for shared versus dedicated partition
 */
static int powerpc_book3s_idle_probe(void)
{
	if (cpuidle_disable != IDLE_NO_OVERRIDE)
		return -ENODEV;

	if (firmware_has_feature(FW_FEATURE_SPLPAR)) {
		if (get_lppaca()->shared_proc) {
			cpuidle_state_table = shared_states;
			max_idle_state = ARRAY_SIZE(shared_states);
		} else {
			cpuidle_state_table = dedicated_states;
			max_idle_state = ARRAY_SIZE(dedicated_states);
		}
	} else if (firmware_has_feature(FW_FEATURE_OPALv3)) {
		cpuidle_state_table = powernv_states;

		/* Device tree can indicate more idle states */
		max_idle_state = powernv_add_idle_states();
	}

	return 0;
}

static int __init powerpc_book3s_processor_idle_init(void)
{
	int retval;

	retval = powerpc_book3s_idle_probe();
	if (retval)
		return retval;

	powerpc_book3s_cpuidle_driver_init();
	retval = cpuidle_register(&powerpc_book3s_idle_driver, NULL);
	if (retval) {
		printk(KERN_DEBUG "Registration of powerpc_book3s_idle driver failed.\n");
		return retval;
	}

	register_cpu_notifier(&setup_hotplug_notifier);
	printk(KERN_DEBUG "powerpc_book3s_idle registered\n");
	return 0;
}

device_initcall(powerpc_book3s_processor_idle_init);

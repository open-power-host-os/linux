/*
 * cpufreq driver for the POWER8 processor
 *
 * (C) Copyright IBM 2013
 *
 * Author: Vaidyanathan Srinivasan <svaidy@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <linux/delay.h>
#include <linux/of_platform.h>
#include <linux/sysfs.h>
#include <linux/reboot.h>

#include <asm/cputhreads.h>
#include <asm/firmware.h>
#include <asm/topology.h>
#include <asm/machdep.h>
#include <asm/prom.h>
#include <asm/scom.h>

/* XXX FIXME: Make this per-core */
static DEFINE_MUTEX(freq_switch_mutex);

#define POWERNV_MAX_PSTATES	256

static struct cpufreq_frequency_table powernv_freqs[POWERNV_MAX_PSTATES+1];
static unsigned long powernv_freqs_data[POWERNV_MAX_PSTATES+1];

/*
 * Note: The set of pstates consists of contiguous integers, the
 * smallest of which is indicated by powernv_pstate_info.min, the
 * largest of which is indicated by powernv_pstate_info.max.
 *
 * The nominal pstate is the highest non-turbo pstate in this
 * platform. This is indicated by powernv_pstate_info.nominal.
 */
static struct powernv_pstate_info {
	int min;
	int max;
	int nominal;
	int nr_pstates;
} powernv_pstate_info;

/*
 * Initialize the freq table based on data obtained
 * from the OCC passed via device-tree
 */

static int init_powernv_pstates(void)
{
	struct device_node *power_mgt;
	struct property *prop;
	int nr_pstates = 0;
	int pstate_min, pstate_max, pstate_nominal;
	u32 *pstate_ids, *pstate_freqs;
	int i;

	power_mgt = of_find_node_by_path("/ibm,opal/power-mgt");
	if (!power_mgt) {
		pr_warn("powernv-cpufreq: \
			DT node /ibm,opal/power-mgt not found\n");
		return -ENODEV;
	}

	prop = of_find_property(power_mgt, "ibm,pstate-min", NULL);
	if (!prop) {
		pr_warn("powernv-cpufreq: \
			DT node /ibm,opal/power-mgt/ibm,pstate-min \
			not found\n");
		return -ENODEV;
	}
	pstate_min = * (u32 *) prop->value;

	prop = of_find_property(power_mgt, "ibm,pstate-max", NULL);
	if (!prop) {
		pr_warn("powernv-cpufreq: \
			DT node /ibm,opal/power-mgt/ibm,pstate-max \
			not found\n");
		return -ENODEV;
	}
	pstate_max = * (u32 *) prop->value;

	prop = of_find_property(power_mgt, "ibm,pstate-nominal", NULL);
	if (!prop) {
		pr_warn("powernv-cpufreq: \
			DT node /ibm,opal/power-mgt/ibm,pstate-nominal \
			not found\n");
		return -ENODEV;
	}
	pstate_nominal = * (u32 *) prop->value;
	printk(KERN_INFO "cpufreq pstate min %d nominal %d max %d\n", pstate_min, pstate_nominal,
						pstate_max);

	prop = of_find_property(power_mgt, "ibm,pstate-ids", NULL);
	if (!prop) {
		pr_warn("powernv-cpufreq: \
			DT node /ibm,opal/power-mgt/ibm,pstate-ids \
			not found\n");
		return -ENODEV;
	}
	pstate_ids = (u32 *) prop->value;

	prop = of_find_property(power_mgt, "ibm,pstate-frequencies-mhz", NULL);
	if (!prop) {
		/* Older firmware */
		prop = of_find_property(power_mgt, "ibm,pstate-freqencies-mhz", NULL);
		if (!prop) {
			pr_warn("powernv-cpufreq: \
			DT node /ibm,opal/power-mgt/ibm,pstate-frequencies-mhz \
						not found\n");
			return -ENODEV;
		}
	}
	pstate_freqs = (u32 *) prop->value;

	nr_pstates = prop->length/sizeof(u32);

	if (!nr_pstates) {
		pr_warn("No PStates found\n");
		return -ENODEV;
	}

	pr_debug("NR PStates %d\n", nr_pstates);
	for (i = 0; i < nr_pstates; i++) {
		pr_debug("PState id %d freq %d MHz\n", pstate_ids[i], pstate_freqs[i]);
		powernv_freqs[i].index = i;
		powernv_freqs_data[i] = pstate_ids[i];
		powernv_freqs[i].frequency = pstate_freqs[i] * 1000; /* kHz */
	}

	/* End entry */
	powernv_freqs[i].index = i;
	powernv_freqs[i].frequency = CPUFREQ_TABLE_END;
	powernv_freqs_data[i] = 0;

	powernv_pstate_info.min = pstate_min;
	powernv_pstate_info.max = pstate_max;
	powernv_pstate_info.nominal = pstate_nominal;
	powernv_pstate_info.nr_pstates = nr_pstates;

	return 0;
}

/* Returns the CPU frequency corresponding to the pstate_id. */
static unsigned int pstate_id_to_freq(int pstate_id)
{
	int i;

	i = powernv_pstate_info.max - pstate_id;
	if (i >= powernv_pstate_info.nr_pstates || i < 0) {
		pr_warn("PState id %d outside of PState table, "
			"reporting nominal id %d instead\n",
			pstate_id, powernv_pstate_info.nominal);
		i = powernv_pstate_info.max - powernv_pstate_info.nominal;
	}

	return powernv_freqs[i].frequency;
}

/*
 * cpuinfo_nominal_freq_show - Show the nominal CPU frequency as indicated by
 * the firmware
 */
static ssize_t cpuinfo_nominal_freq_show(struct cpufreq_policy *policy,
					char *buf)
{
	return sprintf(buf, "%u\n",
		pstate_id_to_freq(powernv_pstate_info.nominal));
}

struct freq_attr cpufreq_freq_attr_cpuinfo_nominal_freq =
	__ATTR_RO(cpuinfo_nominal_freq);

static struct freq_attr *powernv_cpu_freq_attr[] = {
	&cpufreq_freq_attr_scaling_available_freqs,
	&cpufreq_freq_attr_cpuinfo_nominal_freq,
	NULL,
};

/* Helper routines */

/* Access method to these SPR is special */

static inline unsigned long get_pmspr(unsigned long sprn)
{
	/* TBD: Fix the access protocol */
	switch(sprn) {
		case SPRN_PMCR:
			return mfspr(SPRN_PMCR);

		case SPRN_PMICR:
			return mfspr(SPRN_PMICR);

		case SPRN_PMSR:
			return mfspr(SPRN_PMSR);
	}
	BUG();
}

static inline void set_pmspr(unsigned long sprn, unsigned long val)
{
	/* TBD: Fix the access protocol */
	switch(sprn) {
		case SPRN_PMCR:
			mtspr(SPRN_PMCR, val);
			return;

		case SPRN_PMICR:
			mtspr(SPRN_PMICR, val);
			return;

		case SPRN_PMSR:
			mtspr(SPRN_PMSR, val);
			return;
	}
	BUG();
}

/*
 * Use objects of this type to query/update
 * pstates on a remote CPU via smp_call_function.
 */
struct powernv_smp_call_data {
	unsigned int freq;
	int pstate_id;
};

/*
 * powernv_read_cpu_freq: Reads the current frequency on this CPU.
 *
 * Called via smp_call_function.
 *
 * Note: The caller of the smp_call_function should pass an argument of
 * the type 'struct powernv_smp_call_data *' along with this function.
 *
 * The current frequency on this CPU will be returned via
 * ((struct powernv_smp_call_data *)arg)->freq;
 */
static void powernv_read_cpu_freq(void *arg)
{
	unsigned long pmspr_val;
	s8 local_pstate_id;
	struct powernv_smp_call_data *freq_data = arg;

	pmspr_val = get_pmspr(SPRN_PMSR);

	/*
	 * The local pstate id corresponds bits 48..55 in the PMSR.
	 * Note: Watch out for the sign!
	 */
	local_pstate_id = (pmspr_val >> 48) & 0xff;
	freq_data->pstate_id = local_pstate_id;
	freq_data->freq = pstate_id_to_freq(freq_data->pstate_id);

	pr_debug("cpu %d pmsr %016lX pstate_id %d frequency %d kHz\n",
		raw_smp_processor_id(), pmspr_val, freq_data->pstate_id,
		freq_data->freq);
}

/*
 * powernv_cpufreq_get: Returns the CPU frequency as reported by the
 * firmware for CPU 'cpu'. This value is reported through the sysfs
 * file cpuinfo_cur_freq.
 */
unsigned int powernv_cpufreq_get(unsigned int cpu)
{
	struct powernv_smp_call_data freq_data;

	smp_call_function_any(cpu_sibling_mask(cpu), powernv_read_cpu_freq,
			&freq_data, 1);

	return freq_data.freq;
}



static void set_pstate(void *pstate)
{
	unsigned long val;
	unsigned long pstate_ul = *(unsigned long *) pstate;
	val = get_pmspr(SPRN_PMCR);
	val = val & 0x0000ffffffffffffULL;
	/* Set both local and global state */
	val = val | (pstate_ul << 56) | (pstate_ul << 48);
	pr_debug("Setting cpu %d pmcr to %lX\n", smp_processor_id(), val);
	set_pmspr(SPRN_PMCR, val);
}

int powernv_set_freq(cpumask_var_t cpus, unsigned int new_index)
{
	unsigned long val = powernv_freqs_data[new_index];

	/*
	 * Use smp_call_function to send IPI and execute the
	 * mtspr on target cpu. We could do that without IPI
	 * if current CPU is within policy->cpus (core)
	 */

	val = val & 0xFF;
	smp_call_function_any(cpus, set_pstate, &val, 1);
	return 0;
}

static int powernv_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
	int base, i;

#ifdef CONFIG_SMP
	base = cpu_first_thread_sibling(policy->cpu);

	for (i = 0; i < threads_per_core; i++) {
		cpumask_set_cpu(base + i, policy->cpus);
	}
#endif
	policy->cpuinfo.transition_latency = 25000;

	/* if DEBUG is enabled set_pmode() measures the latency
	 * of a transition */

	/* Print frequency table */
	for (i=0; powernv_freqs[i].frequency!=CPUFREQ_TABLE_END; i++)
		pr_debug("%d: %d\n", i, powernv_freqs[i].frequency);

	policy->cur = powernv_freqs[0].frequency;
	policy->suspend_freq = pstate_id_to_freq(powernv_pstate_info.nominal);
	cpufreq_frequency_table_get_attr(powernv_freqs, policy->cpu);
	return cpufreq_frequency_table_cpuinfo(policy, powernv_freqs);
}

static int powernv_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
	smp_call_function_single(policy->cpu, set_pstate, &powernv_pstate_info.min, 1);
	cpufreq_frequency_table_put_attr(policy->cpu);
	return 0;
}

static int powernv_cpufreq_verify(struct cpufreq_policy *policy)
{
	return cpufreq_frequency_table_verify(policy, powernv_freqs);
}

static int powernv_cpufreq_reboot_notifier(struct notifier_block *nb,
                                unsigned long action, void *unused)
{
	cpufreq_suspend();
	return NOTIFY_DONE;
}

static struct notifier_block powernv_cpufreq_reboot_nb = {
	.notifier_call = powernv_cpufreq_reboot_notifier,
};

static int powernv_cpufreq_target(struct cpufreq_policy *policy,
			      unsigned int target_freq,
			      unsigned int relation)
{
	int rc;
	struct cpufreq_freqs freqs;
	unsigned int new_index;

	cpufreq_frequency_table_target(policy,
				       powernv_freqs,
				       target_freq,
				       relation,
				       &new_index);

	freqs.old = policy->cur;
	freqs.new = powernv_freqs[new_index].frequency;
	freqs.cpu = policy->cpu;

	mutex_lock(&freq_switch_mutex);
	cpufreq_notify_transition(policy, &freqs, CPUFREQ_PRECHANGE);

	pr_debug("setting frequency for cpu %d to %d kHz (data: 0x%lx)",
		 policy->cpu,
		 powernv_freqs[new_index].frequency,
		 powernv_freqs_data[new_index]);

	rc = powernv_set_freq(policy->cpus, new_index);

	cpufreq_notify_transition(policy, &freqs, CPUFREQ_POSTCHANGE);
	mutex_unlock(&freq_switch_mutex);

	return rc;
}

static struct cpufreq_driver powernv_cpufreq_driver = {
	.verify		= powernv_cpufreq_verify,
	.target		= powernv_cpufreq_target,
	.init		= powernv_cpufreq_cpu_init,
	.exit		= powernv_cpufreq_cpu_exit,
	.name		= "powernv-cpufreq",
	.flags		= CPUFREQ_CONST_LOOPS,
	.get		= powernv_cpufreq_get,
	.attr 		= powernv_cpu_freq_attr,
	.suspend        = cpufreq_generic_suspend,
};

static int __init powernv_cpufreq_init(void)
{
	int rc = 0;

	/* Don't probe on pseries (guest) platforms */
	if (!firmware_has_feature(FW_FEATURE_OPALv3))
		return -ENODEV;

	/* Detect pstates from device tree and init */

	rc = init_powernv_pstates();

	if (rc) {
		printk(KERN_INFO "powernv-cpufreq disabled\n");
		return rc;
	}

	register_reboot_notifier(&powernv_cpufreq_reboot_nb);
	rc = cpufreq_register_driver(&powernv_cpufreq_driver);
	return rc;
}

static void __exit powernv_cpufreq_exit(void)
{
	unregister_reboot_notifier(&powernv_cpufreq_reboot_nb);
	cpufreq_unregister_driver(&powernv_cpufreq_driver);
}

module_init(powernv_cpufreq_init);
module_exit(powernv_cpufreq_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vaidyanathan Srinivasan <svaidy@linux.vnet.ibm.com>");



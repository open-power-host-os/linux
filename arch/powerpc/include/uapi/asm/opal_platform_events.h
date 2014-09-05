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
 * Copyright IBM Corp. 2014
 *
 * Author: Anshuman Khandual <khandual@linux.vnet.ibm.com>
 */
#ifndef __LINUX_OPAL_PLATFORM_EVENTS_H
#define __LINUX_OPAL_PLATFORM_EVENTS_H

#include <linux/types.h>

/* EPOW classification */
enum epow_condition {
	EPOW_SYSPOWER_CHNG	= 0,	/* Power */
	EPOW_SYSPOWER_FAIL	= 1,
	EPOW_SYSPOWER_INCL	= 2,
	EPOW_SYSPOWER_UPS	= 3,
	EPOW_SYSTEMP_AMB	= 4,	/* Temperature */
	EPOW_SYSTEMP_INT	= 5,
	EPOW_SYSTEMP_HMD	= 6,
	EPOW_SYSCOOL_INSF	= 7,	/* Cooling */
	EPOW_MAX = 8,
};

/* OPAL EPOW event */
struct epow_event {
	__u64	epow[EPOW_MAX];		/* Detailed system EPOW status */
	__u64	timeout;		/* Timeout to shutdown in secs */
};

/* OPAL DPO event */
struct dpo_event {
	__u64	orig_timeout;		/* Platform provided timeout in secs */
	__u64	remain_timeout;		/* Timeout to shutdown in secs */
};

/* OPAL event */
struct opal_plat_event {
	__u32	type;			/* Type of OPAL platform event */
#define OPAL_PLAT_EVENT_TYPE_EPOW	0
#define OPAL_PLAT_EVENT_TYPE_DPO	1
#define OPAL_PLAT_EVENT_TYPE_MAX	2
	__u32	size;			/* Size of OPAL platform event */
	union {
		struct epow_event epow;	/* EPOW platform event */
		struct dpo_event  dpo;	/* DPO platform event */
	};
};

/*
 * Suggested read size
 *
 * The user space client should attempt to read OPAL_PLAT_EVENT_READ_SIZE
 * amount of data from the character device file '/dev/opal_event' at any
 * point of time. The kernel driver will pass an entire opal_plat_event
 * structure in every read. This ensures that minium data the user space
 * client gets from the kernel is one opal_plat_event structure.
 */
#define	PLAT_EVENT_MAX_SIZE	4096

/*
 * Suggested user operation
 *
 * The user space client must follow these steps in order to be able to
 * exploit the features exported through the OPAL platform event driver.
 *
 *	(1) Open the character device file
 *	(2) Poll on the file for POLLIN
 *	(3) When unblocked, must attempt to read PLAT_EVENT_MAX_SIZE size
 *	(4) Kernel driver will pass one opal_plat_event structure
 *	(5) Poll again for more new events
 *
 * The character device file (/dev/opal_event) must be opened and operated by
 * only one user space client at any point of time. Other attempts to open the
 * file will be returned by the driver as EBUSY.
 */

#endif /* __LINUX_OPAL_PLATFORM_EVENTS_H */

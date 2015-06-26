/*
 * IBM PowerNV opal platform events driver
 *
 * Copyright IBM Corporation 2014
 *
 * Author: Anshuman Khandual <khandual@linux.vnet.ibm.com>
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
#define PREFIX		"OPAL_EVENT"
#define pr_fmt(fmt)	PREFIX ": " fmt

#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/timer.h>
#include <linux/reboot.h>
#include <asm/uaccess.h>
#include <asm/opal.h>
#include <asm/opal_platform_events.h>

/* Platform events driver */
static dev_t opal_event_dev;
static struct cdev opal_event_cdev;
static struct class *opal_event_class;
static bool opal_event_open_flag;

#define OPAL_EVENT_MAX_DEVS	1

/* Platform events timers */
static struct timer_list opal_event_timer;

static DECLARE_WAIT_QUEUE_HEAD(opal_plat_evt_wait);
static DECLARE_WAIT_QUEUE_HEAD(opal_plat_open_wait);
static DEFINE_SPINLOCK(opal_plat_evt_spinlock);
static DEFINE_SPINLOCK(opal_plat_timer_spinlock);
static DEFINE_MUTEX(opal_plat_evt_mutex);

/*
 * Platform timeout values
 *
 * XXX: The default timeout value is 5 minutes. In future this
 * should be communicated from the platform firmware through
 * device tree attributes.
 */
#define OPAL_EPOW_TIMEOUT	300

struct opal_platform_evt {
	struct opal_plat_event opal_event;
	struct list_head link;
};
static LIST_HEAD(opal_event_queue);
static unsigned long opal_dpo_target;
static bool opal_event_probe_finished;

/*
 * OPAL event map
 *
 * Converts OPAL event type into it's description.
 */
static const char *opal_event_map[OPAL_PLAT_EVENT_TYPE_MAX] = {
	"OPAL_PLAT_EVENT_TYPE_EPOW", "OPAL_PLAT_EVENT_TYPE_DPO"
};

/*
 * opal_event_timeout
 *
 * This is the actual timer handler. If the any of the timers
 * expire, this function will be called to shutdown the system
 * gracefully.
 */
static void opal_event_timeout(unsigned long data)
{
	orderly_poweroff(1);
}

/*
 * opal_event_start_timer
 *
 * This will start opal event timer with given timeout value as the expiry
 * if either the timer is not active or the expiry value of the already
 * activated timer is at a later point of time in the future compared to the
 * timeout value for this given new event. The function mod_timer takes care
 * all the cases whether the opal event timer is already active or not.
 */
static void opal_event_start_timer(unsigned long event, u64 timeout)
{
	unsigned long flags;

	/* Timer active with earlier timeout */
	spin_lock_irqsave(&opal_plat_timer_spinlock, flags);
	if (timer_pending(&opal_event_timer) &&
			(opal_event_timer.expires < (jiffies + timeout * HZ))) {
		spin_unlock_irqrestore(&opal_plat_timer_spinlock, flags);
		pr_info("Timer for %s event active with an earlier timeout\n",
					opal_event_map[opal_event_timer.data]);
		return;
	}
	opal_event_timer.data = event;
	mod_timer(&opal_event_timer, jiffies + timeout * HZ);
	spin_unlock_irqrestore(&opal_plat_timer_spinlock, flags);
	pr_info("Timer activated for %s event\n", opal_event_map[event]);
}

/*
 * opal_event_stop_timer
 *
 * This will attempt to stop opal_event_timer if it is already enabled.
 */
static void opal_event_stop_timer(void)
{
	unsigned long flags;

	spin_lock_irqsave(&opal_plat_timer_spinlock, flags);
	del_timer_sync(&opal_event_timer);
	spin_unlock_irqrestore(&opal_plat_timer_spinlock, flags);
	pr_info("Timer deactivated\n");
}

/*
 * opal_event_read
 *
 * User client needs to attempt to read PLAT_EVENT_MAX_SIZE amount of data
 * from the file descriptor at a time. The driver will pass a single node
 * from the list if available at a time and then delete the node from the list.
 */
static ssize_t opal_event_read(struct file *filep,
			char __user *buf, size_t len, loff_t *off)
{
	struct opal_platform_evt *evt;
	unsigned long flags;

	if (len < sizeof(struct opal_plat_event))
		return -EINVAL;

	/* Fetch the first node on the list */
	spin_lock_irqsave(&opal_plat_evt_spinlock, flags);
	if (list_empty(&opal_event_queue)) {
		spin_unlock_irqrestore(&opal_plat_evt_spinlock, flags);
		return 0;
	}

	/* Fetch and delete from the list */
	evt = list_first_entry(&opal_event_queue,
					struct opal_platform_evt, link);
	list_del(&evt->link);

	/*
	 * Update the remaining timeout for DPO event.
	 * This can only be updated during the read time.
	 */
	if (evt->opal_event.type == OPAL_PLAT_EVENT_TYPE_DPO) {
		unsigned long timeout;
		if (opal_dpo_target &&
				evt->opal_event.dpo.orig_timeout) {
			timeout = (opal_dpo_target - jiffies) / HZ;
			evt->opal_event.dpo.remain_timeout = timeout;
		}
	}
	spin_unlock_irqrestore(&opal_plat_evt_spinlock, flags);

	if (copy_to_user(buf, &evt->opal_event,
		sizeof(struct opal_plat_event))) {

		/*
		 * Copy to user has failed. The event node had
		 * been deleted from the list. Lets add it back
		 * there.
		 */
		spin_lock_irqsave(&opal_plat_evt_spinlock, flags);
		list_add_tail(&evt->link, &opal_event_queue);
		spin_unlock_irqrestore(&opal_plat_evt_spinlock, flags);
		return -EFAULT;
	}

	kfree(evt);
	return sizeof(struct opal_plat_event);
}

/*
 * opal_event_poll
 *
 * Poll is unblocked right away with POLLIN when data is available.
 * When data is not available, the process will have to block till
 * it gets waked up and data is available to read.
 */
static unsigned int opal_event_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &opal_plat_evt_wait, wait);
	if (!list_empty(&opal_event_queue))
		return POLLIN;
	return 0;
}

/*
 * opal_event_open
 *
 * This makes sure that only one process can open the
 * character device file at any point of time. Others
 * attempting to open the file descriptor will either
 * get EBUSY (with O_NONBLOCK flag) or wait for the
 * other process to close the file descriptor.
 */
static int opal_event_open(struct inode *inode, struct file *file)
{
	int err;

	mutex_lock(&opal_plat_evt_mutex);
	while (opal_event_open_flag) {
		mutex_unlock(&opal_plat_evt_mutex);
		if (file->f_flags & O_NONBLOCK)
			return -EBUSY;
		err = wait_event_interruptible(opal_plat_open_wait,
							!opal_event_open_flag);
		if (err)
			return -ERESTARTSYS;
		mutex_lock(&opal_plat_evt_mutex);
	}
	opal_event_open_flag = true;
	mutex_unlock(&opal_plat_evt_mutex);
	return 0;
}

/*
 * opal_event_release
 *
 * Releases the file descriptor for the device file.
 */
static int opal_event_release(struct inode *inode, struct file *file)
{
	mutex_lock(&opal_plat_evt_mutex);
	if (opal_event_open_flag) {
		opal_event_open_flag = false;
		wake_up_interruptible(&opal_plat_open_wait);
	}
	mutex_unlock(&opal_plat_evt_mutex);
	return 0;
}

/* Defined file operation */
static const struct file_operations fops = {
	.owner	= THIS_MODULE,
	.open		= opal_event_open,
	.release	= opal_event_release,
	.read		= opal_event_read,
	.poll		= opal_event_poll,
};

/* Process the received EPOW information */
void process_epow(__u64 *epow, int16_t *epow_status, int max_epow_class)
{
	/*
	 * Platform might have returned less number of EPOW
	 * subclass status than asked for. This situation
	 * happens when the platform firmware is older compared
	 * to the kernel.
	 */

	if (!max_epow_class) {
		pr_warn("EPOW: OPAL_SYSEPOW_POWER subclass not present\n");
		return;
	}

	/* Power */
	max_epow_class--;
	if (epow_status[OPAL_SYSEPOW_POWER] & OPAL_SYSPOWER_CHNG) {
		pr_info("EPOW: Power configuration changed\n");
		epow[EPOW_SYSPOWER_CHNG] = 1;
	}

	if (epow_status[OPAL_SYSEPOW_POWER] & OPAL_SYSPOWER_FAIL) {
		pr_info("EPOW: Impending system power failure\n");
		epow[EPOW_SYSPOWER_FAIL] = 1;
	}

	if (epow_status[OPAL_SYSEPOW_POWER] & OPAL_SYSPOWER_INCL) {
		pr_info("EPOW: Incomplete system power\n");
		epow[EPOW_SYSPOWER_INCL] = 1;
	}

	if (epow_status[OPAL_SYSEPOW_POWER] & OPAL_SYSPOWER_UPS) {
		pr_info("EPOW: System on UPS power\n");
		epow[EPOW_SYSPOWER_UPS] = 1;
	}

	if (!max_epow_class) {
		pr_warn("EPOW: OPAL_SYSEPOW_TEMP subclass not present\n");
		return;
	}

	/* Temperature */
	max_epow_class--;
	if (epow_status[OPAL_SYSEPOW_TEMP] & OPAL_SYSTEMP_AMB) {
		pr_info("EPOW: Over ambient temperature\n");
		epow[EPOW_SYSTEMP_AMB] = 1;
	}

	if (epow_status[OPAL_SYSEPOW_TEMP] & OPAL_SYSTEMP_INT) {
		pr_info("EPOW: Over internal temperature\n");
		epow[EPOW_SYSTEMP_INT] = 1;
	}

	if (epow_status[OPAL_SYSEPOW_TEMP] & OPAL_SYSTEMP_HMD) {
		pr_info("EPOW: Over internal humidity\n");
		epow[EPOW_SYSTEMP_HMD] = 1;
	}

	if (!max_epow_class) {
		pr_warn("EPOW: OPAL_SYSEPOW_COOLING subclass not present\n");
		return;
	}

	/* Cooling */
	max_epow_class--;
	if (epow_status[OPAL_SYSEPOW_COOLING] & OPAL_SYSCOOL_INSF) {
		pr_info("EPOW: Insufficient cooling\n");
		epow[EPOW_SYSCOOL_INSF] = 1;
	}
}

/*
 * fetch_epow_status
 *
 * Fetch the system EPOW status through an OPAL call and
 * validate the number of EPOW sub class status received.
 */
static void fetch_epow_status(int16_t *epow_status, int16_t *n_epow)
{
	int rc;

	memset(epow_status, 0, sizeof(int16_t) * OPAL_SYSEPOW_MAX);
	*n_epow = OPAL_SYSEPOW_MAX;
	rc = opal_get_epow_status(epow_status, n_epow);
	if (rc != OPAL_SUCCESS) {
		pr_err("EPOW: OPAL call failed\n");
		memset(epow_status, 0, sizeof(int16_t) * OPAL_SYSEPOW_MAX);
		*n_epow = 0;
		return;
	}
	if (!(*n_epow))
		pr_err("EPOW: No subclass status received\n");
}

/*
 * fetch_dpo_timeout
 *
 * Fetch the system DPO timeout status through an OPAL call.
 */
static void fetch_dpo_timeout(int64_t *dpo_timeout)
{
	int rc;

	rc = opal_get_dpo_status(dpo_timeout);
	if (rc == OPAL_WRONG_STATE) {
		pr_info("DPO: Not initiated by OPAL\n");
		*dpo_timeout = 0;
	}
}

/*
 * valid_epow
 *
 * Validate the received EPOW event status. This ensures
 * that there are valid status for various EPOW sub classes
 * and their individual events.
 */
static bool valid_epow(int16_t *epow_status, int16_t n_epow)
{
	int i;

	/* EPOW sub classes present */
	if (!n_epow)
		return false;

	/* EPOW events present */
	for (i = 0; i < n_epow; i++) {
		if (epow_status[i])
			return true;
	}
	return false;
}

/*
 * epow_exclude
 *
 * XXX: EPOW events on the action exclude list. System shutdown
 * would not be scheduled for all these platform events. In future
 * this should be communicated from the platform firmware through
 * device tree attributes.
 */
static bool epow_exclude(int epow_event)
{
	switch (epow_event) {
	case EPOW_SYSPOWER_CHNG:
		return true;
	case EPOW_SYSPOWER_FAIL:
		return true;
	case EPOW_SYSPOWER_INCL:
		return true;
	case EPOW_SYSTEMP_HMD:
		return true;
	case EPOW_SYSCOOL_INSF:
		return true;
	default:
		return false;
	}
}

/*
 * actionable_epow
 *
 * There are some EPOW events for which the user client must receive
 * their status but the driver would not schedule a timer for that
 * event as the platform would not force shutdown the system because
 * of this event. This filters only the actionable EPOW events for
 * which shutdown timer need to be scheduled.
 */
static bool actionable_epow(__u64 *epow)
{
	int i;

	for (i = 0; i < EPOW_MAX; i++) {
		if (!epow_exclude(i) && epow[i])
			return true;
	}
	return false;
}

/*
 * opal_event_handle_basic
 *
 * Sets up the basic information for an opal platform event,
 * activates the timer, adds to the list and wakes up waiting
 * threads on the character device.
 */
static void opal_event_handle_basic(struct opal_platform_evt *evt,
				unsigned long type, unsigned long timeout)
{
	unsigned long flags;

	evt->opal_event.type = type;
	switch (type) {
	case OPAL_PLAT_EVENT_TYPE_EPOW:
		evt->opal_event.size = sizeof(struct epow_event);
		evt->opal_event.epow.timeout = timeout;
		if (actionable_epow(evt->opal_event.epow.epow))
			opal_event_start_timer(OPAL_PLAT_EVENT_TYPE_EPOW, 0);
		break;
	case  OPAL_PLAT_EVENT_TYPE_DPO:
		evt->opal_event.size = sizeof(struct dpo_event);
		evt->opal_event.dpo.orig_timeout = timeout;
		opal_event_start_timer(OPAL_PLAT_EVENT_TYPE_DPO, 0);
		break;
	default:
		pr_err("Unknown event type\n");
		break;
	}
	spin_lock_irqsave(&opal_plat_evt_spinlock, flags);
	list_add_tail(&evt->link, &opal_event_queue);
	spin_unlock_irqrestore(&opal_plat_evt_spinlock, flags);
	wake_up_interruptible(&opal_plat_evt_wait);
}

/*
 * opal_event_existing_status
 *
 * Fetch and process existing opal platform event conditions
 * present on the system. If events detected, add them to the
 * list which can be consumed by the user space right away.
 */
static void opal_event_existing_status(void)
{
	struct opal_platform_evt *evt;
	int64_t dpo_timeout;
	int16_t	epow_status[OPAL_SYSEPOW_MAX], n_epow;

	fetch_epow_status(epow_status, &n_epow);
	if (valid_epow(epow_status, n_epow)) {
		evt = kzalloc(sizeof(struct opal_platform_evt), GFP_KERNEL);
		if (!evt) {
			pr_err("EPOW: Memory allocation for event failed\n");
			return;
		}
		process_epow(evt->opal_event.epow.epow, epow_status, n_epow);
		opal_event_handle_basic(evt, OPAL_PLAT_EVENT_TYPE_EPOW,
							OPAL_EPOW_TIMEOUT);
	}

	fetch_dpo_timeout(&dpo_timeout);
	if (dpo_timeout) {
		evt = kzalloc(sizeof(struct opal_platform_evt), GFP_KERNEL);
		if (!evt) {
			pr_err("DPO: Memory allocation for event failed\n");
			return;
		}
		opal_dpo_target = jiffies + dpo_timeout * HZ;
		opal_event_handle_basic(evt, OPAL_PLAT_EVENT_TYPE_DPO,
								dpo_timeout);
	}
}

/* Platform EPOW message received */
static int opal_epow_event(struct notifier_block *nb,
				unsigned long msg_type, void *msg)
{
	struct opal_platform_evt *evt;
	int16_t	epow_status[OPAL_SYSEPOW_MAX], n_epow;

	if (msg_type != OPAL_MSG_EPOW)
		return 0;

	fetch_epow_status(epow_status, &n_epow);
	if (!valid_epow(epow_status, n_epow))
		return -EINVAL;

	pr_debug("EPOW event: Power(%x) Thermal(%x) Cooling(%x)\n",
			epow_status[0], epow_status[1], epow_status[2]);
	evt = kzalloc(sizeof(struct opal_platform_evt), GFP_KERNEL);
	if (!evt) {
		pr_err("EPOW: Memory allocation for event failed\n");
		return -ENOMEM;
	}
	process_epow(evt->opal_event.epow.epow, epow_status, n_epow);
	opal_event_handle_basic(evt,
				OPAL_PLAT_EVENT_TYPE_EPOW, OPAL_EPOW_TIMEOUT);
	return 0;
}

/* Platform DPO message received */
static int opal_dpo_event(struct notifier_block *nb,
				unsigned long msg_type, void *msg)
{
	struct opal_platform_evt *evt;
	int64_t dpo_timeout;

	if (msg_type != OPAL_MSG_DPO)
		return 0;

	fetch_dpo_timeout(&dpo_timeout);
	if (!dpo_timeout)
		return -EINVAL;

	pr_debug("DPO event: Timeout:%llu\n", dpo_timeout);
	evt = kzalloc(sizeof(struct opal_platform_evt), GFP_KERNEL);
	if (!evt) {
		pr_err("DPO: Memory allocation for event failed\n");
		return -ENOMEM;
	}
	opal_dpo_target = jiffies + dpo_timeout * HZ;
	opal_event_handle_basic(evt, OPAL_PLAT_EVENT_TYPE_DPO, dpo_timeout);
	return 0;
}

/* OPAL EPOW event notifier block */
static struct notifier_block opal_epow_nb = {
	.notifier_call  = opal_epow_event,
	.next           = NULL,
	.priority       = 0,
};

/* OPAL DPO event notifier block */
static struct notifier_block opal_dpo_nb = {
	.notifier_call  = opal_dpo_event,
	.next           = NULL,
	.priority       = 0,
};

/* Platform driver probe */
static int opal_event_probe(struct platform_device *pdev)
{
	struct device *dev;
	int ret;

	if (opal_event_probe_finished) {
		pr_err("%s getting called once again\n", __func__);
		return 0;
	}
	opal_event_probe_finished = true;

	init_timer(&opal_event_timer);
	opal_event_timer.function = opal_event_timeout;
	opal_event_open_flag = false;
	opal_dpo_target = 0;

	ret = alloc_chrdev_region(&opal_event_dev, 0,
					OPAL_EVENT_MAX_DEVS, "opal_event");
	if (ret < 0) {
		dev_err(&pdev->dev, "aloc_chrdev_region failed\n");
		return ret;
	}

	opal_event_class = class_create(THIS_MODULE, "opal_event");
	if (IS_ERR(opal_event_class)) {
		ret = PTR_ERR(opal_event_class);
		dev_err(&pdev->dev, "class_create failed with %d\n", ret);
		goto fail_chrdev;
	}

	dev = device_create(opal_event_class, &pdev->dev,
					opal_event_dev, NULL, "opal_event");
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		dev_err(&pdev->dev, "device_create failed with %d\n", ret);
		goto fail_class;
	}

	cdev_init(&opal_event_cdev, &fops);
	ret = cdev_add(&opal_event_cdev, opal_event_dev, OPAL_EVENT_MAX_DEVS);
	if (ret < 0) {
		dev_err(dev, "cdev_add failed\n");
		ret = -EINVAL;
		goto fail_device;
	}

	ret = opal_message_notifier_register(OPAL_MSG_EPOW, &opal_epow_nb);
	if (ret) {
		pr_err("EPOW: Platform event message notifier failed\n");
		goto fail_cdev;
	}

	ret = opal_message_notifier_register(OPAL_MSG_DPO, &opal_dpo_nb);
	if (ret) {
		pr_err("DPO: Platform event message notifier failed\n");
		opal_notifier_unregister(&opal_epow_nb);
		goto fail_cdev;
	}

	/*
	 * During the system boot, reboot and kexecs, the host can miss
	 * some of the EPOW or DPO messages sent from OPAL. This ensures
	 * that the current status of EPOW or DPO if any, is fetched and
	 * then updated correctly. The user space needs to first read the
	 * existing system status before entering into the poll/read loop.
	 *
	 */
	opal_event_existing_status();
	pr_info("OPAL platform event driver initialized\n");
	return 0;
fail_cdev:
	cdev_del(&opal_event_cdev);
fail_device:
	device_destroy(opal_event_class, opal_event_dev);
fail_class:
	class_destroy(opal_event_class);
fail_chrdev:
	unregister_chrdev_region(opal_event_dev, OPAL_EVENT_MAX_DEVS);
	return ret;
}

/* Platform driver remove */
static int opal_event_remove(struct platform_device *pdev)
{
	struct opal_platform_evt *evt;

	/* OPAL notifiers */
	opal_notifier_unregister(&opal_dpo_nb);
	opal_notifier_unregister(&opal_epow_nb);

	/* Devices */
	cdev_del(&opal_event_cdev);
	device_destroy(opal_event_class, opal_event_dev);
	class_destroy(opal_event_class);
	unregister_chrdev_region(opal_event_dev, OPAL_EVENT_MAX_DEVS);

	/* Timers */
	opal_event_stop_timer();

	/* Flush the list */
	while (!list_empty(&opal_event_queue)) {
		evt = list_first_entry(&opal_event_queue,
					struct opal_platform_evt, link);
		list_del(&evt->link);
		kfree(evt);
	}

	pr_info("OPAL platform event driver exited\n");
	return 0;
}

/* Platform driver property match */
static struct of_device_id opal_event_match[] = {
	{
		.compatible	= "ibm,opal-v3-epow",
	},
	{},
};
MODULE_DEVICE_TABLE(of, opal_event_match);

static struct platform_driver opal_event_driver = {
	.probe	= opal_event_probe,
	.remove = opal_event_remove,
	.driver = {
		.name = "opal-platform-event-driver",
		.owner = THIS_MODULE,
		.of_match_table = opal_event_match,
	},
};

static int __init opal_platform_event_init(void)
{
	opal_event_probe_finished = false;
	return platform_driver_register(&opal_event_driver);
}

static void __exit opal_platform_event_exit(void)
{
	platform_driver_unregister(&opal_event_driver);
}
module_init(opal_platform_event_init);
module_exit(opal_platform_event_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anshuman Khandual <khandual@linux.vnet.ibm.com>");
MODULE_DESCRIPTION("PowerNV OPAL platform events driver");

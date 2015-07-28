/*
 * PowerNV LED Driver
 *
 * Copyright IBM Corp. 2015
 *
 * Author: Vasant Hegde <hegdevasant@linux.vnet.ibm.com>
 * Author: Anshuman Khandual <khandual@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/leds.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <asm/opal.h>

/*
 * By default unload path resets all the LEDs. But on PowerNV platform
 * we want to retain LED state across reboot as these are controlled by
 * firmware. Also service processor can modify the LEDs independent of
 * OS. Hence avoid resetting LEDs in unload path.
 */
static bool led_disabled;

/* Map LED type to description. */
struct led_type_map {
	const int	type;
	const char	*desc;
};
static const struct led_type_map led_type_map[] = {
	{OPAL_SLOT_LED_TYPE_ID,		POWERNV_LED_TYPE_IDENTIFY},
	{OPAL_SLOT_LED_TYPE_FAULT,	POWERNV_LED_TYPE_FAULT},
	{OPAL_SLOT_LED_TYPE_ATTN,	POWERNV_LED_TYPE_ATTENTION},
	{-1,				NULL},
};

/*
 * LED set routines have been implemented as work queue tasks scheduled
 * on the global work queue. Individual task calls OPAL interface to set
 * the LED state which might sleep for some time.
 */
struct powernv_led_data {
	struct led_classdev	cdev;
	char			*loc_code;	/* LED location code */
	int			led_type;	/* OPAL_SLOT_LED_TYPE_* */
	enum led_brightness	value;		/* Brightness value */
	struct mutex		lock;
	struct work_struct	work_led;	/* LED update workqueue */
};

struct powernv_leds_priv {
	int num_leds;
	struct powernv_led_data powernv_leds[];
};

static __be64 max_led_type;


static inline int sizeof_powernv_leds_priv(int num_leds)
{
	return sizeof(struct powernv_leds_priv) +
		(sizeof(struct powernv_led_data) * num_leds);
}

/* Returns OPAL_SLOT_LED_TYPE_* for given led type string */
static int powernv_get_led_type(const char *led_type_desc)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(led_type_map); i++)
		if (!strcmp(led_type_map[i].desc, led_type_desc))
			return led_type_map[i].type;

	return -1;
}

/*
 * This commits the state change of the requested LED through an OPAL call.
 * This function is called from work queue task context when ever it gets
 * scheduled. This function can sleep at opal_async_wait_response call.
 */
static void powernv_led_set(struct powernv_led_data *powernv_led)
{
	int rc, token;
	u64 led_mask, led_value = 0;
	__be64 max_type;
	struct opal_msg msg;
	struct device *dev = powernv_led->cdev.dev;

	/* Prepare for the OPAL call */
	max_type = max_led_type;
	led_mask = OPAL_SLOT_LED_STATE_ON << powernv_led->led_type;
	if (powernv_led->value)
		led_value = led_mask;

	/* OPAL async call */
	token = opal_async_get_token_interruptible();
	if (token < 0) {
		if (token != -ERESTARTSYS)
			dev_err(dev, "%s: Couldn't get OPAL async token\n",
				__func__);
		return;
	}

	rc = opal_leds_set_ind(token, powernv_led->loc_code,
			       led_mask, led_value, &max_type);
	if (rc != OPAL_ASYNC_COMPLETION) {
		dev_err(dev, "%s: OPAL set LED call failed for %s [rc=%d]\n",
			__func__, powernv_led->loc_code, rc);
		goto out_token;
	}

	rc = opal_async_wait_response(token, &msg);
	if (rc) {
		dev_err(dev,
			"%s: Failed to wait for the async response [rc=%d]\n",
			__func__, rc);
		goto out_token;
	}

	rc = be64_to_cpu(msg.params[1]);
	if (rc != OPAL_SUCCESS)
		dev_err(dev, "%s : OAPL async call returned failed [rc=%d]\n",
			__func__, rc);

out_token:
	opal_async_release_token(token);
}

/*
 * This function fetches the LED state for a given LED type for
 * mentioned LED classdev structure.
 */
static enum led_brightness
powernv_led_get(struct powernv_led_data *powernv_led)
{
	int rc;
	__be64 mask, value, max_type;
	u64 led_mask, led_value;
	struct device *dev = powernv_led->cdev.dev;

	/* Fetch all LED status */
	mask = cpu_to_be64(0);
	value = cpu_to_be64(0);
	max_type = max_led_type;

	rc = opal_leds_get_ind(powernv_led->loc_code,
			       &mask, &value, &max_type);
	if (rc != OPAL_SUCCESS && rc != OPAL_PARTIAL) {
		dev_err(dev, "%s: OPAL get led call failed [rc=%d]\n",
			__func__, rc);
		return LED_OFF;
	}

	led_mask = be64_to_cpu(mask);
	led_value = be64_to_cpu(value);

	/* LED status available */
	if (!((led_mask >> powernv_led->led_type) & OPAL_SLOT_LED_STATE_ON)) {
		dev_err(dev, "%s: LED status not available for %s\n",
			__func__, powernv_led->cdev.name);
		return LED_OFF;
	}

	/* LED status value */
	if ((led_value >> powernv_led->led_type) & OPAL_SLOT_LED_STATE_ON)
		return LED_FULL;

	return LED_OFF;
}

/* Execute LED set task for given led classdev */
static void powernv_deferred_led_set(struct work_struct *work)
{
	struct powernv_led_data *powernv_led =
		container_of(work, struct powernv_led_data, work_led);

	mutex_lock(&powernv_led->lock);
	powernv_led_set(powernv_led);
	mutex_unlock(&powernv_led->lock);
}

/*
 * LED classdev 'brightness_get' function. This schedules work
 * to update LED state.
 */
static void powernv_brightness_set(struct led_classdev *led_cdev,
				   enum led_brightness value)
{
	struct powernv_led_data *powernv_led =
		container_of(led_cdev, struct powernv_led_data, cdev);

	/* Do not modify LED in unload path */
	if (led_disabled)
		return;

	/* Prepare the request */
	powernv_led->value = value;

	/* Schedule the new task */
	schedule_work(&powernv_led->work_led);
}

/* LED classdev 'brightness_get' function */
static enum led_brightness
powernv_brightness_get(struct led_classdev *led_cdev)
{
	struct powernv_led_data *powernv_led =
		container_of(led_cdev, struct powernv_led_data, cdev);

	return powernv_led_get(powernv_led);
}


/*
 * This function registers classdev structure for any given type of LED on
 * a given child LED device node.
 */
static int powernv_led_create(struct device *dev,
			      struct powernv_led_data *powernv_led,
			      const char *led_type_desc)
{
	int rc;

	/* Make sure LED type is supported */
	powernv_led->led_type = powernv_get_led_type(led_type_desc);
	if (powernv_led->led_type == -1) {
		dev_warn(dev, "%s: No support for led type : %s\n",
			 __func__, led_type_desc);
		return -EINVAL;
	}

	/* Create the name for classdev */
	powernv_led->cdev.name = devm_kasprintf(dev, GFP_KERNEL, "%s:%s",
						powernv_led->loc_code,
						led_type_desc);
	if (!powernv_led->cdev.name) {
		dev_err(dev,
			"%s: Memory allocation failed for classdev name\n",
			__func__);
		return -ENOMEM;
	}

	powernv_led->cdev.brightness_set = powernv_brightness_set;
	powernv_led->cdev.brightness_get = powernv_brightness_get;
	powernv_led->cdev.brightness = LED_OFF;
	powernv_led->cdev.max_brightness = LED_FULL;

	mutex_init(&powernv_led->lock);
	INIT_WORK(&powernv_led->work_led, powernv_deferred_led_set);

	/* Register the classdev */
	rc = led_classdev_register(dev, &powernv_led->cdev);
	if (rc)
		dev_err(dev, "%s: Classdev registration failed for %s\n",
			__func__, powernv_led->cdev.name);

	return rc;
}

/* Go through LED device tree node and register LED classdev structure */
static int powernv_led_classdev(struct platform_device *pdev,
				struct device_node *led_node,
				struct powernv_leds_priv *priv, int num_leds)
{
	const char *cur = NULL;
	int i, rc = -1;
	struct property *p;
	struct device_node *np;
	struct powernv_led_data *powernv_led;
	struct device *dev = &pdev->dev;

	for_each_child_of_node(led_node, np) {
		p = of_find_property(np, "led-types", NULL);
		if (!p)
			continue;

		while ((cur = of_prop_next_string(p, cur)) != NULL) {
			powernv_led = &priv->powernv_leds[priv->num_leds++];
			if (priv->num_leds > num_leds) {
				rc = -ENOMEM;
				goto classdev_fail;
			}

			powernv_led->loc_code = (char *)np->name;

			rc = powernv_led_create(dev, powernv_led, cur);
			if (rc)
				goto classdev_fail;
		} /* while end */
	}

	platform_set_drvdata(pdev, priv);
	return rc;

classdev_fail:
	for (i = priv->num_leds - 2; i >= 0; i--) {
		powernv_led = &priv->powernv_leds[i];
		led_classdev_unregister(&powernv_led->cdev);
		mutex_destroy(&powernv_led->lock);
	}

	return rc;
}

/*
 * We want to populate LED device for each LED type. Hence we
 * have to calculate count explicitly.
 */
static int powernv_leds_count(struct device_node *led_node)
{
	const char *cur = NULL;
	int num_leds = 0;
	struct property *p;
	struct device_node *np;

	for_each_child_of_node(led_node, np) {
		p = of_find_property(np, "led-types", NULL);
		if (!p)
			continue;

		while ((cur = of_prop_next_string(p, cur)) != NULL)
			num_leds++;
	}

	return num_leds;
}

/* Platform driver probe */
static int powernv_led_probe(struct platform_device *pdev)
{
	int num_leds;
	struct device_node *led_node;
	struct powernv_leds_priv *priv;

	led_node = of_find_node_by_path("/ibm,opal/leds");
	if (!led_node) {
		dev_err(&pdev->dev,
			"%s: LED parent device node not found\n", __func__);
		return -EINVAL;
	}

	num_leds = powernv_leds_count(led_node);
	if (num_leds <= 0) {
		dev_err(&pdev->dev,
			"%s: No location code found under LED node\n",
			__func__);
		return -EINVAL;
	}

	priv = devm_kzalloc(&pdev->dev,
			    sizeof_powernv_leds_priv(num_leds), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	/* Max supported LED type */
	max_led_type = cpu_to_be64(OPAL_SLOT_LED_TYPE_MAX);

	return powernv_led_classdev(pdev, led_node, priv, num_leds);
}

/* Platform driver remove */
static int powernv_led_remove(struct platform_device *pdev)
{
	int i;
	struct powernv_led_data *powernv_led;
	struct powernv_leds_priv *priv;

	/* Disable LED operation */
	led_disabled = true;

	priv = platform_get_drvdata(pdev);

	for (i = 0; i < priv->num_leds; i++) {
		powernv_led = &priv->powernv_leds[i];
		led_classdev_unregister(&powernv_led->cdev);
		flush_work(&powernv_led->work_led);
		mutex_destroy(&powernv_led->lock);
	}

	dev_info(&pdev->dev, "PowerNV led module unregistered\n");
	return 0;
}

/* Platform driver property match */
static const struct of_device_id powernv_led_match[] = {
	{
		.compatible	= "ibm,opal-v3-led",
	},
	{},
};
MODULE_DEVICE_TABLE(of, powernv_led_match);

static struct platform_driver powernv_led_driver = {
	.probe	= powernv_led_probe,
	.remove = powernv_led_remove,
	.driver = {
		.name = "powernv-led-driver",
		.owner = THIS_MODULE,
		.of_match_table = powernv_led_match,
	},
};

module_platform_driver(powernv_led_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("PowerNV LED driver");
MODULE_AUTHOR("Vasant Hegde <hegdevasant@linux.vnet.ibm.com>");

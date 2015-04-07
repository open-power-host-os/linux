/*
 * Self-test for compression
 *
 * Copyright (C) 2015 Dan Streetman, IBM Corp
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
 */

#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/crypto.h>
#include <linux/rwsem.h>
#include <linux/ratelimit.h>

#define MODULE_NAME "comp_selftest"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dan Streetman <ddstreet@ieee.org>");
MODULE_DESCRIPTION("Crypto Compression Self-Test");

static unsigned int test_kthreads_max = 64;
module_param_named(threads_max, test_kthreads_max, uint, 0444);

static unsigned int test_buffer_order = 2;
module_param_named(buffer_order, test_buffer_order, uint, 0444);

#define TEST_KTHREADS_DEFAULT	(4)

#define TEST_REPEAT_DEFAULT	(1)

#define TEST_BPS_WINDOW_DEFAULT	(1)

#define TEST_BUFFER_SIZE	(PAGE_SIZE << test_buffer_order)

#define TEST_CHECK_INTERVAL	(msecs_to_jiffies(500))

#define OFFSET_START_DEFAULT	(0)
#define OFFSET_END_DEFAULT	OFFSET_START_DEFAULT
#define OFFSET_INTERVAL_DEFAULT	(1)
#define LENGTH_START_DEFAULT	(PAGE_SIZE)
#define LENGTH_END_DEFAULT	LENGTH_START_DEFAULT
#define LENGTH_INTERVAL_DEFAULT	(1)

struct test_range {
	u32 start, interval, end;
};

struct test_param {
	u32 running;
	u32 repeat;
	u32 kthreads;
	u32 bps_window; /* in seconds */
	struct test_range offset[3];
	struct test_range length[3];
};

struct test_kthread_param {
	bool running;
	struct task_struct *kthread;
	struct crypto_comp *tfm;
	u8 *buffer[3];
	u32 offset[3];
	u32 length[3];
	atomic64_t bps[2];
};

static struct test_kthread_param *test_kthread_params;

static struct task_struct *test_kthread;
static int test_return;
static u8 *test_buffer;

static atomic64_t test_max_bps[2];

#define TEST_TFM_NAME_MAX	(32)
static char test_tfm[TEST_TFM_NAME_MAX];

static struct test_param test_params, test_new_params;

static DECLARE_RWSEM(test_lock);


static unsigned long total_bps(int i)
{
	unsigned long total = 0;
	int j;

	for (j = 0; j < test_kthreads_max; j++)
		total += atomic64_read(&test_kthread_params[j].bps[i]);

	return total;
}

static void update_max_bps(int i)
{
	uint64_t prev, t;

	t = total_bps(i);
	prev = atomic64_read(&test_max_bps[i]);
	while (t > prev) {
		uint64_t a = atomic64_cmpxchg(&test_max_bps[i], prev, t);

		if (prev == a)
			break;
		prev = a;
	}
}

#define NS_PER_S	(1000000000)

static void update_bps(struct test_kthread_param *p,
		       int i, u64 bytes, ktime_t start)
{
	u64 ns = ktime_to_ns(ktime_sub(ktime_get(), start));
	u64 bps = atomic64_read(&p->bps[i]);
	u64 window_ns = NS_PER_S * test_params.bps_window;
	u64 window_bytes = bps * test_params.bps_window;
	s64 a, b, delta;

	a = window_ns * bytes;
	b = ns * window_bytes;

	delta = (s64)(a - b) / (s64)(window_ns + ns);

	window_bytes += delta;

	atomic64_set(&p->bps[i], window_bytes / test_params.bps_window);

	update_max_bps(i);
}

static void reset_bps(void)
{
	int i;

	for (i = 0; i < test_kthreads_max; i++) {
		atomic64_set(&test_kthread_params[i].bps[0], 0);
		atomic64_set(&test_kthread_params[i].bps[1], 0);
	}

	atomic64_set(&test_max_bps[0], 0);
	atomic64_set(&test_max_bps[1], 0);
}

static int test_compare(struct test_kthread_param *p, unsigned int clen)
{
	u8 *a = &p->buffer[0][p->offset[0]];
	u8 *c = &p->buffer[2][p->offset[2]];
	unsigned int alen = p->length[0];

	if (alen != clen) {
		pr_err("buffer length mismatch, alen 0x%x clen 0x%x\n",
		      alen, clen);
		return -EINVAL;
	}

	if (memcmp(a, c, alen)) {
		pr_err("buffer data mismatch\n");
		return -EINVAL;
	}

	return 0;
}

static int __test_decompress(struct test_kthread_param *p, unsigned int blen)
{
	u8 *b = &p->buffer[1][p->offset[1]];
	u8 *c = &p->buffer[2][p->offset[2]];
	unsigned int clen = p->length[2];
	ktime_t start = ktime_get();
	int ret;

	ret = crypto_comp_decompress(p->tfm, b, blen, c, &clen);
	if (ret)
		return ret;

	update_bps(p, 1, clen, start);

	return test_compare(p, clen);
}

static int test_decompress(struct test_kthread_param *p, unsigned int blen)
{
	struct test_range *off, *len;
	u32 o, l;
	int ret;

	off = &test_params.offset[2];
	len = &test_params.length[2];

	for (l = len->start; l <= len->end; l += len->interval) {
		p->length[2] = l;

		for (o = off->start; o <= off->end; o += off->interval) {
			p->offset[2] = o;

			ret = __test_decompress(p, blen);
			if (ret)
				return ret;

			if (kthread_should_stop())
				return 0;

			/* so we don't appear hung */
			schedule();
		}
	}

	return 0;
}

static int __test_compress(struct test_kthread_param *p)
{
	u8 *a = &p->buffer[0][p->offset[0]];
	u8 *b = &p->buffer[1][p->offset[1]];
	unsigned int alen = p->length[0], blen = p->length[1];
	ktime_t start = ktime_get();
	int ret;

	ret = crypto_comp_compress(p->tfm, a, alen, b, &blen);
	if (ret)
		return ret;

	update_bps(p, 0, alen, start);

	return test_decompress(p, blen);
}

static int test_compress(struct test_kthread_param *p)
{
	struct test_range *off, *len;
	u32 o, l;
	int ret;

	off = &test_params.offset[1];
	len = &test_params.length[1];

	for (l = len->start; l <= len->end; l += len->interval) {
		p->length[1] = l;

		for (o = off->start; o <= off->end; o += off->interval) {
			p->offset[1] = o;

			ret = __test_compress(p);
			if (ret)
				return ret;

			if (kthread_should_stop())
				return 0;

			/* so we don't appear hung */
			schedule();
		}
	}

	return 0;
}

static int test_kthread_func(void *arg)
{
	struct test_kthread_param *p = arg;
	struct test_range *off, *len;
	u32 o, l;
	int ret;

	off = &test_params.offset[0];
	len = &test_params.length[0];

repeat:
	for (l = len->start; l <= len->end; l += len->interval) {
		p->length[0] = l;

		for (o = off->start; o <= off->end; o += off->interval) {
			p->offset[0] = o;

			ret = test_compress(p);
			if (ret)
				goto end;

			if (kthread_should_stop())
				goto end;

			/* so we don't appear hung */
			schedule();
		}
	}

	if (test_params.repeat)
		goto repeat;

end:
	if (ret)
		test_return = ret;

	p->running = false;

	return 0;
}

static void test_free_kthread(int i)
{
	struct test_kthread_param *p;

	if (i > test_kthreads_max)
		return;

	p = &test_kthread_params[i];

	if (p->tfm && !IS_ERR(p->tfm))
		crypto_free_comp(p->tfm);
	p->tfm = NULL;

	free_pages((unsigned long)p->buffer[0], test_buffer_order);
	p->buffer[0] = NULL;
	free_pages((unsigned long)p->buffer[1], test_buffer_order);
	p->buffer[1] = NULL;
	free_pages((unsigned long)p->buffer[2], test_buffer_order);
	p->buffer[2] = NULL;
}

static int test_alloc_kthread(int i)
{
	struct test_kthread_param *p;
	int ret = 0;

	if (i > test_kthreads_max)
		return -EINVAL;

	p = &test_kthread_params[i];

	p->buffer[0] = (u8 *)__get_free_pages(GFP_KERNEL, test_buffer_order);
	p->buffer[1] = (u8 *)__get_free_pages(GFP_KERNEL, test_buffer_order);
	p->buffer[2] = (u8 *)__get_free_pages(GFP_KERNEL, test_buffer_order);
	p->tfm = crypto_alloc_comp(test_tfm, 0, 0);

	if (IS_ERR(p->tfm)) {
		pr_err("could not create compressor %s : %ld\n",
			 test_tfm, PTR_ERR(p->tfm));
		ret = PTR_ERR(p->tfm);
	}

	if (!p->buffer[0] || !p->buffer[1] || !p->buffer[2]) {
		pr_err("could not create buffer\n");
		ret = -ENOMEM;
	}

	if (ret) {
		test_free_kthread(i);
	} else {
		memcpy(p->buffer[0], test_buffer, TEST_BUFFER_SIZE);
		memcpy(p->buffer[1], test_buffer, TEST_BUFFER_SIZE);
		memcpy(p->buffer[2], test_buffer, TEST_BUFFER_SIZE);
	}

	return ret;
}

static int test_kthread_running(void)
{
	int i;

	for (i = 0; i < test_kthreads_max; i++)
		if (test_kthread_params[i].running)
			return 1;

	return 0;
}

static int test_run(void *arg)
{
	int i;

	test_return = 0;

	if (test_tfm[0] == 0) {
		test_return = -ENODEV;
		pr_err("compression self test error: no compressor defined\n");
		goto error;
	}

	reset_bps();

	pr_info("compression self test starting\n");
	pr_info("  compressor: %s\n", test_tfm);
	pr_info("  repeat: %s\n", test_params.repeat ? "Y" : "N");
	pr_info("  threads: %d\n", test_params.kthreads);
	pr_info("  offsets %x-%x/%x, %x-%x/%x, %x-%x/%x\n",
		test_params.offset[0].start, test_params.offset[0].end,
		test_params.offset[0].interval,
		test_params.offset[1].start, test_params.offset[1].end,
		test_params.offset[1].interval,
		test_params.offset[2].start, test_params.offset[2].end,
		test_params.offset[2].interval);
	pr_info("  lengths %x-%x/%x, %x-%x/%x, %x-%x/%x\n",
		test_params.length[0].start, test_params.length[0].end,
		test_params.length[0].interval,
		test_params.length[1].start, test_params.length[1].end,
		test_params.length[1].interval,
		test_params.length[2].start, test_params.length[2].end,
		test_params.length[2].interval);

	for (i = 0; !test_return && i < test_params.kthreads; i++) {
		test_return = test_alloc_kthread(i);
		if (test_return)
			while (--i >= 0)
				test_free_kthread(i);
	}

	for (i = 0; !test_return && i < test_params.kthreads; i++) {
		struct test_kthread_param *p = &test_kthread_params[i];

		p->running = true;
		p->kthread = kthread_run(test_kthread_func, p, "selftest%d", i);
		if (IS_ERR(p->kthread)) {
			test_return = PTR_ERR(p->kthread);
			p->kthread = NULL;
			p->running = false;
		} else {
			get_task_struct(p->kthread);
		}
	}

	while (!kthread_should_stop() && !test_return && test_kthread_running())
		schedule_timeout_interruptible(msecs_to_jiffies(100));

	for (i = 0; i < test_params.kthreads; i++) {
		struct test_kthread_param *p = &test_kthread_params[i];

		if (p->running)
			kthread_stop(p->kthread);
		if (p->kthread)
			put_task_struct(p->kthread);
		p->kthread = NULL;
		p->running = false;
	}

	pr_info("compression self test MBps %ld/%ld peak %ld/%ld\n",
		(unsigned long)(total_bps(0) / 1000000),
		(unsigned long)(total_bps(1) / 1000000),
		(unsigned long)(atomic64_read(&test_max_bps[0]) / 1000000),
		(unsigned long)(atomic64_read(&test_max_bps[1]) / 1000000));

	if (kthread_should_stop())
		pr_info("compression self test stopped by user\n");
	else
		pr_info("compression self test ended\n");

error:
	/* this causes test_stop() to get called */
	test_new_params.running = 0;

	if (test_return)
		pr_info("compression self test failed\n");

	return test_return;
}

static void test_stop(void)
{
	if (!test_kthread)
		return;

	if (!IS_ERR(test_kthread)) {
		kthread_stop(test_kthread);
		put_task_struct(test_kthread);
	}

	test_kthread = NULL;
	test_params.running = false;
	test_new_params.running = false;
}

static int test_start(void)
{
	int ret = 0;

	if (test_kthread)
		return 0;

	test_kthread = kthread_run(test_run, NULL, MODULE_NAME);
	if (IS_ERR(test_kthread)) {
		ret = PTR_ERR(test_kthread);
		test_stop();
	} else
		get_task_struct(test_kthread);

	return ret;
}

/* this changes the source buffer passed in */
static void test_buffer_fill(u8 *buf, size_t len)
{
	size_t i, l, pos;

	/* repeat source buf across entire test buffer,
	 * changing each byte by 1 per repeat
	 */
	for (pos = 0; pos < TEST_BUFFER_SIZE; pos += len) {
		l = min_t(size_t, len, TEST_BUFFER_SIZE - pos);

		memcpy(&test_buffer[pos], buf, l);

		if (pos + len < TEST_BUFFER_SIZE)
			for (i = 0; i < len; i++)
				buf[i] += 1;
	}
}

static ssize_t test_buffer_read(struct file *file, char __user *buf,
				size_t len, loff_t *off)
{
	return simple_read_from_buffer(buf, len, off,
				       test_buffer, TEST_BUFFER_SIZE);
}

static ssize_t test_buffer_write(struct file *file, const char __user *buf,
				 size_t len, loff_t *off)
{
	size_t l = min_t(size_t, len, TEST_BUFFER_SIZE);
	char *tmp;
	u32 was_running;

	tmp = kmalloc(l, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	if (copy_from_user(tmp, buf, l)) {
		kfree(tmp);
		return -EFAULT;
	}

	down_write(&test_lock);

	was_running = test_params.running && test_new_params.running;

	/* if was_running, this clears the running flags */
	test_stop();

	/* special case if writing to start, we fill out the rest
	 * of the buffer using the starting pattern
	 */
	if (*off == 0)
		test_buffer_fill(tmp, l);
	else
		l = simple_write_to_buffer(test_buffer, TEST_BUFFER_SIZE,
					   off, buf, l);
	*off += l;

	if (was_running) {
		int ret;

		test_new_params.running = was_running;
		test_params.running = was_running;
		ret = test_start();
		if (ret)
			l = ret;
	}

	up_write(&test_lock);

	kfree(tmp);

	return l;
}

static const struct file_operations test_buffer_ops = {
	.owner =	THIS_MODULE,
	.read =		test_buffer_read,
	.write =	test_buffer_write,
};

static ssize_t test_compressor_read(struct file *file, char __user *buf,
				    size_t len, loff_t *off)
{
	char name[TEST_TFM_NAME_MAX] = "none\n";

	down_read(&test_lock);

	if (test_tfm[0] != 0)
		snprintf(name, TEST_TFM_NAME_MAX, "%s\n", test_tfm);
	name[TEST_TFM_NAME_MAX-1] = 0;

	up_read(&test_lock);

	return simple_read_from_buffer(buf, len, off, name, TEST_TFM_NAME_MAX);
}

static ssize_t test_compressor_write(struct file *file, const char __user *buf,
				     size_t len, loff_t *off)
{
	char tmp[TEST_TFM_NAME_MAX], *name;
	size_t l = min_t(size_t, len, TEST_TFM_NAME_MAX);
	u32 was_running;

	if (l < 1)
		return -EINVAL;

	if (copy_from_user(tmp, buf, l))
		return -EFAULT;
	tmp[l-1] = 0;
	name = strim(tmp);
	l = strlen(name) + 1;

	if (!crypto_has_comp(name, 0, 0))
		return -ENODEV;

	down_write(&test_lock);

	was_running = test_params.running && test_new_params.running;

	/* if was_running, this clears the running flags */
	test_stop();

	strncpy(test_tfm, name, l);
	test_tfm[l-1] = 0;

	if (was_running) {
		int ret;

		test_new_params.running = was_running;
		test_params.running = was_running;
		ret = test_start();
		if (ret)
			len = ret;
	}

	up_write(&test_lock);

	return len;
}

static const struct file_operations test_compressor_ops = {
	.owner =	THIS_MODULE,
	.read =		test_compressor_read,
	.write =	test_compressor_write,
};

static ssize_t test_status_read(struct file *file, char __user *buf,
				size_t len, loff_t *off)
{
	int tmplen = 120;
	char tmp[tmplen];

	if (!test_params.running) {
		if (*off == 0) /* haven't printed anything yet, so print msg */
			snprintf(tmp, tmplen, "Test not running\n");
		else if (*off == 1) /* printed status, just print \n */
			snprintf(tmp, tmplen, "\n");
		else /* printed msg or \n, report end */
			return 0;
		*off = 2;
		goto end;
	}

	/* slow down reading */
	schedule_timeout_interruptible(msecs_to_jiffies(250));

	snprintf(tmp, tmplen, "Threads %d MBps: %lu/%lu peak %lu/%lu       \r",
		 test_params.kthreads,
		 (unsigned long)(total_bps(0) / 1000000),
		 (unsigned long)(total_bps(1) / 1000000),
		 (unsigned long)(atomic64_read(&test_max_bps[0]) / 1000000),
		 (unsigned long)(atomic64_read(&test_max_bps[1]) / 1000000));
	tmp[tmplen - 2] = '\r';
	tmp[tmplen - 1] = 0;

end:
	len = min(len, strlen(tmp));

	if (copy_to_user(buf, tmp, len))
		return -EFAULT;

	if (*off == 0)
		*off = 1;

	return len;
}

static const struct file_operations test_status_ops = {
	.owner =	THIS_MODULE,
	.read =		test_status_read,
};

static void test_param_check_valid(int i)
{
	struct test_range *off, *len;

	off = &test_params.offset[i];
	len = &test_params.length[i];

	/* interval must be at least 1 */
	if (off->interval < 1)
		off->interval = OFFSET_INTERVAL_DEFAULT;
	if (len->interval < 1)
		len->interval = LENGTH_INTERVAL_DEFAULT;

	/* end offset + length can't be more than buffer size */
	if (off->end + len->end > TEST_BUFFER_SIZE)
		off->end = max_t(u32, 0, TEST_BUFFER_SIZE - len->end);
	if (off->end + len->end > TEST_BUFFER_SIZE)
		len->end = TEST_BUFFER_SIZE;

	/* end must be equal or after start */
	if (off->end < off->start)
		off->start = off->end;
	if (len->end < len->start)
		len->start = len->end;
}

static void test_param_change(void)
{
	bool should_run;
	int i;

	down_write(&test_lock);

	should_run = test_new_params.running;

	/* if already running, this clears running flags */
	test_stop();

	test_new_params.running = should_run;

	memcpy(&test_params, &test_new_params, sizeof(test_params));

	/* kthreads must be between 1 and max */
	if (test_params.kthreads < 1)
		test_params.kthreads = 1;
	if (test_params.kthreads > test_kthreads_max)
		test_params.kthreads = test_kthreads_max;

	/* bps_window must be at least 1 */
	if (test_params.bps_window < 1)
		test_params.bps_window = 1;

	for (i = 0; i < 3; i++)
		test_param_check_valid(i);

	/* update any corrected params */
	memcpy(&test_new_params, &test_params, sizeof(test_params));

	if (test_params.running)
		test_start();

	up_write(&test_lock);
}

static int test_check(void *ignored)
{
	bool changed;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;

		schedule_timeout(TEST_CHECK_INTERVAL);

		if (kthread_should_stop())
			break;

		down_read(&test_lock);
		changed = !!memcmp(&test_params, &test_new_params,
				   sizeof(test_params));
		up_read(&test_lock);

		if (changed)
			test_param_change();
	}

	return 0;
}

static struct task_struct *test_check_kthread;

static struct dentry *test_root;

static void test_exit(void)
{
	if (test_root && !IS_ERR(test_root))
		debugfs_remove_recursive(test_root);
	if (test_check_kthread && !IS_ERR(test_check_kthread))
		kthread_stop(test_check_kthread);
	test_stop();
	kfree(test_kthread_params);
	free_pages((unsigned long)test_buffer, test_buffer_order);
}
module_exit(test_exit);

static int __init test_init(void)
{
	struct dentry *offsets, *lengths;
	u8 test_buffer_fill_default[8] = { 0 };
	int ret = 0, i;

	if (!debugfs_initialized())
		return -EINVAL;

	test_root = debugfs_create_dir(MODULE_NAME, NULL);
	if (IS_ERR(test_root)) {
		pr_err("could not create debugfs dir %s : %ld\n",
		       MODULE_NAME, PTR_ERR(test_root));
		return PTR_ERR(test_root);
	}

	offsets = debugfs_create_dir("offsets", test_root);
	if (IS_ERR(offsets)) {
		pr_err("could not create debugfs dir %s/offsets : %ld\n",
		       MODULE_NAME, PTR_ERR(offsets));
		ret = PTR_ERR(offsets);
		goto end;
	}
	lengths = debugfs_create_dir("lengths", test_root);
	if (IS_ERR(lengths)) {
		pr_err("could not create debugfs dir %s/lengths : %ld\n",
		       MODULE_NAME, PTR_ERR(lengths));
		ret = PTR_ERR(lengths);
		goto end;
	}

	debugfs_create_file("status", S_IRUGO, test_root, NULL,
			    &test_status_ops);
	debugfs_create_file("compressor", S_IRUGO | S_IWUSR, test_root, NULL,
			    &test_compressor_ops);
	debugfs_create_file("buffer", S_IRUSR | S_IWUSR, test_root, NULL,
			    &test_buffer_ops);

	debugfs_create_bool("running", S_IRUGO | S_IWUSR, test_root,
			    &test_new_params.running);
	debugfs_create_bool("repeat", S_IRUGO | S_IWUSR, test_root,
			    &test_new_params.repeat);
	debugfs_create_u32("threads", S_IRUGO | S_IWUSR, test_root,
			    &test_new_params.kthreads);
	debugfs_create_u32("bps_window", S_IRUGO | S_IWUSR, test_root,
			    &test_new_params.bps_window);

	debugfs_create_u32("start_a", S_IRUGO | S_IWUSR, offsets,
			    &test_new_params.offset[0].start);
	debugfs_create_u32("start_b", S_IRUGO | S_IWUSR, offsets,
			    &test_new_params.offset[1].start);
	debugfs_create_u32("start_c", S_IRUGO | S_IWUSR, offsets,
			    &test_new_params.offset[2].start);
	debugfs_create_u32("end_a", S_IRUGO | S_IWUSR, offsets,
			    &test_new_params.offset[0].end);
	debugfs_create_u32("end_b", S_IRUGO | S_IWUSR, offsets,
			    &test_new_params.offset[1].end);
	debugfs_create_u32("end_c", S_IRUGO | S_IWUSR, offsets,
			    &test_new_params.offset[2].end);
	debugfs_create_u32("interval_a", S_IRUGO | S_IWUSR, offsets,
			    &test_new_params.offset[0].interval);
	debugfs_create_u32("interval_b", S_IRUGO | S_IWUSR, offsets,
			    &test_new_params.offset[1].interval);
	debugfs_create_u32("interval_c", S_IRUGO | S_IWUSR, offsets,
			    &test_new_params.offset[2].interval);

	debugfs_create_u32("start_a", S_IRUGO | S_IWUSR, lengths,
			    &test_new_params.length[0].start);
	debugfs_create_u32("start_b", S_IRUGO | S_IWUSR, lengths,
			    &test_new_params.length[1].start);
	debugfs_create_u32("start_c", S_IRUGO | S_IWUSR, lengths,
			    &test_new_params.length[2].start);
	debugfs_create_u32("end_a", S_IRUGO | S_IWUSR, lengths,
			    &test_new_params.length[0].end);
	debugfs_create_u32("end_b", S_IRUGO | S_IWUSR, lengths,
			    &test_new_params.length[1].end);
	debugfs_create_u32("end_c", S_IRUGO | S_IWUSR, lengths,
			    &test_new_params.length[2].end);
	debugfs_create_u32("interval_a", S_IRUGO | S_IWUSR, lengths,
			    &test_new_params.length[0].interval);
	debugfs_create_u32("interval_b", S_IRUGO | S_IWUSR, lengths,
			    &test_new_params.length[1].interval);
	debugfs_create_u32("interval_c", S_IRUGO | S_IWUSR, lengths,
			    &test_new_params.length[2].interval);

	test_kthread_params = kcalloc(test_kthreads_max,
				      sizeof(*test_kthread_params),
				      GFP_KERNEL);

	if (!test_kthread_params) {
		pr_err("could kthread params\n");
		ret = -ENOMEM;
		goto end;
	}

	test_buffer = (u8 *)__get_free_pages(GFP_KERNEL, test_buffer_order);
	if (!test_buffer) {
		pr_err("could not allocate test buffer\n");
		ret = -ENOMEM;
		goto end;
	}

	test_buffer_fill(test_buffer_fill_default,
			 ARRAY_SIZE(test_buffer_fill_default));

	test_params.running = 0;
	test_params.repeat = TEST_REPEAT_DEFAULT;
	test_params.kthreads = TEST_KTHREADS_DEFAULT;
	test_params.bps_window = TEST_BPS_WINDOW_DEFAULT;
	for (i = 0; i < 3; i++) {
		test_params.offset[i].start = OFFSET_START_DEFAULT;
		test_params.offset[i].end = OFFSET_END_DEFAULT;
		test_params.offset[i].interval = OFFSET_INTERVAL_DEFAULT;
		test_params.length[i].start = LENGTH_START_DEFAULT;
		test_params.length[i].end = LENGTH_END_DEFAULT;
		test_params.length[i].interval = LENGTH_INTERVAL_DEFAULT;
	}
	memcpy(&test_new_params, &test_params, sizeof(test_params));

	test_check_kthread = kthread_run(test_check, NULL, MODULE_NAME "_chk");
	if (IS_ERR(test_check_kthread))
		ret = PTR_ERR(test_check_kthread);

end:
	if (ret)
		test_exit();

	return ret;
}
module_init(test_init);

/*
 * Cryptographic API for the 842 compression algorithm.
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
 * Copyright (C) IBM Corporation, 2011-2015
 *
 * Original Authors: Robert Jennings <rcj@linux.vnet.ibm.com>
 *                   Seth Jennings <sjenning@linux.vnet.ibm.com>
 *
 * Rewrite: Dan Streetman <ddstreet@ieee.org>
 *
 * This is an interface to the NX-842 compression hardware in PowerPC
 * processors (see drivers/crypto/nx/nx-842.c for details).  Most (all?)
 * of the complexity of this drvier is due to the fact that the NX-842
 * compression hardware requires the input and output data buffers to be
 * specifically aligned, to be a specific multiple in length, and within
 * specific minimum and maximum lengths.  Those restrictions, provided by
 * the nx-842 driver via is nx842_constraints, mean this driver must use
 * bounce buffers and headers to correct misaligned in or out buffers,
 * and to split input buffers that are too large.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/vmalloc.h>
#include <linux/nx842.h>
#include <linux/sw842.h>
#include <linux/ratelimit.h>

/* The first 5 bits of this magic are 0x1f, which is an invalid 842 5-bit
 * template (see lib/842/842_decompress.c), so this magic number
 * will never appear at the start of a raw 842 compressed buffer.
 * That can be useful in the future, if buffer alignment and length is
 * correct, to not require the use of any header, which will save some
 * space in the resulting compressed buffer; then in decompress, if the
 * input buffer does not contain this header magic, it's assumed to be
 * a raw compressed buffer and should be passed directly to the NX-842
 * hardware driver.
 */
#define CRYPTO_842_MAGIC	(0xf842)
#define CRYPTO_842_GROUP_MAX	(0x19)	/* max 0-based index, real max is +1 */
#define CRYPTO_842_HEADER_SIZE(h)				\
	(sizeof(*(h)) +	sizeof((h)->group) * (h)->groups)
#define CRYPTO_842_HEADER_MAX_SIZE					\
	(sizeof(struct crypto842_header) +				\
	 sizeof(struct crypto842_header_group) * CRYPTO_842_GROUP_MAX)

/* try longer on comp because we can fallback to sw decomp if hw is busy */
#define COMP_BUSY_TIMEOUT	(250) /* ms */
#define DECOMP_BUSY_TIMEOUT	(50) /* ms */

struct crypto842_header_group {
	u16 padding;	/* unused bytes at start of group */
	u32 length;	/* length of group, not including padding */
} __packed;

struct crypto842_header {
	u16 magic;		/* CRYPTO_842_MAGIC */
	u16 ignore;		/* decompressed end bytes to ignore */
	u8 groups;		/* 0-based; add 1 for total */
	struct crypto842_header_group group[1];
} __packed;

struct crypto842_param {
	u8 *in;
	long iremain;
	u8 *out;
	long oremain;
	long ototal;
};

struct crypto842_ctx {
	void *wmem;	/* working memory for 842 */
	void *bounce;	/* bounce buffer to correct alignment */

	/* header includes 1 group, so the total usable groups are
	 * max + 1; meaning max is the highest valid 0-based index.
	 */
	struct crypto842_header header;
	struct crypto842_header_group group[CRYPTO_842_GROUP_MAX];
};

static int crypto842_init(struct crypto_tfm *tfm)
{
	struct crypto842_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->wmem = kmalloc(NX842_MEM_COMPRESS, GFP_NOFS);
	ctx->bounce = (void *)__get_free_page(GFP_NOFS);
	if (!ctx->wmem || !ctx->bounce) {
		kfree(ctx->wmem);
		free_page((unsigned long)ctx->bounce);
		return -ENOMEM;
	}

	return 0;
}

static void crypto842_exit(struct crypto_tfm *tfm)
{
	struct crypto842_ctx *ctx = crypto_tfm_ctx(tfm);

	kfree(ctx->wmem);
	free_page((unsigned long)ctx->bounce);
}

static inline bool check_len(char *type, long len)
{
	bool valid = len > 0;

	if (!valid)
		pr_err("invalid %s length 0x%lx\n", type, len);

	return valid;
}

static int read_constraints(struct nx842_constraints *c)
{
	int ret;

	ret = nx842_constraints(c);
	if (ret) {
		pr_err_ratelimited("could not get nx842 constraints : %d\n",
				   ret);
		return ret;
	}

	if (c->alignment > PAGE_SIZE) {
		WARN_ONCE(1, "NX842 alignment is invalid, ignoring : 0x%x\n",
			  c->alignment);
		c->alignment = 1;
	}

	if (c->minimum > PAGE_SIZE) {
		WARN_ONCE(1, "NX842 minimum is invalid, ignoring : 0x%x\n",
			  c->minimum);
		c->minimum = 1;
	}

	return 0;
}

static int crypto842_add_header(struct crypto842_header *hdr, u8 *buf)
{
	int s = CRYPTO_842_HEADER_SIZE(hdr);

	/* error - compress should have added space for header */
	if (s > hdr->group[0].padding) {
		WARN_ONCE(1, "Internal driver error: no space for header\n");
		return -EINVAL;
	}

	memcpy(buf, hdr, s);

	return 0;
}

static int __crypto842_compress(struct crypto842_ctx *ctx,
				struct crypto842_param *p,
				struct crypto842_header_group *g,
				struct nx842_constraints *c,
				bool first)
{
	unsigned int slen = p->iremain, dlen = p->oremain, tmplen;
	unsigned int adj_slen = slen;
	u8 *src = p->in, *dst = p->out;
	int ret, dskip;
	ktime_t timeout;

	if (p->iremain <= 0 || p->oremain <= 0)
		return -EINVAL;

	if (slen % c->multiple)
		adj_slen = round_up(slen, c->multiple);
	if (slen < c->minimum)
		adj_slen = c->minimum;
	if (slen > c->maximum)
		adj_slen = slen = c->maximum;
	if (adj_slen > slen || (unsigned long)src % c->alignment) {
		adj_slen = min_t(unsigned int, adj_slen, PAGE_SIZE);
		slen = min_t(unsigned int, slen, PAGE_SIZE);
		if (adj_slen > slen)
			memset(ctx->bounce + slen, 0, adj_slen - slen);
		memcpy(ctx->bounce, src, slen);
		src = ctx->bounce;
		slen = adj_slen;
	}

	/* skip space for the main header */
	dskip = first ? CRYPTO_842_HEADER_MAX_SIZE : 0;
	if ((unsigned long)(dst + dskip) % c->alignment)
		dskip = (int)(PTR_ALIGN(dst + dskip, c->alignment) - dst);
	if (dskip >= dlen)
		return -ENOSPC;
	dst += dskip;
	dlen -= dskip;
	if (dlen % c->multiple)
		dlen = round_down(dlen, c->multiple);
	if (dlen < c->minimum)
		return -ENOSPC;
	if (dlen > c->maximum)
		dlen = c->maximum;

	tmplen = dlen;
	timeout = ktime_add_ms(ktime_get(), COMP_BUSY_TIMEOUT);
	do {
		dlen = tmplen; /* reset dlen, if we're retrying */
		ret = nx842_compress(src, slen, dst, &dlen, ctx->wmem);
	} while (ret == -EBUSY && ktime_before(ktime_get(), timeout));
	if (ret)
		return ret;

	g->padding = dskip;
	g->length = dlen;

	p->in += slen;
	p->iremain -= slen;
	p->out += dskip + dlen;
	p->oremain -= dskip + dlen;
	p->ototal += dskip + dlen;

	return 0;
}

static int crypto842_compress(struct crypto_tfm *tfm,
			      const u8 *src, unsigned int slen,
			      u8 *dst, unsigned int *dlen)
{
	struct crypto842_ctx *ctx = crypto_tfm_ctx(tfm);
	struct crypto842_header *hdr = &ctx->header;
	struct crypto842_param p;
	struct nx842_constraints c;
	int ret;

	p.in = (u8 *)src;
	p.iremain = slen;
	p.out = dst;
	p.oremain = *dlen;
	p.ototal = 0;

	*dlen = 0;

	if (!check_len("src", p.iremain) || !check_len("dest", p.oremain))
		return -EINVAL;

	ret = read_constraints(&c);
	if (ret)
		return ret;

	hdr->magic = CRYPTO_842_MAGIC;
	hdr->groups = 0;

	while (p.iremain > 0) {
		int n = hdr->groups++;

		if (n > CRYPTO_842_GROUP_MAX)
			return -ENOSPC;

		ret = __crypto842_compress(ctx, &p, &hdr->group[n], &c, !n);
		if (ret)
			return ret;
	}

	/* count is zero-based, so 1 less than actual count */
	hdr->groups--;

	/* ignore indicates the input stream needed to be padded */
	hdr->ignore = abs(p.iremain);
	if (hdr->ignore)
		pr_debug("marked %d bytes as ignore\n", hdr->ignore);

	ret = crypto842_add_header(hdr, dst);
	if (ret)
		return ret;

	*dlen = p.ototal;

	return 0;
}

static int __crypto842_decompress(struct crypto842_ctx *ctx,
				  struct crypto842_param *p,
				  struct crypto842_header_group *g,
				  struct nx842_constraints *c,
				  bool usehw)
{
	unsigned int slen = g->length, dlen = p->oremain, tmplen;
	u8 *src = p->in, *dst = p->out;
	int ret, doffset = 0;
	ktime_t timeout;

	if (p->iremain <= 0 || p->oremain <= 0 || !slen)
		return -EINVAL;

	if (g->padding + slen > p->iremain)
		return -EINVAL;

	src += g->padding;

	if (usehw) {
		/* skip length-based constraints for compressed buffer;
		 * the hardware created it, so it should accept any
		 * buffer length it created.  Defer to the hw driver
		 * to handle or reject.
		 *
		 * however we do need to correct alignment, since the buffer
		 * may have been moved in memory since it was created.
		 */
		if ((unsigned long)src % c->alignment) {
			/* We only have 1 page of bounce buffer; if the
			 * compressed data is larger and misaligned, we'll
			 * have to use sw to decompress.  If this is a
			 * common problem, someone should increase the
			 * bounce buffer size (or make sure you keep large
			 * compressed buffers aligned).
			 */
			if (slen > PAGE_SIZE) {
				pr_warn("Compressed buffer misaligned\n");
				usehw = false;
			} else {
				memcpy(ctx->bounce, src, slen);
				src = ctx->bounce;
			}
		}

		/* if the dest buffer isn't aligned, we have no choice but to
		 * use an aligned buffer and copy the results into place.
		 * So we just align the start position, reduce the length, and
		 * after decompressing move the data back to the actual buffer
		 * start position.
		 */
		if ((unsigned long)dst % c->alignment) {
			doffset = (int)(PTR_ALIGN(dst, c->alignment) - dst);
			dst += doffset;
			dlen -= doffset;
		}
		if (dlen % c->multiple)
			dlen = round_down(dlen, c->multiple);
		if (dlen < c->minimum)
			return -ENOSPC;
		if (dlen > c->maximum)
			dlen = c->maximum;
	}

	tmplen = dlen;
	timeout = ktime_add_ms(ktime_get(), DECOMP_BUSY_TIMEOUT);
	do {
		if (!usehw)
			break;

		dlen = tmplen; /* reset dlen, if we're retrying */
		ret = nx842_decompress(src, slen, dst, &dlen, ctx->wmem);
	} while (ret == -EBUSY && ktime_before(ktime_get(), timeout));
	if (!usehw || ret) {
		dlen = tmplen; /* reset dlen, if hw failed */
		ret = sw842_decompress(src, slen, dst, &dlen);
	}
	if (ret)
		return ret;

	if (doffset) {
		dst -= doffset;
		memmove(dst, dst + doffset, dlen);
	}

	p->in += g->padding + slen;
	p->iremain -= g->padding + slen;
	p->out += doffset + dlen;
	p->oremain -= doffset + dlen;
	p->ototal += doffset + dlen;

	return 0;
}

static int crypto842_decompress(struct crypto_tfm *tfm,
				const u8 *src, unsigned int slen,
				u8 *dst, unsigned int *dlen)
{
	struct crypto842_ctx *ctx = crypto_tfm_ctx(tfm);
	struct crypto842_header *hdr;
	struct crypto842_param p;
	struct nx842_constraints c;
	int n, ret, hdr_len;
	bool usehw = true;

	p.in = (u8 *)src;
	p.iremain = slen;
	p.out = dst;
	p.oremain = *dlen;
	p.ototal = 0;

	*dlen = 0;

	if (!check_len("src", p.iremain) || !check_len("dest", p.oremain))
		return -EINVAL;

	ret = read_constraints(&c);
	if (ret) {
		pr_err("could not get nx842 constraints : %d\n", ret);
		usehw = false;
		ret = 0;
	}

	hdr = (struct crypto842_header *)src;

	/* If it doesn't start with our header magic number,
	 * we didn't create it and therefore can't decompress it.
	 */
	if (hdr->magic != CRYPTO_842_MAGIC) {
		pr_err("header magic 0x%04x is not 0x%04x\n",
			 hdr->magic, CRYPTO_842_MAGIC);
		return -EINVAL;
	}
	if (hdr->groups > CRYPTO_842_GROUP_MAX) {
		pr_err("header has too many groups 0x%x, max 0x%x\n",
			 hdr->groups, CRYPTO_842_GROUP_MAX);
		return -EINVAL;
	}

	hdr_len = CRYPTO_842_HEADER_SIZE(hdr);
	memcpy(&ctx->header, src, hdr_len);
	hdr = &ctx->header;

	/* groups is zero-based */
	for (n = 0; n <= hdr->groups; n++) {
		if (n > CRYPTO_842_GROUP_MAX)
			return -EINVAL;

		ret = __crypto842_decompress(ctx, &p, &hdr->group[n], &c,
					     usehw);
		if (ret)
			return ret;
	}

	/* ignore the last N bytes, which were padding */
	p.ototal -= hdr->ignore;
	if (hdr->ignore)
		pr_debug("ignoring last 0x%x bytes:\n", hdr->ignore);

	*dlen = p.ototal;

	return 0;
}

static struct crypto_alg alg = {
	.cra_name		= "842",
	.cra_flags		= CRYPTO_ALG_TYPE_COMPRESS,
	.cra_ctxsize		= sizeof(struct crypto842_ctx),
	.cra_module		= THIS_MODULE,
	.cra_init		= crypto842_init,
	.cra_exit		= crypto842_exit,
	.cra_u			= { .compress = {
	.coa_compress		= crypto842_compress,
	.coa_decompress		= crypto842_decompress } }
};

static int __init crypto842_mod_init(void)
{
	return crypto_register_alg(&alg);
}

static void __exit crypto842_mod_exit(void)
{
	crypto_unregister_alg(&alg);
}

module_init(crypto842_mod_init);
module_exit(crypto842_mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("842 Compression Algorithm");
MODULE_AUTHOR("Dan Streetman <ddstreet@ieee.org>");
MODULE_ALIAS_CRYPTO("842");

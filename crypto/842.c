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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corporation, 2011
 *
 * Authors: Robert Jennings <rcj@linux.vnet.ibm.com>
 *          Seth Jennings <sjenning@linux.vnet.ibm.com>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/vmalloc.h>
#include <linux/nx842.h>
#include <linux/sw842.h>
#include <linux/timer.h>

struct crypto842_ctx {
	void *wmem; /* working memory for 842 */
};

static int crypto842_init(struct crypto_tfm *tfm)
{
	struct crypto842_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->wmem = kmalloc(NX842_MEM_COMPRESS, GFP_NOFS);
	if (!ctx->wmem)
		return -ENOMEM;

	return 0;
}

static void crypto842_exit(struct crypto_tfm *tfm)
{
	struct crypto842_ctx *ctx = crypto_tfm_ctx(tfm);

	kfree(ctx->wmem);
}

static int crypto842_compress(struct crypto_tfm *tfm, const u8 *src,
			    unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct crypto842_ctx *ctx = crypto_tfm_ctx(tfm);

	return nx842_compress(src, slen, dst, dlen, ctx->wmem);
}

static int crypto842_decompress(struct crypto_tfm *tfm, const u8 *src,
			      unsigned int slen, u8 *dst, unsigned int *dlen)
{
	struct crypto842_ctx *ctx = crypto_tfm_ctx(tfm);

	if (nx842_decompress(src, slen, dst, dlen, ctx->wmem))
		return sw842_decompress(src, slen, dst, dlen);

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

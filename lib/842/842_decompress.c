/*
 * 842 Decompressor
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
 *
 * The 842 compressed format is made up of multiple blocks, each of
 * which have the format:
 *
 * <template>[arg1][arg2][arg3][arg4]
 *
 * where there are between 0 and 4 template args, depending on the specific
 * template operation.  For normal operations, each arg is either a specific
 * number of data bytes to add to the output stream, or an index pointing
 * to a previously-written number of data bytes to copy to the output stream.
 *
 * The template code is a 5-bit value.  This code indicates what to
 * do with the following data.  Template codes from 0 to 0x19 should
 * use the template table, the static "ops" table in the code below.
 * For each template (table row), there are between 1 and 4 actions;
 * each action corresponds to an arg following the template code
 * bits.  Each action is either a "data" type action, or a "index"
 * type action, and each action results in 2, 4, or 8 bytes being
 * written to the output stream.  Each template (i.e. all actions in
 * the table row) will add up to 8 bytes being written to the output
 * stream.  Any row with less than 4 actions is padded with noop
 * actions, indicated by N0 (for which there is no corresponding arg
 * in the compressed data stream).
 *
 * "Data" actions, indicated in the table by D2, D4, and D8, mean that
 * the corresponding arg is 2, 4, or 8 bytes, respectively, in the
 * compressed data stream should be copied directly to the output stream.
 *
 * "Index" actions, indicated in the table by I2, I4, and I8, mean
 * the corresponding arg is an index parameter that points to,
 * respectively, a 2, 4, or 8 byte value already in the output
 * stream, that should be copied to the end of the output stream.
 * Essentially, the index points to a position in a ring buffer that
 * contains the last N bytes of output stream data.  The number of bits
 * for each index's arg are: 8 bits for I2, 9 bits for I4, and 8 bits for
 * I8.  Since each index points to a 2, 4, or 8 byte section, this means
 * that I2 can reference 512 bytes ((2^8 bits = 256) * 2 bytes), I4 can
 * reference 2048 bytes ((2^9 = 512) * 4 bytes), and I8 can reference
 * 2048 bytes ((2^8 = 256) * 8 bytes).  Think of it as a dedicated ring
 * buffer for each of I2, I4, and I8 that are updated for each byte
 * written to the output stream.  In this implementation, the output stream
 * is directly used for each index; there is no additional memory required.
 * Note that the index is into a ring buffer, not a sliding window;
 * for example, if there have been 260 bytes written to the output stream,
 * an I2 index of 0 would index to byte 256 in the output stream, while
 * an I2 index of 16 would index to byte 16 in the output stream.
 *
 * There are also 3 special template codes; 0x1b for "repeat", 0x1c for
 * "zeros", and 0x1e for "end".  The "repeat" operation is followed by
 * a 6 bit arg N indicating how many times to repeat.  The last 8
 * bytes written to the output stream are written again to the output
 * stream, N + 1 times.  The "zeros" operation, which has no arg bits,
 * writes 8 zeros to the output stream.  The "end" operation, which also
 * has no arg bits, signals the end of the compressed data.  There may
 * be some number of padding (don't care, but usually 0) bits after
 * the "end" operation bits, to fill the stream length to a specific
 * byte multiple (usually a multiple of 8, 16, or 32 bytes).
 *
 * After all actions for each operation code are processed, another
 * template code is in the next 5 bits.  The decompression ends
 * once the "end" template code is detected.
 */

#ifndef STATIC
#include <linux/module.h>
#include <linux/kernel.h>
#endif

#include <linux/sw842.h>

/* special templates */
#define OP_REPEAT	(0x1B)
#define OP_ZEROS	(0x1C)
#define OP_END		(0x1E)

/* additional bits of each op param */
#define OP_BITS		(5)
#define REPEAT_BITS	(6)
#define I2_BITS		(8)
#define I4_BITS		(9)
#define I8_BITS		(8)

/* rolling fifo sizes */
#define I2_FIFO_SIZE	(512)
#define I4_FIFO_SIZE	(2048)
#define I8_FIFO_SIZE	(2048)

/* Arbitrary values used to indicate action */
#define OP_ACTION	(0x30)
#define OP_ACTION_NOOP	(0x00)
#define OP_ACTION_DATA	(0x10)
#define OP_ACTION_INDEX	(0x20)
#define OP_AMOUNT	(0x0f)
#define OP_AMOUNT_0	(0x00)
#define OP_AMOUNT_2	(0x02)
#define OP_AMOUNT_4	(0x04)
#define OP_AMOUNT_8	(0x08)

#define D2		(OP_ACTION_DATA  | OP_AMOUNT_2)
#define D4		(OP_ACTION_DATA  | OP_AMOUNT_4)
#define D8		(OP_ACTION_DATA  | OP_AMOUNT_8)
#define I2		(OP_ACTION_INDEX | OP_AMOUNT_2)
#define I4		(OP_ACTION_INDEX | OP_AMOUNT_4)
#define I8		(OP_ACTION_INDEX | OP_AMOUNT_8)
#define N0		(OP_ACTION_NOOP  | OP_AMOUNT_0)

#define OPS_MAX		(0x19)

static u8 ops[OPS_MAX + 1][4] = {
	{ D8, N0, N0, N0 },
	{ D4, D2, I2, N0 },
	{ D4, I2, D2, N0 },
	{ D4, I2, I2, N0 },
	{ D4, I4, N0, N0 },
	{ D2, I2, D4, N0 },
	{ D2, I2, D2, I2 },
	{ D2, I2, I2, D2 },
	{ D2, I2, I2, I2 },
	{ D2, I2, I4, N0 },
	{ I2, D2, D4, N0 },
	{ I2, D4, I2, N0 },
	{ I2, D2, I2, D2 },
	{ I2, D2, I2, I2 },
	{ I2, D2, I4, N0 },
	{ I2, I2, D4, N0 },
	{ I2, I2, D2, I2 },
	{ I2, I2, I2, D2 },
	{ I2, I2, I2, I2 },
	{ I2, I2, I4, N0 },
	{ I4, D4, N0, N0 },
	{ I4, D2, I2, N0 },
	{ I4, I2, D2, N0 },
	{ I4, I2, I2, N0 },
	{ I4, I4, N0, N0 },
	{ I8, N0, N0, N0 }
};

struct sw842_param {
	u8 *in;
	int bit;
	int ilen;
	u8 *out;
	u8 *ostart;
	int olen;
};

/**
 * Get the next specified bits, up to 57 bits
 *
 * This also increments the byte and bit positions, and remaining
 * length.  This can return no more than 57 bits, because in the
 * worst case the starting bit is bit 7, which would place the end
 * of the following 57 bits at the end of an 8 byte span, which
 * is the max that this function's type casting approach can
 * handle.
 *
 * Returns: the value of the requested bits, or -1 on failure
 */
static s64 next_bits(struct sw842_param *p, int n)
{
	u64 v;
	u8 *in = p->in;
	int b = p->bit, bits = b + n;

	if (b > 7 || n > 57) {
		WARN(1, "b %d n %d\n", b, n);
		return -EINVAL;
	}

	if (DIV_ROUND_UP(bits, 8) > p->ilen)
		return -EOVERFLOW;

	if (bits <= 8)
		v = *in >> (8 - bits);
	else if (bits <= 16)
		v = be16_to_cpu(*(__be16 *)in) >> (16 - bits);
	else if (bits <= 32)
		v = be32_to_cpu(*(__be32 *)in) >> (32 - bits);
	else
		v = be64_to_cpu(*(__be64 *)in) >> (64 - bits);

	p->bit += n;

	p->in += p->bit / 8;
	p->ilen -= p->bit / 8;
	p->bit %= 8;

	return (s64)(v & ((1 << n) - 1));
}

static int __do_data(struct sw842_param *p, int n)
{
	s64 v = next_bits(p, n * 8);

	if (v < 0 || n > p->olen)
		return -EINVAL;

	switch (n) {
	case 2:
		*(__be16 *)p->out = cpu_to_be16((u16)v);
		break;
	case 4:
		*(__be32 *)p->out = cpu_to_be32((u32)v);
		break;
	default:
		return -EINVAL;
	}
	p->out += n;
	p->olen -= n;

	return 0;
}

static int do_data(struct sw842_param *p, int n)
{
	switch (n) {
	case 2:
		if (__do_data(p, 2))
			return -EINVAL;
		break;
	case 8:
		/* we copy two 4-byte chunks here because
		 * next_bits() can't do a full 64 bits
		 */
		if (__do_data(p, 4))
			return -EINVAL;
		/* fallthrough */
	case 4:
		if (__do_data(p, 4))
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int __do_index(struct sw842_param *p, int size, int bits, int fsize)
{
	s64 index = next_bits(p, bits);
	u64 offset;
	int total = (int)(p->out - p->ostart);

	if (index < 0)
		return -EINVAL;

	offset = index * size;

	/* a ring buffer of fsize is used; correct the offset */
	if (total > fsize) {
		/* this is where the current fifo is */
		int sec = (total / fsize) * fsize;
		/* the current pos in the fifo */
		int pos = total % fsize;

		/* if the offset is past/at the pos, we need to
		 * go back to the last fifo section
		 */
		if (offset >= pos)
			sec -= fsize;

		offset += sec;
	}

	if (offset + size > total)
		return -EINVAL;

	memcpy(p->out, &p->ostart[offset], size);
	p->out += size;
	p->olen -= size;

	return 0;
}

int do_index(struct sw842_param *p, int n)
{
	switch (n) {
	case 2:
		return __do_index(p, 2, I2_BITS, I2_FIFO_SIZE);
	case 4:
		return __do_index(p, 4, I4_BITS, I4_FIFO_SIZE);
	case 8:
		return __do_index(p, 8, I8_BITS, I8_FIFO_SIZE);
	default:
		return -EINVAL;
	}
}

int do_op(struct sw842_param *p, int o)
{
	int i;
	u8 op, n;

	if (o > OPS_MAX)
		return -EINVAL;

	for (i = 0; i < 4; i++) {
		op = ops[o][i];
		n = op & OP_AMOUNT;

		switch (op & OP_ACTION) {
		case OP_ACTION_DATA:
			if (do_data(p, n))
				return -EINVAL;
			break;
		case OP_ACTION_INDEX:
			if (do_index(p, n))
				return -EINVAL;
			break;
		case OP_ACTION_NOOP:
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * sw842_decompress
 *
 * Decompress the 842-compressed buffer of length @len at @in
 * to the output buffer @out.
 *
 * The compressed buffer must be only a single 842-compressed buffer,
 * with the standard format described in the comments at the top of
 * this file.  Processing will stop when the 842 "END" template is
 * detected, not the end of the buffer.
 *
 * Returns: 0 on success, error on failure.  The @olen parameter
 * will contain the number of output bytes written on success, or
 * 0 on error.
 */
int sw842_decompress(const unsigned char *in, int len,
		     unsigned char *out, int *olen)
{
	struct sw842_param p;
	int op, total = *olen;

	p.in = (unsigned char *)in;
	p.bit = 0;
	p.ilen = len;
	p.out = out;
	p.ostart = out;
	p.olen = *olen;

	*olen = 0;

	while ((op = (int)next_bits(&p, OP_BITS)) != OP_END) {
		if (op < 0)
			return op;

		if (op == OP_REPEAT) {
			int rep = (int)next_bits(&p, REPEAT_BITS);

			if (rep < 0)
				return rep;

			if (p.out == out) /* no previous bytes */
				return -EINVAL;

			/* copy rep + 1 */
			rep++;

			if (rep * 8 > p.olen)
				return -ENOSPC;

			while (rep-- > 0) {
				memcpy(p.out, p.out - 8, 8);
				p.out += 8;
				p.olen -= 8;
			}
		} else if (op == OP_ZEROS) {
			if (8 > p.olen)
				return -ENOSPC;

			memset(p.out, 0, 8);
			p.out += 8;
			p.olen -= 8;
		} else { /* use template */
			if (do_op(&p, op))
				return -EINVAL;
		}
	}

	*olen = total - p.olen;

	return 0;
}
#ifndef STATIC
EXPORT_SYMBOL_GPL(sw842_decompress);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Software 842 Decompressor");
MODULE_AUTHOR("Dan Streetman <ddstreet@ieee.org>");

#endif

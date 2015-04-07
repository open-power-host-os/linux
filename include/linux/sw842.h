#ifndef __SW842_H__
#define __SW842_H__

int sw842_decompress(const unsigned char *src, int srclen,
			unsigned char *dst, int *destlen);

#endif

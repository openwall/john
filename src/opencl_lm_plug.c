/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#if HAVE_OPENCL

#include <string.h>

#include "opencl_lm.h"
#include "arch.h"
#include "common.h"
#include "../run/opencl/opencl_lm_hst_dev_shared.h"
#include "unicode.h"
#include "mask_ext.h"

opencl_lm_combined *opencl_lm_all;
opencl_lm_transfer *opencl_lm_keys;
unsigned int *opencl_lm_int_key_loc = NULL;
unsigned int CC_CACHE_ALIGN opencl_lm_index768[0x300];
unsigned char opencl_lm_u[0x100];

static unsigned char LM_KP[56] = {
	1, 2, 3, 4, 5, 6, 7,
	10, 11, 12, 13, 14, 15, 0,
	19, 20, 21, 22, 23, 8, 9,
	28, 29, 30, 31, 16, 17, 18,
	37, 38, 39, 24, 25, 26, 27,
	46, 47, 32, 33, 34, 35, 36,
	55, 40, 41, 42, 43, 44, 45,
	48, 49, 50, 51, 52, 53, 54
};

static unsigned char LM_reverse[16] = {
	0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15
};

static  unsigned char LM_IP[64] = {
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
	56, 48, 40, 32, 24, 16, 8, 0,
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6
};

static unsigned char opencl_LM_PC1[56] = {
	56, 48, 40, 32, 24, 16, 8,
	0, 57, 49, 41, 33, 25, 17,
	9, 1, 58, 50, 42, 34, 26,
	18, 10, 2, 59, 51, 43, 35,
	62, 54, 46, 38, 30, 22, 14,
	6, 61, 53, 45, 37, 29, 21,
	13, 5, 60, 52, 44, 36, 28,
	20, 12, 4, 27, 19, 11, 3
};

static unsigned char opencl_LM_ROT[16] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static unsigned char opencl_LM_PC2[48] = {
	13, 16, 10, 23, 0, 4,
	2, 27, 14, 5, 20, 9,
	22, 18, 11, 3, 25, 7,
	15, 6, 26, 19, 12, 1,
	40, 51, 30, 36, 46, 54,
	29, 39, 50, 44, 32, 47,
	43, 48, 38, 55, 33, 52,
	45, 41, 49, 35, 28, 31
};

void opencl_lm_init_index()
{
	int p,q,s,t ;
	int round, index, bit;

	s = 0;
	t = 0;
	for (round = 0; round < 16; round++) {
		s += opencl_LM_ROT[round];
		for (index = 0; index < 48; index++) {
			p = opencl_LM_PC2[index];
			q = p < 28 ? 0 : 28;
			p += s;
			while (p >= 28) p -= 28;
			bit = opencl_LM_PC1[p + q];
			bit ^= 070;
			bit -= bit >> 3;
			bit = 55 - bit;
			bit = LM_KP[bit];
			opencl_lm_index768[t++] = bit;
		}
	}

	for (p = 0; p < 0x100; p++)
		opencl_lm_u[p] = CP_up[p];
}

void opencl_lm_init(int block)
{
	int index;

	for (index = 0; index < LM_DEPTH; index++)
		opencl_lm_all[block].pxkeys[index] =
			&opencl_lm_keys[block].xkeys.c[0][index & 7][index >> 3];
}

void opencl_lm_set_key(char *key, int index)
{
	unsigned long c;
	unsigned char *dst;
	unsigned int section, key_index;

	section = index >> LM_LOG_DEPTH;
	key_index = index & (LM_DEPTH - 1);
	dst = opencl_lm_all[section].pxkeys[key_index];

	c = (unsigned char)key[0];
	if (!c) goto fill7;
	*dst = opencl_lm_u[c];
	c = (unsigned char)key[1];
	if (!c) goto fill6;
	*(dst + sizeof(lm_vector) * 8) = opencl_lm_u[c];
	c = (unsigned char)key[2];
	if (!c) goto fill5;
	*(dst + sizeof(lm_vector) * 8 * 2) = opencl_lm_u[c];
	c = (unsigned char)key[3];
	if (!c) goto fill4;
	*(dst + sizeof(lm_vector) * 8 * 3) = opencl_lm_u[c];
	c = (unsigned char)key[4];
	if (!c) goto fill3;
	*(dst + sizeof(lm_vector) * 8 * 4) = opencl_lm_u[c];
	c = (unsigned char)key[5];
	if (!c) goto fill2;
	*(dst + sizeof(lm_vector) * 8 * 5) = opencl_lm_u[c];
	c = (unsigned char)key[6];
	*(dst + sizeof(lm_vector) * 8 * 6) = opencl_lm_u[c];
	return;
fill7:
	dst[0] = 0;
fill6:
	dst[sizeof(lm_vector) * 8] = 0;
fill5:
	dst[sizeof(lm_vector) * 8 * 2] = 0;
fill4:
	dst[sizeof(lm_vector) * 8 * 3] = 0;
fill3:
	dst[sizeof(lm_vector) * 8 * 4] = 0;
fill2:
	dst[sizeof(lm_vector) * 8 * 5] = 0;
	dst[sizeof(lm_vector) * 8 * 6] = 0;
}

void opencl_lm_set_key_mm(char *key, int index)
{
	unsigned int len = strlen(key);
	unsigned int i;
	unsigned long c;

	for (i = 0; i < len; i++) {
		c = (unsigned char) key[i];
		memset(opencl_lm_keys[index].xkeys.v[i], opencl_lm_u[c], 8 * sizeof(lm_vector));
	}

	for (i = len; i < PLAINTEXT_LENGTH; i++)
		memset(opencl_lm_keys[index].xkeys.v[i], 0, 8 * sizeof(lm_vector));

	if (!mask_gpu_is_static) {
		opencl_lm_int_key_loc[index] = 0;
		for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
			if (mask_skip_ranges[i] != -1)  {
				opencl_lm_int_key_loc[index] |= ((mask_int_cand.
				int_cpu_mask_ctx->ranges[mask_skip_ranges[i]].offset +
				mask_int_cand.int_cpu_mask_ctx->
				ranges[mask_skip_ranges[i]].pos) & 0xff) << (i << 3);
			}
			else
				opencl_lm_int_key_loc[index] |= 0x80 << (i << 3);
		}
	}
}

static WORD *lm_get_binary_raw(WORD *raw, int count)
{
	static WORD out[2];

/* For odd iteration counts, swap L and R here instead of doing it one
 * more time in lm_crypt(). */
	count &= 1;
	out[count] = raw[0];
	out[count ^ 1] = raw[1];

	return out;
}

static WORD *opencl_lm_do_IP(WORD in[2])
{
	static WORD out[2];
	int src, dst;

	out[0] = out[1] = 0;
	for (dst = 0; dst < 64; dst++) {
		src = LM_IP[dst ^ 0x20];

		if (in[src >> 5] & (1 << (src & 0x1F)))
			out[dst >> 5] |= 1 << (dst & 0x1F);
	}

	return out;
}

WORD *opencl_lm_get_binary(char *ciphertext)
{
	WORD block[2], value;
	int l, h;
	int index;

	block[0] = block[1] = 0;
	for (index = 0; index < 16; index += 2) {
		l = atoi16[ARCH_INDEX(ciphertext[index])];
		h = atoi16[ARCH_INDEX(ciphertext[index + 1])];
		value = LM_reverse[l] | (LM_reverse[h] << 4);
		block[index >> 3] |= value << ((index << 2) & 0x18);
	}

	return lm_get_binary_raw(opencl_lm_do_IP(block), 1);
}

static WORD *opencl_lm_do_FP(WORD in[2])
{
	static WORD out[2];
	int src, dst;

	out[0] = out[1] = 0;
	for (src = 0; src < 64; src++) {
		dst = LM_IP[src ^ 0x20];

		if (in[src >> 5] & ((unsigned WORD)1 << (src & 0x1F)))
			out[dst >> 5] |= (unsigned WORD)1 << (dst & 0x1F);
	}

	return out;
}

char *opencl_lm_get_source(WORD *raw)
{
	static char out[17];
	char *p;
	WORD swapped[2], *block, value;
	int l, h;
	int index;

	swapped[0] = raw[1];
	swapped[1] = raw[0];

	block = opencl_lm_do_FP(swapped);

	p = out;
	for (index = 0; index < 16; index += 2) {
		value = (block[index >> 3] >> ((index << 2) & 0x18)) & 0xff;
		l = LM_reverse[value & 0xf];
		h = LM_reverse[value >> 4];
		*p++ = itoa16[l];
		*p++ = itoa16[h];
	}
	*p = 0;

	return out;
}

#endif /* #if HAVE_OPENCL */

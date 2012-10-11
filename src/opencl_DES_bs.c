/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9 
 */

#include <string.h>

#include "arch.h"
#include "common.h"
#include "opencl_DES_bs.h"
#include "unicode.h"


#define DEPTH
#define START
#define init_depth()
#define for_each_depth()

opencl_DES_bs_combined CC_CACHE_ALIGN opencl_DES_bs_all[MULTIPLIER];

static unsigned char DES_LM_KP[56] = {
	1, 2, 3, 4, 5, 6, 7,
	10, 11, 12, 13, 14, 15, 0,
	19, 20, 21, 22, 23, 8, 9,
	28, 29, 30, 31, 16, 17, 18,
	37, 38, 39, 24, 25, 26, 27,
	46, 47, 32, 33, 34, 35, 36,
	55, 40, 41, 42, 43, 44, 45,
	48, 49, 50, 51, 52, 53, 54
};

static unsigned char DES_LM_reverse[16] = {
	0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15
};

static unsigned char opencl_DES_E[48] = {
	31, 0, 1, 2, 3, 4,
	3, 4, 5, 6, 7, 8,
	7, 8, 9, 10, 11, 12,
	11, 12, 13, 14, 15, 16,
	15, 16, 17, 18, 19, 20,
	19, 20, 21, 22, 23, 24,
	23, 24, 25, 26, 27, 28,
	27, 28, 29, 30, 31, 0
};

static  unsigned char DES_IP[64] = {
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
	56, 48, 40, 32, 24, 16, 8, 0,
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6
};

static unsigned char opencl_DES_PC1[56] = {
	56, 48, 40, 32, 24, 16, 8,
	0, 57, 49, 41, 33, 25, 17,
	9, 1, 58, 50, 42, 34, 26,
	18, 10, 2, 59, 51, 43, 35,
	62, 54, 46, 38, 30, 22, 14,
	6, 61, 53, 45, 37, 29, 21,
	13, 5, 60, 52, 44, 36, 28,
	20, 12, 4, 27, 19, 11, 3
};

static unsigned char opencl_DES_ROT[16] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static unsigned char opencl_DES_PC2[48] = {
	13, 16, 10, 23, 0, 4,
	2, 27, 14, 5, 20, 9,
	22, 18, 11, 3, 25, 7,
	15, 6, 26, 19, 12, 1,
	40, 51, 30, 36, 46, 54,
	29, 39, 50, 44, 32, 47,
	43, 48, 38, 55, 33, 52,
	45, 41, 49, 35, 28, 31
};

static unsigned char DES_atoi64[0x100] = {
	18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
	34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
	50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0, 1,
	2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 5, 6, 7, 8, 9, 10,
	11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
	27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 32, 33, 34, 35, 36,
	37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
	53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0, 1, 2, 3, 4,
	5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
	37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
	53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0, 1, 2, 3, 4,
	5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
	37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
	53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0, 1, 2, 3, 4
};
void init_index(int LM)
{	
	int p,q,s,t ;
	int round, index, bit;

	s = 0;
	t = 0;
	for (round = 0; round < 16; round++) {
		s += opencl_DES_ROT[round];
		for (index = 0; index < 48; index++) {
			p = opencl_DES_PC2[index];
			q = p < 28 ? 0 : 28;
			p += s;
			while (p >= 28) p -= 28;
			bit = opencl_DES_PC1[p + q];
			bit ^= 070;
			bit -= bit >> 3;
			bit = 55 - bit;
			if (LM) bit = DES_LM_KP[bit];
			//*k++ = &opencl_DES_bs_all[block].K[bit] START;
			index768[t++] = bit;
		}
	}
  
}

void opencl_DES_bs_init(int LM, int cpt,int block)
{
	//WORD **k;
	int index;
	//int p, q, s, round, bit;
	//int c;

	for_each_t(n) {
/*	  
#if DES_BS_EXPAND
		if (LM)
			k = opencl_DES_bs_all[block].KS.p;
		else
			k = opencl_DES_bs_all[block].KSp;
#else
		k = opencl_DES_bs_all[block].KS.p;
#endif

		s = 0;
		for (round = 0; round < 16; round++) {
			s += opencl_DES_ROT[round];
			for (index = 0; index < 48; index++) {
				p = opencl_DES_PC2[index];
				q = p < 28 ? 0 : 28;
				p += s;
				while (p >= 28) p -= 28;
				bit = opencl_DES_PC1[p + q];
				bit ^= 070;
				bit -= bit >> 3;
				bit = 55 - bit;
				if (LM) bit = DES_LM_KP[bit];
				*k++ = &opencl_DES_bs_all[block].K[bit] START;
			}
		}*/
if(block==0)
init_index(LM);
/*
 * Have keys go to bit layers where DES_bs_get_hash() and DES_bs_cmp_one()
 * currently expect them.
 */
		for (index = 0; index < DES_BS_DEPTH; index++)
			opencl_DES_bs_all[block].pxkeys[index] =
			    &opencl_DES_bs_data[block].xkeys.c[0][index & 7][index >> 3];

		if (LM) {
			/*for (c = 0; c < 0x100; c++)
#ifdef BENCH_BUILD
			if (c >= 'a' && c <= 'z')
				opencl_DES_bs_all[block].E.u[c] = c & ~0x20;
			else
				opencl_DES_bs_all[block].E.u[c] = c;
#else
			opencl_DES_bs_all[block].E.u[c] = CP_up[c];
#endif*/
		} else {
			for (index = 0; index < 48; index++)
				//opencl_DES_bs_all[block].Ens[index] =
				  //  &opencl_DES_bs_all[block].B[opencl_DES_E[index]];
			opencl_DES_bs_all[block].Ens[index] =
				    &B[opencl_DES_E[index] + block*64];
			opencl_DES_bs_all[block].salt = 0xffffff;

			opencl_DES_bs_set_salt(0);

		}


		//memset(&opencl_DES_bs_data[block].zero, 0, sizeof(opencl_DES_bs_data[block].zero));
		//memset(&opencl_DES_bs_data[block].ones, -1, sizeof(opencl_DES_bs_data[block].ones));
		//for (bit = 0; bit < 8; bit++)
			//memset(&opencl_DES_bs_data[block].masks[bit], 1 << bit,
			  //  sizeof(opencl_DES_bs_data[block].masks[bit]));

	}


}

void opencl_DES_bs_set_key(char *key, int index)
{
	unsigned char *dst;
	unsigned int sector,key_index;
	unsigned int flag=key[0];
	init_t();
	sector = index>>DES_BS_LOG2;
	key_index = index & (DES_BS_DEPTH-1);
	dst = opencl_DES_bs_all[sector].pxkeys[key_index];

	opencl_DES_bs_data[sector].keys_changed = 1;
	
	dst[0] = 				(!flag)?0:key[0];
	dst[sizeof(DES_bs_vector) * 8]      =	(!flag)?0:key[1];
	flag = flag&&key[1] ;
	dst[sizeof(DES_bs_vector) * 8 * 2]  =	(!flag)?0:key[2];
	flag = flag&&key[2];
	dst[sizeof(DES_bs_vector) * 8 * 3]  =	(!flag)?0:key[3];
	flag = flag&&key[3];
	dst[sizeof(DES_bs_vector) * 8 * 4]  =	(!flag)?0:key[4];
	flag = flag&&key[4]&&key[5];
	dst[sizeof(DES_bs_vector) * 8 * 5]  =	(!flag)?0:key[5];
	flag = flag&&key[6];
	dst[sizeof(DES_bs_vector) * 8 * 6]  =	(!flag)?0:key[6];
	dst[sizeof(DES_bs_vector) * 8 * 7]  =	(!flag)?0:key[7];
/*
	if (!key[0]) goto fill8;
	*dst = key[0];
	*(dst + sizeof(DES_bs_vector) * 8) = key[1];
	*(dst + sizeof(DES_bs_vector) * 8 * 2) = key[2];
	if (!key[1]) goto fill6;
	if (!key[2]) goto fill5;
	*(dst + sizeof(DES_bs_vector) * 8 * 3) = key[3];
	*(dst + sizeof(DES_bs_vector) * 8 * 4) = key[4];
	if (!key[3]) goto fill4;
	if (!key[4] || !key[5]) goto fill3;
	*(dst + sizeof(DES_bs_vector) * 8 * 5) = key[5];
	if (!key[6]) goto fill2;
	*(dst + sizeof(DES_bs_vector) * 8 * 6) = key[6];
	*(dst + sizeof(DES_bs_vector) * 8 * 7) = key[7];
	return;
fill8:
	dst[0] = 0;
	dst[sizeof(DES_bs_vector) * 8] = 0;
fill6:
	dst[sizeof(DES_bs_vector) * 8 * 2] = 0;
fill5:
	dst[sizeof(DES_bs_vector) * 8 * 3] = 0;
fill4:
	dst[sizeof(DES_bs_vector) * 8 * 4] = 0;
fill3:
	dst[sizeof(DES_bs_vector) * 8 * 5] = 0;
fill2:
	dst[sizeof(DES_bs_vector) * 8 * 6] = 0;
	dst[sizeof(DES_bs_vector) * 8 * 7] = 0;
	*/
}
/*
void opencl_DES_bs_set_key_LM(char *key, int index)
{
	unsigned long c;
	unsigned char *dst;
	unsigned int sector,key_index;
	init_t();
	sector = index/DES_BS_DEPTH;
	key_index = index % DES_BS_DEPTH;
	dst = opencl_DES_bs_all[sector].pxkeys[key_index];


	c = (unsigned char)key[0];
	if (!c) goto fill7;
	*dst = opencl_DES_bs_all[sector].E.u[c];
	c = (unsigned char)key[1];
	if (!c) goto fill6;
	*(dst + sizeof(DES_bs_vector) * 8) = opencl_DES_bs_all[sector].E.u[c];
	c = (unsigned char)key[2];
	if (!c) goto fill5;
	*(dst + sizeof(DES_bs_vector) * 8 * 2) = opencl_DES_bs_all[sector].E.u[c];
	c = (unsigned char)key[3];
	if (!c) goto fill4;
	*(dst + sizeof(DES_bs_vector) * 8 * 3) = opencl_DES_bs_all[sector].E.u[c];
	c = (unsigned char)key[4];
	if (!c) goto fill3;
	*(dst + sizeof(DES_bs_vector) * 8 * 4) = opencl_DES_bs_all[sector].E.u[c];
	c = (unsigned char)key[5];
	if (!c) goto fill2;
	*(dst + sizeof(DES_bs_vector) * 8 * 5) = opencl_DES_bs_all[sector].E.u[c];
	c = (unsigned char)key[6];
	*(dst + sizeof(DES_bs_vector) * 8 * 6) = opencl_DES_bs_all[sector].E.u[c];
	return;
fill7:
	dst[0] = 0;
fill6:
	dst[sizeof(DES_bs_vector) * 8] = 0;
fill5:
	dst[sizeof(DES_bs_vector) * 8 * 2] = 0;
fill4:
	dst[sizeof(DES_bs_vector) * 8 * 3] = 0;
fill3:
	dst[sizeof(DES_bs_vector) * 8 * 4] = 0;
fill2:
	dst[sizeof(DES_bs_vector) * 8 * 5] = 0;
	dst[sizeof(DES_bs_vector) * 8 * 6] = 0;
}
*/
static WORD *DES_bs_get_binary_raw(WORD *raw, int count)
{
	static WORD out[2];

/* For odd iteration counts, swap L and R here instead of doing it one
 * more time in DES_bs_crypt(). */
	count &= 1;
	out[count] = raw[0];
	out[count ^ 1] = raw[1];

	return out;
}

WORD *opencl_DES_bs_get_binary(char *ciphertext)
{
	return DES_bs_get_binary_raw(
		opencl_DES_raw_get_binary(ciphertext),
		opencl_DES_raw_get_count(ciphertext));
}

WORD *opencl_DES_bs_get_binary_LM(char *ciphertext)
{
	WORD block[2], value;
	int l, h;
	int index;

	block[0] = block[1] = 0;
	for (index = 0; index < 16; index += 2) {
		l = atoi16[ARCH_INDEX(ciphertext[index])];
		h = atoi16[ARCH_INDEX(ciphertext[index + 1])];
		value = DES_LM_reverse[l] | (DES_LM_reverse[h] << 4);
		block[index >> 3] |= value << ((index << 2) & 0x18);
	}

	return DES_bs_get_binary_raw(opencl_DES_do_IP(block), 1);
}

static MAYBE_INLINE int DES_bs_get_hash(int index, int count)
{
	int result;
	DES_bs_vector *b;
	unsigned int sector;
	init_t();
	sector = index>>DES_BS_LOG2; 
	index &= (DES_BS_DEPTH-1);
#if ARCH_LITTLE_ENDIAN
/*
 * This is merely an optimization.  Nothing will break if this check for
 * little-endian archs is removed, even if the arch is in fact little-endian.
 */
	init_depth();
	//b = (DES_bs_vector *)&opencl_DES_bs_all[sector].B[0] DEPTH;
	b = (DES_bs_vector *)&B[sector*64] DEPTH;
#define GET_BIT(bit) \
	(((unsigned WORD)b[(bit)] START >> index) & 1)
#else
	depth = index >> 3;
	index &= 7;
	//b = (DES_bs_vector *)((unsigned char *)&opencl_DES_bs_all[sector].B[0] START + depth);
	b = (DES_bs_vector *)((unsigned char *)&B[sector*64] START + depth);
#define GET_BIT(bit) \
	(((unsigned int)*(unsigned char *)&b[(bit)] START >> index) & 1)
#endif
#define MOVE_BIT(bit) \
	(GET_BIT(bit) << (bit))

	result = GET_BIT(0);
	result |= MOVE_BIT(1);
	result |= MOVE_BIT(2);
	result |= MOVE_BIT(3);
	if (count == 4) return result;

	result |= MOVE_BIT(4);
	result |= MOVE_BIT(5);
	result |= MOVE_BIT(6);
	result |= MOVE_BIT(7);
	if (count == 8) return result;

	result |= MOVE_BIT(8);
	result |= MOVE_BIT(9);
	result |= MOVE_BIT(10);
	result |= MOVE_BIT(11);
	if (count == 12) return result;

	result |= MOVE_BIT(12);
	result |= MOVE_BIT(13);
	result |= MOVE_BIT(14);
	result |= MOVE_BIT(15);
	if (count == 16) return result;

	result |= MOVE_BIT(16);
	result |= MOVE_BIT(17);
	result |= MOVE_BIT(18);
	result |= MOVE_BIT(19);
	if (count == 20) return result;

	result |= MOVE_BIT(20);
	result |= MOVE_BIT(21);
	result |= MOVE_BIT(22);
	result |= MOVE_BIT(23);
	if (count == 24) return result;

	result |= MOVE_BIT(24);
	result |= MOVE_BIT(25);
	result |= MOVE_BIT(26);

#undef GET_BIT
#undef MOVE_BIT

	return result;
}

int opencl_DES_bs_get_hash_0(int index)
{
	return DES_bs_get_hash(index, 4);
}

int opencl_DES_bs_get_hash_1(int index)
{
	return DES_bs_get_hash(index, 8);
}

int opencl_DES_bs_get_hash_2(int index)
{
	return DES_bs_get_hash(index, 12);
}

int opencl_DES_bs_get_hash_3(int index)
{
	return DES_bs_get_hash(index, 16);
}

int opencl_DES_bs_get_hash_4(int index)
{
	return DES_bs_get_hash(index, 20);
}

int opencl_DES_bs_get_hash_5(int index)
{
	return DES_bs_get_hash(index, 24);
}

int opencl_DES_bs_get_hash_6(int index)
{
	return DES_bs_get_hash(index, 27);
}

/*
 * The trick used here allows to compare one ciphertext against all the
 * DES_bs_crypt*() outputs in just O(log2(ARCH_BITS)) operations, assuming
 * that DES_BS_VECTOR is 0 or 1. This routine isn't vectorized yet.
 */
int opencl_DES_bs_cmp_all(WORD *binary, int count)
{
	WORD value, mask;
	int bit;
	DES_bs_vector *b;
	unsigned int sector=0,count_multiple;
	if(count&(DES_BS_DEPTH-1)==0) count_multiple=count;
	else count_multiple = ((count>>DES_BS_LOG2)+1)<<DES_BS_LOG2;
	//for_each_t(n)
	for(sector=0;sector < (count_multiple>>DES_BS_LOG2); sector++) {
		value = binary[0];
		//b = (DES_bs_vector *)&opencl_DES_bs_all[sector].B[0] DEPTH;
		b = (DES_bs_vector *)&B[sector*64] DEPTH;

		mask = b[0] START ^ -(value & 1);
		mask |= b[1] START ^ -((value >> 1) & 1);
		if (mask == ~(WORD)0) goto next_depth;
		mask |= b[2] START ^ -((value >> 2) & 1);
		mask |= b[3] START ^ -((value >> 3) & 1);
		if (mask == ~(WORD)0) goto next_depth;
		value >>= 4;
		b += 4;
		for (bit = 4; bit < 32; bit += 2) {
			mask |= b[0] START ^
				-(value & 1);
			if (mask == ~(WORD)0) goto next_depth;
			mask |= b[1] START ^
				-((value >> 1) & 1);
			if (mask == ~(WORD)0) goto next_depth;
			value >>= 2;
			b += 2;
		}

		return 1;
next_depth:
		;
	}

	return 0;
}

int opencl_DES_bs_cmp_one(WORD *binary, int count, int index)
{
	int bit;
	DES_bs_vector *b;
	int depth;
	unsigned int sector;
	init_t();
	sector = index>>DES_BS_LOG2;
	index &= (DES_BS_DEPTH-1);
	depth = index >> 3;
	index &= 7;

	//b = (DES_bs_vector *)((unsigned char *)&opencl_DES_bs_all[sector].B[0] START + depth);
	b = (DES_bs_vector *)((unsigned char *)&B[sector*64] START + depth);

#define GET_BIT \
	((unsigned WORD)*(unsigned char *)&b[0] START >> index)

	for (bit = 0; bit < 31; bit++, b++)
		if ((GET_BIT ^ (binary[0] >> bit)) & 1)
			return 0;

	for (; bit < count; bit++, b++)
		if ((GET_BIT ^ (binary[bit >> 5] >> (bit & 0x1F))) & 1)
			return 0;

#undef GET_BIT

	return 1;
}

WORD opencl_DES_raw_get_salt(char *ciphertext)
{
	if (ciphertext[13]) return DES_atoi64[ARCH_INDEX(ciphertext[5])] |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[6])] << 6) |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[7])] << 12) |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[8])] << 18);
	else return DES_atoi64[ARCH_INDEX(ciphertext[0])] |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[1])] << 6);
}

WORD opencl_DES_raw_get_count(char *ciphertext)
{
	if (ciphertext[13]) return DES_atoi64[ARCH_INDEX(ciphertext[1])] |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[2])] << 6) |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[3])] << 12) |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[4])] << 18);
	else return 25;
}

WORD *opencl_DES_do_IP(WORD in[2])
{
	static WORD out[2];
	int src, dst;

	out[0] = out[1] = 0;
	for (dst = 0; dst < 64; dst++) {
		src = DES_IP[dst ^ 0x20];

		if (in[src >> 5] & (1 << (src & 0x1F)))
			out[dst >> 5] |= 1 << (dst & 0x1F);
	}

	return out;
}

WORD *opencl_DES_raw_get_binary(char *ciphertext)
{
	WORD block[3];
	WORD mask;
	int ofs, chr, src, dst, value;

	if (ciphertext[13]) ofs = 9; else ofs = 2;

	block[0] = block[1] = 0;
	dst = 0;
	for (chr = 0; chr < 11; chr++) {
		value = DES_atoi64[ARCH_INDEX(ciphertext[chr + ofs])];
		mask = 0x20;

		for (src = 0; src < 6; src++) {
			if (value & mask)
				block[dst >> 5] |= 1 << (dst & 0x1F);
			mask >>= 1;
			dst++;
		}
	}

	return opencl_DES_do_IP(block);
}


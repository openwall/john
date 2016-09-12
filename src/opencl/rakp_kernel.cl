/*
 * Code largely based on OpenCL SHA1 kernel by Samuele Giovanni Tonon (C) 2011,
 * magnum (C) 2012
 *
 * OpenCL RAKP kernel (C) 2013 by Harrison Neal
 * Vectorizing, packed key buffer and other optimizations (c) magnum 2013
 *
 * Licensed under GPLv2
 * This program comes with ABSOLUTELY NO WARRANTY, neither expressed nor
 * implied. See the following for more information on the GPLv2 license:
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1.h"

#define CONCAT(TYPE,WIDTH)	TYPE ## WIDTH
#define VECTOR(x, y)		CONCAT(x, y)

#define VEC_IN(NUM)	  \
	base = index[gid * V_WIDTH + 0x##NUM]; \
	len = ((base & 63) + 3) / 4; \
	keys = key_array + (base >> 6); \
	for (i = 0; i < len; i++) \
		K[i].s##NUM = SWAP32(keys[i])

#define VEC_OUT(NUM)	  \
	digest[i * gws * V_WIDTH + gid * V_WIDTH + 0x##NUM] = stage2[i].s##NUM

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void rakp_kernel(__constant      uint* salt,
                 __global const  uint* key_array,
                 __global const  uint* index,
                 __global        uint* digest)
{
	MAYBE_VECTOR_UINT W[16], K[16] = { 0 }, stage1[5], stage2[5];
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	uint i;
	uint base = index[gid * V_WIDTH];
	uint len = ((base & 63) + 3) / 4;
	__global const uint *keys = key_array + (base >> 6);

#ifdef SCALAR
	for (i = 0; i < len; i++)
		K[i] = SWAP32(keys[i]);
#else
	for (i = 0; i < len; i++)
		K[i].s0 = SWAP32(keys[i]);

	VEC_IN(1);
#if V_WIDTH > 2
	VEC_IN(2);
#if V_WIDTH > 3
	VEC_IN(3);
#if V_WIDTH > 4
	VEC_IN(4);
	VEC_IN(5);
	VEC_IN(6);
	VEC_IN(7);
#if V_WIDTH > 8
	VEC_IN(8);
	VEC_IN(9);
	VEC_IN(a);
	VEC_IN(b);
	VEC_IN(c);
	VEC_IN(d);
	VEC_IN(e);
	VEC_IN(f);
#endif
#endif
#endif
#endif
#endif
	for (i = 0; i < 16; i++)
		W[i] = K[i] ^ 0x36363636U;
	sha1_single(MAYBE_VECTOR_UINT, W, stage1);

	for (i = 0; i < 16; i++)
		W[i] = *salt++;
	sha1_block(MAYBE_VECTOR_UINT, W, stage1);

	for (i = 0; i < 16; i++)
		W[i] = *salt++;
	sha1_block(MAYBE_VECTOR_UINT, W, stage1);

	for (i = 0; i < 16; i++)
		W[i] = K[i] ^ 0x5C5C5C5CU;
	sha1_single(MAYBE_VECTOR_UINT, W, stage2);

	for (i = 0; i < 5; i++)
		W[i] = stage1[i];
	W[5] = 0x80000000;
	W[15] = 672; // (64 + 20) * 8
	sha1_block_160Z(MAYBE_VECTOR_UINT, W, stage2);

	for (i = 0; i < 5; i++)
#ifdef SCALAR
		digest[i * gws + gid] = stage2[i];
#else
	{
		VEC_OUT(0);
		VEC_OUT(1);
#if V_WIDTH > 2
		VEC_OUT(2);
#if V_WIDTH > 3
		VEC_OUT(3);
#if V_WIDTH > 4
		VEC_OUT(4);
		VEC_OUT(5);
		VEC_OUT(6);
		VEC_OUT(7);
#if V_WIDTH > 8
		VEC_OUT(8);
		VEC_OUT(9);
		VEC_OUT(a);
		VEC_OUT(b);
		VEC_OUT(c);
		VEC_OUT(d);
		VEC_OUT(e);
		VEC_OUT(f);
#endif
#endif
#endif
#endif
	}
#endif
}

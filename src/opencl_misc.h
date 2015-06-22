/*
 * OpenCL macros
 *
 * Copyright (c) 2014, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * NOTICE: After changes in headers, you probably need to drop cached
 * kernels to ensure the changes take effect:
 *
 * For nvidia:
 * rm -fr ~/.nv/ComputeCache
 *
 * AMD, Apple, some others
 * rm ../run/kernels/?*.bin
 *
 */

#ifndef _OPENCL_MISC_H
#define _OPENCL_MISC_H

#include "opencl_device_info.h"

/* Note: long is *always* 64-bit in OpenCL */
typedef uchar uint8_t;
typedef char int8_t;
typedef ushort uint16_t;
typedef short int16_t;
typedef uint uint32_t;
typedef int int32_t;
typedef ulong uint64_t;
typedef long int64_t;

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#if !gpu_nvidia(DEVICE_INFO) || nvidia_sm_5x(DEVICE_INFO)
#define USE_BITSELECT 1
#elif gpu_nvidia(DEVICE_INFO)
#define OLD_NVIDIA 1
#endif

#define CONCAT(TYPE,WIDTH)	TYPE ## WIDTH
#define VECTOR(x, y)		CONCAT(x, y)

/* host code may pass -DV_WIDTH=2 or some other width */
#if defined(V_WIDTH) && V_WIDTH > 1
#define MAYBE_VECTOR_UINT	VECTOR(uint, V_WIDTH)
#define MAYBE_VECTOR_ULONG	VECTOR(ulong, V_WIDTH)
#else
#define MAYBE_VECTOR_UINT	uint
#define MAYBE_VECTOR_ULONG	ulong
#define SCALAR 1
#endif

/* Workaround for problem seen with 9600GT */
#if OLD_NVIDIA
#define MAYBE_CONSTANT	__global const
#else
#define MAYBE_CONSTANT	__constant
#endif

#if USE_BITSELECT
inline uint SWAP32(uint x)
{
	return bitselect(rotate(x, 24U), rotate(x, 8U), 0x00FF00FFU);
}

#define SWAP64(n)	bitselect( \
		bitselect(rotate(n, 24UL), \
		          rotate(n, 8UL), 0x000000FF000000FFUL), \
		bitselect(rotate(n, 56UL), \
		          rotate(n, 40UL), 0x00FF000000FF0000UL), \
		0xFFFF0000FFFF0000UL)
#else
inline uint SWAP32(uint x)
{
	x = rotate(x, 16U);
	return ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
}

// You would not believe how many driver bugs variants of this macro reveal
#define SWAP64(n)	  \
            (((n)             << 56)   | (((n) & 0xff00)     << 40) |   \
            (((n) & 0xff0000) << 24)   | (((n) & 0xff000000) << 8)  |   \
            (((n) >> 8)  & 0xff000000) | (((n) >> 24) & 0xff0000)   |   \
            (((n) >> 40) & 0xff00)     | ((n)  >> 56))
#endif

#if defined(SCALAR)
#define VSWAP32 SWAP32
#else
/* Vector-capable swap32() */
inline MAYBE_VECTOR_UINT VSWAP32(MAYBE_VECTOR_UINT x)
{
	x = rotate(x, 16U);
	return ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
}
#endif

#if gpu_nvidia(DEVICE_INFO)
// Faster on nvidia, no difference on AMD
#if __ENDIAN_LITTLE__
#define GET_UINT32BE(n, b, i)	(n) = SWAP32(((uint*)(b))[(i) >> 2])
#define PUT_UINT32BE(n, b, i)	((uint*)(b))[(i) >> 2] = SWAP32(n)
#else
#define GET_UINT32BE(n, b, i)	(n) = ((uint*)(b))[(i) >> 2]
#define PUT_UINT32BE(n, b, i)	((uint*)(b))[(i) >> 2] = (n)
#endif

#else /* Safe code for any arch */

#define GET_UINT32BE(n, b, i)	  \
	{ \
		(n) = ((uint) (b)[(i)] << 24) \
			| ((uint) (b)[(i) + 1] << 16) \
			| ((uint) (b)[(i) + 2] <<  8) \
			| ((uint) (b)[(i) + 3]      ); \
	}

#define PUT_UINT32BE(n, b, i)	  \
	{ \
		(b)[(i)    ] = (uchar) ((n) >> 24); \
		(b)[(i) + 1] = (uchar) ((n) >> 16); \
		(b)[(i) + 2] = (uchar) ((n) >>  8); \
		(b)[(i) + 3] = (uchar) ((n)      ); \
	}
#endif

/* Any device can do 8-bit reads BUT these macros are scalar only! */
#define GETCHAR(buf, index) (((uchar*)(buf))[(index)])
#define GETCHAR_G(buf, index) (((__global uchar*)(buf))[(index)])
#define GETCHAR_L(buf, index) (((__local uchar*)(buf))[(index)])
#define GETCHAR_BE(buf, index) (((uchar*)(buf))[(index) ^ 3])
#define GETCHAR_MC(buf, index) (((MAYBE_CONSTANT uchar*)(buf))[(index)])
#define LASTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & (0xffffff00U << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))

#if no_byte_addressable(DEVICE_INFO) || !defined(SCALAR) || (gpu_amd(DEVICE_INFO) && defined(AMD_PUTCHAR_NOCAST))
/* 32-bit stores */
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))
#define PUTCHAR_G	PUTCHAR
#define PUTCHAR_L	PUTCHAR
#define PUTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))
#define PUTCHAR_BE_G	PUTCHAR_BE
#define PUTSHORT(buf, index, val) (buf)[(index)>>1] = ((buf)[(index)>>1] & ~(0xffffU << (((index) & 1) << 4))) + ((val) << (((index) & 1) << 4))
#define PUTSHORT_BE(buf, index, val) (buf)[(index)>>1] = ((buf)[(index)>>1] & ~(0xffffU << ((((index) & 1) ^ 3) << 4))) + ((val) << ((((index) & 1) ^ 3) << 4))
#define XORCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2]) ^ ((val) << (((index) & 3) << 3))
#define XORCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2]) ^ ((val) << ((((index) & 3) ^ 3) << 3))

#else
/* 8-bit stores */
#define PUTCHAR(buf, index, val) ((uchar*)(buf))[index] = (val)
#define PUTCHAR_G(buf, index, val) ((__global uchar*)(buf))[(index)] = (val)
#define PUTCHAR_L(buf, index, val) ((__local uchar*)(buf))[(index)] = (val)
#define PUTCHAR_BE(buf, index, val) ((uchar*)(buf))[(index) ^ 3] = (val)
#define PUTCHAR_BE_G(buf, index, val) ((__global uchar*)(buf))[(index) ^ 3] = (val)
#define PUTSHORT(buf, index, val) ((ushort*)(buf))[index] = (val)
#define PUTSHORT_BE(buf, index, val) ((ushort*)(buf))[(index) ^ 1] = (val)
#define XORCHAR(buf, index, val) ((uchar*)(buf))[(index)] ^= (val)
#define XORCHAR_BE(buf, index, val) ((uchar*)(buf))[(index) ^ 3] ^= (val)
#endif

/* Use with some caution... */
#define memcpy_macro(dst, src, count) do {	  \
		for (uint _i = 0; _i < count; _i++) \
			(dst)[_i] = (src)[_i]; \
	} while (0)

/* requires int/uint */
#define dump_stuff_msg(msg, x, size) do {	  \
		uint ii; \
		printf("%s : ", msg); \
		for (ii = 0; ii < size/4; ii++) \
			printf("%08x ", SWAP32(x[ii])); \
		printf("\n"); \
	} while (0)

/* requires int/uint */
#define dump_stuff_be_msg(msg, x, size) do {	  \
		uint ii; \
		printf("%s : ", msg); \
		for (ii = 0; ii < size/4; ii++) \
			printf("%08x ", x[ii]); \
		printf("\n"); \
	} while (0)

#endif

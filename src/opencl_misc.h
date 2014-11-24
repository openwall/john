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

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

#define CONCAT(TYPE,WIDTH)	TYPE ## WIDTH
#define VECTOR(x, y)		CONCAT(x, y)

/* host code may pass -DV_WIDTH=2 or some other width */
#if defined(V_WIDTH) && V_WIDTH > 1
#define MAYBE_VECTOR_UINT	VECTOR(uint, V_WIDTH)
#else
#define MAYBE_VECTOR_UINT	uint
#define SCALAR
#endif

/* Workaround for problem seen with 9600GT */
#if gpu_nvidia(DEVICE_INFO)
#define MAYBE_CONSTANT const __global
#else
#define MAYBE_CONSTANT	__constant
#endif

#if gpu_nvidia(DEVICE_INFO) || amd_gcn(DEVICE_INFO)
inline uint SWAP32(uint x)
{
	x = rotate(x, 16U);
	return ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
}
#else
#define SWAP32(a)	(as_uint(as_uchar4(a).wzyx))
#endif

#define LASTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & (0xffffff00U << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))

#if no_byte_addressable(DEVICE_INFO)
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))
#define PUTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))
#define PUTCHAR_G	PUTCHAR
#define PUTCHAR_BE_G	PUTCHAR_BE
#define PUTSHORT(buf, index, val) (buf)[(index)>>1] = ((buf)[(index)>>1] & ~(0xffffU << (((index) & 1) << 4))) + ((val) << (((index) & 1) << 4))
#define PUTSHORT_BE(buf, index, val) (buf)[(index)>>1] = ((buf)[(index)>>1] & ~(0xffffU << ((((index) & 1) ^ 3) << 4))) + ((val) << ((((index) & 1) ^ 3) << 4))
#else
#define PUTCHAR(buf, index, val) ((uchar*)(buf))[index] = (val)
#define PUTCHAR_BE(buf, index, val) ((uchar*)(buf))[(index) ^ 3] = (val)
#define PUTCHAR_BE_G(buf, index, val) ((__global uchar*)(buf))[(index) ^ 3] = (val)
#define PUTSHORT(buf, index, val) ((ushort*)(buf))[index] = (val)
#define PUTSHORT_BE(buf, index, val) ((ushort*)(buf))[(index) ^ 1] = (val)
#endif

#define GETCHAR(buf, index) (((uchar*)(buf))[(index)])
#define GETCHAR_G(buf, index) (((__global uchar*)(buf))[(index)])
#define GETCHAR_BE(buf, index) (((uchar*)(buf))[(index) ^ 3])

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

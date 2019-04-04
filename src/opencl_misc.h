/*
 * OpenCL common macros
 *
 * Copyright (c) 2014-2015, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * NOTICE: After changes in headers, with nvidia driver you probably
 * need to drop cached kernels to ensure the changes take effect:
 *
 * rm -fr ~/.nv/ComputeCache
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

#if __SIZEOF_HOST_SIZE_T__ == 8 /* This is set by opencl_common.c */
typedef uint64_t host_size_t;
#else
typedef uint32_t host_size_t;
#endif

/*
 * "Copy" of the one in dyna_salt.h (we only need it to be right size,
 * bitfields are not allowed in OpenCL)
 */
typedef struct dyna_salt_t {
	host_size_t salt_cmp_size;
	host_size_t bitfield_and_offset;
} dyna_salt;

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

/*
 * Host code may pass -DV_WIDTH=2 or some other width.
 */
#if V_WIDTH > 1
#define MAYBE_VECTOR_UINT	VECTOR(uint, V_WIDTH)
#define MAYBE_VECTOR_ULONG	VECTOR(ulong, V_WIDTH)
#else
#define MAYBE_VECTOR_UINT	uint
#define MAYBE_VECTOR_ULONG	ulong
#define SCALAR 1
#endif

#if SCALAR && 0 /* Used for testing */
#define HAVE_LUT3	1
inline uint lut3(uint x, uint y, uint z, uchar m)
{
	uint i;
	uint r = 0;
	for (i = 0; i < sizeof(uint) * 8; i++)
		r |= (uint)((m >> ( (((x >> i) & 1) << 2) |
		                    (((y >> i) & 1) << 1) |
		                     ((z >> i) & 1) )) & 1) << i;
	return r;
}
#endif

/*
 * Apparently nvidias can optimize stuff better (ending up in *better* LUT
 * use) with the basic formulas instead of bitselect ones. Most formats
 * show no difference but pwsafe does.
 */
#if !gpu_nvidia(DEVICE_INFO)
#define USE_BITSELECT 1
#endif

#if SM_MAJOR == 1
#define OLD_NVIDIA 1
#endif

#if cpu(DEVICE_INFO)
#define HAVE_ANDNOT 1
#endif

#if SCALAR && SM_MAJOR >= 5 && (DEV_VER_MAJOR > 352 || (DEV_VER_MAJOR == 352 && DEV_VER_MINOR >= 21))
#define HAVE_LUT3	1
inline uint lut3(uint a, uint b, uint c, uint imm)
{
	uint r;
	asm("lop3.b32 %0, %1, %2, %3, %4;"
	    : "=r" (r)
	    : "r" (a), "r" (b), "r" (c), "i" (imm));
	return r;
}

#if 0 /* This does no good */
#define HAVE_LUT3_64	1
inline ulong lut3_64(ulong a, ulong b, ulong c, uint imm)
{
	ulong t, r;

	asm("lop3.b32 %0, %1, %2, %3, %4;"
	    : "=r" (t)
	    : "r" ((uint)a), "r" ((uint)b), "r" ((uint)c), "i" (imm));
	r = t;
	asm("lop3.b32 %0, %1, %2, %3, %4;"
	    : "=r" (t)
	    : "r" ((uint)(a >> 32)), "r" ((uint)(b >> 32)), "r" ((uint)(c >> 32)), "i" (imm));
	return r + (t << 32);
}
#endif
#endif

#if defined cl_amd_media_ops && !__MESA__ && gpu_amd(DEVICE_INFO)
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
#define BITALIGN(hi, lo, s) amd_bitalign((hi), (lo), (s))
#elif SCALAR && SM_MAJOR > 3 || (SM_MAJOR == 3 && SM_MINOR >= 2)
inline uint funnel_shift_right(uint hi, uint lo, uint s)
{
	uint r;
	asm("shf.r.wrap.b32 %0, %1, %2, %3;"
	    : "=r" (r)
	    : "r" (lo), "r" (hi), "r" (s));
	return r;
}

inline uint funnel_shift_right_imm(uint hi, uint lo, uint s)
{
	uint r;
	asm("shf.r.wrap.b32 %0, %1, %2, %3;"
	    : "=r" (r)
	    : "r" (lo), "r" (hi), "i" (s));
	return r;
}
#define BITALIGN(hi, lo, s) funnel_shift_right(hi, lo, s)
#define BITALIGN_IMM(hi, lo, s) funnel_shift_right_imm(hi, lo, s)
#else
#define BITALIGN(hi, lo, s) (((hi) << (32 - (s))) | ((lo) >> (s)))
#endif

#ifndef BITALIGN_IMM
#define BITALIGN_IMM(hi, lo, s) BITALIGN(hi, lo, s)
#endif

#define CONCAT(TYPE,WIDTH)	TYPE ## WIDTH
#define VECTOR(x, y)		CONCAT(x, y)

/* Workaround for problem seen with 9600GT */
#ifndef MAYBE_CONSTANT
#if OLD_NVIDIA
#define MAYBE_CONSTANT	__global const
#else
#define MAYBE_CONSTANT	__constant
#endif
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

#if SCALAR
#define VSWAP32 SWAP32
#else
/* Vector-capable swap32() */
inline MAYBE_VECTOR_UINT VSWAP32(MAYBE_VECTOR_UINT x)
{
	x = rotate(x, 16U);
	return ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
}
#endif

/*
 * These macros must not require alignment of (b).
 */
#define GET_UINT32(n, b, i)	  \
	{ \
		(n) = ((uint) (b)[(i)]      ) \
			| ((uint) (b)[(i) + 1] <<  8) \
			| ((uint) (b)[(i) + 2] << 16) \
			| ((uint) (b)[(i) + 3] << 24); \
	}

#define PUT_UINT32(n, b, i)	  \
	{ \
		(b)[(i)    ] = (uchar) ((n)      ); \
		(b)[(i) + 1] = (uchar) ((n) >>  8); \
		(b)[(i) + 2] = (uchar) ((n) >> 16); \
		(b)[(i) + 3] = (uchar) ((n) >> 24); \
	}

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

#define PUT_UINT64(n, b, i)	  \
	{ \
		(b)[(i)    ] = (uchar) ((n)      ); \
		(b)[(i) + 1] = (uchar) ((ulong)(n) >>  8); \
		(b)[(i) + 2] = (uchar) ((ulong)(n) >> 16); \
		(b)[(i) + 3] = (uchar) ((ulong)(n) >> 24); \
		(b)[(i) + 4] = (uchar) ((ulong)(n) >> 32); \
		(b)[(i) + 5] = (uchar) ((ulong)(n) >> 40); \
		(b)[(i) + 6] = (uchar) ((ulong)(n) >> 48); \
		(b)[(i) + 7] = (uchar) ((ulong)(n) >> 56); \
	}

#define GET_UINT64BE(n, b, i)	  \
	{ \
		(n) = ((ulong) (b)[(i)] << 56) \
			| ((ulong) (b)[(i) + 1] << 48) \
			| ((ulong) (b)[(i) + 2] << 40) \
			| ((ulong) (b)[(i) + 3] << 32) \
			| ((ulong) (b)[(i) + 4] << 24) \
			| ((ulong) (b)[(i) + 5] << 16) \
			| ((ulong) (b)[(i) + 6] <<  8) \
			| ((ulong) (b)[(i) + 7]      ); \
	}

#define PUT_UINT64BE(n, b, i)	  \
	{ \
		(b)[(i)    ] = (uchar) ((ulong)(n) >> 56); \
		(b)[(i) + 1] = (uchar) ((ulong)(n) >> 48); \
		(b)[(i) + 2] = (uchar) ((ulong)(n) >> 40); \
		(b)[(i) + 3] = (uchar) ((ulong)(n) >> 32); \
		(b)[(i) + 4] = (uchar) ((ulong)(n) >> 24); \
		(b)[(i) + 5] = (uchar) ((ulong)(n) >> 16); \
		(b)[(i) + 6] = (uchar) ((ulong)(n) >>  8); \
		(b)[(i) + 7] = (uchar) ((n)      ); \
	}

/*
 * These require (b) to be aligned!
 */
#if __ENDIAN_LITTLE__
#define GET_UINT32_ALIGNED(n, b, i)	(n) = ((uint*)(b))[(i) >> 2]
#define PUT_UINT32_ALIGNED(n, b, i)	((uint*)(b))[(i) >> 2] = (n)
#define GET_UINT32BE_ALIGNED(n, b, i)	(n) = SWAP32(((uint*)(b))[(i) >> 2])
#define PUT_UINT32BE_ALIGNED(n, b, i)	((uint*)(b))[(i) >> 2] = SWAP32(n)
#define PUT_UINT64_ALIGNED(n, b, i)	((ulong*)(b))[(i) >> 3] = (n)
#define GET_UINT64BE_ALIGNED(n, b, i)	(n) = SWAP64(((ulong*)(b))[(i) >> 3])
#define PUT_UINT64BE_ALIGNED(n, b, i)	((ulong*)(b))[(i) >> 3] = SWAP64(n)
#else
#define GET_UINT32_ALIGNED(n, b, i)	(n) = SWAP32(((uint*)(b))[(i) >> 2])
#define PUT_UINT32_ALIGNED(n, b, i)	((uint*)(b))[(i) >> 2] = SWAP32(n)
#define GET_UINT32BE_ALIGNED(n, b, i)	(n) = ((uint*)(b))[(i) >> 2]
#define PUT_UINT32BE_ALIGNED(n, b, i)	((uint*)(b))[(i) >> 2] = (n)
#define PUT_UINT64_ALIGNED(n, b, i)	((ulong*)(b))[(i) >> 3] = SWAP64(n)
#define GET_UINT64BE_ALIGNED(n, b, i)	(n) = ((ulong*)(b))[(i) >> 3]
#define PUT_UINT64BE_ALIGNED(n, b, i)	((ulong*)(b))[(i) >> 3] = (n)
#endif

/* Any device can do 8-bit reads BUT these macros are scalar only! */
#define GETCHAR(buf, index) (((uchar*)(buf))[(index)])
#define GETCHAR_G(buf, index) (((__global uchar*)(buf))[(index)])
#define GETCHAR_L(buf, index) (((__local uchar*)(buf))[(index)])
#define GETCHAR_BE(buf, index) (((uchar*)(buf))[(index) ^ 3])
#define GETCHAR_MC(buf, index) (((MAYBE_CONSTANT uchar*)(buf))[(index)])
#define LASTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & (0xffffff00U << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))

#if no_byte_addressable(DEVICE_INFO) || !SCALAR || (gpu_amd(DEVICE_INFO) && defined(AMD_PUTCHAR_NOCAST))
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

inline int check_pkcs_pad(const uchar *data, int len, int blocksize)
{
	int pad_len, padding, real_len;

	if (len & (blocksize - 1) || len < blocksize)
		return -1;

	pad_len = data[len - 1];

	if (pad_len < 1 || pad_len > blocksize)
		return -1;

	real_len = len - pad_len;
	data += real_len;

	padding = pad_len;

	while (pad_len--)
		if (*data++ != padding)
			return -1;

	return real_len;
}

/*
 * Use with some caution. Memory type agnostic and if both src and dst are
 * 8-bit types, this works like a normal memcpy.
 *
 * If src and dst are larger but same size, it will still work fine but
 * 'count' is number of ELEMENTS and not BYTES.
 *
 * If src and dst are different size types, you will get what you asked for...
 */
#define memcpy_macro(dst, src, count) do {	  \
		uint c = count; \
		for (uint _i = 0; _i < c; _i++) \
			(dst)[_i] = (src)[_i]; \
	} while (0)

/*
 * Optimized functions. You need to pick the one that corresponds to the
 * source- and destination memory type(s).
 *
 * Note that for very small sizes, the overhead may make these functions
 * slower than naive code. On the other hand, due to inlining we will
 * hopefully have stuff optimized away more often than not!
 */

/* src and dst are private mem */
inline void memcpy_pp(void *dst, const void *src, uint count)
{
	union {
		const uint *w;
		const uchar *c;
	} s;
	union {
		uint *w;
		uchar *c;
	} d;

	s.c = src;
	d.c = dst;

	if (((size_t)dst & 0x03) == ((size_t)src & 0x03)) {
		while (((size_t)s.c) & 0x03 && count--)
			*d.c++ = *s.c++;

		while (count >= 4) {
			*d.w++ = *s.w++;
			count -= 4;
		}
	}

	while (count--) {
		*d.c++ = *s.c++;
	}
}

/* src is private mem, dst is global mem */
inline void memcpy_pg(__global void *dst, const void *src, uint count)
{
	union {
		const uint *w;
		const uchar *c;
	} s;
	union {
		__global uint *w;
		__global uchar *c;
	} d;

	s.c = src;
	d.c = dst;

	if (((size_t)dst & 0x03) == ((size_t)src & 0x03)) {
		while (((size_t)s.c) & 0x03 && count--)
			*d.c++ = *s.c++;

		while (count >= 4) {
			*d.w++ = *s.w++;
			count -= 4;
		}
	}

	while (count--) {
		*d.c++ = *s.c++;
	}
}

/* src is global mem, dst is private mem */
inline void memcpy_gp(void *dst, __global const void *src, uint count)
{
	union {
		__global const uint *w;
		__global const uchar *c;
	} s;
	union {
		uint *w;
		uchar *c;
	} d;

	s.c = src;
	d.c = dst;

	if (((size_t)dst & 0x03) == ((size_t)src & 0x03)) {
		while (((size_t)s.c) & 0x03 && count--)
			*d.c++ = *s.c++;

		while (count >= 4) {
			*d.w++ = *s.w++;
			count -= 4;
		}
	}

	while (count--) {
		*d.c++ = *s.c++;
	}
}

/* src is constant mem, dst is private mem */
inline void memcpy_cp(void *dst, __constant void *src, uint count)
{
	union {
		__constant uint *w;
		__constant uchar *c;
	} s;
	union {
		uint *w;
		uchar *c;
	} d;

	s.c = src;
	d.c = dst;

	if (((size_t)dst & 0x03) == ((size_t)src & 0x03)) {
		while (((size_t)s.c) & 0x03 && count--)
			*d.c++ = *s.c++;

		while (count >= 4) {
			*d.w++ = *s.w++;
			count -= 4;
		}
	}

	while (count--) {
		*d.c++ = *s.c++;
	}
}

/* src is MAYBE_CONSTANT mem, dst is private mem */
inline void memcpy_mcp(void *dst, MAYBE_CONSTANT void *src, uint count)
{
	union {
		MAYBE_CONSTANT uint *w;
		MAYBE_CONSTANT uchar *c;
	} s;
	union {
		uint *w;
		uchar *c;
	} d;

	s.c = src;
	d.c = dst;

	if (((size_t)dst & 0x03) == ((size_t)src & 0x03)) {
		while (((size_t)s.c) & 0x03 && count--)
			*d.c++ = *s.c++;

		while (count >= 4) {
			*d.w++ = *s.w++;
			count -= 4;
		}
	}

	while (count--) {
		*d.c++ = *s.c++;
	}
}

/* dst is private mem */
inline void memset_p(void *p, uint val, uint count)
{
	const uint val4 = val | (val << 8) | (val << 16) | (val << 24);
	union {
		uint *w;
		uchar *c;
	} d;

	d.c = p;

	while (((size_t)d.c) & 0x03 && count--)
		*d.c++ = val;

	while (count >= 4) {
		*d.w++ = val4;
		count -= 4;
	}

	while (count--)
		*d.c++ = val;
}

/* dst is global mem */
inline void memset_g(__global void *p, uint val, uint count)
{
	const uint val4 = val | (val << 8) | (val << 16) | (val << 24);
	union {
		__global uint *w;
		__global uchar *c;
	} d;

	d.c = p;

	while (((size_t)d.c) & 0x03 && count--)
		*d.c++ = val;

	while (count >= 4) {
		*d.w++ = val4;
		count -= 4;
	}

	while (count--)
		*d.c++ = val;
}

/* s1 and s2 are private mem */
inline int memcmp_pp(const void *s1, const void *s2, uint size)
{
	union {
		const uint *w;
		const uchar *c;
	} a;
	union {
		const uint *w;
		const uchar *c;
	} b;

	a.c = s1;
	b.c = s2;

	if (((size_t)s1 & 0x03) == ((size_t)s2 & 0x03)) {
		while (((size_t)a.c) & 0x03 && size--)
			if (*b.c++ != *a.c++)
				return 1;

		while (size >= 4) {
			if (*b.w++ != *a.w++)
				return 1;
			size -= 4;
		}
	}

	while (size--)
		if (*b.c++ != *a.c++)
			return 1;

	return 0;
}

/* s1 is private mem, s2 is constant mem */
inline int memcmp_pc(const void *s1, __constant const void *s2, uint size)
{
	union {
		const uint *w;
		const uchar *c;
	} a;
	union {
		__constant const uint *w;
		__constant const uchar *c;
	} b;

	a.c = s1;
	b.c = s2;

	if (((size_t)s1 & 0x03) == ((size_t)s2 & 0x03)) {
		while (((size_t)a.c) & 0x03 && size--)
			if (*b.c++ != *a.c++)
				return 1;

		while (size >= 4) {
			if (*b.w++ != *a.w++)
				return 1;
			size -= 4;
		}
	}

	while (size--)
		if (*b.c++ != *a.c++)
			return 1;

	return 0;
}

/* s1 is private mem, s2 is MAYBE_CONSTANT mem */
inline int memcmp_pmc(const void *s1, MAYBE_CONSTANT void *s2, uint size)
{
	union {
		const uint *w;
		const uchar *c;
	} a;
	union {
		MAYBE_CONSTANT uint *w;
		MAYBE_CONSTANT uchar *c;
	} b;

	a.c = s1;
	b.c = s2;

	if (((size_t)s1 & 0x03) == ((size_t)s2 & 0x03)) {
		while (((size_t)a.c) & 0x03 && size--)
			if (*b.c++ != *a.c++)
				return 1;

		while (size >= 4) {
			if (*b.w++ != *a.w++)
				return 1;
			size -= 4;
		}
	}

	while (size--)
		if (*b.c++ != *a.c++)
			return 1;

	return 0;
}

/* haystack is private mem, needle is constant mem */
inline int memmem_pc(const void *haystack, size_t haystack_len,
                     __constant const void *needle, size_t needle_len)
{
	char* haystack_ = (char*)haystack;
	__constant const char* needle_ = (__constant const char*)needle;
	int hash = 0;
	int hay_hash = 0;
	char* last;
	size_t i;

	if (haystack_len < needle_len)
		return 0;

	if (!needle_len)
		return 1;

	for (i = needle_len; i; --i) {
		hash += *needle_++;
		hay_hash += *haystack_++;
	}

	haystack_ = (char*)haystack;
	needle_ = (__constant char*)needle;
	last = haystack_+(haystack_len - needle_len + 1);
	for (; haystack_ < last; ++haystack_) {
		if (hash == hay_hash &&
		    *haystack_ == *needle_ &&
		    !memcmp_pc (haystack_, needle_, needle_len))
			return 1;

		hay_hash -= *haystack_;
		hay_hash += *(haystack_+needle_len);
	}

	return 0;
}

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

/*
 * The reason the functions below are macros is it's the only way we can use
 * them regardless of memory type (eg. __local or __global). The downside is
 * we can't cast them so we need eg. dump8_le for a char array, or output will
 * not be correct.
 */

/* Dump an array (or variable) as hex */
#define dump(x)   dump_stuff_msg(STRINGIZE(x), x, sizeof(x))
#define dump_stuff(x, size) dump_stuff_msg(STRINGIZE(x), x, size)

/*
 * This clumsy beast finally hides the problem from user.
 */
#define dump_stuff_msg(msg, x, size) do {	  \
		switch (sizeof((x)[0])) { \
		case 8: \
			dump_stuff64_msg(msg, x, size); \
			break; \
		case 4: \
			dump_stuff32_msg(msg, x, size); \
			break; \
		case 2: \
			dump_stuff16_msg(msg, x, size); \
			break; \
		case 1: \
			dump_stuff8_msg(msg, x, size); \
			break; \
		} \
	} while (0)

/* requires char/uchar */
#define dump_stuff8_msg(msg, x, size) do {	  \
		uint ii; \
		printf("%s : ", msg); \
		for (ii = 0; ii < (uint)size; ii++) { \
			printf("%02x", (x)[ii]); \
			if (ii % 4 == 3) \
				printf(" "); \
		} \
		printf("\n"); \
	} while (0)

/* requires short/ushort */
#define dump_stuff16_msg(msg, x, size) do {	  \
		uint ii; \
		printf("%s : ", msg); \
		for (ii = 0; ii < (uint)(size)/2; ii++) { \
			printf("%04x", (x)[ii]); \
			if (ii % 2 == 1) \
				printf(" "); \
		} \
		printf("\n"); \
	} while (0)

/* requires int/uint */
#define dump_stuff32_msg(msg, x, size) do {	  \
		uint ii; \
		printf("%s : ", msg); \
		for (ii = 0; ii < (uint)(size)/4; ii++) \
			printf("%08x ", SWAP32((x)[ii])); \
		printf("\n"); \
	} while (0)

/* requires long/ulong */
#define dump_stuff64_msg(msg, x, size) do {	  \
		uint ii; \
		printf("%s : ", msg); \
		for (ii = 0; ii < (uint)(size)/8; ii++) \
			printf("%016lx ", SWAP64((x)[ii])); \
		printf("\n"); \
	} while (0)

#endif

/*
 * OpenCL common macros
 *
 * Copyright (c) 2014-2020, magnum
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

/* long is always 64-bit in OpenCL while long long is reserved for 128 bits */
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

#ifndef NULL
#define NULL ((void*)0)
#endif

/* Compatibility with non-clang compilers. */
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if __llvm__ || __has_builtin(__builtin_expect)
#define likely(x)        __builtin_expect(!!(x), 1)
#define unlikely(x)      __builtin_expect(!!(x), 0)
#else
#define likely(x)        (x)
#define unlikely(x)      (x)
#endif

/*
 * Most runtimes will inline nearly everything without request.
 */
#if _OPENCL_COMPILER

#define NOINLINE  __attribute__((noinline))

#ifndef INLINE
#if __MESA__
#define INLINE
#elif __POCL__
#define INLINE    inline
#else
#define INLINE    static inline
#endif
#endif

#endif /* _OPENCL_COMPILER */

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
INLINE uint lut3(uint x, uint y, uint z, uchar m)
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
INLINE uint lut3(uint a, uint b, uint c, uint imm)
{
	uint r;
	asm("lop3.b32 %0, %1, %2, %3, %4;"
	    : "=r" (r)
	    : "r" (a), "r" (b), "r" (c), "i" (imm));
	return r;
}

#if 0 /* This does no good */
#define HAVE_LUT3_64	1
INLINE ulong lut3_64(ulong a, ulong b, ulong c, uint imm)
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
INLINE uint funnel_shift_right(uint hi, uint lo, uint s)
{
	uint r;
	asm("shf.r.wrap.b32 %0, %1, %2, %3;"
	    : "=r" (r)
	    : "r" (lo), "r" (hi), "r" (s));
	return r;
}

INLINE uint funnel_shift_right_imm(uint hi, uint lo, uint s)
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

#define block_swap32(W, len)	for (uint i = 0; i < len; i++) W[i] = SWAP32(W[i])
#define block_swap64(W, len)	for (uint i = 0; i < len; i++) W[i] = SWAP64(W[i])

INLINE ushort SWAP16(ushort x)
{
	return ((x << 8) + (x >> 8));
}

#if USE_BITSELECT
INLINE uint SWAP32(uint x)
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
INLINE uint SWAP32(uint x)
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
INLINE MAYBE_VECTOR_UINT VSWAP32(MAYBE_VECTOR_UINT x)
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
 * Allow some strict aliasing violations, for nvidia only.
 * These require (b) to be aligned!
 */
#if gpu_nvidia(DEVICE_INFO)
#define ALLOW_ALIASING_VIOLATIONS	1
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
#endif

/* Any device can do 8-bit reads BUT these macros are scalar only! */
#define GETCHAR(buf, index) (((uchar*)(buf))[(index)])
#define GETCHAR_G(buf, index) (((__global uchar*)(buf))[(index)])
#define GETCHAR_L(buf, index) (((__local uchar*)(buf))[(index)])
#define GETCHAR_BE(buf, index) (((uchar*)(buf))[(index) ^ 3])
#define GETCHAR_MC(buf, index) (((MAYBE_CONSTANT uchar*)(buf))[(index)])
#define LASTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & (0xffffff00U << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))
#define LASTCHAR_BE64(buf, index, val) (buf)[(index)>>3] = ((buf)[(index)>>3] & (0xffffffffffffff00UL << ((((index) & 7) ^ 7) << 3))) + ((ulong)(val) << ((((index) & 7) ^ 7) << 3))
#define LASTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & (0xffffff00U << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))

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

INLINE int check_pkcs_pad(const uchar *data, int len, int blocksize)
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
		uint _memcpy_c = count; \
		for (uint _memcpy_i = 0; _memcpy_i < _memcpy_c; _memcpy_i++) \
			(dst)[_memcpy_i] = (src)[_memcpy_i]; \
	} while (0)

/*
 * memcpy functions.  Until we require OpenCL 2.0, you need to pick the one
 * that corresponds to the source- and destination memory type(s).
 */

/* src and dst are private mem */
INLINE void memcpy_pp(void* restrict dst, const void* restrict src, uint count)
{
	const char *s = src;
	char *d = dst;

	while (count--)
		*d++ = *s++;
}

/* src is private mem, dst is global mem */
INLINE void memcpy_pg(__global void* restrict dst, const void* restrict src, uint count)
{
	const char *s = src;
	__global char *d = dst;

	while (count--)
		*d++ = *s++;
}

/* src is global mem, dst is private mem */
INLINE void memcpy_gp(void* restrict dst, __global const void* restrict src, uint count)
{
	__global const char *s = src;
	char *d = dst;

	while (count--)
		*d++ = *s++;
}

/* src is constant mem, dst is private mem */
INLINE void memcpy_cp(void* restrict dst, __constant void* restrict src, uint count)
{
	__constant char *s = src;
	char *d = dst;

	while (count--)
		*d++ = *s++;
}

/* src is MAYBE_CONSTANT mem, dst is private mem */
INLINE void memcpy_mcp(void* restrict dst, MAYBE_CONSTANT void* restrict src, uint count)
{
	MAYBE_CONSTANT char *s = src;
	char *d = dst;

	while (count--)
		*d++ = *s++;
}

/* dst is private mem */
INLINE void memset_p(void *p, uint val, uint count)
{
	char *d = p;

	while (count--)
		*d++ = val;
}

/* dst is global mem */
INLINE void memset_g(__global void *p, uint val, uint count)
{
	__global char *d = p;

	while (count--)
		*d++ = val;
}

/* s1 and s2 are private mem */
INLINE int memcmp_pp(const void *s1, const void *s2, uint size)
{
	const uchar *a = s1;
	const uchar *b = s2;

	while (size--)
		if (*a++ != *b++)
			return 1;

	return 0;
}

/* s1 is private mem, s2 is global mem */
INLINE int memcmp_pg(const void *s1, __global const void *s2, uint size)
{
	const uchar *a = s1;
	__global const uchar *b = s2;

	while (size--)
		if (*a++ != *b++)
			return 1;

	return 0;
}

/* s1 is private mem, s2 is constant mem */
INLINE int memcmp_pc(const void *s1, __constant const void *s2, uint size)
{
	const uchar *a = s1;
	__constant const uchar *b = s2;

	while (size--)
		if (*a++ != *b++)
			return 1;

	return 0;
}

/* s1 is global mem, s2 is constant mem */
INLINE int memcmp_gc(__global const void *s1, __constant void *s2, uint size)
{
	__global const uchar *a = s1;
	__constant uchar *b = s2;

	while (size--)
		if (*a++ != *b++)
			return 1;

	return 0;
}

/* s1 is private mem, s2 is MAYBE_CONSTANT mem */
INLINE int memcmp_pmc(const void *s1, MAYBE_CONSTANT void *s2, uint size)
{
	const uchar *a = s1;
	MAYBE_CONSTANT uchar *b = s2;

	while (size--)
		if (*a++ != *b++)
			return 1;

	return 0;
}

/* haystack is private mem, needle is constant mem */
INLINE int memmem_pc(const void *haystack, size_t haystack_len,
                     __constant const void *needle, size_t needle_len)
{
	const char *haystack_ = haystack;
	__constant const char *needle_ = needle;
	int hash = 0;
	int hay_hash = 0;
	const char *last;
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

	for (last = haystack_ + (haystack_len - needle_len + 1); haystack_ < last; ++haystack_) {
		if (hash == hay_hash && *haystack_ == *needle_ && !memcmp_pc(haystack_, needle_, needle_len))
			return 1;

		hay_hash -= *haystack_;
		hay_hash += *(haystack_+needle_len);
	}

	return 0;
}

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

/*
 * The below macros need to be called with pointer already cast to
 * uchar pointer of its type - such as "(__constant uchar*)salt->u"
 * because type is unknown to us so void* can't help us.
 */

#define dump_le(x, size) dump_stuff_msg(STRINGIZE(x), x, size)
#define dump_be(x, size) dump_stuff_be_msg(STRINGIZE(x), x, size)
#define dump_be64(x, size) dump_stuff_be64_msg(STRINGIZE(x), x, size)

#define dump_stuff_msg(msg, x, size) do {	  \
		printf("%s : ", msg); \
		for (uint xedni_ = 0; xedni_ < (uint)size; xedni_++) { \
			printf("%02x", (x)[xedni_]); \
			if (xedni_ % 4 == 3) \
				printf(" "); \
		} \
		printf("\n"); \
	} while (0)

#define dump_stuff_be_msg(msg, x, size) do {	  \
		printf("%s : ", msg); \
		for (uint xedni_ = 0; xedni_ < (uint)size; xedni_++) { \
			printf("%02x", (x)[xedni_ ^ 3]); \
			if (xedni_ % 4 == 3) \
				printf(" "); \
		} \
		printf("\n"); \
	} while (0)

#define dump_stuff_be64_msg(msg, x, size) do {	  \
		printf("%s : ", msg); \
		for (uint xedni_ = 0; xedni_ < (uint)size; xedni_++) { \
			printf("%02x", (x)[xedni_ ^ 7]); \
			if (xedni_ % 4 == 3) \
				printf(" "); \
		} \
		printf("\n"); \
	} while (0)

#endif

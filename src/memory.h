/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2003,2010-2012,2016 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Memory allocation routines.
 */

#ifndef _JOHN_MEMORY_H
#define _JOHN_MEMORY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arch.h"

/*
 * Standard alignments for mem_alloc_tiny().
 */
#define MEM_ALIGN_NONE			1
#define MEM_ALIGN_WORD			ARCH_SIZE
/*
 * These are hopefully suitable guesses.  They are right for only a subset of
 * the architectures/CPUs we support, yet our use of them does not require that
 * they be entirely correct.
 */
#ifdef _MSC_VER
#define MEM_ALIGN_CACHE			64
#else
#define MEM_ALIGN_CACHE			(ARCH_SIZE * 8)
#endif
#define MEM_ALIGN_PAGE			0x1000

/*
 * SIMD buffers need to be aligned to register size
 */
#if SIMD_COEF_32
#ifdef _MSC_VER
#define MEM_ALIGN_SIMD			16
#else
#define MEM_ALIGN_SIMD			(SIMD_COEF_32 * 4)
#endif
#else
#define MEM_ALIGN_SIMD			(16)
#endif

/*
 * Block size used by mem_alloc_tiny().
 */
#define MEM_ALLOC_SIZE			0x10000

/*
 * Use mem_alloc() instead of allocating a new block in mem_alloc_tiny()
 * if more than MEM_ALLOC_MAX_WASTE bytes would be lost.
 * This shouldn't be set too small, or mem_alloc_tiny() will keep calling
 * mem_alloc() for many allocations in a row, which might end up wasting even
 * more memory to malloc() overhead.
 */
#define MEM_ALLOC_MAX_WASTE		0xff

/*
 * Memory saving level, setting this high enough disables alignments (if the
 * architecture allows).
 */
extern unsigned int mem_saving_level;

/*
 * Allocates size bytes and returns a pointer to the allocated memory, or NULL
 * if size is 0.
 * If an error occurs, the function does not return.
 */
extern void *mem_alloc(size_t size);

/*
 * Allocates nmemb*size bytes using calloc(3) and returns a pointer to the
 * allocated memory, or NULL if nmemb or/and size are 0.
 * If an error occurs, the function does not return.
 */
extern void *mem_calloc(size_t nmemb, size_t size);

/*
 * Change an existing allocated block to size bytes and return a pointer to
 * the new block, or NULL if size is 0. Content is preserved to the extent
 * possible.
 * If an error occurs, the function does not return.
 */
extern void *mem_realloc(void *old_ptr, size_t size);

/* These allow alignment and are wrappers to system-specific functions */
extern void *mem_alloc_align(size_t size, size_t align);

extern void *mem_calloc_align(size_t count, size_t size, size_t align);

/*
 * Creates a new NUL-terminated copy of the given string using strdup() and
 * returns a pointer to it.  The allocation is done using malloc().
 * If an error occurs, the function does not return.
 */
extern char *xstrdup(const char *str);

/*
 * Frees memory allocated with mem_alloc() and sets the pointer to NULL.
 * Does nothing if the pointer is already NULL.
 */
#undef MEM_FREE

#ifdef _MSC_VER
#define malloc(a) _aligned_malloc(a,16)
#define realloc(a,b) _aligned_realloc(a,b,16)
#define calloc(a,b) memset(_aligned_malloc(a*b,16),0,a*b)
#define free(a) _aligned_free(a)
#define strdup(a) strdup_MSVC(a)
extern char *strdup_MSVC(const char *str);
#define MEM_FREE(ptr) \
{ \
	if ((ptr)) { \
		_aligned_free((ptr)); \
		(ptr) = NULL; \
	} \
}

#elif HAVE___MINGW_ALIGNED_MALLOC
#define malloc(a) __mingw_aligned_malloc(a,(sizeof(long long)))
#define realloc(a,b) __mingw_aligned_realloc(a,b,(sizeof(long long)))
#define calloc(a,b) memset(__mingw_aligned_malloc(a*b,(sizeof(long long))),0,a*b)
#define free(a) __mingw_aligned_free(a)
#define strdup(a) strdup_MSVC(a)
extern char *strdup_MSVC(const char *str);

#define MEM_FREE(ptr) \
{ \
	if ((ptr)) { \
		__mingw_aligned_free((ptr)); \
		(ptr) = NULL; \
	} \
}

#else
#define MEM_FREE(ptr) \
{ \
	if ((ptr)) { \
		free((ptr)); \
		(ptr) = NULL; \
	} \
}
#endif

/*
 * Similar to the above function, except the memory can't be freed.
 * This one is used to reduce the overhead.
 */
extern void *mem_alloc_tiny(size_t size, size_t align);

/*
 * this version same as mem_alloc_tiny, but initialized the memory
 * to NULL bytes, like CALLOC(3) function does
 */
extern void *mem_calloc_tiny(size_t size, size_t align);

/*
 * Uses mem_alloc_tiny() to allocate the memory, and copies src in there.
 */
extern void *mem_alloc_copy(const void *src, size_t size, size_t align);

/*
 * Similar to the above function, but for ASCIIZ strings.
 */
extern char *str_alloc_copy(const char *src);

/*
 * This will 'cleanup' the memory allocated by mem_alloc_tiny().  All
 * of that memory was 'blindly' allocated, and not freed up during
 * the run of john.  Now, it is 'cleaned' up.
 */
extern void cleanup_tiny_memory();

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

#define dump_stuff(d, sz) dump_stuff_msg(STRINGIZE(d), d, sz)
#define dump_stuff_be(d, sz) dump_stuff_be_msg(STRINGIZE(d), d, sz)
#define dump_stuff_mmx(d, sz, idx) dump_stuff_mmx_msg(STRINGIZE(d), d, sz, idx)
#define dump_stuff_mmx64(d, sz, idx)	  \
	dump_stuff_mmx64_msg(STRINGIZE(d), d, sz, idx)
#define dump_out_mmx(d, sz, idx)	  \
	dump_out_mmx_msg(STRINGIZE(d), d, sz, idx)
#define dump_stuff_shammx(d, sz, idx)	  \
	dump_stuff_shammx_msg(STRINGIZE(d), d, sz, idx)
#define dump_out_shammx(d, sz, idx)	  \
	dump_out_shammx_msg(STRINGIZE(d), d, sz, idx)
#define dump_stuff_shammx64(d, sz, idx)	  \
	dump_stuff_shammx64_msg(STRINGIZE(d), d, sz, idx)
#define dump_out_shammx64(d, sz, idx)	  \
	dump_out_shammx64_msg(STRINGIZE(d), d, sz, idx)
#define dump_stuff_mpara_mmx(d, sz, idx)	  \
	dump_stuff_mpara_mmx_msg(STRINGIZE(d), d, sz, idx)

/* Dump an array (or variable) as hex */
#define dump_le(d) dump_stuff_msg(STRINGIZE(d), d, sizeof(d))
#define dump_be(d) dump_stuff_be_msg(STRINGIZE(d), d, sizeof(d))

/* Dump memory as text (non-printables as dots) */
#define dump_text(d, sz) dump_text_msg(STRINGIZE(d), d, sz)

extern void dump_text_msg(const void *msg, const void *in, int len);

extern void dump_stuff_msg(const void *msg, const void *x, unsigned int size);
extern void dump_stderr_msg(const void *msg, const void *x, unsigned int size);
extern void dump_stuff_be_msg(const void *msg, const void *x, unsigned int size);

#if defined (SIMD_COEF_32) || defined(NT_X86_64) || defined (SIMD_PARA_MD5) || defined (SIMD_PARA_MD4) || defined (SIMD_PARA_SHA1)
extern void dump_stuff_mmx_msg(const void *msg, const void *buf, unsigned int size, unsigned int index);
// for flat input, we do want to see SHA512 without byte swapping.
extern void dump_stuff_mmx64_msg(const void *msg, const void *buf, unsigned int size, unsigned int index);
extern void dump_out_mmx_msg(const void *msg, const void *buf, unsigned int size, unsigned int index);
extern void dump_stuff_shammx_msg(const void *msg, const void *buf, unsigned int size, unsigned int index);
extern void dump_out_shammx_msg(const void *msg, const void *buf, unsigned int size, unsigned int index);
extern void dump_stuff_shammx64_msg(const void *msg, const void *buf, unsigned int size, unsigned int index);
extern void dump_out_shammx64_msg(const void *msg, const void *buf, unsigned int size, unsigned int index);
#endif

#if defined (SIMD_PARA_MD5)
// these functions help debug arrays of contigious MD5 prepared PARA buffers. Seen in sunmd5 at the current time.
extern void dump_stuff_mpara_mmx_msg(const void *msg, const void *buf, unsigned int size, unsigned int index);
// a 'getter' to help debugging.  Returns a flat buffer, vs printing it out.
extern void getbuf_stuff_mpara_mmx(unsigned char *oBuf, const void *buf, unsigned int size, unsigned int index);
#endif

/*
 * here, a stack buffer that is at least align-1 bytes LARGER than required, can be
 * properly aligned to 'align' bytes. So:   char tmpbuf[256+15], *aligned_buf=mem_align(tmpbuf,16);
 * will give you a stack buffer, aligned to 16 bytes.  There are bugs in some compilers which cause
 * JTR_ALIGN(x) to fail properly (such as a bug in bitcoin OMP mode for linux32)
 * Switched to a define macro for performance.
 */
#define mem_align(a,b) (void*)(((char*)(a))+(((b)-1)-(((size_t)((char*)(a))-1)&((b)-1))))


/*
 * 16-bit endian-swap a memory buffer in place. Size is in octets (so should
 * be a multiple of 2). From now on, this function may be used on any arch.
 * this is needed for some swapping of things like UTF16LE to UTF16BE, etc.
 */
extern void alter_endianity_w16(void * x, unsigned int size);

/*
 * 32-bit endian-swap a memory buffer in place. Size is in octets (so should
 * be a multiple of 4). From now on, this function may be used on any arch.
 */
extern void alter_endianity(void * x, unsigned int size);

/* 32-bit endian-swap a memory buffer in place. Count is in 32-bit words */
extern void alter_endianity_w(void *x, unsigned int count);

/* 64-bit endian-swap a memory buffer in place. Count is in 64-bit words */
extern void alter_endianity_w64(void *x, unsigned int count);

#if ARCH_ALLOWS_UNALIGNED
// we can inline these, to always use JOHNSWAP/JOHNSWAP64
// NOTE, more portable to use #defines to inline, than the MAYBE_INLINE within header files.
#if !ARCH_LITTLE_ENDIAN
#define alter_endianity_to_BE(a,b)
#define alter_endianity_to_BE64(a,b)
#define alter_endianity_to_LE(ptr,word32_cnt) do{ \
    int i; \
    for (i=0;i<word32_cnt; i++) \
        ((uint32_t*)ptr)[i] = JOHNSWAP(((uint32_t*)ptr)[i]); \
}while(0)
#define alter_endianity_to_LE64(ptr,word64_cnt) do{ \
    int i; \
    for (i=0;i<word64_cnt; i++) \
        ((uint64_t*)ptr)[i] = JOHNSWAP64(((uint64_t*)ptr)[i]); \
}while(0)
#else
#define alter_endianity_to_LE(a,b)
#define alter_endianity_to_LE64(a,b)
#define alter_endianity_to_BE(ptr,word32_cnt) do{ \
    int i; \
    for (i=0;i<word32_cnt; i++) \
        ((uint32_t*)ptr)[i] = JOHNSWAP(((uint32_t*)ptr)[i]); \
}while(0)
#define alter_endianity_to_BE64(ptr,word64_cnt) do{ \
    int i; \
    for (i=0;i<word64_cnt; i++) \
        ((uint64_t*)ptr)[i] = JOHNSWAP64(((uint64_t*)ptr)[i]); \
}while(0)
#endif
#else
#if !ARCH_LITTLE_ENDIAN
#define alter_endianity_to_BE(a,b)
#define alter_endianity_to_LE(a,b) do{alter_endianity_w(a,b);}while(0)
#define alter_endianity_to_BE64(a,b)
#define alter_endianity_to_LE64(a,b) do{alter_endianity_w64(a,b);}while(0)
#else
#define alter_endianity_to_BE(a,b) do{alter_endianity_w(a,b);}while(0)
#define alter_endianity_to_LE(a,b)
#define alter_endianity_to_BE64(a,b) do{alter_endianity_w64(a,b);}while(0)
#define alter_endianity_to_LE64(a,b)
#endif
#endif

typedef struct {
	void * base, * aligned;
	size_t base_size, aligned_size;
} region_t;

extern void* alloc_region_t(region_t * region, size_t size);
extern void init_region_t(region_t * region);
extern int free_region_t(region_t * region);

#endif

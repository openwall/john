/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2010,2012,2016 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h> /* for isprint() */
#if HAVE_MEMALIGN && HAVE_MALLOC_H
#include <malloc.h>
#endif

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "johnswap.h"

#if defined(WITH_ASAN) && !defined(DEBUG)
#define DEBUG
#endif

#if (defined (_MSC_VER) || HAVE___MINGW_ALIGNED_MALLOC)
char *strdup_MSVC(const char *str)
{
	char * s;
	s = (char*)mem_alloc(strlen(str)+1);
	if (s != NULL)
		strcpy(s, str);
	return s;
}
#endif

unsigned int mem_saving_level = 0;

// Add 'cleanup' methods for the mem_alloc_tiny.  VERY little cost, but
// allows us to check for mem leaks easier.
struct rm_list
{
	void *mem;
	struct rm_list *next;
};
static struct rm_list *mem_alloc_tiny_memory;

static void add_memory_link(void *v) {
	struct rm_list *p = (struct rm_list *)mem_alloc(sizeof(struct rm_list));
	p->next = mem_alloc_tiny_memory;
	p->mem = v;
	mem_alloc_tiny_memory = p;
}
// call at program exit.
void cleanup_tiny_memory()
{
	struct rm_list *p = mem_alloc_tiny_memory, *p2;
	for (;;) {
		if (!p)
			return;
		free(p->mem);
		p2 = p->next;
		free(p);
		p = p2;
	}
}

#if defined(WITH_ASAN) || defined(DEBUG)
static void mem_debug_fill(void *p, size_t size)
{
	if (p)
		memset(p, 0xde, size);
}
#else
#define mem_debug_fill(p, size) /* nothing */
#endif

void *mem_alloc(size_t size)
{
	void *res;

	if (!size)
		return NULL;

	if (!(res = malloc(size))) {
		fprintf(stderr, "mem_alloc(): %s trying to allocate "Zu" bytes\n", strerror(ENOMEM), size);
		error();
	}

	mem_debug_fill(res, size);

	return res;
}

void *mem_calloc(size_t nmemb, size_t size)
{
	void *res;

	if (!nmemb || !size)
		return NULL;

	if (!(res = calloc(nmemb, size))) {
		fprintf(stderr, "mem_calloc(): %s trying to allocate "Zu" bytes\n", strerror(ENOMEM), nmemb * size);
		error();
	}

	return res;
}

void *mem_realloc(void *old_ptr, size_t size)
{
	void *res;

	if (!size)
		return NULL;

	if (!(res = realloc(old_ptr, size))) {
		fprintf(stderr, "mem_realloc(): %s trying to allocate "Zu" bytes\n", strerror(ENOMEM), size);
		error();
	}

/* We don't know old size, so also don't know how much to mem_debug_fill() */

	return res;
}

char *xstrdup (const char* str)
{
	char *res = strdup(str);

	if (res == NULL) {
		fprintf(stderr, "xstrdup(): %s\n", strerror (ENOMEM));
		error();
	}
	
	return res;
}

/*
 * if -DDEBUG we turn mem_alloc_tiny() to essentially be just a malloc()
 * with additional alignment. The reason for this is it's way easier to
 * trace bugs that way.
 * Also, with -DDEBUG we always return exactly the requested
 * alignment, in order to trigger bugs!
 */
#ifdef DEBUG
#undef  MEM_ALLOC_SIZE
#define MEM_ALLOC_SIZE 0
#endif
void *mem_alloc_tiny(size_t size, size_t align)
{
	static char *buffer = NULL;
	static size_t bufree = 0;
	size_t mask;
	char *p;

#if defined(DEBUG)
	size += align;
#endif
#ifdef DEBUG
	/*
	 * We may be called with size zero, for example from ldr_load_pw_line()
	 * that calls mem_alloc_copy() with format->params.salt_size as size.
	 * This causes problems with -DDEBUG without this fix because we never
	 * get out of the while loop when MEM_ALLOC_SIZE is zero too. The
	 * previous fix for this was returning NULL but that lead to other
	 * problems that I did not bother digging into. This fix should be
	 * 100% safe.
	 */
	if (size == 0)
		size = 1;
#endif

#if ARCH_ALLOWS_UNALIGNED
	if (mem_saving_level > 2 && align < MEM_ALIGN_SIMD)
		align = MEM_ALIGN_NONE;
#endif

	mask = align - 1;

	do {
		if (buffer) {
			size_t need =
			    size + mask - (((size_t)buffer + mask) & mask);
			if (bufree >= need) {
				p = buffer;
				p += mask;
				p -= (size_t)p & mask;
				bufree -= need;
				buffer = p + size;
#if defined(DEBUG)
				/* Ensure alignment is no better than requested */
				if (((size_t)p & ((mask << 1) + 1)) == 0)
					p += align;
#endif
				return p;
			}
		}

		if (size + mask > MEM_ALLOC_SIZE ||
		    bufree > MEM_ALLOC_MAX_WASTE)
			break;
		buffer = (char*)mem_alloc(MEM_ALLOC_SIZE);
		add_memory_link((void*)buffer);
		bufree = MEM_ALLOC_SIZE;
	} while (1);

	p = (char*)mem_alloc(size + mask);
	add_memory_link((void*)p);
	p += mask;
	p -= (size_t)p & mask;
#if defined(DEBUG)
	/* Ensure alignment is no better than requested */
	if (((size_t)p & ((mask << 1) + 1)) == 0)
		p += align;
#endif
	return p;
}

void *mem_calloc_tiny(size_t size, size_t align)
{
	char *cp = (char*) mem_alloc_tiny(size, align);

	memset(cp, 0, size);
	return cp;
}

void *mem_alloc_copy(const void *src, size_t size, size_t align)
{
	return memcpy(mem_alloc_tiny(size, align), src, size);
}

void *mem_alloc_align(size_t size, size_t align)
{
	void *ptr = NULL;
	if (align < sizeof(void*))
		align = sizeof(void*);
	if (!size)
		return NULL;
#ifdef DEBUG
    assert(!(align & (align - 1)));
#endif
#if HAVE_POSIX_MEMALIGN
	if (posix_memalign(&ptr, align, size))
		pexit("posix_memalign ("Zu" bytes)", size);
#elif HAVE_ALIGNED_ALLOC
	/* According to the Linux man page, "size should be a multiple of
	   alignment", whatever they mean with "should"... This does not
	   make any sense whatsoever but we round it up to comply. */
	size = ((size + (align - 1)) / align) * align;
	if (!(ptr = aligned_alloc(align, size)))
		pexit("aligned_alloc ("Zu" bytes)", size);
#elif HAVE_MEMALIGN
	/* Let's just pray this implementation can actually free it */
#if defined(__sparc__) || defined(__sparc) || defined(sparc) || defined(__sparcv9)
	if (!(ptr = memalign(align, size)))
#else
	if (!(ptr = memalign(&ptr, align, size)))
#endif
		pexit("memalign ("Zu" bytes)", size);
#elif HAVE___MINGW_ALIGNED_MALLOC
	if (!(ptr = __mingw_aligned_malloc(size, align)))
		pexit("__mingw_aligned_malloc (%u bytes)", (unsigned)size);
#elif HAVE__ALIGNED_MALLOC
	if (!(ptr = _aligned_malloc(size, align)))
		pexit("_aligned_malloc ("Zu" bytes)", size);

#elif AC_BUILT
#error No suitable alligned alloc found, please report to john-dev mailing list (state your OS details).

/* we need an aligned alloc function for legacy builds */
#elif _ISOC11_SOURCE
	size = ((size + (align - 1)) / align) * align;
	if (!(ptr = aligned_alloc(align, size)))
		pexit("aligned_alloc ("Zu" bytes)", size);
#else
	if (posix_memalign(&ptr, align, size))
		pexit("posix_memalign ("Zu" bytes)", size);
#endif
	mem_debug_fill(ptr, size);
	return ptr;
}

void *mem_calloc_align(size_t count, size_t size, size_t align)
{
	void *ptr = mem_alloc_align(size * count, align);

	memset(ptr, 0, size * count);
	return ptr;
}

char *str_alloc_copy(const char *src)
{
	size_t size;

	if (!src) return "";
	if (!*src) return "";

	size = strlen(src) + 1;
	return (char *)memcpy(mem_alloc_tiny(size, MEM_ALIGN_NONE), src, size);
}

void alter_endianity_w16(void * _x, unsigned int size) {
	unsigned char c, *x = (unsigned char*)_x;

	// size is in octets
	size>>=1;
	while (size--) {
		c = *x;
		*x = x[1];
		x[1] = c;
		x += 2;
	}
}

void alter_endianity(void *_x, unsigned int size) {
	uint32_t *x = (uint32_t*)_x;

	// size is in octets
	size>>=2;

#if !ARCH_ALLOWS_UNALIGNED
	if (is_aligned(x, sizeof(uint32_t))) {
#endif
		while (size--) {
			*x = JOHNSWAP(*x);
			x++;
		}
#if !ARCH_ALLOWS_UNALIGNED
	} else {
		unsigned char *cpX, c;

		cpX = (unsigned char*)x;
		while (size--) {
			c = *cpX;
			*cpX = cpX[3];
			cpX[3] = c;
			c = cpX[1];
			cpX[1] = cpX[2];
			cpX[2] = c;
			cpX += 4;
		}
	}
#endif
}

void dump_text_msg(const void *msg, const void *in, int len)
{
	unsigned char *p = (unsigned char*)in;

	printf("%s : ", (char *)msg);
	while (len--) {
		fputc(isprint(*p) ? *p : '.', stdout);
		p++;
	}
	fputc('\n', stdout);
}

void dump_stuff_msg(const void *msg, const void *x, unsigned int size)
{
	unsigned int i;

	printf("%s : ", (char *)msg);
	for (i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)x)[i]);
		if ( (i%4)==3 )
		printf(" ");
	}
	fputc('\n', stdout);
}

void dump_stuff_be_msg(const void *msg, const void *x, unsigned int size)
{
	unsigned int i;

	printf("%s : ", (char *)msg);
	for (i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)x)[i^3]);
		if ( (i%4)==3 )
		printf(" ");
	}
	fputc('\n', stdout);
}

#if defined(SIMD_COEF_32) || defined(NT_X86_64) || defined (SIMD_PARA_MD5) || defined (SIMD_PARA_MD4) || defined (SIMD_PARA_SHA1)
#ifndef SIMD_COEF_32
#define SIMD_COEF_32	4
#endif
#ifndef SIMD_COEF_64
#define SIMD_COEF_64 2
#endif
#ifndef SIMD_COEF_32
#define SIMD_COEF_32 4
#endif

// These work for standard SIMD_COEF_32 buffers, AND for SSEi MMX_PARA multiple SIMD_COEF_32 blocks, where index will be mod(X * SIMD_COEF_32) and not simply mod(SIMD_COEF_32)
#define SHAGETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3) )*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32 ) //for endianity conversion
#define SHAGETOUTPOS(i, index)	( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3) )*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*20*SIMD_COEF_32 ) //for endianity conversion
// for MD4/MD5 or any 64 byte LE SSE interleaved hash
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3) )*SIMD_COEF_32 +    ((i)&3)  + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32  )
#define GETOUTPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3) )*SIMD_COEF_32 +    ((i)&3)  + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32  )
// for SHA384/SHA512 128 byte BE interleaved hash (arrays of 16 8 byte ints)
#define SHA64GETPOS(i,index)	( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7) )*SIMD_COEF_64 + (7-((i)&7)) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*8*SIMD_COEF_64 )
#define SHA64GETOUTPOS(i,index)	( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7) )*SIMD_COEF_64 + (7-((i)&7)) + (unsigned int)index/SIMD_COEF_64*64*SIMD_COEF_64 )

// for SHA384/SHA512 128 byte FLAT interleaved hash (arrays of 16 8 byte ints), but we do not BE interleave.
#define SHA64GETPOSne(i,index)      ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7) )*SIMD_COEF_64 + ((i)&7) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*8*SIMD_COEF_64 )

void dump_stuff_mmx_msg(const void *msg, const void *buf, unsigned int size,
                        unsigned int index)
{
	unsigned int i;

	printf("%s : ", (char*)msg);
	for (i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[GETPOS(i, index)]);
		if ( (i%4)==3 )
			printf(" ");
	}
	fputc('\n', stdout);
}

void dump_out_mmx_msg(const void *msg, const void *buf, unsigned int size,
                      unsigned int index)
{
	unsigned int i;

	printf("%s : ", (char*)msg);
	for (i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[GETOUTPOS(i, index)]);
		if ( (i%4)==3 )
			printf(" ");
	}
	fputc('\n', stdout);
}

#if defined (SIMD_PARA_MD5)
#define GETPOSMPARA(i, index)	( (index&(SIMD_COEF_32-1))*4 + (((i)&(0xffffffff-3))%64)*SIMD_COEF_32 + (i/64)*SIMD_COEF_32*SIMD_PARA_MD5*64 +    ((i)&3)  + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32  )
// multiple para blocks
void dump_stuff_mpara_mmx_msg(const void *msg, const void *buf, unsigned int size,
                              unsigned int index)
{
	unsigned int i;

	printf("%s : ", (char*)msg);
	for (i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[GETPOSMPARA(i, index)]);
		if ( (i%4)==3 )
			printf(" ");
	}
	fputc('\n', stdout);
}

// obuf has to be at lease size long.  This function will unwind the SSE-para buffers into a flat.
void getbuf_stuff_mpara_mmx(unsigned char *oBuf, const void *buf, unsigned int size, unsigned int index) {
	unsigned int i;

	for (i=0;i<size;i++)
		*oBuf++ = ((unsigned char*)buf)[GETPOSMPARA(i, index)];
}
#endif

void dump_stuff_shammx_msg(const void *msg, const void *buf, unsigned int size,
                           unsigned int index)
{
	unsigned int i;

	printf("%s : ", (char*)msg);
	for (i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[SHAGETPOS(i, index)]);
		if ( (i%4)==3 )
			printf(" ");
	}
	fputc('\n', stdout);
}

void dump_out_shammx_msg(const void *msg, const void *buf, unsigned int size,
                         unsigned int index)
{
	unsigned int i;

	printf("%s : ", (char*)msg);
	for (i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[SHAGETOUTPOS(i, index)]);
		if ( (i%4)==3 )
			printf(" ");
	}
	fputc('\n', stdout);
}

void dump_stuff_shammx64_msg(const void *msg, const void *buf, unsigned int size, unsigned int index) {
	unsigned int i;

	printf("%s : ", (char*)msg);
	for (i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[SHA64GETPOS(i, index)]);
		if ( (i%4)==3 )
			printf(" ");
	}
	fputc('\n', stdout);
}

void dump_stuff_mmx64_msg(const void *msg, const void *buf, unsigned int size, unsigned int index) {
	unsigned int i;

	printf("%s : ", (char*)msg);
	for (i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[SHA64GETPOSne(i, index)]);
		if ( (i%4)==3 )
			printf(" ");
	}
	fputc('\n', stdout);
}

void dump_out_shammx64_msg(const void *msg, const void *buf, unsigned int size, unsigned int index) {
	unsigned int i;

	printf("%s : ", (char*)msg);
	for (i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[SHA64GETOUTPOS(i, index)]);
		if ( (i%4)==3 )
			printf(" ");
	}
	fputc('\n', stdout);
}
#endif

void alter_endianity_w(void *_x, unsigned int count) {
	int i = -1;
	uint32_t *x = (uint32_t*)_x;
#if ARCH_ALLOWS_UNALIGNED
	while (++i < count) {
		x[i] = JOHNSWAP(x[i]);
	}
#else
	unsigned char *cpX, c;
	if (is_aligned(x,sizeof(uint32_t))) {
		// we are in alignment.
		while (++i < count) {
			x[i] = JOHNSWAP(x[i]);
		}
		return;
	}
	// non-aligned data :(
	cpX = (unsigned char*)x;
	while (++i < count) {
		c = *cpX;
		*cpX = cpX[3];
		cpX[3] = c;
		c = cpX[1];
		cpX[1] = cpX[2];
		cpX[2] = c;
		cpX += 4;
	}
#endif
}

void alter_endianity_w64(void *_x, unsigned int count) {
	int i = -1;
	uint64_t *x = (uint64_t*)_x;
#if ARCH_ALLOWS_UNALIGNED
	while (++i < count) {
		x[i] = JOHNSWAP64(x[i]);
	}
#else
	unsigned char *cpX, c;
	if (is_aligned(x,sizeof(uint64_t))) {
		// we are in alignment.
		while (++i < count) {
			x[i] = JOHNSWAP64(x[i]);
		}
		return;
	}
	// non-aligned data :(
	cpX = (unsigned char*)x;
	while (++i < count) {
		c = *cpX;
		*cpX = cpX[7];
		cpX[7] = c;
		c = cpX[1];
		cpX[1] = cpX[6];
		cpX[6] = c;
		c = cpX[2];
		cpX[2] = cpX[5];
		cpX[5] = c;
		c = cpX[3];
		cpX[3] = cpX[4];
		cpX[4] = c;
		cpX += 8;
	}
#endif
}

#ifdef __unix__
#include <sys/mman.h>
#endif

#define HUGEPAGE_THRESHOLD		(12 * 1024 * 1024)

#ifdef __x86_64__
#define HUGEPAGE_SIZE			(2 * 1024 * 1024)
#else
#undef HUGEPAGE_SIZE
#endif

void *
alloc_region_t(region_t * region, size_t size)
{
	size_t base_size = size;
	void * base, * aligned;
#ifdef MAP_ANON
	int flags =
#ifdef MAP_NOCORE
	    MAP_NOCORE |
#endif
	    MAP_ANON | MAP_PRIVATE;
#if defined(MAP_HUGETLB) && defined(HUGEPAGE_SIZE)
	size_t new_size = size;
	const size_t hugepage_mask = (size_t)HUGEPAGE_SIZE - 1;
	if (size >= HUGEPAGE_THRESHOLD && size + hugepage_mask >= size) {
		flags |= MAP_HUGETLB;
/*
 * Linux's munmap() fails on MAP_HUGETLB mappings if size is not a multiple of
 * huge page size, so let's round up to huge page size here.
 */
		new_size = size + hugepage_mask;
		new_size &= ~hugepage_mask;
	}
	base = mmap(NULL, new_size, PROT_READ | PROT_WRITE, flags, -1, 0);
	if (base != MAP_FAILED) {
		base_size = new_size;
	} else
	if (flags & MAP_HUGETLB) {
		flags &= ~MAP_HUGETLB;
		base = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
	}

#else
	base = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
#endif
	if (base == MAP_FAILED)
		base = NULL;
	aligned = base;
#elif defined(HAVE_POSIX_MEMALIGN)
	if ((errno = posix_memalign(&base, 64, size)) != 0)
		base = NULL;
	aligned = base;
#else
	base = aligned = NULL;
	if (size + 63 < size) {
		errno = ENOMEM;
	} else if ((base = malloc(size + 63)) != NULL) {
		aligned = (uint8_t *)base + 63;
		aligned = (uint8_t *)aligned - ((uintptr_t)aligned & 63);
	}
#endif
	region->base = base;
	region->aligned = aligned;
	region->base_size = base ? base_size : 0;
	region->aligned_size = base ? size : 0;
	mem_debug_fill(aligned, size);
	return aligned;
}

inline void init_region_t(region_t * region)
{
	region->base = region->aligned = NULL;
	region->base_size = region->aligned_size = 0;
}

int free_region_t(region_t * region)
{
	if (region->base) {
#ifdef MAP_ANON
		if (munmap(region->base, region->base_size))
			return -1;
#else
		free(region->base);
#endif
	}
	init_region_t(region);
	return 0;
}

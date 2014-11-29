/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2010,2012 by Solar Designer
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
#include <ctype.h> /* for isprint() */

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "johnswap.h"
#include "memdbg.h"

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
	// mark these as 'tiny' memory, so that memory snapshot checking does not
	// flag these as leaks.  At program exit, this memory will still get checked,
	// but it should be freed, so will still be globally checked for leaks.
	MEMDBG_tag_mem_from_alloc_tiny(v);
	MEMDBG_tag_mem_from_alloc_tiny((void*)p);
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

void *mem_alloc_func(size_t size
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
	)
{
	void *res;

	if (!size) return NULL;
#if defined (MEMDBG_ON)
	res = (char*) MEMDBG_alloc(size, file, line);
#else
	res = malloc(size);
#endif
	if (!res) {
		fprintf(stderr, "mem_alloc(): %s trying to allocate %zd bytes\n", strerror(ENOMEM), size);
		error();
	}

	return res;
}

void *mem_calloc_func(size_t size
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
	)
{
#if defined (MEMDBG_ON)
	char *res = (char*) MEMDBG_alloc(size, file, line);
#else
	char *res = (char*) mem_alloc(size);
#endif
	memset(res, 0, size);
	return res;
}

/*
 * if -DDEBUG we turn mem_alloc_tiny() to essentially be just a malloc()
 * with additional alignment. The reason for this is it's way easier to
 * trace bugs that way.
 */
#ifdef DEBUG
#undef  MEM_ALLOC_SIZE
#define MEM_ALLOC_SIZE 0
#endif
void *mem_alloc_tiny_func(size_t size, size_t align
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
)
{
	static char *buffer = NULL;
	static size_t bufree = 0;
	size_t mask;
	char *p;

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
				return p;
			}
		}

		if (size + mask > MEM_ALLOC_SIZE ||
		    bufree > MEM_ALLOC_MAX_WASTE)
			break;
#if defined (MEMDBG_ON)
		buffer = (char*)mem_alloc_func(MEM_ALLOC_SIZE, file, line);
#else
		buffer = (char*)mem_alloc(MEM_ALLOC_SIZE);
#endif
		add_memory_link((void*)buffer);
		bufree = MEM_ALLOC_SIZE;
	} while (1);

#if defined (MEMDBG_ON)
	p = (char*)mem_alloc_func(size + mask, file, line);
#else
	p = (char*)mem_alloc(size + mask);
#endif
	add_memory_link((void*)p);
	p += mask;
	p -= (size_t)p & mask;
	return p;
}

void *mem_calloc_tiny_func(size_t size, size_t align
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
	) {
#if defined (MEMDBG_ON)
	char *cp = (char*)mem_alloc_tiny_func(size, align, file, line);
#else
	char *cp = (char*) mem_alloc_tiny(size, align);
#endif
	memset(cp, 0, size);
	return cp;
}

void *mem_alloc_copy_func(void *src, size_t size, size_t align
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
	) {
#if defined (MEMDBG_ON)
	return memcpy(mem_alloc_tiny_func(size, align, file, line), src, size);
#else
	return memcpy(mem_alloc_tiny(size, align), src, size);
#endif
}

char *str_alloc_copy_func(char *src
#if defined (MEMDBG_ON)
	, char *file, int line
#endif
	) {
	size_t size;

	if (!src) return "";
	if (!*src) return "";

	size = strlen(src) + 1;
#if defined (MEMDBG_ON)
	return (char *)memcpy(mem_alloc_tiny_func(size, MEM_ALIGN_NONE, file, line), src, size);
#else
	return (char *)memcpy(mem_alloc_tiny(size, MEM_ALIGN_NONE), src, size);
#endif
}

void *mem_align(void *stack_ptr, int align) {
    char *cp_align = (char*)stack_ptr;

    cp_align += (align-1);
    cp_align -= (size_t)cp_align % align; // if we stipulate that align must be 1<<x (i.e. base 2), %align can be replaced with &(align-1)
    return (void*)cp_align;
}

void dump_text(void *in, int len)
{
	unsigned char *p = (unsigned char*)in;

	while (len--) {
		fputc(isprint(*p) ? *p : '.', stdout);
		p++;
	}
	fputc('\n', stdout);
}

void dump_stuff_noeol(void *x, unsigned int size)
{
	unsigned int i;
	for(i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)x)[i]);
		if( (i%4)==3 )
		printf(" ");
	}
}
void dump_stuff(void* x, unsigned int size)
{
	dump_stuff_noeol(x,size);
	printf("\n");
}
void dump_stuff_msg(void *msg, void *x, unsigned int size) {
	printf("%s : ", (char *)msg);
	dump_stuff(x, size);
}
void dump_stuff_msg_sepline(void *msg, void *x, unsigned int size) {
	printf("%s :\n", (char *)msg);
	dump_stuff(x, size);
}

void dump_stuff_be_noeol(void *x, unsigned int size) {
	unsigned int i;
	for(i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)x)[i^3]);
		if( (i%4)==3 )
		printf(" ");
	}
}
void dump_stuff_be(void* x, unsigned int size)
{
	dump_stuff_be_noeol(x,size);
	printf("\n");
}
void dump_stuff_be_msg(void *msg, void *x, unsigned int size) {
	printf("%s : ", (char *)msg);
	dump_stuff_be(x, size);
}
void dump_stuff_be_msg_sepline(void *msg, void *x, unsigned int size) {
	printf("%s :\n", (char *)msg);
	dump_stuff_be(x, size);
}

void alter_endianity(void *_x, unsigned int size) {
	ARCH_WORD_32 *x = (ARCH_WORD_32*)_x;

	// size is in octets
	size>>=2;

#if !ARCH_ALLOWS_UNALIGNED
	if (is_aligned(x, sizeof(ARCH_WORD_32))) {
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

#if defined(MMX_COEF) || defined(NT_X86_64) || defined (MD5_SSE_PARA) || defined (MD4_SSE_PARA) || defined (SHA1_SSE_PARA)
#ifndef MMX_COEF
#define MMX_COEF	4
#endif
#ifndef MMX_COEF_SHA512
#define MMX_COEF_SHA512 2
#endif
#ifndef MMX_COEF_SHA256
#define MMX_COEF_SHA256 4
#endif

// These work for standard MMX_COEF buffers, AND for SSEi MMX_PARA multiple MMX_COEF blocks, where index will be mod(X * MMX_COEF) and not simply mod(MMX_COEF)
#define SHAGETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3) )*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*4*MMX_COEF ) //for endianity conversion
#define SHAGETOUTPOS(i, index)	( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3) )*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*20*MMX_COEF ) //for endianity conversion
// for MD4/MD5 or any 64 byte LE SSE interleaved hash
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3) )*MMX_COEF +    ((i)&3)  + (index>>(MMX_COEF>>1))*64*MMX_COEF  )
#define GETOUTPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3) )*MMX_COEF +    ((i)&3)  + (index>>(MMX_COEF>>1))*16*MMX_COEF  )
// for SHA384/SHA512 128 byte BE interleaved hash (arrays of 16 8 byte ints)
#define SHA64GETPOS(i,index)	( (index&(MMX_COEF_SHA512-1))*8 + ((i)&(0xffffffff-7) )*MMX_COEF_SHA512 + (7-((i)&7)) + (index>>(MMX_COEF_SHA512>>1))*SHA_BUF_SIZ*8*MMX_COEF_SHA512 )
#define SHA64GETOUTPOS(i,index)	( (index&(MMX_COEF_SHA512-1))*8 + ((i)&(0xffffffff-7) )*MMX_COEF_SHA512 + (7-((i)&7)) + (index>>(MMX_COEF_SHA512>>1))*64*MMX_COEF_SHA512 )

void dump_stuff_mmx_noeol(void *buf, unsigned int size, unsigned int index) {
	unsigned int i;
	for(i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[GETPOS(i, index)]);
		if( (i%4)==3 )
			printf(" ");
	}
}
void dump_stuff_mmx(void *buf, unsigned int size, unsigned int index) {
	dump_stuff_mmx_noeol(buf, size, index);
	printf("\n");
}
void dump_stuff_mmx_msg(void *msg, void *buf, unsigned int size, unsigned int index) {
	printf("%s : ", (char*)msg);
	dump_stuff_mmx(buf, size, index);
}
void dump_stuff_mmx_msg_sepline(void *msg, void *buf, unsigned int size, unsigned int index) {
	printf("%s :\n", (char*)msg);
	dump_stuff_mmx(buf, size, index);
}
void dump_out_mmx_noeol(void *buf, unsigned int size, unsigned int index) {
	unsigned int i;
	for(i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[GETOUTPOS(i, index)]);
		if( (i%4)==3 )
			printf(" ");
	}
}
void dump_out_mmx(void *buf, unsigned int size, unsigned int index) {
	dump_out_mmx_noeol(buf,size,index);
	printf("\n");
}
void dump_out_mmx_msg(void *msg, void *buf, unsigned int size, unsigned int index) {
	printf("%s : ", (char*)msg);
	dump_out_mmx(buf, size, index);
}
void dump_out_mmx_msg_sepline(void *msg, void *buf, unsigned int size, unsigned int index) {
	printf("%s :\n", (char*)msg);
	dump_out_mmx(buf, size, index);
}

#if defined (MD5_SSE_PARA)
#define GETPOSMPARA(i, index)	( (index&(MMX_COEF-1))*4 + (((i)&(0xffffffff-3))%64)*MMX_COEF + (i/64)*MMX_COEF*MD5_SSE_PARA*64 +    ((i)&3)  + (index>>(MMX_COEF>>1))*64*MMX_COEF  )
// multiple para blocks
void dump_stuff_mpara_mmx_noeol(void *buf, unsigned int size, unsigned int index) {
	unsigned int i;
	for(i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[GETPOSMPARA(i, index)]);
		if( (i%4)==3 )
			printf(" ");
	}
}
void dump_stuff_mpara_mmx(void *buf, unsigned int size, unsigned int index) {
	dump_stuff_mpara_mmx_noeol(buf, size, index);
	printf("\n");
}
// obuf has to be at lease size long.  This function will unwind the SSE-para buffers into a flat.
void getbuf_stuff_mpara_mmx(unsigned char *oBuf, void *buf, unsigned int size, unsigned int index) {
	unsigned int i;
	for(i=0;i<size;i++)
		*oBuf++ = ((unsigned char*)buf)[GETPOSMPARA(i, index)];
}
void dump_stuff_mpara_mmx_msg(void *msg, void *buf, unsigned int size, unsigned int index) {
	printf("%s : ", (char*)msg);
	dump_stuff_mpara_mmx(buf, size, index);
}
void dump_stuff_mpara_mmx_msg_sepline(void *msg, void *buf, unsigned int size, unsigned int index) {
	printf("%s :\n", (char*)msg);
	dump_stuff_mpara_mmx(buf, size, index);
}
#endif

void dump_stuff_shammx(void *buf, unsigned int size, unsigned int index) {
	unsigned int i;
	for(i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[SHAGETPOS(i, index)]);
		if( (i%4)==3 )
			printf(" ");
	}
	printf("\n");
}
void dump_stuff_shammx_msg(void *msg, void *buf, unsigned int size, unsigned int index) {
	printf("%s : ", (char*)msg);
	dump_stuff_shammx(buf, size, index);
}
void dump_out_shammx(void *buf, unsigned int size, unsigned int index) {
	unsigned int i;
	for(i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[SHAGETOUTPOS(i, index)]);
		if( (i%4)==3 )
			printf(" ");
	}
	printf("\n");
}
void dump_out_shammx_msg(void *msg, void *buf, unsigned int size, unsigned int index) {
	printf("%s : ", (char*)msg);
	dump_out_shammx(buf, size, index);
}

void dump_stuff_shammx64(void *buf, unsigned int size, unsigned int index) {
	unsigned int i;
	for(i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[SHA64GETPOS(i, index)]);
		if( (i%4)==3 )
			printf(" ");
	}
	printf("\n");
}
void dump_stuff_shammx64_msg(void *msg, void *buf, unsigned int size, unsigned int index) {
	printf("%s : ", (char*)msg);
	dump_stuff_shammx64(buf, size, index);
}
void dump_out_shammx64(void *buf, unsigned int size, unsigned int index) {
	unsigned int i;
	for(i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)buf)[SHA64GETOUTPOS(i, index)]);
		if( (i%4)==3 )
			printf(" ");
	}
	printf("\n");
}
void dump_out_shammx64_msg(void *msg, void *buf, unsigned int size, unsigned int index) {
	printf("%s : ", (char*)msg);
	dump_out_shammx64(buf, size, index);
}
#endif

void alter_endianity_w(void *_x, unsigned int count) {
	int i = -1;
	ARCH_WORD_32 *x = (ARCH_WORD_32*)_x;
#if ARCH_ALLOWS_UNALIGNED
	while (++i < count) {
		x[i] = JOHNSWAP(x[i]);
	}
#else
	unsigned char *cpX, c;
	if (is_aligned(x,sizeof(ARCH_WORD_32))) {
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
	ARCH_WORD_64 *x = (ARCH_WORD_64*)_x;
#if ARCH_ALLOWS_UNALIGNED
	while (++i < count) {
		x[i] = JOHNSWAP64(x[i]);
	}
#else
	unsigned char *cpX, c;
	if (is_aligned(x,sizeof(ARCH_WORD_64))) {
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
		cpX += 4;
	}
#endif
}

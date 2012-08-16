/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2003,2010,2011 by Solar Designer
 */

/*
 * Memory allocation routines.
 */

#ifndef _JOHN_MEMORY_H
#define _JOHN_MEMORY_H

#include <stdio.h>
#include <stdlib.h>

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
#define MEM_ALIGN_CACHE			(ARCH_SIZE * 8)
#define MEM_ALIGN_PAGE			0x1000

/*
 * SIMD buffers need to be aligned to register size
 */
#if MMX_COEF
#define MEM_ALIGN_SIMD			(MMX_COEF * 4)
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
 * Allocates size bytes and returns a pointer to the allocated memory.
 * If an error occurs, the function does not return.
 */
extern void *mem_alloc(size_t size);

/*
 * Frees memory allocated with mem_alloc() and sets the pointer to NULL.
 * Does nothing if the pointer is already NULL.
 */
#define MEM_FREE(ptr) \
{ \
	if ((ptr)) { \
		free((ptr)); \
		(ptr) = NULL; \
	} \
}

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
extern void *mem_alloc_copy(size_t size, size_t align, void *src);

/*
 * Similar to the above function, but for ASCIIZ strings.
 */
extern char *str_alloc_copy(char *src);

/*
 * This will 'cleanup' the memory allocated by mem_alloc_tiny().  All
 * of that memory was 'blindly' allocated, and not freed up during
 * the run of john.  Now, it is 'cleaned' up.
 */
extern void cleanup_tiny_memory();


void dump_stuff(void *x, unsigned int size);
void dump_stuff_msg(void *msg, void *x, unsigned int size);
void dump_stuff_noeol(void *x, unsigned int size);
void dump_stuff_msg_sepline(void *msg, void *x, unsigned int size);
#if defined (MMX_COEF) || defined(NT_X86_64) || defined (MD5_SSE_PARA) || defined (MD4_SSE_PARA) || defined (SHA1_SSE_PARA)
void dump_stuff_mmx(void *x, unsigned int size, unsigned int index);
void dump_stuff_mmx_noeol(void *x, unsigned int size, unsigned int index);
void dump_stuff_mmx_msg(void *msg, void *buf, unsigned int size, unsigned int index);
void dump_stuff_mmx_msg_sepline(void *msg, void *buf, unsigned int size, unsigned int index);
void dump_out_mmx(void *x, unsigned int size, unsigned int index);
void dump_out_mmx_noeol(void *x, unsigned int size, unsigned int index);
void dump_out_mmx_msg(void *msg, void *buf, unsigned int size, unsigned int index);
void dump_out_mmx_msg_sepline(void *msg, void *buf, unsigned int size, unsigned int index);
void dump_stuff_shammx(void *x, unsigned int size, unsigned int index);
void dump_stuff_shammx_msg(void *msg, void *buf, unsigned int size, unsigned int index);
void dump_out_shammx(void *x, unsigned int size, unsigned int index);
void dump_out_shammx_msg(void *msg, void *buf, unsigned int size, unsigned int index);
void alter_endianity(void * x, unsigned int size);
#endif

#if defined (MD5_SSE_PARA)
// these functions help debug arrays of contigious MD5 prepared PARA buffers. Seen in sunmd5 at the current time.
void dump_stuff_mpara_mmx(void *x, unsigned int size, unsigned int index);
void dump_stuff_mpara_mmx_noeol(void *x, unsigned int size, unsigned int index);
void dump_stuff_mpara_mmx_msg(void *msg, void *buf, unsigned int size, unsigned int index);
void dump_stuff_mpara_mmx_msg_sepline(void *msg, void *buf, unsigned int size, unsigned int index);
// a 'getter' to help debugging.  Returns a flat buffer, vs printing it out.
void getbuf_stuff_mpara_mmx(unsigned char *oBuf, void *buf, unsigned int size, unsigned int index);
#endif


void alter_endianity_w(void *x, unsigned int count);
#if (ARCH_LITTLE_ENDIAN==0)
#define alter_endianity_to_BE(a,b)
#define alter_endianity_to_LE(a,b) do{alter_endianity_w(a,b);}while(0)
#else
#define alter_endianity_to_BE(a,b) do{alter_endianity_w(a,b);}while(0)
#define alter_endianity_to_LE(a,b)
#endif


#endif

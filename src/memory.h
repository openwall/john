/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 */

/*
 * Memory allocation routines.
 */

#ifndef _JOHN_MEMORY_H
#define _JOHN_MEMORY_H

#include <stdio.h>

#include "arch.h"

/*
 * Standard alignments for mem_alloc_tiny().
 */
#define MEM_ALIGN_NONE			1
#define MEM_ALIGN_WORD			ARCH_SIZE
#define MEM_ALIGN_CACHE			(ARCH_SIZE * 8)

/*
 * Block size used by mem_alloc_tiny().
 */
#define MEM_ALLOC_SIZE			0x10000

/*
 * Use mem_alloc() instead of allocating a new block in mem_alloc_tiny()
 * if more than MEM_ALLOC_MAX bytes would be lost.
 */
#define MEM_ALLOC_MAX			0x400

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
 * Returns immediately if the pointer is already NULL.
 */
extern void mem_free(void **ptr);

/*
 * Similar to the above function, except the memory can't be freed.
 * This one is used to reduce the overhead.
 */
extern void *mem_alloc_tiny(size_t size, size_t align);

/*
 * Uses mem_alloc_tiny() to allocate the memory, and copies src in there.
 */
extern void *mem_alloc_copy(size_t size, size_t align, void *src);

/*
 * Similar to the above function, but for ASCIIZ strings.
 */
extern char *str_alloc_copy(char *src);

#endif

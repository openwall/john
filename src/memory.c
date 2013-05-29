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

#include "arch.h"
#include "misc.h"
#include "memory.h"

unsigned int mem_saving_level = 0;

void *mem_alloc(size_t size)
{
	void *res;

	if (!size) return NULL;

	if (!(res = malloc(size))) {
		fprintf(stderr, "malloc: %s\n", strerror(ENOMEM));
		error();
	}

	return res;
}

void *mem_alloc_tiny(size_t size, size_t align)
{
	static char *buffer = NULL;
	static size_t bufree = 0;
	size_t mask;
	char *p;

#if ARCH_ALLOWS_UNALIGNED
	if (mem_saving_level > 2)
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

		buffer = mem_alloc(MEM_ALLOC_SIZE);
		bufree = MEM_ALLOC_SIZE;
	} while (1);

	p = mem_alloc(size + mask);
	p += mask;
	p -= (size_t)p & mask;
	return p;
}

void *mem_alloc_copy(void *src, size_t size, size_t align)
{
	return memcpy(mem_alloc_tiny(size, align), src, size);
}

char *str_alloc_copy(char *src)
{
	size_t size;

	if (!src) return "";
	if (!*src) return "";

	size = strlen(src) + 1;
	return (char *)memcpy(mem_alloc_tiny(size, MEM_ALIGN_NONE), src, size);
}

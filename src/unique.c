/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1998,1999,2002,2003,2005,2006,2011 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#define _POSIX_SOURCE /* for fdopen(3) */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "memory.h"

#define ENTRY_END_HASH			0xFFFFFFFF /* also hard-coded */
#define ENTRY_END_LIST			0xFFFFFFFE
#define ENTRY_DUPE			0xFFFFFFFD

static struct {
	unsigned int *hash;
	char *data;
} buffer;

static FILE *output;

#if ARCH_ALLOWS_UNALIGNED && !ARCH_INT_GT_32

#define get_int(ptr) \
	(*(ptr))

#define put_int(ptr, value) \
	*(ptr) = (value);

#else

static unsigned int get_int(unsigned int *ptr)
{
	unsigned char *bytes = (unsigned char *)ptr;

	return
		(unsigned int)bytes[0] |
		((unsigned int)bytes[1] << 8) |
		((unsigned int)bytes[2] << 16) |
		((unsigned int)bytes[3] << 24);
}

static void put_int(unsigned int *ptr, unsigned int value)
{
	unsigned char *bytes = (unsigned char *)ptr;

	bytes[0] = value;
	bytes[1] = value >> 8;
	bytes[2] = value >> 16;
	bytes[3] = value >> 24;
}

#endif

#define get_data(ptr) \
	get_int((unsigned int *)&buffer.data[ptr])

#define put_data(ptr, value) \
	put_int((unsigned int *)&buffer.data[ptr], value)

static unsigned int line_hash(char *line)
{
	unsigned int hash, extra;
	char *p;

	p = line + 2;
	hash = (unsigned char)line[0];
	if (!hash)
		goto out;
	extra = (unsigned char)line[1];
	if (!extra)
#if UNIQUE_HASH_SIZE >= 0x100
		goto out;
#else
		goto out_and;
#endif

	while (*p) {
		hash <<= 3; extra <<= 2;
		hash += (unsigned char)p[0];
		if (!p[1]) break;
		extra += (unsigned char)p[1];
		p += 2;
		if (hash & 0xe0000000) {
			hash ^= hash >> UNIQUE_HASH_LOG;
			extra ^= extra >> UNIQUE_HASH_LOG;
			hash &= UNIQUE_HASH_SIZE - 1;
		}
	}

	hash -= extra;
	hash ^= extra << (UNIQUE_HASH_LOG / 2);

	hash ^= hash >> UNIQUE_HASH_LOG;

#if UNIQUE_HASH_SIZE < 0x100
out_and:
#endif
	hash &= UNIQUE_HASH_SIZE - 1;
out:
	return hash;
}

static void init_hash(void)
{
#if 0
	int index;

	for (index = 0; index < UNIQUE_HASH_SIZE; index++)
		buffer.hash[index] = ENTRY_END_HASH;
#else
/* ENTRY_END_HASH is 0xFFFFFFFF */
	memset(buffer.hash, 0xff, UNIQUE_HASH_SIZE * sizeof(unsigned int));
#endif
}

static void read_buffer(void)
{
	char line[LINE_BUFFER_SIZE];
	unsigned int ptr, current, *last;

	init_hash();

	ptr = 0;
	while (fgetl(line, sizeof(line), stdin)) {
		last = &buffer.hash[line_hash(line)];
#if ARCH_LITTLE_ENDIAN && !ARCH_INT_GT_32
		current = *last;
#else
		current = get_int(last);
#endif
		while (current != ENTRY_END_HASH) {
			if (!strcmp(line, &buffer.data[current + 4])) break;
			last = (unsigned int *)&buffer.data[current];
			current = get_int(last);
		}
		if (current != ENTRY_END_HASH) continue;

		put_int(last, ptr);

		put_data(ptr, ENTRY_END_HASH);
		ptr += 4;

		strcpy(&buffer.data[ptr], line);
		ptr += strlen(line) + 1;

		if (ptr > UNIQUE_BUFFER_SIZE - sizeof(line) - 8) break;
	}

	if (ferror(stdin)) pexit("fgets");

	put_data(ptr, ENTRY_END_LIST);
}

static void write_buffer(void)
{
	unsigned int ptr, hash;

	ptr = 0;
	while ((hash = get_data(ptr)) != ENTRY_END_LIST) {
		unsigned int length, size;
		ptr += 4;
		length = strlen(&buffer.data[ptr]);
		size = length + 1;
		if (hash != ENTRY_DUPE) {
			buffer.data[ptr + length] = '\n';
			if (fwrite(&buffer.data[ptr], size, 1, output) != 1)
				pexit("fwrite");
		}
		ptr += size;
	}
}

static void clean_buffer(void)
{
	char line[LINE_BUFFER_SIZE];
	unsigned int current, *last;

	if (fseek(output, 0, SEEK_SET) < 0) pexit("fseek");

	while (fgetl(line, sizeof(line), output)) {
		last = &buffer.hash[line_hash(line)];
#if ARCH_LITTLE_ENDIAN && !ARCH_INT_GT_32
		current = *last;
#else
		current = get_int(last);
#endif
		while (current != ENTRY_END_HASH && current != ENTRY_DUPE) {
			if (!strcmp(line, &buffer.data[current + 4])) {
				put_int(last, get_data(current));
				put_data(current, ENTRY_DUPE);
				break;
			}
			last = (unsigned int *)&buffer.data[current];
			current = get_int(last);
		}
	}

	if (ferror(output)) pexit("fgets");

/* Workaround a Solaris stdio bug */
	if (fseek(output, 0, SEEK_END) < 0) pexit("fseek");
}

static void unique_init(char *name)
{
	int fd;

	buffer.hash = mem_alloc(UNIQUE_HASH_SIZE * sizeof(unsigned int));
	buffer.data = mem_alloc(UNIQUE_BUFFER_SIZE);

	if ((fd = open(name, O_RDWR | O_CREAT | O_EXCL, 0600)) < 0)
		pexit("open: %s", name);
	if (!(output = fdopen(fd, "w+"))) pexit("fdopen");
}

static void unique_run(void)
{
	read_buffer();
	write_buffer();

	while (!feof(stdin)) {
		read_buffer();
		clean_buffer();
		write_buffer();
	}
}

static void unique_done(void)
{
	if (fclose(output)) pexit("fclose");
}

int unique(int argc, char **argv)
{
	if (argc != 2) {
		puts("Usage: unique OUTPUT-FILE");

		if (argc <= 1)
			return 0;
		else
			error();
	}

	unique_init(argv[1]);
	unique_run();
	unique_done();

	return 0;
}

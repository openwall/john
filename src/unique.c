/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99 by Solar Designer
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "memory.h"

#define ENTRY_END_HASH			0xFFFFFFFF
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
		(unsigned int)bytes[0] +
		((unsigned int)bytes[1] << 8) +
		((unsigned int)bytes[2] << 16) +
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
	unsigned int hash = 0;

	while (*line) {
		hash <<= 2;
		hash ^= *line++;
		hash += hash >> UNIQUE_HASH_LOG;
	}

	hash &= UNIQUE_HASH_SIZE - 1;

	return hash;
}

static void init_hash(void)
{
	int index;

	for (index = 0; index < UNIQUE_HASH_SIZE; index++)
		buffer.hash[index] = ENTRY_END_HASH;
}

static void read_buffer(void)
{
	char line[LINE_BUFFER_SIZE];
	unsigned int ptr, current, *last;

	init_hash();

	ptr = 0;
	while (fgetl(line, sizeof(line), stdin)) {
		last = &buffer.hash[line_hash(line)];
#if ARCH_LITTLE_ENDIAN
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
		ptr += 4;
		if (hash != ENTRY_DUPE) {
			fprintf(output, "%s\n", &buffer.data[ptr]);
			if (ferror(output)) pexit("fprintf");
		}
		ptr += strlen(&buffer.data[ptr]) + 1;
	}
}

static void clean_buffer(void)
{
	char line[LINE_BUFFER_SIZE];
	unsigned int current, *last;

	if (fseek(output, 0, SEEK_SET) < 0) pexit("fseek");

	while (fgetl(line, sizeof(line), output)) {
		last = &buffer.hash[line_hash(line)];
		current = *last;
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
		printf("Usage: %s OUTPUT-FILE\n",
			argv[0] ? argv[0] : "unique");

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

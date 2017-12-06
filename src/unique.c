/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1998,1999,2002,2003,2005,2006,2011 by Solar Designer
 * Copyright (c) 2011 by Jim Fougeron
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * -v  (some debugging output
 * -inp=fname vs using stdin
 * -ex_file=FNAME       also unique's against this external file
 * -ex_file_only=FNAME  uniq against extern file, and assumes current file is
 *                      already unique, so does not unique it.
 * -cut=len  Trims each line to len, prior to unique. Also, any -ex_file=
 *           file has its lines trimmed (to properly compare).
 * -cut=LM   Trim each line to 7 bytes, and grab the next (up to) 7 bytes
 *           and upcase each.  Warning, if using -ex_file= make sure these
 *           files are 'proper' LM format (7 char and upcase).  No auto
 *           trimming/upcasing is done.
 * -mem=num. A number that overrides the UNIQUE_HASH_LOG value from within
 *           params.h.  The default is 24 or 25.  valid range from 13 to 25.
 *           25 will use a 2GB memory buffer, and 33 entry million hash table
 *           Each number doubles size.
 */

#if AC_BUILT
#include "autoconfig.h"
#else
#define _POSIX_SOURCE /* for fdopen(3) */
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#if !AC_BUILT || HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <string.h>
#ifdef _MSC_VER
#include <io.h>
#pragma warning ( disable : 4996 )
#define fdopen _fdopen
#endif

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "memory.h"
#include "jumbo.h"
#include "memdbg.h"

#define ENTRY_END_HASH			0xFFFFFFFF /* also hard-coded */
#define ENTRY_END_LIST			0xFFFFFFFE
#define ENTRY_DUPE			0xFFFFFFFD

static struct {
	unsigned int *hash;
	char *data;
} buffer;

static FILE *fpInput;
static FILE *output;
static FILE *use_to_unique_but_not_add;
static int do_not_unique_against_self=0;

uint64_t totLines=0, written_lines=0;
int verbose=0, cut_len=0, LM=0;
unsigned int vUNIQUE_HASH_LOG=UNIQUE_HASH_LOG, vUNIQUE_HASH_SIZE=UNIQUE_HASH_SIZE, vUNIQUE_BUFFER_SIZE=UNIQUE_BUFFER_SIZE;
unsigned int vUNIQUE_HASH_MASK = UNIQUE_HASH_SIZE - 1;
unsigned int vUNIQUE_HASH_LOG_HALF = UNIQUE_HASH_LOG / 2;

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
		goto out;

	while (*p) {
		hash <<= 3; extra <<= 2;
		hash += (unsigned char)p[0];
		if (!p[1]) break;
		extra += (unsigned char)p[1];
		p += 2;
		if (hash & 0xe0000000) {
			hash ^= hash >> vUNIQUE_HASH_LOG;
			extra ^= extra >> vUNIQUE_HASH_LOG;
			hash &= vUNIQUE_HASH_MASK;
		}
	}

	hash -= extra;
	hash ^= extra << vUNIQUE_HASH_LOG_HALF;

	hash ^= hash >> vUNIQUE_HASH_LOG;

	hash &= vUNIQUE_HASH_MASK;
out:
	return hash;
}

static void init_hash(void)
{
#if 0
	int index;

	for (index = 0; index < vUNIQUE_HASH_SIZE; index++)
		buffer.hash[index] = ENTRY_END_HASH;
#else
/* ENTRY_END_HASH is 0xFFFFFFFF */
	memset(buffer.hash, 0xff, vUNIQUE_HASH_SIZE * sizeof(unsigned int));
#endif
}

static void upcase(char *cp) {
	while (*cp) {
		if (*cp >= 'a' && *cp <= 'z')
			*cp -= 0x20;
		++cp;
	}
}

static void read_buffer(void)
{
	char line[LINE_BUFFER_SIZE];
	unsigned int ptr, current, *last;

	init_hash();

	ptr = 0;
	while (fgetl(line, sizeof(line), fpInput)) {
		char LM_Buf[8];
		if (LM) {
			if (strlen(line) > 7) {
				strncpy(LM_Buf, &line[7], 7);
				LM_Buf[7] = 0;
				upcase(LM_Buf);
				++totLines;
			}
			else
				*LM_Buf = 0;
			line[7] = 0;
			upcase(line);
		} else if (cut_len) line[cut_len] = 0;
		++totLines;
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
		if (current != ENTRY_END_HASH) {
			if (LM && *LM_Buf)
				goto DoExtraLM;
			continue;
		}

		put_int(last, ptr);

		put_data(ptr, ENTRY_END_HASH);
		ptr += 4;

		strcpy(&buffer.data[ptr], line);
		ptr += strlen(line) + 1;

		if (ptr > vUNIQUE_BUFFER_SIZE - sizeof(line) - 8) break;

DoExtraLM:;
		if (LM && *LM_Buf) {
			last = &buffer.hash[line_hash(LM_Buf)];
#if ARCH_LITTLE_ENDIAN && !ARCH_INT_GT_32
			current = *last;
#else
			current = get_int(last);
#endif
			while (current != ENTRY_END_HASH) {
				if (!strcmp(LM_Buf, &buffer.data[current + 4])) break;
				last = (unsigned int *)&buffer.data[current];
				current = get_int(last);
			}
			if (current != ENTRY_END_HASH) continue;

			put_int(last, ptr);

			put_data(ptr, ENTRY_END_HASH);
			ptr += 4;

			strcpy(&buffer.data[ptr], LM_Buf);
			ptr += strlen(LM_Buf) + 1;

			if (ptr > vUNIQUE_BUFFER_SIZE - sizeof(line) - 8) break;
		}
	}

	if (ferror(fpInput)) pexit("fgets");

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
			++written_lines;
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

	if (use_to_unique_but_not_add) {
		if (fseek(use_to_unique_but_not_add, 0, SEEK_SET) < 0) pexit("fseek");
		while (fgetl(line, sizeof(line), use_to_unique_but_not_add)) {
			if (cut_len) line[cut_len] = 0;
			last = &buffer.hash[line_hash(line)];
#if ARCH_LITTLE_ENDIAN && !ARCH_INT_GT_32
			current = *last;
#else
			current = get_int(last);
#endif
			while (current != ENTRY_END_HASH) {
				if (current != ENTRY_DUPE && !strcmp(line, &buffer.data[current + 4])) {
					put_int(last, get_data(current));
					put_data(current, ENTRY_DUPE);
					break;
				}
				last = (unsigned int *)&buffer.data[current];
				current = get_int(last);
			}
		}
	}

	if (do_not_unique_against_self)
	  return;

	if (fseek(output, 0, SEEK_SET) < 0) pexit("fseek");

	while (fgetl(line, sizeof(line), output)) {
		if (cut_len) line[cut_len] = 0;
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

	buffer.hash = mem_alloc(vUNIQUE_HASH_SIZE * sizeof(unsigned int));
	buffer.data = mem_alloc(vUNIQUE_BUFFER_SIZE);

#if defined (_MSC_VER) || defined(__MINGW32__)
	fd = open(name, O_RDWR | O_CREAT | O_EXCL | O_BINARY, 0600);
#else
	fd = open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
#endif
	if (fd < 0)
		pexit("open: %s", name);
	if (!(output = fdopen(fd, "wb+"))) pexit("fdopen");
}

static void unique_run(void)
{
	read_buffer();
	if (use_to_unique_but_not_add)
	  clean_buffer();
	write_buffer();

	while (!feof(fpInput)) {
		read_buffer();
		clean_buffer();
		write_buffer();

		if (verbose)
			printf("\rTotal lines read %"PRIu64" Unique lines written %"PRIu64"\r", totLines, written_lines);
	}
}

static void unique_done(void)
{
	if (fclose(output)) pexit("fclose");
}

int unique(int argc, char **argv)
{
	while (argc > 2 && (!strcmp(argv[1], "-v") || !strncmp(argv[1], "-inp=", 5) || !strncmp(argv[1], "-cut=", 5) || !strncmp(argv[1], "-mem=", 5))) {
		int i;
		if (!strcmp(argv[1], "-v"))
		{
			verbose = 1;
			--argc;
			for (i = 1; i < argc; ++i)
				argv[i] = argv[i+1];
		}
		else if (!strncmp(argv[1], "-inp=", 5))
		{
			fpInput = fopen(&argv[1][5], "rb");
			if (!fpInput)
				exit(fprintf(stderr, "Error, could not open input file %s\n", &argv[1][5]));
			--argc;
			for (i = 1; i < argc; ++i)
				argv[i] = argv[i+1];
		}
		else if (!strncmp(argv[1], "-cut=", 5))
		{
			if (!strcmp(argv[1], "-cut=LM")) {
				cut_len = 7;
				LM = 1;
			}
			else
				sscanf(argv[1], "-cut=%d", &cut_len);
			if (cut_len < 0 || cut_len >= LINE_BUFFER_SIZE)
				exit(fprintf(stderr, "Error, invalid length in the -cut= param\n"));
			--argc;
			for (i = 1; i < argc; ++i)
				argv[i] = argv[i+1];
		}
		else if (!strncmp(argv[1], "-mem=", 5))
		{
			int len;
			sscanf(argv[1], "-mem=%d", &len);
			if (len > 25) {
				fprintf(stderr, "Warning, max memory usages reduced to 25\n");
				len = 25;
			}
			if (len < 13) {
				fprintf(stderr, "Warning the min memory usage allowed is 13\n");
				len = 13;
			}
			--argc;
			for (i = 1; i < argc; ++i)
				argv[i] = argv[i+1];

// Original from params.h in john-1.7.7
//#define UNIQUE_HASH_LOG			20
//#define UNIQUE_HASH_SIZE		(1 << UNIQUE_HASH_LOG)
//#define UNIQUE_BUFFER_SIZE		0x4000000

			vUNIQUE_HASH_LOG = len;
			vUNIQUE_HASH_SIZE = (1 << vUNIQUE_HASH_LOG);
			vUNIQUE_BUFFER_SIZE = 64 * vUNIQUE_HASH_SIZE;
			vUNIQUE_HASH_MASK = vUNIQUE_HASH_SIZE - 1;
			vUNIQUE_HASH_LOG_HALF = vUNIQUE_HASH_LOG / 2;
		}
	}
	if (argc == 3 && !strncmp(argv[2], "-ex_file=", 9)) {
		use_to_unique_but_not_add = fopen(&argv[2][9], "rb");
		argc = 2;
		if (use_to_unique_but_not_add)
		  printf("Not outputting any lines found in file %s\n", &argv[2][9]);
	}
	if (argc == 3 && !strncmp(argv[2], "-ex_file_only=", 14)) {
		use_to_unique_but_not_add = fopen(&argv[2][14], "rb");
		argc = 2;
		if (use_to_unique_but_not_add)
		  printf("Expecting file to be unique, and not outputting any lines found in file %s\n", &argv[2][14]);
		else
		  exit(printf("Error, in this mode, we MUST have a file to test against\n"));
		do_not_unique_against_self = 1;
	}
	if (argc != 2) {
#if defined (__MINGW32__)
	    puts("");
#endif
		printf("Usage: unique [-v] [-inp=fname] [-cut=len] [-mem=num] OUTPUT-FILE [-ex_file=FNAME2] [-ex_file_only=FNAME2]\n\n"
			 "       reads from stdin 'normally', but can be overridden by optional -inp=\n"
			 "       If -ex_file=XX is used, then data from file XX is also used to\n"
			 "       unique the data, but nothing is ever written to XX. Thus, any data in\n"
			 "       XX, will NOT output into OUTPUT-FILE (for making iterative dictionaries)\n"
			 "       -ex_file_only=XX assumes the file is 'unique', and only checks against XX\n"
			 "       -cut=len  Will trim each input lines to 'len' bytes long, prior to running\n"
			 "       the unique algorithm. The 'trimming' is done on any -ex_file[_only] file\n"
			 "       -mem=num.  A number that overrides the UNIQUE_HASH_LOG value from within\n"
			 "       params.h.  The default is %u.  Valid range is from 13 to 25 (memory usage\n"
			 "       doubles each number).  If you go TOO large, unique will swap and thrash and\n"
			 "       work VERY slow\n"
			 "\n"
			 "       -v is for 'verbose' mode, outputs line counts during the run\n",
			UNIQUE_HASH_LOG);

		if (argc <= 1)
			return 0;
		else
			error();
	}

	if (!fpInput)
		fpInput = stdin;
	unique_init(argv[1]);
	unique_run();
	unique_done();
    printf("Total lines read %"PRIu64" Unique lines written %"PRIu64"\n", totLines, written_lines);

	return 0;
}

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1998,1999,2002,2003,2005,2006,2011,2020 by Solar Designer
 * Copyright (c) 2011 by Jim Fougeron
 * Copyright (c) 2016-2019 by magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#if AC_BUILT
#include "autoconfig.h"
#else
#define _POSIX_SOURCE /* for fdopen(3) */
#define _XPG6
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

#ifdef _MSC_VER
#include <io.h>
#pragma warning ( disable : 4996 )
#define fdopen _fdopen
#endif

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "memory.h"
#include "common.h"
#include "jumbo.h"

typedef size_t uq_idx;
typedef size_t uq_hash;

#if __SIZEOF_SIZE_T__ == 4
#define ENTRY_END_HASH			0xFFFFFFFF /* also hard-coded */
#define ENTRY_END_LIST			0xFFFFFFFE
#define ENTRY_DUPE			0xFFFFFFFD
#define HASH_MAX			0xE0000000
#else
#define ENTRY_END_HASH			0xFFFFFFFFFFFFFFFFull
#define ENTRY_END_LIST			0xFFFFFFFFFFFFFFFEull
#define ENTRY_DUPE			0xFFFFFFFFFFFFFFFDull
#define HASH_MAX			0xF800000000000000ull
#endif

static struct {
	uq_idx *hash;
	char *data;
} buffer;

static FILE *input;
static FILE *output;
static FILE *ex_file;

static int ex_file_only;
static int verbose, cut_len, lm_split, slow, mlc;

static size_t tot_lines, written_lines;
static size_t unique_hash_size = UNIQUE_HASH_SIZE;
static size_t unique_buffer_size = UNIQUE_BUFFER_SIZE;
static size_t unique_hash_mask = UNIQUE_HASH_SIZE - 1;
static size_t unique_hash_log, unique_hash_log_half;

#if ARCH_ALLOWS_UNALIGNED

#define get_idx(ptr)	  \
	(*(ptr))

#define put_idx(ptr, value)	  \
	*(ptr) = (value);

#else

static uq_idx get_idx(void *ptr)
{
	uint8_t *bytes = ptr;
	uq_idx idx;

	idx = (uq_idx)bytes[0] | ((uq_idx)bytes[1] << 8) |
		((uq_idx)bytes[2] << 16) | ((uq_idx)bytes[3] << 24);
#if __SIZEOF_SIZE_T__ >= 8
	idx |= (uq_idx)bytes[4] << 32 | ((uq_idx)bytes[5] << 40) |
		((uq_idx)bytes[6] << 48) | ((uq_idx)bytes[7] << 56);
#endif
	return idx;
}

static void put_idx(void *ptr, uq_idx value)
{
	uint8_t *bytes = ptr;

	bytes[0] = value;
	bytes[1] = value >> 8;
	bytes[2] = value >> 16;
	bytes[3] = value >> 24;
#if __SIZEOF_SIZE_T__ >= 8
	bytes[4] = value >> 32;
	bytes[5] = value >> 40;
	bytes[6] = value >> 48;
	bytes[7] = value >> 56;
#endif
}

#endif

#define get_data(ptr)	  \
	get_idx((uq_idx*)&buffer.data[ptr])

#define put_data(ptr, value)	  \
	put_idx((uq_idx*)&buffer.data[ptr], value)

static uq_hash line_hash(char *line)
{
	uq_hash hash, extra;
	char *p;
	char *e = &line[mlc ? mlc : LINE_BUFFER_SIZE];

	p = line + 2;
	hash = (uint8_t)line[0];
	if (!hash)
		goto out;
	extra = (uint8_t)line[1];
	if (!extra)
		goto out;

	while (*p && p < e) {
		hash <<= 5;
		hash += (uint8_t)p[0];
		if (!p[1] || &p[1] >= e)
			break;
		extra *= hash | 1812433253;
		extra += (uint8_t)p[1];
		p += 2;
		if (hash & HASH_MAX) {
			hash ^= hash >> unique_hash_log;
			extra ^= extra >> unique_hash_log;
			hash &= unique_hash_mask;
		}
	}

	hash -= extra;
	hash ^= extra << unique_hash_log_half;

	hash ^= hash >> unique_hash_log;

	hash &= unique_hash_mask;
out:
	return hash;
}

static void init_hash(void)
{
	/* ENTRY_END_HASH is 0xFFFFFFFF (or 0xFFFFFFFFFFFFFFFF) */
	memset(buffer.hash, 0xff, unique_hash_size * sizeof(*buffer.hash));
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
	uq_idx current;
	uq_idx ptr, *last;

	init_hash();

	ptr = 0;
	while (fgetl(line, sizeof(line), input)) {
		char lm_buf[8];

		if (lm_split) {
			if (strlen(line) > 7) {
				strncpy(lm_buf, &line[7], 7);
				lm_buf[7] = 0;
				upcase(lm_buf);
				++tot_lines;
			}
			else
				*lm_buf = 0;
			line[7] = 0;
			upcase(line);
		} else if (cut_len)
			line[cut_len] = 0;
		++tot_lines;

		last = &buffer.hash[line_hash(line)];
		current = get_idx(last);
		while (current != ENTRY_END_HASH) {
			if (mlc ? !strncmp(line, &buffer.data[current + sizeof(uq_idx)], mlc)
			    : !strcmp(line, &buffer.data[current + sizeof(uq_idx)]))
				break;
			last = (uq_idx*)&buffer.data[current];
			current = get_idx(last);
		}
		if (current != ENTRY_END_HASH) {
			if (lm_split && *lm_buf)
				goto DoExtraLM;
			continue;
		}

		put_idx(last, ptr);

		put_data(ptr, ENTRY_END_HASH);
		ptr += sizeof(uq_idx);

		strcpy(&buffer.data[ptr], line);
		ptr += strlen(line) + 1;

		if (ptr > unique_buffer_size - sizeof(line) -
		    2 * sizeof(uq_idx))
			break;

	DoExtraLM:;
		if (lm_split && *lm_buf) {
			last = &buffer.hash[line_hash(lm_buf)];
			current = get_idx(last);
			while (current != ENTRY_END_HASH) {
				if (mlc ? !strncmp(lm_buf, &buffer.data[current + sizeof(uq_idx)], mlc)
				    : !strcmp(lm_buf, &buffer.data[current + sizeof(uq_idx)]))
					break;
				last = (uq_idx*)&buffer.data[current];
				current = get_idx(last);
			}
			if (current != ENTRY_END_HASH)
				continue;

			put_idx(last, ptr);

			put_data(ptr, ENTRY_END_HASH);
			ptr += sizeof(uq_idx);

			strcpy(&buffer.data[ptr], lm_buf);
			ptr += strlen(lm_buf) + 1;

			if (ptr > unique_buffer_size -
			    sizeof(line) - 2 * sizeof(uq_idx))
				break;
		}
	}

	if (ferror(input))
		pexit("fgets");

	put_data(ptr, ENTRY_END_LIST);
}

static void write_buffer(void)
{
	uq_idx ptr, hash;

	ptr = 0;
	while ((hash = get_data(ptr)) != ENTRY_END_LIST) {
		uq_idx length, size;

		ptr += sizeof(uq_idx);
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
	uq_idx current, *last;

	if (ex_file) {
		if (fseek(ex_file, 0, SEEK_SET) < 0)
			pexit("fseek");
		while (fgetl(line, sizeof(line), ex_file)) {
			if (cut_len)
				line[cut_len] = 0;
			last = &buffer.hash[line_hash(line)];
			current = get_idx(last);
			while (current != ENTRY_END_HASH) {
				if (current != ENTRY_DUPE &&
				    (mlc ? !strncmp(line, &buffer.data[current + sizeof(uq_idx)], mlc)
				     : !strcmp(line, &buffer.data[current + sizeof(uq_idx)]))) {
					put_idx(last, get_data(current));
					put_data(current, ENTRY_DUPE);
					break;
				}
				last = (uq_idx*)&buffer.data[current];
				current = get_idx(last);
			}
		}
		if (ex_file_only)
			return;
	}

	if (fseek(output, 0, SEEK_SET) < 0)
		pexit("fseek");

	while (fgetl(line, sizeof(line), output)) {
		last = &buffer.hash[line_hash(line)];
		current = get_idx(last);
		while (current != ENTRY_END_HASH && current != ENTRY_DUPE) {
			if (mlc ? !strncmp(line, &buffer.data[current + sizeof(uq_idx)], mlc)
			    : !strcmp(line, &buffer.data[current + sizeof(uq_idx)])) {
				put_idx(last, get_data(current));
				put_data(current, ENTRY_DUPE);
				break;
			}
			last = (uq_idx*)&buffer.data[current];
			current = get_idx(last);
		}
	}

	if (ferror(output))
		pexit("fgets");

/* Work around a Solaris stdio bug */
	if (fseek(output, 0, SEEK_END) < 0)
		pexit("fseek");
}

#undef log2
#define log2 jtr_log2
static size_t log2(size_t val)
{
	size_t res = 0;

	while (val >>= 1)
		res++;

	return res;
}

static void unique_init(char *name)
{
	int fd;

	if (verbose)
		fprintf(stderr,
	        "Hash size %d (%s/%sB), input buffer %sB. Total alloc. %sB\n",
	        (int)log2(unique_hash_size), human_prefix(unique_hash_size),
	        human_prefix(unique_hash_size * sizeof(*buffer.hash)),
	        human_prefix(unique_buffer_size),
	        human_prefix(unique_hash_size * sizeof(*buffer.hash) +
	                     unique_buffer_size));

	buffer.hash = mem_alloc(unique_hash_size * sizeof(*buffer.hash));
	buffer.data = mem_alloc(unique_buffer_size);

#if defined (_MSC_VER) || defined(__MINGW32__)
	fd = open(name, O_RDWR | O_CREAT | O_EXCL | O_BINARY, 0600);
#else
	fd = open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
#endif
	if (fd < 0)
		pexit("open: %s", name);
	if (!(output = fdopen(fd, "wb+")))
		pexit("fdopen");
}

static void unique_run(void)
{
	read_buffer();
	if (ex_file)
		clean_buffer();
	write_buffer();

	while (!feof(input)) {
		++slow;
		if (verbose)
			fprintf(stderr,
			        "Slow pass %d; Total lines read: "Zu", unique lines written: "Zu" (%u%%)\n",
			        slow, tot_lines, written_lines,
			        tot_lines ? (uint32_t)(100 * written_lines / tot_lines) : 0);
		read_buffer();
		clean_buffer();
		write_buffer();
	}
}

static void unique_done(void)
{
	if (fclose(output))
		pexit("fclose");
}

static void pop_arg(int arg, int *argc, char **argv)
{
	int i;

	--(*argc);
	for (i = arg; i < *argc; i++)
		argv[i] = argv[i + 1];
}

int unique(int argc, char **argv)
{
	int i = 1;
	size_t buf_size = 0;

	while (argc - i) {
		if (!strcmp(argv[i], "-v")) {
			verbose++;
			pop_arg(i, &argc, argv);
			continue;
		}
		if (!strncmp(argv[i], "-inp=", 5) ||
		    !strncmp(argv[i], "-i=", 3)) {
			char *fname = strchr(argv[i], '=');

			input = fopen(++fname, "rb");
			if (!input)
				error_msg("Error, could not open input file %s\n", fname);
			pop_arg(i, &argc, argv);
			continue;
		}
		if (!strncmp(argv[i], "-cut=", 5)) {
			if (!strcmp(argv[i], "-cut=LM")) {
				cut_len = 7;
				lm_split = 1;
			} else {
				char nul = 0;
				if (sscanf(argv[i], "-cut=%d%c", &cut_len, &nul) < 1 || nul)
					cut_len = -1;
			}
			if (cut_len < 0 || cut_len >= LINE_BUFFER_SIZE)
				error_msg("Error, invalid length in the -cut= param\n");
			pop_arg(i, &argc, argv);
			continue;
		}
		if (!strncmp(argv[i], "-mlc=", 5)) {
			char nul = 0;
			if (sscanf(argv[i], "-mlc=%d%c", &mlc, &nul) < 1 || nul ||
			    mlc < 2 || mlc >= LINE_BUFFER_SIZE)
				error_msg("Error, -mlc=length must be 2..%d\n", LINE_BUFFER_SIZE);
			fprintf(stderr, "Will only consider %d first characters of a line for uniqueness\n", mlc);
			pop_arg(i, &argc, argv);
			continue;
		}
		if (!strncmp(argv[i], "-mem=", 5)) {
			char *new_arg;
			uint32_t log;
			size_t buf;
			char nul = 0;
			if (sscanf(argv[i], "-mem=%d%c", &log, &nul) < 1 || nul)
				log = 0;
			buf = ((1ULL << log) * UNIQUE_AVG_LEN) >> 30ULL;
			fprintf(stderr,
"Warning: The -mem=%u option is deprecated, use -hash-size=%u (log2 of hash\n"
"         table size) and/or -buf=%u (total buffer size, in GB) instead\n",
			        log, log, (uint32_t)MAX(1, buf));
			new_arg = mem_alloc_tiny(strlen(argv[i] + 8),
			                         MEM_ALIGN_NONE);
			strcpy(new_arg, "-hash-size");
			strcat(new_arg, &argv[i][4]);
			argv[i] = new_arg;
		}
		if (!strncmp(argv[i], "-hash-size=", 11)) {
			unsigned int log;
			char nul = 0;
			if (sscanf(argv[i], "-hash-size=%u%c", &log, &nul) < 1 || nul)
				log = 0;
			if (sizeof(uq_idx) < 8 && log > 25)
				error_msg("Error: This build of unique can't use a -hash-size larger than 25\n");

			unique_hash_log = log;
			pop_arg(i, &argc, argv);
			continue;
		}
		if (!strncmp(argv[i], "-buf=", 5)) {
			unsigned int p;
			char nul = 0;
			if (sscanf(argv[i], "-buf=%u%c", &p, &nul) < 1 || nul)
				p = 0;
#if __SIZEOF_SIZE_T__ < 8
			if (p > 3)
				error_msg("Error: Can't use a -buf of more than 3 GB (this is a 32-bit build)\n");
#endif
			if (!(buf_size = (size_t)p << 30))
				buf_size = 1U << 28;

			if (!unique_hash_log)
				unique_hash_log =
					log2(buf_size / UNIQUE_AVG_LEN);
			pop_arg(i, &argc, argv);
			continue;
		}
		if (!ex_file && !strncmp(argv[i], "-ex_file=", 9)) {
			ex_file = fopen(&argv[i][9], "rb");
			if (ex_file)
				fprintf(stderr, "Also suppressing any lines found in '%s'\n", &argv[i][9]);
			else
				pexit("fopen: %s", &argv[i][9]);
			pop_arg(i, &argc, argv);
			continue;
		}
		if (!ex_file && !strncmp(argv[i], "-ex_file_only=", 14)) {
			ex_file = fopen(&argv[i][14], "rb");
			if (ex_file)
				fprintf(stderr, "Expecting input to be unique, but suppressing any lines found in '%s'\n", &argv[i][14]);
			else
				pexit("fopen: %s", &argv[i][14]);
			ex_file_only = 1;
			pop_arg(i, &argc, argv);
			continue;
		}
		i++;
	}

	if (unique_hash_log <= 0)
		unique_hash_log = UNIQUE_HASH_LOG;
	if (unique_hash_log >= 40)
		unique_hash_log = 40;
	unique_hash_size = (size_t)1 << unique_hash_log;
	if (unique_hash_log < 22 || unique_hash_log >= 40)
		error_msg("Error: Requested hash size is unreasonably %s (%d, %s/%sB)\n",
		    unique_hash_log < 30 ? "small" : "large",
		    (int)unique_hash_log, human_prefix(unique_hash_size),
		    human_prefix(unique_hash_size * sizeof(*buffer.hash)));
	unique_hash_log_half = unique_hash_log / 2;
	unique_hash_mask = unique_hash_size - 1;
	if (buf_size) {
		unique_buffer_size = buf_size - unique_hash_size * sizeof(*buffer.hash);
		if (unique_buffer_size > buf_size)
			error_msg("Error: Requested hash size exceeds requested total memory allocation\n");
	} else {
		unique_buffer_size = UNIQUE_AVG_LEN * unique_hash_size;
	}
	if (unique_buffer_size < (1U << 27))
		error_msg("Error: Input buffer size is unreasonably small (%sB)\n", human_prefix(unique_buffer_size));

	if (argc != 2) {
		fprintf(stderr,
"Usage: unique [option[s]] OUTPUT-FILE\n\n"
"Options:\n"
"-v                 verbose mode, output stats even without slow passes\n"
"-inp=FILE          read from FILE instead of stdin\n"
"-cut=N             truncate input lines to max. N bytes (default 1023)\n"
"-cut=LM            for LM: Split lines longer than 7 in two, and uppercase\n"
"-hash-size=N       override the hash size (given in log2). The default is\n"
"                   %u for %sB, memory use doubles for each increment\n"
"-buf=N             Total allowed buffer size, in GB. If -hash-size isn't\n"
"                   given as well, a sensible one will be used\n"
"-mlc=LEN           Only consider LEN first characters of each line\n"
"-ex_file=FILE      the data from FILE is also used to unique the output, but\n"
"                   nothing is ever written to FILE\n"
"-ex_file_only=FILE assumes the input is already unique, and only checks\n"
"                   against FILE (again the latter is not written to)\n"
"\n"
"NOTE that if you try to use more memory than actually available physical\n"
"memory, performance will just drop.\n\n",
		        UNIQUE_HASH_LOG,
			human_prefix(UNIQUE_HASH_SIZE * sizeof(buffer.hash) +
			             UNIQUE_BUFFER_SIZE));

		if (argc <= 1)
			return 0;
		else
			error();
	}

	if (!input)
		input = stdin;

	unique_init(argv[1]);
	unique_run();
	unique_done();

	fprintf(stderr,
	        "Total lines read: "Zu", unique lines written: "Zu" (%u%%), ",
	        tot_lines, written_lines, tot_lines ?
	        (uint32_t)(100 * written_lines / tot_lines) : 0);
	if (slow)
		fprintf(stderr, "%d slow passes\n", slow);
	else
		fprintf(stderr, "no slow passes\n");

	return 0;
}

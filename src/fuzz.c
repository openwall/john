/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2015 by Kai Zhao
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include "os.h"

#include <sys/stat.h>

#if _MSC_VER || __MINGW32__ || __MINGW64__ || __CYGWIN__ || HAVE_WINDOWS_H
#include "win32_memmap.h"
#undef MEM_FREE
#if !defined(__CYGWIN__) && !defined(__MINGW64__)
#include "mmap-windows.c"
#endif /* __CYGWIN */
#endif /* _MSC_VER ... */

#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
#include <io.h> /* mingW _mkdir */
#endif

#if defined(HAVE_MMAP)
#include <sys/mman.h>
#endif

#include "jumbo.h"
#include "misc.h"	// error()
#include "common.h"
#include "config.h"
#include "john.h"
#include "options.h"
#include "params.h"
#include "signals.h"
#include "unicode.h"

#define is_alnum_ascii(c) \
	(('0' <= (c) && (c) <= '9') \
	 || ('a' <= (c) && (c) <= 'z') \
	 || ('A' <= (c) && (c) <= 'Z'))

#define is_alpha_ascii(c) \
	(('a' <= (c) && (c) <= 'z') \
	 || ('A' <= (c) && (c) <= 'Z'))

#define _STR_VALUE(arg)         #arg
#define STR_MACRO(n)            _STR_VALUE(n)

#define CHAR_FROM -128
#define CHAR_TO 127

// old value from params.h
#define FUZZ_LINE_BUFFER_SIZE 0x30000
static char fuzz_hash[FUZZ_LINE_BUFFER_SIZE];
static char status_file_path[PATH_BUFFER_SIZE + 1];

struct FuzzDic {
	struct FuzzDic *next;
	char *value;
};

static int fuzz_limit;
static struct FuzzDic *rfd;

static FILE *s_file; // Status file which is ./fuzz_status/'format->params.label'

extern int pristine_gecos;
extern int single_skip_login;

static char *file_pos, *file_end;

static char *get_line()
{
	char *new_line, *line_start;

	line_start = file_pos;
	while (file_pos < file_end && *file_pos != '\n')
		file_pos++;

	if (file_pos == file_end)
		return NULL;
	file_pos++;

	new_line = mem_alloc(file_pos - line_start);
	strncpy(new_line, line_start, file_pos - line_start);
	new_line[file_pos - line_start - 1] = 0;

	return new_line;
}

static void fuzz_init_dictionary()
{
	FILE *file;
	char *line;
	struct FuzzDic *last_fd, *pfd;
	int64_t file_len = 0;
#ifdef HAVE_MMAP
	char *mem_map;
#else
	char *file_start;
#endif

	if (!(file = jtr_fopen(options.fuzz_dic, "r")))
		pexit("fopen: %s", options.fuzz_dic);

	jtr_fseek64(file, 0, SEEK_END);
	if ((file_len = jtr_ftell64(file)) == -1)
		pexit(STR_MACRO(jtr_ftell64));
	jtr_fseek64(file, 0, SEEK_SET);
	if (file_len == 0) {
		if (john_main_process)
			fprintf(stderr, "Error, dictionary file is empty\n");
		error();
	}

#ifdef HAVE_MMAP
	mem_map = MAP_FAILED;
	if (file_len < ((1LL)<<32))
		mem_map = mmap(NULL, file_len, PROT_READ, MAP_SHARED,
			fileno(file), 0);
	if (mem_map == MAP_FAILED) {
		mem_map = NULL;
		fprintf(stderr, "fuzz: memory mapping failed (%s)\n",
		        strerror(errno));
		error();
	} else {
		file_pos = mem_map;
		file_end = mem_map + file_len;
	}
#else
	file_pos = file_start = mem_alloc(file_len);
	file_end = file_start + file_len;
	if (fread(file_pos, 1, (size_t)file_len, file) != file_len) {
		if (ferror(file))
			pexit("fread");
		fprintf(stderr, "fread: Unexpected EOF\n");
		error();
	}
#endif

	rfd = mem_alloc(sizeof(struct FuzzDic));
	rfd->next = NULL;
	last_fd = rfd;

	while ((line = get_line()) != NULL) {
		pfd = mem_alloc(sizeof(struct FuzzDic));
		pfd->next = NULL;
		pfd->value = line;
		last_fd->next = pfd;
		last_fd = pfd;
	}

#ifdef HAVE_MMAP
	if (mem_map)
		munmap(mem_map, file_len);
#else
	MEM_FREE(file_start);
#endif
	file_pos = file_end = NULL;

	if (ferror(file)) pexit("fgets");

	if (fclose(file)) pexit("fclose");
}

// Replace chars with '9$*#'
static char * replace_each_chars(char *ciphertext, int *is_replace_finish)
{
	static int replaced_chars_index = 0;
	static int cipher_index = 0;
	static char replaced_chars[5] = "\xFF" "9$*#";

	if (cipher_index >= strlen(ciphertext))
		cipher_index = 0;

	while (replaced_chars_index < sizeof(replaced_chars)) {
		if (ciphertext[cipher_index] != replaced_chars[replaced_chars_index]) {
			fuzz_hash[cipher_index] = replaced_chars[replaced_chars_index];
			replaced_chars_index++;
			return fuzz_hash;
		}
		replaced_chars_index++;
	}
	if (replaced_chars_index == sizeof(replaced_chars)) {
		replaced_chars_index = 0;
		cipher_index++;
	}
	if (cipher_index >= strlen(ciphertext)) {
		*is_replace_finish = 1;
		cipher_index = 0;
		replaced_chars_index = 0;
		return NULL;
	} else {
		while (replaced_chars_index < sizeof(replaced_chars)) {
			if (ciphertext[cipher_index] != replaced_chars[replaced_chars_index]) {
				fuzz_hash[cipher_index] = replaced_chars[replaced_chars_index];
				replaced_chars_index++;
				return fuzz_hash;
			}
			replaced_chars_index++;
		}
	}
	// It will never reach here
	return NULL;
}

// Swap two adjacent chars
// e.g
// ABCDE -> BACDE, ACBDE, ABDCE, ABCED
static char * swap_chars(char *origin_ctext, int *is_swap_finish)
{
	static int cipher_index = 1;

	while (cipher_index < strlen(fuzz_hash)) {
		if (origin_ctext[cipher_index - 1] != origin_ctext[cipher_index]) {
			fuzz_hash[cipher_index - 1] = origin_ctext[cipher_index];
			fuzz_hash[cipher_index] = origin_ctext[cipher_index - 1];
			cipher_index++;
			return fuzz_hash;
		}
		cipher_index++;
	}

	cipher_index = 1;
	*is_swap_finish = 1;
	return NULL;
}

// Append times of the last char
// times: 1, 2, 6, 42, 1806
static char * append_last_char(char *origin_ctext, int *is_append_finish)
{
	static int times = 1;
	static int i = 0;
	int origin_ctext_len = 0;
	int append_len = 0;

	origin_ctext_len = strlen(origin_ctext);

	if (origin_ctext_len == 0 || i == 5) {
		times = 1;
		i = 0;
		*is_append_finish = 1;
		return NULL;
	}

	if (origin_ctext_len + times < FUZZ_LINE_BUFFER_SIZE)
		append_len = times;
	else
		append_len = FUZZ_LINE_BUFFER_SIZE - origin_ctext_len - 1;

	memset(fuzz_hash + origin_ctext_len, origin_ctext[origin_ctext_len - 1], append_len);
	fuzz_hash[origin_ctext_len + append_len] = 0;

	i++;
	times *= times + 1;

	return fuzz_hash;
}

// Change hash cases, such as "abcdef" -> "Abcdef"
static char * change_case(char *origin_ctext, int *is_chgcase_finish)
{
	char c;
	char *pc;
	static int flag = 2;
	static int cipher_index = 0;

	if (cipher_index >= strlen(origin_ctext))
		cipher_index = 0;

	while (origin_ctext[cipher_index]) {
		c = origin_ctext[cipher_index];
		if ('a' <= c && 'z' >= c) {
			fuzz_hash[cipher_index] = c - 'a' + 'A';
			cipher_index++;
			return fuzz_hash;
		} else if ('A' <= c && 'Z' >= c) {
			fuzz_hash[cipher_index] = c - 'A' + 'a';
			cipher_index++;
			return fuzz_hash;
		}
		cipher_index++;
	}

	if (flag == 2) {
		// Change all to upper cases
		pc = fuzz_hash;
		while (*pc) {
			if ('a' <= *pc && 'z' >= *pc)
				*pc = *pc - 'a' + 'A';
			pc++;
		}

		flag--;
		return fuzz_hash;
	} else if (flag == 1) {
		// Change all to lower cases
		pc = fuzz_hash;
		while (*pc) {
			if ('A' <= *pc && 'Z' >= *pc)
				*pc = *pc - 'A' + 'a';
			pc++;
		}

		flag--;
		return fuzz_hash;
	}

	flag = 2;
	cipher_index = 0;
	*is_chgcase_finish = 1;
	return NULL;
}

// Insert str before pos in origin_ctext, and copy the result
// to out
static void insert_str(char *origin_ctext, int pos, char *str, char *out)
{
	const int origin_ctext_len = strlen(origin_ctext);
	int str_len = strlen(str);

	if (str_len + origin_ctext_len >= FUZZ_LINE_BUFFER_SIZE)
		str_len = FUZZ_LINE_BUFFER_SIZE - origin_ctext_len - 1;

	strncpy(out, origin_ctext, pos);
	strncpy(out + pos, str, str_len);
	strcpy(out + pos + str_len, origin_ctext + pos);
}

// Insert strings from dictionary before each char
static char * insert_dic(char *origin_ctext, int *is_insertdic_finish)
{
	static int flag = 0;
	static struct FuzzDic *pfd = NULL;
	static int index = 0;
	static int flag_long = 0;

	if (!rfd)
		return NULL;

	if (!flag) {
		pfd = rfd->next;
		flag = 1;
	}

	if (!pfd) {
		flag = 0;
		*is_insertdic_finish = 1;
		return NULL;
	}

	if (100000 > strlen(origin_ctext)) {
		// Insert strings before each char
		insert_str(origin_ctext, index++, pfd->value, fuzz_hash);
		if (index >= strlen(origin_ctext) + 1) {
			index = 0;
			pfd = pfd->next;
		}
	} else {
		// Insert strings before and after these chars: ",.:#$*@"
		while (index < strlen(origin_ctext)) {
			switch (origin_ctext[index]) {
			case ',':
			case '.':
			case ':':
			case '#':
			case '$':
			case '*':
			case '@':
				if (!flag_long) {
					insert_str(origin_ctext, index, pfd->value, fuzz_hash);
					flag_long = 1;
				} else {
					insert_str(origin_ctext, index + 1, pfd->value, fuzz_hash);
					flag_long = 0;
					index++;
				}
			default:
				index++;
				break;
			}
		}
		if (index >= strlen(origin_ctext)) {
			index = 0;
			pfd = pfd->next;
		}
	}

	return fuzz_hash;
}

// Insert str before pos in origin_ctext, and copy the result
// to out
static void insert_char(char *origin_ctext, int pos, char c, int size, char *out)
{
	const int origin_ctext_len = strlen(origin_ctext);

	if (pos > origin_ctext_len)
		pos = origin_ctext_len;
	if (size + origin_ctext_len >= FUZZ_LINE_BUFFER_SIZE)
		size = FUZZ_LINE_BUFFER_SIZE- origin_ctext_len - 1;

	strncpy(out, origin_ctext, pos);
	memset(out + pos, c, size);
	strcpy(out + pos + size, origin_ctext + pos);
}

// Insert chars from -128 to 127
static char * insert_chars(char *origin_ctext, int *is_insertchars_finish)
{
	static int oc_index = 0;
	static int c_index = CHAR_FROM;
	static int flag_long = 0;
	static int times[5] = { 1, 10, 100, 1000, 10000 };
	static int times_index = 0;

	if (oc_index > strlen(origin_ctext))
		oc_index = 0;

//printf("%s:%d %s(oc='%s', times_index=%d, c_index=%d, oc_index=%d)\n",
//	__FILE__, __LINE__, __FUNCTION__, origin_ctext,
//	times_index, c_index, oc_index);

	if (times_index > 4) {
		times_index = 0;
		c_index++;
		if (c_index > CHAR_TO) {
			c_index = CHAR_FROM;
			oc_index++;
			flag_long = 0;
			if (oc_index > strlen(origin_ctext)) {
				oc_index = 0;
				*is_insertchars_finish = 1;
				return NULL;
			}
		}
	}

	if (100000 > strlen(origin_ctext)) {
		// Insert chars before each char
		insert_char(origin_ctext, oc_index, (char)c_index, times[times_index++], fuzz_hash);
	} else {
		// Insert chars before and after these chars: ",.:#$*"
		while (oc_index < strlen(origin_ctext)) {
			switch (origin_ctext[oc_index]) {
			case ',':
			case '.':
			case ':':
			case '#':
			case '$':
			case '*':
				if (!flag_long) {
					insert_char(origin_ctext, oc_index, (char)c_index, times[times_index], fuzz_hash);
					flag_long = 1;
				} else {
					insert_char(origin_ctext, oc_index + 1, (char)c_index, times[times_index], fuzz_hash);
					times_index++;
					flag_long = 0;
				}
				return fuzz_hash;
			default:
				oc_index++;
				break;
			}
		}
		oc_index = 0;
		c_index = CHAR_FROM;
		flag_long = 0;
		times_index = 0;
		return NULL;
	}

	return fuzz_hash;
}

// find length as digits, increment it and insert data after delimiter
static char * update_length_data(char *origin_ctext, int *is_updatelengthdata_finish)
{
	static int times = 1;
	static int pos = 0;
	/* Modes: 0 search, */
	/* then insert 1 raw, 2 hex, 3 base64 threating length as decimal, */
	/*   or insert 4 raw, 5 hex, 6 base64 threating length as hex. */
	static int mode = 0;
	unsigned long long len = 0, as_decimal = 0, as_hex = 0;
	int inc, hex_mode, digit, pos2;

	if (pos > strlen(origin_ctext))
		pos = 0;

	if (mode == 0) {
		for (; origin_ctext[pos] && !mode; ++pos) {
			if (!is_alnum_ascii(origin_ctext[pos])) {
				for (pos2 = pos + 1; atoi16[ARCH_INDEX(origin_ctext[pos2])] != 0x7f; ++pos2)
					;
				if (!origin_ctext[pos2]
				    || pos2 == pos + 1
				    || is_alpha_ascii(origin_ctext[pos2]))
					continue;
				mode = 1;
			}
		}
		if (!origin_ctext[pos]) {
			times = 1;
			pos = 0;
			mode = 0;
			*is_updatelengthdata_finish = 1;
			return NULL;
		}
	}

	for (pos2 = pos; (digit = atoi16[ARCH_INDEX(origin_ctext[pos2])]) != 0x7f; ++pos2) {
		/* Skip decimal modes if there is a letter. */
		if (digit > 9 && mode < 4)
			mode = 4;
		/* It may overflow. Side effect: truncation of long hex fields. */
		as_decimal = as_decimal * 10 + digit;
		as_hex = as_hex * 16 + digit;
	}

	hex_mode = mode >= 4;
	len = hex_mode ? as_hex : as_decimal;
	/* Number of chars to be inserted: raw 1x, hex 2x, base64 4/3x. */
	/* base64 gets times*3 chars to have full blocks. */
	inc = times;
	if (mode == 1 || mode == 4) {
		len += inc;
	} else if (mode == 2 || mode == 5) {
		len += inc;
		inc *= 2;
	} else if (mode == 3 || mode == 6) {
		len += inc * 3;
		inc *= 4;
	}
	snprintf(fuzz_hash, FUZZ_LINE_BUFFER_SIZE,
	         hex_mode ? "%.*s%llx%c%0*d%s"
	                  : "%.*s%llu%c%0*d%s",
	         pos, origin_ctext, len, origin_ctext[pos2], inc, 0, &origin_ctext[pos2 + 1]);
	times += (times < 260 ? 1
	          : times < 5000 ? 13
	          : times < 10000 ? 29 : 113);
	if (times > 20000) {
		times = 1;
		++mode;
		if (mode > 6)
			mode = 0;
	}
	return fuzz_hash;
}

// as insert_chars(), but 0s are inserted at beginning of fields, times vary
static char * insert_zeros(char *origin_ctext, int *is_insertzeros_finish)
{
	static int times = 0;
	static int pos = 0;
	int c, c1;

	if (pos > strlen(origin_ctext))
		pos = 0;

	if (times == 0 && pos == 0) {
		c = origin_ctext[0];
		if (is_alnum_ascii(c))
			times = 1;
	}

	if (times == 0) {
		/* Search position for insertion. */
		for (; origin_ctext[pos] && !times; ++pos) {
			c = origin_ctext[pos];
			c1 = origin_ctext[pos + 1];
			if (!is_alnum_ascii(c) && is_alnum_ascii(c1))
				times = 1;
		}
		if (!origin_ctext[pos]) {
			times = 0;
			pos = 0;
			*is_insertzeros_finish = 1;
			return NULL;
		}
	}

	snprintf(fuzz_hash, FUZZ_LINE_BUFFER_SIZE,
	         "%.*s%0*d%s",
	         pos, origin_ctext, times, 0, &origin_ctext[pos]);
	times += (times < 300 ? 1
	          : times < 5000 ? 20
	          : times < 10000 ? 60 : 160);
	if (times > 20000) {
		times = 0;
		++pos;
	}
	return fuzz_hash;
}

static char * get_next_fuzz_case(const char *label, char *ciphertext)
{
	static int is_replace_finish = 0; // is_replace_finish = 1 if all the replaced cases have been generated
	static int is_swap_finish = 0; // is_swap_finish = 1 if all the swaped cases have been generated
	static int is_append_finish = 0; // is_append_finish = 1 if all the appended cases have been generated
	static int is_chgcase_finish = 0; // is_chgcase_finish = 1 if all the change cases have been generated
	static int is_insertdic_finish = 0; // is_insertdic_finish = 1 if all the insert dictionary cases have been generated
	static int is_insertchars_finish = 0; // is_insertchars_finish = 1 if all the chars from -128 to 127 cases have been generated
	static int is_updatelengthdata_finish = 0;
	static int is_insertzeros_finish = 0;
	static const char *last_label = NULL;
	static char *last_ciphertext = NULL;

	if (strlen(ciphertext) > FUZZ_LINE_BUFFER_SIZE) {
		fprintf(stderr, "ciphertext='%s' is bigger than the FUZZ_LINE_BUFFER_SIZE=%d\n",
			ciphertext, FUZZ_LINE_BUFFER_SIZE);
		error();
	}
	strcpy(fuzz_hash, ciphertext);

	if (!last_label)
		last_label = label;

	if (!last_ciphertext)
		last_ciphertext = ciphertext;

	if (strcmp(label, last_label) != 0 || strcmp(ciphertext, last_ciphertext) != 0) {
		is_replace_finish = 0;
		is_swap_finish = 0;
		is_append_finish = 0;
		is_chgcase_finish = 0;
		is_insertdic_finish = 0;
		is_insertchars_finish = 0;
		is_updatelengthdata_finish = 0;
		is_insertzeros_finish = 0;
		last_label = label;
		last_ciphertext = ciphertext;
	}

	if (!is_replace_finish)
		if (replace_each_chars(ciphertext, &is_replace_finish))
			return fuzz_hash;

	if (!is_swap_finish)
		if (swap_chars(ciphertext, &is_swap_finish))
			return fuzz_hash;

	if (!is_append_finish)
		if (append_last_char(ciphertext, &is_append_finish))
			return fuzz_hash;

	if (!is_chgcase_finish)
		if (change_case(ciphertext, &is_chgcase_finish))
			return fuzz_hash;

	if (!is_insertdic_finish)
		if (insert_dic(ciphertext, &is_insertdic_finish))
			return fuzz_hash;

	if (!is_insertchars_finish)
		if (insert_chars(ciphertext, &is_insertchars_finish))
			return fuzz_hash;

	if (!is_updatelengthdata_finish)
		if (update_length_data(ciphertext, &is_updatelengthdata_finish))
			return fuzz_hash;

	if (!is_insertzeros_finish)
		if (insert_zeros(ciphertext, &is_insertzeros_finish))
			return fuzz_hash;

	return NULL;
}

static void init_status(const char *format_label)
{
	sprintf(status_file_path, "%s", "fuzz_status");
#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
	if (_mkdir(status_file_path)) { // MingW
#else
	if (mkdir(status_file_path, S_IRUSR | S_IWUSR | S_IXUSR)) {
#endif
		if (errno != EEXIST) pexit("mkdir: %s", status_file_path);
	} else
		fprintf(stderr, "Created directory: %s\n", status_file_path);

	sprintf(status_file_path, "%s/%s", "fuzz_status", format_label);
	if (!(s_file = fopen(status_file_path, "w")))
		pexit("fopen: %s", status_file_path);
}

static void save_index(const int index)
{
	fprintf(s_file, "%d\n", index);
	fflush(s_file);
}

static void fuzz_test(struct db_main *db, struct fmt_main *format)
{
	int index;
	char *ret, *line;
	struct fmt_tests *current;

	printf("Fuzzing: %s%s%s%s [%s]%s... ",
	       format->params.label,
	       format->params.format_name[0] ? ", " : "",
	       format->params.format_name,
	       format->params.benchmark_comment,
	       format->params.algorithm_name,
#ifndef BENCH_BUILD
	       (options.target_enc == UTF_8 &&
	       format->params.flags & FMT_UNICODE) ?
	       " in UTF-8 mode" : "");
#else
	       "");
#endif
	fflush(stdout);


	// validate that there are no NULL function pointers
	if (format->methods.prepare == NULL)    return;
	if (format->methods.valid == NULL)      return;
	if (format->methods.split == NULL)      return;
	if (format->methods.init == NULL)       return;

	index = 0;
	current = format->params.tests;

	init_status(format->params.label);
	ldr_init_database(db, &options.loader);
	db->format = format;

	while (!event_abort && index < fuzz_limit) {
		ret = get_next_fuzz_case(format->params.label, current->ciphertext);
		save_index(index++);
		line = fuzz_hash;
		ldr_load_pw_line(db, line);

		if (!ret) {
			if (!(++current)->ciphertext)
				break;
		}
	}
	if (fclose(s_file)) pexit("fclose");
	remove(status_file_path);
	fmt_done(format);
	ldr_fix_database(db);
	ldr_free_db(db, 0);
	if (!event_abort)
		printf("   Completed\n");
}

// Dump fuzzed hashes which index is between from and to, including from and excluding to
static void fuzz_dump(struct fmt_main *format, const int from, const int to)
{
	int index;
	char *ret;
	struct fmt_tests *current;
	char file_name[PATH_BUFFER_SIZE];
	FILE *file;
	size_t len = 0;

	sprintf(file_name, "pwfile.%s", format->params.label);

	printf("Generating %s for %s%s%s%s ... ",
	       file_name,
	       format->params.label,
	       format->params.format_name[0] ? ", " : "",
	       format->params.format_name,
	       format->params.benchmark_comment);
	fflush(stdout);

	if (!(file = fopen(file_name, "w")))
		pexit("fopen: %s", file_name);

	index = 0;
	current = format->params.tests;

	while (1) {
		ret = get_next_fuzz_case(format->params.label, current->ciphertext);
		if (index >= from) {
			if (index == to)
				break;
			fprintf(file, "%s\n", fuzz_hash);
			len += 1 + strlen(fuzz_hash);
		}
		index++;
		if (!ret) {
			if (!(++current)->ciphertext)
				break;
		}
	}
	printf(LLu" bytes\n", (unsigned long long) len);
	if (fclose(file)) pexit("fclose");
}


int fuzz(struct db_main *db)
{
	char *p;
	int from, to;
	unsigned int total;
	struct fmt_main *format;

	pristine_gecos = cfg_get_bool(SECTION_OPTIONS, NULL,
	        "PristineGecos", 0);
	single_skip_login = cfg_get_bool(SECTION_OPTIONS, NULL,
		"SingleSkipLogin", 0);

	if (options.flags & FLG_FUZZ_DUMP_CHK) {
		from = -1;
		to = -1;

		if (options.fuzz_dump) {
			p = strtok(options.fuzz_dump, ",");
			if (p) {
				sscanf(p, "%d", &from);
				p = strtok(NULL, ",");

				if (p)
					sscanf(p, "%d", &to);
			}
		}
		if (from > to) {
			fprintf(stderr, "--fuzz-dump from=%d is bigger than to=%d\n",
				from, to);
			error();
		}
	}

	fuzz_limit = 0x7fffffff;
	if (options.fuzz_dic) {
		if (isdec(options.fuzz_dic))
			fuzz_limit = atoi(options.fuzz_dic);
		else
			fuzz_init_dictionary();
	}

	total = 0;
	if ((format = fmt_list))
	do {
/* Silently skip formats for which we have no tests, unless forced */
		if (!format->params.tests && format != fmt_list)
			continue;

		if (options.flags & FLG_FUZZ_DUMP_CHK)
			fuzz_dump(format, from, to);
		else
			fuzz_test(db, format);

		if (!event_abort)
			total++;
	} while ((format = format->next) && !event_abort);

	if (options.flags & FLG_FUZZ_DUMP_CHK)
		printf("\nGenerated pwfile.<format> for %u formats\n", total);
	else if (total)
		printf("\nAll %u formats passed fuzzing test!\n", total);

	return 0;
}

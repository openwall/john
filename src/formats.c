/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006,2008,2010-2013,2015 by Solar Designer
 */

#if AC_BUILT
#include "autoconfig.h"
#else
#define _GNU_SOURCE 1 /* for strcasestr */
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "params.h"
#include "memory.h"
#include "formats.h"
#include "dyna_salt.h"
#include "misc.h"
#include "unicode.h"
#include "base64_convert.h"
#include "dynamic_compiler.h"
#ifndef BENCH_BUILD
#include "options.h"
#include "config.h"
#include "loader.h"
#endif
#include "john.h"

/* this is just for advance_cursor() */
#include "opencl_common.h"
#include "jumbo.h"
#include "bench.h"
#include "omp_autotune.h"

char fmt_null_key[PLAINTEXT_BUFFER_SIZE];

struct fmt_main *fmt_list = NULL;
static struct fmt_main **fmt_tail = &fmt_list;
static char *buf_key;

int fmt_raw_len;

int self_test_running;
int benchmark_running;

#ifndef BENCH_BUILD
static int orig_min, orig_max, orig_len;

static void test_fmt_split_unifies_case_4(struct fmt_main *format, char *ciphertext, int *is_split_unifies_case, int call_cnt);
static void test_fmt_split_unifies_case_3(struct fmt_main *format,
	char *ciphertext, int *has_change_case, int *is_need_unify_case);
static void test_fmt_split_unifies_case(struct fmt_main *format, char *ciphertext, int *is_split_unifies_case, int call_cnt);
static void get_longest_common_string(char *fstr, char *sstr, int *first_index,
	int *second_index, int *size);
static void test_fmt_8_bit(struct fmt_main *format, void *binary,
	char *ciphertext, char *plaintext, int *is_ignore_8th_bit,
	int *plaintext_is_blank, struct db_salt *dbsalt);
static void test_fmt_case(struct fmt_main *format, void *binary,
	char *ciphertext, char* plaintext, int *is_case_sensitive,
	int *plaintext_has_alpha, struct db_salt *dbsalt);
static char *test_fmt_tunable_costs(struct fmt_main *format);
#endif

/*
 * List of format classes valid for this build (actually all are valid
 * to ask for but we don't list those that can't match).
 *
 * This list is used in listconf.c and john.c
 */
char fmt_class_list[] = "all, enabled, disabled"
#if _OPENMP
	", omp"
#endif
#if HAVE_OPENCL || HAVE_ZTEX
	", mask"
#endif
#if HAVE_ZTEX
	", ztex"
#endif
#if HAVE_OPENCL
	", opencl, vector"
#endif
#ifndef DYNAMIC_DISABLED
	", dynamic"
#endif
	", cpu";

int fmt_is_class(char *name)
{
	return (name && (!strcasecmp(name, "all") || !strcasecmp(name, "enabled") || !strcasecmp(name, "disabled") ||
	                 !strcasecmp(name , "omp") ||
	                 !strcasecmp(name , "mask") ||
	                 !strcasecmp(name , "ztex") ||
	                 !strcasecmp(name , "opencl") || !strcasecmp(name , "vector") ||
	                 !strcasecmp(name , "dynamic") ||
	                 !strcasecmp(name , "cpu")));
}

/*
 * Does req_format match format?
 *
 * req_format can be an exact full match or a wildc*rd, for format label,
 * or it can be @algo where 'algo' must be a substring of algorithm_name,
 * or it can be #name where 'name' must be a substring of format's long name
 * or it can be a format class/group such as "opencl", "dynamic" or "omp"
 */
int fmt_match(const char *req_format, struct fmt_main *format, int override_disable)
{
	/* Exact full match */
	if (!strcasecmp(req_format, format->params.label))
		return 1;

#ifndef BENCH_BUILD
	int enabled = override_disable || !((options.flags & FLG_TEST_CHK) || options.listconf) ||
		!cfg_get_bool(SECTION_DISABLED, SUBSECTION_FORMATS, format->params.label, 0);
	char *pos = NULL;

#ifndef DYNAMIC_DISABLED
	if (!strncasecmp(req_format, "dynamic=", 8) && !strcasecmp(format->params.label, "dynamic=")) {
		DC_HANDLE H;

		if (!dynamic_compile(req_format, &H) && !dynamic_assign_script_to_format(H, format))
			return 1;
	}
#endif

	/* Override any config settings such as [Disabled:Formats] */
	if (!strcasecmp(req_format, "all"))
		return 1;

	/* Is this format disabled? */
	if (!strcasecmp(req_format, "disabled"))
		return cfg_get_bool(SECTION_DISABLED, SUBSECTION_FORMATS, format->params.label, 0);
	else if (!strcasecmp(req_format, "enabled"))
		return !cfg_get_bool(SECTION_DISABLED, SUBSECTION_FORMATS, format->params.label, 0);

	/* Label wildcard, as in --format=office* */
	/* We disregard '*' for dynamic compiler format in case it's part of an expression */
	if (strncasecmp(req_format, "dynamic=", 8) && (pos = strchr(req_format, '*'))) {
		if (pos != strrchr(req_format, '*')) {
			if (john_main_process)
				fprintf(stderr, "Error: '%s': Only one wildcard allowed in a format name\n", req_format);
			error();
		}

		int pre_len = (pos - req_format);

		/* Match anything before wildcard, as in office*, if applicable */
		if (pre_len && strncasecmp(format->params.label, req_format, pre_len))
			return 0;

		/* Match anything after wildcard, as in *office or raw*ng, if applicable */
		if (*(++pos)) {
			int trail_len = strlen(pos);
			int label_len = strlen(format->params.label);

			if (label_len - pre_len < trail_len)
				return 0;

			if (strcasecmp(&format->params.label[label_len - trail_len], pos))
				return 0;
		}
		return enabled;
	}

	/* Algo match, eg. --format=@xop or --format=@sha384 */
	if (req_format[0] == '@' && req_format[1])
		return enabled && strcasestr(format->params.algorithm_name, ++req_format);

	/* Long-name match, eg. --format=#ipmi or --format=#1password */
	if (req_format[0] == '#' && req_format[1])
		return enabled && strcasestr(format->params.format_name, ++req_format);

	/* Format classes */
	if (!strcasecmp(req_format, "dynamic"))
		return enabled && (format->params.flags & FMT_DYNAMIC);

	if (!strcasecmp(req_format, "cpu"))
		return enabled && !(strstr(format->params.label, "-opencl") || strstr(format->params.label, "-ztex"));

	if (!strcasecmp(req_format, "opencl"))
		return enabled && strstr(format->params.label, "-opencl");

	if (!strcasecmp(req_format, "ztex"))
		return enabled && strstr(format->params.label, "-ztex");

	if (!strcasecmp(req_format, "mask"))
		return enabled && (format->params.flags & FMT_MASK);

#if HAVE_OPENCL
	if (!strcasecmp(req_format, "vector") && strstr(format->params.label, "-opencl")) {
		int vectorized;
		const char *orig_algo = format->params.algorithm_name;

		fmt_init(format);
		vectorized = (ocl_v_width > 1);
		fmt_done(format);
		format->params.algorithm_name = orig_algo;

		return enabled && vectorized;
	}
#endif

	if (!strcasecmp(req_format, "omp"))
		return enabled && (format->params.flags & FMT_OMP);

#endif /* BENCH_BUILD */
	return 0;
}

#ifndef BENCH_BUILD

/* Exclusions. Drop any format(s) matching rej_format from full list */
static int exclude_formats(char *rej_format, struct fmt_main **full_fmt_list)
{
	struct fmt_main *current, *prev = NULL;
	int removed = 0;

	if ((current = *full_fmt_list))
	do {
		if (fmt_match(rej_format, current, 1)) {
			if (prev)
				prev->next = current->next;
			else
				*full_fmt_list = current->next;
			removed++;
		} else
			prev = current;
	} while ((current = current->next));

	return removed;
}

/* Inclusions. Move any format(s) matching req_format from full list to new list */
static int include_formats(char *req_format, struct fmt_main **full_fmt_list)
{
	struct fmt_main *current, *prev = NULL, *next = NULL;
	int added = 0;

	if ((current = *full_fmt_list))
	do {
		next = current->next;
		if (fmt_match(req_format, current, 0)) {
			if (prev)
				prev->next = next;
			else
				*full_fmt_list = next;
			fmt_register(current);
			added++;
		} else
			prev = current;
	} while ((current = next));

	return added;
}

/* Requirements. Drop any format(s) NOT matching req_format from new list */
static int prune_formats(char *req_format, int override_disable)
{
	struct fmt_main *current, *prev = NULL;
	int removed = 0;

	if ((current = fmt_list))
	do {
		if (!fmt_match(req_format, current, override_disable)) {
			if (prev)
				prev->next = current->next;
			else
				fmt_list = current->next;
			removed++;
		} else
			prev = current;
	} while ((current = current->next));

	return removed;
}

static int is_in_fmt_list(char *req_format)
{
	struct fmt_main *current;
	int result = 0;

	if ((current = fmt_list))
	do
		result += fmt_match(req_format, current, 1);
	while ((current = current->next));

	return result;
}

/* Modelled after ldr_split_string */
static void comma_split(struct list_main *dst, const char *src)
{
	char *word, *pos;
	char c;
	char *src_cpy = xstrdup(src);

	strlwr(src_cpy);

	pos = src_cpy;
	do {
		word = pos;
		while (*word == ',')
			word++;

		if (!*word)
			break;

		pos = word;

		while (*pos && *pos != ',')
			pos++;

		c = *pos;
		*pos = 0;

		list_add_unique(dst, word);

		*pos++ = c;

	} while (c);

	MEM_FREE(src_cpy);
}

char* fmt_type(char *name)
{
	if (name[1] && (name[0] == '+' || name[0] == '-'))
		name++;

	if (fmt_is_class(name))
		return "class";

	if (strchr(name, '*') || name[0] == '@' || name[0] == '#')
		return "wildcard";

	return "name";
}

int fmt_check_custom_list(void)
{
	if (strchr(options.format_list, ',')) {
		struct list_main *req_formats;

		list_init(&req_formats);
		comma_split(req_formats, options.format_list);

		if (req_formats->count) {
			struct list_entry *req_format = req_formats->head;
			struct fmt_main *full_fmt_list = fmt_list;
			int had_i = 0, num_e = 0;

			fmt_list = NULL;
			fmt_tail = &fmt_list;

			/* "-" Exclusions first, from the full list. */
			do {
				if (req_format->data[0] == '-') {
					char *exclude_fmt = &(req_format->data[1]);

					if (!exclude_fmt[0])
						error_msg("Error: '%s' in format list doesn't make sense\n", req_format->data);
					num_e += exclude_formats(exclude_fmt, &full_fmt_list);
				}
			} while ((req_format = req_format->next));

			/* Inclusions. Move to the new list. */
			req_format = req_formats->head;
			do {
				if ((req_format->data[0] != '-') && (req_format->data[0] != '+')) {
					had_i = 1;
					if (!include_formats(req_format->data, &full_fmt_list) && !is_in_fmt_list(req_format->data)) {
						if (john_main_process)
							fprintf(stderr, "Error: No format matched requested %s '%s'%s\n",
							        fmt_type(req_format->data),
							        req_format->data,
							        num_e ? " after exclusions" : "");
						error();
					}
				}
			} while ((req_format = req_format->next));

			if (!had_i)
				include_formats("*", &full_fmt_list);

			/* "+" Requirements. Scan the new list and prune formats not matching. */
			req_format = req_formats->head;
			do {
				if (req_format->data[0] == '+') {
					char *require_fmt = &(req_format->data[1]);

					if (!require_fmt[0])
						error_msg("Error: '%s' in format list doesn't make sense\n", req_format->data);
					prune_formats(require_fmt, had_i);

					if (!fmt_list) {
						if (john_main_process)
							fprintf(stderr, "Error: No format matched requested '%s' after processing '%s'\n",
							        options.format_list, req_format->data);
						error();
					}
				}
			} while ((req_format = req_format->next));

			if (!fmt_list) {
				if (john_main_process)
					fprintf(stderr, "Error: No format matched requested criteria '%s'\n", options.format_list);
				error();
			}

			return 1;
		} else
			error_msg("Error: Format list '%s' made no sense\n", options.format_list);
	}

	return 0;
}
#endif /* BENCH_BUILD */

void fmt_register(struct fmt_main *format)
{
	format->private.initialized = 0;
	format->next = NULL;
	*fmt_tail = format;
	fmt_tail = &format->next;
}

void fmt_init(struct fmt_main *format)
{
	if (!buf_key)
		buf_key = mem_alloc_tiny(PLAINTEXT_BUFFER_SIZE, MEM_ALIGN_SIMD);

	if (!format->private.initialized) {
#ifndef BENCH_BUILD
		orig_min = format->params.min_keys_per_crypt;
		orig_max = format->params.max_keys_per_crypt;
		orig_len = format->params.plaintext_length;
#endif
		if (!fmt_raw_len)
			fmt_raw_len = format->params.plaintext_length;
		format->methods.init(format);
#ifndef BENCH_BUILD
		/* NOTE, we have to grab these values (the first time), from after
		   the format has been initialized for thin dynamic formats */
		if (orig_len == 0 && format->params.plaintext_length) {
			orig_min = format->params.min_keys_per_crypt;
			orig_max = format->params.max_keys_per_crypt;
			orig_len = format->params.plaintext_length;
		}

		if (john_main_process && !(options.flags & FLG_TEST_CHK) &&
		    !options.listconf && options.target_enc != UTF_8 &&
		    format->params.flags & FMT_UTF8)
			fprintf(stderr, "Warning: %s format should always be "
			        "UTF-8. Use --target-encoding=utf8\n",
				format->params.label);

		if (john_main_process && !(options.flags & FLG_TEST_CHK) && !options.listconf) {
			if (format->params.flags & FMT_NOT_EXACT) {
				fprintf(stderr, "Note: This format may emit false positives, ");
				if (options.keep_guessing == 0)
					fprintf(stderr, "but we will stop after finding first\n");
				else
					fprintf(stderr, "so it will keep trying even after finding a possible candidate.\n");
			} else if (options.keep_guessing == 1)
				fprintf(stderr, "Note: Will keep guessing even after finding a possible candidate.\n");
		}

		if (options.keep_guessing == 1) /* tri-state */
			format->params.flags |= FMT_NOT_EXACT;
		else if (options.keep_guessing == 0)
			format->params.flags &= ~FMT_NOT_EXACT;
#endif
		format->private.initialized = 1;
	}
#ifndef BENCH_BUILD
	if (options.force_maxkeys) {
		if (options.force_maxkeys > format->params.max_keys_per_crypt) {
			fprintf(stderr,
			    "Can't set mkpc larger than %u for %s format\n",
			    format->params.max_keys_per_crypt,
			    format->params.label);
			error();
		}
		if (options.force_maxkeys < format->params.min_keys_per_crypt)
			format->params.min_keys_per_crypt =
				options.force_maxkeys;
	}
	if (!(options.flags & FLG_LOOPBACK_CHK) &&
	    options.req_maxlength > format->params.plaintext_length) {
		fprintf(stderr, "Can't set max length larger than %u "
		        "for %s format\n",
		        format->params.plaintext_length,
		        format->params.label);
		error();
	}
#endif
}

void fmt_done(struct fmt_main *format)
{
	if (format->private.initialized) {
		format->methods.done();
		format->private.initialized = 0;
#ifdef HAVE_OPENCL
		opencl_done();
#endif
#ifndef BENCH_BUILD
		format->params.min_keys_per_crypt = orig_min;
		format->params.max_keys_per_crypt = orig_max;
		format->params.plaintext_length = orig_len;
#endif
	}
	fmt_raw_len = 0;
}

void fmt_all_done(void)
{
	struct fmt_main *format = fmt_list;

	while (format) {
		if (format->private.initialized) {
			format->methods.done();
			format->private.initialized = 0;
		}
		format = format->next;
	}
#ifdef HAVE_OPENCL
	opencl_done();
#endif
}

static int is_poweroftwo(size_t align)
{
	return align != 0 && (align & (align - 1)) == 0;
}

#undef is_aligned /* clash with common.h */
static int is_aligned(void *p, size_t align)
{
	return ((size_t)p & (align - 1)) == 0;
}

/* Mutes ASan problems. We pass a buffer long enough for any use */
#define fmt_set_key(key, index)	  \
	{ \
		char *s = key, *d = buf_key; \
		while ((*d++ = *s++)); \
		format->methods.set_key(buf_key, index); \
	}

#define MAXLABEL        "3133731337" /* must be non-letter ASCII chars only */
#define MAXLABEL_SIMD   "80808080\x80" /* Catch a common bug */
static char *longcand(struct fmt_main *format, int index, int ml)
{
	static char out[PLAINTEXT_BUFFER_SIZE];
	int i;

	for (i = 0; i < ml; ++i)
		out[i] = '0' + (i+index)%10;

	if (!(format->params.flags & FMT_8_BIT) ||
#ifndef BENCH_BUILD
	    !(format->params.flags & FMT_CASE) || options.target_enc == UTF_8
#else
	    !(format->params.flags & FMT_CASE)
#endif
	   )
		memcpy(out, MAXLABEL, strlen(MAXLABEL));
	else
		memcpy(out, MAXLABEL_SIMD, strlen(MAXLABEL_SIMD));
	out[ml] = 0;

	return out;
}

#ifndef BENCH_BUILD
static char* is_key_right(struct fmt_main *format, int index,
	void *binary, char *ciphertext, char *plaintext,
	int is_test_fmt_case, struct db_salt *dbsalt)
{
	static char err_buf[200];
	int i, size, count, match, len;
	char *key;

	if (is_test_fmt_case && index != 0)
		return "index should be 0 when test_fmt_case";

	count = index + 1;
	match = format->methods.crypt_all(&count, dbsalt);

	if ((match && !format->methods.cmp_all(binary, match)) ||
	    (!match && format->methods.cmp_all(binary, match))) {
		if (options.verbosity > VERB_LEGACY)
			snprintf(err_buf, sizeof(err_buf), "cmp_all(%d) %s", match, ciphertext);
		else
			sprintf(err_buf, "cmp_all(%d)", match);
		return err_buf;
	}

	if (match == 0) {
		if (options.verbosity > VERB_LEGACY)
			snprintf(err_buf, sizeof(err_buf), "crypt_all(%d) zero return %s", index + 1, ciphertext);
		else
			sprintf(err_buf, "crypt_all(%d) zero return", index + 1);
		return err_buf;
	}

	for (i = match - 1; i >= 0; i--) {
		if (format->methods.cmp_one(binary, i))
			break;
	}

	if (i == -1) {
		if (options.verbosity > VERB_LEGACY)
			snprintf(err_buf, sizeof(err_buf), "cmp_one(%d) %s", match, ciphertext);
		else
			sprintf(err_buf, "cmp_one(%d)", match);
		return err_buf;
	}

	for (size = 0; size < PASSWORD_HASH_SIZES; size++)
	if (format->methods.binary_hash[size] &&
	    format->methods.get_hash[size] &&
	    format->methods.get_hash[size] != fmt_default_get_hash &&
	    format->methods.get_hash[size](i) !=
	    format->methods.binary_hash[size](binary)) {
		if (options.verbosity > VERB_LEGACY) {
			// Dump out as much as possible (up to 3 full bytes). This can
			// help in trying to track down problems, like needing to SWAP
			// the binary or other issues, when doing BE ports.  Here
			// PASSWORD_HASH_SIZES is assumed to be 7. This loop will max
			// out at 6, in that case (i.e. 3 full bytes).
			int maxi=size;
			while (maxi+2 < PASSWORD_HASH_SIZES && format->methods.binary_hash[maxi]) {
				if (format->methods.binary_hash[++maxi] == NULL) {
					--maxi;
					break;
				}
			}
			if (format->methods.get_hash[maxi] && format->methods.binary_hash[maxi])
				sprintf(err_buf, "get_hash[%d](%d) %x!=%x %s", size, index,
					format->methods.get_hash[maxi](index),
					format->methods.binary_hash[maxi](binary),
					ciphertext);
			else
				sprintf(err_buf, "get_hash[%d](%d) %x!=%x %s", size,
					index, format->methods.get_hash[size](index),
					format->methods.binary_hash[size](binary),
					ciphertext);
		} else
		{
			sprintf(err_buf, "get_hash[%d](%d) %x!=%x", size,
				index, format->methods.get_hash[size](index),
				format->methods.binary_hash[size](binary));
		}
		return err_buf;
	}

	if (!format->methods.cmp_exact(ciphertext, i)) {
		if (options.verbosity > VERB_LEGACY)
			snprintf(err_buf, sizeof(err_buf), "cmp_exact(%d) %s", match, ciphertext);
		else
			sprintf(err_buf, "cmp_exact(%d)", i);
		return err_buf;
	}

	key = format->methods.get_key(i);
	len = strlen(key);

	if (len < format->params.plaintext_min_length ||
		len > format->params.plaintext_length) {
		if (options.verbosity > VERB_LEGACY)
		snprintf(err_buf, sizeof(err_buf), "The length of string returned by get_key() is %d "
			"but should be between plaintext_min_length=%d and plaintext_length=%d %s",
			len, format->params.plaintext_min_length,
			format->params.plaintext_length, key);
		else
		sprintf(err_buf, "The length of string returned by get_key() is %d "
			"but should be between plaintext_min_length=%d and plaintext_length=%d",
			len, format->params.plaintext_min_length,
			format->params.plaintext_length);
		return err_buf;
	}

	if (is_test_fmt_case)
		return NULL;

	if (format->params.flags & FMT_CASE) {
		// Case-sensitive passwords
		if (strncmp(key, plaintext, format->params.plaintext_length)) {
			if (options.verbosity > VERB_LEGACY)
				snprintf(err_buf, sizeof(err_buf), "get_key(%d) (case) %s %s", i, key, plaintext);
			else
				sprintf(err_buf, "get_key(%d)", i);
			return err_buf;
		}
	} else {
		// Case-insensitive passwords
		if (strncasecmp(key, plaintext,
			format->params.plaintext_length)) {
			if (options.verbosity > VERB_LEGACY)
				snprintf(err_buf, sizeof(err_buf), "get_key(%d) (no case) %s %s", i, key, plaintext);
			else
				sprintf(err_buf, "get_key(%d)", i);
			return err_buf;
		}
	}

	return NULL;
}
#endif

int fmt_bincmp(void *b1, void *b2, struct fmt_main *format)
{
	if (!(format->params.flags & FMT_BLOB))
		return memcmp(b1, b2, format->params.binary_size);

	size_t s1 = ((fmt_data*)b1)->size;
	size_t s2 = ((fmt_data*)b2)->size;

	if (s1 != s2)
		return 1;

	b1 = ((fmt_data*)b1)->blob;
	b2 = ((fmt_data*)b2)->blob;

	return memcmp(b1, b2, s1);
}

static char *fmt_self_test_body(struct fmt_main *format,
    void *binary_copy, void *salt_copy, struct db_main *db, int full_lvl)
{
	static char s_size[200];
#ifndef BENCH_BUILD
	char *ret;
#endif
	struct fmt_tests *current;
	char *ciphertext, *plaintext;
	int ntests, done, index, max, size;
	void *binary, *salt;
	int binary_align_warned = 0, salt_align_warned = 0;
	int salt_cleaned_warned = 0, binary_cleaned_warned = 0;
	int salt_dupe_warned = 0, i;
#ifndef BENCH_BUILD
	int cnt_split_unifies_case = 0;// just in case only the last test case unifies.
	int dhirutest = 0;
	int maxlength = 0;
	int extra_tests = options.flags & FLG_TEST_CHK;
#else
	int extra_tests = 0;
#endif
	int ml, sl = 0;
	int plaintext_has_alpha = 0;   // Does plaintext has alphabet: a-z A-Z
	int is_case_sensitive = 0;     // Is password case sensitive, FMT_CASE
	int plaintext_is_blank = 1;    // Is plaintext blank ""
	int is_ignore_8th_bit = 1;     // Is ignore 8th bit, FMT_8_BIT
	int is_split_unifies_case = 0; // Is split() unifies case
	int is_split_unifies_case_4 = 0;
	int is_change_case = 0;        // Is change cases of ciphertext and it is valid
	int is_need_unify_case = 1;    // Is need to unify cases in split()
	int fmt_split_case = ((format->params.flags & FMT_SPLIT_UNIFIES_CASE)==FMT_SPLIT_UNIFIES_CASE);
	int while_condition;           // since -test and -test-full use very do{}while(cond) so we use a var.
#ifndef BENCH_BUILD
	struct db_salt *dbsalt;
#endif

	// validate that there are no NULL function pointers
	if (format->methods.prepare == NULL)    return "method prepare NULL";
	if (format->methods.valid == NULL)      return "method valid NULL";
	if (format->methods.split == NULL)      return "method split NULL";
	if (format->methods.init == NULL)       return "method init NULL";

	(void)size;  // quiet stupid warning.

/*
 * Test each format just once unless we're debugging.
 */
#ifndef DEBUG
	if (format->private.initialized == 2)
		return NULL;
#endif
#ifndef BENCH_BUILD
	if (options.flags & FLG_NOTESTS) {
		fmt_init(format);
		dyna_salt_init(format);
		omp_autotune_run(db);
		format->methods.reset(db);
		format->private.initialized = 2;
		format->methods.clear_keys();
		return NULL;
	}
	ret = test_fmt_tunable_costs(format);
	if (ret)
		return ret;
#endif
#if defined(HAVE_OPENCL)
	if (strcasestr(format->params.label, "-opencl") &&
	    !strstr(format->params.label, "-opencl")) {
		return "-opencl suffix must be lower case";
	}
#endif

	if (!(current = format->params.tests))
		return NULL;
	ntests = 0;
	while ((current++)->ciphertext)
		ntests++;
	current = format->params.tests;
#if defined (_MSC_VER) && !defined (BENCH_BUILD)
	if (current->ciphertext[0] == 0 &&
	    !strcasecmp(format->params.label, "LUKS")) {
		// luks has a string that is longer than the 64k max string length of
		// VC. So to get it to work, we post load the the test value.
		void LUKS_test_fixup();
		LUKS_test_fixup();
		current = format->params.tests;
	}
#endif

	if (ntests == 0)
		return NULL;

	/* Check prepare, valid, split before init */
	if (!current->fields[1])
		current->fields[1] = current->ciphertext;
	ciphertext = format->methods.prepare(current->fields, format);
	if (!ciphertext || strlen(ciphertext) < 7)
		return "prepare (before init)";
	if (format->methods.valid(ciphertext, format) != 1)
		return "valid (before init)";
	if (!format->methods.split(ciphertext, 0, format))
		return "split() returned NULL (before init)";
	fmt_init(format);

	// validate that there are no NULL function pointers after init()
	if (format->methods.done == NULL)       return "method done NULL";
	if (format->methods.reset == NULL)      return "method reset NULL";
	if (format->methods.binary == NULL)     return "method binary NULL";
	if (format->methods.salt == NULL)       return "method salt NULL";
	if (format->methods.source == NULL)     return "method source NULL";
	if (!format->methods.binary_hash[0])    return "method binary_hash[0] NULL";
	if (format->methods.salt_hash == NULL)  return "method salt_hash NULL";
	if (format->methods.set_salt == NULL)   return "method set_salt NULL";
	if (format->methods.set_key == NULL)    return "method set_key NULL";
	if (format->methods.get_key == NULL)    return "method get_key NULL";
	if (format->methods.clear_keys == NULL) return "method clear_keys NULL";
	if (format->methods.crypt_all == NULL)  return "method crypt_all NULL";
	if (format->methods.get_hash[0]==NULL)  return "method get_hash[0] NULL";
	if (format->methods.cmp_all == NULL)    return "method cmp_all NULL";
	if (format->methods.cmp_one == NULL)    return "method cmp_one NULL";
	if (format->methods.cmp_exact == NULL)  return "method cmp_exact NULL";

	if (format->params.plaintext_length < 1 ||
	    format->params.plaintext_length > PLAINTEXT_BUFFER_SIZE - 3)
		return "plaintext_length";

	if (format->params.benchmark_length < 0 ||
	    (format->params.benchmark_length & 0xff) <
	    format->params.plaintext_min_length ||
	    (format->params.benchmark_length & 0xff) >
	    format->params.plaintext_length)
		return "benchmark_length";

	if (!is_poweroftwo(format->params.binary_align))
		return "binary_align";

	if (!is_poweroftwo(format->params.salt_align))
		return "salt_align";

	if (format->methods.valid("*", format))
		return "valid";

	if (format->methods.source != fmt_default_source &&
	    format->params.salt_size != 0)
		return "source method only allowed for unsalted formats";

	if (format->params.flags & FMT_HUGE_INPUT) {
		for (size = 0; size < PASSWORD_HASH_SIZES; size++) {
			/*
			 * We could allow this, but they would need to calculate the
			 * same MD5 as the $SOURCE_HASH$ of a truncated pot entry and
			 * return a portion of that.  This test could instead confirm
			 * that's the case.  Given common properties of these formats,
			 * it not likely worth bothering with.
			 */
			if (format->methods.binary_hash[size] &&
			    format->methods.binary_hash[size] !=
			    fmt_default_binary_hash)
				return "binary_hash method not allowed for FMT_HUGE_INPUT";
			if (format->methods.get_hash[size] &&
			    format->methods.get_hash[size] !=
			    fmt_default_get_hash)
				return "get_hash method not allowed for FMT_HUGE_INPUT";
		}
	}

	if ((!format->methods.binary_hash[0] || format->methods.binary_hash[0] ==
	     fmt_default_binary_hash) && format->params.salt_size > 512 &&
	    !(format->params.flags & FMT_HUGE_INPUT))
		return "FMT_HUGE_INPUT should be set";

	ml = format->params.plaintext_length;
#ifndef BENCH_BUILD
	/* UTF-8 bodge in reverse. Otherwise we will get truncated keys back
	   from the max-length self-test */
	if ((options.target_enc == UTF_8) &&
	    (format->params.flags & FMT_ENC) &&
	    (format->params.flags & FMT_UNICODE))
		ml /= 3;

	omp_autotune_run(db);
#endif

	format->methods.reset(db);
	dyna_salt_init(format);

	if ((format->methods.split == fmt_default_split) &&
	    (format->params.flags & FMT_SPLIT_UNIFIES_CASE))
		return "FMT_SPLIT_UNIFIES_CASE";

	if ((format->params.flags & FMT_OMP_BAD) &&
	    !(format->params.flags & FMT_OMP))
		return "FMT_OMP_BAD";

	if ((format->params.flags & FMT_ENC) &&
	    !(format->params.flags & FMT_UNICODE))
		return "FMT_ENC without FMT_UNICODE";

	if ((format->params.flags & FMT_ENC) &&
	    !(format->params.flags & FMT_8_BIT))
		return "FMT_ENC without FMT_8_BIT";

	if ((format->params.flags & FMT_UTF8) &&
	    !(format->params.flags & FMT_8_BIT))
		return "FMT_UTF8 without FMT_8_BIT";

	if ((format->params.flags & FMT_UNICODE) &&
	    !(format->params.flags & FMT_8_BIT))
		return "FMT_UNICODE without FMT_8_BIT";

	if ((format->params.flags & FMT_BLOB) &&
	    (format->params.binary_size != sizeof(fmt_data)))
		return "FMT_BLOB with incorrect binary size";

	if ((format->methods.binary == fmt_default_binary) &&
	    (format->params.binary_size > 0))
		return "Using default binary() with a non-zero BINARY_SIZE";

	if ((format->methods.salt == fmt_default_salt) &&
	    (format->params.salt_size > 0))
		return "Warning: Using default salt() with a non-zero SALT_SIZE";

	if (format->params.min_keys_per_crypt < 1)
		return "min keys per crypt";

	if (format->params.max_keys_per_crypt < 1)
		return "max keys per crypt";

	if (format->params.max_keys_per_crypt <
	    format->params.min_keys_per_crypt)
		return "max < min keys per crypt";

	done = 0;
	index = 0; max = format->params.max_keys_per_crypt;

	do {
		if (strnlen(current->ciphertext, LINE_BUFFER_SIZE) >
		    MAX_CIPHERTEXT_SIZE &&
		    !(format->params.flags & FMT_HUGE_INPUT))
			return "Long test vector ciphertext but no FMT_HUGE_INPUT";

		if (strlen(current->plaintext) > format->params.plaintext_length &&
		    !(format->params.flags & FMT_TRUNC))
			return "Long test vector plaintext but no FMT_TRUNC";

		if (!current->fields[1])
			current->fields[1] = current->ciphertext;
		ciphertext = format->methods.prepare(current->fields, format);
		if (!ciphertext || (strcmp(format->params.label, "plaintext") &&
		                    strlen(ciphertext) < 7))
			return "prepare";
		if (format->methods.valid(ciphertext, format) != 1) {
			snprintf(s_size, sizeof(s_size), "valid (%s)", ciphertext);
			return s_size;
		}

#if !defined(BENCH_BUILD)
		if (extra_tests && !dhirutest++ &&
		    strcmp(format->params.label, "plaintext") &&
		    strcmp(format->params.label, "dummy") &&
		    strcmp(format->params.label, "crypt")) {
			if (*ciphertext == '$') {
				char *p, *k = xstrdup(ciphertext);

				p = k + 1;
				while (*p) {
					if (*p++ == '$') {
						*p = 0;
						// $tag$ only
						if (format->methods.valid(k, format)) {
							snprintf(s_size, sizeof(s_size), "promiscuous valid (%s)", k);
							return s_size;
						}
						*p = '$';
						while (*p)
							*p++ = '$';
						// $tag$$$$$$$$$$$$$$$$$$
						if (format->methods.valid(k, format)) {
							sprintf(s_size, "promiscuous valid");
							return s_size;
						}
						break;
					}
				}
				MEM_FREE(k);
			}
		}
		if (full_lvl >= 0) {
			// numerous tests. We need to 'merge' into 1, probably.
			if (format->methods.split != fmt_default_split) {
				if (!fmt_split_case && format->params.binary_size && is_need_unify_case)
					test_fmt_split_unifies_case_3(format, ciphertext, &is_change_case, &is_need_unify_case);
				test_fmt_split_unifies_case(format, ciphertext, &is_split_unifies_case, cnt_split_unifies_case);
				test_fmt_split_unifies_case_4(format, ciphertext, &is_split_unifies_case_4, cnt_split_unifies_case);
				++cnt_split_unifies_case;
			}
		}
#endif

		ciphertext = format->methods.split(ciphertext, 0, format);
		if (!ciphertext)
			return "split() returned NULL";

		if (format->params.signature[0]) {
			int i, error = 1;
			for (i = 0; i < FMT_SIGNATURES && format->params.signature[i] && error; i++) {
				error = strncmp(ciphertext, format->params.signature[i], strlen(format->params.signature[i]));
			}
			if (error) {
#if DEBUG
				fprintf(stderr, "ciphertext:%s\n", ciphertext);
#endif
				if (format->methods.split == fmt_default_split)
					return "fmt_default_split() doesn't convert raw hashes";
				else
					return "split() doesn't add expected format tag";
			}
		}

		plaintext = current->plaintext;

		if (!sl)
			sl = strlen(plaintext);
/*
 * Make sure the declared binary_size and salt_size are sufficient to actually
 * hold the binary ciphertexts and salts.  We do this by copying the values
 * returned by binary() and salt() only to the declared sizes.
 */
		if (!(binary = format->methods.binary(ciphertext)))
			return "binary() returned NULL";
#if ARCH_ALLOWS_UNALIGNED
		if (mem_saving_level <= 2 || format->params.binary_align >= MEM_ALIGN_SIMD)
#endif
		if (!binary_align_warned &&
			!is_aligned(binary, format->params.binary_align) &&
		    format->params.binary_size > 0) {
			puts("Warning: binary() returned misaligned pointer");
			binary_align_warned = 1;
		}

		/* validate that binary() returns cleaned buffer */
		if (extra_tests && !binary_cleaned_warned && format->params.binary_size) {
			BLOB_FREE(format, binary);
			memset(binary, 0xAF, format->params.binary_size);
			binary = format->methods.binary(ciphertext);
			if (((unsigned char*)binary)[format->params.binary_size-1] == 0xAF)
			{
				BLOB_FREE(format, binary);
				memset(binary, 0xCC, format->params.binary_size);
				binary = format->methods.binary(ciphertext);
				if (((unsigned char*)binary)[format->params.binary_size-1] == 0xCC)
				{
					/* possibly did not clean the binary. */
					puts("Warning: binary() not pre-cleaning buffer");
					binary_cleaned_warned = 1;
				}
			}
			/* Clean up the mess we might have caused */
			BLOB_FREE(format, binary);
			memset(binary, 0, format->params.binary_size);
			binary = format->methods.binary(ciphertext);
		}
		*((char*)binary_copy) = 0;
		if (format->params.binary_size)
			memcpy(binary_copy, binary, format->params.binary_size);
		binary = binary_copy;

		salt = format->methods.salt(ciphertext);
		if (!salt)
			return "salt() returned NULL";
		dyna_salt_create(salt);
#if ARCH_ALLOWS_UNALIGNED
		if (mem_saving_level <= 2 || format->params.salt_align >= MEM_ALIGN_SIMD)
#endif
		if (!salt_align_warned &&
			!is_aligned(salt, format->params.salt_align) &&
		    format->params.salt_size > 0) {
			puts("Warning: salt() returned misaligned pointer");
			salt_align_warned = 1;
		}

		/* validate that salt dupe checks will work */
		if (!salt_dupe_warned && format->params.salt_size) {
			char *copy = mem_alloc(format->params.salt_size);

			memcpy(copy, salt, format->params.salt_size);
			salt = format->methods.salt(ciphertext);
			dyna_salt_create(salt);
			if (dyna_salt_cmp(copy, salt, format->params.salt_size))
			{
				puts("Warning: No dupe-salt detection");
				salt_dupe_warned = 1;
				// These can be useful in tracking down salt
				// dupe problems.
				//fprintf(stderr, "%s\n", ciphertext);
				//dump_stuff(copy, format->params.salt_size);
				//dump_stuff(salt, format->params.salt_size);
			}
			dyna_salt_remove(copy);
			MEM_FREE(copy);
		}

		/* validate that salt() returns cleaned buffer */
		if (extra_tests && !salt_cleaned_warned && format->params.salt_size) {
			if ((format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT) {
				dyna_salt *p1, *p2=0, *p3=0;
				p1 = *((dyna_salt**)salt);
				dyna_salt_smash(salt, 0xAF);
				salt = format->methods.salt(ciphertext);
				dyna_salt_create(salt);
				p2 = *((dyna_salt**)salt);
				if (dyna_salt_smash_check(salt, 0xAF))
				{
					dyna_salt_smash(salt, 0xC3);
					salt = format->methods.salt(ciphertext);
					dyna_salt_create(salt);
					p3 = *((dyna_salt**)salt);
					if (dyna_salt_smash_check(salt, 0xC3)) {
						/* possibly did not clean the salt. */
						puts("Warning: salt() not pre-cleaning buffer");
						salt_cleaned_warned = 1;
					}
				}
				/* Clean up the mess we might have caused */
				dyna_salt_remove(&p1);
				dyna_salt_remove(&p2);
				dyna_salt_remove(&p3);
			} else {
				memset(salt, 0xAF, format->params.salt_size);
				salt = format->methods.salt(ciphertext);
				if (((unsigned char*)salt)[format->params.salt_size-1] == 0xAF)
				{
					memset(salt, 0xC3, format->params.salt_size);
					salt = format->methods.salt(ciphertext);
					if (((unsigned char*)salt)[format->params.salt_size-1] == 0xC3) {
						/* possibly did not clean the salt. */
						puts("Warning: salt() not pre-cleaning buffer");
						salt_cleaned_warned = 1;
					}
				}
				/* Clean up the mess we might have caused */
				memset(salt, 0, format->params.salt_size);
			}
			salt = format->methods.salt(ciphertext);
			dyna_salt_create(salt);
		}

		*((char*)salt_copy) = 0;
		if (format->params.salt_size)
			memcpy(salt_copy, salt, format->params.salt_size);
		salt = salt_copy;

		if (strcmp(ciphertext,
		    format->methods.source(ciphertext, binary)))
			return "source";

		if (format->params.salt_size == 0 &&
		    format->methods.salt_hash(salt))
			return "salt_hash non-zero with salt_size of 0";

		if ((unsigned int)format->methods.salt_hash(salt) >=
		    SALT_HASH_SIZE)
			return "salt_hash";

		format->methods.set_salt(salt);
#ifndef BENCH_BUILD
		if ((format->methods.get_hash[0] != fmt_default_get_hash) &&
		    strlen(ciphertext) > MAX_CIPHERTEXT_SIZE)
			return "Huge ciphertext format can't use get_hash()";

		if ((dbsalt = db->salts))
		do {
			if (!dyna_salt_cmp(salt, dbsalt->salt,
			                   format->params.salt_size))
				break;
		} while ((dbsalt = dbsalt->next));
		if (db->salts && !dbsalt) {
			return "Could not find salt in db - salt() return inconsistent?";
		}
#endif
#ifndef BENCH_BUILD
		if (extra_tests && maxlength == 0) {
			//int min = format->params.min_keys_per_crypt;
			maxlength = 1;

			/* Check that claimed max. length is actually supported:
			   1. Fill the buffer with maximum length keys */
			format->methods.clear_keys();
			for (i = 0; i < max; i++) {
				char *pCand = longcand(format, i, ml);
				fmt_set_key(pCand, i);
			}

#if defined(HAVE_OPENCL)
			advance_cursor();
#endif
			/* 2. Now read them back and verify they are intact */
			for (i = 0; i < max; i++) {
				char *getkey = format->methods.get_key(i);
				char *setkey = longcand(format, i, ml);

				if (!getkey)
					return "get_key() returned NULL";

				if (strncmp(getkey, setkey, ml + 1)) {
					if (strnlen(getkey, ml + 1) > ml)
					sprintf(s_size, "max. length in index "
					        "%d: wrote %d, got longer back",
					        i, ml);
					else
					sprintf(s_size, "max. length in index "
					        "%d: wrote %d, got %d back", i,
					        ml, (int)strlen(getkey));
					fprintf(stderr, "\ngetkey = %s\nsetkey = %s\n", getkey, setkey);

					return s_size;
				}
			}
		}

#endif
		if (full_lvl >= 0) {
#ifndef BENCH_BUILD
			// Test FMT_CASE
			format->methods.clear_keys();
			test_fmt_case(format, binary, ciphertext, plaintext,
				&is_case_sensitive, &plaintext_has_alpha, dbsalt);

			// Test FMT_8_BIT
			format->methods.clear_keys();
			format->methods.set_salt(salt);
			test_fmt_8_bit(format, binary, ciphertext, plaintext,
				&is_ignore_8th_bit, &plaintext_is_blank, dbsalt);
#endif
			format->methods.clear_keys();
			format->methods.set_salt(salt);
			for (i = 0; i < max - 1; i++) {
				char *pCand = longcand(format, i, ml);
				fmt_set_key(pCand, i);
			}
			fmt_set_key(current->plaintext, max - 1);
		} else {
			if (index == 0)
				format->methods.clear_keys();
			fmt_set_key(current->plaintext, index);
		}
#if !defined(BENCH_BUILD) && defined(HAVE_OPENCL)
		advance_cursor();
#endif
		if (full_lvl >= 0) {
#ifndef BENCH_BUILD
			ret = is_key_right(format, max - 1, binary, ciphertext, plaintext, 0, dbsalt);
			BLOB_FREE(format, binary);
			if (ret)
				return ret;
#endif
			format->methods.clear_keys();
			dyna_salt_remove(salt);
			while_condition = (++current)->ciphertext != NULL;
		} else {
#ifndef BENCH_BUILD
			ret = is_key_right(format, index, binary, ciphertext, plaintext, 0, dbsalt);
			BLOB_FREE(format, binary);
			if (ret)
				return ret;
#endif
/* Remove some old keys to better test cmp_all() */
			if (index & 1) {
				format->methods.clear_keys();
				for (i = 0; i <= index; i++)
					fmt_set_key(fmt_null_key, i);
			}

/* 0 1 2 3 4 6 9 13 19 28 42 63 94 141 211 316 474 711 1066 ... */
			if (index >= 2 && max > ntests) {
/* Always call set_key() even if skipping. Some formats depend on it. */
				for (i = index + 1;
				     i < max && i < (index + (index >> 1)); i++)
					fmt_set_key(longcand(format, i, sl), i);
				index = i;
			} else
				index++;

			if (index >= max) {
				format->methods.clear_keys();
				index = (max > 5 && max > ntests && done != 1) ? 5 : 0;
/* Always call set_key() even if skipping. Some formats depend on it. */
				for (i = 0; i < index; i++)
					fmt_set_key(longcand(format, i, sl), i);
				done |= 1;
			}

			if (!(++current)->ciphertext) {
#if defined(HAVE_OPENCL)
/* Jump straight to last index for GPU formats but always call set_key() */
				if (strstr(format->params.label, "-opencl")) {
					for (i = index; i < max - 1; i++)
						fmt_set_key(longcand(format, i, sl), i);
					index = max - 1;
				}
#endif
				current = format->params.tests;
				done |= 2;
			}
			dyna_salt_remove(salt);
			while_condition = done != 3;
		}
	} while (while_condition);

	if (full_lvl >= 0) {
		if (plaintext_has_alpha) {
			if (is_case_sensitive && !(format->params.flags & FMT_CASE)) {
				snprintf(s_size, sizeof(s_size),
					"%s doesn't set FMT_CASE but at least one test-vector is case-sensitive",
					format->params.label);
				return s_size;
			} else if (!is_case_sensitive && (format->params.flags & FMT_CASE)) {
				snprintf(s_size, sizeof(s_size),
					"%s sets FMT_CASE but all test-vectors are case-insensitive",
					format->params.label);
				return s_size;
			}
		}

		if (!plaintext_is_blank) {
			if (!strcmp(format->params.label, "crypt")) {
/*
 * We "can't" reliably know if the underlying system's crypt() is 8-bit or not,
 * and in fact this will vary by actual hash type, of which multiple ones may
 * be loaded at once (with that one format). crypt SHOULD set FMT_8_BIT
 */
				if (!(format->params.flags & FMT_8_BIT)) {
					snprintf(s_size, sizeof(s_size),
						"crypt should set FMT_8_BIT");
					return s_size;
				}
			} else if (!strncasecmp(format->params.label, "wpapsk-pmk", 10)) {
/* WPAPSK-PMK is 64 hex digits */
				if (format->params.flags & FMT_8_BIT) {
					snprintf(s_size, sizeof(s_size),
						"%s should not set FMT_8_BIT",
						format->params.label);
					return s_size;
				}
			} else if (!strncasecmp(format->params.label, "sl3", 3)) {
/*
 * The SL3 format technically handles 8-bit but the "passwords" are all digits.
 */
				if (format->params.flags & FMT_8_BIT) {
					snprintf(s_size, sizeof(s_size),
						"%s should not set FMT_8_BIT",
						format->params.label);
					return s_size;
				}
			} else if (!is_ignore_8th_bit &&
				   !(format->params.flags & FMT_8_BIT)) {
				snprintf(s_size, sizeof(s_size),
					"%s doesn't set FMT_8_BIT but at least one test-vector does not ignore the 8th bit",
					format->params.label);
				return s_size;
			} else if (is_ignore_8th_bit &&
				   (format->params.flags & FMT_8_BIT)) {
				snprintf(s_size, sizeof(s_size),
					"%s sets FMT_8_BIT but all test-vectors ignore the 8th bit",
					format->params.label);
				return s_size;
			}
		}

		switch (is_split_unifies_case) {
			case 1:
				snprintf(s_size, sizeof(s_size), "should set FMT_SPLIT_UNIFIES_CASE");
				return s_size;
			case 2:
				snprintf(s_size, sizeof(s_size), "should not set FMT_SPLIT_UNIFIES_CASE");
				return s_size;
			case 3:
				snprintf(s_size, sizeof(s_size), "split() is only casing sometimes");
				return s_size;
			case 4:
				snprintf(s_size, sizeof(s_size), "split() case, or valid() should fail");
				return s_size;
			case 0:
			case -1:
			default:
				break;
		}
		switch (is_split_unifies_case_4) {
			case 1:
				snprintf(s_size, sizeof(s_size), "should set FMT_SPLIT_UNIFIES_CASE (#4)");
				return s_size;
			case 2:
				snprintf(s_size, sizeof(s_size), "should not set FMT_SPLIT_UNIFIES_CASE (#4)");
				return s_size;
			case 3:
				snprintf(s_size, sizeof(s_size), "split() is only casing sometimes (#4)");
				return s_size;
			case 4:
				snprintf(s_size, sizeof(s_size), "split() case, or valid() should fail (#4)");
				return s_size;
			case 0:
			case -1:
			default:
				break;
		}

		// Currently this code only has false positive failures, so for now, it is comment out.
		// @loverszhaokai needs to look at a re-do of the function.  The 'blind' casing fails
		// when there are constant strings, or things like user names embedded in the hash,
		// or other non-hex strings.
		// Fixed the function,  Dec 13, 2017.  Jfoug.  Changed to function with --test-full=0
		if (full_lvl >= 0)
		if (!fmt_split_case && format->params.binary_size != 0 && is_change_case && is_need_unify_case) {
			snprintf(s_size, sizeof(s_size),
				"should unify cases in split() and set FMT_SPLIT_UNIFIES_CASE (#3)");
			return s_size;
		}
	}

	format->methods.clear_keys();
	format->private.initialized = 2;

	return NULL;
}

#ifndef BENCH_BUILD
static void test_fmt_case(struct fmt_main *format, void *binary,
	char *ciphertext, char* plaintext, int *is_case_sensitive,
	int *plaintext_has_alpha, struct db_salt *dbsalt)
{
	char *plain_copy, *pk;

	if (*plaintext == 0)
		return;

	plain_copy = xstrdup(plaintext);
	pk = plain_copy;

	while (*pk) {
		if (*pk >= 'a' && *pk <= 'z') {
			*pk += 'A' - 'a';
			break;
		} else if (*pk >= 'A' && *pk <= 'Z') {
			*pk += 'a' - 'A';
			break;
		}
		pk++;
	}
	if (*pk == 0)
		goto out;

	*plaintext_has_alpha = 1;
	fmt_set_key(plain_copy, 0);

	if (is_key_right(format, 0, binary, ciphertext, plain_copy, 1, dbsalt))
		*is_case_sensitive = 1;

out:
	MEM_FREE(plain_copy);
}

static void test_fmt_8_bit(struct fmt_main *format, void *binary,
	char *ciphertext, char *plaintext, int *is_ignore_8th_bit,
	int *plaintext_is_blank, struct db_salt *dbsalt)
{
	char *plain_copy, *pk, *ret_all_set, *ret_none_set;

	if (*plaintext == 0)
		return;

	*plaintext_is_blank = 0;
	plain_copy = xstrdup(plaintext);

	// All OR '\x80'
	pk = plain_copy;
	while (*pk) {
		*pk |= '\x80';
		pk++;
	}

	fmt_set_key(plain_copy, 0);
	ret_all_set = is_key_right(format, 0, binary, ciphertext,
	                           plain_copy, 0, dbsalt);

	format->methods.clear_keys();

	// All AND '\x7F'
	pk = plain_copy;
	while (*pk) {
		*pk &= '\x7F';
		pk++;
	}

	fmt_set_key(plain_copy, 0);
	ret_none_set = is_key_right(format, 0, binary, ciphertext,
	                            plain_copy, 0, dbsalt);

	if (ret_all_set != ret_none_set)
		*is_ignore_8th_bit = 0;

	MEM_FREE(plain_copy);
}

static int chrcasecmp(char lc, char rc)
{
	if (lc >= 'a' && lc <= 'z')
		lc += 'A' - 'a';
	if (rc >= 'a' && rc <= 'z')
		rc += 'A' - 'a';
	return lc - rc;
}

/*
 * Since the split() may add prefix or suffix to the original ciphertext, and
 * the split() may truncate the original ciphertext, so we would better get
 * the longest common strings for the ciphertext and the string returned by
 * split(), and check the cases
 */
static void get_longest_common_string(char *fstr, char *sstr, int *first_index,
	int *second_index, int *size)
{
	int fi, si, max, fp, sp, cnt_len, fj, sj;

	fi = si = max = 0;
	fp = sp = 0;

	while (fstr[fi]) {

		si = max;
		while (sstr[si]) {

			if (!chrcasecmp(fstr[fi], sstr[si])) {

				fj = fi - 1;
				sj = si - 1;
				cnt_len = 1;

				while (fj >= 0 && sj >= 0) {
					if (chrcasecmp(fstr[fj], sstr[sj]))
						break;
					cnt_len++;
					fj--;
					sj--;
				}
				if (cnt_len > max) {
					max = cnt_len;
					fp = fi;
					sp = si;
				}
			}
			si++;
		}
		fi++;
	}

	*size = max;
	*first_index = fp - max + 1;
	*second_index = sp - max + 1;
}

/* settings for is_split_unifies_case
 * case -1: casing happening, but every hash has been correct.
 * case 0: no error found (or casing not being used)
 * case 1: "should set FMT_SPLIT_UNIFIES_CASE"
 * case 2: "should not set FMT_SPLIT_UNIFIES_CASE"
 * case 3: "split() is only casing sometimes"
 * case 4: "split() case, or valid() should fail"
 */
static void test_fmt_split_unifies_case(struct fmt_main *format, char *ciphertext, int *is_split_unifies_case, int call_cnt)
{
	char *cipher_copy, *ret, *bin_hex=0, *ret_copy=0;
	void *bin;
	int first_index, second_index, size, index;
	int change_count = 0;
	char fake_user[5] = "john";
	char *flds[10] = {0,0,0,0,0,0,0,0,0,0};

	if (*is_split_unifies_case>2) return; /* already know all we need to know. */

	cipher_copy = xstrdup(ciphertext);

	/*
	 * check for common case problem.  hash is HEX, so find it, change it,
	 * and is there is no split, or split() does not fix it, then check
	 * valid().  If valid allows the hash, THEN we have a #4 problem.
	 */
	flds[0] = fake_user;
	flds[1] = cipher_copy;
	ret = format->methods.prepare(flds, format);
	if (format->methods.valid(ret, format)) {
		char *cp;
		int do_test=0;
		ret = format->methods.split(ret, 0, format);
		ret_copy = xstrdup(ret);
		bin = format->methods.binary(ret_copy);
		if (BLOB_SIZE(format, bin) > 4) {
			bin_hex = mem_alloc(BLOB_SIZE(format, bin) * 2 + 1);
			base64_convert(BLOB_BINARY(format, bin), e_b64_raw,
			               BLOB_SIZE(format, bin), bin_hex, e_b64_hex,
			               BLOB_SIZE(format, bin) * 2 + 1, 0, 0);
			cp = strstr(ret_copy, bin_hex);
			strupr(bin_hex);
			if (cp) {
				do_test |= 1;
				memcpy(cp, bin_hex, strlen(bin_hex));
				/* NOTE, there can be cases where hashes are PURE digits.  Thus, this test can not be used to validate case */
				if (!strcmp(ret, ret_copy))
					do_test &= ~1;
			} else {
				cp = strstr(ret_copy, bin_hex);
				if (cp) {
					do_test |= 1;
					strlwr(bin_hex);
					memcpy(cp, bin_hex, strlen(bin_hex));
					/* NOTE, there can be cases where hashes are PURE digits.  Thus, this test can not be used to validate case */
					if (!strcmp(ret, ret_copy))
						do_test &= ~1;
				}
			}
			MEM_FREE(bin_hex);
		}
		BLOB_FREE(format, bin);
		if (format->params.salt_size>4 && format->params.salt_size < strlen(ret_copy)-10) {
			bin_hex = mem_alloc(format->params.salt_size*2+1);
			bin = format->methods.salt(ret_copy);
			dyna_salt_create(bin);
			base64_convert(bin, e_b64_raw, format->params.salt_size, bin_hex, e_b64_hex, format->params.salt_size*2+1, 0, 0);
			dyna_salt_remove(bin);
			cp = strstr(ret_copy, bin_hex);
			strupr(bin_hex);
			if (cp) {
				do_test |= 2;
				memcpy(cp, bin_hex, strlen(bin_hex));
				/* NOTE, there can be cases where hashes are PURE digits.  Thus, this test can not be used to validate case */
				if (!strcmp(ret, ret_copy))
					do_test &= ~2;
			} else {
				cp = strstr(ret_copy, bin_hex);
				if (cp) {
					do_test |= 2;
					strlwr(bin_hex);
					memcpy(cp, bin_hex, strlen(bin_hex));
					/* NOTE, there can be cases where hashes are PURE digits.  Thus, this test can not be used to validate case */
					if (!strcmp(ret, ret_copy))
						do_test &= ~2;
				}
			}
			MEM_FREE(bin_hex);
		}
		if (!do_test) {
			MEM_FREE(cipher_copy);
			MEM_FREE(ret_copy);
			return;
		}
		ret = format->methods.split(ret_copy, 0, format);
		if (!strcmp(ret_copy, ret)) {
			if (format->methods.valid(ret_copy, format)) {
				/* we have the bug! */
				MEM_FREE(bin_hex);
				MEM_FREE(ret_copy);
				MEM_FREE(cipher_copy);
				if (!strncmp(format->params.label, "@dynamic=", 9))	// white list this one.
					*is_split_unifies_case = 4;
				return;
			}
		}
	}


	ret = format->methods.split(cipher_copy, 0, format);
	if (strcmp(cipher_copy, ret)) {
		get_longest_common_string(cipher_copy, ret, &first_index,
			&second_index, &size);
		if (strncmp(cipher_copy + first_index, ret + second_index, size))
			goto change_case;
	}
/*
 * Find the second '$' if the ciphertext begins with '$'. We shoud not change the
 * cases between the first and the second '$', since the string is format label
 * and split() may check it
 */
	index = 0;
	if (cipher_copy[0] == '$') {
		index = 1;
		while (cipher_copy[index] && cipher_copy[index] != '$')
			index++;
	}
	if (!index && !strncmp(cipher_copy, "@dynamic=", 9)) {
		index = 1;
		while (cipher_copy[index] && cipher_copy[index] != '@')
			index++;
	}

	/* Lower case */
	strlwr(cipher_copy + index);
	if (strcmp(cipher_copy + index, ciphertext + index))
		++change_count;
	ret = format->methods.split(cipher_copy, 0, format);
	if (strcmp(cipher_copy, ret)) {
		get_longest_common_string(cipher_copy, ret, &first_index,
			&second_index, &size);
		if (strncmp(cipher_copy + first_index, ret + second_index, size))
			goto change_case;
	}

	/* Upper case */
	strupr(cipher_copy + index);
	if (strcmp(cipher_copy + index, ciphertext + index))
		++change_count;
	ret = format->methods.split(cipher_copy, 0, format);
	if (strcmp(cipher_copy, ret)) {
		get_longest_common_string(cipher_copy, ret, &first_index,
			&second_index, &size);
		if (strncmp(cipher_copy + first_index, ret + second_index, size))
			goto change_case;
	}

	MEM_FREE(ret_copy);
	MEM_FREE(cipher_copy);
	if (!change_count && strncmp(format->params.label, "@dynamic=", 9)) // white list this one.
		*is_split_unifies_case = 2;
	else
		*is_split_unifies_case = 0;
	return;

change_case:
	MEM_FREE(ret_copy);
	MEM_FREE(cipher_copy);
	if (strncmp(format->params.label, "@dynamic=", 9)) // white list this one.
		return;
	if (call_cnt == 0)
		*is_split_unifies_case = -1;
	else if (*is_split_unifies_case != -1)
		*is_split_unifies_case = 3;
	return;
}

/*
 * This function is to detect whether the format need to unify cases in split()
 * and add FMT_SPLIT_UNIFIES_CASE
 *
 *  NOTE, I think this test is NOT valid!  The 'results' of this function are
 *        currently not being listed to screen.  Right now, there is a handful
 *        of failures, and every one of them is a false-positive.
 */
static void test_fmt_split_unifies_case_3(struct fmt_main *format,
	char *ciphertext, int *has_change_case, int *is_need_unify_case)
{
	char *cipher_copy, *split_ret;
	int index;
	void *orig_binary, *orig_salt;
	void *binary, *salt;

	cipher_copy = xstrdup(ciphertext);
	split_ret = format->methods.split(cipher_copy, 0, format);

	orig_binary = NULL;
	orig_salt = NULL;

	binary = format->methods.binary(split_ret);
	if (binary) {
		orig_binary = mem_alloc(BLOB_SIZE(format, binary));
		memcpy(orig_binary, BLOB_BINARY(format, binary),
		       BLOB_SIZE(format, binary));

		salt = format->methods.salt(split_ret);
		dyna_salt_create(salt);
		if (salt && format->params.salt_size) {
			orig_salt = mem_alloc(format->params.salt_size);
			memcpy(orig_salt, salt, format->params.salt_size);
		}
		dyna_salt_remove(salt);
		BLOB_FREE(format, binary);
	}

/*
 * Find the second '$' if the ciphertext begins with '$'. We shoud not change the
 * cases between the first and the second '$', since the string is format label
 * and split() may check it
 */
	index = 0;
	if (cipher_copy[0] == '$') {
		index = 1;
		while (cipher_copy[index] && cipher_copy[index] != '$')
			index++;
	}
	if (!index && !strncmp(cipher_copy, "@dynamic=", 9)) {
		index = 1;
		while (cipher_copy[index] && cipher_copy[index] != '@')
			index++;
	}

	// Lower case
	strlwr(cipher_copy + index);

	if (strcmp(cipher_copy, ciphertext)) {
		if (format->methods.valid(cipher_copy, format)) {

			*has_change_case = 1;
			split_ret = format->methods.split(cipher_copy, 0, format);
			if (!strcmp(split_ret, ciphertext))
				*is_need_unify_case = 0;
			binary = format->methods.binary(split_ret);

			if (binary && fmt_bincmp(orig_binary, binary, format)) {
				// Do not need to unify cases in split() and add
				// FMT_SPLIT_UNIFIES_CASE
				*is_need_unify_case = 0;
			}
			BLOB_FREE(format, binary);
		} else
			*is_need_unify_case = 0;
	}

	// Upper case
	strupr(cipher_copy + index);

	if (strcmp(cipher_copy, ciphertext)) {
		if (format->methods.valid(cipher_copy, format)) {

			*has_change_case = 1;
			split_ret = format->methods.split(cipher_copy, 0, format);
			if (!strcmp(split_ret, ciphertext))
				*is_need_unify_case = 0;
			binary = format->methods.binary(split_ret);

			if (binary && fmt_bincmp(orig_binary, binary, format)) {
				// Do not need to unify cases in split() and add
				// FMT_SPLIT_UNIFIES_CASE
				*is_need_unify_case = 0;
			}
			BLOB_FREE(format, binary);
		} else
			*is_need_unify_case = 0;
	}

	MEM_FREE(orig_salt);
	MEM_FREE(orig_binary);
	MEM_FREE(cipher_copy);
}

static int is_known_len(int len) {
	switch (len) {
		case 16: case 24: case 28: case 32:
		case 40: case 48: case 56: case 64:
		case 72: case 84: case 96: case 112: case 128:
			return 1;
		default:
			if (len&1)
				return 0;
			if (len > 128)
				return 1;
	}
	return 0;
}

static void test_fmt_split_unifies_case_4(struct fmt_main *format, char *ciphertext, int *is_split_unifies_case, int call_cnt)
{
	char *cipher_copy, *ret, *ret_copy=0, *ret_fix;
	int change_count = 0, i;
	char fake_user[5] = "john";
	char *flds[10] = {0,0,0,0,0,0,0,0,0,0};
	static unsigned char case_hex_chars[256], case_hex_init=0;

	if (!case_hex_init) {
		case_hex_init = 1;
		memset(case_hex_chars, 0, sizeof(case_hex_chars));
		for (i = '0'; i <= '9'; ++i) case_hex_chars[i] = 1;	// 'bits'
		for (i = 'a'; i <= 'f'; ++i) case_hex_chars[i] = 2;
		for (i = 'A'; i <= 'F'; ++i) case_hex_chars[i] = 4;
	}

	if (*is_split_unifies_case>2) return; /* already know all we need to know. */

	cipher_copy = xstrdup(ciphertext);

	/*
	 * check for common case problem, but in a 'generic' manner. Here, we find sets of
	 * data that are 'hex-like'. All one case, not pure digits, AND of a 'known' expected length. The
	 * lengths we care about are:  16, 24, 28, 32, 40, 48, 56, 64, 72, 80, 96, 112, 128
	 * and even length strings > 128 bytes (which are likely data blobs).  When we find strings
	 * this length, we mangle them, and see if the format fixes them, or rejects them.  If the format
	 * neither fixes and does not reject the hash, then we return 'error'
	 */
	flds[0] = fake_user;
	flds[1] = cipher_copy;
	ret = format->methods.prepare(flds, format);
	if (format->methods.valid(ret, format)) {
		char *cp;
		ret = format->methods.split(ret, 0, format);
		ret_copy = xstrdup(ret);
		// Ok, now walk the string, LOOKING for hex string or known lengths which are all 1 case, and NOT pure numeric
		cp = ret_copy;
		while (strlen(cp) > 16) {
			if (case_hex_chars[ARCH_INDEX(*cp)]) {
				unsigned cnt = 1, vals=case_hex_chars[ARCH_INDEX(*cp)];
				char *cp2 = cp+1;
				while (case_hex_chars[ARCH_INDEX(*cp2)]) {
					++cnt;
					vals |= case_hex_chars[ARCH_INDEX(*cp2)];
					++cp2;
				}
				if ( ((vals&6) == 2 || (vals&6) == 4) && is_known_len(cnt)) {
					// Ok, we have 'found' a hex block of a 'known' length.
					// Flip the case, and see if split() returns it to cannonical
					// or if valid says not valid.  If either of those happen, then
					// we do not have the bug. If both fail, then we flag this format
					// as HAVING the bug (possibly having the bug, but we report it).
					int good = 0;
					while (cp < cp2) {
						if (*cp < '0' || *cp > '9')
							*cp ^= 0x20;
						++cp;
					}
					ret_fix = format->methods.split(ret_copy, 0, format);
					if (!strcmp(ret_fix, ret))
						good = 1;
					else if (!format->methods.valid(ret_fix, format))
						good = 1;
					if (!good) {
						// white list.
						if (!strncmp(ret, "@dynamic=", 9) || strstr(ret, "$HEX$") ||
						    (ret[0]=='$'&&ret[1]=='2'&&ret[3]=='$'&& (ret[2]=='a'||ret[2]=='b'||ret[2]=='x'||ret[2]=='y') ) )
						{
						} else
							goto change_case;
					}
				}
				cp = cp2;
			}
			else
				++cp;
		}
	}

	MEM_FREE(cipher_copy);
	MEM_FREE(ret_copy);
	if (call_cnt == 0)
		*is_split_unifies_case = -1;
	else if (*is_split_unifies_case != -1)
		*is_split_unifies_case = 3;
	return;

change_case:
	MEM_FREE(ret_copy);
	MEM_FREE(cipher_copy);
	if (!change_count)
		*is_split_unifies_case = 2;
	else
		*is_split_unifies_case = 0;
	return;
}

static char *test_fmt_tunable_costs( struct fmt_main *format)
{
	int i, j;
	char *name;

	for (i = 0; i < FMT_TUNABLE_COSTS; i++) {
		if ((name = format->params.tunable_cost_name[i])) {
			if (!format->methods.tunable_cost_value[i])
				return "more tunable cost names than methods";
			for (j = 0; name[j] != '\0'; j++)
				if (name[j] == ',')
					return "tunable cost name contains commas";
			if (j == 0)
				return "empty tunable cost name";

		}
		else if (format->methods.tunable_cost_value[i])
			return "more tunable cost methods than names";
	}
	return NULL;
}
#endif

/*
 * Allocate memory for a copy of a binary ciphertext or salt with only the
 * minimum guaranteed alignment.  We do this to test that binary_hash*(),
 * cmp_*(), and salt_hash() do accept such pointers.
 */
static void *alloc_binary(void **alloc, size_t size, size_t align)
{
	size_t mask = align - 1;
	char *p;

/* Ensure minimum required alignment and leave room for "align" bytes more */
	p = *alloc = mem_alloc(size + mask + align);
	p += mask;
	p -= (size_t)p & mask;

/* If the alignment is too great, reduce it to the minimum */
	if (!((size_t)p & align))
		p += align;

	return p;
}

char *fmt_self_test(struct fmt_main *format, struct db_main *db)
{
	char *retval;
	void *binary_alloc, *salt_alloc;
	void *binary_copy, *salt_copy;

	binary_copy = alloc_binary(&binary_alloc,
	    format->params.binary_size?format->params.binary_size:1, format->params.binary_align);
	salt_copy = alloc_binary(&salt_alloc,
	    format->params.salt_size?format->params.salt_size:1, format->params.salt_align);

	self_test_running = 1;

	retval = fmt_self_test_body(format, binary_copy, salt_copy, db, benchmark_level);

	self_test_running = 0;

	MEM_FREE(salt_alloc);
	MEM_FREE(binary_alloc);

	return retval;
}

void fmt_default_init(struct fmt_main *self)
{
}

void fmt_default_done(void)
{
}

void fmt_default_reset(struct db_main *db)
{
}

char *fmt_default_prepare(char *fields[10], struct fmt_main *self)
{
	return fields[1];
}

char *fmt_default_split(char *ciphertext, int index, struct fmt_main *self)
{
	return ciphertext;
}

void *fmt_default_binary(char *ciphertext)
{
	return ciphertext;
}

void *fmt_default_salt(char *ciphertext)
{
	return ciphertext;
}

char *fmt_default_source(char *source, void *binary)
{
	return source;
}

int fmt_default_binary_hash(void *binary)
{
	return 0;
}

int fmt_default_binary_hash_0(void * binary)
{
	return *(uint32_t *) binary & PH_MASK_0;
}

int fmt_default_binary_hash_1(void * binary)
{
	return *(uint32_t *) binary & PH_MASK_1;
}

int fmt_default_binary_hash_2(void * binary)
{
	return *(uint32_t *) binary & PH_MASK_2;
}

int fmt_default_binary_hash_3(void * binary)
{
	return *(uint32_t *) binary & PH_MASK_3;
}

int fmt_default_binary_hash_4(void * binary)
{
	return *(uint32_t *) binary & PH_MASK_4;
}

int fmt_default_binary_hash_5(void * binary)
{
	return *(uint32_t *) binary & PH_MASK_5;
}

int fmt_default_binary_hash_6(void * binary)
{
	return *(uint32_t *) binary & PH_MASK_6;
}

int fmt_default_salt_hash(void *salt)
{
	return 0;
}

int fmt_default_dyna_salt_hash(void *salt)
{
	/* if the hash is a dyna_salt type hash, it can simply use this function */
	dyna_salt_john_core *mysalt = *(dyna_salt_john_core **)salt;
	unsigned v;
	int i;
	unsigned char *p;

	p = (unsigned char*)mysalt;
	p += mysalt->dyna_salt.salt_cmp_offset;
#ifdef DYNA_SALT_DEBUG
	dump_stuff_msg((void*)__FUNCTION__, p, mysalt->dyna_salt.salt_cmp_size>48?48:mysalt->dyna_salt.salt_cmp_size);
	fprintf(stderr, "fmt_default_dyna_salt_hash(): cmp size %u\n", (unsigned)mysalt->dyna_salt.salt_cmp_size);
#endif
	v = 0;
	for (i = 0; i < mysalt->dyna_salt.salt_cmp_size; ++i) {
		v *= 11;
		v += *p++;
	}
#ifdef DYNA_SALT_DEBUG
	fprintf(stderr, "fmt_default_dyna_salt_hash(): return %d\n", v & (SALT_HASH_SIZE - 1));
#endif
	return v & (SALT_HASH_SIZE - 1);
}

void fmt_default_set_salt(void *salt)
{
}

void fmt_default_clear_keys(void)
{
}

int fmt_default_get_hash(int index)
{
	return 0;
}

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006,2008,2010,2011 by Solar Designer
 *
 * ...with a change in the jumbo patch, by JimF
 */

#include <stdio.h>
#include <string.h>

#include "params.h"
#include "formats.h"
#ifndef BENCH_BUILD
#include "options.h"
#endif
#ifdef HAVE_OPENCL
#include "common-opencl.h"
#endif

struct fmt_main *fmt_list = NULL;
static struct fmt_main **fmt_tail = &fmt_list;

extern volatile int bench_running;

#if defined(DEBUG) && !defined(BENCH_BUILD)
/* We could move this to misc.c */
static size_t fmt_strnlen(const char *s, size_t max) {
    const char *p=s;
    while(*p && max--)
		++p;
    return(p - s);
}
#endif

void fmt_register(struct fmt_main *format)
{
	format->private.initialized = 0;
	format->next = NULL;
	*fmt_tail = format;
	fmt_tail = &format->next;
}

void fmt_init(struct fmt_main *format)
{
	if (!format->private.initialized) {
		format->methods.init(format);
		format->private.initialized = 1;
	}
#ifndef BENCH_BUILD
	if (options.force_maxkeys) {
		if (options.force_maxkeys <= format->params.max_keys_per_crypt)
			format->params.min_keys_per_crypt =
				format->params.max_keys_per_crypt =
				options.force_maxkeys;
		else {
			fprintf(stderr, "Can't set mkpc larger than %u for %s format\n", format->params.max_keys_per_crypt, format->params.label);
			error();
		}
	}
	if (options.force_maxlength) {
		if (options.force_maxlength <= format->params.plaintext_length)
			format->params.plaintext_length =
				options.force_maxlength;
		else {
			fprintf(stderr, "Can't set max length larger than %u for %s format\n", format->params.plaintext_length, format->params.label);
			error();
		}
	}
#endif
}

/* Mutes ASAN problems. We pass a buffer long enough for any use */
#define fmt_set_key(key, index)	  \
	{ \
		static char buf_key[PLAINTEXT_BUFFER_SIZE]; \
		strncpy(buf_key, key, sizeof(buf_key)); \
		format->methods.set_key(buf_key, index); \
	}

char *fmt_self_test(struct fmt_main *format)
{
	static char s_size[128];
	struct fmt_tests *current;
	char *ciphertext, *plaintext;
	int i, ntests, done, index, max, size;
	void *binary, *salt;
#if defined(DEBUG) && !defined(BENCH_BUILD)
	int binary_size_warned = 0, salt_size_warned = 0;
	int validkiller = 0;
	int lengthcheck = 0;
	int ml = format->params.plaintext_length;
	char longcand[PLAINTEXT_BUFFER_SIZE + 1];

	/* UTF-8 bodge in reverse */
	if ((options.utf8) && (format->params.flags & FMT_UTF8) &&
	    (format->params.flags & FMT_UNICODE))
		ml /= 3;
#endif

	if (format->params.plaintext_length > PLAINTEXT_BUFFER_SIZE - 3)
		return "length";

/*
 * Test each format just once unless we're debugging.
 */
#ifndef DEBUG
	if (format->private.initialized == 2)
		return NULL;
#endif

	if (format->methods.valid("*",format)) return "valid";

	fmt_init(format);

	if ((format->methods.split == fmt_default_split) &&
	    (format->params.flags & FMT_SPLIT_UNIFIES_CASE))
		return "FMT_SPLIT_UNIFIES_CASE";

#if DEBUG
	/* These conditions do not necessarily mean we have a bug */
	if ((format->methods.binary == fmt_default_binary) &&
	    (format->params.binary_size > 0) && !binary_size_warned) {
		binary_size_warned = 1;
		puts("Warning: Using default binary() with a non-zero BINARY_SIZE");
	}

	if ((format->methods.salt == fmt_default_salt) &&
	    (format->params.salt_size > 0) && !salt_size_warned) {
		salt_size_warned = 1;
		puts("Warning: Using default salt() with a non-zero SALT_SIZE");
	}
#endif

	if (!(current = format->params.tests)) return NULL;
	ntests = 0;
	while ((current++)->ciphertext)
		ntests++;
	current = format->params.tests;
	if (ntests==0) return NULL;

	/* We use this to keep opencl_process_event() from doing stuff
	 * while self-test is running. */
	bench_running = 1;

	done = 0;
	index = 0; max = format->params.max_keys_per_crypt;
	do {
		char *prepared;
		current->flds[1] = current->ciphertext;
		prepared = format->methods.prepare(current->flds, format);
		if (!prepared || strlen(prepared) < 7) // $dummy$ can be just 7 bytes long.
			return "prepare";
		if (format->methods.valid(prepared,format) != 1)
			return "valid";

#if defined(DEBUG) && !defined(BENCH_BUILD)
		if (validkiller == 0) {
			char *killer = strdup(prepared);

			validkiller = 1;
			for (i = strlen(killer) - 1; i > 0; i--) {
				killer[i] = 0;
				format->methods.valid(killer, format);
			}
			MEM_FREE(killer);
		}
#endif

		ciphertext = format->methods.split(prepared, 0);
		plaintext = current->plaintext;

		binary = format->methods.binary(ciphertext);
		salt = format->methods.salt(ciphertext);

		if ((unsigned int)format->methods.salt_hash(salt) >=
		    SALT_HASH_SIZE)
			return "salt_hash";

		format->methods.set_salt(salt);

#if defined(DEBUG) && !defined(BENCH_BUILD)
		/* Check that claimed maxlength is actually supported */
		/* This version is for max == 1, other version below */
		if (lengthcheck == 0 && max == 1) {
			lengthcheck = 2;

			/* Fill the buffer with maximum length key */
			memset(longcand, 'A', ml);
			longcand[ml] = 0;
			format->methods.set_key(longcand, index);

			format->methods.crypt_all(index + 1);

			/* Now read it back and verify it's intact */
			if (strncmp(format->methods.get_key(index),
			            longcand, ml + 1)) {
				if (fmt_strnlen(format->methods.get_key(index), ml + 1) > ml)
					sprintf(s_size, "max. length in index %d: wrote %d, got longer back", index, ml);
				else
					sprintf(s_size, "max. length in index %d: wrote %d, got %d back", index, ml, (int)strlen(format->methods.get_key(index)));
				return s_size;
			}
		}
		if (lengthcheck == 3 && index == 2) {
			format->methods.clear_keys();
			for (i = 0; i < 2; i++)
				fmt_set_key("", i);
		}
#endif
		if (index == 0)
			format->methods.clear_keys();
		fmt_set_key(current->plaintext, index);

#if defined(DEBUG) && !defined(BENCH_BUILD)
		/* Check that claimed maxlength is actually supported */
		/* This version is for max > 1 */
		/* Part 1: Fill the buffer with maximum length keys */
		if (index == 1 && lengthcheck == 0 && max > 1) {
			lengthcheck = 1;

			format->methods.clear_keys();
			for (i = 0; i < max; i++) {
				if (i == index) {
					fmt_set_key(
						current->plaintext, index);
				}
				else {
					memset(longcand, 'A' + (i % 23), ml);
					longcand[ml] = 0;
					format->methods.set_key(longcand, i);
				}
			}
		}
#endif
#ifdef HAVE_OPENCL
		advance_cursor();
#endif
#if defined(DEBUG) && !defined(BENCH_BUILD)
		if (lengthcheck == 1)
			format->methods.crypt_all(max);
		else
#endif
			format->methods.crypt_all(index + 1);

#if defined(DEBUG) && !defined(BENCH_BUILD)
		/* Check that claimed maxlength is actually supported */
		/* Part 2: Now read them back and verify they are intact */
		if (index == 1 && lengthcheck == 1 && max > 1) {
			lengthcheck = 3;

			for (i = 0; i < max; i++) {
				if (i == index) continue;
				memset(longcand, 'A' + (i % 23), ml);
				longcand[ml] = 0;
				if (strncmp(format->methods.get_key(i),
				            longcand, ml + 1)) {
					if (fmt_strnlen(format->methods.get_key(i), ml + 1) > ml)
						sprintf(s_size, "max. length in index %d: wrote %d, got longer back", i, ml);
					else
						sprintf(s_size, "max. length in index %d: wrote %d, got %d back", i, ml, (int)strlen(format->methods.get_key(i)));
					return s_size;
				}
			}
		}
#endif
		for (size = 0; size < PASSWORD_HASH_SIZES; size++)
		if (format->methods.binary_hash[size] &&
		    format->methods.get_hash[size](index) !=
		    format->methods.binary_hash[size](binary)) {
			sprintf(s_size, "get_hash[%d](%d)", size, index);
			return s_size;
		}

		if (!format->methods.cmp_all(binary, index + 1)) {
			sprintf(s_size, "cmp_all(%d)", index + 1);
			return s_size;
		}
		if (!format->methods.cmp_one(binary, index)) {
			sprintf(s_size, "cmp_one(%d)", index);
			return s_size;
		}
		if (!format->methods.cmp_exact(ciphertext, index)) {
			sprintf(s_size, "cmp_exact(%d)", index);
			return s_size;
		}
		if (strncmp(format->methods.get_key(index), plaintext, format->params.plaintext_length)) {
			sprintf(s_size, "get_key(%d)", index);
			return s_size;
		}

/* Remove some old keys to better test cmp_all() */
		if (index & 1)
			fmt_set_key("", index);

/* 0 1 2 3 4 6 9 13 19 28 42 63 94 141 211 316 474 711 1066 ... */
		if (index >= 2 && max > ntests) {
			/* Always call set_key() even if skipping. Some
			   formats depend on it */
			for (i = index;
			     i < max && i < (index + (index >> 1)); i++)
				fmt_set_key("", i);
			index = i;
		} else
			index++;

		if (index >= max) {
			index = (max > 5 && max > ntests && done != 1) ? 5 : 0;
			done |= 1;
		}

		if (!(++current)->ciphertext) {
/* Jump straight to last index for non-bitslice DES */
			if (!(format->params.flags & FMT_BS) &&
			    (!strcmp(format->params.label, "des") ||
			    !strcmp(format->params.label, "bsdi") ||
			    !strcmp(format->params.label, "afs")))
				index = max - 1;

			current = format->params.tests;
			done |= 2;
		}
	} while (done != 3);

	bench_running = 0;

	format->methods.clear_keys();
	format->private.initialized = 2;

	return NULL;
}

void fmt_default_init(struct fmt_main *self)
{
}

char *fmt_default_prepare(char *split_fields[10], struct fmt_main *self)
{
	return split_fields[1];
}

int fmt_default_valid(char *ciphertext, struct fmt_main *self)
{
	return 0;
}

char *fmt_default_split(char *ciphertext, int index)
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

int fmt_default_binary_hash(void *binary)
{
	return 0;
}

int fmt_default_salt_hash(void *salt)
{
	return 0;
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

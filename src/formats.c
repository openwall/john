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

struct fmt_main *fmt_list = NULL;
static struct fmt_main **fmt_tail = &fmt_list;

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
			fprintf(stderr, "Can't set length larger than %u for %s format\n", format->params.plaintext_length, format->params.label);
			error();
		}
	}
#endif
}

char *fmt_self_test(struct fmt_main *format)
{
	static char s_size[32];
	struct fmt_tests *current;
	char *ciphertext, *plaintext;
	int ntests, done, index, max, size;
	void *binary, *salt;

	if (format->params.plaintext_length > PLAINTEXT_BUFFER_SIZE - 3)
		return "length";

	if (format->methods.valid("*",format)) return "valid";

	fmt_init(format);

	if (!(current = format->params.tests)) return NULL;
	ntests = 0;
	while ((current++)->ciphertext)
		ntests++;
	current = format->params.tests;
	if (ntests==0) return NULL;

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
		ciphertext = format->methods.split(prepared, 0);
		plaintext = current->plaintext;

		binary = format->methods.binary(ciphertext);
		salt = format->methods.salt(ciphertext);

		if ((unsigned int)format->methods.salt_hash(salt) >=
		    SALT_HASH_SIZE)
			return "salt_hash";

		format->methods.set_salt(salt);
		if (index == 0)
			format->methods.clear_keys();
		format->methods.set_key(current->plaintext, index);

		format->methods.crypt_all(index + 1);

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
			format->methods.set_key("", index);

/* 0 1 2 3 4 6 9 13 19 28 42 63 94 141 211 316 474 711 1066 ... */
		if (index >= 2 && max > ntests)
			index += index >> 1;
		else
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

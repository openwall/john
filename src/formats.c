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
	if (options.mkpc) {
		if (options.mkpc <= format->params.max_keys_per_crypt)
			format->params.min_keys_per_crypt =
				format->params.max_keys_per_crypt =
				options.mkpc;
		else {
			fprintf(stderr, "Can't set mkpc larger than %u for %s format\n", format->params.max_keys_per_crypt, format->params.label);
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

	// validate that there are no NULL function pointers
	if (format->methods.init == NULL)       return "method init NULL";
	if (format->methods.prepare == NULL)    return "method prepare NULL";
	if (format->methods.valid == NULL)      return "method valid NULL";
	if (format->methods.split == NULL)      return "method split NULL";
	if (format->methods.binary == NULL)     return "method binary NULL";
	if (format->methods.salt == NULL)       return "method salt NULL";
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
	if (format->methods.get_source == NULL) return "method get_source NULL";

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
		char *prepared, *sourced, Buf[LINE_BUFFER_SIZE];
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
		if (format->methods.get_source != fmt_default_get_source) {
			sourced = format->methods.get_source(binary, salt, Buf);
			if (strcmp(sourced, prepared))
				return "get_source";
		}

		if ((unsigned int)format->methods.salt_hash(salt) >=
		    SALT_HASH_SIZE)
			return "salt_hash";

		format->methods.set_salt(salt);
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

void fmt_default_init(struct fmt_main *pFmt)
{
}

char *fmt_default_prepare(char *split_fields[10], struct fmt_main *pFmt)
{
	return split_fields[1];
}

int fmt_default_valid(char *ciphertext, struct fmt_main *pFmt)
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

char *fmt_default_get_source(void *binary_hash, void *salt, char ReturnBuf[LINE_BUFFER_SIZE]) 
{
	*ReturnBuf = 0;
	return ReturnBuf;
}

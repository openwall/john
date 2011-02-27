/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006,2008,2010,2011 by Solar Designer
 */

#include <stdio.h>
#include <string.h>

#include "params.h"
#include "formats.h"

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
		format->methods.init();
		format->private.initialized = 1;
	}
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

	if (format->methods.valid("*")) return "valid";

	fmt_init(format);

	if (!(current = format->params.tests)) return NULL;
	ntests = 0;
	while ((current++)->ciphertext)
		ntests++;
	current = format->params.tests;

	done = 0;
	index = 0; max = format->params.max_keys_per_crypt;
	do {
		if (format->methods.valid(current->ciphertext) != 1)
			return "valid";
		ciphertext = format->methods.split(current->ciphertext, 0);
		plaintext = current->plaintext;

		binary = format->methods.binary(ciphertext);
		salt = format->methods.salt(ciphertext);

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

		if (!format->methods.cmp_all(binary, index + 1))
			return "cmp_all";
		if (!format->methods.cmp_one(binary, index))
			return "cmp_one";
		if (!format->methods.cmp_exact(ciphertext, index))
			return "cmp_exact";

		if (strncmp(format->methods.get_key(index), plaintext,
		    format->params.plaintext_length))
			return "get_key";

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

void fmt_default_init(void)
{
}

int fmt_default_valid(char *ciphertext)
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

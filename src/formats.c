/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006,2008,2010 by Solar Designer
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
	int done, index, max, size;
	void *binary, *salt;

	if (format->params.plaintext_length > PLAINTEXT_BUFFER_SIZE - 3)
		return "length";

	if (format->methods.valid("*")) return "valid";

	fmt_init(format);

	if (!(current = format->params.tests)) return NULL;

	done = 0;
	index = 0; max = format->params.max_keys_per_crypt;
	if (max > 2 && !(format->params.flags & FMT_BS)) max = 2;
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

		index = (index << 1) + 1; /* 0, 1, 3, 7, 15, 31, 63, ... */
		if (index >= max) {
			index = 0;
			done |= 1;
		}

		if (!(++current)->ciphertext) {
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

void fmt_default_clear_keys(void)
{
}

int fmt_default_get_hash(int index)
{
	return 0;
}

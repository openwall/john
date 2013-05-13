/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006,2008,2010-2013 by Solar Designer
 */

#include <stdio.h>
#include <string.h>

#include "params.h"
#include "memory.h"
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
		format->methods.init(format);
		format->private.initialized = 1;
	}
}

void fmt_done(struct fmt_main *format)
{
	if (format->private.initialized) {
		format->methods.done();
		format->private.initialized = 0;
	}
}

static int is_poweroftwo(size_t align)
{
	return align != 0 && (align & (align - 1)) == 0;
}

static int is_aligned(void *p, size_t align)
{
	return ((size_t)p & (align - 1)) == 0;
}

static char *fmt_self_test_body(struct fmt_main *format,
    void *binary_copy, void *salt_copy)
{
	static char s_size[32];
	struct fmt_tests *current;
	char *ciphertext, *plaintext;
	int ntests, done, index, max, size;
	void *binary, *salt;
	int binary_align_warned = 0, salt_align_warned = 0;

/*
 * Test each format just once unless we're debugging.
 */
#ifndef DEBUG
	if (format->private.initialized == 2)
		return NULL;
#endif

	if (format->params.plaintext_length < 1 ||
	    format->params.plaintext_length > PLAINTEXT_BUFFER_SIZE - 3)
		return "plaintext_length";

	if (!is_poweroftwo(format->params.binary_align))
		return "binary_align";

	if (!is_poweroftwo(format->params.salt_align))
		return "salt_align";

	if (format->methods.valid("*", format))
		return "valid";

	fmt_init(format);

	format->methods.reset(NULL);

	if (!(current = format->params.tests)) return NULL;
	ntests = 0;
	while ((current++)->ciphertext)
		ntests++;
	current = format->params.tests;

	done = 0;
	index = 0; max = format->params.max_keys_per_crypt;
	do {
		if (!current->fields[1])
			current->fields[1] = current->ciphertext;
		ciphertext = format->methods.prepare(current->fields, format);
		if (!ciphertext || strlen(ciphertext) < 7)
			return "prepare";
		if (format->methods.valid(ciphertext, format) != 1)
			return "valid";
		ciphertext = format->methods.split(ciphertext, 0, format);
		plaintext = current->plaintext;

/*
 * Make sure the declared binary_size and salt_size are sufficient to actually
 * hold the binary ciphertexts and salts.  We do this by copying the values
 * returned by binary() and salt() only to the declared sizes.
 */
		binary = format->methods.binary(ciphertext);
		if (!is_aligned(binary, format->params.binary_align) &&
		    !binary_align_warned) {
			puts("Warning: binary() returned misaligned pointer");
			binary_align_warned = 1;
		}
		memcpy(binary_copy, binary, format->params.binary_size);
		binary = binary_copy;

		salt = format->methods.salt(ciphertext);
		if (!is_aligned(salt, format->params.salt_align) &&
		    !salt_align_warned) {
			puts("Warning: salt() returned misaligned pointer");
			salt_align_warned = 1;
		}
		memcpy(salt_copy, salt, format->params.salt_size);
		salt = salt_copy;

		if (strcmp(ciphertext,
		    format->methods.source(ciphertext, binary)))
			return "source";

		if ((unsigned int)format->methods.salt_hash(salt) >=
		    SALT_HASH_SIZE)
			return "salt_hash";

		format->methods.set_salt(salt);
		format->methods.set_key(current->plaintext, index);

		{
			int count = index + 1;
			int match = format->methods.crypt_all(&count, NULL);
/* If salt is NULL, the return value must always match *count the way it is
 * after the crypt_all() call. */
			if (match != count)
				return "crypt_all";
		}

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

	format->private.initialized = 2;

	return NULL;
}

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

char *fmt_self_test(struct fmt_main *format)
{
	char *retval;
	void *binary_alloc, *salt_alloc;
	void *binary_copy, *salt_copy;

	binary_copy = alloc_binary(&binary_alloc,
	    format->params.binary_size, format->params.binary_align);
	salt_copy = alloc_binary(&salt_alloc,
	    format->params.salt_size, format->params.salt_align);

	retval = fmt_self_test_body(format, binary_copy, salt_copy);

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

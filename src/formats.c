/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006,2008,2010-2012 by Solar Designer
 *
 * ...with a change in the jumbo patch, by JimF
 */

#include <stdio.h>
#include <string.h>

#include "params.h"
#include "memory.h"
#include "formats.h"
#include "memory.h"
#include "misc.h"
#ifndef BENCH_BUILD
#include "options.h"
#else
#include "loader.h"
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
			fprintf(stderr,
			    "Can't set mkpc larger than %u for %s format\n",
			    format->params.max_keys_per_crypt,
			    format->params.label);
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

/*
 * Test pointers returned by binary() and salt() for possible misalignment.
 */
static int is_misaligned(void *p, int size)
{
	unsigned long mask = 0;
	if (size >= ARCH_SIZE)
		mask = ARCH_SIZE - 1;
	else if (size >= 4)
		mask = 3;
	return (unsigned long)p & mask;
}

static char *fmt_self_test_body(struct fmt_main *format,
    void *binary_copy, void *salt_copy)
{
	static char s_size[32];
	struct fmt_tests *current;
	char *ciphertext = NULL, *plaintext;
	int ntests, done, index, max, size;
	void *binary, *salt;
	struct db_password pw;

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
		char *prepared, Buf[LINE_BUFFER_SIZE];
		current->flds[1] = current->ciphertext;
		prepared = format->methods.prepare(current->flds, format);
		if (!prepared || strlen(prepared) < 7) // $dummy$ can be just 7 bytes long.
			return "prepare";
		if (format->methods.valid(prepared,format) != 1)
			return "valid";
		/* Ensure we have a misaligned ciphertext */
		if (!ciphertext)
			ciphertext = (char*)mem_alloc_tiny(LINE_BUFFER_SIZE + 1,
			    MEM_ALIGN_WORD) + 1;
		strcpy(ciphertext, format->methods.split(prepared, 0));
		plaintext = current->plaintext;

/*
 * Make sure the declared binary_size and salt_size are sufficient to actually
 * hold the binary ciphertexts and salts.  We do this by copying the values
 * returned by binary() and salt() only to the declared sizes.
 */
		binary = format->methods.binary(ciphertext);
		if (!binary)
			return "binary (NULL)";
		if (format->methods.binary != fmt_default_binary &&
		    format->methods.binary_hash[0] != fmt_default_binary_hash &&
		    is_misaligned(binary, format->params.binary_size))
			return "binary (alignment)";

		memcpy(binary_copy, binary, format->params.binary_size);
		binary = binary_copy;

		salt = format->methods.salt(ciphertext);
		if (!salt)
			return "salt (NULL)";
		if (format->methods.salt != fmt_default_salt &&
		    format->methods.salt_hash != fmt_default_salt_hash &&
		    is_misaligned(salt, format->params.salt_size))
			return "salt (alignment)";
		memcpy(salt_copy, salt, format->params.salt_size);
		salt = salt_copy;

/* 
 * get_source testing is a little 'different', because the source pointer
 * of the db_password structure will point to either the source or to the
 * salt, depending upon if the get_source is implemented or not. For
 * testing, we HAVE to observe the exact same behavior here.
 */
		pw.binary = binary;
		if (format->methods.get_source == fmt_default_get_source)
			pw.source = ciphertext;
		else
			pw.source = (char*)salt;
		if (strcmp(format->methods.get_source(&pw, Buf), ciphertext)) 
			return "get_source";

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
		if (strncmp(format->methods.get_key(index), plaintext,
			format->params.plaintext_length)) {
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
			format->methods.clear_keys();
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
			format->methods.clear_keys();
		}
	} while (done != 3);

	return NULL;
}

/*
 * Allocate memory for a copy of a binary ciphertext or salt with only the
 * minimum guaranteed alignment.  We do this to test that binary_hash*(),
 * cmp_*(), and salt_hash() do accept such pointers.
 */
static void *alloc_binary(size_t size, void **alloc)
{
	*alloc = mem_alloc(size + 8 + 4);

	if (size >= ARCH_SIZE)
		return *alloc;
	if (size >= 4)
		return (((char*)*alloc)+4);
	return (((char*)*alloc)+1);
}

char *fmt_self_test(struct fmt_main *format)
{
	char *retval;
	void *binary_alloc, *salt_alloc;
	void *binary_copy, *salt_copy;

	binary_copy = alloc_binary(format->params.binary_size, &binary_alloc);
	memset((char*)binary_copy + format->params.binary_size, 'b', 8);

	salt_copy = alloc_binary(format->params.salt_size, &salt_alloc);
	memset((char*)salt_copy + format->params.salt_size, 's', 8);

	retval = fmt_self_test_body(format, binary_copy, salt_copy);
	if (!retval) {
		if (memcmp((char*)binary_copy + format->params.binary_size,
			"bbbbbbbb", 8))
			return "Binary buffer overrun";
		if (memcmp((char*)salt_copy + format->params.salt_size,
			"ssssssss", 8))
			return "Salt buffer overrun";
	}
	MEM_FREE(salt_alloc);
	MEM_FREE(binary_alloc);

	return retval;
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

char *fmt_default_get_source(struct db_password *current_pw, char ReturnBuf[LINE_BUFFER_SIZE]) 
{
	return current_pw->source;
}

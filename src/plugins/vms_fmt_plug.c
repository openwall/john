/*
 * This file is part of John the Ripper password cracker.
 *
 * It comes from OpenVMS support 2.4(jtr_vms_2-4.zip) patch
 * posted by David Jones.
 *
 * Converted to OpenVMS format module by David Jones
 *
 * Copyright (c) 2011 by David L. Jones <jonesd/at/columbus.rr.com>,
 * Copyright (c) 2012 by Dhiru Kholia <dhiru/at/openwall.com> and
 * is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted. */

#if !AC_BUILT
#if __GNUC__ && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ARCH_LITTLE_ENDIAN 1
#endif
#endif
#include "arch.h"
#if ARCH_LITTLE_ENDIAN
#if FMT_EXTERNS_H
extern struct fmt_main fmt_VMS;
#elif FMT_REGISTERS_H
john_register_one(&fmt_VMS);
#else

#include <stdio.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "vms_std.h"
#include "common.h"
#include "formats.h"
#ifdef VMS
#include <ssdef.h>
#define UAIsM_PWDMIX UAI$M_PWDMIX
#else
/*
 * Emulate symbols defined for VMS services.
 */
#define UAIsM_PWDMIX 0x2000000
#endif

#define FORMAT_LABEL			"OpenVMS"
#define FORMAT_NAME			"Purdy"
#define FORMAT_TAG           "$V$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		UAF_ENCODE_SIZE
#define BINARY_SIZE			8
#define BINARY_ALIGN		4
#define SALT_SIZE			sizeof(struct uaf_hash_info)
#define SALT_ALIGN			sizeof(uaf_qword)

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		8

#ifndef OMP_SCALE
#define OMP_SCALE               32 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests[] = {
/*
 * The following two test vectors: "USER" and "service" are case-insensitive
 */
	{"$V$9AYXUd5LfDy-aj48Vj54P-----", "USER"},
	{"$V$p1UQjRZKulr-Z25g5lJ-------", "service"},
/*
 * The following one test vector: "President#44" is case-sensitive
 */
	{"$V$S44zI913bBx-UJrcFSC------D", "President#44"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uaf_qword (*crypt_out)[BINARY_SIZE / sizeof(uaf_qword)];
static int initialized;

/*
 * See if signature of ciphertext (from passwd file) matches the hack
 * produced by the uaf_encode routine (starts with $V$)
 */
static int valid(char *ciphertext, struct fmt_main *self )
{
	struct uaf_hash_info pwd;

	if (!initialized) {
		uaf_init();
		initialized = 1;
	}

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;	/* no match */

	if ( strlen ( ciphertext ) < (UAF_ENCODE_SIZE-1) )
		return 0;

	if (!uaf_hash_decode(ciphertext, &pwd))
		return 0;

#ifdef VMS_DEBUG
	fprintf(stderr, "/VMS_STD/ get_salt decoded '%s' to %x/%x-%x-%x-%x-%x"
		"  %ld\n", ciphertext, pwd.salt, pwd.alg, pwd.username.r40[0],
		pwd.username.r40[1], pwd.username.r40[2], pwd.username.r40[3],
		pwd.flags);
#endif
	if (pwd.alg < 1 || pwd.alg > 3)
		return 0;

	return 1;
}

static void fmt_vms_init ( struct fmt_main *self )
{
	omp_autotune(self, OMP_SCALE);

	/* Init bin 2 hex table for faster conversions later */
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));

	if (!initialized) {
		uaf_init();
		initialized = 1;
	}
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

/*
 * Save a password (key) for testing.  VMS_std_set_key returns position value
 * we can use if needed to recall the key by a fmt->get_key request.  On get_key
 * return a private copy.
 */
static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

/*
 * Save salt for producing ciphertext from it and saved keys at next crypt call.
 */
static struct uaf_hash_info *cur_salt;

void VMS_std_set_salt ( void *salt )
{
	cur_salt = (struct uaf_hash_info*)salt;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

/*
 * Hash the password and salt saved with VMS_std_set_key and VMS_std_set_salt,
 * saving the result in global storage for retrieval by vms_fmt.c module.
 */
int VMS_std_crypt(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		uaf_test_password (cur_salt, saved_key[index], 0, crypt_out[index]);
	}

	return count;
}

/*
 * Extract salt from ciphertext string to static storage and return
 * pointer to it.  Salt is effectively 70-80 bits (username, salt,
 * algorithm, pwdmix flag).
 */
char *VMS_std_get_salt(char *ciphertext)
{
	static struct uaf_hash_info pwd;
	memset(&pwd, 0, sizeof(pwd));
	uaf_hash_decode ( ciphertext, &pwd );
#ifdef VMS_DEBUG
	printf("/VMS_STD/ get_salt decoded '%s' to %x/%x-%x-%x-%x-%x  %ld\n",
			ciphertext, pwd.salt, pwd.alg, pwd.username.r40[0], pwd.username.r40[1],
			pwd.username.r40[2], pwd.username.r40[3], pwd.flags );
#endif
	return (char *) &pwd;
}

/*
 * Extract binary hash from ciphertext into static storage and return
 * pointer to it.
 */
VMS_word *VMS_std_get_binary(char *ciphertext)
{
	static union {
		struct uaf_hash_info pwd;
		VMS_word b[16];
	} out;

	uaf_hash_decode ( ciphertext, &out.pwd );

	return out.b;
}
/*
 * Class record.
 */
struct fmt_main fmt_VMS = {
	{
		FORMAT_LABEL,			/* .label */
		FORMAT_NAME,			/* .format_name */
		VMS_ALGORITHM_NAME,		/* .algorithm_name */
		BENCHMARK_COMMENT,		/* .benchmark_comment */
		BENCHMARK_LENGTH,		/* .benchmark_length (pwd break len) */
		0,
		PLAINTEXT_LENGTH,		/* .plaintext_length (max) */
		BINARY_SIZE,			/* .binary_size (quadword) */
		BINARY_ALIGN,
		SALT_SIZE,			/* .salt_size (word) */
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
/*
 * This format supports both case-sensitive and case-insensitive passwords,
 * so this format should set FMT_CASE
 */
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		fmt_vms_init,			/* changed for jumbo */
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		(void *(*)(char *))VMS_std_get_binary,
		(void *(*)(char *))VMS_std_get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		(void (*)(void *))VMS_std_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		VMS_std_crypt,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#else
#if !defined(FMT_EXTERNS_H) && !defined(FMT_REGISTERS_H)
#ifdef __GNUC__
#warning ": OpenVMS format requires little-endian, format disabled."
#elif _MSC_VER
#pragma message(": OpenVMS format requires little-endian, format disabled.")
#endif
#endif

#endif	/* ARCH_LITTLE_ENDIAN */

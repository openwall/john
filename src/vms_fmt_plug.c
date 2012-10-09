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

#include <stdio.h>
#include <string.h>
#include "arch.h"
#include "misc.h"
#include "vms_std.h"
#include "common.h"
#include "formats.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               64
#endif
#ifndef UAI$M_PWDMIX
#define UAI$M_PWDMIX 0x2000000
#endif

#define FORMAT_LABEL			"openvms"
#define FORMAT_NAME			"OpenVMS Purdy"
#define FORMAT_NAME_NOPWDMIX		"OpenVMS Purdy (nopwdmix)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		UAF_ENCODE_SIZE
#define BINARY_SIZE			8
#define SALT_SIZE			sizeof(struct uaf_hash_info)

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"$V$9AYXUd5LfDy-aj48Vj54P-----", "USER"},
	{"$V$9AYXUd5LfDy-aj48Vj54P-----", "USER"},
	{"$V$p1UQjRZKulr-Z25g5lJ-------", "service"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uaf_qword (*crypt_out)[BINARY_SIZE / sizeof(uaf_qword)];

/*
 * See if signature of ciphertext (from passwd file) matches the hack
 * produced by the uaf_encode routine (starts with $V$)
 */
static int valid(char *ciphertext, struct fmt_main *self )
{
	if (strncmp(ciphertext, "$V$", 3)) return 0;	/* no match */
	if ( strlen ( ciphertext ) < (UAF_ENCODE_SIZE-1) )
		return 0;
	return 1;
}

static void fmt_vms_init ( struct fmt_main *self )
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	/* Init bin 2 hex table for faster conversions later */
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	uaf_init ( );
}

/*
 * Prepare function.
 */
char *prepare ( char *split_fields[10], struct fmt_main *pFmt )
{
	return split_fields[1];
}


/*
 * Save a password (key) for testing.  VMS_std_set_key returns position value
 * we can use if needed to recall the key by a fmt->get_key request.  On get_key
 * return a private copy.
 */
static void set_key(char *key, int index)
{
	strcpy(saved_key[index], key);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
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

#if FMT_MAIN_VERSION > 9
static char *fmt_vms_split(char *ciphertext, int index, struct fmt_main *pFmt)
#else
static char *fmt_vms_split(char *ciphertext, int index)
#endif
{
	return ciphertext;
}


/*
 * Save salt for producing ciphertext from it and saved keys at next crypt call.
 */

struct uaf_hash_info *cur_salt;

void VMS_std_set_salt ( void *salt )
{
	cur_salt = (struct uaf_hash_info*)salt;
}


#ifdef DEBUG
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

/*
 * Hash the password and salt saved with VMS_std_set_key and VMS_std_set_salt,
 * saving the result in global storage for retrieval by vms_fmt.c module.
 */
void VMS_std_crypt(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		uaf_test_password (cur_salt, saved_key[index], 0, crypt_out[index]);
	}
}

/*
 * Extract salt from ciphertext string to static storage and return
 * pointer to it.  Salt is effectively 70-80 bits (username, salt,
 * algorithm, pwdmix flag).
 */
char *VMS_std_get_salt(char *ciphertext)
{
	static struct uaf_hash_info pwd;
	uaf_hash_decode ( ciphertext, &pwd );
#ifdef DEBUG
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
		PLAINTEXT_LENGTH,		/* .plaintext_lenght (max) */
		BINARY_SIZE,			/* .binary_size (quadword) */
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,			/* .salt_size (word) */
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
		fmt_vms_init,			/* changed for jumbo */
		prepare,			/* Added for jumbo */
		valid,
		fmt_vms_split,
		(void *(*)(char *))VMS_std_get_binary,
		(void *(*)(char *))VMS_std_get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		(void (*)(void *))VMS_std_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		(void (*)(int)) VMS_std_crypt,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

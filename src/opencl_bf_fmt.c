/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 by Sayantan Datta <std2048 at gmail dot com>
 * It is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#include <stdlib.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "opencl_bf_std.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"bf-opencl"
#define FORMAT_NAME			"OpenBSD Blowfish"

#define ALGORITHM_NAME			"OpenCL"

#define BENCHMARK_COMMENT		" (x32)"
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		72
#define CIPHERTEXT_LENGTH		60

#define BINARY_SIZE			4
#define SALT_SIZE			sizeof(BF_salt)

#define MIN_KEYS_PER_CRYPT		BF_N
#define MAX_KEYS_PER_CRYPT		BF_N

static struct fmt_tests tests[] = {
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
		"U*U"},
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
		"U*U*"},
	{"$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a",
		"U*U*U"},
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy",
		""},
	{"$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui",
		"0123456789abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		"chars after 72 are ignored"},
	{"$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e",
		"\xa3"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq",
		"\xa3"},
	{"$2x$05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS",
		"\xd1\x91"},
	{"$2x$05$6bNw2HLQYeqHYyBfLMsv/O9LIGgn8OMzuDoHfof8AQimSGfcSWxnS",
		"\xd0\xc1\xd2\xcf\xcc\xd8"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6",
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"chars after 72 are ignored as usual"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy",
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"},
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy",
		""},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe",
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
		"\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"},
	{NULL}
};

static char saved_key[BF_N][PLAINTEXT_LENGTH + 1];
static char keys_mode;
static int sign_extension_bug;
static BF_salt saved_salt;

static void init(struct fmt_main *pFmt)
{	// BF_select_device(platform,device);
        BF_select_device(platform_id,gpu_id);
	keys_mode = 'a';
	sign_extension_bug = 0;
	fprintf(stderr, "****Please see 'opencl_bf_std.h' for device specific optimizations****\n");
	atexit(BF_clear_buffer);
}

static int valid(char *ciphertext,struct fmt_main *pFmt)
{
	int rounds;
	char *pos;

	if (strncmp(ciphertext, "$2a$", 4) &&
	    strncmp(ciphertext, "$2x$", 4)) return 0;

	if (ciphertext[4] < '0' || ciphertext[4] > '9') return 0;
	if (ciphertext[5] < '0' || ciphertext[5] > '9') return 0;
	rounds = atoi(ciphertext + 4);
	if (rounds < 4 || rounds > 31) return 0;

	if (ciphertext[6] != '$') return 0;

	for (pos = &ciphertext[7]; atoi64[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos || pos - ciphertext != CIPHERTEXT_LENGTH) return 0;

	if (opencl_BF_atoi64[ARCH_INDEX(*(pos - 1))] & 3) return 0;
	if (opencl_BF_atoi64[ARCH_INDEX(ciphertext[28])] & 0xF) return 0;

	return 1;
}

static int binary_hash_0(void *binary)
{
	return *(BF_word *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(BF_word *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(BF_word *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(BF_word *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(BF_word *)binary & 0xFFFFF;
}

static int binary_hash_5(void *binary)
{
	return *(BF_word *)binary & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
	return *(BF_word *)binary & 0x7FFFFFF;
}

static int get_hash_0(int index)
{
	return opencl_BF_out[index][0] & 0xF;
}

static int get_hash_1(int index)
{
	return opencl_BF_out[index][0] & 0xFF;
}

static int get_hash_2(int index)
{
	return opencl_BF_out[index][0] & 0xFFF;
}

static int get_hash_3(int index)
{
	return opencl_BF_out[index][0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return opencl_BF_out[index][0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	return opencl_BF_out[index][0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	return opencl_BF_out[index][0] & 0x7FFFFFF;
}

static int salt_hash(void *salt)
{
	return ((BF_salt *)salt)->salt[0] & 0x3FF;
}

static void set_salt(void *salt)
{
	memcpy(&saved_salt, salt, sizeof(saved_salt));
}

static void set_key(char *key, int index)
{
	opencl_BF_std_set_key(key, index, sign_extension_bug);

	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static void crypt_all(int count)
{
	if (keys_mode != saved_salt.subtype) {
		int i;

		keys_mode = saved_salt.subtype;
		sign_extension_bug = (keys_mode == 'x');
		for (i = 0; i < count; i++)
			opencl_BF_std_set_key(saved_key[i], i, sign_extension_bug);
	}

	opencl_BF_std_crypt(&saved_salt, count);
}

static int cmp_all(void *binary, int count)
{
	int i;
	for (i = 0; i < count; i++)
		if (*(BF_word *)binary == opencl_BF_out[i][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *(BF_word *)binary == opencl_BF_out[index][0];
}

static int cmp_exact(char *source, int index)
{
	opencl_BF_std_crypt_exact(index);

	return !memcmp(opencl_BF_std_get_binary(source), opencl_BF_out[index],
	    sizeof(BF_binary));
}

struct fmt_main fmt_opencl_bf = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		opencl_BF_std_get_binary,
		opencl_BF_std_get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
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

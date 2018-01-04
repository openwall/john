/*
 * This software is Copyright (c) 2017 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_wpapsk_pmk;
#elif FMT_REGISTERS_H
john_register_one(&fmt_wpapsk_pmk);
#else

#include <string.h>
#include <assert.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "wpapmk.h"
#include "sha.h"
#include "base64_convert.h"
#include "memdbg.h"

#define FORMAT_LABEL		"wpapsk-pmk"
#if AC_BUILT && !HAVE_OPENSSL_CMAC_H
#ifdef _MSC_VER
#pragma message ("Notice: WPAPMK (CPU) format built without support for 802.11w. Upgrade your OpenSSL.")
#else
#warning Notice: WPAPMK (CPU) format built without support for 802.11w. Upgrade your OpenSSL.
#endif
#define FORMAT_NAME		"WPA/WPA2 master key"
#else
#define FORMAT_NAME		"WPA/WPA2/PMF master key"
#endif

#define ALGORITHM_NAME		"MD5/SHA-1/SHA-2"

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	128

#ifndef OMP_SCALE
#define OMP_SCALE 2 // MKPC and OMP_SCALE tuned for core i7
#endif

extern wpapsk_hash *outbuffer;
extern wpapsk_salt currentsalt;
extern hccap_t hccap;
extern mic_t *mic;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	assert(sizeof(hccap_t) == HCCAP_SIZE);

	outbuffer = mem_alloc(sizeof(*outbuffer) *
	                      self->params.max_keys_per_crypt);
	mic = mem_alloc(sizeof(*mic) *
	                self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(mic);
	MEM_FREE(outbuffer);
}

static void set_key(char *key, int index)
{
	int i;

	for (i = 0; i < 32; i++)
		((unsigned char*)outbuffer[index].v)[i] =
			(atoi16[ARCH_INDEX(key[i << 1])] << 4) |
			atoi16[ARCH_INDEX(key[(i << 1) + 1])];
}

static char* get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	int i;

	for (i = 0; i < 32; i++) {
		ret[i << 1] =
			itoa16[ARCH_INDEX(((unsigned char*)outbuffer[index].v)[i] >> 4)];
		ret[(i << 1) + 1] =
			itoa16[ARCH_INDEX(((unsigned char*)outbuffer[index].v)[i] & 0xf)];
	}
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	wpapsk_postprocess(count);

	return count;
}

struct fmt_main fmt_wpapsk_pmk = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_MIN_LEN,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_OMP,
		{
#if !AC_BUILT || HAVE_OPENSSL_CMAC_H
			"key version [1:WPA 2:WPA2 3:802.11w]"
#else
			"key version [1:WPA 2:WPA2]"
#endif
		},
		{ FORMAT_TAG },
		tests
	},
	{
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			get_keyver,
		},
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
		salt_compare,
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

#endif /* plugin stanza */

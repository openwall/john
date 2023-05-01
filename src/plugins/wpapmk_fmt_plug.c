/*
 * This software is Copyright (c) 2018 magnum,
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
#define WPAPMK
#include "wpapsk.h"
#include "sha.h"
#include "base64_convert.h"
#include "options.h"
#include "john.h"

#define FORMAT_LABEL		"wpapsk-pmk"
#if !HAVE_OPENSSL_CMAC_H
#ifdef _MSC_VER
#pragma message("Notice: WPAPSK-PMK (CPU) format built without support for 802.11w (this needs recent OpenSSL)")
#else
#warning Notice: WPAPSK-PMK (CPU) format built without support for 802.11w (this needs recent OpenSSL)
#endif
#define FORMAT_NAME		"WPA/WPA2/PMKID master key"
#else
#define FORMAT_NAME		"WPA/WPA2/PMF/PMKID master key"
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

	if (options.flags & (FLG_BATCH_CHK | FLG_INC_CHK | FLG_SINGLE_CHK)) {
		if (john_main_process) {
			char *t, *pf = str_alloc_copy(self->params.label);

			if ((t = strrchr(pf, '-')))
				*t = 0;

			fprintf(stderr,
"The \"%s\" format takes hex keys of length 64 as input. Most normal\n"
"cracking approaches does not make sense. You probably wanted to use the\n"
"\"%s\" format (even for PMKID hashes).\n",
			        self->params.label, pf);
		}
		error();
	}
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
	return *pcount;
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
		FMT_OMP | FMT_BLOB,
		{
#if 1
			NULL
#elif !AC_BUILT || HAVE_OPENSSL_CMAC_H
			"key version [0:PMKID 1:WPA 2:WPA2 3:802.11w]"
#else
			"key version [0:PMKID 1:WPA 2:WPA2]"
#endif
		},
		{
			FORMAT_TAG, ""
		},
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
		fmt_default_salt,
		{
			NULL //get_keyver,
		},
		fmt_default_source,
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
		NULL,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash,
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

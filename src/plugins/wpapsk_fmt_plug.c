/*
 * This software is
 * Copyright (c) 2012 Lukas Odzioba <ukasz at openwall dot net>,
 * Copyright (c) 2012-2018 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Code is based on  Aircrack-ng source
 *
 * SSE2 code enhancement, Jim Fougeron, Jan, 2013.
 *  Also removed oSSL EVP code and coded what it does (which is simple), inline.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_wpapsk;
#elif FMT_REGISTERS_H
john_register_one(&fmt_wpapsk);
#else

#include <string.h>
#include <assert.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "simd-intrinsics.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "pbkdf2_hmac_sha1.h"
#include "wpapsk.h"
#include "sha.h"
#include "options.h"
#include "unicode.h"

#define FORMAT_LABEL		"wpapsk"
#if !HAVE_OPENSSL_CMAC_H
#ifdef _MSC_VER
#pragma message("Notice: WPAPSK (CPU) format built without support for 802.11w (this needs recent OpenSSL)")
#else
#warning Notice: WPAPSK (CPU) format built without support for 802.11w (this needs recent OpenSSL)
#endif
#define FORMAT_NAME		"WPA/WPA2/PMKID PSK"
#else
#define FORMAT_NAME		"WPA/WPA2/PMF/PMKID PSK"
#endif
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 32/" ARCH_BITS_STR
#endif

#ifdef SIMD_COEF_32
#define NBKEYS	(SIMD_COEF_32 * SIMD_PARA_SHA1)
#else
#define NBKEYS	1
#endif

#define MIN_KEYS_PER_CRYPT	NBKEYS
#define MAX_KEYS_PER_CRYPT	(NBKEYS * 2)

#ifndef OMP_SCALE
#define OMP_SCALE 2 // tuned w/ MKPC, core i7M HT SIMD/non-SIMD
#endif

extern wpapsk_password *inbuffer;
extern wpapsk_hash *outbuffer;
extern wpapsk_salt *cur_salt;
extern hccap_t hccap;
extern mic_t *mic;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	assert(sizeof(hccap_t) == HCCAP_SIZE);

	inbuffer = mem_alloc(sizeof(*inbuffer) *
	                     self->params.max_keys_per_crypt);
	outbuffer = mem_alloc(sizeof(*outbuffer) *
	                      self->params.max_keys_per_crypt);
	mic = mem_alloc(sizeof(*mic) *
	                self->params.max_keys_per_crypt);

	/*
	 * Implementations seen IRL that have 8 *bytes* (of eg. UTF-8) passwords
	 * as opposed to 8 *characters*. This hack is not ideal.
	 */
	if (options.target_enc == UTF_8 && options.internal_cp != UTF_8)
		self->params.plaintext_min_length = 2;

	/*
	 * Zero the lengths in case crypt_all() is called with some keys
	 * still not set.  This may happen during self-tests.
	 */
	{
		int i;
		for (i = 0; i < self->params.max_keys_per_crypt; i++)
			inbuffer[i].length = 0;
	}
}

static void done(void)
{
	MEM_FREE(mic);
	MEM_FREE(outbuffer);
	MEM_FREE(inbuffer);
}

#ifndef SIMD_COEF_32
static MAYBE_INLINE void wpapsk_cpu(int count,
    wpapsk_password *in, wpapsk_hash *out, wpapsk_salt *salt)
{
	int j;

#ifdef _OPENMP
#pragma omp parallel for default(none) private(j) shared(count, salt, in, out)
#endif
	for (j = 0; j < count; j++) {
		pbkdf2_sha1((const unsigned char*)(in[j].v),
		            in[j].length,
		            salt->essid, salt->length,
		            4096, (unsigned char*)&out[j],
		            32, 0);
	}
}
#else
static MAYBE_INLINE void wpapsk_sse(int count, wpapsk_password *in, wpapsk_hash *out, wpapsk_salt *salt)
{
	int t; // thread count
	int loops = (count+NBKEYS-1) / NBKEYS;

#ifdef _OPENMP
#pragma omp parallel for default(none) private(t) shared(count, salt, in, out, loops)
#endif
	for (t = 0; t < loops; t++) {
		int lens[NBKEYS], i;
		unsigned char *pin[NBKEYS];
		union {
			uint32_t *pout[NBKEYS];
			unsigned char *poutc;
		} x;
		for (i = 0; i < NBKEYS; ++i) {
			lens[i] = in[t*NBKEYS+i].length;
			pin[i] = (unsigned char*)in[t*NBKEYS+i].v;
			x.pout[i] = &out[t*NBKEYS+i].v[0];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens,
		                salt->essid, salt->length,
		                4096, &(x.poutc),
		                32, 0);
	}
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

#ifndef SIMD_COEF_32
	wpapsk_cpu(count, inbuffer, outbuffer, cur_salt);
#else
	wpapsk_sse(count, inbuffer, outbuffer, cur_salt);
#endif

	return count;
}

struct fmt_main fmt_wpapsk = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_BLOB,
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
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
		salt_hash,
		salt_compare,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

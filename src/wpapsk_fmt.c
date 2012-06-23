/*
* This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*
* Code is based on  Aircrack-ng source
*/
#include <string.h>
#include "arch.h"
#include <assert.h>
#include "formats.h"
#include "common.h"
#include "misc.h"
//#define WPAPSK_DEBUG
#include "wpapsk.h"
#include <openssl/hmac.h>
#include <openssl/sha.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL		"wpapsk"
#define FORMAT_NAME		"WPA-PSK PBKDF2-HMAC-SHA-1"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

extern wpapsk_password *inbuffer;
extern wpapsk_hash *outbuffer;
extern wpapsk_salt currentsalt;
extern hccap_t hccap;
extern mic_t *mic;
static struct fmt_tests tests[] = {
/// testcase from http://wiki.wireshark.org/SampleCaptures = wpa-Induction.pcap
	{"$WPAPSK$Coherer#..l/Uf7J..qHUXMunTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosMyXdNxfBZUAYmgKqeb6GBPxLiIZr56NtWTGR/Cp5ldAk61.5I0.Ec.2...........nTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosM.................................................................3X.I.E..1uk0.E..1uk2.E..1uk0....................................................................................................................................................................................../t.....U...8FWdk8OpPckhewBwt4MXYI", "Induction"},
	{NULL}
};

static void init(struct fmt_main *pFmt)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt *= omp_t;
	pFmt->params.max_keys_per_crypt *= omp_t;
#endif

	assert(sizeof(hccap_t) == HCCAP_SIZE);

	inbuffer = mem_alloc(sizeof(*inbuffer) *
	    pFmt->params.max_keys_per_crypt);
	outbuffer = mem_alloc(sizeof(*outbuffer) *
	    pFmt->params.max_keys_per_crypt);
	mic = mem_alloc(sizeof(*mic) *
	    pFmt->params.max_keys_per_crypt);

/*
 * Zeroize the lengths in case crypt_all() is called with some keys still
 * not set.  This may happen during self-tests.
 */
	{
		int i;
		for (i = 0; i < pFmt->params.max_keys_per_crypt; i++)
			inbuffer[i].length = 0;
	}
}

static MAYBE_INLINE void wpapsk_cpu(int count,
    wpapsk_password * in, wpapsk_hash * out, wpapsk_salt * salt)
{
	int j;
	int slen = salt->length + 4;

#ifdef _OPENMP
#pragma omp parallel for default(none) private(j) shared(count, slen, salt, in, out)
#endif
	for (j = 0; j < count; j++) {
		int i, k;
		unsigned char essid[32 + 4];
		union {
			unsigned char c[64];
			uint32_t i[16];
		} buffer;
		union {
			unsigned char c[40];
			uint32_t i[10];
		} outbuf;
		SHA_CTX ctx_ipad;
		SHA_CTX ctx_opad;
		SHA_CTX sha1_ctx;

		memset(essid, 0, 32 + 4);
		memcpy(essid, salt->salt, salt->length);
		memset(&buffer, 0, 64);
		memcpy(&buffer, in[j].v, in[j].length);

		SHA1_Init(&ctx_ipad);
		SHA1_Init(&ctx_opad);

		for (i = 0; i < 16; i++)
			buffer.i[i] ^= 0x36363636;
		SHA1_Update(&ctx_ipad, buffer.c, 64);

		for (i = 0; i < 16; i++)
			buffer.i[i] ^= 0x6a6a6a6a;
		SHA1_Update(&ctx_opad, buffer.c, 64);

		essid[slen - 1] = 1;
		HMAC(EVP_sha1(), in[j].v, in[j].length, essid, slen,
		    outbuf.c, NULL);
		memcpy(&buffer, &outbuf, 20);

		for (i = 1; i < 4096; i++) {
			memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
			SHA1_Update(&sha1_ctx, buffer.c, 20);
			SHA1_Final(buffer.c, &sha1_ctx);

			memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
			SHA1_Update(&sha1_ctx, buffer.c, 20);
			SHA1_Final(buffer.c, &sha1_ctx);

			for (k = 0; k < 5; k++)
				outbuf.i[k] ^= buffer.i[k];
		}
		essid[slen - 1] = 2;
		HMAC(EVP_sha1(), in[j].v, in[j].length, essid, slen,
		    &outbuf.c[20], NULL);
		memcpy(&buffer, &outbuf.c[20], 20);

		for (i = 1; i < 4096; i++) {
			memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
			SHA1_Update(&sha1_ctx, buffer.c, 20);
			SHA1_Final(buffer.c, &sha1_ctx);

			memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
			SHA1_Update(&sha1_ctx, buffer.c, 20);
			SHA1_Final(buffer.c, &sha1_ctx);

			for (k = 5; k < 8; k++)
				outbuf.i[k] ^= buffer.i[k - 5];
		}

		memcpy(&out[j], &outbuf, 32);
	}
}

static void crypt_all(int count)
{
	wpapsk_cpu(count, inbuffer, outbuffer, &currentsalt);
	wpapsk_postprocess(count);
}

struct fmt_main fmt_wpapsk = {
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
		    FMT_CASE | FMT_8_BIT | FMT_OMP,
		    tests
	},
	{
		    init,
		    fmt_default_prepare,
		    valid,
		    fmt_default_split,
		    binary,
		    salt,
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

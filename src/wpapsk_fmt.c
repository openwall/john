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
#include "wpapsk.h"
#include <openssl/hmac.h>
#include <openssl/sha.h>

#define FORMAT_LABEL		"wpapsk"
#define FORMAT_NAME		FORMAT_LABEL
#define ALGORITHM_NAME		"OpenSSL"

#define	KEYS_PER_CRYPT		1
#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

//#define WPAPSK_DEBUG

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
	assert(sizeof(hccap_t) == HCCAP_SIZE);
	inbuffer =
	    (wpapsk_password *) malloc(sizeof(wpapsk_password) *
	    MAX_KEYS_PER_CRYPT);
	outbuffer =
	    (wpapsk_hash *) malloc(sizeof(wpapsk_hash) * MAX_KEYS_PER_CRYPT);
	mic = (mic_t *) malloc(sizeof(mic_t) * MAX_KEYS_PER_CRYPT);
	if (inbuffer == NULL || outbuffer == NULL || mic == NULL) {
		fprintf(stderr, "Memory alocation error\n");
		exit(1);
	}
}

static void wpapsk_cpu(wpapsk_password * in, wpapsk_hash * out,
    wpapsk_salt * salt)
{
	int i, j, k;
	unsigned char essid[32 + 4];
	unsigned char buffer[64];
	memset(essid, 0, 32 + 4);
	memcpy(essid, salt->salt, salt->length);
	int slen = salt->length + 4;

	for (j = 0; j < KEYS_PER_CRYPT; j++) {
		SHA_CTX ctx_ipad;
		SHA_CTX ctx_opad;
		SHA_CTX sha1_ctx;
		memset(buffer, 0, 64);
		memcpy(buffer, in[j].v, in[j].length);

		SHA1_Init(&ctx_ipad);
		SHA1_Init(&ctx_opad);

		for (i = 0; i < 64; i++)
			buffer[i] ^= 0x36;
		SHA1_Update(&ctx_ipad, buffer, 64);

		for (i = 0; i < 64; i++)
			buffer[i] ^= 0x6a;
		SHA1_Update(&ctx_opad, buffer, 64);

		essid[slen - 1] = 1;
		HMAC(EVP_sha1(), in[j].v, in[j].length, essid, slen,
		    (unsigned char *) out[j].v, NULL);
		memcpy(buffer, out[j].v, 20);

		for (i = 1; i < 4096; i++) {
			memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
			SHA1_Update(&sha1_ctx, buffer, 20);
			SHA1_Final(buffer, &sha1_ctx);

			memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
			SHA1_Update(&sha1_ctx, buffer, 20);
			SHA1_Final(buffer, &sha1_ctx);

			for (k = 0; k < 5; k++) {
				unsigned int *p = (unsigned int *) buffer;
				out[j].v[k] ^= p[k];
			}
		}
		essid[slen - 1] = 2;
		HMAC(EVP_sha1(), in[j].v, in[j].length, essid, slen,
		    (unsigned char *) out[j].v + 5 * 4, NULL);
		memcpy(buffer, out[j].v + 5, 20);

		for (i = 1; i < 4096; i++) {
			memcpy(&sha1_ctx, &ctx_ipad, sizeof(sha1_ctx));
			SHA1_Update(&sha1_ctx, buffer, 20);
			SHA1_Final(buffer, &sha1_ctx);

			memcpy(&sha1_ctx, &ctx_opad, sizeof(sha1_ctx));
			SHA1_Update(&sha1_ctx, buffer, 20);
			SHA1_Final(buffer, &sha1_ctx);

			for (k = 5; k < 8; k++) {
				unsigned int *p = (unsigned int *) buffer;
				outbuffer[j].v[k] ^= p[k - 5];
			}
		}
	}
}

static void crypt_all(int count)
{
	wpapsk_cpu(inbuffer, outbuffer, &currentsalt);
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
		    FMT_CASE | FMT_8_BIT,
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

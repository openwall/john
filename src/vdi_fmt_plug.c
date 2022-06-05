/*
 * VirtualBox (VDI) volume support to John The Ripper
 *
 * Written by JimF <jfoug at openwall.net> in 2015.  No copyright
 * is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2015 JimF and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * Information about this algorithm taken from:
 * http://www.sinfocol.org/archivos/2015/07/VBOXDIECracker.phps
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_vdi;
#elif FMT_REGISTERS_H
john_register_one(&fmt_vdi);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "xts.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "crc32.h"
#include "johnswap.h"
#include "base64_convert.h"
#include "pbkdf2_hmac_sha256.h"

#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(struct vdi_salt)
#define SALT_ALIGN              4
#define BINARY_SIZE             32
#define BINARY_ALIGN            4
#define MAX_SALT_LEN            32
#define MAX_KEY_LEN             64
#define FORMAT_LABEL            "vdi"
#define FORMAT_NAME             "VirtualBox-VDI AES_XTS"
#define FORMAT_TAG              "$vdi$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "PBKDF2-SHA256 " SHA256_ALGORITHM_NAME " + AES_XTS"

#if SSE_GROUP_SZ_SHA256
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA256 * 4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      8
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               8 // Tuned w/ MKPC for core i7
#endif

static unsigned char (*key_buffer)[PLAINTEXT_LENGTH + 1];
static unsigned char (*crypt_out)[MAX_SALT_LEN];

static struct fmt_tests tests[] = {
	// The 'JtR' test hashes were made with VirtualBox. The others were made with pass_gen.pl
	{"$vdi$aes-xts256$sha256$2000$2000$64$32$709f6df123f1ccb126ea1f3e565beb78d39cafdc98e0daa2e42cc43cef11f786$0340f137136ad54f59f4b24ef0bf35240e140dfd56bbc19ce70aee6575f0aabf$0a27e178f47a0b05a752d6e917b89ef4205c6ae76705c34858390f8afa6cf03a45d98fab53b76d8d1c68507e7810633db4b83501a2496b7e443eccb53dbc8473$7ac5f4ad6286406e84af31fd36881cf558d375ae29085b08e6f65ebfd15376ca", "jtr"},
	{"$vdi$aes-xts256$sha256$2000$2000$64$32$d72ee0aecd496b084117bb8d87f5e37de71973518a2ef992c895907a09b73b83$afb33e56a7f81b1e3db70f599b62ecf3d223405abb63bcf569bb29acab9c81a6$3b3769fd3cfaf8e11f67fdc9d54aed8c8962a769f3f66cb2b9cb8700c01a66e6b1c996fdee9727188c765bde224047b8ced7a9b5f5381e7ad7271a9cbf049fde$1c5bca64cbedd76802eddc3e6ffd834e8c1f1ff1157de6ae6feb3740051e2cfa", "password"},
	{"$vdi$aes-xts256$sha256$2000$2000$64$32$a4e4480927153ecbb7509afb8d49468e62c8bb22aaab458f4115bff63364de41$c69605220d1ed03618f0236a88e225db1ec69e7a95dbe63ee00778cc8b91424e$0a1de9c85452fafd19ceb0821a115c7fec6fab4ef51fc57fabc25bf973417684a78683267513923f88231a6efd2442ce9279f2a5614d4cfcb930b5ef413f34c3$d79ea5522ad79fc409bbcd1e8a2bb75e16a53e1eef940b4fe954cee1c2491fd2", "ripper"},
	{"$vdi$aes-xts256$sha256$2000$2000$64$32$450ce441592003821931e73ea314dcd0effff1b74b61a8fc4046573d0f448057$18c48e3d7677bc9471607cec83d036b963f23f7bb16f09ea438395b61dcf14d5$c4893bce14fa3a1f915004b9ec0fd6a7215ddebdd2ca4bc2b4ec164253c2f2319685a8f8245ec8e2d9e7a53c6aec5fd2d4ca7ba510ffc7456a72285d40ce7d35$793e58317b9bf6318d1b4cef1e05f5a8579a50fb7efde884ea68b096b7043aad", "john"},
	{"$vdi$aes-xts256$sha256$2000$2000$64$32$472476df7d16f80d612d4c9ff35678a2011605dc98b76b6d78632859c259d5d0$aa89f9bea1139da6ace97e13c823d713030fda0c8c55ad2fcea358746cc0b4cc$507aaf7c9e00b492042072a17b3975fc88e30e1d5927e63cb335c630b7b873e4c9af2df63c95b42896e15bb33c37c9f572a65f97441b3707ce5d81c521dfd30e$111004a8d9167b55ff5db510cc136f2bceacf4a9f50807742e2bbc110847174e", "really long password with ! stuff!!! ;)"},
	// Some aes-128 samples. They run exactly at the same speed as the AES-256 hashes.
	{"$vdi$aes-xts128$sha256$2000$2000$32$32$d3fd2bb27734f25918ac726717b192091253441c4bc71a814d0a6483e73325ea$ef560858b4c068bd8d994cdf038f51cb1b9f59335d72cb874e79a13c5b6aa84a$79ff000f7638d39b0d02ad08dfcede8740087e334e98022465a380bdf78fff13$302f4c4f58c0dee9676dfdaf3ada9e3d7ec4b5bfc7e6565c941f4ec7337368d4", "jtr"},
	{"$vdi$aes-xts128$sha256$2000$2000$32$32$16894e7496bac97bc467faa3efe5a3ba009e1591990c9422e4352bfb39ead4d6$00780af3703680b63239b61d0395e9ff673ee843d7a77d61541e0fdc096c49d1$72434a81a27bb1cd85be529600c3620e4eeed45d12f8ef337cc51c040306be7d$4a5b2129577289a8a0f6a93d7a578cd248d158bc70d6ab89f5ccf31704812e85", "blowhard"},
	{"$vdi$aes-xts128$sha256$2000$2000$32$32$4e9d103c944479a4e2b2e33d4757e11fc1a7263ba3b2e99d9ad4bc9aeb7f9337$ade43b6eb1d878f0a5532070fb81697a8164ff7b9798e35649df465068ae7e81$f1e443252c872e305eda848d05676a20af8df405262984b39baf0f0aa1b48247$2601e9e08d19ca20745a6a33f74259bdca06014455370b0bb6b79eb0c5e60581", "foobar"},
	{NULL}
};

static struct vdi_salt {
	unsigned char salt1[MAX_SALT_LEN];
	unsigned char salt2[MAX_SALT_LEN];
	unsigned char encr[MAX_KEY_LEN];
	int crypt_type;		// 1, 256, 384, 512 for the pbkdf2 algo (currently ONLY 256 implemented, so that is all we handle right now).
	int evp_type;		// 128 or 256 for AES-128XTS or AES-256XTS
	int rounds1;
	int rounds2;
	int keylen;
	int saltlen;
} *psalt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	key_buffer = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*key_buffer));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(key_buffer);
	MEM_FREE(crypt_out);
}

static int valid(char* ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr;
	int keylen;
	int saltlen;
	char *p;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext + FORMAT_TAG_LEN);
	keeptr = ctcopy;

	if ((p = strtokm(ctcopy, "$")) == NULL)	/* decr type*/
		goto err;
	if (strcmp(p, "aes-xts256") && strcmp(p, "aes-xts128"))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* pbkdf2 algo */
		goto err;
	//if (strcmp(p, "sha1") && strcmp(p, "sha256") && strcmp(p, "sha384") && strcmp(p, "sha512"))
	if (strcmp(p, "sha256"))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* pbkdf2-1 iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* pbkdf2-2 iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* key length */
		goto err;
	if (!isdec(p))
		goto err;
	keylen = atoi(p);
	if (keylen > MAX_KEY_LEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt length */
		goto err;
	if (!isdec(p))
		goto err;
	saltlen = atoi(p);
	if (saltlen > MAX_SALT_LEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt1 */
		goto err;
	if (strlen(p) != saltlen * 2)
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt2 */
		goto err;
	if (strlen(p) != saltlen * 2)
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* encr_key */
		goto err;
	if (strlen(p) != keylen * 2)
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* final_result */
		goto err;
	if (strlen(p) != saltlen * 2)
		goto err;
	if (!ishexlc(p))
		goto err;

	if ((p = strtokm(NULL, "$")) != NULL)
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;

}

static void set_salt(void *salt)
{
	psalt = salt;
}

static void* get_salt(char *ciphertext)
{
	static char buf[sizeof(struct vdi_salt)+4];
	struct vdi_salt *s = (struct vdi_salt *)mem_align(buf, 4);
	char *ctcopy, *keeptr;
	char *p;

	memset(buf, 0, sizeof(buf));
	ctcopy = xstrdup(ciphertext + FORMAT_TAG_LEN);
	keeptr = ctcopy;
	p = strtokm(ctcopy, "$");	/* decr type*/
	s->evp_type = !strcmp(p, "aes-xts128") ? 128 : 256;
	p = strtokm(NULL, "$");	/* pbkdf2 algo */
	s->crypt_type = 256;	/* right now, we ONLY handle pbkdf2-sha256 */
	p = strtokm(NULL, "$");	/* pbkdf2-1 iterations */
	s->rounds1 = atoi(p);
	p = strtokm(NULL, "$");	/* pbkdf2-2 iterations */
	s->rounds2 = atoi(p);
	p = strtokm(NULL, "$");	/* key length */
	s->keylen = atoi(p);
	p = strtokm(NULL, "$");	/* salt length */
	s->saltlen = atoi(p);
	p = strtokm(NULL, "$");	/* salt1 */
	base64_convert(p, e_b64_hex, s->saltlen*2, s->salt1, e_b64_raw, s->saltlen, 0, 0);
	p = strtokm(NULL, "$");	/* salt2 */
	base64_convert(p, e_b64_hex, s->saltlen*2, s->salt2, e_b64_raw, s->saltlen, 0, 0);
	p = strtokm(NULL, "$");	/* encr_key */
	base64_convert(p, e_b64_hex, s->keylen*2, s->encr, e_b64_raw, s->keylen, 0, 0);

	MEM_FREE(keeptr);
	return s;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count;  i += MIN_KEYS_PER_CRYPT) {
		unsigned char key[MAX_KEY_LEN];
#if SSE_GROUP_SZ_SHA256
		unsigned char Keys[SSE_GROUP_SZ_SHA256][MAX_KEY_LEN];
		unsigned char Decr[SSE_GROUP_SZ_SHA256][MAX_KEY_LEN];
#else
		unsigned char Decr[1][MAX_KEY_LEN];
		int ksz = strlen((char *)key_buffer[i]);
#endif
		int j;

#if SSE_GROUP_SZ_SHA256
		int lens[SSE_GROUP_SZ_SHA256];
		unsigned char *pin[SSE_GROUP_SZ_SHA256];
		union {
			unsigned char *pout[SSE_GROUP_SZ_SHA256];
			unsigned char *poutc;
		} x;
		for (j = 0; j < SSE_GROUP_SZ_SHA256; ++j) {
			lens[j] = strlen((char*)(key_buffer[i+j]));
			pin[j] = key_buffer[i+j];
			x.pout[j] = Keys[j];
		}
		pbkdf2_sha256_sse((const unsigned char **)pin, lens, psalt->salt1, psalt->saltlen, psalt->rounds1, &(x.poutc), psalt->keylen, 0);
#else
		pbkdf2_sha256((const unsigned char*)key_buffer[i], ksz, psalt->salt1, psalt->saltlen, psalt->rounds1, key, psalt->keylen, 0);
#endif
		for (j = 0; j < MIN_KEYS_PER_CRYPT; ++j) {
#if SSE_GROUP_SZ_SHA256
			memcpy(key, Keys[j], sizeof(key));
#endif
			// Try to decrypt using AES
			AES_XTS_decrypt(key, Decr[j], psalt->encr, psalt->keylen, psalt->evp_type);
		}

#if SSE_GROUP_SZ_SHA256
		for (j = 0; j < SSE_GROUP_SZ_SHA256; ++j) {
			lens[j] = psalt->keylen;
			pin[j] = Decr[j];
			x.pout[j] = crypt_out[i+j];
		}
		pbkdf2_sha256_sse((const unsigned char **)pin, lens, psalt->salt2, psalt->saltlen, psalt->rounds2, &(x.poutc), psalt->saltlen, 0);
#else
		pbkdf2_sha256(Decr[0], psalt->keylen, psalt->salt2, psalt->saltlen, psalt->rounds2, crypt_out[i], psalt->saltlen, 0);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], 4))
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

static void set_key(char* key, int index)
{
	strnzcpy((char*)key_buffer[index], key, sizeof(*key_buffer));
}

static char *get_key(int index)
{
	return (char*)(key_buffer[index]);
}

static int salt_hash(void *salt)
{
	unsigned v=0, i;
	unsigned char *psalt = (unsigned char *)salt;
	psalt += 40; // skips us to the salt stuff.
	for (i = 0; i < 64; ++i) {
		v *= 11;
		v += psalt[i];
	}
	return v & (SALT_HASH_SIZE - 1);
}

static void *binary(char *ciphertext) {
	static uint32_t full[MAX_SALT_LEN / 4];
	unsigned char *realcipher = (unsigned char*)full;

	ciphertext = strrchr(ciphertext, '$') + 1;
	base64_convert(ciphertext, e_b64_hex, strlen(ciphertext), realcipher, e_b64_raw, MAX_SALT_LEN, 0, 0);

	return (void*)realcipher;
}

struct fmt_main fmt_vdi = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		"",                               // BENCHMARK_COMMENT
		0x107,                            // BENCHMARK_LENGTH
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		salt_hash,
		NULL,
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

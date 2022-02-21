/*
 * Cracker for leet.cc hashes.
 *
 * hsh = bin2hex(hash("sha512", $password . $salt, true) ^ hash("whirlpool", $salt . $password, true))
 * $salt == username
 *
 * Input hash format: username:hash
 *
 * This software is Copyright (c) 2016, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_leet;
#elif FMT_REGISTERS_H
john_register_one(&fmt_leet);
#else

#include <string.h>

#include "arch.h"

#if AC_BUILT
#include "autoconfig.h"
#endif

#include "openssl_local_overrides.h"
#if HAVE_LIBCRYPTO
#include <openssl/opensslv.h>
#endif
#if (AC_BUILT && HAVE_WHIRLPOOL) ||	  \
   (!AC_BUILT && OPENSSL_VERSION_NUMBER >= 0x10000000 && !HAVE_NO_SSL_WHIRLPOOL)
#include <openssl/whrlpool.h>
#define WP_TYPE "OpenSSL"
#define sph_whirlpool_context    WHIRLPOOL_CTX
#define sph_whirlpool_init(a)	 WHIRLPOOL_Init(a)
#define sph_whirlpool(a,b,c)	 WHIRLPOOL_Update(a,b,c)
#define sph_whirlpool_close(b,a) WHIRLPOOL_Final(a,b)
#else
#define WP_TYPE "SPH"
#include "sph_whirlpool.h"
#endif

#ifdef _OPENMP
#include <omp.h>
#endif

#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

#ifdef SIMD_COEF_64
#define SHA512_TYPE          SHA512_ALGORITHM_NAME
#define NBKEYS					(SIMD_COEF_64*SIMD_PARA_SHA512)
#else
#define SHA512_TYPE          "32/" ARCH_BITS_STR
#define NBKEYS					1
#endif

#ifdef SIMD_COEF_64
#define PLAINTEXT_LENGTH        (111-32)
#define MAX_SALT_LEN            32
#else
#define PLAINTEXT_LENGTH        125
#define MAX_SALT_LEN            256
#endif

#define FORMAT_LABEL            "leet"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "SHA-512(" SHA512_TYPE ") + Whirlpool(" WP_TYPE "/" ARCH_BITS_STR ")"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define BINARY_SIZE             64
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            sizeof(uint64_t)
#define SALT_ALIGN              sizeof(int)

#ifndef OMP_SCALE
#define OMP_SCALE               128
#endif

#define MIN_KEYS_PER_CRYPT      NBKEYS
#define MAX_KEYS_PER_CRYPT      (64 * NBKEYS)

static struct fmt_tests leet_tests[] = {
	{"salt$f86036a85e3ff84e73bf10769011ecdbccbf5aaed9df0240310776b42f5bb8776e612ab15a78bbfc39e867448a08337d97427e182e72922bbaa903ee75b2bfd4", "password"},
	{"Babeface$3e6380026fc262465934fd5352659c874e611cbf3229cdbf1407c3bae4c6f0b9c437470d202bccc65cf82faf883d299f1ab30ed841cd8f2472c58f4f05ac6ca3", "john"},
	{"user$b8baf965f515e41c9bf4bc31f0652f27b746c3155f79bc39d2ba8557a8e4a803fd4c0418d577957044bd403d98847750231cb9f03fb213dcddf73304180309dc", "ripper"},
	{"harvey$581e6f9aee99df55bb815bb608707a640a8deae3bad343d0421822518f2c9d8a053221356894628e30f70bf91d36ca2a7300407ec6686fefaa46cbad07b0f78e", "openwall"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static uint64_t (*crypt_out)[1];

static struct custom_salt {
	int saltlen;
	unsigned char salt[MAX_SALT_LEN];
} *cur_salt;

static void init(struct fmt_main *self)
{
	int keys;

	omp_autotune(self, OMP_SCALE);

	keys = self->params.max_keys_per_crypt;
	saved_key = mem_calloc(sizeof(*saved_key), keys);
	saved_len = mem_calloc(keys, sizeof(*saved_len));
	crypt_out = mem_calloc_align(sizeof(*crypt_out), keys, sizeof(uint64_t));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

// salt (username) is added to the ciphertext in the prepare function
static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	q = strrchr(p, '$'); // end of salt
	if (!q)
		return 0;

	if (q - p > MAX_SALT_LEN)
		return 0;

	if (q - p == 0)
		return 0;

	q = strrchr(ciphertext, '$') + 1;
	if (strlen(q) != BINARY_SIZE * 2)
		goto err;
	if (!ishex(q))
		goto err;

	return 1;

err:
	return 0;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	char* cp;

	if (!split_fields[0])
		return split_fields[1];
	if (strnlen(split_fields[1], BINARY_SIZE * 2 + 1) != BINARY_SIZE * 2)
		return split_fields[1];
	cp = mem_alloc(strlen(split_fields[0]) + strlen(split_fields[1]) + 2);
	sprintf(cp, "%s$%s", split_fields[0], split_fields[1]);
	if (valid(cp, self)) {
		char *cipher = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cipher;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *p, *q;

	memset(&cs, 0, sizeof(cs));
	p = ciphertext;
	q = strrchr(ciphertext, '$');

	strncpy((char*)cs.salt, p, q - p);
	cs.saltlen = q - p;

	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{	static union {
		unsigned char c[BINARY_SIZE+1];
		uint64_t dummy;
	} buf;
	int i;
	unsigned char *out = buf.c;
	char *p;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

/* using our own binary_hash_x() functions allows us to avoid BE / LE issues */
static int binary_hash_0(void *binary) { return *((uint64_t *)binary) & PH_MASK_0; }
static int binary_hash_1(void *binary) { return *((uint64_t *)binary) & PH_MASK_1; }
static int binary_hash_2(void *binary) { return *((uint64_t *)binary) & PH_MASK_2; }
static int binary_hash_3(void *binary) { return *((uint64_t *)binary) & PH_MASK_3; }
static int binary_hash_4(void *binary) { return *((uint64_t *)binary) & PH_MASK_4; }
static int binary_hash_5(void *binary) { return *((uint64_t *)binary) & PH_MASK_5; }
static int binary_hash_6(void *binary) { return *((uint64_t *)binary) & PH_MASK_6; }

#define COMMON_GET_HASH_64BIT_HASH
#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += NBKEYS) {
		sph_whirlpool_context wctx;
		int i;
		union {
			unsigned char buf[BINARY_SIZE];
			uint64_t p64[1];
		} output1[NBKEYS], output2;
#ifdef SIMD_COEF_64
		// Not sure why JTR_ALIGN(MEM_ALIGN_SIMD) does n ot work here
		// but if used, it cores travis-ci, so we use mem_align instead
		unsigned char _in[8*16*MIN_KEYS_PER_CRYPT+MEM_ALIGN_SIMD];
		unsigned char _out[8*8*MIN_KEYS_PER_CRYPT+MEM_ALIGN_SIMD];
		uint64_t *in = (uint64_t*)mem_align(_in, MEM_ALIGN_SIMD);
		uint64_t *out = (uint64_t*)mem_align(_out, MEM_ALIGN_SIMD);

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			int x80_off = saved_len[index+i]+cur_salt->saltlen;
			unsigned char *cp = (unsigned char*)&(in[16*i]);
			memcpy(cp, saved_key[index+i], saved_len[index+i]);
			memcpy(&cp[saved_len[index+i]], cur_salt->salt, cur_salt->saltlen);
			cp[x80_off] = 0x80;
			memset(&cp[x80_off+1], 0, 120-(x80_off+1));
			in[i*16+15] = x80_off<<3;
		}
		SIMDSHA512body(in, out, NULL, SSEi_FLAT_IN);
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
#if ARCH_LITTLE_ENDIAN==1
			output1[i].p64[0] = JOHNSWAP64(out[((i/SIMD_COEF_64)*8*SIMD_COEF_64+i%SIMD_COEF_64)]);
#else
			output1[i].p64[0] = out[((i/SIMD_COEF_64)*8*SIMD_COEF_64+i%SIMD_COEF_64)];
#endif
		}
#else
		SHA512_CTX sctx;

		SHA512_Init(&sctx);
		SHA512_Update(&sctx, saved_key[index], saved_len[index]);
		SHA512_Update(&sctx, cur_salt->salt, cur_salt->saltlen);
		SHA512_Final(output1[0].buf, &sctx);
#endif
		for (i = 0; i < NBKEYS; ++i) {
			sph_whirlpool_init(&wctx);
			sph_whirlpool(&wctx, cur_salt->salt, cur_salt->saltlen);
			sph_whirlpool(&wctx, saved_key[index+i], saved_len[index+i]);
			sph_whirlpool_close(&wctx, output2.buf);
			crypt_out[index+i][0] = output1[i].p64[0] ^ output2.p64[0];
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint64_t*)binary)[0] == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return ((uint64_t*)binary)[0] == crypt_out[index][0];
}

static int cmp_exact(char *source, int index)
{
	// don't worry about SIMD here.
	// we already are 64 bit 'sure'.  This extra check
	// is not really needed, but does not hurt much
	SHA512_CTX sctx;
	int i;
	void *bin = get_binary(source);
	sph_whirlpool_context wctx;
	unsigned char output1[BINARY_SIZE], output2[BINARY_SIZE];

	SHA512_Init(&sctx);
	SHA512_Update(&sctx, saved_key[index], saved_len[index]);
	SHA512_Update(&sctx, cur_salt->salt, cur_salt->saltlen);
	SHA512_Final(output1, &sctx);

	sph_whirlpool_init(&wctx);
	sph_whirlpool(&wctx, cur_salt->salt, cur_salt->saltlen);
	sph_whirlpool(&wctx, saved_key[index], saved_len[index]);
	sph_whirlpool_close(&wctx, output2);
	for (i = 0; i < BINARY_SIZE; ++i)
		output1[i] ^= output2[i];
	return !memcmp(output1, bin, BINARY_SIZE);
}

static void leet_set_key(char *key, int index)
{
	saved_len[index] =
		strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

// Public domain hash function by DJ Bernstein
static int salt_hash(void *salt)
{
	unsigned int hash = 5381;
	struct custom_salt *fck = (struct custom_salt *)salt;
	unsigned char *s = fck->salt;
	int length = fck->saltlen / 4;

	while (length) {
		hash = ((hash << 5) + hash) ^ *s++;
		length--;
	}
	return hash & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_leet = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{
			NULL,
		},
		{ NULL },
		leet_tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			NULL
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
		NULL,
		set_salt,
		leet_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
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

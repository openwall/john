/*
 * JtR format for cracking RACF KDFAES hashes (reference implementation).
 *
 * This software is Copyright (c) 2018, Bigendian Smalls <mainframe [at]
 * bigendiansmalls.com> and it is hereby released to the general public under
 * the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_racf_kdfaes;
#elif FMT_REGISTERS_H
john_register_one(&fmt_racf_kdfaes);
#else

#include <stdint.h>
#include <openssl/des.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               1

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "aes.h"
#include "sha2.h"
#include "memory.h"

#define FORMAT_LABEL            "RACF-KDFAES"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$racf$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "DES/HMAC-SHA256/AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x507
#define PLAINTEXT_LENGTH        8
#define CIPHERTEXT_LENGTH       96
#define BINARY_SIZE             16
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(uint32_t)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define MAX_SALT_SIZE           16
#define PAD_SIZE                64
#define HEADER                  "E7D7E66D00018000"
#define HEADER_LEN              (sizeof(HEADER)-1)
#define HASH_OUTPUT_SIZE        32

static const unsigned char a2e[256] = {
	0,  1,  2,  3, 55, 45, 46, 47, 22,  5, 37, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 60, 61, 50, 38, 24, 25, 63, 39, 28, 29, 30, 31,
	64, 79,127,123, 91,108, 80,125, 77, 93, 92, 78,107, 96, 75, 97,
	240,241,242,243,244,245,246,247,248,249,122, 94, 76,126,110,111,
	124,193,194,195,196,197,198,199,200,201,209,210,211,212,213,214,
	215,216,217,226,227,228,229,230,231,232,233, 74,224, 90, 95,109,
	121,129,130,131,132,133,134,135,136,137,145,146,147,148,149,150,
	151,152,153,162,163,164,165,166,167,168,169,192,106,208,161,  7,
	32, 33, 34, 35, 36, 21,  6, 23, 40, 41, 42, 43, 44,  9, 10, 27,
	48, 49, 26, 51, 52, 53, 54,  8, 56, 57, 58, 59,  4, 20, 62,225,
	65, 66, 67, 68, 69, 70, 71, 72, 73, 81, 82, 83, 84, 85, 86, 87,
	88, 89, 98, 99,100,101,102,103,104,105,112,113,114,115,116,117,
	118,119,120,128,138,139,140,141,142,143,144,154,155,156,157,158,
	159,160,170,171,172,173,174,175,176,177,178,179,180,181,182,183,
	184,185,186,187,188,189,190,191,202,203,204,205,206,207,218,219,
	220,221,222,223,234,235,236,237,238,239,250,251,252,253,254,255
};

/* This is a2e[] with each entry XOR 0x55, left-shifted one bit
   and finally with odd parity so that DES_set_key_unchecked
   can be used directly.  This provides about 15% speed up.    */
static const unsigned char a2e_precomputed[256] = {
	 171, 168, 174, 173, 196, 241, 247, 244, 134, 161, 224, 188, 179, 176, 182, 181,
	 138, 137, 143, 140, 211, 208, 206, 230, 155, 152, 213, 229, 146, 145, 151, 148,
	  42,  52,  84,  93,  28, 115,  11,  81,  49,  16,  19,  55, 124, 107,  61, 104,
	  74,  73,  79,  76,  67,  64,  70,  69,  91,  88,  94,  22,  50,  87, 118, 117,
	  82,  41,  47,  44,  35,  32,  38,  37,  59,  56,   8,  14,  13,   2,   1,   7,
	   4,  26,  25, 110, 109,  98,  97, 103, 100, 122, 121,  62, 107,  31,  21, 112,
	  88, 168, 174, 173, 162, 161, 167, 164, 186, 185, 137, 143, 140, 131, 128, 134,
	 133, 155, 152, 239, 236, 227, 224, 230, 229, 251, 248,  42, 127,  11, 233, 164,
	 234, 233, 239, 236, 227, 128, 167, 133, 251, 248, 254, 253, 242, 185, 191, 157,
	 203, 200, 158, 205, 194, 193, 199, 186, 218, 217, 223, 220, 162, 131, 214, 104,
	  41,  47,  44,  35,  32,  38,  37,  59,  56,   8,  14,  13,   2,   1,   7,   4,
	  26,  25, 110, 109,  98,  97, 103, 100, 122, 121,  74,  73,  79,  76,  67,  64,
	  70,  69,  91, 171, 191, 188, 179, 176, 182, 181, 138, 158, 157, 146, 145, 151,
	 148, 234, 254, 253, 242, 241, 247, 244, 203, 200, 206, 205, 194, 193, 199, 196,
	 218, 217, 223, 220, 211, 208, 214, 213,  62,  61,  50,  49,  55,  52,  31,  28,
	  19,  16,  22,  21, 127, 124, 115, 112, 118, 117,  94,  93,  82,  81,  87,  84
};

/* in-place ascii2ebcdic conversion */
static void ascii2ebcdic(unsigned char *str)
{
	int i;
	int n = strlen((const char*)str);

	for (i = 0; i < n; ++i)
		str[i] = a2e[str[i]];
}

/* replace missing characters in userid by EBCDIC spaces (0x40) */
static void process_userid(unsigned char *str)
{
	int i;

	for (i = strlen((const char*)str); i < 8; ++i)
		str[i] = 0x40;

	str[8] = 0; /* terminate string */
}

static struct fmt_tests racf_kdfaes_tests[] = {
	{"$racf$*USER1*E7D7E66D00018000000900320010001054FDAABCDEF012345674A0F58EE6137D203D3CD649E9E52F80A1F1B7CD263EE2", "P@ssw0rd"},
	{"$racf$*USER123*E7D7E66D00018000001000340010001054FDAABCDEF012345674A0F58EE6137D3B3AD9EC21E371BE67D5A75BE0E892B8", "openwall"},
	{ NULL }
};

static struct custom_salt {
	unsigned char userid[16]; /* 8 chars padded to AES block */
	uint32_t mfact_log2, mfact, rfact;
	uint8_t salt[MAX_SALT_SIZE + 8];
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(crypt_out);
}

static void *get_salt(char *ciphertext);

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p, *q;
	char *c;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	p = strtok(ctcopy, "*");
	if (!p)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)
		goto err;
	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;

	c = strrchr(ciphertext, '*');
	if (!c)
		goto err;
	if (strncmp(c + 1, HEADER, HEADER_LEN))  // header check
		goto err;

	if (!*q && q - p == CIPHERTEXT_LENGTH) {
		struct custom_salt *cs = get_salt(ciphertext);
		if (!cs->mfact || !cs->rfact)
			goto err;

		MEM_FREE(keeptr);
		return 1;
	}

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '*') + 65;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy, *username;
	char *p;
	char hexstr[5];
	unsigned long v;
	int i;

	memset(&cs, 0, sizeof(cs));

	ctcopy += FORMAT_TAG_LEN;
	username = strtok(ctcopy, "*");

	strncpy((char*)cs.userid, username, 8);
	ascii2ebcdic(cs.userid);
	process_userid(cs.userid);

	p = strrchr(ciphertext, '*');

	memcpy(hexstr, p + HEADER_LEN + 1, 4);
	hexstr[4] = 0;
	v = strtoul(hexstr, NULL, 16);
	if (v >= 8 && v <= 16) {
		cs.mfact_log2 = v;
		cs.mfact = v = (1U << v) / HASH_OUTPUT_SIZE;
	}

	memcpy(hexstr, p + HEADER_LEN + 1 + 4, 4);
	v = strtoul(hexstr, NULL, 16);
	if (v >= 50 && v <= 1000)
		cs.rfact = v;

	p += 33;
	for (i = 0; i < MAX_SALT_SIZE; i++) {
		cs.salt[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	for (; i < MAX_SALT_SIZE+7; i++)
		cs.salt[i] = 0;
	cs.salt[MAX_SALT_SIZE+2] = (cs.mfact >> 8);
	cs.salt[MAX_SALT_SIZE+3] = (cs.mfact & 0xff);
	cs.salt[MAX_SALT_SIZE+7] = 1;

	MEM_FREE(keeptr);
	return (void *)&cs;
}

static int salt_hash(void *salt)
{
	struct custom_salt *cs = (struct custom_salt *)salt;
	union {
		uint8_t u8[4];
		uint32_t u32;
	} u;
	u.u8[0] = cs->salt[0];
	u.u8[1] = cs->salt[1];
	u.u8[2] = cs->salt[2];
	u.u8[3] = cs->salt[3];
	u.u32 += cs->mfact + cs->rfact;
	return (*(uint32_t *)salt + u.u32) & (SALT_HASH_SIZE - 1);
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void racf_kdfaes_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static void get_des_hash(char *key, unsigned char *dhash)
{
	DES_cblock des_key;
	DES_key_schedule schedule;
	DES_cblock ivec;
	int j;

	for (j = 0; key[j]; j++)
		des_key[j] = a2e_precomputed[ARCH_INDEX(key[j])];

	while (j < 8)
		des_key[j++] = 0x2a;

	DES_set_key_unchecked(&des_key, &schedule);

	memset(ivec, 0, 8);
	DES_cbc_encrypt(cur_salt->userid, dhash, 8, &schedule, &ivec, DES_ENCRYPT);
}

#define HMAC_SHA_IPAD_XOR 0x3636363636363636ULL
#define HMAC_SHA_OPAD_XOR 0x5c5c5c5c5c5c5c5cULL

#define hash_xor_input(a, b, c) \
	a[0] ^= b; \
	a[1] ^= b; \
	a[2] ^= b; \
	a[3] ^= b; \
	a[4] = c; \
	a[5] = c; \
	a[6] = c; \
	a[7] = c;

typedef union {
	unsigned char uc[64];
	uint64_t u64[8];
} hash_input;

typedef union {
	unsigned char uc[32];
	uint64_t u64[4];
} hash_output;

typedef struct {
	SHA256_CTX ictx, octx;
} hmac_sha256_ctx;

static MAYBE_INLINE void hmac_sha256_start(hmac_sha256_ctx *ctx, const unsigned char *key, size_t key_len) {
	hash_input buf;

	/* assert(key_len <= 32); */
	memcpy(buf.uc, key, key_len);
	memset(&buf.uc[key_len], 0, 32 - key_len);
	hash_xor_input(buf.u64, HMAC_SHA_IPAD_XOR, HMAC_SHA_IPAD_XOR);
	SHA256_Init(&ctx->ictx);
	SHA256_Update(&ctx->ictx, buf.uc, 64);
	hash_xor_input(buf.u64, HMAC_SHA_IPAD_XOR ^ HMAC_SHA_OPAD_XOR, HMAC_SHA_OPAD_XOR);
	SHA256_Init(&ctx->octx);
	SHA256_Update(&ctx->octx, buf.uc, 64);
}

static MAYBE_INLINE void hmac_sha256_finish(hmac_sha256_ctx *ctx, const unsigned char *data, size_t data_len, unsigned char *digest) {
	hash_output local_digest;

	SHA256_Update(&ctx->ictx, data, data_len);
	SHA256_Final(local_digest.uc, &ctx->ictx);
	SHA256_Update(&ctx->octx, local_digest.uc, sizeof(local_digest));
	SHA256_Final(digest, &ctx->octx);
}

static MAYBE_INLINE void hmac_sha256_finish_const(const hmac_sha256_ctx *ctx, const unsigned char *data, size_t data_len, unsigned char *digest) {
	hmac_sha256_ctx tmp = *ctx;
	hmac_sha256_finish(&tmp, data, data_len, digest);
}

static MAYBE_INLINE void hmac_sha256_full(const unsigned char *key, size_t key_len, const unsigned char *data, size_t data_len, unsigned char *digest) {
	hmac_sha256_ctx ctx;

	hmac_sha256_start(&ctx, key, key_len);
	hmac_sha256_finish(&ctx, data, data_len, digest);
}

#define hash_xor(a, b) \
	a.u64[0] ^= b.u64[0]; \
	a.u64[1] ^= b.u64[1]; \
	a.u64[2] ^= b.u64[2]; \
	a.u64[3] ^= b.u64[3];

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		const uint32_t rounds = cur_salt->rfact * 100 - 1;
		const uint32_t mask = cur_salt->mfact - 1;
		uint32_t r, n, ml;
		hash_output *t1p, *t1f = mem_alloc(HASH_OUTPUT_SIZE * cur_salt->mfact);
		hash_output h, t1;
		union {
			unsigned char uc[52];
			hash_output h;
		} m;
		hmac_sha256_ctx ctx;
		unsigned char dh[8];
		AES_KEY akey;

		ml = sizeof(cur_salt->salt);
		memcpy(m.uc, cur_salt->salt, ml);

		// get des hash
		get_des_hash(saved_key[index], dh);  // k1

		// kdf
		hmac_sha256_start(&ctx, dh, 8);
		memcpy(m.uc+48, "\x00\x00\x00\x01", 4);
		t1p = t1f;
		n = cur_salt->mfact;
		do {
			hmac_sha256_finish_const(&ctx, m.uc, ml, h.uc);

			t1 = h;
			r = rounds - 1;
			do {
				hmac_sha256_finish_const(&ctx, h.uc, HASH_OUTPUT_SIZE, h.uc);
				hash_xor(t1, h);
			} while (--r);
			memcpy(m.uc, h.uc, 16);
			hmac_sha256_finish_const(&ctx, h.uc, HASH_OUTPUT_SIZE, h.uc);
			hash_xor(t1, h);

			memcpy(m.uc+16, t1.uc, HASH_OUTPUT_SIZE);
			ml = 52;
			*t1p++ = t1;
		} while (--n);

		t1p = &t1;
		memcpy(m.uc + HASH_OUTPUT_SIZE, "\x00\x00\x00\x01", 4);
		for (n = 0; n <= mask; n++) {
			m.h = t1f[(((uint32_t)t1p->uc[30] << 8) | t1p->uc[31]) & mask];
			hmac_sha256_full(t1p->uc, HASH_OUTPUT_SIZE, m.uc, HASH_OUTPUT_SIZE + 4, t1f[n].uc);
			t1p = &t1f[n];
		}

		hmac_sha256_start(&ctx, t1p->uc, HASH_OUTPUT_SIZE);
		hmac_sha256_finish_const(&ctx, t1f->uc, ml, h.uc);

		memcpy(t1f[mask].uc, "\x00\x00\x00\x01", 4);
		hmac_sha256_finish_const(&ctx, t1f->uc, (HASH_OUTPUT_SIZE * mask) + 4, h.uc);

		t1 = h;
		r = rounds;
		do {
			hmac_sha256_finish_const(&ctx, h.uc, HASH_OUTPUT_SIZE, h.uc);
			hash_xor(t1, h);
		} while (--r);

		// encrypt user name
		AES_set_encrypt_key(t1.uc, 256, &akey);
		AES_encrypt(cur_salt->userid, (unsigned char *)crypt_out[index], &akey);

		MEM_FREE(t1f);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;

	for (; index < count; index++) {
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
			return 1;
	}

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

static unsigned int tunable_cost_mfact(void *_salt)
{
	struct custom_salt *salt = (struct custom_salt *)_salt;
	return salt->mfact_log2;
}

static unsigned int tunable_cost_rfact(void *_salt)
{
	struct custom_salt *salt = (struct custom_salt *)_salt;
	return salt->rfact;
}

struct fmt_main fmt_racf_kdfaes = {
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
		{"PMEM", "PREP"},
		{ FORMAT_TAG },
		racf_kdfaes_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{tunable_cost_mfact, tunable_cost_rfact},
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
		salt_hash,
		NULL,
		set_salt,
		racf_kdfaes_set_key,
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
#endif /* HAVE_LIBCRYPTO */

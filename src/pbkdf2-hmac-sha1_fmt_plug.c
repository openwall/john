/*
 * This software is Copyright (c) 2013 magnum and it is hereby released to
 * the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pbkdf2_hmac_sha1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pbkdf2_hmac_sha1);
#else

#include <ctype.h>
#include <string.h>
#include <assert.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "base64_convert.h"
#include "stdint.h"
#define PBKDF2_HMAC_SHA1_ALSO_INCLUDE_CTX 1
#include "pbkdf2_hmac_sha1.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               64
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL            "PBKDF2-HMAC-SHA1"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$pbkdf2-hmac-sha1$"
#define PKCS5S2_TAG             "{PKCS5S2}"
#define PK5K2_TAG               "$p5k2$"

#define TAG_LEN                 (sizeof(FORMAT_TAG) - 1)

#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 32/" ARCH_BITS_STR
#endif

#define BINARY_SIZE             20
#define BINARY_ALIGN            sizeof(ARCH_WORD_32)
#define MAX_BINARY_SIZE         (4 * BINARY_SIZE)
#define MAX_SALT_SIZE           64
#define MAX_CIPHERTEXT_LENGTH   (TAG_LEN + 6 + 1 + 2*MAX_SALT_SIZE + 1 + 2*MAX_BINARY_SIZE)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(ARCH_WORD_32)

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

#define PAD_SIZE                64
#define PLAINTEXT_LENGTH        125

static struct fmt_tests tests[] = {
	{"$pbkdf2-hmac-sha1$1000.fd11cde0.27de197171e6d49fc5f55c9ef06c0d8751cd7250", "3956"},
	{"$pbkdf2-hmac-sha1$1000.6926d45e.231c561018a4cee662df7cd4a8206701c5806af9", "1234"},
	{"$pbkdf2-hmac-sha1$1000.98fcb0db.37082711ff503c2d2dea9a5cf7853437c274d32e", "5490"},
	// WPA-PSK DK (raw key as stored by some routers)
	// ESSID was "Harkonen" - converted to hex 4861726b6f6e656e
	{"$pbkdf2-hmac-sha1$4096$4861726b6f6e656e$ee51883793a6f68e9615fe73c80a3aa6f2dd0ea537bce627b929183cc6e57925", "12345678"},
	// these get converted in prepare()
	// http://pythonhosted.org/passlib/lib/passlib.hash.atlassian_pbkdf2_sha1.html, 10000 iterations
	{"{PKCS5S2}DQIXJU038u4P7FdsuFTY/+35bm41kfjZa57UrdxHp2Mu3qF2uy+ooD+jF5t1tb8J", "password"},
	// http://pythonhosted.org/passlib/lib/passlib.hash.cta_pbkdf2_sha1.html, 10000 iterations
	{"$p5k2$2710$oX9ZZOcNgYoAsYL-8bqxKg==$AU2JLf2rNxWoZxWxRCluY0u6h6c=", "password" },
	{NULL}
};

static struct custom_salt {
	unsigned int length;
	unsigned int rounds;
	unsigned int use_utf8;
	//unsigned int outlen; /* Not used yet */
	unsigned char salt[MAX_SALT_SIZE];
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static char *prepare(char *fields[10], struct fmt_main *self)
{
	static char Buf[256];
	if (strncmp(fields[1], PKCS5S2_TAG, 9) != 0 && strncmp(fields[1], PK5K2_TAG, 6))
		return fields[1];
	if (!strncmp(fields[1], PKCS5S2_TAG, 9)) {
		char tmp[120+4];
		if (strlen(fields[1]) > 75) return fields[1];
		//{"{PKCS5S2}DQIXJU038u4P7FdsuFTY/+35bm41kfjZa57UrdxHp2Mu3qF2uy+ooD+jF5t1tb8J", "password"},
		//{"$pbkdf2-hmac-sha1$10000.0d0217254d37f2ee0fec576cb854d8ff.edf96e6e3591f8d96b9ed4addc47a7632edea176bb2fa8a03fa3179b75b5bf09", "password"},
		base64_convert(&(fields[1][9]), e_b64_mime, strlen(&(fields[1][9])), tmp, e_b64_hex, sizeof(tmp), 0);
		sprintf(Buf, "$pbkdf2-hmac-Sha1$10000.%32.32s.%s", tmp, &tmp[32]);
		return Buf;
	}
	if (!strncmp(fields[1], PK5K2_TAG, 6)) {
		char tmps[140+4], tmph[70+4], *cp, *cp2;
		unsigned iter=0;
		// salt was listed as 1024 bytes max. But our max salt size is 64 bytes (~90 base64 bytes).
		if (strlen(fields[1]) > 128) return fields[1];
		//{"$p5k2$2710$oX9ZZOcNgYoAsYL-8bqxKg==$AU2JLf2rNxWoZxWxRCluY0u6h6c=", "password" },
		//{"$pbkdf2-hmac-sha1$10000.a17f5964e70d818a00b182fef1bab12a.014d892dfdab3715a86715b144296e634bba87a7", "password"},
		cp = fields[1];
		cp += 6;
		while (*cp && *cp != '$') {
			iter *= 0x10;
			iter += atoi16[ARCH_INDEX(*cp)];
			++cp;
		}
		if (*cp != '$') return fields[1];
		++cp;
		cp2 = strchr(cp, '$');
		if (!cp2) return fields[1];
		base64_convert(cp, e_b64_mime, cp2-cp, tmps, e_b64_hex, sizeof(tmps), flg_Base64_MIME_DASH_UNDER);
		++cp2;
		base64_convert(cp2, e_b64_mime, strlen(cp2), tmph, e_b64_hex, sizeof(tmph), flg_Base64_MIME_DASH_UNDER);
		sprintf(Buf, "$pbkdf2-hmac-Sha1$%d.%s.%s", iter, tmps, tmph);
		return Buf;
	}
	return fields[1];
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ptr, *ctcopy, *keeptr;
	size_t len;
	char *delim;

	if (strncasecmp(ciphertext, FORMAT_TAG, TAG_LEN))
		return 0;

	if (strlen(ciphertext) > MAX_CIPHERTEXT_LENGTH)
		return 0;

	ciphertext += TAG_LEN;

	delim = strchr(ciphertext, '.') ? "." : "$";

	if (!(ctcopy = strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	if (!(ptr = strtokm(ctcopy, delim)))
		goto error;
	if (!atou(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, delim)))
		goto error;
	len = strlen(ptr); // salt hex length
	if (len > 2 * MAX_SALT_SIZE || len & 1)
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, delim)))
		goto error;
	len = strlen(ptr); // binary length
	if (len < BINARY_SIZE || len > MAX_BINARY_SIZE || len & 1)
		goto error;
	if (!ishex(ptr))
		goto error;
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[MAX_CIPHERTEXT_LENGTH + 1];

	strnzcpy(out, ciphertext, sizeof(out));
	strlwr(out);
	return out;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *p;
	int saltlen;
	char delim;

	if (!strncasecmp(ciphertext, FORMAT_TAG, sizeof(FORMAT_TAG) - 1))
		ciphertext += sizeof(FORMAT_TAG) - 1;
	cs.use_utf8 = ciphertext[13] == 'S';
	cs.rounds = atou(ciphertext);
	delim = strchr(ciphertext, '.') ? '.' : '$';
	ciphertext = strchr(ciphertext, delim) + 1;
	p = strchr(ciphertext, delim);
	saltlen = 0;
	memset(cs.salt, 0, sizeof(cs.salt));
	while (ciphertext < p) {        /** extract salt **/
		cs.salt[saltlen++] =
			atoi16[ARCH_INDEX(ciphertext[0])] * 16 +
			atoi16[ARCH_INDEX(ciphertext[1])];
		ciphertext += 2;
	}
	cs.length = saltlen;

	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[MAX_BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i, len;
	char delim;

	delim = strchr(ciphertext, '.') ? '.' : '$';
	p = strrchr(ciphertext, delim) + 1;
	len = strlen(p) / 2;
	for (i = 0; i < len && *p; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#if !ARCH_LITTLE_ENDIAN
	for (i = 0; i < len/sizeof(ARCH_WORD_32); ++i) {
		((ARCH_WORD_32*)out)[i] = JOHNSWAP(((ARCH_WORD_32*)out)[i]);
	}
#endif
	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
	{
#ifdef SSE_GROUP_SZ_SHA1
		int lens[SSE_GROUP_SZ_SHA1], i;
		unsigned char *pin[SSE_GROUP_SZ_SHA1];
		union {
			ARCH_WORD_32 *pout[SSE_GROUP_SZ_SHA1];
			unsigned char *poutc;
		} x;
		for (i = 0; i < SSE_GROUP_SZ_SHA1; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			x.pout[i] = crypt_out[index+i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens,
		                cur_salt->salt, cur_salt->length,
		                cur_salt->rounds, &(x.poutc),
		                BINARY_SIZE, 0);
#else
		pbkdf2_sha1((const unsigned char*)(saved_key[index]),
		            strlen(saved_key[index]),
		            cur_salt->salt, cur_salt->length,
		            cur_salt->rounds, (unsigned char*)crypt_out[index],
		            BINARY_SIZE, 0);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

/* Check the FULL binary, just for good measure. There is no chance we'll
   have a false positive here but this function is not performance sensitive. */
static int cmp_exact(char *source, int index)
{
	int i = 0, len, result;
	char *p;
	char delim;
	unsigned char *binary, *crypt;

	delim = strchr(source, '.') ? '.' : '$';
	p = strrchr(source, delim) + 1;
	len = strlen(p) / 2;

	if (len == BINARY_SIZE) return 1;

	binary = mem_alloc(len);
	crypt = mem_alloc(len);

	while (*p) {
		binary[i++] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#if !ARCH_LITTLE_ENDIAN
	for (i = 0; i < len/sizeof(ARCH_WORD_32); ++i) {
		((ARCH_WORD_32*)binary)[i] = JOHNSWAP(((ARCH_WORD_32*)binary)[i]);
	}
#endif
	pbkdf2_sha1((const unsigned char*)(saved_key[index]),
	            strlen(saved_key[index]),
	            cur_salt->salt, cur_salt->length,
	            cur_salt->rounds, crypt, len, 0);
	result = !memcmp(binary, crypt, len);
	//dump_stuff_msg("hash binary", binary, len);
	//dump_stuff_msg("calc binary", crypt, len);
	MEM_FREE(binary);
	MEM_FREE(crypt);
	if (!result)
		fprintf(stderr, "\n%s: Warning: Partial match for '%s'.\n"
		        "This is a bug or a malformed input line of:\n%s\n",
		        FORMAT_LABEL, saved_key[index], source);
	return result;
}

static void set_key(char *key, int index)
{
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->rounds;
}
#endif

struct fmt_main fmt_pbkdf2_hmac_sha1 = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
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
		NULL,
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

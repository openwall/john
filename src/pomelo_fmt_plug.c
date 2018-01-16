/*
 * POMELO cracker patch for JtR. Hacked together during the Hash Runner 2015
 * contest by Dhiru Kholia.
 */

#include "arch.h"

// Enable this format only on little-endian systems
#if ARCH_LITTLE_ENDIAN

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pomelo;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pomelo);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "memdbg.h"

#define FORMAT_LABEL            "pomelo"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$pomelo$"
#define TAG_LENGTH              sizeof(FORMAT_TAG) - 1

#if !defined(JOHN_NO_SIMD) && defined(__AVX2__)
#define ALGORITHM_NAME          "POMELO 256/256 AVX2 1x"
#elif !defined(JOHN_NO_SIMD) && defined(__SSE2__)
#define ALGORITHM_NAME          "POMELO 128/128 SSE2 1x"
#elif !defined(USE_GCC_ASM_IA32) && defined(USE_GCC_ASM_X64)
#define ALGORITHM_NAME          "POMELO 64/64"
#else
#define ALGORITHM_NAME          "POMELO 32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        125
#define CIPHERTEXT_LENGTH       64
#define BINARY_SIZE             32
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      16

#ifndef OMP_SCALE
#define OMP_SCALE               8 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests pomelo_tests[] = {
	{"$pomelo$2$3$hash runner 2015$8333ad83e46e425872c5545741d6da105cd31ad58926e437d32247e59b26703e", "HashRunner2014"},
	{"$pomelo$2$3$mysalt$b5bebcd9820de6a58dba52abf76aaf6eed4c5c672dbda64e69e3e3cbcc401314", "password"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt {
	unsigned char salt[64];
	unsigned int saltlen;
	unsigned int t_cost;
	unsigned int m_cost;
} *cur_salt;


static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	if (!saved_key) {
		saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
		crypt_out = mem_calloc(self->params.max_keys_per_crypt,	sizeof(*crypt_out));
	}
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext;
	char Buf[256];

	if (strncmp(p, FORMAT_TAG, TAG_LENGTH))
		return 0;

	p += TAG_LENGTH;
	strnzcpy(Buf, p, sizeof(Buf));

	p = strtokm(Buf, "$");
	if (!p || !isdec(p))
		return 0;
	p = strtokm(NULL, "$");
	if (!p || !isdec(p))
		return 0;
	p = strtokm(NULL, "$");
	if (!p || strlen(p) >= sizeof(cur_salt->salt))
		return 0;
	p = strtokm(NULL, "$");
	if (!p || strlen(p) != CIPHERTEXT_LENGTH)
		return 0;

	while(*p)
		if (atoi16l[ARCH_INDEX(*p++)] == 0x7f)
			return 0;

	return 1;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *p, *q;

	memset(&cs, 0, sizeof(cs));
	p = ciphertext + TAG_LENGTH;
	cs.t_cost = atoi(p);
	p = strchr(p, '$') + 1;
	cs.m_cost = atoi(p);
	p = strchr(p, '$') + 1;
	q = strchr(p, '$');

	cs.saltlen = q - p;
	strncpy((char*)cs.salt, p, cs.saltlen);

	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	int i;
	char *p = strrchr(ciphertext, '$') + 1;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);
	memset(out, 0, BINARY_SIZE);

	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

int PHS_pomelo(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		PHS_pomelo((unsigned char *)crypt_out[index], 32, saved_key[index], strlen(saved_key[index]), cur_salt->salt, cur_salt->saltlen, cur_salt->t_cost, cur_salt->m_cost);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
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

static void pomelo_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_pomelo = {
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
		{ NULL },
		{ FORMAT_TAG },
		pomelo_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL },
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
		pomelo_set_key,
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

#endif /* ARCH_LITTLE_ENDIAN */

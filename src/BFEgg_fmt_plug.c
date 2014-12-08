/*
 * This file is part of Eggdrop blowfish patch for John The Ripper.
 * Copyright (c) 2002 by Sun-Zero <sun-zero at freemail.hu>
 * This is a free software distributable under terms of the GNU GPL.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_BFEgg;
#elif FMT_REGISTERS_H
john_register_one(&fmt_BFEgg);
#else

#include <string.h>

#include "misc.h"
#include "formats.h"
#include "common.h"
#include "blowfish.c"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
// Tuning on AMD A8 4500M laptop, cygwin64 with OMP(4x) -test=5
// 4   = 44330 (original)
// 16  = 54760
// 24  = 56151
// 32  = 56216
// 64  = 57770
// 96  = 57888
// 128 = 58016  > instant -test=0
// 256 = 58282  // from here on, not enough gain to matter.
// 512 = 58573
// 1024= 59464
// 4096= 59244  > 1s -test=0
#define OMP_SCALE               128
#endif
#include "memdbg.h"

#define FORMAT_LABEL			"bfegg"
#define FORMAT_NAME			"Eggdrop"
#define ALGORITHM_NAME			"Blowfish 32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		31
#define CIPHERTEXT_LENGTH		13

#define BINARY_SIZE			7
#define BINARY_ALIGN			4
#define SALT_SIZE			0
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
    {"+9F93o1OxwgK1", "123456"},
    {"+C/.8o.Wuph9.", "qwerty"},
    {"+EEHgy/MBLDd0", "walkman"},
    {"+vPBrs07OTXE/", "tesztuser"},
    {"+zIvO/1nDsd9.", "654321"},
    {NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[(BINARY_SIZE + 1) / sizeof(ARCH_WORD_32)];

#if defined (_MSC_VER) || defined (__MINGW32__)
// in VC, _atoi64 is a function.
#define _atoi64 JtR_atoi64
#endif

static const char _itoa64[] = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static char _atoi64[0x100];

static int valid(char *ciphertext, struct fmt_main *self) {
    char *pos;

    if (*ciphertext != '+') return 0;
    if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;

    for (pos = &ciphertext[1]; atoi64[ARCH_INDEX(*pos)] != 0x7F; pos++);
    if (*pos || pos - ciphertext != CIPHERTEXT_LENGTH) return 0;

    return 1;
}

void init(struct fmt_main *self) {
    const char *pos;

#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);

    memset(_atoi64, 0x7F, sizeof(_atoi64));
    for (pos = _itoa64; pos <= &_itoa64[63]; pos++)
        _atoi64[ARCH_INDEX(*pos)] = pos - _itoa64;
}

/* The base64 is flawed - we just mimic flaws from the original code */
static void *binary(char *ciphertext)
{
	static union toalign {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD_32 a[1];
	} a;
	unsigned char *out = a.c;
	ARCH_WORD_32 value;
	char *pos;

	pos = ciphertext + 1;

	value = (ARCH_WORD_32)_atoi64[ARCH_INDEX(pos[0])] |
		((ARCH_WORD_32)_atoi64[ARCH_INDEX(pos[1])] << 6) |
		((ARCH_WORD_32)_atoi64[ARCH_INDEX(pos[2])] << 12) |
		((ARCH_WORD_32)_atoi64[ARCH_INDEX(pos[3])] << 18);
	out[0] = value;
	out[1] = value >> 8;
	out[2] = value >> 16;
	out[3] = _atoi64[ARCH_INDEX(pos[4])] |
		(_atoi64[ARCH_INDEX(pos[5])] << 6);
	pos += 6;
	value = (ARCH_WORD_32)_atoi64[ARCH_INDEX(pos[0])] |
		((ARCH_WORD_32)_atoi64[ARCH_INDEX(pos[1])] << 6) |
		((ARCH_WORD_32)_atoi64[ARCH_INDEX(pos[2])] << 12) |
		((ARCH_WORD_32)_atoi64[ARCH_INDEX(pos[3])] << 18);
	out[4] = value;
	out[5] = value >> 8;
	out[6] = value >> 16;

	return (void *)out;
}

static void set_key(char *key, int index) {
    strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH+1);
}

static char *get_key(int index) {
  return saved_key[index];
}

static int cmp_all(void *binary, int count) {
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index) {
  return 1;
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
	int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		/*if (saved_key[index][0] == '\0') {
			zerolengthkey = 1;
		} else {
			zerolengthkey = 0; */
		if (saved_key[index][0] != 0)
			blowfish_encrypt_pass(saved_key[index],
				(char*)crypt_out[index]);
	}
	return count;
}

struct fmt_main fmt_BFEgg = {
  {
    FORMAT_LABEL,
    FORMAT_NAME,
    ALGORITHM_NAME,
    BENCHMARK_COMMENT,
    BENCHMARK_LENGTH,
    PLAINTEXT_LENGTH,
    BINARY_SIZE,
    BINARY_ALIGN,
    SALT_SIZE,
    SALT_ALIGN,
    MIN_KEYS_PER_CRYPT,
    MAX_KEYS_PER_CRYPT,
    FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
    tests
  }, {
    init,
    fmt_default_done,
    fmt_default_reset,
    fmt_default_prepare,
    valid,
    fmt_default_split,
    binary,
    fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
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
	fmt_default_set_salt,
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

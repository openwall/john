/*
 * This file is part of Eggdrop blowfish patch for John The Ripper.
 * Copyright (c) 2002 by Sun-Zero <sun-zero at freemail.hu>
 * This is a free software distributable under terms of the GNU GPL.
 */

#include <string.h>

#include "misc.h"
#include "formats.h"
#include "common.h"
#include "blowfish.c"

#define FORMAT_LABEL			"bfegg"
#define FORMAT_NAME			"Eggdrop Blowfish"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		31
#define CIPHERTEXT_LENGTH		13

#define BINARY_SIZE			7
#define SALT_SIZE			0

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

int zerolengthkey = 0;

static char crypt_key[BINARY_SIZE];
static char saved_key[PLAINTEXT_LENGTH + 1];

#if defined (_MSC_VER) || defined (__MINGW32__)
// in VC, _atoi64 is a function.
#define _atoi64 JtR_atoi64
#endif

static char _itoa64[] = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static char _atoi64[0x100];

static int valid(char *ciphertext, struct fmt_main *self) {
    char *pos;

    if (strncmp(ciphertext, "+", 1) != 0) return 0;
    if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;

    for (pos = &ciphertext[1]; atoi64[ARCH_INDEX(*pos)] != 0x7F; pos++);
    if (*pos || pos - ciphertext != CIPHERTEXT_LENGTH) return 0;

    return 1;
}

void init(struct fmt_main *self) {
    char *pos;

    memset(_atoi64, 0x7F, sizeof(_atoi64));
    for (pos = _itoa64; pos <= &_itoa64[63]; pos++)
        _atoi64[ARCH_INDEX(*pos)] = pos - _itoa64;

    blowfish_first_init();
}

/* The base64 is flawed - we just mimic flaws from the original code */
static void *binary(char *ciphertext)
{
	static char out[BINARY_SIZE];
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
    strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
}

static char *get_key(int index) {
  return saved_key;
}

static int cmp_all(void *binary, int count) {
  if (zerolengthkey) return 0;
  return !memcmp(binary, crypt_key, BINARY_SIZE);
}

static int cmp_exact(char *source, int index) {
  return 1;
}

static void crypt_all(int count) {
    if (saved_key[0] == '\0') {
	zerolengthkey = 1;
    } else {
	zerolengthkey = 0;
        blowfish_encrypt_pass(saved_key, crypt_key);
    }
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
    SALT_SIZE,
    MIN_KEYS_PER_CRYPT,
    MAX_KEYS_PER_CRYPT,
    FMT_CASE | FMT_8_BIT,
    tests
  }, {
    init,
	fmt_default_prepare,
    valid,
    fmt_default_split,
    binary,
    fmt_default_salt,
    {
	fmt_default_binary_hash,
	fmt_default_binary_hash,
	fmt_default_binary_hash,
	fmt_default_binary_hash,
	fmt_default_binary_hash
    },
	fmt_default_salt_hash,
	fmt_default_set_salt,
	set_key,
	get_key,
	fmt_default_clear_keys,
	crypt_all,
	{
	    fmt_default_get_hash,
	    fmt_default_get_hash,
	    fmt_default_get_hash,
	    fmt_default_get_hash,
	    fmt_default_get_hash
	},
	    cmp_all,
	    cmp_all,
	    cmp_exact
  }
};

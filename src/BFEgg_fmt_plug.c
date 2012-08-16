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
#define CIPHERTEXT_LENGTH		33

#define BINARY_SIZE			13
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

static char crypt_key[BINARY_SIZE + 1];
static char saved_key[PLAINTEXT_LENGTH + 1];

static int valid(char *ciphertext, struct fmt_main *self) {
    if (strncmp(ciphertext, "+", 1) != 0) return 0;
    if (strlen(ciphertext) != 13) return 0;

    return 1;
}

void init(struct fmt_main *self) {
    blowfish_first_init();
}


static void set_key(char *key, int index) {
    strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
}

static char *get_key(int index) {
  return saved_key;
}

static int cmp_all(void *binary, int index) {
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
    fmt_default_binary,
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

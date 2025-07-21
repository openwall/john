/*
* Format for cracking BackDrop CMS database passwords
* Hash logic in python is like:
*
* count = 2**NITER
* result = hashlib.sha512(salt + password).digest()
* while count > 0:
*     result = hashlib.sha512(result + password).digest()
*     count -= 1
* return result
*
*/

#if FMT_EXTERNS_H
extern struct fmt_main fmt_backdrop;
#elif FMT_REGISTERS_H
john_register_one(&fmt_backdrop);
#else

#include <string.h>
#include <ctype.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "jtr_sha2.h"
#include "md5.h"
#include "rc4.h"
#include "jumbo.h"
#include "unicode.h"
#include "base64_convert.h"

#define FORMAT_LABEL            "backdrop"
#define FORMAT_NAME             "BackDrop CMS"
#define FORMAT_TAG              "$backdrop$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "SHA512 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define BINARY_SIZE             0
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define SALT_LENGTH             8
#define PLAINTEXT_LENGTH        25
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      8   /* Otherwise, pre-test is too long to complete */
#define MAX_ENCRYPTED_LEN       55-12   /* Hash is truncated to 55 character, prefix is 12 char long */
#define MAX_ENCRYPTED_BYTES_LEN 32
#define BACKDROP_MAX_HASH_COUNT 30

#define SHA512_LEN              64

#ifndef OMP_SCALE
#define OMP_SCALE               1   /* Otherwise, pre-test is too long to complete */
#endif

#define B64_ALPHABET            "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

static struct fmt_tests backdrop_tests[] = {
	/* RAW backdrop CMS format is $S$EEAGFzd8HSQ/IzwpqI79aJgRvqZnH4JSKLv2C83wUphw0nuoTY8v*/
	{"$backdrop$S$EEAGFzd8HSQ/IzwpqI79aJgRvqZnH4JSKLv2C83wUphw0nuoTY8v", "BackDropJ2024DS2024"},
	{"$backdrop$S$GqX57SsAfRin5BjWbWU2fVPyn7g6OXhIQNp8F3r53DItd/DH79rm", "openwall"},
	{NULL}
};

/* Original password */
static char (*orig_key)[PLAINTEXT_LENGTH + 1];
/* Salted password */
static char (*saved_key)[PLAINTEXT_LENGTH + SALT_LENGTH + 1];
/* SHA512 internal salted password */
static char (*saved_internal_key)[PLAINTEXT_LENGTH + SHA512_LEN + 1];
/* Length of current original password */
static int *saved_len;
static int *cracked, cracked_count;

static struct custom_salt {
	uint32_t type; /* 1 for SHA512 */
	uint64_t nb_iter;  /* number of hash iterations */
	unsigned char salt[8];  /* salt value */
	unsigned char encrypted_bytes[MAX_ENCRYPTED_LEN];  /* encrypted password value */
} *cur_salt;


int get_letter_position(const char *str, char letter)
{
	char *pos = strchr(str, letter);
	if (pos != NULL) {
		return pos - str;  /* pointer arithmetic gives index */
	} else {
		return -1;  /* not found */
	}
}

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	orig_key = mem_calloc(sizeof(*orig_key), self->params.max_keys_per_crypt);
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_internal_key = mem_calloc(sizeof(*saved_internal_key), self->params.max_keys_per_crypt);

	saved_len = mem_calloc(sizeof(*saved_len), self->params.max_keys_per_crypt);

	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	MEM_FREE(orig_key);
	MEM_FREE(saved_key);
	MEM_FREE(saved_internal_key);
	MEM_FREE(saved_len);
	MEM_FREE(cracked);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0) {
		return 0;
	}

	char *ctcopy, *keeptr;
	int ltr_pos = -1;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;

	if (strlen(ctcopy) == 54) { /* Hash type S, SHA512 */
		if (ctcopy[0] != 'S' || ctcopy[1] != '$') {
			goto err;
		}
		ctcopy += 2;

		/* Check log2 number of iteration bounds */
		ltr_pos = get_letter_position(B64_ALPHABET, ctcopy[0]);
		if ((ltr_pos <= 0) || (ltr_pos > BACKDROP_MAX_HASH_COUNT)) {
			goto err;
		}
		ctcopy += 1;
		/* Verify all B64 char in the password are valid */
		for (int idx=0; idx < MAX_ENCRYPTED_LEN; idx++) {
			ltr_pos = get_letter_position(B64_ALPHABET, ctcopy[0]);
			ctcopy += 1;
			if (ltr_pos < 0) {
				goto err;
			}
		}
		MEM_FREE(keeptr);
		return 1;
	}
	else { /* Other hash type not supported. */
		goto err;
	}

err:
	MEM_FREE(keeptr);
	return 0;
}


static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	memset(&cs, 0, SALT_SIZE);

	unsigned char *ctcopy = (unsigned char *)xstrdup(ciphertext);
	unsigned char *keeptr = ctcopy;
	int ltr_pos=-1;

	ctcopy += TAG_LENGTH;
	if (ctcopy[0] == 'S') {
		cs.type = 1;
	}
	else {
		/* Case not supported, put here for potential future evolution */
		cs.type = 0;
	}
	ctcopy += 2; /* letter type + $ */

	/* parse number of iterations */
	ltr_pos = get_letter_position(B64_ALPHABET, ctcopy[0]);
	cs.nb_iter = 1 << ltr_pos;
	ctcopy += 1;

	/* parse salt */
	memcpy(cs.salt, ctcopy, 8);
	ctcopy += 8;

	/* parse encrypted password */
	unsigned char decoded_password[80];
	memset(decoded_password, 0, sizeof(decoded_password));
	base64_convert(ctcopy, e_b64_cryptBS, 43, decoded_password, e_b64_raw, sizeof(decoded_password), flg_Base64_NO_FLAGS, 0);

	memcpy(cs.encrypted_bytes, decoded_password, 43);
	MEM_FREE(keeptr);
	return &cs;
}


static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}


static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0]) * cracked_count);


#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {

		uint8_t tmpBuf[SHA512_LEN];
		memset(tmpBuf, 0, sizeof(tmpBuf));

		if (cur_salt->type == 0) {
			/* Case not supported, put here for potential future evolution */
		} else if (cur_salt->type == 1) {
			SHA512_CTX ctx;
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, saved_key[index], saved_len[index]+SALT_LENGTH);
			SHA512_Final(tmpBuf, &ctx);
			for (unsigned long i=0; i<cur_salt->nb_iter; i++) {
				memcpy(saved_internal_key[index], tmpBuf, SHA512_LEN);
				SHA512_Init(&ctx);
				SHA512_Update(&ctx, saved_internal_key[index], saved_len[index]+SHA512_LEN);
				SHA512_Final(tmpBuf, &ctx);
			}
		}

		if (memcmp(tmpBuf, cur_salt->encrypted_bytes, MAX_ENCRYPTED_BYTES_LEN) == 0) {
			cracked[index] = 1;
		}
		else {
			cracked[index] = 0;
		}
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index=0;

	for (index = 0; index < count; index++) {
		if (cracked[index]) {
			return 1;
		}
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	memset(saved_key[index], 0, PLAINTEXT_LENGTH + SALT_LENGTH + 1);
	memset(orig_key[index], 0, PLAINTEXT_LENGTH + 1);
	size_t keylen = strlen(key);

	memcpy(orig_key[index], key, keylen);

	memcpy(saved_key[index], cur_salt->salt, 8);
	memcpy(saved_key[index]+SALT_LENGTH, key, keylen);

	saved_len[index] = keylen;

	memset(saved_internal_key[index], 0, PLAINTEXT_LENGTH + SHA512_LEN + 1);
	memcpy(saved_internal_key[index]+SHA512_LEN, key, keylen);
}

static char *get_key(int index)
{
	return orig_key[index];
}

struct fmt_main fmt_backdrop = {
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
		FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_ENC | FMT_CASE,
		{ NULL },
		{ FORMAT_TAG },
		backdrop_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
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

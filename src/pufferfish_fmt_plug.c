/*
 * Pufferfish cracker patch for JtR. Hacked together during the Hash Runner
 * 2015 contest by Dhiru Kholia.
 *
 * Pufferfish has been placed in the public domain and is, and will remain,
 * available world-wide on a royalty-free basis. The designer is unaware of any
 * patent or patent application that covers the use or implementation of the
 * submitted algorithm. Designed by Jeremi M Gosney.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_EVP_SHA512

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pufferfish;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pufferfish);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "pufferfish_common.h"
// #include "pufferfish_itoa64.h"
#include "pufferfish.h"
#include "memdbg.h"

#define FORMAT_LABEL		"pufferfish"
#define FORMAT_NAME		"Pufferfish"

#define FORMAT_TAG		"$PF$"
#define TAG_LENGTH		4

#if !defined(USE_GCC_ASM_IA32) && defined(USE_GCC_ASM_X64)
#define ALGORITHM_NAME		"64/64"
#else
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	125
#define CIPHERTEXT_LENGTH	43   // base64 size
#define BINARY_SIZE		32
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		4
#define BINARY_ALIGN		sizeof(ARCH_WORD_32)

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests pufferfish_tests[] = {
	{"$PF$KBOuLFhriderZgM3u8j69kIE4vW$C8ktW5hn1fJKKzHnLGmjpeCTwcY.PxKsgi6s5Ygwy62", "password"},
	{"$PF$KBOuLD/3sKXiBfz4XcMZxLKmmvG$66B64KyTZBu7q7MVpczqENIFUghjc.HLsLwOM9NDviy", ""},
	{"$PF$KBOuLMWPCSO0fpsmJc1eac64eq6$dNljII1cz8m0er8aEs0SnpWIC6ndGHjaGr4Aet//SUK", "openwall123"},
	{"$PF$KBOuLBHJb8ri9zajQslWHwAJj3u$m3PS1k.ijRv6nSXcVjPVDD0wPkGpcwlL/KUNsJs447a", "openwall123"},
	{"$PF$KBOuLMss9l5K0c0miLerGZOLwP2$O76WDUQK8QG9yBYHfxSkYX1PFgHcWrotBdJzEGpQ2Bq", "openwall123"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];
static struct custom_salt {
        char settings[128];
} *cur_salt;

static void init(struct fmt_main *self)
{
	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,	sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static void *get_salt(char *ciphertext)
{
        static struct custom_salt cs;

	char *p = ciphertext;
        char *q = strrchr(ciphertext, '$');
	int len = q - p;

        memset(&cs, 0, sizeof(cs));
        strncpy(cs.settings, p, len);

        return (void *)&cs;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext;

	if (strncmp(p, FORMAT_TAG, TAG_LENGTH))
		return 0;
	else
		p += TAG_LENGTH;

	p = strrchr(ciphertext, '$');
	if (!p)
		return 0;

	if (strlen(p + 1) != CIPHERTEXT_LENGTH)
		return 0;

	return 1;
}

int decode64 (unsigned char *dst, int size, char *src);

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p = strrchr(ciphertext, '$') + 1;
	unsigned char buffer[BINARY_SIZE + 8];  // base64 decoding

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);
	memset(out, 0, BINARY_SIZE);

	decode64(buffer, CIPHERTEXT_LENGTH, p);
	memcpy(out, buffer, BINARY_SIZE);

	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

/* static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
} */

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	for (index = 0; index < count; index++)
	{
		char backup_settings[128];

		strncpy(backup_settings, cur_salt->settings, 128);
		pufferfish_custom(saved_key[index], strlen(saved_key[index]), backup_settings, (unsigned char*)crypt_out[index], 32, 1);
		fflush(stdout);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
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

static void set_salt(void *salt)
{
        cur_salt = (struct custom_salt *)salt;
}

static void stribog_set_key(char *key, int index)
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

struct fmt_main fmt_pufferfish = {
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
		FMT_CASE, // FMT_OMP is currently buggy!
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		pufferfish_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
		NULL,
		set_salt,
		stribog_set_key,
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

#endif /* HAVE_EVP_SHA512 */

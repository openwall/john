/*
 * PHPS_fmt.c
 *
 * Salted PHP on the form (php-code): $hash = MD5(MD5($pass).$salt);
 * Based on salted IPB2 mode (by regenrecht at o2.pl).
 *
 * albert veli gmail com, 2007
 *
 * Convert hashes to the form username:$PHPS$salt$hash
 * For instance, if the pw file has the form
 * 1234<::>luser<::>luser@hotmail.com<::><::>1ea46bf1f5167b63d12bd47c8873050e<::>C9%
 * it can be converted to the wanted form with the following perl script:
 *
 * #!/usr/bin/perl -w
 * while (<>) {
 *    my @fields = split(/<::>/, $_);
 *    my $a =  substr $fields[5], 0, 1;
 *    my $b =  substr $fields[5], 1, 1;
 *    my $c =  substr $fields[5], 2, 1;
 *    printf "%s:\$IPB2\$%02x%02x%02x\$%s\n", $fields[1], ord($a), ord($b), ord($c), $fields[4];
 * }
 *
 * BUGS: Can't handle usernames with ':' in them.
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "md5.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL		"phps"
#define FORMAT_NAME		"PHPS MD5"
#define ALGORITHM_NAME		"MD5(MD5($pass).$salt)"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0

#define MD5_BINARY_SIZE		16
#define MD5_HEX_SIZE		(MD5_BINARY_SIZE * 2)

#define BINARY_SIZE		MD5_BINARY_SIZE

#define SALT_SIZE		3
#define PROCESSED_SALT_SIZE	SALT_SIZE

#define PLAINTEXT_LENGTH	32
#define CIPHERTEXT_LENGTH	(1 + 4 + 1 + SALT_SIZE * 2 + 1 + MD5_HEX_SIZE)

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests phps_tests[] = {
	{"$PHPS$433925$5d756853cd63acee76e6dcd6d3728447", "welcome"},
	{NULL}
};

static char itoa16_shr_04[] =
	"0000000000000000"
	"1111111111111111"
	"2222222222222222"
	"3333333333333333"
	"4444444444444444"
	"5555555555555555"
	"6666666666666666"
	"7777777777777777"
	"8888888888888888"
	"9999999999999999"
	"aaaaaaaaaaaaaaaa"
	"bbbbbbbbbbbbbbbb"
	"cccccccccccccccc"
	"dddddddddddddddd"
	"eeeeeeeeeeeeeeee"
	"ffffffffffffffff";

static char itoa16_and_0f[] =
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef";

static MD5_CTX ctx;
static char saved_key[PLAINTEXT_LENGTH + 1];
static int saved_key_len;
static char workspace[MD5_HEX_SIZE * 2];
static char output[MD5_BINARY_SIZE];

static int phps_valid(char *ciphertext, struct fmt_main *self)
{
	if (!ciphertext)
		return 0;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;

	if (strncmp(ciphertext, "$PHPS$", 6) != 0)
		return 0;

 	if (ciphertext[12] != '$')
		return 0;

 	if (strspn(ciphertext+6, itoa16) != SALT_SIZE * 2)
		return 0;

 	if (strspn(ciphertext+13, itoa16) != MD5_HEX_SIZE)
		return 0;

	return 1;
}

static void *phps_binary(char *ciphertext)
{
	static unsigned char binary_cipher[BINARY_SIZE];
	int i;

	ciphertext += 13;
	for (i = 0; i < MD5_HEX_SIZE; ++i)
		binary_cipher[i] =
			(atoi16[ARCH_INDEX(ciphertext[i*2])] << 4)
			+ atoi16[ARCH_INDEX(ciphertext[i*2+1])];

	return (void *)binary_cipher;
}

static void *phps_salt(char *ciphertext)
{
	static unsigned char binary_salt[SALT_SIZE];
	int i;

	ciphertext += 6;
	for (i = 0; i < SALT_SIZE; ++i)
		binary_salt[i] =
			(atoi16[ARCH_INDEX(ciphertext[i*2])] << 4)
			+ atoi16[ARCH_INDEX(ciphertext[i*2+1])];

	return (void*)binary_salt;
}

static void phps_set_salt(void *salt)
{
	memcpy((char*)(workspace + MD5_HEX_SIZE), (char*)salt, PROCESSED_SALT_SIZE);
}

static int strnfcpy_count(char *dst, char *src, int size)
{
	char *dptr = dst, *sptr = src;
	int count = size;

	while (count--)
		if (!(*dptr++ = *sptr++)) break;

	return size-count-1;
}

static void phps_set_key(char *key, int index)
{
	static unsigned char key_hash[MD5_BINARY_SIZE];
	unsigned char *kh = key_hash;
	unsigned char *workspace_ptr = (unsigned char *) workspace;
	unsigned char v;
	int i;

	saved_key_len = strnfcpy_count(saved_key, key, PLAINTEXT_LENGTH);

	MD5_Init(&ctx);
	MD5_Update(&ctx, saved_key, saved_key_len);
	MD5_Final(key_hash, &ctx);

	for (i = 0; i < MD5_BINARY_SIZE; ++i) {
		v = *kh++;
		*workspace_ptr++ = itoa16_shr_04[ARCH_INDEX(v)];
		*workspace_ptr++ = itoa16_and_0f[ARCH_INDEX(v)];
	}
}

static char *phps_get_key(int index)
{
	return saved_key;
}

static void phps_crypt_all(int count)
{
	MD5_Init(&ctx);
	MD5_Update(&ctx, workspace, MD5_HEX_SIZE + SALT_SIZE);
	MD5_Final((unsigned char *) output, &ctx);
}

static int phps_cmp_all(void *binary, int index)
{
	return !memcmp(binary, output, MD5_BINARY_SIZE);
}

static int phps_cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_PHPS = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		PROCESSED_SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		phps_tests
	},
	{
		fmt_default_init,
		fmt_default_prepare,
		phps_valid,
		fmt_default_split,
		phps_binary,
		phps_salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		phps_set_salt,
		phps_set_key,
		phps_get_key,
		fmt_default_clear_keys,
		phps_crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		phps_cmp_all,
		phps_cmp_all,
		phps_cmp_exact
	}
};


/**
 * GNU Emacs settings: K&R with 1 tab indent.
 * Local Variables:
 * c-file-style: "k&r"
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */

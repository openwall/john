/*
 * IPB2_fmt.c (version 4)
 *
 * Invision Power Board 2.x salted MD5 module for Solar Designer's JtR
 * Uses Solar Designer's MD5 implementation.
 * regenrecht at o2.pl, Jan 2006
 *
 * Hashes list should have form of username:$IPB2$salt$hash
 * Values to be taken from IPB database, where:
 * salt = bin2hex(ibf_members_converge.converge_pass_salt)
 * hash = ibf_members_converge.converge_pass_hash
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "md5.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL		"ipb2"
#define FORMAT_NAME		"IPB2 MD5"
#define ALGORITHM_NAME		"Invision Power Board 2.x salted MD5"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0

#define MD5_BINARY_SIZE		16
#define MD5_HEX_SIZE		(MD5_BINARY_SIZE * 2)

#define BINARY_SIZE		MD5_BINARY_SIZE

#define SALT_SIZE		5
#define PROCESSED_SALT_SIZE	MD5_HEX_SIZE

#define PLAINTEXT_LENGTH	32
#define CIPHERTEXT_LENGTH	(1 + 4 + 1 + SALT_SIZE * 2 + 1 + MD5_HEX_SIZE)

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests ipb2_tests[] = {
	{"$IPB2$2e75504633$d891f03a7327639bc632d62a7f302604", "welcome"},
	{"$IPB2$735a213a4e$4f23de7bb115139660db5e953153f28a", "enter"},
	{"$IPB2$5d75343455$de98ba8ca7bb16f43af05e9e4fb8afee", "matrix"},
	{"$IPB2$556c576c39$16d4f29c71b05bd75e61d0254800bfa3", "123456"},
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
static ARCH_WORD_32 output[MD5_BINARY_SIZE / sizeof(ARCH_WORD_32)];

static int ipb2_valid(char *ciphertext, struct fmt_main *pFmt)
{
	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;

	if (strncmp(ciphertext, "$IPB2$", 6) != 0)
		return 0;

	if (ciphertext[16] != '$')
		return 0;

	if (strspn(ciphertext+6, itoa16) != SALT_SIZE*2)
		return 0;

	if (strspn(ciphertext+17, itoa16) != MD5_HEX_SIZE)
		return 0;

	return 1;
}

static void *ipb2_binary(char *ciphertext)
{
	static unsigned char binary_cipher[BINARY_SIZE];
	int i;

	ciphertext += 17;
	for (i = 0; i < MD5_HEX_SIZE; ++i)
		binary_cipher[i] =
			(atoi16[ARCH_INDEX(ciphertext[i*2])] << 4)
			+ atoi16[ARCH_INDEX(ciphertext[i*2+1])];

	return (void *)binary_cipher;
}

static void *ipb2_salt(char *ciphertext)
{
	static unsigned char binary_salt[SALT_SIZE];
	static unsigned char salt_hash[MD5_BINARY_SIZE];
	static unsigned char hex_salt[MD5_HEX_SIZE];
	int i;

	ciphertext += 6;
	for (i = 0; i < SALT_SIZE; ++i)
		binary_salt[i] =
			(atoi16[ARCH_INDEX(ciphertext[i*2])] << 4)
			+ atoi16[ARCH_INDEX(ciphertext[i*2+1])];

	MD5_Init(&ctx);
	MD5_Update(&ctx, binary_salt, SALT_SIZE);
	MD5_Final(salt_hash, &ctx);

	for (i = 0; i < MD5_BINARY_SIZE; ++i) {
		hex_salt[i*2] = itoa16[ARCH_INDEX(salt_hash[i] >> 4)];
		hex_salt[i*2+1] = itoa16[ARCH_INDEX(salt_hash[i] & 0x0f)];
	}

	return (void*)hex_salt;
}

static void ipb2_set_salt(void *salt)
{
	memcpy((char*)workspace, (char*)salt, PROCESSED_SALT_SIZE);
}

static int strnfcpy_count(char *dst, char *src, int size)
{
	char *dptr = dst, *sptr = src;
	int count = size;

	while (count--)
		if (!(*dptr++ = *sptr++)) break;

	return size-count-1;
}

static void ipb2_set_key(char *key, int index)
{
	static unsigned char key_hash[MD5_BINARY_SIZE];
	unsigned char *kh = key_hash;
	unsigned char *workspace_ptr = (unsigned char *) (workspace + PROCESSED_SALT_SIZE);
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

static char *ipb2_get_key(int index)
{
	return saved_key;
}

static void ipb2_crypt_all(int count)
{
	MD5_Init(&ctx);
	MD5_Update(&ctx, workspace, MD5_HEX_SIZE * 2);
	MD5_Final((unsigned char *) output, &ctx);
}

static int ipb2_cmp_all(void *binary, int index)
{
	return !memcmp(binary, output, MD5_BINARY_SIZE);
}

static int ipb2_cmp_exact(char *source, int index)
{
	return 1;
}

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD_32*)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(ARCH_WORD_32*)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(ARCH_WORD_32*)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(ARCH_WORD_32*)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(ARCH_WORD_32*)binary & 0xFFFFF;
}

static int get_hash_0(int index)
{
	return *output & 0xF;
}

static int get_hash_1(int index)
{
	return *output & 0xFF;
}

static int get_hash_2(int index)
{
	return *output & 0xFFF;
}

static int get_hash_3(int index)
{
	return *output & 0xFFFF;
}

static int get_hash_4(int index)
{
	return *output & 0xFFFFF;
}

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32*)salt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_IPB2 = {
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
		ipb2_tests
	},
	{
		fmt_default_init,
		fmt_default_prepare,
		ipb2_valid,
		fmt_default_split,
		ipb2_binary,
		ipb2_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		ipb2_set_salt,
		ipb2_set_key,
		ipb2_get_key,
		fmt_default_clear_keys,
		ipb2_crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		ipb2_cmp_all,
		ipb2_cmp_all,
		ipb2_cmp_exact
	}
};

/*
 * AS/400 DES plugin for JtR.
 *
 * This software is Copyright (c) 2016 Rob Schoemaker (@5up3rUs3r) and Bart
 * Kulach (@bartholozz) and it is hereby released to the general public under
 * the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * See http://www.hackthelegacy.org for details and tooling to retrieve hashes
 * from AS/400 systems.
 *
 * Based on RACF cracker patch for JtR by Dhiru Kholia <dhiru.kholia at gmail.com>, and
 * Nigel Pentland <nigel at nigelpentland.net> and Main Framed <mainframed767 at gmail.com>.
 *
 * Hash format => userid:$as400des$*userid*hash
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_as400des;
#elif FMT_REGISTERS_H
john_register_one(&fmt_as400des);
#else

#include <string.h>
#include <openssl/des.h>

#include "arch.h"
#include "crc32.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"

#define FORMAT_LABEL            "as400-des"
#define FORMAT_NAME             "AS/400 DES"
#define FORMAT_TAG              "$as400des$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "DES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        10  /* passwords can not be longer than 10 characters*/
#define CIPHERTEXT_LENGTH       16
#define BINARY_SIZE             8
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

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

/* format userid to conform to spec */
static void process_userid(unsigned char *str)
{
	int i;

	if (strlen((const char*)str)<=8) // if length userid <8 --> rightpad with spaces
	{
		for (i = strlen((const char*)str); i < 8; ++i)
			str[i] = 0x40;
		str[8] = 0; /* terminate string */
	}
	else
	{
		// if length userid is 9 or 10 --> do bitswitch operation to create userid of length 8

		// if length=9, right pad with spaces to length of 10
		if (strlen((const char*)str)==9)
		{
			str[9] = 0x40;
			str[10] = 0;
		}
		str[0] ^= str[8] & 0xC0;
		str[1] ^= (str[8] & 0x30) << 2;
		str[2] ^= (str[8] & 0x0C) << 4;
		str[3] ^= str[8] << 6;
		str[4] ^= str[9] & 0xC0;
		str[5] ^= (str[9] & 0x30) << 2;
		str[6] ^= (str[9] & 0x0C) << 4;
		str[7] ^= str[9] << 6;
		str[8] = 0; /* terminate string */
	}
}

static struct fmt_tests as400_des_tests[] = {
	{"$as400des$AAAAAAA*CA2E330B2FD1820E", "AAAAAAAA"},
	{"$as400des$AAAAAAAA*062314297C496E0E", "AAAAAAAA"},
	{"$as400des$JJJJJJJJ*8B5F0B1D0826D927", "TESTTEST"},
	{"$as400des$TTTTTTTT*424B258AF8B9061B", "TESTTEST"},
	{"$as400des$A*0F7DE80335E8ED68", "A"},
	{"$as400des$OPEN3*EC76FC0DEF5B0A83", "SYS1"},
	{"$as400des$TESTTEST*0FF48804F759193F", "TESTTEST"},
	{"$as400des$SYSOPR*83845F8EEC7C20D8", "SYSOPR"},
	{"$as400des$TCPIP*657889CD0F5D40DF", "SYS1"},
	{"$as400des$TESTER*E05AB770EA048421", "TEST"},
	{"$as400des$USERNAME*48E3704CF54B79B2", "PASSWORD10"},
	{"$as400des$USERNAME*760FECC695DF4E27", "PASSWORD"},
	{"$as400des$USERID*AB171E6EE8E98037", "PASSWORD9"},
	{"$as400des$ROB*D09E49EB96A1BE45", "SCHOEMAKER"},
	{"$as400des$BART*25C0729AA18D1929", "KULACH"},
	{NULL}
};

static struct custom_salt {
	unsigned char userid[10 + 1];
} *cur_salt;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
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

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "*"); /* username */
	if (!p)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* hash */
		goto err;
	if (hexlenu(p, &extra) != CIPHERTEXT_LENGTH || extra)
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy, *username;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$as400des$" */
	username = strtokm(ctcopy, "*");
	/* process username */
	strncpy((char*)cs.userid, username, 10);
	cs.userid[10] = 0; // terminate username at 10 bytes
	ascii2ebcdic(cs.userid);
	process_userid(cs.userid);
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '*') + 1;
		for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		DES_cblock des_key;
		DES_key_schedule schedule;
		int i;
		int saved_key_length = strlen(saved_key[index]);

		if (saved_key_length <= 8) {
			/* process key */
			for (i = 0; saved_key[index][i]; i++)
				des_key[i] = a2e_precomputed[ARCH_INDEX(saved_key[index][i])];

			/* replace missing characters in password by (EBCDIC space (0x40) XOR 0x55) << 1 */
			while(i < 8)
				des_key[i++] = 0x2a;

			DES_set_key_unchecked(&des_key, &schedule);
			/* do encryption */
			DES_ecb_encrypt((const_DES_cblock*)cur_salt->userid, (DES_cblock*)crypt_out[index], &schedule, DES_ENCRYPT);
		}
		else {
			DES_cblock des_key1, des_key2;
			DES_key_schedule schedule1, schedule2;
			DES_cblock hash_1, hash_2;
			unsigned char output[8];

			/* process key */
			for (i = 0; i < 8; i++)
				des_key1[i] = a2e_precomputed[ARCH_INDEX(saved_key[index][i])];

			for (i = 0; i < saved_key_length-8; i++)
				des_key2[i] = a2e_precomputed[ARCH_INDEX(saved_key[index][8+i])];

			/* replace missing characters in password by (EBCDIC space (0x40) XOR 0x55) << 1 */
			while(i < 8)
				des_key2[i++] = 0x2a;

			DES_set_key_unchecked(&des_key1, &schedule1);
			DES_ecb_encrypt((const_DES_cblock*)cur_salt->userid, &hash_1, &schedule1, DES_ENCRYPT);
			DES_set_key_unchecked(&des_key2, &schedule2);
			DES_ecb_encrypt((const_DES_cblock*)cur_salt->userid, &hash_2, &schedule2, DES_ENCRYPT);
			for (i = 0; i < 8; i++) {
				output[i] = hash_1[i] ^ hash_2[i];
			}

			memcpy((unsigned char*)crypt_out[index], output, 8);
		}
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

static void as400_des_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_as400des = {
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
		FMT_CASE | FMT_TRUNC | FMT_8_BIT,
		{ NULL },
		{ FORMAT_TAG },
		as400_des_tests
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
		as400_des_set_key,
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

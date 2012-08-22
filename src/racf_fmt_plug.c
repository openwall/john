/* RACF cracker patch for JtR. Hacked together during March of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com> .
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Thanks to Nigel Pentland <nigel at nigelpentland.net>, author of CRACF for
 * providing algorithm details.
 *
 * Thanks to Main Framed <mainframed767 at gmail.com> for providing test vectors,
 * algorithm details and requesting the RACF cracker in the first place.
 *
 * racfdump format => userid:$racf$*userid*deshash
 */

#include <openssl/des.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "crc32.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
static int omp_t = 1;
#endif

#define FORMAT_LABEL		"racf"
#define FORMAT_NAME		"RACF DES"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0
#define PLAINTEXT_LENGTH	8
#define BINARY_SIZE		8
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static unsigned char a2e[256] = {
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
static unsigned char a2e_precomputed[256] = {
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

/* replace missing characters in userid by EBCDIC spaces (0x40) */
static void process_userid(unsigned char *str)
{
	int i;
	for (i = strlen((const char*)str); i < 8; ++i)
		str[i] = 0x40;
	str[8] = 0; /* terminate string */
}

#ifdef RACF_DEBUG
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

static struct fmt_tests racf_tests[] = {
	{"$racf$*AAAAAAA*CA2E330B2FD1820E", "AAAAAAAA"},
	{"$racf$*AAAAAAAA*062314297C496E0E", "AAAAAAAA"},
	{"$racf$*JJJJJJJJ*8B5F0B1D0826D927", "TESTTEST"},
	{"$racf$*TTTTTTTT*424B258AF8B9061B", "TESTTEST"},
	{"$racf$*A*0F7DE80335E8ED68", "A"},
	{"$racf$*OPEN3*EC76FC0DEF5B0A83", "SYS1"},
	{"$racf$*TESTTEST*0FF48804F759193F", "TESTTEST"},
	{"$racf$*SYSOPR*83845F8EEC7C20D8", "SYSOPR"},
	{"$racf$*TCPIP*657889CD0F5D40DF", "SYS1"},
	{"$racf$*TESTER*E05AB770EA048421", "TEST"},
	{NULL}
};

static struct custom_salt {
	unsigned char userid[8 + 1];
} *cur_salt;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$racf$", 6);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy, *username;
	static struct custom_salt cs;
	ctcopy += 7;	/* skip over "$racf$*" */
	username = strtok(ctcopy, "*");
	/* process username */
	strcpy((char*)cs.userid, username);
	ascii2ebcdic(cs.userid);
	process_userid(cs.userid);
#ifdef RACF_DEBUG
	printf("userid in EBCDIC : ");
	print_hex(cs.userid, 8);
#endif
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

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		DES_cblock des_key;
		DES_key_schedule schedule;
		DES_cblock ivec;
		int i;

		/* process key */
		for(i = 0; saved_key[index][i]; i++)
			des_key[i] = a2e_precomputed[ARCH_INDEX(saved_key[index][i])];

		/* replace missing characters in userid by (EBCDIC space (0x40) XOR 0x55) << 1 */
		while(i < 8)
			des_key[i++] = 0x2a;

		DES_set_key_unchecked(&des_key, &schedule);

		/* do encryption */
		memset(ivec, 0, 8);
		DES_cbc_encrypt(cur_salt->userid, (unsigned char*)crypt_out[index], 8, &schedule, &ivec, DES_ENCRYPT);
	}
}

static int cmp_all(void *binary, int count)
{
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

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void racf_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > 8)
		saved_key_length = 8;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main racf_fmt = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
                DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
                DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		racf_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		set_salt,
		racf_set_key,
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

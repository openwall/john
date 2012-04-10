/* RACF cracker patch for JtR. Hacked together during March of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com> .
 *
 * This software is Copyright © 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
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
#define FORMAT_NAME		"RACF"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	8
#define BINARY_SIZE		16
#define SALT_SIZE		sizeof(*salt_struct)
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

static void process_key(unsigned char *str)
{
	int i;
	/* replace missing characters in key by EBCDIC spaces (0x40) */
	for (i = strlen((const char*)str); i < 8; ++i)
		str[i] = 0x40;
	for (i = 0; i < 8; ++i) {
		str[i] = str[i] ^ 0x55; /* obfuscate by XOR'ing */
		str[i] = str[i] << 1; /* left-shift bit which is mostly 1 */
	}
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
	char unsigned hash[8];
} *salt_struct;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static void init(struct fmt_main *pFmt)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	pFmt->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	cracked = mem_calloc_tiny(sizeof(*cracked) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$racf$", 6);
}

static void *get_salt(char *ciphertext)
{
	int i;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	ctcopy += 7;	/* skip over "$racf$*" */
	salt_struct = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	char *username = strtok(ctcopy, "*");
	/* process username */
	strcpy((char*)salt_struct->userid, username);
#ifdef RACF_DEBUG
	printf("userid in ASCII : %s\n", salt_struct->userid);
#endif
	ascii2ebcdic(salt_struct->userid);
	process_userid(salt_struct->userid);
#ifdef RACF_DEBUG
	printf("userid in EBCDIC : ");
	print_hex(salt_struct->userid, 8);
#endif
	/* process DES hash */
	char *inputhash = strtok(NULL, "*");
	for (i = 0; i < 8; i++)
		salt_struct->hash[i] = atoi16[ARCH_INDEX(inputhash[i * 2])] * 16
			+ atoi16[ARCH_INDEX(inputhash[i * 2 + 1])];
#ifdef RACF_DEBUG
	printf("inputhash : ");
	print_hex(salt_struct->hash, 8);
#endif
	free(keeptr);
	return (void *)salt_struct;
}


static void set_salt(void *salt)
{
	salt_struct = (struct custom_salt *)salt;
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
		unsigned char encrypted[8];
		unsigned char key[PLAINTEXT_LENGTH+1];
		strcpy((char*)key, saved_key[index]);
		/* process key */
		ascii2ebcdic(key);
		process_key(key);
		memcpy(des_key, key, 8);
		DES_key_schedule schedule;
		DES_cblock ivec;
		memset(ivec, 0, 8);
		DES_set_odd_parity(&des_key);
		DES_set_key_checked(&des_key, &schedule);
		/* do encryption */
		DES_cbc_encrypt(salt_struct->userid, encrypted, 8, &schedule, &ivec, DES_ENCRYPT);
		if(!memcmp(salt_struct->hash, encrypted, 8))
			cracked[index] = 1;
		else
			cracked[index] = 0;
	}
}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
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
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		racf_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		racf_set_key,
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

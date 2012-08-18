/*
 * This is a copy of the old "thick" raw-md5 format, modified for hashes made
 * from UTF-16 plaintexts. It also supports the --encoding=utf8 flag, making
 * it convert from UTF-8 instead of the default, ISO-8859-1. My changes are
 * released under the same terms as stated below.
 * This will be replaced by a "thin" md5_gen format as soon as md5_gen supports
 * md5(unicode($p)).
 * magnum, 2011
 *
 * This software is Copyright (c) 2004 bartavelle, <bartavelle at bandecon.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Minor changes by David Luyer <david at luyer.net> to
 * use a modified (faster) version of Solar Designer's
 * md5 implementation.
 *
 * More improvement by
 * Balázs Bucsay - earthquake at rycon.hu - http://www.rycon.hu/
 * (2times faster, but it's only works up to 54characters)
 *
 * Added in SSE2 (and MMX) support from md5-mmx.S by
 * Jim Fougeron - jfoug at cox dot net
 * (1.5 to 3.5x faster, depending upon core type).
 * Done in blocks of 64 hashs per 'run' (to avoid
 * fseek() slowdown issues in wordlist.c code
 *
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"

#ifdef MMX_COEF
#include "md5.h"
#else
#if ARCH_LITTLE_ENDIAN
#define MD5_out MD5_out_eq
#else
#define MD5_out MD5_bitswapped_out_eq
#endif
typedef unsigned int MD5_u32plus;
extern void MD5_Go_eq(unsigned char *data, unsigned int len, int index);
extern void MD5_Go2_eq(unsigned char *data, unsigned int len, int index);
#endif

#define FORMAT_LABEL		"raw-md5-unicode"
#define FORMAT_NAME			"Raw MD5 of Unicode plaintext"
#ifdef MMX_COEF
#if (MMX_COEF == 2)
#define ALGORITHM_NAME		"raw-md5-unicode MMX 32x2"
#else
#define ALGORITHM_NAME		"raw-md5-unicode SSE2 16x4"
#endif
#else
#define ALGORITHM_NAME		"raw-md5-unicode 64x1"
#endif

#ifdef MMX_TYPE
#define BENCHMARK_COMMENT	MMX_TYPE
#else
#define BENCHMARK_COMMENT		""
#endif
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		54 // octets, not characters
#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE				16
#define SALT_SIZE				0

#ifdef MMX_COEF
#if MMX_COEF==2
#define BLOCK_LOOPS 32
#else
#define BLOCK_LOOPS 16
#endif
#define MIN_KEYS_PER_CRYPT	MMX_COEF*BLOCK_LOOPS
#define MAX_KEYS_PER_CRYPT	MMX_COEF*BLOCK_LOOPS
#define GETPOS(i, index)		( (index)*4 + ((i) & (0xffffffff-3) )*MMX_COEF + ((i)&3) )
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	64
extern ARCH_WORD_32 MD5_out[MAX_KEYS_PER_CRYPT];
extern char MD5_tmp[MAX_KEYS_PER_CRYPT][CIPHERTEXT_LENGTH + 1];
#endif

/* Note some plaintexts will be replaced in init() if running UTF-8 */
static struct fmt_tests rawmd5_tests[] = {
	{"16c47151c18ac087cd12b3a70746c790", "test1"},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
	{"9c3abef89ff76f8acd80eae37b35f64f", "test2"},
	{"849ee1b88b5d887bdb058180a666b450", "test3"},
	{"8c4cb7e8b33b56a833cdaa8673f3b425", "test4"},
	{"537e738b1ac5551f65106368dc301ece", "thatsworking"},
	{NULL}
};

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key rawMD5unicode_saved_key
#define crypt_key rawMD5unicode_crypt_key
#ifdef _MSC_VER
__declspec(align(16)) unsigned char saved_key[BLOCK_LOOPS][64*MMX_COEF];
__declspec(align(16)) unsigned char crypt_key[BLOCK_LOOPS][BINARY_SIZE*MMX_COEF];
#else
unsigned char saved_key[BLOCK_LOOPS][64 * MMX_COEF] __attribute__ ((aligned(16)));
unsigned char crypt_key[BLOCK_LOOPS][BINARY_SIZE * MMX_COEF] __attribute__ ((aligned(16)));
#endif
static unsigned long total_len[BLOCK_LOOPS];
#else
static unsigned char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1 + 128 /* MD5 scratch space */ ];
static unsigned int saved_key_len[MAX_KEYS_PER_CRYPT];
#endif

static int valid(char *ciphertext, struct fmt_main *self)
{
	int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;
	for (i = 0; i < CIPHERTEXT_LENGTH; i++) {
		if (!((('0' <= ciphertext[i]) && (ciphertext[i] <= '9')) ||
			(('a' <= ciphertext[i]) && (ciphertext[i] <= 'f'))))
			return 0;
	}
	return 1;
}

static void rawmd5_set_key_enc(char *_key, int index);
extern struct fmt_main fmt_rawMD5unicode;

static void rawmd5_init(struct fmt_main *self)
{
	if (options.utf8) {
		fmt_rawMD5unicode.methods.set_key = rawmd5_set_key_enc;
		// We may need three bytes of input to produce two bytes of key
		fmt_rawMD5unicode.params.plaintext_length = PLAINTEXT_LENGTH / 2 * 3;
		rawmd5_tests[1].ciphertext = "94a4e171de16580742c4d141e6607bf7";
		rawmd5_tests[1].plaintext = "\xE2\x82\xAC";	// Euro sign
		rawmd5_tests[2].ciphertext = "03c60810f0e54d16e826aca385d776c8";
		rawmd5_tests[2].plaintext = "\xE2\x82\xAC\xE2\x82\xAC";	// 2 x euro
		rawmd5_tests[3].ciphertext = "2d554433d7cde7ec8d16aaf126c3be6b";
		rawmd5_tests[3].plaintext = "\xE2\x82\xAC\xC3\xBC";	// euro and u-umlaut
		rawmd5_tests[4].ciphertext = "8007d9070b27db7b30433df2cd10abc1";
		rawmd5_tests[4].plaintext = "\xC3\xBC\xE2\x82\xAC";	// u-umlaut and euro
	} else if (options.encoding_7_bit || options.iso8859_1) {
		rawmd5_tests[1].ciphertext = "ea7ab2b5c07650badab30790d0c9b63e";
		rawmd5_tests[1].plaintext = "\xFC";	// German u-umlaut in iso-8859-1
		rawmd5_tests[2].ciphertext = "f0a0b9f1dea0e458cec9a284ff434d44";
		rawmd5_tests[2].plaintext = "\xFC\xFC";
		rawmd5_tests[3].ciphertext = "d25a0b436b768777cc9a343d283dbf5a";
		rawmd5_tests[3].plaintext = "\xFC\xFC\xFC";
		rawmd5_tests[4].ciphertext = "719917322bf12168f8c55939e4fec8de";
		rawmd5_tests[4].plaintext = "\xFC\xFC\xFC\xFC";
		// We *will* produce a key twice as large as input (in octets)
		fmt_rawMD5unicode.params.plaintext_length = PLAINTEXT_LENGTH / 2;
	} else {
		fmt_rawMD5unicode.methods.set_key = rawmd5_set_key_enc;
		// We *will* produce a key twice as large as input (in octets)
		fmt_rawMD5unicode.params.plaintext_length = PLAINTEXT_LENGTH / 2;
	}
}

static void rawmd5_set_key(char *_key, int index)
{
	unsigned char *key = (unsigned char *) _key;
	unsigned int i, outlen;
#ifdef MMX_COEF
	unsigned int idx;
#endif

	outlen = 2 * strlen(_key);
	if (outlen > PLAINTEXT_LENGTH)
		outlen = PLAINTEXT_LENGTH;
#ifdef MMX_COEF
	idx = (((unsigned) index) >> (MMX_COEF >> 1));
	if (index == 0) {
		memset(saved_key, 0, sizeof(saved_key));
		memset(total_len, 0, sizeof(total_len));
	}
	for (i = 0; i < outlen; i += 2)
		saved_key[idx][GETPOS(i, index & (MMX_COEF - 1))] = key[i >> 1];
	saved_key[idx][GETPOS(i, index & (MMX_COEF - 1))] = 0x80;
	total_len[idx] +=
	    (outlen << (((32 / MMX_COEF) * (index & (MMX_COEF - 1)))));
#else
	saved_key_len[index] = outlen;
	for (i = 0; i < outlen; i += 2) {
		saved_key[index][i] = key[i >> 1];
		saved_key[index][i + 1] = 0;
	}
#endif
}

static void rawmd5_set_key_enc(char *_key, int index)
{
	int utf8len = strlen(_key);
	unsigned char *key = (unsigned char *) _key;
	UTF16 utf16key[PLAINTEXT_LENGTH/2 + 1];
	int outlen;
	int i;
#ifdef MMX_COEF
	unsigned int idx;
#endif

	outlen =
	    enc_to_utf16(utf16key, PLAINTEXT_LENGTH / 2, key,
	    utf8len) * sizeof(UTF16);
	if (outlen <= 0) {
		utf8len = -outlen;
		if (outlen != 0)
			outlen = strlen16(utf16key) * sizeof(UTF16);
	}
#ifdef MMX_COEF
	idx = (((unsigned) index) >> (MMX_COEF >> 1));
	if (index == 0) {
		memset(saved_key, 0, sizeof(saved_key));
		memset(total_len, 0, sizeof(total_len));
	}
	for (i = 0; i < outlen; i += 2) {
		saved_key[idx][GETPOS(i, index & (MMX_COEF - 1))] =
		    (char) utf16key[i >> 1];
		saved_key[idx][GETPOS(i + 1, index & (MMX_COEF - 1))] =
		    (char) (utf16key[i >> 1] >> 8);
	}
	saved_key[idx][GETPOS(i, index & (MMX_COEF - 1))] = 0x80;
	total_len[idx] +=
	    (outlen << (((32 / MMX_COEF) * (index & (MMX_COEF - 1)))));
#else
	for (i = 0; i < outlen; i += 2) {
#if ARCH_LITTLE_ENDIAN
		saved_key[index][i] = (char) utf16key[i >> 1];
		saved_key[index][i + 1] = (char) (utf16key[i >> 1] >> 8);
#else
		saved_key[index][i + 1] = (char) utf16key[i >> 1];
		saved_key[index][i] = (char) (utf16key[i >> 1] >> 8);
#endif
	}
	saved_key_len[index] = outlen;
#endif
}

static char *rawmd5_get_key(int index)
{
	unsigned int i;
	int outlen = 0;
	static UTF16 key[PLAINTEXT_LENGTH / 2 + 1];
#ifdef MMX_COEF
	unsigned int idx;
	idx = (((unsigned) index) >> (MMX_COEF >> 1));
#endif
#ifdef MMX_COEF
	for (i = 0; saved_key[idx][GETPOS(i, index & (MMX_COEF - 1))] != 0x80; i += 2)
		key[outlen++] = saved_key[idx][GETPOS(i, index & (MMX_COEF - 1))] |
			saved_key[idx][GETPOS(i + 1, index & (MMX_COEF - 1))] << 8;
#else
	for (i = 0; i < saved_key_len[index]; i += 2) {
		key[outlen++] = saved_key[index][i] |
			saved_key[index][i + 1] << 8;
	}
#endif
	key[outlen] = 0;
	return (char *)utf16_to_enc(key);
}

static int rawmd5_cmp_all(void *binary, int count)
{
#ifdef MMX_COEF
	unsigned int i, j;
	unsigned int cnt =
	    (((unsigned) count + MMX_COEF - 1) >> (MMX_COEF >> 1));
	for (j = 0; j < cnt; ++j) {
		int SomethingGood = 1;
		i = 0;
		while (i < (BINARY_SIZE / 4)) {
			if ((((unsigned long *) binary)[i] !=
				((unsigned long *) &(crypt_key[j]))[i *
				    MMX_COEF])
			    && (((unsigned long *) binary)[i] !=
				((unsigned long *) &(crypt_key[j]))[i *
				    MMX_COEF + 1])
#if (MMX_COEF > 3)
			    && (((unsigned long *) binary)[i] !=
				((unsigned long *) &(crypt_key[j]))[i *
				    MMX_COEF + 2])
			    && (((unsigned long *) binary)[i] !=
				((unsigned long *) &(crypt_key[j]))[i *
				    MMX_COEF + 3])
#endif
			    ) {
				SomethingGood = 0;
				break;
			}
			++i;
		}
		if (SomethingGood)
			return 1;
	}
	return 0;
#else
	unsigned int i;

	for (i = 0; i < count; i++) {
		if (!(*((unsigned int *) binary) -
			*((unsigned int *) &MD5_out[i])))
			return 1;
	}

	return 0;
#endif
}

static int rawmd5_cmp_one(void *binary, int index)
{
#ifdef MMX_COEF
	unsigned int idx = (((unsigned) index) >> (MMX_COEF >> 1));
	return ((((ARCH_WORD_32 *) binary)[0] ==
		((ARCH_WORD_32 *) & (crypt_key[idx]))[0 * MMX_COEF +
		    (index & (MMX_COEF - 1))]) &&
	    (((ARCH_WORD_32 *) binary)[1] ==
		((ARCH_WORD_32 *) & (crypt_key[idx]))[1 * MMX_COEF +
		    (index & (MMX_COEF - 1))])
#if (MMX_COEF > 3)
	    &&
	    (((ARCH_WORD_32 *) binary)[2] ==
		((ARCH_WORD_32 *) & (crypt_key[idx]))[2 * MMX_COEF +
		    (index & (MMX_COEF - 1))]) &&
	    (((ARCH_WORD_32 *) binary)[3] ==
		((ARCH_WORD_32 *) & (crypt_key[idx]))[3 * MMX_COEF +
		    (index & (MMX_COEF - 1))])
#endif
	    );
#else
	return (!(*((unsigned int *) binary) - (unsigned int) MD5_out[index]));
#endif
}

static int rawmd5_cmp_exact(char *source, int index)
{
#ifdef MMX_COEF
	return 1;
#else
	MD5_Go2_eq((unsigned char *) saved_key[index], saved_key_len[index],
	    index);
	return !memcmp(source, MD5_tmp[index], CIPHERTEXT_LENGTH);
#endif
}

static void rawmd5_crypt_all(int count)
{
	// get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef MMX_COEF
	unsigned int cnt =
	    (((unsigned) count + MMX_COEF - 1) >> (MMX_COEF >> 1));
	unsigned i;
	for (i = 0; i < cnt; ++i)
		mdfivemmx((unsigned char *) &(crypt_key[i]),
		    (unsigned char *) &(saved_key[i]), total_len[i]);
#else
	unsigned int i;

	for (i = 0; i < count; i++)
		MD5_Go_eq((unsigned char *) saved_key[i], saved_key_len[i], i);
#endif
}

static int rawmd5_binary_hash_0(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xf;
}

static int rawmd5_binary_hash_1(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xff;
}

static int rawmd5_binary_hash_2(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfff;
}

static int rawmd5_binary_hash_3(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xffff;
}

static int rawmd5_binary_hash_4(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfffff;
}

static int rawmd5_get_hash_0(int index)
{
#ifdef MMX_COEF
	unsigned int idx = (((unsigned) index) >> (MMX_COEF >> 1));
	return ((ARCH_WORD_32 *) & (crypt_key[idx]))[index & (MMX_COEF -
		1)] & 0xf;
#else
	return MD5_out[index] & 0xF;
#endif
}

static int rawmd5_get_hash_1(int index)
{
#ifdef MMX_COEF
	unsigned int idx = (((unsigned) index) >> (MMX_COEF >> 1));
	return ((ARCH_WORD_32 *) & (crypt_key[idx]))[index & (MMX_COEF -
		1)] & 0xff;
#else
	return MD5_out[index] & 0xFF;
#endif
}

static int rawmd5_get_hash_2(int index)
{
#ifdef MMX_COEF
	unsigned int idx = (((unsigned) index) >> (MMX_COEF >> 1));
	return ((ARCH_WORD_32 *) & (crypt_key[idx]))[index & (MMX_COEF -
		1)] & 0xfff;
#else
	return MD5_out[index] & 0xFFF;
#endif
}

static int rawmd5_get_hash_3(int index)
{
#ifdef MMX_COEF
	unsigned int idx = (((unsigned) index) >> (MMX_COEF >> 1));
	return ((ARCH_WORD_32 *) & (crypt_key[idx]))[index & (MMX_COEF -
		1)] & 0xffff;
#else
	return MD5_out[index] & 0xFFFF;
#endif
}

static int rawmd5_get_hash_4(int index)
{
#ifdef MMX_COEF
	unsigned int idx = (((unsigned) index) >> (MMX_COEF >> 1));
	return ((ARCH_WORD_32 *) & (crypt_key[idx]))[index & (MMX_COEF -
		1)] & 0xfffff;
#else
	return MD5_out[index] & 0xFFFFF;
#endif
}


static void *rawmd5_binary(char *ciphertext)
{
	static char *realcipher;
	int i;
	if (!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	for (i = 0; i < BINARY_SIZE; i++) {
		realcipher[i] =
		    atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
	}
	return (void *) realcipher;
}

struct fmt_main fmt_rawMD5unicode = {
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
		    FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8,
		    rawmd5_tests
	}, {
		    rawmd5_init,
		    fmt_default_prepare,
		    valid,
		    fmt_default_split,
		    rawmd5_binary,
		    fmt_default_salt,
		    {
				rawmd5_binary_hash_0,
				rawmd5_binary_hash_1,
				rawmd5_binary_hash_2,
				rawmd5_binary_hash_3,
			rawmd5_binary_hash_4},
		    fmt_default_salt_hash,
		    fmt_default_set_salt,
		    rawmd5_set_key,
		    rawmd5_get_key,
		    fmt_default_clear_keys,
		    rawmd5_crypt_all,
		    {
				rawmd5_get_hash_0,
				rawmd5_get_hash_1,
				rawmd5_get_hash_2,
				rawmd5_get_hash_3,
			rawmd5_get_hash_4},
		    rawmd5_cmp_all,
		    rawmd5_cmp_one,
	    rawmd5_cmp_exact}
};

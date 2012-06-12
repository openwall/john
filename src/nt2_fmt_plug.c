/*
 * Alternate NT format
 *
 * This  software is Copyright © 2011 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * Losely based on rawSHA1, by bartavelle
 * and is also using his mmx/sse2/sse-intrinsics functions
 *
 */

#include <string.h>

#include "arch.h"

#ifdef MD4_SSE_PARA
#define MMX_COEF			4
#include "sse-intrinsics.h"
#define NBKEYS				(MMX_COEF * MD4_SSE_PARA)
#elif MMX_COEF
#define NBKEYS				MMX_COEF
#endif

#include "md4.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"
#include "memory.h"
#include "johnswap.h"

#define FORMAT_LABEL			"nt2"
#define FORMAT_NAME			"NT v2"

#ifdef MD4_SSE_PARA
#define ALGORITHM_NAME			"SSE2i " MD4_N_STR
#elif defined(MMX_COEF) && MMX_COEF == 4
#define ALGORITHM_NAME			"SSE2 4x"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define ALGORITHM_NAME			"MMX 2x"
#elif defined(MMX_COEF)
#define ALGORITHM_NAME			"?"
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define CIPHERTEXT_LENGTH		36

#define BINARY_SIZE			16
#define SALT_SIZE			0

#ifdef MMX_COEF
#ifdef MD4_SSE_PARA
#define BLOCK_LOOPS			1
#else
#define BLOCK_LOOPS			1
#endif
#define PLAINTEXT_LENGTH		27
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS * BLOCK_LOOPS
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + ((i)&3) + (index>>(MMX_COEF>>1))*16*MMX_COEF*4 )
#else
#define PLAINTEXT_LENGTH		125
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#ifdef MMX_COEF
static unsigned char (*saved_key);
static unsigned char (*crypt_key);
static unsigned int (**buf_ptr);
#ifndef MD4_SSE_PARA
static unsigned int total_len;
#endif
#else
static MD4_CTX ctx;
static int saved_key_length;
static UTF16 saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
#endif

// Note: the ISO-8859-1 plaintexts will be replaced in init() if running UTF-8
static struct fmt_tests tests[] = {
	{"$NT$b7e4b9022cd45f275334bbdb83bb5be5", "John the Ripper"},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$7a21990fcd3d759941e45c490f143d5f", "12345"},
	{"$NT$f9e37e83b83c47a93c2f09f66408631b", "abc123"},
	{"$NT$8846f7eaee8fb117ad06bdd830b7586c", "password"},
	{"$NT$2b2ac2d1c7c8fda6cea80b5fad7563aa", "computer"},
	{"$NT$32ed87bdb5fdc5e9cba88547376818d4", "123456"},
	{"$NT$b7e0ea9fbffcf6dd83086e905089effd", "tigger"},
	{"$NT$7ce21f17c0aee7fb9ceba532d0546ad6", "1234"},
	{"$NT$b23a90d0aad9da3615fafc27a1b8baeb", "a1b2c3"},
	{"$NT$2d20d252a479f485cdf5e171d93985bf", "qwerty"},
	{"$NT$3dbde697d71690a769204beb12283678", "123"},
	{"$NT$c889c75b7c1aae1f7150c5681136e70e", "xxx"},
	{"$NT$d5173c778e0f56d9fc47e3b3c829aca7", "money"},
	{"$NT$0cb6948805f797bf2a82807973b89537", "test"},
	{"$NT$0569fcf2b14b9c7f3d3b5f080cbd85e5", "carmen"},
	{"$NT$f09ab1733a528f430353834152c8a90e", "mickey"},
	{"$NT$878d8014606cda29677a44efa1353fc7", "secret"},
	{"$NT$85ac333bbfcbaa62ba9f8afb76f06268", "summer"},
	{"$NT$5962cc080506d90be8943118f968e164", "internet"},
	{"$NT$f07206c3869bda5acd38a3d923a95d2a", "service"},
	{"$NT$d0dfc65e8f286ef82f6b172789a0ae1c", "canada"},
	{"$NT$066ddfd4ef0e9cd7c256fe77191ef43c", "hello"},
	{"$NT$39b8620e745b8aa4d1108e22f74f29e2", "ranger"},
	{"$NT$8d4ef8654a9adc66d4f628e94f66e31b", "shadow"},
	{"$NT$320a78179516c385e35a93ffa0b1c4ac", "baseball"},
	{"$NT$e533d171ac592a4e70498a58b854717c", "donald"},
	{"$NT$5eee54ce19b97c11fd02e531dd268b4c", "harley"},
	{"$NT$6241f038703cbfb7cc837e3ee04f0f6b", "hockey"},
	{"$NT$becedb42ec3c5c7f965255338be4453c", "letmein"},
	{"$NT$ec2c9f3346af1fb8e4ee94f286bac5ad", "maggie"},
	{"$NT$f5794cbd75cf43d1eb21fad565c7e21c", "mike"},
	{"$NT$74ed32086b1317b742c3a92148df1019", "mustang"},
	{"$NT$63af6e1f1dd9ecd82f17d37881cb92e6", "snoopy"},
	{"$NT$58def5844fe58e8f26a65fff9deb3827", "buster"},
	{"$NT$f7eb9c06fafaa23c4bcf22ba6781c1e2", "dragon"},
	{"$NT$dd555241a4321657e8b827a40b67dd4a", "jordan"},
	{"$NT$bb53a477af18526ada697ce2e51f76b3", "michael"},
	{"$NT$92b7b06bb313bf666640c5a1e75e0c18", "michelle"},
	{NULL}
};

static void set_key_utf8(char *_key, int index);
static void set_key_CP(char *_key, int index);

static void init(struct fmt_main *pFmt)
{
#if MMX_COEF
	int i;
#endif
	if (options.utf8) {
		/* This avoids an if clause for every set_key */
		pFmt->methods.set_key = set_key_utf8;
#if MMX_COEF
		/* kick it up from 27. We will truncate in setkey_utf8() */
		pFmt->params.plaintext_length = 3 * PLAINTEXT_LENGTH;
#endif
		tests[1].plaintext = "\xC3\xBC";	// German u-umlaut in UTF-8
		tests[1].ciphertext = "$NT$8bd6e4fb88e01009818749c5443ea712";
		tests[2].plaintext = "\xC3\xBC\xC3\xBC"; // two of them
		tests[2].ciphertext = "$NT$cc1260adb6985ca749f150c7e0b22063";
		tests[3].plaintext = "\xE2\x82\xAC";	// euro sign
		tests[3].ciphertext = "$NT$030926b781938db4365d46adc7cfbcb8";
		tests[4].plaintext = "\xE2\x82\xAC\xE2\x82\xAC";
		tests[4].ciphertext = "$NT$682467b963bb4e61943e170a04f7db46";
	} else {
		if (!options.ascii && !options.iso8859_1) {
			/* This avoids an if clause for every set_key */
			pFmt->methods.set_key = set_key_CP;
		}
		if (CP_to_Unicode[0xfc] == 0x00fc) {
			tests[1].plaintext = "\xFC";	// German u-umlaut in UTF-8
			tests[1].ciphertext = "$NT$8bd6e4fb88e01009818749c5443ea712";
			tests[2].plaintext = "\xFC\xFC"; // two of them
			tests[2].ciphertext = "$NT$cc1260adb6985ca749f150c7e0b22063";
			tests[3].plaintext = "\xFC\xFC\xFC";	// 3 of them
			tests[3].ciphertext = "$NT$2e583e8c210fb101994c19877ac53b89";
			tests[4].plaintext = "\xFC\xFC\xFC\xFC";
			tests[4].ciphertext = "$NT$243bb98e7704797f92b1dd7ded6da0d0";
		}
	}
#if MMX_COEF
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * 64*pFmt->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_tiny(sizeof(*crypt_key) * BINARY_SIZE*pFmt->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	buf_ptr = mem_calloc_tiny(sizeof(*buf_ptr) * pFmt->params.max_keys_per_crypt, sizeof(*buf_ptr));
	for (i=0; i<pFmt->params.max_keys_per_crypt; i++)
		buf_ptr[i] = (unsigned int*)&saved_key[GETPOS(0, i)];
#endif
}

static char *split(char *ciphertext, int index)
{
	static char out[37];

	if (!strncmp(ciphertext, "$NT$", 4))
		ciphertext += 4;

	out[0] = '$';
	out[1] = 'N';
	out[2] = 'T';
	out[3] = '$';

	memcpy(&out[4], ciphertext, 32);
	out[36] = 0;

	strlwr(&out[4]);

	return out;
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *pos;

	if (strncmp(ciphertext, "$NT$", 4)!=0) return 0;

	for (pos = &ciphertext[4]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);

	if (!*pos && pos - ciphertext == CIPHERTEXT_LENGTH)
		return 1;
	else
		return 0;
}

// here to 'handle' the pwdump files:  user:uid:lmhash:ntlmhash:::
// Note, we address the user id inside loader.
static char *prepare(char *split_fields[10], struct fmt_main *pFmt)
{
	static char out[33+5];
	extern struct options_main options;
	if (!valid(split_fields[1], pFmt)) {
		if (strlen(split_fields[3]) == 32) {
			sprintf(out, "$NT$%s", split_fields[3]);
			if (valid(out,pFmt))
				return out;
		}
		if (options.format && !strcmp(options.format, FORMAT_LABEL) && strlen(split_fields[1]) == 32) {
			sprintf(out, "$NT$%s", split_fields[1]);
			if (valid(out,pFmt))
				return out;
		}
	}
	return split_fields[1];
}

static void *binary(char *ciphertext)
{
	static unsigned long out_[16/sizeof(unsigned long)];
	unsigned int *out = (unsigned int*)out_;
	unsigned int i;
	unsigned int temp;

	ciphertext+=4;
	for (i=0; i<4; i++)
	{
		temp  = (atoi16[ARCH_INDEX(ciphertext[i*8+0])])<<4;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+1])]);

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+2])])<<12;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+3])])<<8;

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+4])])<<20;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+5])])<<16;

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+6])])<<28;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+7])])<<24;

#if ARCH_LITTLE_ENDIAN
		out[i]=temp;
#else
		out[i]=JOHNSWAP(temp);
#endif
	}
//	dump_stuff_msg("binary", out, 16);
	return out;
}

// ISO-8859-1 to UCS-2, directly into vector key buffer
static void set_key(char *_key, int index)
{
#ifdef MMX_COEF
	const unsigned char *key = (unsigned char*)_key;
	unsigned int *keybuf_word = buf_ptr[index];
	unsigned int len, temp2;

#ifndef MD4_SSE_PARA
	if (!index)
		total_len = 0;
#endif
	len = 0;
	while((temp2 = *key++)) {
		unsigned int temp;
		if ((temp = *key++) && len < PLAINTEXT_LENGTH - 1)
		{
			temp2 |= (temp << 16);
			*keybuf_word = temp2;
		}
		else
		{
			temp2 |= (0x80 << 16);
			*keybuf_word = temp2;
			len++;
			goto key_cleaning;
		}
		len += 2;
		keybuf_word += MMX_COEF;
	}
	*keybuf_word = 0x80;

key_cleaning:
	keybuf_word += MMX_COEF;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}

#ifdef MD4_SSE_PARA
	((unsigned int *)saved_key)[14*MMX_COEF + (index&3) + (index>>2)*16*MMX_COEF] = len << 4;
#else
	total_len += len << (1 + ( (32/MMX_COEF) * index ) );
#endif
#else
#if ARCH_LITTLE_ENDIAN
	UTF8 *s = (UTF8*)_key;
	UTF16 *d = saved_key;
	while (*s)
		*d++ = *s++;
	*d = 0;
	saved_key_length = (int)((char*)d - (char*)saved_key);
#else
	UTF8 *s = (UTF8*)_key;
	UTF8 *d = (UTF8*)saved_key;
	while (*s) {
		*d++ = *s++;
		++d;
	}
	*d = 0;
	saved_key_length = (int)((char*)d - (char*)saved_key);
#endif
//	dump_stuff_msg(_key, saved_key, 24);
#endif
}

// Legacy codepage to UCS-2, directly into vector key buffer
static void set_key_CP(char *_key, int index)
{
#ifdef MMX_COEF
	const unsigned char *key = (unsigned char*)_key;
	unsigned int *keybuf_word = buf_ptr[index];
	unsigned int len;

#ifndef MD4_SSE_PARA
	if (!index)
		total_len = 0;
#endif
	len = 0;
	while((*keybuf_word = CP_to_Unicode[*key++])) {
		unsigned int temp;
		if ((temp = CP_to_Unicode[*key++]) && len < PLAINTEXT_LENGTH - 1)
			*keybuf_word |= (temp << 16);
		else {
			*keybuf_word |= (0x80 << 16);
			len++;
			goto key_cleaning_enc;
		}
		len += 2;
		keybuf_word += MMX_COEF;
	}
	*keybuf_word = 0x80;

key_cleaning_enc:
	keybuf_word += MMX_COEF;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}

#ifdef MD4_SSE_PARA
	((unsigned int *)saved_key)[14*MMX_COEF + (index&3) + (index>>2)*16*MMX_COEF] = len << 4;
#else
	total_len += len << (1 + ( (32/MMX_COEF) * index ) );
#endif
#else
	saved_key_length = enc_to_utf16((UTF16*)&saved_key,
	                                PLAINTEXT_LENGTH + 1,
	                                (unsigned char*)_key,
	                                strlen(_key)) << 1;
	if (saved_key_length <= 0)
		saved_key_length = strlen16(saved_key);
#endif
}

// UTF-8 to UCS-2, directly into vector key buffer
static void set_key_utf8(char *_key, int index)
{
#ifdef MMX_COEF
	const UTF8 *source = (UTF8*)_key;
	unsigned int *keybuf_word = buf_ptr[index];
	UTF32 chl, chh = 0x80;
	unsigned int len = 0;

#ifndef MD4_SSE_PARA
	if (!index)
		total_len = 0;
#endif
	while (*source) {
		chl = *source;
		if (chl >= 0xC0) {
			unsigned int extraBytesToRead = opt_trailingBytesUTF8[chl & 0x3f];
			switch (extraBytesToRead) {
			case 2:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else
					return;
			case 1:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else
					return;
			case 0:
				break;
			default:
				return;
			}
			chl -= offsetsFromUTF8[extraBytesToRead];
		}
		source++;
		len++;
		if (*source && len < PLAINTEXT_LENGTH) {
			chh = *source;
			if (chh >= 0xC0) {
				unsigned int extraBytesToRead =
					opt_trailingBytesUTF8[chh & 0x3f];
				switch (extraBytesToRead) {
				case 2:
					++source;
					if (*source) {
						chh <<= 6;
						chh += *source;
					} else
						return;
				case 1:
					++source;
					if (*source) {
						chh <<= 6;
						chh += *source;
					} else
						return;
				case 0:
					break;
				default:
					return;
				}
				chh -= offsetsFromUTF8[extraBytesToRead];
			}
			source++;
			len++;
		} else {
			chh = 0x80;
			*keybuf_word = (chh << 16) | chl;
			keybuf_word += MMX_COEF;
			break;
		}
		*keybuf_word = (chh << 16) | chl;
		keybuf_word += MMX_COEF;
	}
	if (chh != 0x80 || len == 0) {
		*keybuf_word = 0x80;
		keybuf_word += MMX_COEF;
	}

	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}

#ifdef MD4_SSE_PARA
	((unsigned int *)saved_key)[14*MMX_COEF + (index&3) + (index>>2)*16*MMX_COEF] = len << 4;
#else
	total_len += len << (1 + ( (32/MMX_COEF) * index ) );
#endif
#else
	saved_key_length = utf8_to_utf16((UTF16*)&saved_key,
	                                 PLAINTEXT_LENGTH + 1,
	                                 (unsigned char*)_key,
	                                 strlen(_key)) << 1;
	if (saved_key_length <= 0)
		saved_key_length = strlen16(saved_key);
#endif
}

static char *get_key(int index)
{
#ifdef MMX_COEF
	// Get the key back from the key buffer, from UCS-2
	unsigned int *keybuffer = (unsigned int*)&saved_key[GETPOS(0, index)];
	static UTF16 key[PLAINTEXT_LENGTH + 1];
	unsigned int md4_size=0;
	unsigned int i=0;

	for(; md4_size < PLAINTEXT_LENGTH; i += MMX_COEF, md4_size++)
	{
		key[md4_size] = keybuffer[i];
		key[md4_size+1] = keybuffer[i] >> 16;
		if (key[md4_size] == 0x80 && key[md4_size+1] == 0) {
			key[md4_size] = 0;
			break;
		}
		++md4_size;
		if (key[md4_size] == 0x80 && ((keybuffer[i+MMX_COEF]&0xFFFF) == 0 || md4_size == PLAINTEXT_LENGTH)) {
			key[md4_size] = 0;
			break;
		}
	}
	return (char*)utf16_to_enc(key);
#else
#if ARCH_LITTLE_ENDIAN
//	char *x = utf16_to_enc(saved_key);
//	printf ("x=%s\n",x);
//	return x;
	return (char*)utf16_to_enc(saved_key);
#else
	int i;
	UTF16 Tmp[80];
	UTF8 *p = (UTF8*)saved_key, *p2 = (UTF8*)Tmp;
	for (i = 0; i < saved_key_length; i += 2) {
		p2[i] = p[i+1];
		p2[i+1] = p[i];
	}
	p2[i] = 0;
	p2[i+1] = 0;
//	char *x = utf16_to_enc(Tmp);
//	printf ("x=%s\n",x);
//	return x;
	return (char*)utf16_to_enc(Tmp);
#endif
#endif
}

static int cmp_all(void *binary, int count) {
#ifdef MMX_COEF
	unsigned int x,y=0;

#if MD4_SSE_PARA
	for(;y<MD4_SSE_PARA*BLOCK_LOOPS;y++)
#endif
		for(x=0;x<MMX_COEF;x++)
		{
			if( ((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*4] )
				return 1;
		}
	return 0;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int count){
	return (1);
}

static int cmp_one(void *binary, int index)
{
#ifdef MMX_COEF
	unsigned int x,y;
	x = index&3;
	y = index/4;

	if( ((ARCH_WORD_32*)binary)[0] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*4] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[1] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*4+MMX_COEF] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[2] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*4+2*MMX_COEF] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[3] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*4+3*MMX_COEF] )
		return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static void crypt_all(int count) {
#if defined(MD4_SSE_PARA)
#if (BLOCK_LOOPS > 1)
	int i;
	// This was an experiment. It's not used (unless you bump BLOCK_LOOPS),
	// cause it does not scale well. We would need to parallelize set_key()
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < BLOCK_LOOPS; i++)
		SSEmd4body(&saved_key[i*NBKEYS*64], (unsigned int*)&crypt_key[i*NBKEYS*BINARY_SIZE], 1);
#else
	SSEmd4body(saved_key, (unsigned int*)crypt_key, 1);
#endif
#elif defined(MMX_COEF)
	mdfourmmx(crypt_key, saved_key, total_len);
#else
	MD4_Init( &ctx );
//	dump_stuff_msg("saved_key", saved_key, saved_key_length);
	MD4_Update(&ctx, (unsigned char*)saved_key, saved_key_length);
	MD4_Final((unsigned char*) crypt_key, &ctx);
//	dump_stuff_msg("crypt_key", crypt_key, 16);
#endif
}

static int binary_hash_0(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xf; }
static int binary_hash_1(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xff; }
static int binary_hash_2(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfff; }
static int binary_hash_3(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffff; }
static int binary_hash_4(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfffff; }
static int binary_hash_5(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffffff; }
static int binary_hash_6(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0x7ffffff; }

#ifdef MMX_COEF
static int get_hash_0(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*4] & 0xf;
}
static int get_hash_1(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*4] & 0xff;
}
static int get_hash_2(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*4] & 0xfff;
}
static int get_hash_3(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*4] & 0xffff;
}
static int get_hash_4(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*4] & 0xfffff;
}
static int get_hash_5(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*4] & 0xffffff;
}
static int get_hash_6(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*4] & 0x7ffffff;
}
#else
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[index] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[index] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[index] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[index] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[index] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[index] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[index] & 0x7ffffff; }
#endif

struct fmt_main fmt_magnumNT = {
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
#if (BLOCK_LOOPS > 1) && defined(SSE_MD4_PARA)
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8,
		tests
	}, {
		init,
		prepare,
		valid,
		split,
		binary,
		fmt_default_salt,
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
		fmt_default_set_salt,
		set_key,
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

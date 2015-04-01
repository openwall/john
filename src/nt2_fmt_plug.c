/*
 * Alternate NT format, with reduced binary size
 *
 * This software is Copyright 2011, 2012 magnum, and it is hereby released to
 * the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 *
 * Losely based on rawSHA1, by bartavelle
 * and is also using his mmx/sse2/sse-intrinsics functions
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_NT2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_NT2);
#else

#include <string.h>

#include "arch.h"

#ifdef SIMD_COEF_32
#define NBKEYS				(SIMD_COEF_32 * MD4_SSE_PARA)
#endif
#include "sse-intrinsics.h"

#include "md4.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"
#include "memory.h"
#include "johnswap.h"
#include "memdbg.h"

#define FORMAT_LABEL			"nt2" /* Should be nt-ng now */
#define FORMAT_NAME			"NT"

#define ALGORITHM_NAME			"MD4 " MD4_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define CIPHERTEXT_LENGTH		32

#define DIGEST_SIZE			16
#define BINARY_SIZE			16 // source()
#define BINARY_ALIGN			4
#define SALT_SIZE			0
#define SALT_ALIGN			1

#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif

#ifdef SIMD_COEF_32
#if defined(_OPENMP)
#ifdef __XOP__
#define BLOCK_LOOPS			(1024*1024)
#elif __AVX__
#define BLOCK_LOOPS			4096 // tuned for i7 w/o HT
#else
#define BLOCK_LOOPS			1 // Old CPUs won't work well with OMP
#endif
#else
#define BLOCK_LOOPS			1 // Never change this
#endif
#define PLAINTEXT_LENGTH		27
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS * BLOCK_LOOPS
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (index>>SIMD_COEF32_BITS)*16*SIMD_COEF_32*4 )
#else
#define PLAINTEXT_LENGTH		125
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#ifdef SIMD_COEF_32
static unsigned char (*saved_key);
static unsigned char (*crypt_key);
static unsigned int (**buf_ptr);
#else
static MD4_CTX ctx;
static int saved_len;
static UTF16 saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[DIGEST_SIZE / 4];
#endif

// Note: the ISO-8859-1 plaintexts will be replaced in init() if running UTF-8
static struct fmt_tests tests[] = {
	{"b7e4b9022cd45f275334bbdb83bb5be5", "John the Ripper"},
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

static void init(struct fmt_main *self)
{
#if SIMD_COEF_32
	int i;
#endif
	if (pers_opts.target_enc == UTF_8) {
		/* This avoids an if clause for every set_key */
		self->methods.set_key = set_key_utf8;
#if SIMD_COEF_32
		/* kick it up from 27. We will truncate in setkey_utf8() */
		self->params.plaintext_length = 3 * PLAINTEXT_LENGTH;
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
		if (pers_opts.target_enc != ASCII && pers_opts.target_enc != ISO_8859_1) {
			/* This avoids an if clause for every set_key */
			self->methods.set_key = set_key_CP;
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
#if SIMD_COEF_32
	saved_key = mem_calloc_align(64 * self->params.max_keys_per_crypt,
	                             sizeof(*saved_key), MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_align(DIGEST_SIZE *
	                             self->params.max_keys_per_crypt,
	                             sizeof(*crypt_key), MEM_ALIGN_SIMD);
	buf_ptr = mem_calloc(self->params.max_keys_per_crypt, sizeof(*buf_ptr));
	for (i=0; i<self->params.max_keys_per_crypt; i++)
		buf_ptr[i] = (unsigned int*)&saved_key[GETPOS(0, i)];
#endif
}

static void done(void)
{
#if SIMD_COEF_32
	MEM_FREE(buf_ptr);
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
#endif
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
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

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	if (!strncmp(ciphertext, "$NT$", 4))
		ciphertext += 4;

	for (pos = ciphertext; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);

	if (!*pos && pos - ciphertext == CIPHERTEXT_LENGTH)
		return 1;
	else
		return 0;
}

// here to 'handle' the pwdump files:  user:uid:lmhash:ntlmhash:::
// Note, we address the user id inside loader.
static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	static char out[33+5];

	if (!valid(split_fields[1], self)) {
		if (split_fields[3] && strlen(split_fields[3]) == 32) {
			sprintf(out, "$NT$%s", split_fields[3]);
			if (valid(out,self))
				return out;
		}
	}
	return split_fields[1];
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned long dummy;
		unsigned int i[DIGEST_SIZE/sizeof(unsigned int)];
	} _out;
	unsigned int *out = _out.i;
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
#ifdef SIMD_COEF_32
	const unsigned char *key = (unsigned char*)_key;
	unsigned int *keybuf_word = buf_ptr[index];
	unsigned int len, temp2;

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
		keybuf_word += SIMD_COEF_32;
	}
	*keybuf_word = 0x80;

key_cleaning:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}

	((unsigned int *)saved_key)[14*SIMD_COEF_32 + (index&3) + (index>>SIMD_COEF32_BITS)*16*SIMD_COEF_32] = len << 4;
#else
#if ARCH_LITTLE_ENDIAN
	UTF8 *s = (UTF8*)_key;
	UTF16 *d = saved_key;
	while (*s)
		*d++ = *s++;
	*d = 0;
	saved_len = (int)((char*)d - (char*)saved_key);
#else
	UTF8 *s = (UTF8*)_key;
	UTF8 *d = (UTF8*)saved_key;
	while (*s) {
		*d++ = *s++;
		++d;
	}
	*d = 0;
	saved_len = (int)((char*)d - (char*)saved_key);
#endif
//	dump_stuff_msg(_key, saved_key, 24);
#endif
}

// Legacy codepage to UCS-2, directly into vector key buffer
static void set_key_CP(char *_key, int index)
{
#ifdef SIMD_COEF_32
	const unsigned char *key = (unsigned char*)_key;
	unsigned int *keybuf_word = buf_ptr[index];
	unsigned int len, temp2;

	len = 0;
	while((temp2 = *key++)) {
		unsigned int temp;
		temp2 = CP_to_Unicode[temp2];
		if ((temp = *key++) && len < PLAINTEXT_LENGTH - 1)
		{
			temp = CP_to_Unicode[temp];
			temp2 |= (temp << 16);
			*keybuf_word = temp2;
		} else {
			temp2 |= (0x80 << 16);
			*keybuf_word = temp2;
			len++;
			goto key_cleaning_enc;
		}
		len += 2;
		keybuf_word += SIMD_COEF_32;
	}
	*keybuf_word = 0x80;

key_cleaning_enc:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}
	((unsigned int *)saved_key)[14*SIMD_COEF_32 + (index&3) + (index>>SIMD_COEF32_BITS)*16*SIMD_COEF_32] = len << 4;
#else
	saved_len = enc_to_utf16((UTF16*)&saved_key,
	                                PLAINTEXT_LENGTH + 1,
	                                (unsigned char*)_key,
	                                strlen(_key)) << 1;
	if (saved_len < 0)
		saved_len = strlen16(saved_key);
#endif
}

// UTF-8 to UCS-2, directly into vector key buffer
static void set_key_utf8(char *_key, int index)
{
#ifdef SIMD_COEF_32
	const UTF8 *source = (UTF8*)_key;
	unsigned int *keybuf_word = buf_ptr[index];
	UTF32 chl, chh = 0x80;
	unsigned int len = 0;

	while (*source) {
		chl = *source;
		if (chl >= 0xC0) {
			unsigned int extraBytesToRead = opt_trailingBytesUTF8[chl & 0x3f];
			switch (extraBytesToRead) {
#if NT_FULL_UNICODE
			case 3:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else
					goto bailout;
#endif
			case 2:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else
					goto bailout;
			case 1:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else
					goto bailout;
			case 0:
				break;
			default:
				goto bailout;
			}
			chl -= offsetsFromUTF8[extraBytesToRead];
		}
		source++;
		len++;
#if NT_FULL_UNICODE
		if (chl > UNI_MAX_BMP) {
			if (len == PLAINTEXT_LENGTH) {
				chh = 0x80;
				*keybuf_word = (chh << 16) | chl;
				keybuf_word += SIMD_COEF_32;
				break;
			}
			#define halfBase 0x0010000UL
			#define halfShift 10
			#define halfMask 0x3FFUL
			#define UNI_SUR_HIGH_START  (UTF32)0xD800
			#define UNI_SUR_LOW_START   (UTF32)0xDC00
			chl -= halfBase;
			chh = (UTF16)((chl & halfMask) + UNI_SUR_LOW_START);;
			chl = (UTF16)((chl >> halfShift) + UNI_SUR_HIGH_START);
			len++;
		} else
#endif
		if (*source && len < PLAINTEXT_LENGTH) {
			chh = *source;
			if (chh >= 0xC0) {
				unsigned int extraBytesToRead =
					opt_trailingBytesUTF8[chh & 0x3f];
				switch (extraBytesToRead) {
#if NT_FULL_UNICODE
				case 3:
					++source;
					if (*source) {
						chl <<= 6;
						chl += *source;
					} else
						goto bailout;
#endif
				case 2:
					++source;
					if (*source) {
						chh <<= 6;
						chh += *source;
					} else
						goto bailout;
				case 1:
					++source;
					if (*source) {
						chh <<= 6;
						chh += *source;
					} else
						goto bailout;
				case 0:
					break;
				default:
					goto bailout;
				}
				chh -= offsetsFromUTF8[extraBytesToRead];
			}
			source++;
			len++;
		} else {
			chh = 0x80;
			*keybuf_word = (chh << 16) | chl;
			keybuf_word += SIMD_COEF_32;
			break;
		}
		*keybuf_word = (chh << 16) | chl;
		keybuf_word += SIMD_COEF_32;
	}
	if (chh != 0x80 || len == 0) {
		*keybuf_word = 0x80;
		keybuf_word += SIMD_COEF_32;
	}

bailout:
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}

	((unsigned int *)saved_key)[14*SIMD_COEF_32 + (index&3) + (index>>SIMD_COEF32_BITS)*16*SIMD_COEF_32] = len << 4;

#else
	saved_len = utf8_to_utf16((UTF16*)&saved_key,
	                                 PLAINTEXT_LENGTH + 1,
	                                 (unsigned char*)_key,
	                                 strlen(_key)) << 1;
	if (saved_len < 0)
		saved_len = strlen16(saved_key);
#endif
}

static char *get_key(int index)
{
#ifdef SIMD_COEF_32
	// Get the key back from the key buffer, from UCS-2
	unsigned int *keybuffer = (unsigned int*)&saved_key[GETPOS(0, index)];
	static UTF16 key[PLAINTEXT_LENGTH + 1];
	unsigned int md4_size=0;
	unsigned int i=0;

	for(; md4_size < PLAINTEXT_LENGTH; i += SIMD_COEF_32, md4_size++)
	{
		key[md4_size] = keybuffer[i];
		key[md4_size+1] = keybuffer[i] >> 16;
		if (key[md4_size] == 0x80 && key[md4_size+1] == 0) {
			key[md4_size] = 0;
			break;
		}
		++md4_size;
		if (key[md4_size] == 0x80 && ((keybuffer[i+SIMD_COEF_32]&0xFFFF) == 0 || md4_size == PLAINTEXT_LENGTH)) {
			key[md4_size] = 0;
			break;
		}
	}
	return (char*)utf16_to_enc(key);
#else
	return (char*)utf16_to_enc(saved_key);
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
#ifdef SIMD_COEF_32
#if (BLOCK_LOOPS > 1)
	int i;

	const int count = (*pcount + NBKEYS - 1) / NBKEYS;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++)
		SSEmd4body(&saved_key[i*NBKEYS*64], (unsigned int*)&crypt_key[i*NBKEYS*DIGEST_SIZE], NULL, SSEi_MIXED_IN);
#else
	SSEmd4body(saved_key, (ARCH_WORD_32*)crypt_key, NULL, SSEi_MIXED_IN);
#endif

#else
	MD4_Init( &ctx );
//	dump_stuff_msg("saved_key", saved_key, saved_len);
	MD4_Update(&ctx, (unsigned char*)saved_key, saved_len);
	MD4_Final((unsigned char*) crypt_key, &ctx);
//	dump_stuff_msg("crypt_key", crypt_key, 16);
#endif
	return *pcount;
}

static int cmp_all(void *binary, int count) {
#ifdef SIMD_COEF_32
	unsigned int x,y=0;
	for(; y < MD4_SSE_PARA * BLOCK_LOOPS; y++)
		for(x = 0; x < SIMD_COEF_32; x++)
		{
			if( ((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[y*SIMD_COEF_32*4+x] )
				return 1;
		}
	return 0;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	unsigned int x = index&(SIMD_COEF_32-1);
	unsigned int y = index/SIMD_COEF_32;

#if BINARY_SIZE < DIGEST_SIZE
	return ((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*4];
#else
	int i;
	for(i=0;i<(DIGEST_SIZE/4);i++)
		if ( ((ARCH_WORD_32*)binary)[i] != ((ARCH_WORD_32*)crypt_key)[y*SIMD_COEF_32*4+i*SIMD_COEF_32+x] )
			return 0;
	return 1;
#endif
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
#if BINARY_SIZE == DIGEST_SIZE
	return 1;
#else
#ifdef SIMD_COEF_32
	unsigned int i, x, y;
	ARCH_WORD_32 *full_binary;

	full_binary = (ARCH_WORD_32*)get_binary(source);
	x = index&(SIMD_COEF_32-1);
	y = index/SIMD_COEF_32;
	for(i=0;i<(DIGEST_SIZE/4);i++)
		if (full_binary[i] != ((ARCH_WORD_32*)crypt_key)[y*SIMD_COEF_32*4+i*SIMD_COEF_32+x])
			return 0;
	return 1;
#else
	return !memcmp(get_binary(source), crypt_key, DIGEST_SIZE);
#endif
#endif
}

#ifdef SIMD_COEF_32
static int get_hash_0(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*4] & 0xf;
}
static int get_hash_1(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*4] & 0xff;
}
static int get_hash_2(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*4] & 0xfff;
}
static int get_hash_3(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*4] & 0xffff;
}
static int get_hash_4(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*4] & 0xfffff;
}
static int get_hash_5(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*4] & 0xffffff;
}
static int get_hash_6(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*4] & 0x7ffffff;
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

static char *source(char *source, void *binary)
{
	static char Buf[CIPHERTEXT_LENGTH + 4 + 1];
	unsigned char *cpi;
	char *cpo;
	int i;

	strcpy(Buf, "$NT$");
	cpo = &Buf[4];

	cpi = (unsigned char*)(binary);

	for (i = 0; i < 16; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}

struct fmt_main fmt_NT2 = {
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
#if defined(_OPENMP) && (BLOCK_LOOPS > 1) && defined(MD4_SSE_PARA)
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_UTF8,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		source,
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

#endif /* plugin stanza */

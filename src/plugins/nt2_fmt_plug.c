/*
 * NT-ng format, using intrinsics.
 *
 * This software is Copyright 2011, 2012 magnum, and it is hereby released to
 * the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 *
 * Losely based on rawSHA1, by bartavelle
 * and is also using his mmx/sse2/simd-intrinsics functions
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_NT2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_NT2);
#else

#include <string.h>

#include "arch.h"
#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif
#if defined(_OPENMP)
#include <omp.h>
#endif

#define REVERSE_STEPS
#include "md4.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"
#include "memory.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

#ifdef SIMD_COEF_32
#define NBKEYS				(SIMD_COEF_32 * SIMD_PARA_MD4)
#endif

#define FORMAT_LABEL			"NT"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"MD4 " MD4_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107

#define CIPHERTEXT_LENGTH		32
#define FORMAT_TAG				"$NT$"
#define TAG_LENGTH				(sizeof(FORMAT_TAG) - 1)

#define DIGEST_SIZE			16
#define BINARY_SIZE			DIGEST_SIZE
#define BINARY_ALIGN			4
#define SALT_SIZE			0
#define SALT_ALIGN			1

#if SIMD_COEF_32
#define PLAINTEXT_LENGTH		27
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		(NBKEYS * 8)
#define GETPOSW(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i*4)&(0xffffffff-3))*SIMD_COEF_32 + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32*4 )
#else
#define PLAINTEXT_LENGTH		125
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		64
#endif

#ifndef OMP_SCALE
#define OMP_SCALE			16 // Tuned w/ MKPC for core i7 incl non-SIMD
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

static char *source(char *source, void *binary)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1] = FORMAT_TAG;
	uint32_t b[4];
	char *p;
	int i, j;

	memcpy(b, binary, sizeof(b));

#if SIMD_COEF_32 && defined(REVERSE_STEPS)
	md4_unreverse(b);
#endif

#if !ARCH_LITTLE_ENDIAN && !defined (SIMD_COEF_32)
	alter_endianity(b, 16);
#endif

	p = &out[TAG_LENGTH];
	for (i = 0; i < 4; i++)
		for (j = 0; j < 8; j++)
			*p++ = itoa16[(b[i] >> ((j ^ 1) * 4)) & 0xf];

	return out;
}

#ifdef SIMD_COEF_32
static unsigned char (*saved_key);
static unsigned char (*crypt_key);
static unsigned int (**buf_ptr);
#else
static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_key)[4];
static int (*saved_len);
#endif

static void set_key_utf8(char *_key, int index);
static void set_key_CP(char *_key, int index);

static void init(struct fmt_main *self)
{
#if SIMD_COEF_32
	int i;
#endif

	omp_autotune(self, OMP_SCALE);

	if (options.target_enc == UTF_8) {
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
		if (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1) {
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
		buf_ptr[i] = (unsigned int*)&saved_key[GETPOSW(0, i)];
#else
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
#endif
}

static void done(void)
{
#if SIMD_COEF_32
	MEM_FREE(buf_ptr);
#else
	MEM_FREE(saved_len);
#endif
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[37];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);

	memcpylwr(&out[TAG_LENGTH], ciphertext, 32);
	out[36] = 0;

	return out;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

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
	static char out[33 + TAG_LENGTH + 1];

	if (!valid(split_fields[1], self) && split_fields[1][0] != '$') {
		if (split_fields[3] && strlen(split_fields[3]) == 32) {
			sprintf(out, "%s%s", FORMAT_TAG, split_fields[3]);
			if (valid(out, self))
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

	ciphertext += TAG_LENGTH;
	for (i=0; i<4; i++)
	{
		temp  = ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+0])]))<<4;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+1])]));

		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+2])]))<<12;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+3])]))<<8;

		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+4])]))<<20;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+5])]))<<16;

		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+6])]))<<28;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+7])]))<<24;

#if ARCH_LITTLE_ENDIAN || defined(SIMD_COEF_32)
		out[i]=temp;
#else
		out[i]=JOHNSWAP(temp);
#endif
	}

#if SIMD_COEF_32 && defined(REVERSE_STEPS)
	md4_reverse(out);
#endif

	//dump_stuff_msg("\nbinary", out, 16);
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

	((unsigned int *)saved_key)[14*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32] = len << 4;
#else
#if ARCH_LITTLE_ENDIAN
	UTF8 *s = (UTF8*)_key;
	UTF16 *d = saved_key[index];
	while (*s)
		*d++ = *s++;
	*d = 0;
	saved_len[index] = (int)((char*)d - (char*)saved_key[index]);
#else
	UTF8 *s = (UTF8*)_key;
	UTF8 *d = (UTF8*)saved_key[index];
	while (*s) {
		*d++ = *s++;
		++d;
	}
	*d = 0;
	saved_len[index] = (int)((char*)d - (char*)saved_key[index]);
#endif
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
	((unsigned int *)saved_key)[14*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32] = len << 4;
#else
	saved_len[index] = enc_to_utf16(saved_key[index],
	                                PLAINTEXT_LENGTH + 1,
	                                (unsigned char*)_key,
	                                strlen(_key)) << 1;
	if (saved_len[index] < 0)
		saved_len[index] = strlen16(saved_key[index]);
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

	((unsigned int *)saved_key)[14*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32] = len << 4;

#else
	saved_len[index] = utf8_to_utf16(saved_key[index],
	                                 PLAINTEXT_LENGTH + 1,
	                                 (unsigned char*)_key,
	                                 strlen(_key)) << 1;
	if (saved_len[index] < 0)
		saved_len[index] = strlen16(saved_key[index]);
#endif
}

static char *get_key(int index)
{
#ifdef SIMD_COEF_32
	// Get the key back from the key buffer, from UCS-2
	unsigned int *keybuffer = (unsigned int*)&saved_key[GETPOSW(0, index)];
	static UTF16 key[PLAINTEXT_LENGTH + 1];
	unsigned int md4_size=0;
	unsigned int i=0;

	for (; md4_size < PLAINTEXT_LENGTH; i += SIMD_COEF_32, md4_size++)
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
#if !ARCH_LITTLE_ENDIAN
	alter_endianity_w16(key, md4_size<<1);
#endif
	return (char*)utf16_to_enc(key);
#else
	return (char*)utf16_to_enc(saved_key[index]);
#endif
}

#ifndef REVERSE_STEPS
#undef SSEi_REVERSE_STEPS
#define SSEi_REVERSE_STEPS SSEi_NO_OP
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i = 0;
	const unsigned int count =
		(*pcount + MIN_KEYS_PER_CRYPT - 1) / MIN_KEYS_PER_CRYPT;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
#ifdef SIMD_COEF_32

		SIMDmd4body(&saved_key[i*NBKEYS*64], (unsigned int*)&crypt_key[i*NBKEYS*DIGEST_SIZE], NULL, SSEi_REVERSE_STEPS | SSEi_MIXED_IN);

#else
		MD4_CTX ctx;

		MD4_Init( &ctx );
		MD4_Update(&ctx, (unsigned char*)saved_key[i], saved_len[i]);
		MD4_Final((unsigned char*) crypt_key[i], &ctx);
#endif
	}
	return *pcount;
}

static int cmp_all(void *binary, int count) {
#ifdef SIMD_COEF_32
	unsigned int x, y;
	const unsigned int c = (count + SIMD_COEF_32 - 1) / SIMD_COEF_32;

	for (y = 0; y < c; y++) {
		for (x = 0; x < SIMD_COEF_32; x++) {
			if ( ((uint32_t*)binary)[1] == ((uint32_t*)crypt_key)[y*SIMD_COEF_32*4+x+SIMD_COEF_32] )
				return 1;
		}
	}

	return 0;
#else
	int i;

	for (i = 0; i < count; i++)
		if (!memcmp(binary, crypt_key[i], BINARY_SIZE))
			return 1;
	return 0;
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	unsigned int x = index&(SIMD_COEF_32-1);
	unsigned int y = (unsigned int)index/SIMD_COEF_32;

	return ((uint32_t*)binary)[1] == ((uint32_t*)crypt_key)[x+y*SIMD_COEF_32*4+SIMD_COEF_32];
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
#ifdef SIMD_COEF_32
	uint32_t crypt_key[DIGEST_SIZE / 4];
	UTF16 u16[PLAINTEXT_LENGTH + 1];
	MD4_CTX ctx;
	UTF8 *key = (UTF8*)get_key(index);
	int len = enc_to_utf16(u16, PLAINTEXT_LENGTH, key, strlen((char*)key));

	if (len <= 0)
		len = strlen16(u16);

	MD4_Init(&ctx);
	MD4_Update(&ctx, u16, len << 1);
	MD4_Final((void*)crypt_key, &ctx);

#if !ARCH_LITTLE_ENDIAN
	alter_endianity(crypt_key, 16);
#endif
#ifdef REVERSE_STEPS
	md4_reverse(crypt_key);
#endif
	return !memcmp(get_binary(source), crypt_key, DIGEST_SIZE);
#else
	return 1;
#endif
}

#ifdef SIMD_COEF_32
#define SIMD_INDEX (index&(SIMD_COEF_32-1))+(unsigned int)index/SIMD_COEF_32*SIMD_COEF_32*4+SIMD_COEF_32
static int get_hash_0(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_0; }
static int get_hash_1(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_1; }
static int get_hash_2(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_2; }
static int get_hash_3(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_3; }
static int get_hash_4(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_4; }
static int get_hash_5(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_5; }
static int get_hash_6(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_6; }
#else
static int get_hash_0(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_0; }
static int get_hash_1(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_1; }
static int get_hash_2(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_2; }
static int get_hash_3(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_3; }
static int get_hash_4(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_4; }
static int get_hash_5(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_5; }
static int get_hash_6(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_6; }
#endif

static int binary_hash_0(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_0; }
static int binary_hash_1(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_1; }
static int binary_hash_2(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_2; }
static int binary_hash_3(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_3; }
static int binary_hash_4(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_4; }
static int binary_hash_5(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_5; }
static int binary_hash_6(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_6; }

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
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_ENC,
		{ NULL },
		{ FORMAT_TAG },
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
		{ NULL },
		source,
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

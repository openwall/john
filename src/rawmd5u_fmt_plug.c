/*
 * Thick raw-md5-unicode (come-back :)
 *
 * This software is Copyright (c) 2011 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawmd5uthick;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawmd5uthick);
#else

#include <string.h>

#include "arch.h"

#ifdef SIMD_COEF_32
#define NBKEYS				(SIMD_COEF_32 * SIMD_PARA_MD5)
#endif
#include "simd-intrinsics.h"

#include "md5.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"
#include "memory.h"
#include "johnswap.h"

#define FORMAT_LABEL			"Raw-MD5u"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"md5(utf16($p)) " MD5_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107

#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE			16
#define BINARY_ALIGN			4
#define SALT_SIZE			0
#define SALT_ALIGN			1

#ifdef SIMD_COEF_32
#define BLOCK_LOOPS			1
#define PLAINTEXT_LENGTH		27
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS * BLOCK_LOOPS
#define GETPOSW(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i*4)&(0xffffffff-3))*SIMD_COEF_32 + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32*4 )
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
static MD5_CTX ctx;
static int saved_len;
static UTF16 saved_key[PLAINTEXT_LENGTH + 1];
static uint32_t crypt_key[BINARY_SIZE / 4];
#endif

/* Note some plaintexts will be replaced in init() if running UTF-8 */
static struct fmt_tests tests[] = {
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
	// repeat first hash in exactly the same form that is used in john.pot
	{"$dynamic_29$16c47151c18ac087cd12b3a70746c790", "test1"},
	{NULL}
};

static void set_key_utf8(char *_key, int index);
static void set_key_CP(char *_key, int index);

static void init(struct fmt_main *self)
{
#if SIMD_COEF_32
	int i;
#endif
	if (options.target_enc == UTF_8) {
		/* This avoids an if clause for every set_key */
		self->methods.set_key = set_key_utf8;
#if SIMD_COEF_32
		/* kick it up from 27. We will truncate in setkey_utf8() */
		self->params.plaintext_length = 3 * PLAINTEXT_LENGTH;
#endif
		tests[1].ciphertext = "94a4e171de16580742c4d141e6607bf7";
		tests[1].plaintext = "\xE2\x82\xAC";	// Euro sign
		tests[2].ciphertext = "03c60810f0e54d16e826aca385d776c8";
		tests[2].plaintext = "\xE2\x82\xAC\xE2\x82\xAC";	// 2 x euro
		tests[3].ciphertext = "2d554433d7cde7ec8d16aaf126c3be6b";
		tests[3].plaintext = "\xE2\x82\xAC\xC3\xBC";	// euro and u-umlaut
		tests[4].ciphertext = "8007d9070b27db7b30433df2cd10abc1";
		tests[4].plaintext = "\xC3\xBC\xE2\x82\xAC";	// u-umlaut and euro
	} else {
		if (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1) {
			/* This avoids an if clause for every set_key */
			self->methods.set_key = set_key_CP;
		}
		if (CP_to_Unicode[0xfc] == 0x00fc) {
			tests[1].ciphertext = "ea7ab2b5c07650badab30790d0c9b63e";
			tests[1].plaintext = "\xFC";	// German u-umlaut in iso-8859-1
			tests[2].ciphertext = "f0a0b9f1dea0e458cec9a284ff434d44";
			tests[2].plaintext = "\xFC\xFC";
			tests[3].ciphertext = "d25a0b436b768777cc9a343d283dbf5a";
			tests[3].plaintext = "\xFC\xFC\xFC";
			tests[4].ciphertext = "719917322bf12168f8c55939e4fec8de";
			tests[4].plaintext = "\xFC\xFC\xFC\xFC";
		}
	}
#if SIMD_COEF_32
	saved_key = mem_calloc_align(sizeof(*saved_key), 64*self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_align(sizeof(*crypt_key), BINARY_SIZE*self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	buf_ptr = mem_calloc_align(sizeof(*buf_ptr), self->params.max_keys_per_crypt, sizeof(*buf_ptr));
	for (i=0; i<self->params.max_keys_per_crypt; i++)
		buf_ptr[i] = (unsigned int*)&saved_key[GETPOSW(0, i)];
#endif
}

static void done(void)
{
#ifdef SIMD_COEF_32
	MEM_FREE(buf_ptr);
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
#endif
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[32+12+1];

	if (!strncmp(ciphertext, "$dynamic_29$", 12))
		ciphertext += 12;

	strcpy(out, "$dynamic_29$");

	memcpylwr(&out[12], ciphertext, CIPHERTEXT_LENGTH);
	out[sizeof(out)-1] = 0;

	return out;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	if (!strncmp(ciphertext, "$dynamic_29$", 12))
		ciphertext += 12;

	for (pos = ciphertext; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);

	if (!*pos && pos - ciphertext == CIPHERTEXT_LENGTH)
		return 1;
	else
		return 0;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned long dummy;
		unsigned int i[BINARY_SIZE/sizeof(unsigned int)];
	} _out;
	unsigned int *out = _out.i;
	unsigned int i;
	unsigned int temp;

	ciphertext+=12;
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

#if ARCH_LITTLE_ENDIAN==1 || defined(SIMD_COEF_32)
		out[i]=temp;
#else
		out[i]=JOHNSWAP(temp);
#endif
	}
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
			case 3:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else
					goto bailout;
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
		} else if (*source && len < PLAINTEXT_LENGTH) {
			chh = *source;
			if (chh >= 0xC0) {
				unsigned int extraBytesToRead =
					opt_trailingBytesUTF8[chh & 0x3f];
				switch (extraBytesToRead) {
				case 3:
					++source;
					if (*source) {
						chl <<= 6;
						chl += *source;
					} else
						goto bailout;
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
	unsigned int *keybuffer = (unsigned int*)&saved_key[GETPOSW(0, index)];
	static UTF16 key[PLAINTEXT_LENGTH + 1 + 1]; // if only +1 we 'can' overflow.  Not sure why, but ASan found it.
	unsigned int md5_size=0;
	unsigned int i=0;

	for (; md5_size < PLAINTEXT_LENGTH; i += SIMD_COEF_32, md5_size++)
	{
		key[md5_size] = keybuffer[i];
		key[md5_size+1] = keybuffer[i] >> 16;
		if (key[md5_size] == 0x80 && key[md5_size+1] == 0) {
			key[md5_size] = 0;
			break;
		}
		++md5_size;
		if (key[md5_size] == 0x80 && ((keybuffer[i+SIMD_COEF_32]&0xFFFF) == 0 || md5_size == PLAINTEXT_LENGTH)) {
			key[md5_size] = 0;
			break;
		}
	}
#if !ARCH_LITTLE_ENDIAN
	// NOTE, we really should add utf16be_to_enc(key) to unicode.[ch] (and the
	// other 7 or so required functions. currently unicode.c ONLY handles
	// UTF-16LE, but we are left with UTF-16BE due to key loading.
	alter_endianity_w16(key, md5_size<<1);
#endif
	return (char*)utf16_to_enc(key);
#else
	return (char*)utf16_to_enc(saved_key);
#endif
}

static int cmp_all(void *binary, int count) {
#ifdef SIMD_COEF_32
	unsigned int x, y;

	for (y = 0 ; y < SIMD_PARA_MD5*BLOCK_LOOPS; y++) {
		for (x = 0; x < SIMD_COEF_32; x++) {
			if ( ((uint32_t*)binary)[0] == ((uint32_t*)crypt_key)[x+y*SIMD_COEF_32*4] )
				return 1;
		}
	}
	return 0;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	unsigned int x, y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;

	if ( ((uint32_t*)binary)[0] != ((uint32_t*)crypt_key)[x+y*SIMD_COEF_32*4] )
		return 0;
	if ( ((uint32_t*)binary)[1] != ((uint32_t*)crypt_key)[x+y*SIMD_COEF_32*4+SIMD_COEF_32] )
		return 0;
	if ( ((uint32_t*)binary)[2] != ((uint32_t*)crypt_key)[x+y*SIMD_COEF_32*4+2*SIMD_COEF_32] )
		return 0;
	if ( ((uint32_t*)binary)[3] != ((uint32_t*)crypt_key)[x+y*SIMD_COEF_32*4+3*SIMD_COEF_32] )
		return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
#if defined(SIMD_COEF_32)
#if (BLOCK_LOOPS > 1)
	int i;

	// This was an experiment. It's not used (unless you bump BLOCK_LOOPS),
	// cause it does not scale well. We would need to parallelize set_key()
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < BLOCK_LOOPS; i++)
		SIMDmd5body(&saved_key[i*NBKEYS*64], (unsigned int*)&crypt_key[i*NBKEYS*BINARY_SIZE], NULL, SSEi_MIXED_IN);
#else
	SIMDmd5body(saved_key, (unsigned int*)crypt_key, NULL, SSEi_MIXED_IN);
#endif
#else
	MD5_Init( &ctx );
	MD5_Update(&ctx, (unsigned char*)saved_key, saved_len);
	MD5_Final((unsigned char*) crypt_key, &ctx);
#endif
	return count;
}

#define COMMON_GET_HASH_SIMD32 4
#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

struct fmt_main fmt_rawmd5uthick = {
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
#if (BLOCK_LOOPS > 1) && defined(SSE_MD5_PARA)
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
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
		fmt_default_set_salt,
		set_key,
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

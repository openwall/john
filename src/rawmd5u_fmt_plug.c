/*
 * Thick raw-md5-unicode (come-back :)
 *
 * This  software is Copyright © 2011 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 */

#include <string.h>

#include "arch.h"

#ifdef MD5_SSE_PARA
#define MMX_COEF			4
#define NBKEYS				(MMX_COEF * MD5_SSE_PARA)
#elif MMX_COEF
#define NBKEYS				MMX_COEF
#endif
#include "sse-intrinsics.h"

#include "md5.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"
#include "memory.h"
#include "johnswap.h"

#define FORMAT_LABEL			"raw-md5u"
#define FORMAT_NAME			"md5(unicode($p))"

#define ALGORITHM_NAME			MD5_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE			16
#define SALT_SIZE			0

#ifdef MMX_COEF
#ifdef MD5_SSE_PARA
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
#else
static MD5_CTX ctx;
static int saved_key_length;
static UTF16 saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
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
		tests[1].ciphertext = "94a4e171de16580742c4d141e6607bf7";
		tests[1].plaintext = "\xE2\x82\xAC";	// Euro sign
		tests[2].ciphertext = "03c60810f0e54d16e826aca385d776c8";
		tests[2].plaintext = "\xE2\x82\xAC\xE2\x82\xAC";	// 2 x euro
		tests[3].ciphertext = "2d554433d7cde7ec8d16aaf126c3be6b";
		tests[3].plaintext = "\xE2\x82\xAC\xC3\xBC";	// euro and u-umlaut
		tests[4].ciphertext = "8007d9070b27db7b30433df2cd10abc1";
		tests[4].plaintext = "\xC3\xBC\xE2\x82\xAC";	// u-umlaut and euro
	} else {
		if (!options.ascii && !options.iso8859_1) {
			/* This avoids an if clause for every set_key */
			pFmt->methods.set_key = set_key_CP;
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
	static char out[32+12+1];

	if (!strncmp(ciphertext, "$dynamic_29$", 12))
		ciphertext += 12;

	strcpy(out, "$dynamic_29$");

	memcpy(&out[12], ciphertext, 32);
	out[sizeof(out)-1] = 0;

	strlwr(&out[12]);

	return out;
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
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

static void *binary(char *ciphertext)
{
	static unsigned long out_[BINARY_SIZE/sizeof(unsigned long)];
	unsigned int *out = (unsigned int*)out_;
	unsigned int i;
	unsigned int temp;

	ciphertext+=12;
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
	return out;
}

// ISO-8859-1 to UCS-2, directly into vector key buffer
static void set_key(char *_key, int index)
{
#ifdef MMX_COEF
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
		keybuf_word += MMX_COEF;
	}
	*keybuf_word = 0x80;

key_cleaning:
	keybuf_word += MMX_COEF;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}

	((unsigned int *)saved_key)[14*MMX_COEF + (index&3) + (index>>2)*16*MMX_COEF] = len << 4;
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
#endif
}

// Legacy codepage to UCS-2, directly into vector key buffer
static void set_key_CP(char *_key, int index)
{
#ifdef MMX_COEF
	const unsigned char *key = (unsigned char*)_key;
	unsigned int *keybuf_word = buf_ptr[index];
	unsigned int len;

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

	((unsigned int *)saved_key)[14*MMX_COEF + (index&3) + (index>>2)*16*MMX_COEF] = len << 4;
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

	((unsigned int *)saved_key)[14*MMX_COEF + (index&3) + (index>>2)*16*MMX_COEF] = len << 4;
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
	unsigned int md5_size=0;
	unsigned int i=0;

	for(; md5_size < PLAINTEXT_LENGTH; i += MMX_COEF, md5_size++)
	{
		key[md5_size] = keybuffer[i];
		key[md5_size+1] = keybuffer[i] >> 16;
		if (key[md5_size] == 0x80 && key[md5_size+1] == 0) {
			key[md5_size] = 0;
			break;
		}
		++md5_size;
		if (key[md5_size] == 0x80 && ((keybuffer[i+MMX_COEF]&0xFFFF) == 0 || md5_size == PLAINTEXT_LENGTH)) {
			key[md5_size] = 0;
			break;
		}
	}
	return (char*)utf16_to_enc(key);
#else
#if ARCH_LITTLE_ENDIAN
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
	return (char*)utf16_to_enc(Tmp);
#endif
#endif
}

static int cmp_all(void *binary, int count) {
#ifdef MMX_COEF
	unsigned int x,y=0;

#if MD5_SSE_PARA
	for(;y<MD5_SSE_PARA*BLOCK_LOOPS;y++)
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
#if defined(MD5_SSE_PARA)
#if (BLOCK_LOOPS > 1)
	int i;
	// This was an experiment. It's not used (unless you bump BLOCK_LOOPS),
	// cause it does not scale well. We would need to parallelize set_key()
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < BLOCK_LOOPS; i++)
		SSEmd5body(&saved_key[i*NBKEYS*64], (unsigned int*)&crypt_key[i*NBKEYS*BINARY_SIZE], 1);
#else
	SSEmd5body(saved_key, (unsigned int*)crypt_key, 1);
#endif
#elif defined(MMX_COEF)
	mdfivemmx_nosizeupdate(crypt_key, saved_key, 1);
#else
	MD5_Init( &ctx );
	MD5_Update(&ctx, (unsigned char*)saved_key, saved_key_length);
	MD5_Final((unsigned char*) crypt_key, &ctx);
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

struct fmt_main fmt_rawmd5uthick = {
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
#if (BLOCK_LOOPS > 1) && defined(SSE_MD5_PARA)
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8,
		tests
	}, {
		init,
		fmt_default_prepare,
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

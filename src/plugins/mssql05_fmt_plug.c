/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Modified by Mathieu Perrin (mathieu at tpfh.org) 09/06
 * Microsoft MS-SQL05 password cracker
 *
 * UTF-8 support and use of intrinsics by magnum 2011, same terms as above
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_mssql05;
#elif FMT_REGISTERS_H
john_register_one(&fmt_mssql05);
#else

#include <string.h>

#include "arch.h"

//#undef SIMD_COEF_32
//#undef SIMD_PARA_SHA1

/*
 * Only effective for SIMD.
 * Undef to disable reversing steps for benchmarking.
 */
#define REVERSE_STEPS

#ifdef SIMD_COEF_32
#define NBKEYS	(SIMD_COEF_32 * SIMD_PARA_SHA1)
#endif
#include "simd-intrinsics.h"

#include "misc.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"
#include "sha.h"
#include "johnswap.h"

#define FORMAT_LABEL			"mssql05"
#define FORMAT_NAME			"MS SQL 2005"

#define ALGORITHM_NAME			"SHA1 " SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define PLAINTEXT_LENGTH		25
#define CIPHERTEXT_LENGTH		54

#define DIGEST_SIZE			20
#define BINARY_SIZE			DIGEST_SIZE
#define BINARY_ALIGN			4
#define SALT_SIZE			4
#define SALT_ALIGN			4

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 ) //for endianity conversion
#else
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 ) //for endianity conversion
#endif

#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#ifndef SHA_BUF_SIZ
#define SHA_BUF_SIZ             16
#endif

static struct fmt_tests tests[] = {
	{"0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908", "toto"},
	{"0x01004086CEB60ED526885801C23B366965586A43D3DEAC6DD3FD", "titi"},
	{"0x01007437483404C339C3DED1D1A462455533315842ECF3713676", "thisISALongPass"},
	{"0x010071746753050B885462C63CF4F015F084AD64DB4658C1D7D6", "1"},
	{"0x01006F50386B49746C0A24A0F66AA7B6DF80604A79548A6C2F3A", "12"},
	{"0x01006136377289E986FD9970CDB1BB5F50F3F3F15F7263004E3E", "123"},
	{"0x0100304854648C5B02A71C4B2D1213728E635ED3DC5E6677F832", "1234"},
	{"0x0100516E6B47CA2EDB9AC27CBC8D087D28785B3F40BE9835366A", "12345"},
	{"0x0100736A684B3C211B4621996FD7F0AA2A49F0A94B751C45AE01", "123456"},
	{"0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254", "foo",    {"User1"} },
	{"0x01000508513EADDF6DB7DDD270CCA288BF097F2FF69CC2DB74FBB9644D6901764F999BAB9ECB80DE578D92E3F80D", "bar",    {"User2"} },
	{"0x01008408C523CF06DCB237835D701C165E68F9460580132E28ED8BC558D22CEDF8801F4503468A80F9C52A12C0A3", "canard", {"User3"} },
	{"0x0100BF088517935FC9183FE39FDEC77539FD5CB52BA5F5761881E5B9638641A79DBF0F1501647EC941F3355440A2", "lapin",  {"User4"} },
	{NULL}
};

static unsigned char cursalt[SALT_SIZE];

#ifdef SIMD_COEF_32
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key mssql05_saved_key
#define crypt_key mssql05_crypt_key
JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char saved_key[SHA_BUF_SIZ*4*NBKEYS];
JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char crypt_key[DIGEST_SIZE*NBKEYS];

#else

static unsigned char *saved_key;
static uint32_t crypt_key[DIGEST_SIZE / 4];
static int key_length;

#endif

static int valid(char *ciphertext, struct fmt_main *self)
{
	int i;

	if (strncmp(ciphertext, "0x0100", 6))
		return 0;
	if (strnlen(ciphertext, CIPHERTEXT_LENGTH + 1) != CIPHERTEXT_LENGTH)
		return 0;
	for (i = 6; i < CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					//(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f')) ||
					(('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

// Handle full hashes (old and new in one long string) as well. This means the
// [other] mssql format should be registered before this one. If there are
// old-style hashes we should crack them first using that format, then run
// mssql05 with -ru:nt just like LM -> NT format
static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	int len = strnlen(split_fields[1], 95);

	if (len == CIPHERTEXT_LENGTH)
		return split_fields[1];

	if (!strncmp(split_fields[1], "0x0100", 6) && len == 94) {
		char cp[CIPHERTEXT_LENGTH + 1];

		strnzcpy(cp, split_fields[1], CIPHERTEXT_LENGTH + 1);

		if (valid(cp,self)) {
			char *cp2 = str_alloc_copy(cp);
			return cp2;
		}
	}
	return split_fields[1];
}

static void set_salt(void *salt)
{
	memcpy(cursalt, salt, SALT_SIZE);
}

static void *get_salt(char * ciphertext)
{
	static unsigned char *out2;
	int l;

	if (!out2) out2 = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

	for (l=0;l<SALT_SIZE;l++)
	{
		out2[l] = atoi16[ARCH_INDEX(ciphertext[l*2+6])]*16
			+ atoi16[ARCH_INDEX(ciphertext[l*2+7])];
	}

	return out2;
}

static void set_key_CP(char *_key, int index);
static void set_key_utf8(char *_key, int index);

static void init(struct fmt_main *self)
{
#ifdef SIMD_COEF_32
	memset(saved_key, 0, sizeof(saved_key));
#else
	saved_key = mem_calloc(1, PLAINTEXT_LENGTH * 2 + 1 + SALT_SIZE);
#endif
	if (options.target_enc == UTF_8) {
		self->methods.set_key = set_key_utf8;
		self->params.plaintext_length = MIN(125, PLAINTEXT_LENGTH * 3);
	}
	else if (options.target_enc != ISO_8859_1 && options.target_enc != ENC_RAW) {
		self->methods.set_key = set_key_CP;
	}
}

static void done(void)
{
#ifndef SIMD_COEF_32
	MEM_FREE(saved_key);
#endif
}

// ISO-8859-1 to UCS-2, directly into vector key buffer
static void set_key(char *_key, int index)
{
#ifdef SIMD_COEF_32
	const unsigned char *key = (unsigned char*)_key;
	unsigned int *keybuf_word = &((unsigned int*)saved_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32];
	unsigned int len, temp2;

	len = SALT_SIZE >> 1;
	while((temp2 = *key++)) {
		unsigned int temp;
		if ((temp = *key++))
		{
			// works for both BE and LE! setting only 2 bytes and 2 nulls
			*keybuf_word = (temp2 << 24) | (temp<<8);
		}
		else
		{
			// works for both BE and LE! setting only 1 byte and 3 nulls
			*keybuf_word = (temp2 << 24);
			keybuf_word += SIMD_COEF_32;
			*keybuf_word = (0x80 << 8);
			len++;
			goto key_cleaning;
		}
		len += 2;
		keybuf_word += SIMD_COEF_32;
	}
	keybuf_word += SIMD_COEF_32;
	*keybuf_word = (0x80U << 24);

key_cleaning:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}

	((unsigned int *)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = len << 4;
#else
	UTF8 *s = (UTF8*)_key;
	UTF16 *d = (UTF16*)saved_key;
	for (key_length = 0; s[key_length]; key_length++)
#if ARCH_LITTLE_ENDIAN
		d[key_length] = s[key_length];
#else
		d[key_length] = s[key_length] << 8;
#endif
	d[key_length] = 0;
	key_length <<= 1;
#endif
}

// Legacy codepage to UCS-2, directly into vector key buffer
static void set_key_CP(char *_key, int index)
{
#ifdef SIMD_COEF_32
	const unsigned char *key = (unsigned char*)_key;
	unsigned int *keybuf_word = &((unsigned int*)saved_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32];
	unsigned int len, temp2;

	len = SALT_SIZE >> 1;
	while((temp2 = *key++)) {
		unsigned int temp;
		temp2 = CP_to_Unicode[temp2];
		if ((temp = *key++))
		{
			temp = CP_to_Unicode[temp];
			*keybuf_word = JOHNSWAP((temp << 16) | temp2);
		}
		else
		{
			*keybuf_word = JOHNSWAP(temp2);
			keybuf_word += SIMD_COEF_32;
			*keybuf_word = (0x80 << 8);
			len++;
			goto key_cleaning_enc;
		}
		len += 2;
		keybuf_word += SIMD_COEF_32;
	}
	keybuf_word += SIMD_COEF_32;
	*keybuf_word = (0x80U << 24);

key_cleaning_enc:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}

	((unsigned int *)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = len << 4;
#else
	key_length = enc_to_utf16((UTF16*)saved_key, PLAINTEXT_LENGTH,
	                          (unsigned char*)_key, strlen(_key));
	if (key_length < 0)
		key_length = strlen16((UTF16*)saved_key);
	key_length <<= 1;
#endif
}

// UTF-8 to UCS-2, directly into vector key buffer
static void set_key_utf8(char *_key, int index)
{
#ifdef SIMD_COEF_32
	const UTF8 *source = (UTF8*)_key;
	unsigned int *keybuf_word = &((unsigned int*)saved_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32];
	UTF32 chl, chh = 0x80;
	unsigned int len;

	len = SALT_SIZE >> 1;
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
			if (len == PLAINTEXT_LENGTH + (SALT_SIZE >> 1)) {
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
		} else if (*source && len < PLAINTEXT_LENGTH + (SALT_SIZE >> 1)) {
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
			chh = 0xffff;
			*keybuf_word = JOHNSWAP((chh << 16) | chl);
			keybuf_word += SIMD_COEF_32;
			break;
		}
		*keybuf_word = JOHNSWAP((chh << 16) | chl);
		keybuf_word += SIMD_COEF_32;
	}
	if (chh != 0xffff || len == SALT_SIZE >> 1) {
		*keybuf_word = 0xffffffff;
		keybuf_word += SIMD_COEF_32;
		*keybuf_word = (0x80U << 24);
	} else {
		*keybuf_word = 0xffff8000;
	}
	keybuf_word += SIMD_COEF_32;

bailout:
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}

	((unsigned int *)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = len << 4;
#else
	key_length = utf8_to_utf16((UTF16*)saved_key, PLAINTEXT_LENGTH,
	                           (unsigned char*)_key, strlen(_key));
	if (key_length < 0)
		key_length = strlen16((UTF16*)saved_key);

	key_length <<= 1;
#endif
}

static char *get_key(int index) {
#ifdef SIMD_COEF_32
	static UTF16 out[PLAINTEXT_LENGTH + 1];
	unsigned int i,s;

	s = ((((unsigned int *)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] >> 3) - SALT_SIZE) >> 1;
	for (i=0;i<s;i++) {
		out[i] = saved_key[GETPOS(i<<1, index)] |
			(saved_key[GETPOS((i<<1) + 1, index)] << 8);
	}
	out[i] = 0;
#if defined (SIMD_COEF_32) && !ARCH_LITTLE_ENDIAN
	alter_endianity_w16(out, s<<1);
#endif
	return (char*)utf16_to_enc(out);
#else
	((UTF16*)saved_key)[key_length>>1] = 0;
	return (char*)utf16_to_enc((UTF16*)saved_key);
#endif
}

#ifndef REVERSE_STEPS
#undef SSEi_REVERSE_STEPS
#define SSEi_REVERSE_STEPS SSEi_NO_OP
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
#ifdef SIMD_COEF_32
	unsigned i, index;

	for (index = 0; index < count; ++index)
	{
		unsigned len = ((((unsigned int *)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32]) >> 3) - SALT_SIZE;
		for (i=0;i<SALT_SIZE;i++)
			saved_key[GETPOS((len+i), index)] = cursalt[i];
	}
	SIMDSHA1body(saved_key, (unsigned int *)crypt_key, NULL, SSEi_REVERSE_STEPS | SSEi_MIXED_IN);
#else
	SHA_CTX ctx;
	memcpy(saved_key+key_length, cursalt, SALT_SIZE);
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, saved_key, key_length+SALT_SIZE );
	SHA1_Final( (unsigned char *) crypt_key, &ctx);
#endif

	return count;
}

static void *get_binary(char *ciphertext)
{
	static uint32_t out[SHA_BUF_SIZ];
	char *realcipher = (char*)out;
	int i;

	ciphertext += 14;

	for (i=0;i<DIGEST_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}

#ifdef SIMD_COEF_32
#if ARCH_LITTLE_ENDIAN==1
	alter_endianity(realcipher, DIGEST_SIZE);
#endif
#ifdef REVERSE_STEPS
	sha1_reverse(out);
#endif
#endif

	return (void*)realcipher;
}

static int cmp_all(void *binary, int count) {
	int index;

	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_32
        if (((uint32_t*) binary)[4] == ((uint32_t*)crypt_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32 + 4*SIMD_COEF_32])
#else
		if ( ((uint32_t*)binary)[0] == crypt_key[0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	return (((uint32_t*) binary)[4] == ((uint32_t*)crypt_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32 + 4*SIMD_COEF_32]);
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
#if SIMD_COEF_32
	uint32_t crypt_key[SHA_BUF_SIZ];
	UTF8 *key = (UTF8*)get_key(index);
	UTF16 u16[PLAINTEXT_LENGTH+1];
	int len = enc_to_utf16(u16, PLAINTEXT_LENGTH, key, strlen((char*)key));
	SHA_CTX ctx;

	if (len < 0)
		len = strlen16(u16);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, u16, 2 * len);
	SHA1_Update(&ctx, cursalt, SALT_SIZE);
	SHA1_Final((void*)crypt_key, &ctx);

#if ARCH_LITTLE_ENDIAN==1
	alter_endianity(crypt_key, DIGEST_SIZE);
#endif
#ifdef REVERSE_STEPS
	sha1_reverse(crypt_key);
#endif
	return !memcmp(get_binary(source), crypt_key, DIGEST_SIZE);
#else
	return 1;
#endif
}

#ifdef SIMD_COEF_32
#define KEY_OFF (((unsigned int)index/SIMD_COEF_32)*SIMD_COEF_32*5+(index&(SIMD_COEF_32-1))+4*SIMD_COEF_32)
static int get_hash_0(int index) { return ((uint32_t*)crypt_key)[KEY_OFF] & PH_MASK_0; }
static int get_hash_1(int index) { return ((uint32_t*)crypt_key)[KEY_OFF] & PH_MASK_1; }
static int get_hash_2(int index) { return ((uint32_t*)crypt_key)[KEY_OFF] & PH_MASK_2; }
static int get_hash_3(int index) { return ((uint32_t*)crypt_key)[KEY_OFF] & PH_MASK_3; }
static int get_hash_4(int index) { return ((uint32_t*)crypt_key)[KEY_OFF] & PH_MASK_4; }
static int get_hash_5(int index) { return ((uint32_t*)crypt_key)[KEY_OFF] & PH_MASK_5; }
static int get_hash_6(int index) { return ((uint32_t*)crypt_key)[KEY_OFF] & PH_MASK_6; }
#else
static int get_hash_0(int index) { return ((uint32_t*)crypt_key)[4] & PH_MASK_0; }
static int get_hash_1(int index) { return ((uint32_t*)crypt_key)[4] & PH_MASK_1; }
static int get_hash_2(int index) { return ((uint32_t*)crypt_key)[4] & PH_MASK_2; }
static int get_hash_3(int index) { return ((uint32_t*)crypt_key)[4] & PH_MASK_3; }
static int get_hash_4(int index) { return ((uint32_t*)crypt_key)[4] & PH_MASK_4; }
static int get_hash_5(int index) { return ((uint32_t*)crypt_key)[4] & PH_MASK_5; }
static int get_hash_6(int index) { return ((uint32_t*)crypt_key)[4] & PH_MASK_6; }
#endif

static int binary_hash_0(void *binary) { return ((uint32_t*)binary)[4] & PH_MASK_0; }
static int binary_hash_1(void *binary) { return ((uint32_t*)binary)[4] & PH_MASK_1; }
static int binary_hash_2(void *binary) { return ((uint32_t*)binary)[4] & PH_MASK_2; }
static int binary_hash_3(void *binary) { return ((uint32_t*)binary)[4] & PH_MASK_3; }
static int binary_hash_4(void *binary) { return ((uint32_t*)binary)[4] & PH_MASK_4; }
static int binary_hash_5(void *binary) { return ((uint32_t*)binary)[4] & PH_MASK_5; }
static int binary_hash_6(void *binary) { return ((uint32_t*)binary)[4] & PH_MASK_6; }

static int salt_hash(void *salt)
{
	// This gave much better distribution on a huge set I analysed
	return (*((uint32_t*)salt) >> 8) & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_mssql05 = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC,
		{ NULL },
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		salt_hash,
		NULL,
		set_salt,
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

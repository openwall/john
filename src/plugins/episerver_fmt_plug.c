/*
 * *New* EPiServer cracker patch for JtR. Hacked together during Summer of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC. Based on sample
 * code by hashcat's atom.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Obtaining hashes from EPiServer 6.x:
 *
 * sqlcmd -L
 * sqlcmd -S <server> -U sa -P <password> *
 * 1> SELECT name from sys.databases
 * 2> go
 * 1> use <database name>
 * 2> select Email, PasswordFormat, PasswordSalt, Password from aspnet_Membership
 * 3> go
 *
 * JtR Input Format:
 *
 * user:$episerver$*version*base64(salt)*base64(hash)
 *
 * Where,
 *
 * version == 0, for EPiServer 6.x standard config / .NET <= 3.5 SHA1 hash/salt format.
 * 		 hash =  sha1(salt | utf16bytes(password)), PasswordFormat == 1 *
 *
 * version == 1, EPiServer 6.x + .NET >= 4.x SHA256 hash/salt format,
 * 		 PasswordFormat == ?
 *
 * Improved performance, JimF, July 2012.
 * Full Unicode support, magnum, August 2012.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_episerver;
#elif FMT_REGISTERS_H
john_register_one(&fmt_episerver);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "sha.h"
#include "sha2.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64_convert.h"
#include "unicode.h"

#define FORMAT_LABEL            "EPiServer"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$episerver$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define BINARY_SIZE             32 /* larger of the two */
#define BINARY_ALIGN            4
#define SALT_SIZE               sizeof(struct custom_salt)
#define EFFECTIVE_SALT_SIZE     16
#define SALT_ALIGN              4

#ifdef SIMD_COEF_32
#include "simd-intrinsics.h"
#include "johnswap.h"

#define NBKEYS_SHA1             (SIMD_COEF_32 * SIMD_PARA_SHA1)
#define NBKEYS_SHA256           (SIMD_COEF_32 * SIMD_PARA_SHA256)
#define NBKEYS                  (SIMD_COEF_32 * SIMD_PARA_SHA1 * SIMD_PARA_SHA256)

#define HASH_IDX_IN             (((unsigned int)index&(SIMD_COEF_32-1))+(unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32)
#define HASH_IDX_SHA1           (((unsigned int)index&(SIMD_COEF_32-1))+(unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32)
#define HASH_IDX_SHA256         (((unsigned int)index&(SIMD_COEF_32-1))+(unsigned int)index/SIMD_COEF_32*8*SIMD_COEF_32)
#define HASH_IDX_OUT            (cur_salt->version == 0 ? HASH_IDX_SHA1 : HASH_IDX_SHA256)

#if ARCH_LITTLE_ENDIAN
#define GETPOS(i, index)        ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32 ) //for endianness conversion
#else
#define GETPOS(i, index)        ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32 ) //for endianness conversion
#endif

#define ALGORITHM_NAME          "SHA1/SHA256 " SHA256_ALGORITHM_NAME
#define PLAINTEXT_LENGTH        19 // (64 - 9 - 16)/2
#define MIN_KEYS_PER_CRYPT      NBKEYS
#ifdef _OPENMP
#define MAX_KEYS_PER_CRYPT      (NBKEYS * 256)
#else
#define MAX_KEYS_PER_CRYPT      (NBKEYS * 2)
#endif
#else
#define ALGORITHM_NAME          "SHA1/SHA256 32/" ARCH_BITS_STR
#define PLAINTEXT_LENGTH        32
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1024
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               2 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests episerver_tests[] = {
	{"$episerver$*0*fGJ2wn/5WlzqQoDeCA2kXA==*UQgnz/vPWap9UeD8Dhaw3h/fgFA=", "testPassword"},
	{"$episerver$*0*fGJ2wn/5WlzqQoDeCA2kXA==*uiP1YrZlVcHESbfsRt/wljwNeYU=", "sss"},
	{"$episerver$*0*fGJ2wn/5WlzqQoDeCA2kXA==*dxTlKqnxaVHs0210VcX+48QDonA=", "notused"},

	// hashes from pass_gen.pl, including some V1 data
	{"$episerver$*0*OHdOb002Z1J6ZFhlRHRzbw==*74l+VCC9xkGP27sNLPLZLRI/O5A", "test1"},
	{"$episerver$*0*THk5ZHhYNFdQUDV1Y0hScg==*ik+FVrPkEs6LfJU88xl5oBRoZjY", ""},
	{"$episerver$*1*aHIza2pUY0ZkR2dqQnJrNQ==*1KPAZriqakiNvE6ML6xkUzS11QPREziCvYkJc4UtjWs","test1"},
	{"$episerver$*1*RUZzRmNja0c5NkN0aDlMVw==*nh46rc4vkFIL0qGUrKTPuPWO6wqoESSeAxUNccEOe28","thatsworking"},
	{"$episerver$*1*cW9DdnVVUnFwM2FobFc4dg==*Zr/nekpDxU5gjt+fzTSqm0j/twZySBBW44Csoai2Fug","test3"},
	{"$episerver$*0*b0lvUnlWbkVlSFJQTFBMeg==*K7NAoB/wZfZjsG4DuMkNqKYwfTs", "123456789"},
	{NULL}
};

#ifdef SIMD_COEF_32
static uint32_t *saved_key;
static uint32_t *crypt_out;
#else
static char (*saved_key)[3 * PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];
#endif

static struct custom_salt {
	int version;
	unsigned char esalt[18 + 1]; /* base64 decoding, 24 / 4 * 3 = 18 */
} *cur_salt;

#ifdef SIMD_COEF_32
static int mkpc;
static void episerver_set_key_utf8(char *_key, int index);
static void episerver_set_key_CP(char *_key, int index);
#endif

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

#ifdef SIMD_COEF_32
	mkpc = self->params.max_keys_per_crypt;

	saved_key = mem_calloc_align(self->params.max_keys_per_crypt*SHA_BUF_SIZ,
	                             sizeof(*saved_key), MEM_ALIGN_SIMD);
	crypt_out = mem_calloc_align(self->params.max_keys_per_crypt*BINARY_SIZE/4,
	                             sizeof(*crypt_out), MEM_ALIGN_SIMD);
#else
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
#endif

#ifdef SIMD_COEF_32
	if (options.target_enc == UTF_8) {
		self->methods.set_key = episerver_set_key_utf8;
		self->params.plaintext_length = PLAINTEXT_LENGTH * 3;
	}
	else if (options.target_enc != ISO_8859_1 && options.target_enc != ENC_RAW)
		self->methods.set_key = episerver_set_key_CP;
#else
	if (options.target_enc == UTF_8)
		self->params.plaintext_length = PLAINTEXT_LENGTH * 3;
#endif
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ptr, *ctcopy, *keeptr;
	size_t res;
	char tmp[128];

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	if (!(ctcopy = xstrdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;	/* skip leading '$episerver$*' */
	if (strlen(ciphertext) > 255)
		goto error;
	if (!(ptr = strtokm(ctcopy, "*")))
		goto error;
	/* check version, must be '0' or '1' */
	if (*ptr != '0' && *ptr != '1')
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* salt */
		goto error;
	if (strlen(ptr) > 24)
		goto error;
	res = base64_valid_length(ptr, e_b64_mime, flg_Base64_MIME_TRAIL_EQ_CNT, 0);
	if (res < strlen(ptr))
		goto error;
	res = base64_convert(ptr, e_b64_mime, strlen(ptr), tmp, e_b64_raw,
                             sizeof(tmp), flg_Base64_MIME_TRAIL_EQ, 0);
	if (res != 16) /* decoded salt size should be 16 bytes */
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* hash */
		goto error;
	if (strlen(ptr) > 44)
		goto error;
	res = base64_valid_length(ptr, e_b64_mime, flg_Base64_MIME_TRAIL_EQ_CNT, 0);
	if (res < strlen(ptr))
		goto error;
	res = base64_convert(ptr, e_b64_mime, strlen(ptr), tmp, e_b64_raw,
                             sizeof(tmp), flg_Base64_MIME_TRAIL_EQ, 0);
	if (res != 20 && res != 32) /* SHA1 or SHA256 output size */
		goto error;
	if ((ptr = strtokm(NULL, "*"))) /* end */
		goto error;
	MEM_FREE(keeptr);
	return 1;

error:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char _ctcopy[256], *ctcopy=_ctcopy;
	char *p;
	memset(&cs, 0, sizeof(cs));
	strncpy(ctcopy, ciphertext, 255);
	ctcopy[255] = 0;
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$episerver$*" */
	p = strtokm(ctcopy, "*");
	cs.version = atoi(p);
	p = strtokm(NULL, "*");
	base64_convert(p, e_b64_mime, strlen(p), (char*)cs.esalt, e_b64_raw, sizeof(cs.esalt), flg_Base64_NO_FLAGS, 0);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;

	memset(buf.c, 0, sizeof(buf.c));
	p = strrchr(ciphertext, '*') + 1;
	base64_convert(p, e_b64_mime, strlen(p), (char*)out, e_b64_raw, sizeof(buf.c), flg_Base64_DONOT_NULL_TERMINATE, 0);
#if defined(SIMD_COEF_32) && ARCH_LITTLE_ENDIAN
	alter_endianity(out, BINARY_SIZE);
#endif
	return out;
}

// can not use common-get-hash.h since the HASH_IDX_OUT will vary between 5 and
// 8 limbs based upon the current salt.  No way for pre-processor to handle that.
// the only way to use common-get-hash.h would be to make a format for sha1, and
// a 2nd for sha256.  But since we already have a singlular format, we will simply
// not use the common code here.
#ifdef SIMD_COEF_32
static int get_hash_0 (int index) { return crypt_out[HASH_IDX_OUT] & PH_MASK_0; }
static int get_hash_1 (int index) { return crypt_out[HASH_IDX_OUT] & PH_MASK_1; }
static int get_hash_2 (int index) { return crypt_out[HASH_IDX_OUT] & PH_MASK_2; }
static int get_hash_3 (int index) { return crypt_out[HASH_IDX_OUT] & PH_MASK_3; }
static int get_hash_4 (int index) { return crypt_out[HASH_IDX_OUT] & PH_MASK_4; }
static int get_hash_5 (int index) { return crypt_out[HASH_IDX_OUT] & PH_MASK_5; }
static int get_hash_6 (int index) { return crypt_out[HASH_IDX_OUT] & PH_MASK_6; }
#else
static int get_hash_0(int index) { return crypt_out[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_out[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_out[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_out[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_out[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_out[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_out[index][0] & PH_MASK_6; }
#endif

static void set_salt(void *salt)
{
#ifdef SIMD_COEF_32
	int index, j;
	cur_salt = (struct custom_salt *)salt;
	for (index = 0; index < mkpc; ++index)
		for (j = 0; j < EFFECTIVE_SALT_SIZE; ++j) // copy the salt to vector buffer
			((unsigned char*)saved_key)[GETPOS(j, index)] = ((unsigned char*)cur_salt->esalt)[j];
#else
	cur_salt = (struct custom_salt *)salt;
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
#ifdef SIMD_COEF_32
	for (index = 0; index < count; index += (cur_salt->version == 0 ? NBKEYS_SHA1 : NBKEYS_SHA256)) {
		uint32_t *in = &saved_key[HASH_IDX_IN];
		uint32_t *out = &crypt_out[HASH_IDX_OUT];

		if (cur_salt->version == 0)
			SIMDSHA1body(in, out, NULL, SSEi_MIXED_IN);
		else //if (cur_salt->version == 1)
			SIMDSHA256body(in, out, NULL, SSEi_MIXED_IN);
	}
#else
	for (index = 0; index < count; index++) {
		unsigned char passwordBuf[PLAINTEXT_LENGTH*2+2];
		int len;
		len = enc_to_utf16((UTF16*)passwordBuf, PLAINTEXT_LENGTH,
		                   (UTF8*)saved_key[index], strlen(saved_key[index]));
		if (len < 0)
			len = strlen16((UTF16*)passwordBuf);
		len <<= 1;
		if (cur_salt->version == 0) {
			SHA_CTX ctx;
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, cur_salt->esalt, EFFECTIVE_SALT_SIZE);
			SHA1_Update(&ctx, passwordBuf, len);
			SHA1_Final((unsigned char*)crypt_out[index], &ctx);
		}
		else /*if (cur_salt->version == 1)*/ {
			SHA256_CTX ctx;
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, cur_salt->esalt, EFFECTIVE_SALT_SIZE);
			SHA256_Update(&ctx, passwordBuf, len);
			SHA256_Final((unsigned char*)crypt_out[index], &ctx);
		}
	}
#endif
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++) {
#ifdef SIMD_COEF_32
		if (*((uint32_t*)binary) == crypt_out[HASH_IDX_OUT])
#else
		if (*((uint32_t*)binary) == crypt_out[index][0])
#endif
			return 1;
	}

	return 0;
}

static int cmp_one(void *binary, int index)
{
#if SIMD_COEF_32
	return *((uint32_t*)binary) == crypt_out[HASH_IDX_OUT];
#else
	return (*((uint32_t*)binary) == crypt_out[index][0]);
#endif
}

static int cmp_exact(char *source, int index)
{
	void *binary = get_binary(source);
#if SIMD_COEF_32
	uint32_t out[BINARY_SIZE/4];
	int i;
	for (i = 0; i < BINARY_SIZE/4; ++i)
		out[i] = crypt_out[HASH_IDX_OUT + i*SIMD_COEF_32];

	if (cur_salt->version == 0)
		return !memcmp(binary, out, 20);
	else
		return !memcmp(binary, out, BINARY_SIZE);
#else
	if (cur_salt->version == 0)
		return !memcmp(binary, crypt_out[index], 20);
	else
		return !memcmp(binary, crypt_out[index], BINARY_SIZE);
#endif
}

static void episerver_set_key(char *_key, int index)
{
#ifdef SIMD_COEF_32
	unsigned char *key = (unsigned char*)_key;
	uint32_t *keybuf = &saved_key[HASH_IDX_IN];
	uint32_t *keybuf_word = keybuf + 4*SIMD_COEF_32; // skip over the salt
	unsigned int len, temp2;

	len = EFFECTIVE_SALT_SIZE >> 1;
	while((temp2 = *key++)) {
		unsigned int temp;
		if ((temp = *key++))
		{
#if ARCH_LITTLE_ENDIAN
			*keybuf_word = JOHNSWAP((temp << 16) | temp2);
#else
			*keybuf_word = (temp2 << 24) | (temp<<8);
#endif
		}
		else
		{
#if ARCH_LITTLE_ENDIAN
			*keybuf_word = JOHNSWAP((0x80 << 16) | temp2);
#else
			*keybuf_word = (temp2 << 24) | 0x8000;
#endif
			len++;
			goto key_cleaning;
		}
		len += 2;
		keybuf_word += SIMD_COEF_32;
	}
	*keybuf_word = (0x80U << 24);

key_cleaning:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}
	keybuf[15*SIMD_COEF_32] = len << 4;
#else
	strcpy(saved_key[index], _key);
#endif
}

#ifdef SIMD_COEF_32
static void episerver_set_key_CP(char *_key, int index)
{
	unsigned char *key = (unsigned char*)_key;
	uint32_t *keybuf = &saved_key[HASH_IDX_IN];
	uint32_t *keybuf_word = keybuf + 4*SIMD_COEF_32; // skip over the salt
	unsigned int len, temp2;

	len = EFFECTIVE_SALT_SIZE >> 1;
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
			*keybuf_word = JOHNSWAP((0x80 << 16) | temp2);
			len++;
			goto key_cleaning;
		}
		len += 2;
		keybuf_word += SIMD_COEF_32;
	}
	*keybuf_word = (0x80U << 24);

key_cleaning:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}
	keybuf[15*SIMD_COEF_32] = len << 4;
}
#endif

#ifdef SIMD_COEF_32
static void episerver_set_key_utf8(char *_key, int index)
{
	const UTF8 *source = (UTF8*)_key;
	uint32_t *keybuf = &saved_key[HASH_IDX_IN];
	uint32_t *keybuf_word = keybuf + 4*SIMD_COEF_32; // skip over the salt
	UTF32 chl, chh = 0x80;
	unsigned int len;

	len = EFFECTIVE_SALT_SIZE >> 1;
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
			if (len == PLAINTEXT_LENGTH + (EFFECTIVE_SALT_SIZE>>1)) {
				chh = 0x80;
				*keybuf_word = JOHNSWAP((chh << 16) | chl);
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
		} else if (*source && len < PLAINTEXT_LENGTH + (EFFECTIVE_SALT_SIZE>>1)) {
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
			*keybuf_word = JOHNSWAP((chh << 16) | chl);
			keybuf_word += SIMD_COEF_32;
			break;
		}
		*keybuf_word = JOHNSWAP((chh << 16) | chl);
		keybuf_word += SIMD_COEF_32;
	}
	if (chh != 0x80 || len == (EFFECTIVE_SALT_SIZE>>1)) {
		*keybuf_word = (0x80U << 24);
		keybuf_word += SIMD_COEF_32;
	}

bailout:
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}
	keybuf[15*SIMD_COEF_32] = len << 4;
}
#endif

static char *get_key(int index)
{
#ifdef SIMD_COEF_32
	static UTF16 out[PLAINTEXT_LENGTH + 1];
	unsigned int i,s;

	s = ((saved_key[HASH_IDX_IN + 15*SIMD_COEF_32] >> 3) - 16) >> 1;
	for (i = 0; i < s; i++)
		out[i] = ((unsigned char*)saved_key)[GETPOS(16 + (i<<1), index)] | (((unsigned char*)saved_key)[GETPOS(16 + (i<<1) + 1, index)] << 8);
	out[i] = 0;

#if defined (SIMD_COEF_32) && !ARCH_LITTLE_ENDIAN
	alter_endianity_w16(out, s<<1);
#endif
	return (char*)utf16_to_enc(out);
#else
	return saved_key[index];
#endif
}

/* report hash type: 1 SHA1, 2 SHA256 */
static unsigned int hash_type(void *salt)
{
	struct custom_salt *my_salt = salt;

	return (unsigned int) (1 + my_salt->version);
}
struct fmt_main fmt_episerver = {
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
		FMT_OMP | FMT_OMP_BAD | FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC,
		{
			"hash type [1:SHA1 2:SHA256]",
		},
		{ FORMAT_TAG },
		episerver_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			hash_type,
		},
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
		episerver_set_key,
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

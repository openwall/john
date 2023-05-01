/*
 * This software is Copyright (c) 2004 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * UTF-8 support and use of intrinsics by magnum 2011, same terms as above
 *
 * microsoft MS SQL cracker
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_mssql;
#elif FMT_REGISTERS_H
john_register_one(&fmt_mssql);
#else

#include <string.h>

#include "../arch.h"

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
#include "../simd-intrinsics.h"

#include "../misc.h"
#include "../params.h"
#include "../common.h"
#include "../formats.h"
#include "../options.h"
#include "../unicode.h"
#include "../sha.h"
#include "../johnswap.h"

#define FORMAT_LABEL			"mssql"
#define FORMAT_NAME			"MS SQL"

#define ALGORITHM_NAME			"SHA1 " SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define PLAINTEXT_LENGTH		25
#define CIPHERTEXT_LENGTH		94

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
#if (SIMD_COEF_32==2)
#define SALT_EXTRA_LEN          0x40004
#else
#define SALT_EXTRA_LEN          0x4040404
#endif
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

//microsoft unicode ...
#if ARCH_LITTLE_ENDIAN
#define ENDIAN_SHIFT_L
#define ENDIAN_SHIFT_R
#else
#define ENDIAN_SHIFT_L  << 8
#define ENDIAN_SHIFT_R  >> 8
#endif

#ifndef SHA_BUF_SIZ
#define SHA_BUF_SIZ             16
#endif

static struct fmt_tests tests[] = {
	{"0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254", "FOO"},
	{"0x01000508513EADDF6DB7DDD270CCA288BF097F2FF69CC2DB74FBB9644D6901764F999BAB9ECB80DE578D92E3F80D", "BAR"},
	{"0x01008408C523CF06DCB237835D701C165E68F9460580132E28ED8BC558D22CEDF8801F4503468A80F9C52A12C0A3", "CANARD"},
	{"0x0100BF088517935FC9183FE39FDEC77539FD5CB52BA5F5761881E5B9638641A79DBF0F1501647EC941F3355440A2", "LAPIN"},
	{NULL}
};

static unsigned char cursalt[SALT_SIZE];

#ifdef SIMD_COEF_32
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key mssql_saved_key
#define crypt_key mssql_crypt_key
JTR_ALIGN(MEM_ALIGN_SIMD) char saved_key[SHA_BUF_SIZ*4*NBKEYS];
JTR_ALIGN(MEM_ALIGN_SIMD) char crypt_key[DIGEST_SIZE*NBKEYS];
static char plain_keys[NBKEYS][PLAINTEXT_LENGTH*3+1];
#else

static unsigned char saved_key[PLAINTEXT_LENGTH*2 + 1 + SALT_SIZE];
static uint32_t crypt_key[DIGEST_SIZE / 4];
static unsigned int key_length;
static char *plain_keys[1];

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

static void set_salt(void *salt)
{
	memcpy(cursalt, salt, SALT_SIZE);
}

static void * get_salt(char * ciphertext)
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

static void set_key_enc(char *_key, int index);
extern struct fmt_main fmt_mssql;

static void init(struct fmt_main *self)
{
	initUnicode(UNICODE_MS_OLD);

	memset(saved_key, 0, sizeof(saved_key));
	if (options.target_enc == UTF_8)
		fmt_mssql.params.plaintext_length = PLAINTEXT_LENGTH * 3;

	if (options.target_enc != ISO_8859_1 && options.target_enc != ENC_RAW)
		fmt_mssql.methods.set_key = set_key_enc;
}

#ifdef SIMD_COEF_32
static void clear_keys(void) {
	memset(saved_key, 0, sizeof(saved_key));
}
#endif

static void set_key(char *key, int index) {
	UTF8 utf8[PLAINTEXT_LENGTH+1];
	int utf8len, orig_len;

#ifdef SIMD_COEF_32
	int i;
	strnzcpy(plain_keys[index], key, PLAINTEXT_LENGTH + 1);
#else
	plain_keys[index] = key;
#endif
	orig_len = strlen(key);
	utf8len = enc_uc(utf8, sizeof(utf8), (unsigned char*)key, orig_len);
	if (utf8len <= 0 && *key)
		return;

#ifdef SIMD_COEF_32
	((unsigned int *)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = (2*utf8len+SALT_SIZE)<<3;
	for (i=0;i<utf8len;i++)
		saved_key[GETPOS((i*2), index)] = utf8[i];
	saved_key[GETPOS((i*2+SALT_SIZE) , index)] = 0x80;
#else
	key_length = 0;

	while( (((unsigned short *)saved_key)[key_length] = (utf8[key_length] ENDIAN_SHIFT_L ))  )
		key_length++;
#endif
}

static void set_key_enc(char *key, int index) {
	UTF16 utf16key[PLAINTEXT_LENGTH+1], utf16key_tmp[PLAINTEXT_LENGTH+1];
	int utf8len = strlen(key);
	int i;
	int utf16len;

#ifdef SIMD_COEF_32
	strnzcpy(plain_keys[index], key, PLAINTEXT_LENGTH*3 + 1);
#else
	plain_keys[index] = key;
#endif
	utf16len = enc_to_utf16(utf16key_tmp, PLAINTEXT_LENGTH, (unsigned char*)key, utf8len);
	if (utf16len <= 0) {
		utf8len = -utf16len;
		plain_keys[index][utf8len] = 0; // match truncation!
		if (utf16len != 0)
			utf16len = strlen16(utf16key_tmp);
	}
	utf16len = utf16_uc(utf16key, PLAINTEXT_LENGTH, utf16key_tmp, utf16len);
	if (utf16len <= 0)
		utf16len *= -1;

#ifdef SIMD_COEF_32
	((unsigned int *)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = (2*utf16len+SALT_SIZE)<<3;
	for (i=0;i<utf16len;i++)
	{
#if ARCH_LITTLE_ENDIAN==1
		saved_key[GETPOS((i*2), index)] = (char)utf16key[i];
		saved_key[GETPOS((i*2+1), index)] = (char)(utf16key[i]>>8);
#else
		saved_key[GETPOS((i*2), index)] = (char)(utf16key[i]>>8);
		saved_key[GETPOS((i*2+1), index)] = (char)utf16key[i];
#endif
	}
	saved_key[GETPOS((i*2+SALT_SIZE) , index)] = 0x80;
#else
	for (i=0;i<utf16len;i++)
	{
		unsigned char *uc = (unsigned char*)&(utf16key[i]);
		saved_key[(i<<1)  ] = uc[0];
		saved_key[(i<<1)+1] = uc[1];
	}
	key_length = i;
#endif
}

static char *get_key(int index) {
	static UTF8 UC_Key[PLAINTEXT_LENGTH*3+1];
	// Calling this will ONLY upcase characters 'valid' in the code page. There are MANY
	// code pages which mssql WILL upcase the letter (in UCS-2), but there is no upper case value
	// in the code page.  Thus we MUST keep the lower cased letter in this case.
	enc_uc(UC_Key, sizeof(UC_Key), (UTF8*)plain_keys[index], strlen(plain_keys[index]));
	return (char*)UC_Key;
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
		unsigned len = (((((unsigned int *)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32]) >> 3) & 0xff) - SALT_SIZE;
		for (i=0;i<SALT_SIZE;i++)
			saved_key[GETPOS((len+i), index)] = cursalt[i];
	}
	SIMDSHA1body(saved_key, (unsigned int *)crypt_key, NULL, SSEi_REVERSE_STEPS | SSEi_MIXED_IN);
#else
	SHA_CTX ctx;
	memcpy(saved_key+key_length*2, cursalt, SALT_SIZE);
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, saved_key, key_length*2+SALT_SIZE );
	SHA1_Final( (unsigned char *) crypt_key, &ctx);
#endif

	return count;
}

static void *get_binary(char *ciphertext)
{
	static uint32_t out[DIGEST_SIZE/4];
	char *realcipher = (char*)out;
	int i;

	ciphertext += 54;

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

	return (void *)realcipher;
}

static int cmp_all(void *binary, int count) {
	int index;

	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_32
        if (((uint32_t*)binary)[4] == ((uint32_t*)crypt_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32 + 4*SIMD_COEF_32])
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
	char *key = get_key(index);
	UTF16 utf16key[PLAINTEXT_LENGTH+1], utf16key_tmp[PLAINTEXT_LENGTH+1];
	int len;
	SHA_CTX ctx;

	len = enc_to_utf16(utf16key_tmp, PLAINTEXT_LENGTH,
	                        (unsigned char*)key, strlen(key));
	if (len < 0)
		len = strlen16(utf16key_tmp);

	len = utf16_uc(utf16key, PLAINTEXT_LENGTH, utf16key_tmp, len);
	if (len <= 0)
		len *= -1;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, utf16key, 2 * len);
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

struct fmt_main fmt_mssql = {
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
		FMT_8_BIT | FMT_UNICODE | FMT_ENC,
		{ NULL },
		{ NULL },
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
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
#ifdef SIMD_COEF_32
		clear_keys,
#else
		fmt_default_clear_keys,
#endif
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

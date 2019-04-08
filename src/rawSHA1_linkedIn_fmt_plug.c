/*
 * This software is Copyright (c) 2004 bartavelle, <simon at banquise.net>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Optimised set_key() by magnum, 2012
 *
 * This file 'hacked' to work with the LinkedIn hash leak. Those hashes had
 * a lot of partial hashes in there. 00000 was overwritten on hashes that
 * were cracked. In this change, we simply ignore the first 20 bits of the
 * hash, when doing a compare.  JimF June, 2012.
 *
 * NOTE! This format will write complete (repaired) SHA-1 hashes to the .pot
 * file. To show all cracked password properly, you need to *not* specify this
 * format but raw-sha1.
 */

#include "arch.h"

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawSHA1_LI;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawSHA1_LI);
#else

#include <string.h>

#ifdef SIMD_COEF_32
#define NBKEYS	(SIMD_COEF_32 * SIMD_PARA_SHA1)
#endif
#include "simd-intrinsics.h"

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "johnswap.h"
#include "loader.h"
#include "rawSHA1_common.h"
#include "base64_convert.h"

#define FORMAT_LABEL			"Raw-SHA1-Linkedin"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"SHA1 " SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107


#define CIPHERTEXT_LENGTH		(HASH_LENGTH + TAG_LENGTH)

#define BINARY_SIZE			20
#define BINARY_ALIGN			4
#define SALT_SIZE			0
#define SALT_ALIGN			1

#ifdef SIMD_COEF_32
#define PLAINTEXT_LENGTH		55
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define FMT_IS_BE
#include "common-simd-getpos.h"
#else
#define PLAINTEXT_LENGTH		125
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests tests[] = {
	{"000007f070b64a50e9d31ac3f9eda35120e29d6c", "digipalmw221u"},
	{"2fbf0eba37de1d1d633bc1ed943b907f9b360d4c", "azertyuiop1"},
	{"000006c9bca350e96223a850d9e862a6b3bf2641", "magnum"},
	{"$dynamic_26$00000E364706816ABA3E25717850C26C9CD0D89D", "abc"},
	{"000008090e92232ed07092ebed6dc6170457a21d", "azertyuiop2"},
	{"$dynamic_26$0000012f25e64931f3833b26e999e26e81f9ad24", "azertyuiop3"},
	{"00000c1163897ac86e393fa16d6ae2c2fce21602", "7850"},
	{"{SHA}AAALC6nhM8T9hO0xrC5bxZfWF3Q=", "7858"},
	{NULL}
};

/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key rawSHA1_saved_key_LI
#define crypt_key rawSHA1_crypt_key_LI
#ifdef SIMD_COEF_32
JTR_ALIGN(MEM_ALIGN_SIMD) uint32_t saved_key[SHA_BUF_SIZ*NBKEYS];
JTR_ALIGN(MEM_ALIGN_SIMD) uint32_t crypt_key[BINARY_SIZE/4*NBKEYS];
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static uint32_t crypt_key[BINARY_SIZE / 4];
static SHA_CTX ctx;
#endif

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	ciphertext = rawsha1_common_split(ciphertext, index, self);

	// 'normalize' these hashes to all 'appear' to be 00000xxxxxx hashes.
	// on the source() function, we later 'fix' these up.
	memcpy(&ciphertext[TAG_LENGTH], "00000", 5);

	return ciphertext;
}

#define NON_SIMD_SINGLE_SAVED_KEY
#include "common-simd-setkey32.h"

static int cmp_all(void *binary, int count) {
#ifdef SIMD_COEF_32
	unsigned int x, y;
	for (y = 0; y < SIMD_PARA_SHA1; y++) {
		for (x = 0; x < SIMD_COEF_32; x++) {
			if ( ((uint32_t*)binary)[1] == crypt_key[x+y*SIMD_COEF_32*5+SIMD_COEF_32] )
				return 1;
		}
	}
	return 0;
#else
	return !memcmp(&((uint32_t*)binary)[1], &crypt_key[1], BINARY_SIZE - 4);
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int cmp_one(void * binary, int index)
{
#ifdef SIMD_COEF_32
	unsigned int x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;

//	if ( ((uint32_t*)binary)[0] != crypt_key[x+y*SIMD_COEF_32*5] )
//		return 0;
	if ( ((uint32_t*)binary)[1] != crypt_key[x+y*SIMD_COEF_32*5+SIMD_COEF_32] )
		return 0;
	if ( ((uint32_t*)binary)[2] != crypt_key[x+y*SIMD_COEF_32*5+2*SIMD_COEF_32] )
		return 0;
	if ( ((uint32_t*)binary)[3] != crypt_key[x+y*SIMD_COEF_32*5+3*SIMD_COEF_32] )
		return 0;
	if ( ((uint32_t*)binary)[4] != crypt_key[x+y*SIMD_COEF_32*5+4*SIMD_COEF_32] )
		return 0;
	return 1;
#else
	if ( ((uint32_t*)binary)[1] != crypt_key[1] )
		return 0;
	if ( ((uint32_t*)binary)[2] != crypt_key[2] )
		return 0;
	if ( ((uint32_t*)binary)[3] != crypt_key[3] )
		return 0;
	if ( ((uint32_t*)binary)[4] != crypt_key[4] )
		return 0;
	return 1;
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

  // get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef SIMD_COEF_32
	SIMDSHA1body(saved_key, crypt_key, NULL, SSEi_MIXED_IN);
#else
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (unsigned char *) saved_key, strlen( saved_key ) );
	SHA1_Final( (unsigned char *) crypt_key, &ctx);
#endif
	return count;
}

static int binary_hash_0(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_0; }
static int binary_hash_1(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_1; }
static int binary_hash_2(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_2; }
static int binary_hash_3(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_3; }
static int binary_hash_4(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_4; }
static int binary_hash_5(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_5; }
static int binary_hash_6(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_6; }

#ifdef SIMD_COEF_32
#define INDEX	((index&(SIMD_COEF_32-1))+(unsigned int)index/SIMD_COEF_32*SIMD_COEF_32*5)
static int get_hash_0(int index) { return ((uint32_t*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_0; }
static int get_hash_1(int index) { return ((uint32_t*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_1; }
static int get_hash_2(int index) { return ((uint32_t*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_2; }
static int get_hash_3(int index) { return ((uint32_t*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_3; }
static int get_hash_4(int index) { return ((uint32_t*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_4; }
static int get_hash_5(int index) { return ((uint32_t*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_5; }
static int get_hash_6(int index) { return ((uint32_t*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_6; }
#undef INDEX
#else
static int get_hash_0(int index) { return ((uint32_t*)crypt_key)[1] & PH_MASK_0; }
static int get_hash_1(int index) { return ((uint32_t*)crypt_key)[1] & PH_MASK_1; }
static int get_hash_2(int index) { return ((uint32_t*)crypt_key)[1] & PH_MASK_2; }
static int get_hash_3(int index) { return ((uint32_t*)crypt_key)[1] & PH_MASK_3; }
static int get_hash_4(int index) { return ((uint32_t*)crypt_key)[1] & PH_MASK_4; }
static int get_hash_5(int index) { return ((uint32_t*)crypt_key)[1] & PH_MASK_5; }
static int get_hash_6(int index) { return ((uint32_t*)crypt_key)[1] & PH_MASK_6; }
#endif

static void *binary(char *ciphertext)
{
	uint32_t *bin = (uint32_t*)rawsha1_common_get_binary(ciphertext);
#if defined (SIMD_COEF_32) && ARCH_LITTLE_ENDIAN
	alter_endianity(bin, BINARY_SIZE);
#endif
	return (void*)bin;
}

static char *source(char *source, void *binary)
{
	static char Buf[CIPHERTEXT_LENGTH + 1];
	uint32_t out[BINARY_SIZE / 4];
	unsigned char *realcipher = (unsigned char*)out;

#ifdef SIMD_COEF_32
	int i;

	for (i = 0; i < NBKEYS; ++i) {
		if (crypt_key[(i/SIMD_COEF_32)*20+SIMD_COEF_32+(i%SIMD_COEF_32)] == ((uint32_t*)binary)[1]) {
			// Ok, we may have found it.  Check the next 3 DWORDS
			if (crypt_key[(i/SIMD_COEF_32)*20+SIMD_COEF_32*2+(i%SIMD_COEF_32)] == ((uint32_t*)binary)[2] &&
			    crypt_key[(i/SIMD_COEF_32)*20+SIMD_COEF_32*3+(i%SIMD_COEF_32)] == ((uint32_t*)binary)[3] &&
			    crypt_key[(i/SIMD_COEF_32)*20+SIMD_COEF_32*4+(i%SIMD_COEF_32)] == ((uint32_t*)binary)[4]) {
				if (!bench_or_test_running) ((uint32_t*)binary)[0] = crypt_key[(i/SIMD_COEF_32)*20+(i%SIMD_COEF_32)];
				break;
			}
		}
	}
#else
	if (crypt_key[1] == ((uint32_t*)binary)[1] &&
		crypt_key[2] == ((uint32_t*)binary)[2] &&
		crypt_key[3] == ((uint32_t*)binary)[3] &&
		crypt_key[4] == ((uint32_t*)binary)[4])
		   if (!bench_or_test_running) ((uint32_t*)binary)[0] = crypt_key[0];
#endif
	memcpy(realcipher, binary, BINARY_SIZE);
#if defined(SIMD_COEF_32) && ARCH_LITTLE_ENDIAN
	alter_endianity(realcipher, BINARY_SIZE);
#endif
	strcpy(Buf, FORMAT_TAG);
	base64_convert(realcipher, e_b64_raw, 20,
	               &Buf[TAG_LENGTH], e_b64_hex, sizeof(Buf)-TAG_LENGTH,
	               flg_Base64_NO_FLAGS, 0);
	return Buf;
}

struct fmt_main fmt_rawSHA1_LI = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG, FORMAT_TAG_OLD },
		tests
	}, {
		fmt_default_init,
		fmt_default_done,
		fmt_default_reset,
		rawsha1_common_prepare,
		rawsha1_common_valid,
		split,
		binary,
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

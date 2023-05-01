/*
 * Office 2007 cracker patch for JtR. This software is
 * Copyright (c) 2012 Dhiru Kholia <dhiru.kholia at gmail.com>.
 * Copyright (c) 2012-2021 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_office;
#elif FMT_REGISTERS_H
john_register_one(&fmt_office);
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "unicode.h"
#include "aes.h"
#include "sha.h"
#include "sha2.h"
#include "johnswap.h"
#include "office_common.h"
#include "simd-intrinsics.h"

#define FORMAT_LABEL             "Office"
#define FORMAT_NAME              "2007/2010/2013"
#define ALGORITHM_NAME           "SHA1 " SHA1_ALGORITHM_NAME " / SHA512 " SHA512_ALGORITHM_NAME " AES"
#define BENCHMARK_COMMENT        ""
#define BENCHMARK_LENGTH         0x107
#define PLAINTEXT_LENGTH         125

#ifdef SIMD_COEF_32
#define GETPOS_512W(i, index)    ( (index&(SIMD_COEF_64-1))*8 + ((i*8)&(0xffffffff-7))*SIMD_COEF_64 + (uint32_t)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
#define GETOUTPOS_512W(i, index) ( (index&(SIMD_COEF_64-1))*8 + ((i*8)&(0xffffffff-7))*SIMD_COEF_64 + (uint32_t)index/SIMD_COEF_64*8*SIMD_COEF_64*8 )
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS_1(i, index)       ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (uint32_t)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 )
#define GETPOS_512(i, index)     ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + (uint32_t)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
#define GETOUTPOS_512(i, index)  ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + (uint32_t)index/SIMD_COEF_64*8*SIMD_COEF_64*8 )
#else
#define GETPOS_1(i, index)       ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (uint32_t)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 )
#define GETPOS_512(i, index)     ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + ((i)&7) + (uint32_t)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
#define GETOUTPOS_512(i, index)  ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + ((i)&7) + (uint32_t)index/SIMD_COEF_64*8*SIMD_COEF_64*8 )
#endif
#define SHA1_LOOP_CNT            (SIMD_COEF_32 * SIMD_PARA_SHA1)
#define SHA512_LOOP_CNT          (SIMD_COEF_64 * SIMD_PARA_SHA512)
#define MIN_KEYS_PER_CRYPT       (SIMD_COEF_32 * SIMD_PARA_SHA1 * SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT       (SIMD_COEF_32 * SIMD_PARA_SHA1 * SIMD_PARA_SHA512)
#else
#define SHA1_LOOP_CNT            1
#define SHA512_LOOP_CNT          1
#define MIN_KEYS_PER_CRYPT       1
#define MAX_KEYS_PER_CRYPT       1
#endif

#ifndef OMP_SCALE
#define OMP_SCALE                1 // MKPC and scale tuned for i7
#endif

static struct fmt_tests office_tests[] = {
	{"$office$*2007*20*128*16*8b2c9e8c878844fc842012273be4bea8*aa862168b80d8c45c852696a8bb499eb*a413507fabe2d87606595f987f679ff4b5b4c2cd", "Password"},
	/* 2007-Default_myhovercraftisfullofeels_.docx */
	{"$office$*2007*20*128*16*91f095a1fd02595359fe3938fa9236fd*e22668eb1347957987175079e980990f*659f50b9062d36999bf3d0911068c93268ae1d86", "myhovercraftisfullofeels"},
	/* 2007-Default_myhovercraftisfullofeels_.dotx */
	{"$office$*2007*20*128*16*56ea65016fbb4eac14a6770b2dbe7e99*8cf82ce1b62f01fd3b2c7666a2313302*21443fe938177e648c482da72212a8848c2e9c80", "myhovercraftisfullofeels"},
	/* 2007-Default_myhovercraftisfullofeels_.xlsb */
	{"$office$*2007*20*128*16*fbd4cc5dab9b8e341778ddcde9eca740*3a040a9cef3d3675009b22f99718e39c*48053b27e95fa53b3597d48ca4ad41eec382e0c8", "myhovercraftisfullofeels"},
	/* 2007-Default_myhovercraftisfullofeels_.xlsm */
	{"$office$*2007*20*128*16*fbd4cc5dab9b8e341778ddcde9eca740*92bb2ef34ca662ca8a26c8e2105b05c0*0261ba08cd36a324aa1a70b3908a24e7b5a89dd6", "myhovercraftisfullofeels"},
	/* 2007-Default_myhovercraftisfullofeels_.xlsx */
	{"$office$*2007*20*128*16*fbd4cc5dab9b8e341778ddcde9eca740*46bef371486919d4bffe7280110f913d*b51af42e6696baa097a7109cebc3d0ff7cc8b1d8", "myhovercraftisfullofeels"},
	/* 2007-Default_myhovercraftisfullofeels_.xltx */
	{"$office$*2007*20*128*16*fbd4cc5dab9b8e341778ddcde9eca740*1addb6823689aca9ce400be8f9e55fc9*e06bf10aaf3a4049ffa49dd91cf9e7bbf88a1b3b", "myhovercraftisfullofeels"},
	/* Github issue #4780 (256-bit key length) */
	{"$office$*2007*20*256*16*3e94c22e93f35e14162402da444dec28*7057eb00b1e0e1cce5c85ba0727e9686*ff4f3a5a9e872c364e6d83f07af904ce518b53e6", "12Qwaszx"},
	/* 2010-Default_myhovercraftisfullofeels_.docx */
	{"$office$*2010*100000*128*16*213aefcafd9f9188e78c1936cbb05a44*d5fc7691292ab6daf7903b9a8f8c8441*46bfac7fb87cd43bd0ab54ebc21c120df5fab7e6f11375e79ee044e663641d5e", "myhovercraftisfullofeels"},
	/* 2010-Default_myhovercraftisfullofeels_.dotx */
	{"$office$*2010*100000*128*16*0907ec6ecf82ede273b7ee87e44f4ce5*d156501661638cfa3abdb7fdae05555e*4e4b64e12b23f44d9a8e2e00196e582b2da70e5e1ab4784384ad631000a5097a", "myhovercraftisfullofeels"},
	/* 2010-Default_myhovercraftisfullofeels_.xlsb */
	{"$office$*2010*100000*128*16*71093d08cf950f8e8397b8708de27c1f*00780eeb9605c7e27227c5619e91dc21*90aaf0ea5ccc508e699de7d62c310f94b6798ae77632be0fc1a0dc71600dac38", "myhovercraftisfullofeels"},
	/* 2010-Default_myhovercraftisfullofeels_.xlsx */
	{"$office$*2010*100000*128*16*71093d08cf950f8e8397b8708de27c1f*ef51883a775075f30d2207e87987e6a3*a867f87ea955d15d8cb08dc8980c04bf564f8af060ab61bf7fa3543853e0d11a", "myhovercraftisfullofeels"},
	/* 2013-openwall.pptx */
	{"$office$*2013*100000*256*16*9b12805dd6d56f46d07315153f3ecb9c*c5a4a167b51faa6629f6a4caf0b4baa8*87397e0659b2a6fff90291f8e6d6d0018b750b792fefed77001edbafba7769cd", "openwall"},
	/* 365-2013-openwall.docx */
	{"$office$*2013*100000*256*16*774a174239a7495a59cac39a122d991c*b2f9197840f9e5d013f95a3797708e83*ecfc6d24808691aac0daeaeba72aba314d72c6bbd12f7ff0ea1a33770187caef", "openwall"},
	/* 365-2013-password.docx */
	{"$office$*2013*100000*256*16*d4fc9302eedabf9872b24ca700a5258b*7c9554d582520747ec3e872f109a7026*1af5b5024f00e35eaf5fd8148b410b57e7451a32898acaf14275a8c119c3a4fd", "password"},
	/* 365-2013-password.xlsx */
	{"$office$*2013*100000*256*16*59b49c64c0d29de733f0025837327d50*70acc7946646ea300fc13cfe3bd751e2*627c8bdb7d9846228aaea81eeed434d022bb93bb5f4da146cb3ad9d847de9ec9", "password"},
	/* 365-2013-strict-password.docx */
	{"$office$*2013*100000*256*16*f1c23049d85876e6b20e95ab86a477f1*13303dbd27a38ea86ef11f1b2bc56225*9a69596de0655a6c6a5b2dc4b24d6e713e307fb70af2d6b67b566173e89f941d", "password"},

	/* Max password length data, 125 bytes.  Made with pass_gen.pl */
	{"$office$*2007*20*128*16*7268323350556e527671367031526263*54344b786a6967615052493837496735*96c9d7cc44e81971aadfe81cce88cb8b00000000", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"},
	{"$office$*2010*100000*128*16*42624931633777446c67354e34686e64*73592fdc2ecb12cd8dcb3ca2cec852bd*82f7315701818a7150ed7a7977717d0b56dcd1bc27e40a23dee6287a6ed55f9b", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"},
	{"$office$*2013*100000*256*16*36537a3373756b587632386d77665362*c5958bd6177be548ce33d99f8e4fd7a7*43baa9dfab09a7e54b9d719dbe5187f1f7b55d7b761361fe1f60c85b044aa125", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"},

	/* Office 2019 - sample Word document */
	{"$office$*2013*100000*256*16*f4984f25c246bb742259ec55b4bab10c*d7608a90d1f552b6910c5d4ab110e276*04a6a1549a25d4871f63d2d2aa098fd2d6c74ddefcdec92a9616fb48a583f259", "openwall"},
	{NULL}
};

static ms_office_custom_salt *cur_salt;

#define MS_OFFICE_2007_ITERATIONS	50000

/* Password encoded in UCS-2 */
static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
/* UCS-2 password length, in octets */
static int *saved_len;
static int *cracked;

static uint8_t (*encryptionKey)[40];
static uint8_t (*verifierKeys1)[64];
static uint8_t (*verifierKeys512)[128];

/* Office 2010/2013 */
static const uint8_t encryptedVerifierHashInputBlockKey[] = {
	0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79
};
static const uint8_t encryptedVerifierHashValueBlockKey[] = {
	0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e
};

#define dynalloc(var) var = mem_calloc(sizeof(*var), self->params.max_keys_per_crypt)

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	dynalloc(saved_key);
	dynalloc(saved_len);
	dynalloc(cracked);
	dynalloc(encryptionKey);
	dynalloc(verifierKeys1);
	dynalloc(verifierKeys512);

	if (options.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, PLAINTEXT_LENGTH * 3);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
	MEM_FREE(encryptionKey);
	MEM_FREE(verifierKeys1);
	MEM_FREE(verifierKeys512);
}

static uint8_t *DeriveKey(uint8_t *hashValue, uint8_t *X3)
{
	int i;
	uint8_t derivedKey[64];
	SHA_CTX ctx;
	int cbRequiredKeyLength = cur_salt->keySize / 8;
	uint8_t *X1 = X3;
	uint8_t *X2 = &X3[20];

	// See 2.3.4.7 of MS-OFFCRYPTO
	for (i = 0; i < 64; i++)
		derivedKey[i] = (i < 20 ? 0x36 ^ hashValue[i] : 0x36);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, derivedKey, 64);
	SHA1_Final(X1, &ctx);

	if (cur_salt->verifierHashSize < cbRequiredKeyLength) {
		for (i = 0; i < 64; i++)
			derivedKey[i] = (i < 20 ? 0x5C ^ hashValue[i] : 0x5C);

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, derivedKey, 64);
		SHA1_Final(X2, &ctx);
	}

	return X3;
}

#ifdef SIMD_COEF_32
static void GeneratePasswordHashUsingSHA1(int idx, uint8_t final[SHA1_LOOP_CNT][40])
{
	uint8_t hashBuf[20];
	/*
	 * H(0) = H(salt, password)
	 * hashBuf = SHA1Hash(salt, password);
	 * create input buffer for SHA1 from salt and unicode version of password
	 */
	uint8_t X3[40];
	SHA_CTX ctx;
	uint8_t _IBuf[64*SHA1_LOOP_CNT + MEM_ALIGN_CACHE], *keys;
	uint32_t *keys32;
	uint32_t i, j;

	keys = (uint8_t*)mem_align(_IBuf, MEM_ALIGN_CACHE);
	keys32 = (uint32_t*)keys;
	memset(keys, 0, 64 * SHA1_LOOP_CNT);

	for (i = 0; i < SHA1_LOOP_CNT; i++) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, cur_salt->salt, cur_salt->saltSize);
		SHA1_Update(&ctx, saved_key[idx + i], saved_len[idx + i]);
		SHA1_Final(hashBuf, &ctx);

		/*
		 * Generate each hash in turn
		 * H(n) = H(i, H(n-1))
		 * hashBuf = SHA1Hash(i, hashBuf);
		 */

		/*
		 * Create a byte array of the integer and put at the front
		 * of the input buffer.
		 * 1.3.6 says that little-endian byte ordering is expected.
		 */
		for (j = 4; j < 24; j++)
			keys[GETPOS_1(j, i)] = hashBuf[j-4];
		keys[GETPOS_1(j, i)] = 0x80;
		/* 24 bytes of crypt data (192 bits). */
		keys[GETPOS_1(63, i)] = 192;
	}
	/* we do 1 less than actual number of iterations here. */
	for (i = 0; i < MS_OFFICE_2007_ITERATIONS - 1; i++) {
		for (j = 0; j < SHA1_LOOP_CNT; j++) {
			keys[GETPOS_1(0, j)] = i & 0xff;
			keys[GETPOS_1(1, j)] = i >> 8;
		}
		/* Here we output to 4 bytes past start of input buffer. */
		SIMDSHA1body(keys, &keys32[SIMD_COEF_32], NULL,
		             SSEi_MIXED_IN | SSEi_OUTPUT_AS_INP_FMT);
	}
	/*
	 * Last iteration is output to start of input buffer,
	 * then 32 bit 0 appended.
	 * but this is still ends up being 24 bytes of crypt data.
	 */
	for (j = 0; j < SHA1_LOOP_CNT; j++) {
		keys[GETPOS_1(0, j)] = i & 0xff;
		keys[GETPOS_1(1, j)] = i >> 8;
	}
	SIMDSHA1body(keys, keys32, NULL, SSEi_MIXED_IN | SSEi_OUTPUT_AS_INP_FMT);

	/*
	 * Finally, append "block" (0) to H(n)
	 * hashBuf = SHA1Hash(hashBuf, 0);
	 */
	for (i = 0; i < SHA1_LOOP_CNT; i++) {
		keys[GETPOS_1(20,i)] = 0;
		keys[GETPOS_1(21,i)] = 0;
		keys[GETPOS_1(22,i)] = 0;
		keys[GETPOS_1(23,i)] = 0;
	}

	SIMDSHA1body(keys, keys32, NULL, SSEi_MIXED_IN | SSEi_FLAT_OUT);

	/* Now convert back into a 'flat' value, which is a flat array. */
	for (i = 0; i < SHA1_LOOP_CNT; i++)
		memcpy(final[i], DeriveKey(&keys[20 * i], X3), cur_salt->keySize / 8);
}
#else
// for non SIMD, SHA1_LOOP_CNT is 1
static void GeneratePasswordHashUsingSHA1(int idx, uint8_t final[SHA1_LOOP_CNT][40])
{
	uint8_t hashBuf[20], *key;
	UTF16 *passwordBuf = saved_key[idx];
	int passwordBufSize = saved_len[idx];
	/*
	 * H(0) = H(salt, password)
	 * hashBuf = SHA1Hash(salt, password);
	 * create input buffer for SHA1 from salt and unicode version of password
	 */
	uint32_t inputBuf[(0x14 + 0x04 + 4) / sizeof(int)];
	uint8_t X3[40];
	int i;
	SHA_CTX ctx;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, cur_salt->salt, cur_salt->saltSize);
	SHA1_Update(&ctx, passwordBuf, passwordBufSize);
	SHA1_Final(hashBuf, &ctx);

	/*
	 * Generate each hash in turn
	 * H(n) = H(i, H(n-1))
	 * hashBuf = SHA1Hash(i, hashBuf);
	 */

	/*
	 * Create a byte array of the integer and put at the front
	 * of the input buffer.
	 * 1.3.6 says that little-endian byte ordering is expected.
	 */
	memcpy(&inputBuf[1], hashBuf, 20);
	for (i = 0; i < MS_OFFICE_2007_ITERATIONS; i++) {
#if ARCH_LITTLE_ENDIAN
		*inputBuf = i;
#else
		*inputBuf = JOHNSWAP(i);
#endif
		/* 'append' the previously generated hash to the input buffer. */
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, inputBuf, 0x14 + 0x04);
		SHA1_Final((uint8_t*)&inputBuf[1], &ctx);
	}
	/*
	 * Finally, append "block" (0) to H(n)
	 * hashBuf = SHA1Hash(hashBuf, 0);
	 */
	memset(&inputBuf[6], 0, 4);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, &inputBuf[1], 0x14 + 0x04);
	SHA1_Final(hashBuf, &ctx);

	key = DeriveKey(hashBuf, X3);

	/*
	 * Grab the key length bytes of the final hash as the encryption key
	 */
	memcpy(final[0], key, cur_salt->keySize / 8);
}
#endif

#ifdef SIMD_COEF_32
static void GenerateAgileEncryptionKey(int idx,
                                       uint8_t hashBuf[SHA1_LOOP_CNT][64])
{
	uint8_t tmpBuf[20], *keys;
	int hashSize = cur_salt->keySize >> 3;
	uint32_t i, j;
	SHA_CTX ctx;
	uint8_t _IBuf[64 * SHA1_LOOP_CNT + MEM_ALIGN_CACHE];
	uint8_t _OBuf[20 * SHA1_LOOP_CNT + MEM_ALIGN_CACHE];
	uint32_t *keys32, (*crypt)[20 / 4];

	crypt = (void*)mem_align(_OBuf, MEM_ALIGN_CACHE);
	keys = (uint8_t*)mem_align(_IBuf, MEM_ALIGN_CACHE);
	keys32 = (uint32_t*)keys;
	memset(keys, 0, 64 * SHA1_LOOP_CNT);

	for (i = 0; i < SHA1_LOOP_CNT; i++) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, cur_salt->salt, cur_salt->saltSize);
		SHA1_Update(&ctx, saved_key[idx + i], saved_len[idx + i]);
		SHA1_Final(tmpBuf, &ctx);
		for (j = 4; j < 24; j++)
			keys[GETPOS_1(j, i)] = tmpBuf[j - 4];
		keys[GETPOS_1(j, i)] = 0x80;
		// 24 bytes of crypt data (192 bits).
		keys[GETPOS_1(63, i)] = 192;
	}

	// we do 1 less than actual number of iterations here.
	for (i = 0; i < cur_salt->spinCount - 1; i++) {
		for (j = 0; j < SHA1_LOOP_CNT; j++) {
			keys[GETPOS_1(0, j)] = i & 0xff;
			keys[GETPOS_1(1, j)] = (i >> 8) & 0xff;
			keys[GETPOS_1(2, j)] = i >> 16;
		}
		// Here we output to 4 bytes past start of input buffer.
		SIMDSHA1body(keys, &keys32[SIMD_COEF_32], NULL,
		             SSEi_MIXED_IN | SSEi_OUTPUT_AS_INP_FMT);
	}
	// last iteration is output to start of input buffer, then 32 bit 0 appended.
	// but this is still ends up being 24 bytes of crypt data.
	for (j = 0; j < SHA1_LOOP_CNT; j++) {
		keys[GETPOS_1(0, j)] = i & 0xff;
		keys[GETPOS_1(1, j)] = (i >> 8) & 0xff;
		keys[GETPOS_1(2, j)] = i >> 16;
	}
	SIMDSHA1body(keys, keys32, NULL, SSEi_MIXED_IN | SSEi_OUTPUT_AS_INP_FMT);

	// Finally, append "block" (0) to H(n)
	for (i = 0; i < SHA1_LOOP_CNT; i++) {
		for (j = 0; j < 8; j++)
			keys[GETPOS_1(20 + j, i)] = encryptedVerifierHashInputBlockKey[j];
		keys[GETPOS_1(20 + j, i)] = 0x80;
		// 28 bytes of crypt data (192 bits).
		keys[GETPOS_1(63, i)] = 224;
	}
	SIMDSHA1body(keys, (uint32_t*)crypt, NULL, SSEi_MIXED_IN | SSEi_FLAT_OUT);
	for (i = 0; i < SHA1_LOOP_CNT; i++)
		memcpy(hashBuf[i], crypt[i], 20);

	// And second "block" (0) to H(n)
	for (i = 0; i < SHA1_LOOP_CNT; i++) {
		for (j = 0; j < 8; j++)
			keys[GETPOS_1(20 + j, i)] = encryptedVerifierHashValueBlockKey[j];
	}
	SIMDSHA1body(keys, (uint32_t*)crypt, NULL, SSEi_MIXED_IN | SSEi_FLAT_OUT);
	for (i = 0; i < SHA1_LOOP_CNT; i++)
		memcpy(&hashBuf[i][32], crypt[i], 20);

	// Fix up the size per the spec
	if (hashSize > 20) { // FIXME: Is this ever true?
		for (i = 0; i < SHA1_LOOP_CNT; i++) {
			for (j = 20; j < hashSize; j++) {
				hashBuf[i][j] = 0x36;
				hashBuf[i][32 + j] = 0x36;
			}
		}
	}
}
#else
static void GenerateAgileEncryptionKey(int idx,
                                       uint8_t hashBuf[SHA1_LOOP_CNT][64])
{
	/* H(0) = H(salt, password)
	 * hashBuf = SHA1Hash(salt, password);
	 * create input buffer for SHA1 from salt and unicode version of password */
	UTF16 *passwordBuf = saved_key[idx];
	int passwordBufSize = saved_len[idx];
	int hashSize = cur_salt->keySize >> 3;
	uint32_t inputBuf[(28 + 4) / sizeof(int)];
	uint32_t i;
	SHA_CTX ctx;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, cur_salt->salt, cur_salt->saltSize);
	SHA1_Update(&ctx, passwordBuf, passwordBufSize);
	SHA1_Final(hashBuf[0], &ctx);

	/* Generate each hash in turn
	 * H(n) = H(i, H(n-1))
	 * hashBuf = SHA1Hash(i, hashBuf); */

	// Create a byte array of the integer and put at the front of the input buffer
	// 1.3.6 says that little-endian byte ordering is expected
	memcpy(&inputBuf[1], hashBuf[0], 20);
	for (i = 0; i < cur_salt->spinCount; i++) {
#if ARCH_LITTLE_ENDIAN
		*inputBuf = i;
#else
		*inputBuf = JOHNSWAP(i);
#endif
		// 'append' the previously generated hash to the input buffer
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, inputBuf, 0x14 + 0x04);
		SHA1_Final((uint8_t*)&inputBuf[1], &ctx);
	}
	// Finally, append "block" (0) to H(n)
	memcpy(&inputBuf[6], encryptedVerifierHashInputBlockKey, 8);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, &inputBuf[1], 28);
	SHA1_Final(hashBuf[0], &ctx);

	// And second "block" (0) to H(n)
	memcpy(&inputBuf[6], encryptedVerifierHashValueBlockKey, 8);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, &inputBuf[1], 28);
	SHA1_Final(&hashBuf[0][32], &ctx);

	// Fix up the size per the spec
	if (hashSize > 20) { // FIXME: Is this ever true?
		for (i = 20; i < hashSize; i++) {
			hashBuf[0][i] = 0x36;
			hashBuf[0][32 + i] = 0x36;
		}
	}
}
#endif

#ifdef SIMD_COEF_64
static void GenerateAgileEncryptionKey512(int idx, uint8_t hashBuf[SHA512_LOOP_CNT][128])
{
	uint8_t tmpBuf[64], *keys;
	uint32_t i, j, k;
	SHA512_CTX ctx;
	uint8_t _IBuf[128 * SHA512_LOOP_CNT + MEM_ALIGN_CACHE];
	uint8_t _OBuf[64 * SHA512_LOOP_CNT + MEM_ALIGN_CACHE];
	uint64_t *keys64, (*crypt)[64 / 8];
	uint32_t *keys32, *crypt32;

	crypt = (void*)mem_align(_OBuf, MEM_ALIGN_CACHE);
	keys = (uint8_t*)mem_align(_IBuf, MEM_ALIGN_CACHE);
	keys64 = (uint64_t*)keys;
	keys32 = (uint32_t*)keys;
	crypt32 = (uint32_t*)crypt;

	memset(keys, 0, 128 * SHA512_LOOP_CNT);
	for (i = 0; i < SHA512_LOOP_CNT; i++) {
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, cur_salt->salt, cur_salt->saltSize);
		SHA512_Update(&ctx, saved_key[idx + i], saved_len[idx + i]);
		SHA512_Final(tmpBuf, &ctx);
		for (j = 4; j < 68; j++)
			keys[GETPOS_512(j, i)] = tmpBuf[j - 4];
		keys[GETPOS_512(j, i)] = 0x80;
		// 68 bytes of crypt data (0x220 bits).
		keys[GETPOS_512(127, i)] = 0x20;
		keys[GETPOS_512(126, i)] = 0x02;
	}

	// we do 1 less than actual number of iterations here.
	for (i = 0; i < cur_salt->spinCount - 1; i++) {

		// Iteration counter in first 4 bytes
		for (j = 0; j < SHA512_LOOP_CNT; j++) {
			keys[GETPOS_512(0, j)] = i & 0xFF;
			keys[GETPOS_512(1, j)] = (i >> 8) & 0xFF;
			keys[GETPOS_512(2, j)] = (i >> 16) & 0xFF;
			keys[GETPOS_512(3, j)] = (i >> 24) & 0xFF;
		}

		SIMDSHA512body(keys, (uint64_t*)crypt, NULL, SSEi_MIXED_IN);

		// Then we output to 4 bytes past start of input buffer.
		for (j = 0; j < SHA512_LOOP_CNT; j++) {
			uint32_t *o = keys32 + (j & (SIMD_COEF_64 - 1)) * 2 +
				j / SIMD_COEF_64 * 2 * SHA_BUF_SIZ * SIMD_COEF_64;
			uint32_t *in = crypt32 + (j & (SIMD_COEF_64 - 1)) * 2 +
				j / SIMD_COEF_64 * 2 * 8 * SIMD_COEF_64;

			for (k = 0; k < 8; k++) {
#if ARCH_LITTLE_ENDIAN==1
				o[0] = in[1];
				o += SIMD_COEF_64 * 2;
				o[1] = in[0];
				in += SIMD_COEF_64 * 2;
#else
				o[1] = in[0];
				o += SIMD_COEF_64 * 2;
				o[0] = in[1];
				in += SIMD_COEF_64 * 2;
#endif
			}
		}
	}
	// last iteration is output to start of input buffer, then 32 bit 0 appended.
	// but this is still ends up being 24 bytes of crypt data.
	for (j = 0; j < SHA512_LOOP_CNT; j++) {
		keys[GETPOS_512(0, j)] = i & 0xff;
		keys[GETPOS_512(1, j)] = (i >> 8) & 0xff;
		keys[GETPOS_512(2, j)] = i >> 16;
	}
	SIMDSHA512body(keys, keys64, NULL, SSEi_MIXED_IN | SSEi_OUTPUT_AS_INP_FMT);

	// Finally, append "block" (0) to H(n)
	for (i = 0; i < SHA512_LOOP_CNT; i++) {
		for (j = 0; j < 8; j++)
			keys[GETPOS_512(64 + j, i)] = encryptedVerifierHashInputBlockKey[j];
		keys[GETPOS_512(64 + j, i)] = 0x80;
		// 72 bytes of crypt data (0x240  we already have 0x220 here)
		keys[GETPOS_512(127, i)] = 0x40;
	}
	SIMDSHA512body(keys, (uint64_t*)crypt, NULL, SSEi_MIXED_IN | SSEi_FLAT_OUT);
	for (i = 0; i < SHA512_LOOP_CNT; i++)
		memcpy((uint64_t*)(hashBuf[i]), crypt[i], 64);

	// And second "block" (0) to H(n)
	for (i = 0; i < SHA512_LOOP_CNT; i++) {
		for (j = 0; j < 8; j++)
			keys[GETPOS_512(64 + j, i)] = encryptedVerifierHashValueBlockKey[j];
	}
	SIMDSHA512body(keys, (uint64_t*)crypt, NULL, SSEi_MIXED_IN | SSEi_FLAT_OUT);

	for (i = 0; i < SHA512_LOOP_CNT; i++)
		memcpy((uint64_t*)(&hashBuf[i][64]), crypt[i], 64);
}
#else
static void GenerateAgileEncryptionKey512(int idx, uint8_t hashBuf[SHA512_LOOP_CNT][128])
{
	UTF16 *passwordBuf = saved_key[idx];
	int passwordBufSize = saved_len[idx];
	uint32_t inputBuf[128 / sizeof(int)];
	int i;
	SHA512_CTX ctx;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, cur_salt->salt, cur_salt->saltSize);
	SHA512_Update(&ctx, passwordBuf, passwordBufSize);
	SHA512_Final(hashBuf[0], &ctx);

	// Create a byte array of the integer and put at the front of the input buffer
	// 1.3.6 says that little-endian byte ordering is expected
	memcpy(&inputBuf[1], hashBuf, 64);
	for (i = 0; i < cur_salt->spinCount; i++) {
#if ARCH_LITTLE_ENDIAN
		*inputBuf = i;
#else
		*inputBuf = JOHNSWAP(i);
#endif
		// 'append' the previously generated hash to the input buffer
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, inputBuf, 64 + 0x04);
		SHA512_Final((uint8_t*)&inputBuf[1], &ctx);
	}

	// Finally, append "block" (0) to H(n)
	memcpy(&inputBuf[68 / 4], encryptedVerifierHashInputBlockKey, 8);
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, &inputBuf[1], 64 + 8);
	SHA512_Final(hashBuf[0], &ctx);
	// And second "block" (0) to H(n)
	memcpy(&inputBuf[68 / 4], encryptedVerifierHashValueBlockKey, 8);
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, &inputBuf[1], 64 + 8);
	SHA512_Final(&hashBuf[0][64], &ctx);
}
#endif

static void set_salt(void *salt)
{
	cur_salt = (ms_office_custom_salt *)salt;
}

static void
DecryptUsingSymmetricKeyAlgorithm(ms_office_custom_salt *cur_salt,
                                  uint8_t *verifierInputKey,
                                  uint8_t *encryptedVerifier,
                                  const uint8_t *decryptedVerifier,
                                  int length)
{
	uint8_t iv[32];
	AES_KEY akey;

	memcpy(iv, cur_salt->salt, 16);
	memset(&iv[16], 0, 16);
	AES_set_decrypt_key(verifierInputKey, cur_salt->keySize, &akey);
	AES_cbc_encrypt(encryptedVerifier, (uint8_t*)decryptedVerifier,
	                length, &akey, iv, AES_DECRYPT);
}

static int PasswordVerifier(ms_office_binary_blob *blob, uint8_t *key)
{
	uint8_t decryptedVerifier[16];
	uint8_t decryptedVerifierHash[16];
	AES_KEY akey;
	SHA_CTX ctx;
	uint8_t checkHash[20];

	AES_set_decrypt_key(key, cur_salt->keySize, &akey);
	AES_ecb_encrypt(blob->encryptedVerifier, decryptedVerifier,
	                &akey, AES_DECRYPT);

	AES_set_decrypt_key(key, cur_salt->keySize, &akey);
	AES_ecb_encrypt(blob->encryptedVerifierHash, decryptedVerifierHash,
	                &akey, AES_DECRYPT);

	/* find SHA1 hash of decryptedVerifier */
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, decryptedVerifier, 16);
	SHA1_Final(checkHash, &ctx);

	return !memcmp(checkHash, decryptedVerifierHash, 16);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	const int inc =
		(cur_salt->version == 2013) ? SHA512_LOOP_CNT : SHA1_LOOP_CNT;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += inc) {
		if (cur_salt->version == 2007)
			GeneratePasswordHashUsingSHA1(index, &encryptionKey[index]);
		else if (cur_salt->version == 2010)
			GenerateAgileEncryptionKey(index, &verifierKeys1[index]);
		else //if (cur_salt->version == 2013)
			GenerateAgileEncryptionKey512(index, &verifierKeys512[index]);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	ms_office_binary_blob *blob = ((fmt_data*)binary)->blob;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		if (cur_salt->version == 2007)
			cracked[index] = PasswordVerifier(blob, encryptionKey[index]);
		else if (cur_salt->version == 2010) {
			uint8_t decryptedVerifierHashInputBytes[16];
			uint8_t decryptedVerifierHashBytes[32];
			uint8_t hash[20];
			SHA_CTX ctx;

			DecryptUsingSymmetricKeyAlgorithm(cur_salt, verifierKeys1[index],
			                                  blob->encryptedVerifier,
			                                  decryptedVerifierHashInputBytes,
			                                  16);
			DecryptUsingSymmetricKeyAlgorithm(cur_salt,
			                                  &verifierKeys1[index][32],
			                                  blob->encryptedVerifierHash,
			                                  decryptedVerifierHashBytes, 32);
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, decryptedVerifierHashInputBytes, 16);
			SHA1_Final(hash, &ctx);

			cracked[index] = !memcmp(hash, decryptedVerifierHashBytes, 20);
		}
		else /* if (cur_salt->version == 2013) */ {
			uint8_t decryptedVerifierHashInputBytes[16];
			uint8_t decryptedVerifierHashBytes[32];
			uint8_t hash[64];
			SHA512_CTX ctx;

			DecryptUsingSymmetricKeyAlgorithm(cur_salt, verifierKeys512[index],
			                                  blob->encryptedVerifier,
			                                  decryptedVerifierHashInputBytes,
			                                  16);
			DecryptUsingSymmetricKeyAlgorithm(cur_salt,
			                                  &verifierKeys512[index][64],
			                                  blob->encryptedVerifierHash,
			                                  decryptedVerifierHashBytes, 32);
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, decryptedVerifierHashInputBytes, 16);
			SHA512_Final(hash, &ctx);

			cracked[index] = !memcmp(hash, decryptedVerifierHashBytes, 20);
		}
	}

	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	/* convert key to UTF-16LE */
	saved_len[index] = enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH,
	                                (UTF8*)key, strlen(key));
	if (saved_len[index] < 0)
		saved_len[index] = strlen16(saved_key[index]);
	saved_len[index] <<= 1;
}

static char *get_key(int index)
{
	return (char*)utf16_to_enc(saved_key[index]);
}

struct fmt_main fmt_office = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_ENC | FMT_BLOB,
		{
			"MS Office version",
			"iteration count",
		},
		{ FORMAT_TAG_OFFICE },
		office_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		ms_office_common_valid,
		fmt_default_split,
		ms_office_common_binary,
		ms_office_common_get_salt,
		{
			ms_office_common_version,
			ms_office_common_iteration_count,
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
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

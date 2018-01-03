/*
 * Office 2007 cracker patch for JtR. Hacked together during March of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
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
#ifndef OMP_SCALE
#define OMP_SCALE                4
#endif
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
#include "memdbg.h"

#define FORMAT_LABEL             "Office"
#define FORMAT_NAME              "2007/2010/2013"
#define ALGORITHM_NAME           "SHA1 " SHA1_ALGORITHM_NAME " / SHA512 " SHA512_ALGORITHM_NAME " AES"
#define BENCHMARK_COMMENT        ""
#define BENCHMARK_LENGTH         -1
#define PLAINTEXT_LENGTH         125
#define BINARY_SIZE              16
#define SALT_SIZE                sizeof(*cur_salt)
#define BINARY_ALIGN             4
#define SALT_ALIGN               sizeof(int)
#ifdef SIMD_COEF_32
#define GETPOS_512W(i, index)    ( (index&(SIMD_COEF_64-1))*8 + ((i*8)&(0xffffffff-7))*SIMD_COEF_64 + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
#define GETOUTPOS_512W(i, index) ( (index&(SIMD_COEF_64-1))*8 + ((i*8)&(0xffffffff-7))*SIMD_COEF_64 + (unsigned int)index/SIMD_COEF_64*8*SIMD_COEF_64*8 )
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS_1(i, index)       ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 )
#define GETPOS_512(i, index)     ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
#define GETOUTPOS_512(i, index)  ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + (unsigned int)index/SIMD_COEF_64*8*SIMD_COEF_64*8 )
#else
#define GETPOS_1(i, index)       ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 )
#define GETPOS_512(i, index)     ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + ((i)&7) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
#define GETOUTPOS_512(i, index)  ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + ((i)&7) + (unsigned int)index/SIMD_COEF_64*8*SIMD_COEF_64*8 )
#endif
#define SHA1_LOOP_CNT            (SIMD_COEF_32*SIMD_PARA_SHA1)
#define SHA512_LOOP_CNT          (SIMD_COEF_64 * SIMD_PARA_SHA512)
#define MIN_KEYS_PER_CRYPT       (SIMD_COEF_32 * SIMD_PARA_SHA1 * SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT       (SIMD_COEF_32 * SIMD_PARA_SHA1 * SIMD_PARA_SHA512)
#else
#define SHA1_LOOP_CNT            1
#define SHA512_LOOP_CNT          1
#define MIN_KEYS_PER_CRYPT       1
#define MAX_KEYS_PER_CRYPT       1
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

	{NULL}
};

static ms_office_custom_salt *cur_salt;

#define MS_OFFICE_2007_ITERATIONS	50000

/* Password encoded in UCS-2 */
static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
/* UCS-2 password length, in octets */
static int *saved_len;
static uint32_t (*crypt_key)[4];
static int *cracked;

/* Office 2010/2013 */
static const unsigned char encryptedVerifierHashInputBlockKey[] = { 0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79 };
static const unsigned char encryptedVerifierHashValueBlockKey[] = { 0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e };

static unsigned char *DeriveKey(unsigned char *hashValue, unsigned char *X1)
{
	int i;
	unsigned char derivedKey[64];
	SHA_CTX ctx;

	// This is step 4a in 2.3.4.7 of MS_OFFCRYPT version 1.0
	// and is required even though the notes say it should be
	// used only when the encryption algorithm key > hash length.
	for (i = 0; i < 64; i++)
		derivedKey[i] = (i < 20 ? 0x36 ^ hashValue[i] : 0x36);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, derivedKey, 64);
	SHA1_Final(X1, &ctx);

	if (cur_salt->verifierHashSize > cur_salt->keySize/8)
		return X1;

	/* TODO: finish up this function */
	//for (i = 0; i < 64; i++)
	//	derivedKey[i] = (i < 30 ? 0x5C ^ hashValue[i] : 0x5C);

	fprintf(stderr, "\n\n*** ERROR: DeriveKey() entered Limbo.\n");
	fprintf(stderr, "Please report to john-dev mailing list.\n");
	error();

	return NULL;
}

#ifdef SIMD_COEF_32
static void GeneratePasswordHashUsingSHA1(int idx, unsigned char final[SHA1_LOOP_CNT][20])
{
	unsigned char hashBuf[20];
	/* H(0) = H(salt, password)
	 * hashBuf = SHA1Hash(salt, password);
	 * create input buffer for SHA1 from salt and unicode version of password */
	unsigned char X1[20];
	SHA_CTX ctx;
	unsigned char _IBuf[64*SHA1_LOOP_CNT+MEM_ALIGN_CACHE], *keys;
	uint32_t *keys32;
	unsigned i, j;

	keys = (unsigned char*)mem_align(_IBuf, MEM_ALIGN_CACHE);
	keys32 = (uint32_t*)keys;
	memset(keys, 0, 64*SHA1_LOOP_CNT);

	for (i = 0; i < SHA1_LOOP_CNT; ++i) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, cur_salt->osalt, cur_salt->saltSize);
		SHA1_Update(&ctx, saved_key[idx+i], saved_len[idx+i]);
		SHA1_Final(hashBuf, &ctx);

		/* Generate each hash in turn
		 * H(n) = H(i, H(n-1))
		 * hashBuf = SHA1Hash(i, hashBuf); */

		// Create a byte array of the integer and put at the front of the input buffer
		// 1.3.6 says that little-endian byte ordering is expected
		for (j = 4; j < 24; ++j)
			keys[GETPOS_1(j, i)] = hashBuf[j-4];
		keys[GETPOS_1(j, i)] = 0x80;
		// 24 bytes of crypt data (192 bits).
		keys[GETPOS_1(63, i)] = 192;
	}
	// we do 1 less than actual number of iterations here.
	for (i = 0; i < MS_OFFICE_2007_ITERATIONS-1; i++) {
		for (j = 0; j < SHA1_LOOP_CNT; ++j) {
			keys[GETPOS_1(0, j)] = i&0xff;
			keys[GETPOS_1(1, j)] = i>>8;
		}
		// Here we output to 4 bytes past start of input buffer.
		SIMDSHA1body(keys, &keys32[SIMD_COEF_32], NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);
	}
	// last iteration is output to start of input buffer, then 32 bit 0 appended.
	// but this is still ends up being 24 bytes of crypt data.
	for (j = 0; j < SHA1_LOOP_CNT; ++j) {
		keys[GETPOS_1(0, j)] = i&0xff;
		keys[GETPOS_1(1, j)] = i>>8;
	}
	SIMDSHA1body(keys, keys32, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);

	// Finally, append "block" (0) to H(n)
	// hashBuf = SHA1Hash(hashBuf, 0);
	for (i = 0; i < SHA1_LOOP_CNT; ++i) {
		keys[GETPOS_1(20,i)] = 0;
		keys[GETPOS_1(21,i)] = 0;
		keys[GETPOS_1(22,i)] = 0;
		keys[GETPOS_1(23,i)] = 0;
	}

	SIMDSHA1body(keys, keys32, NULL, SSEi_MIXED_IN|SSEi_FLAT_OUT);

	// Now convert back into a 'flat' value, which is a flat array.
	for (i = 0; i < SHA1_LOOP_CNT; ++i)
		memcpy(final[i], DeriveKey(&keys[20*i], X1), cur_salt->keySize/8);
}
#else
// for non MMX, SHA1_LOOP_CNT is 1
static void GeneratePasswordHashUsingSHA1(int idx, unsigned char final[SHA1_LOOP_CNT][20])
{
	unsigned char hashBuf[20], *key;
	UTF16 *passwordBuf=saved_key[idx];
	int passwordBufSize=saved_len[idx];
	/* H(0) = H(salt, password)
	 * hashBuf = SHA1Hash(salt, password);
	 * create input buffer for SHA1 from salt and unicode version of password */
	unsigned int inputBuf[(0x14 + 0x04 + 4) / sizeof(int)];
	unsigned char X1[20];
	int i;
	SHA_CTX ctx;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, cur_salt->osalt, cur_salt->saltSize);
	SHA1_Update(&ctx, passwordBuf, passwordBufSize);
	SHA1_Final(hashBuf, &ctx);

	/* Generate each hash in turn
	 * H(n) = H(i, H(n-1))
	 * hashBuf = SHA1Hash(i, hashBuf); */

	// Create a byte array of the integer and put at the front of the input buffer
	// 1.3.6 says that little-endian byte ordering is expected
	memcpy(&inputBuf[1], hashBuf, 20);
	for (i = 0; i < MS_OFFICE_2007_ITERATIONS; i++) {
#if ARCH_LITTLE_ENDIAN
		*inputBuf = i;
#else
		*inputBuf = JOHNSWAP(i);
#endif
		// 'append' the previously generated hash to the input buffer
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, inputBuf, 0x14 + 0x04);
		SHA1_Final((unsigned char*)&inputBuf[1], &ctx);
	}
	// Finally, append "block" (0) to H(n)
	// hashBuf = SHA1Hash(hashBuf, 0);
	memset(&inputBuf[6], 0, 4);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, &inputBuf[1], 0x14 + 0x04);
	SHA1_Final(hashBuf, &ctx);

	key = DeriveKey(hashBuf, X1);

	// Should handle the case of longer key lengths as shown in 2.3.4.9
	// Grab the key length bytes of the final hash as the encrypytion key
	memcpy(final[0], key, cur_salt->keySize/8);
}
#endif

#ifdef SIMD_COEF_32
static void GenerateAgileEncryptionKey(int idx, unsigned char hashBuf[SHA1_LOOP_CNT][64])
{
	unsigned char tmpBuf[20];
	int hashSize = cur_salt->keySize >> 3;
	unsigned i, j;
	SHA_CTX ctx;
	unsigned char _IBuf[64*SHA1_LOOP_CNT+MEM_ALIGN_CACHE], *keys,
	              _OBuf[20*SHA1_LOOP_CNT+MEM_ALIGN_CACHE];
	uint32_t *keys32, (*crypt)[20/4];

	crypt = (void*)mem_align(_OBuf, MEM_ALIGN_CACHE);
	keys = (unsigned char*)mem_align(_IBuf, MEM_ALIGN_CACHE);
	keys32 = (uint32_t*)keys;
	memset(keys, 0, 64*SHA1_LOOP_CNT);

	for (i = 0; i < SHA1_LOOP_CNT; ++i) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, cur_salt->osalt, cur_salt->saltSize);
		SHA1_Update(&ctx, saved_key[idx+i], saved_len[idx+i]);
		SHA1_Final(tmpBuf, &ctx);
		for (j = 4; j < 24; ++j)
			keys[GETPOS_1(j, i)] = tmpBuf[j-4];
		keys[GETPOS_1(j, i)] = 0x80;
		// 24 bytes of crypt data (192 bits).
		keys[GETPOS_1(63, i)] = 192;
	}

	// we do 1 less than actual number of iterations here.
	for (i = 0; i < cur_salt->spinCount-1; i++) {
		for (j = 0; j < SHA1_LOOP_CNT; ++j) {
			keys[GETPOS_1(0, j)] = i&0xff;
			keys[GETPOS_1(1, j)] = (i>>8)&0xff;
			keys[GETPOS_1(2, j)] = i>>16;
		}
		// Here we output to 4 bytes past start of input buffer.
		SIMDSHA1body(keys, &keys32[SIMD_COEF_32], NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);
	}
	// last iteration is output to start of input buffer, then 32 bit 0 appended.
	// but this is still ends up being 24 bytes of crypt data.
	for (j = 0; j < SHA1_LOOP_CNT; ++j) {
		keys[GETPOS_1(0, j)] = i&0xff;
		keys[GETPOS_1(1, j)] = (i>>8)&0xff;
		keys[GETPOS_1(2, j)] = i>>16;
	}
	SIMDSHA1body(keys, keys32, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);

	// Finally, append "block" (0) to H(n)
	for (i = 0; i < SHA1_LOOP_CNT; ++i) {
		for (j = 0; j < 8; ++j)
			keys[GETPOS_1(20+j, i)] = encryptedVerifierHashInputBlockKey[j];
		keys[GETPOS_1(20+j, i)] = 0x80;
		// 28 bytes of crypt data (192 bits).
		keys[GETPOS_1(63, i)] = 224;
	}
	SIMDSHA1body(keys, (uint32_t*)crypt, NULL, SSEi_MIXED_IN|SSEi_FLAT_OUT);
	for (i = 0; i < SHA1_LOOP_CNT; ++i)
		memcpy(hashBuf[i], crypt[i], 20);

	// And second "block" (0) to H(n)
	for (i = 0; i < SHA1_LOOP_CNT; ++i) {
		for (j = 0; j < 8; ++j)
			keys[GETPOS_1(20+j, i)] = encryptedVerifierHashValueBlockKey[j];
	}
	SIMDSHA1body(keys, (uint32_t*)crypt, NULL, SSEi_MIXED_IN|SSEi_FLAT_OUT);
	for (i = 0; i < SHA1_LOOP_CNT; ++i)
		memcpy(&hashBuf[i][32], crypt[i], 20);

	// Fix up the size per the spec
	if (20 < hashSize) { // FIXME: Is this ever true?
		for (i = 0; i < SHA1_LOOP_CNT; ++i) {
			for (j = 20; j < hashSize; j++) {
				hashBuf[i][j] = 0x36;
				hashBuf[i][32 + j] = 0x36;
			}
		}
	}
}
#else
static void GenerateAgileEncryptionKey(int idx, unsigned char hashBuf[SHA1_LOOP_CNT][64])
{
	/* H(0) = H(salt, password)
	 * hashBuf = SHA1Hash(salt, password);
	 * create input buffer for SHA1 from salt and unicode version of password */
	UTF16 *passwordBuf=saved_key[idx];
	int passwordBufSize=saved_len[idx];
	int hashSize = cur_salt->keySize >> 3;
	unsigned int inputBuf[(28 + 4) / sizeof(int)];
	unsigned int i;
	SHA_CTX ctx;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, cur_salt->osalt, cur_salt->saltSize);
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
		SHA1_Final((unsigned char*)&inputBuf[1], &ctx);
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
	if (20 < hashSize) { // FIXME: Is this ever true?
		for (i = 20; i < hashSize; i++) {
			hashBuf[0][i] = 0x36;
			hashBuf[0][32 + i] = 0x36;
		}
	}
}
#endif

#ifdef SIMD_COEF_64
static void GenerateAgileEncryptionKey512(int idx, unsigned char hashBuf[SHA512_LOOP_CNT][128])
{
	unsigned char tmpBuf[64];
	unsigned int i, j, k;
	SHA512_CTX ctx;
	unsigned char _IBuf[128*SHA512_LOOP_CNT+MEM_ALIGN_CACHE], *keys,
	              _OBuf[64*SHA512_LOOP_CNT+MEM_ALIGN_CACHE];
	uint64_t *keys64, (*crypt)[64/8];
	uint32_t *keys32, *crypt32;

	crypt = (void*)mem_align(_OBuf, MEM_ALIGN_CACHE);
	keys = (unsigned char*)mem_align(_IBuf, MEM_ALIGN_CACHE);
	keys64 = (uint64_t*)keys;
	keys32 = (uint32_t*)keys;
	crypt32 = (uint32_t*)crypt;

	memset(keys, 0, 128*SHA512_LOOP_CNT);
	for (i = 0; i < SHA512_LOOP_CNT; ++i) {
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, cur_salt->osalt, cur_salt->saltSize);
		SHA512_Update(&ctx, saved_key[idx+i], saved_len[idx+i]);
		SHA512_Final(tmpBuf, &ctx);
		for (j = 4; j < 68; ++j)
			keys[GETPOS_512(j, i)] = tmpBuf[j-4];
		keys[GETPOS_512(j, i)] = 0x80;
		// 68 bytes of crypt data (0x220 bits).
		keys[GETPOS_512(127, i)] = 0x20;
		keys[GETPOS_512(126, i)] = 0x02;
	}

	// we do 1 less than actual number of iterations here.
	for (i = 0; i < cur_salt->spinCount-1; i++) {

		// Iteration counter in first 4 bytes
		for (j = 0; j < SHA512_LOOP_CNT; j++) {
			keys[GETPOS_512(0, j)] = i & 0xFF;
			keys[GETPOS_512(1, j)] = (i>>8) & 0xFF;
			keys[GETPOS_512(2, j)] = (i>>16) & 0xFF;
			keys[GETPOS_512(3, j)] = (i>>24) & 0xFF;
		}

		SIMDSHA512body(keys, (uint64_t*)crypt, NULL, SSEi_MIXED_IN);

		// Then we output to 4 bytes past start of input buffer.

		/* Original code to copy in 64 bytes into offset 4.  Not BE compatible.
		for (j = 0; j < SHA512_LOOP_CNT; j++) {
			uint32_t *o = keys32 + (j&(SIMD_COEF_64-1))*2 + j/SIMD_COEF_64*2*SHA_BUF_SIZ*SIMD_COEF_64;
			uint32_t *in = crypt32 + (j&(SIMD_COEF_64-1))*2 + j/SIMD_COEF_64*2*8*SIMD_COEF_64;

			for (k = 0; k < 8; k++) {
				o[0] = in[1];
				o += SIMD_COEF_64*2;
				o[1] = in[0];
				in += SIMD_COEF_64*2;
			}
		}
		*/

		/* First shot: works good, not endianity bound, but is SLOWER (1/2 speed)
		for (j = 0; j < SHA512_LOOP_CNT; j++) {
			for (k = 0; k < 64; k++) {
				keys[GETPOS_512((k+4), j)] = ((unsigned char*)crypt)[GETOUTPOS_512(k,j)];
			}
		}
		*/


		// tweaked original code, swapping uint32_t and this works.
		// it is very likely this code could be optimized even more, by handling data
		// in uint64_t items. First and last would still need handled in uint32, but
		// other 7 elements could be done by reading 2 8 byte values from crypt, shifting
		// and then placing at one time into input buffer.   I might look into doing that
		// and see if there is any improvement.  It may also be benefical to look at using
		// flat buffers here.  Flat buffers would be trivial.  a simple memcpy to move all
		// 64 bytes at once.  NOTE, in flat model, there is NO way to do this using any
		// 64 bit assignments. Either the input buffer, or the crypt buffer would not be
		// properly aligned.  So memcpy would have to be used. BUT it should be trivial
		// and may in the end be a faster solution, than keeping this code in mixed form.
		// but for now, it will be left as a task for someone else.
		for (j = 0; j < SHA512_LOOP_CNT; j++) {
			uint32_t *o = keys32 + (j&(SIMD_COEF_64-1))*2 + j/SIMD_COEF_64*2*SHA_BUF_SIZ*SIMD_COEF_64;
			uint32_t *in = crypt32 + (j&(SIMD_COEF_64-1))*2 + j/SIMD_COEF_64*2*8*SIMD_COEF_64;

			for (k = 0; k < 8; k++) {
#if ARCH_LITTLE_ENDIAN==1
				o[0] = in[1];
				o += SIMD_COEF_64*2;
				o[1] = in[0];
				in += SIMD_COEF_64*2;
#else
				o[1] = in[0];
				o += SIMD_COEF_64*2;
				o[0] = in[1];
				in += SIMD_COEF_64*2;
#endif
			}
		}
	}
	// last iteration is output to start of input buffer, then 32 bit 0 appended.
	// but this is still ends up being 24 bytes of crypt data.
	for (j = 0; j < SHA512_LOOP_CNT; ++j) {
		keys[GETPOS_512(0, j)] = i&0xff;
		keys[GETPOS_512(1, j)] = (i>>8)&0xff;
		keys[GETPOS_512(2, j)] = i>>16;
	}
	SIMDSHA512body(keys, keys64, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);

	// Finally, append "block" (0) to H(n)
	for (i = 0; i < SHA512_LOOP_CNT; ++i) {
		for (j = 0; j < 8; ++j)
			keys[GETPOS_512(64+j, i)] = encryptedVerifierHashInputBlockKey[j];
		keys[GETPOS_512(64+j, i)] = 0x80;
		// 72 bytes of crypt data (0x240  we already have 0x220 here)
		keys[GETPOS_512(127, i)] = 0x40;
	}
	SIMDSHA512body(keys, (uint64_t*)crypt, NULL, SSEi_MIXED_IN|SSEi_FLAT_OUT);
	for (i = 0; i < SHA512_LOOP_CNT; ++i)
		memcpy((uint64_t*)(hashBuf[i]), crypt[i], 64);

	// And second "block" (0) to H(n)
	for (i = 0; i < SHA512_LOOP_CNT; ++i) {
		for (j = 0; j < 8; ++j)
			keys[GETPOS_512(64+j, i)] = encryptedVerifierHashValueBlockKey[j];
	}
	SIMDSHA512body(keys, (uint64_t*)crypt, NULL, SSEi_MIXED_IN|SSEi_FLAT_OUT);

	for (i = 0; i < SHA512_LOOP_CNT; ++i)
		memcpy((uint64_t*)(&hashBuf[i][64]), crypt[i], 64);
}
#else
static void GenerateAgileEncryptionKey512(int idx, unsigned char hashBuf[SHA512_LOOP_CNT][128])
{
	UTF16 *passwordBuf=saved_key[idx];
	int passwordBufSize=saved_len[idx];
	unsigned int inputBuf[128 / sizeof(int)];
	int i;
	SHA512_CTX ctx;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, cur_salt->osalt, cur_salt->saltSize);
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
		SHA512_Final((unsigned char*)&inputBuf[1], &ctx);
	}

	// Finally, append "block" (0) to H(n)
	memcpy(&inputBuf[68/4], encryptedVerifierHashInputBlockKey, 8);
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, &inputBuf[1], 64 + 8);
	SHA512_Final(hashBuf[0], &ctx);
	// And second "block" (0) to H(n)
	memcpy(&inputBuf[68/4], encryptedVerifierHashValueBlockKey, 8);
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, &inputBuf[1], 64 + 8);
	SHA512_Final(&hashBuf[0][64], &ctx);
}
#endif

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_autotune(self, OMP_SCALE);
#endif
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_calloc(sizeof(*saved_len), self->params.max_keys_per_crypt);
	crypt_key = mem_calloc(sizeof(*crypt_key), self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	if (options.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, PLAINTEXT_LENGTH * 3);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(crypt_key);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = (ms_office_custom_salt *)salt;
}

static void DecryptUsingSymmetricKeyAlgorithm(ms_office_custom_salt *cur_salt, unsigned char *verifierInputKey, unsigned char *encryptedVerifier, const unsigned char *decryptedVerifier, int length)
{
	unsigned char iv[32];
	AES_KEY akey;

	memcpy(iv, cur_salt->osalt, 16);
	memset(&iv[16], 0, 16);
	memset(&akey, 0, sizeof(AES_KEY));
	AES_set_decrypt_key(verifierInputKey, cur_salt->keySize, &akey);
	AES_cbc_encrypt(encryptedVerifier, (unsigned char*)decryptedVerifier, length, &akey, iv, AES_DECRYPT);
}

// We now pass in the 16 byte 'output'. The older code has been kept, but
// it no longer used that way. We used to return the 'cracked' value, i.e.
// if it matched, return 1, else 0. Now we store the encryption data to out,
// and then in the format use normal binary_hash() methods to test it. The
// old method used decryption (of the encrypted field). Now we use encrption
// of the plaintext data, and then binary_hash() compares that to the known
// encrypted field data.
// For the time being, the original code has been kept (commented out). I am
// doing this in hopes of figuring out some way to salt-dupe correct the
// office 2010-2013 formats. I do not think they can be done, but I may be
// wrong, so I will keep this code in an "easy to see what changed" layout.
static void PasswordVerifier(ms_office_custom_salt *cur_salt, unsigned char *key, uint32_t *out)
{
	unsigned char decryptedVerifier[16];
	//unsigned char decryptedVerifierHash[16];
	AES_KEY akey;
	SHA_CTX ctx;
	unsigned char checkHash[32];
	unsigned char checkHashed[32];

	memset(&akey, 0, sizeof(AES_KEY));
	AES_set_decrypt_key(key, 128, &akey);
	AES_ecb_encrypt(cur_salt->encryptedVerifier, decryptedVerifier, &akey, AES_DECRYPT);

	// Not using cracked any more.
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, decryptedVerifier, 16);
	SHA1_Final(checkHash, &ctx);
	memset(&akey, 0, sizeof(AES_KEY));
	AES_set_encrypt_key(key, 128, &akey);
	AES_ecb_encrypt(checkHash, checkHashed, &akey, AES_ENCRYPT);
	memcpy(out, checkHashed, 16);

	//AES_set_decrypt_key(key, 128, &akey);
	//AES_ecb_encrypt(cur_salt->encryptedVerifierHash, decryptedVerifierHash, &akey, AES_DECRYPT);
	//
	///* find SHA1 hash of decryptedVerifier */
	//SHA1_Init(&ctx);
	//SHA1_Update(&ctx, decryptedVerifier, 16);
	//SHA1_Final(checkHash, &ctx);
	//
	//return !memcmp(checkHash, decryptedVerifierHash, 16);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0, inc = SHA1_LOOP_CNT;

	if (cur_salt->version == 2013)
		inc = SHA512_LOOP_CNT;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index+=inc)
	{
		int i;
		if (cur_salt->version == 2007) {
			unsigned char encryptionKey[SHA1_LOOP_CNT][20];
			GeneratePasswordHashUsingSHA1(index, encryptionKey);
			for (i = 0; i < SHA1_LOOP_CNT; ++i)
				PasswordVerifier(cur_salt, encryptionKey[i], crypt_key[index+i]);
		}
		else if (cur_salt->version == 2010) {
			unsigned char verifierKeys[SHA1_LOOP_CNT][64], decryptedVerifierHashInputBytes[16], decryptedVerifierHashBytes[32];
			unsigned char hash[20];
			SHA_CTX ctx;
			GenerateAgileEncryptionKey(index, verifierKeys);
			for (i = 0; i < inc; ++i) {
				DecryptUsingSymmetricKeyAlgorithm(cur_salt, verifierKeys[i], cur_salt->encryptedVerifier, decryptedVerifierHashInputBytes, 16);
				DecryptUsingSymmetricKeyAlgorithm(cur_salt, &verifierKeys[i][32], cur_salt->encryptedVerifierHash, decryptedVerifierHashBytes, 32);
				SHA1_Init(&ctx);
				SHA1_Update(&ctx, decryptedVerifierHashInputBytes, 16);
				SHA1_Final(hash, &ctx);
				cracked[index+i] = !memcmp(hash, decryptedVerifierHashBytes, 20);
			}
		}
		else if (cur_salt->version == 2013) {
			unsigned char verifierKeys[SHA512_LOOP_CNT][128], decryptedVerifierHashInputBytes[16], decryptedVerifierHashBytes[32];
			unsigned char hash[64];
			SHA512_CTX ctx;
			GenerateAgileEncryptionKey512(index, verifierKeys);
			for (i = 0; i < inc; ++i) {
				DecryptUsingSymmetricKeyAlgorithm(cur_salt, verifierKeys[i], cur_salt->encryptedVerifier, decryptedVerifierHashInputBytes, 16);
				DecryptUsingSymmetricKeyAlgorithm(cur_salt, &verifierKeys[i][64], cur_salt->encryptedVerifierHash, decryptedVerifierHashBytes, 32);
				SHA512_Init(&ctx);
				SHA512_Update(&ctx, decryptedVerifierHashInputBytes, 16);
				SHA512_Final(hash, &ctx);
				cracked[index+i] = !memcmp(hash, decryptedVerifierHashBytes, 20);
			}
		}
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;
	if (cur_salt->version == 2007) {
		for (index = 0; index < count; index++) {
			if ( ((uint32_t*)binary)[0] == crypt_key[index][0] )
				return 1;
		}
		return 0;
	}
	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	if (cur_salt->version == 2007) {
		return !memcmp(binary, crypt_key[index], BINARY_SIZE);
	}
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int get_hash_0(int index) { if (cur_salt->version!=2007) return 0; return crypt_key[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { if (cur_salt->version!=2007) return 0; return crypt_key[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { if (cur_salt->version!=2007) return 0; return crypt_key[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { if (cur_salt->version!=2007) return 0; return crypt_key[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { if (cur_salt->version!=2007) return 0; return crypt_key[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { if (cur_salt->version!=2007) return 0; return crypt_key[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { if (cur_salt->version!=2007) return 0; return crypt_key[index][0] & PH_MASK_6; }

static void office_set_key(char *key, int index)
{
	/* convert key to UTF-16LE */
	saved_len[index] = enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH, (UTF8*)key, strlen(key));
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_UTF8,
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
		office_set_key,
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

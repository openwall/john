/*
 * Copyright (c) 2010, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 *     * Neither the name of Intel Corporation nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
*/

#if (__cplusplus)
extern "C" {
#endif

#if AC_BUILT
#include "../../autoconfig.h"
#endif

#include "iaesni.h"
#include "iaes_asm_interface.h"

#if (__cplusplus)
}
#endif

#include <stdio.h>
#include <string.h>

#ifdef AC_BUILT
#include "../../autoconfig.h"
#endif

void intel_AES_enc128(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iEncExpandKey128(key,expandedKey);
	iEnc128(&aesData);
}


void intel_AES_enc128_CBC(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t numBlocks,UCHAR *iv)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iEncExpandKey128(key,expandedKey);
	iEnc128_CBC(&aesData);
}


void intel_AES_enc192(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iEncExpandKey192(key,expandedKey);
	iEnc192(&aesData);
}


void intel_AES_enc192_CBC(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t numBlocks,UCHAR *iv)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iEncExpandKey192(key,expandedKey);
	iEnc192_CBC(&aesData);
}


void intel_AES_enc256(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iEncExpandKey256(key,expandedKey);
	iEnc256(&aesData);
}


void intel_AES_enc256_CBC(UCHAR *plainText,UCHAR *cipherText,UCHAR *key,size_t numBlocks,UCHAR *iv)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = plainText;
	aesData.out_block = cipherText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iEncExpandKey256(key,expandedKey);
	iEnc256_CBC(&aesData);
}


void intel_AES_dec128(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iDecExpandKey128(key,expandedKey);
	iDec128(&aesData);
}

void intel_AES_dec128_CBC(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t numBlocks,UCHAR *iv)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iDecExpandKey128(key,expandedKey);
	iDec128_CBC(&aesData);
}


void intel_AES_dec192(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iDecExpandKey192(key,expandedKey);
	iDec192(&aesData);
}


void intel_AES_dec192_CBC(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t numBlocks,UCHAR *iv)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iDecExpandKey192(key,expandedKey);
	iDec192_CBC(&aesData);
}


void intel_AES_dec256(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t numBlocks)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;

	iDecExpandKey256(key,expandedKey);
	iDec256(&aesData);
}


void intel_AES_dec256_CBC(UCHAR *cipherText,UCHAR *plainText,UCHAR *key,size_t numBlocks,UCHAR *iv)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = cipherText;
	aesData.out_block = plainText;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = iv;

	iDecExpandKey256(key,expandedKey);
	iDec256_CBC(&aesData);
}



void intel_AES_encdec256_CTR(UCHAR *in,UCHAR *out,UCHAR *key,size_t numBlocks,UCHAR *ic)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = in;
	aesData.out_block = out;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = ic;

	iEncExpandKey256(key,expandedKey);
	iEnc256_CTR(&aesData);
}

void intel_AES_encdec192_CTR(UCHAR *in,UCHAR *out,UCHAR *key,size_t numBlocks,UCHAR *ic)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = in;
	aesData.out_block = out;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = ic;

	iEncExpandKey192(key,expandedKey);
	iEnc192_CTR(&aesData);
}

void intel_AES_encdec128_CTR(UCHAR *in,UCHAR *out,UCHAR *key,size_t numBlocks,UCHAR *ic)
{
	DEFINE_ROUND_KEYS
	sAesData aesData;
	aesData.in_block = in;
	aesData.out_block = out;
	aesData.expanded_key = expandedKey;
	aesData.num_blocks = numBlocks;
	aesData.iv = ic;

	iEncExpandKey128(key,expandedKey);
	iEnc128_CTR(&aesData);
}



#if HAVE_INTRIN_H

#include <intrin.h>

#elif __i386__

// FIXME: Implement this correctly. Currently always returns "no"

static void __cpuid(unsigned int where[4], unsigned int leaf) {
//  asm volatile("cpuid":"=a"(*where), "=c"(*(where+2)),"=d"(*(where+3)):"a"(leaf));
	where[2] = 0;
  return;
}

#else

static void __cpuid(unsigned int where[4], unsigned int leaf) {
  asm volatile("cpuid":"=a"(*where),"=b"(*(where+1)), "=c"(*(where+2)),"=d"(*(where+3)):"a"(leaf));
  return;
}
#endif

/*
 * check_for_aes_instructions()
 *   return 1 if support AES-NI and 0 if don't support AES-NI
 */

int check_for_aes_instructions()
{
	unsigned int cpuid_results[4];
	int yes=1, no=0;

	// Removed checks for Intel CPU -HN

	__cpuid(cpuid_results,1);

	if (cpuid_results[2] & AES_INSTRCTIONS_CPUID_BIT)
		return yes;

	return no;
}

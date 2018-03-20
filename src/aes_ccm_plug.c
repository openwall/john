/*
 *  NIST SP800-38C compliant CCM implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * Definition of CCM:
 * http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf
 * RFC 3610 "Counter with CBC-MAC (CCM)"
 *
 * Related:
 * RFC 5116 "An Interface and Algorithms for Authenticated Encryption"
 */


#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "aes.h"
#include "aes_ccm.h"

#define CCM_ENCRYPT 0
#define CCM_DECRYPT 1

/*
 * Update the CBC-MAC state in y using a block in b
 * (Always using b as the source helps the compiler optimise a bit better.)
 */
#define UPDATE_CBC_MAC \
	for ( i = 0; i < 16; i++ ) \
		y[i] ^= b[i]; \
	AES_ecb_encrypt(y, y, ctx, AES_ENCRYPT);

/*
 * Encrypt or decrypt a partial block with CTR
 * Warning: using b for temporary storage! src and dst must not be b!
 * This avoids allocating one more 16 bytes buffer while allowing src == dst.
 */
#define CTR_CRYPT(dst, src, len) \
	AES_ecb_encrypt(ctr, b, ctx, AES_ENCRYPT); \
	for ( i = 0; i < len; i++ ) \
		dst[i] = src[i] ^ b[i];

/*
 * Authenticated encryption or decryption
 */
static int ccm_auth_crypt(AES_KEY *ctx, int mode, size_t length, const unsigned
		char *iv, size_t iv_len, const unsigned char *add, size_t
		add_len, const unsigned char *input, unsigned char *output,
		unsigned char *tag, size_t tag_len)
{
	unsigned char i;
	unsigned char q;
	size_t len_left;
	unsigned char b[16];
	unsigned char y[16];
	unsigned char ctr[16];
	const unsigned char *src;
	unsigned char *dst;

	/*
	 * Check length requirements: SP800-38C A.1
	 * Additional requirement: a < 2^16 - 2^8 to simplify the code.
	 * 'length' checked later (when writing it to the first block)
	 */
	if (tag_len < 4 || tag_len > 16 || tag_len % 2 != 0)
		return MBEDTLS_ERR_CCM_BAD_INPUT;

	/* Also implies q is within bounds */
	if (iv_len < 7 || iv_len > 13)
		return MBEDTLS_ERR_CCM_BAD_INPUT;

	if (add_len > 0xFF00)
		return MBEDTLS_ERR_CCM_BAD_INPUT;

	q = 16 - 1 - (unsigned char) iv_len;

	/*
	 * First block B_0:
	 * 0        .. 0        flags
	 * 1        .. iv_len   nonce (aka iv)
	 * iv_len+1 .. 15       length
	 *
	 * With flags as (bits):
	 * 7        0
	 * 6        add present?
	 * 5 .. 3   (t - 2) / 2
	 * 2 .. 0   q - 1
	 */
	b[0] = 0;
	b[0] |= ( add_len > 0 ) << 6;
	b[0] |= ( ( tag_len - 2 ) / 2 ) << 3;
	b[0] |= q - 1;

	memcpy(b + 1, iv, iv_len);

	for (i = 0, len_left = length; i < q; i++, len_left >>= 8)
		b[15-i] = (unsigned char)(len_left & 0xFF);

	if (len_left > 0)
		return MBEDTLS_ERR_CCM_BAD_INPUT;


	/* Start CBC-MAC with first block */
	memset(y, 0, 16);
	UPDATE_CBC_MAC;

	/*
	 * If there is additional data, update CBC-MAC with
	 * add_len, add, 0 (padding to a block boundary)
	 */
	if (add_len > 0)
	{
		size_t use_len;
		len_left = add_len;
		src = add;

		memset( b, 0, 16 );
		b[0] = (unsigned char)( ( add_len >> 8 ) & 0xFF );
		b[1] = (unsigned char)( ( add_len      ) & 0xFF );

		use_len = len_left < 16 - 2 ? len_left : 16 - 2;
		memcpy( b + 2, src, use_len );
		len_left -= use_len;
		src += use_len;

		UPDATE_CBC_MAC;

		while (len_left > 0)
		{
			use_len = len_left > 16 ? 16 : len_left;

			memset(b, 0, 16);
			memcpy(b, src, use_len);
			UPDATE_CBC_MAC;

			len_left -= use_len;
			src += use_len;
		}
	}

	/*
	 * Prepare counter block for encryption:
	 * 0        .. 0        flags
	 * 1        .. iv_len   nonce (aka iv)
	 * iv_len+1 .. 15       counter (initially 1)
	 *
	 * With flags as (bits):
	 * 7 .. 3   0
	 * 2 .. 0   q - 1
	 */
	ctr[0] = q - 1;
	memcpy(ctr + 1, iv, iv_len);
	memset(ctr + 1 + iv_len, 0, q);
	ctr[15] = 1;

	/*
	 * Authenticate and {en,de}crypt the message.
	 *
	 * The only difference between encryption and decryption is
	 * the respective order of authentication and {en,de}cryption.
	 */
	len_left = length;
	src = input;
	dst = output;

	while (len_left > 0)
	{
		size_t use_len = len_left > 16 ? 16 : len_left;

		if (mode == CCM_ENCRYPT)
		{
			memset(b, 0, 16);
			memcpy(b, src, use_len);
			UPDATE_CBC_MAC;
		}

		CTR_CRYPT(dst, src, use_len);

		if (mode == CCM_DECRYPT)
		{
			memset(b, 0, 16);
			memcpy(b, dst, use_len);
			UPDATE_CBC_MAC;
		}

		dst += use_len;
		src += use_len;
		len_left -= use_len;

		/*
		 * Increment counter.
		 * No need to check for overflow thanks to the length check above.
		 */
		for (i = 0; i < q; i++)
			if (++ctr[15-i] != 0)
				break;
	}

	/*
	 * Authentication: reset counter and crypt/mask internal tag
	 */
	for (i = 0; i < q; i++)
		ctr[15-i] = 0;

	CTR_CRYPT(y, y, 16);
	memcpy(tag, y, tag_len);

	return 0;
}

/*
 * Authenticated encryption
 */
int aes_ccm_encrypt_and_tag(const unsigned char *key, int bits, size_t
		length, const unsigned char *iv, size_t iv_len, const unsigned
		char *add, size_t add_len, const unsigned char *input, unsigned
		char *output, unsigned char *tag, size_t tag_len)
{
	AES_KEY ctx;

	AES_set_encrypt_key(key, bits, &ctx);

	return ccm_auth_crypt(&ctx, CCM_ENCRYPT, length, iv, iv_len, add,
			add_len, input, output, tag, tag_len);
}

/*
 * Authenticated decryption
 */
int aes_ccm_auth_decrypt(const unsigned char *key, int bits, size_t length,
		const unsigned char *iv, size_t iv_len, const unsigned char
		*add, size_t add_len, const unsigned char *input, unsigned char
		*output, const unsigned char *tag, size_t tag_len)
{
	int ret;
	unsigned char check_tag[16];
	unsigned char i;
	int diff;
	AES_KEY ctx;

	AES_set_encrypt_key(key, bits, &ctx);

	if ((ret = ccm_auth_crypt(&ctx, CCM_DECRYPT, length, iv, iv_len, add,
					add_len, input, output, check_tag,
					tag_len)) != 0)
		return ret ;

	/* Check tag in "constant-time" */
	for (diff = 0, i = 0; i < tag_len; i++)
		diff |= tag[i] ^ check_tag[i];

	if (diff != 0)
		return MBEDTLS_ERR_CCM_AUTH_FAILED;

	return 0 ;
}

/* De- or encrypts a block of data using AES-CCM (Counter with CBC-MAC)
 * Note that the key must be set in encryption mode (LIBCAES_CRYPT_MODE_ENCRYPT) for both de- and encryption.
 *
 * This function is borrowed from libcaes which is under LGPLv3, https://github.com/libyal/libcaes.
 *
 * This function behaves differently than the standards-compliant functions in
 * PolarSSL, OpenSSL and SJCL. However it behaves like the AES CCM implementation
 * in Windows, and this is useful for us.
 */
int libcaes_crypt_ccm(unsigned char *key, int bits, int mode, const uint8_t
		*nonce, size_t nonce_size, const uint8_t *input_data, size_t
		input_data_size, uint8_t *output_data, size_t output_data_size)
{
	uint8_t block_data[16];
	uint8_t iiv[16]; // internal_initialization_vector
	size_t data_offset         = 0;
	size_t remaining_data_size = 0;
	uint8_t block_index        = 0;
	AES_KEY ctx;

	AES_set_encrypt_key(key, bits, &ctx);

	/*
	 * The IV consists of:
	 * 1 byte size value formatted as: 15 - nonce size - 1
	 * a maximum of 14 bytes containing nonce bytes
	 * 1 byte counter
	 */
	memset(iiv, 0, 16);
	memcpy(&(iiv[1]), nonce, nonce_size);
	iiv[0] = 15 - (uint8_t)nonce_size - 1;

	memcpy(output_data, input_data, input_data_size);
	while ((data_offset + 16 ) < input_data_size) {
		AES_ecb_encrypt(iiv, block_data, &ctx, AES_ENCRYPT);
		for (block_index = 0; block_index < 16; block_index++) {
			output_data[data_offset++] ^= block_data[block_index];
		}
		iiv[15] += 1;
	}
	if (data_offset < input_data_size)
	{
		remaining_data_size = input_data_size - data_offset;

		AES_ecb_encrypt(iiv, block_data, &ctx, AES_ENCRYPT);

		for (block_index = 0; block_index < (uint8_t)remaining_data_size; block_index++ ) {
			output_data[data_offset++] ^= block_data[block_index];
		}
	}

	return 1;
}

#if defined(CCM_DEBUG)
/*
 * Examples 1 to 3 from SP800-38C Appendix C
 */

#define NB_TESTS 3

/*
 * The data is the same for all tests, only the used length changes
 */

static const unsigned char key[] = {
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
};

static const unsigned char iv[] = {
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b
};

static const unsigned char ad[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13
};

static const unsigned char msg[] = {
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
};

static const size_t iv_len [NB_TESTS] = { 7, 8,  12 };
static const size_t add_len[NB_TESTS] = { 8, 16, 20 };
static const size_t msg_len[NB_TESTS] = { 4, 16, 24 };
static const size_t tag_len[NB_TESTS] = { 4, 6,  8  };

static const unsigned char res[NB_TESTS][32] = {
    {   0x71, 0x62, 0x01, 0x5b, 0x4d, 0xac, 0x25, 0x5d },
    {   0xd2, 0xa1, 0xf0, 0xe0, 0x51, 0xea, 0x5f, 0x62,
        0x08, 0x1a, 0x77, 0x92, 0x07, 0x3d, 0x59, 0x3d,
        0x1f, 0xc6, 0x4f, 0xbf, 0xac, 0xcd },
    {   0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a,
        0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97, 0xe7, 0x0b,
        0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5,
        0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0, 0x99, 0x51 }
};

// https://bitwiseshiftleft.github.io/sjcl/browserTest/
unsigned char nkey[] = { 176, 88, 210, 147, 31, 70, 171, 178, 166, 6, 42, 188, 221, 246, 29, 117 };
unsigned char niv[] = { 237, 119, 176, 228, 61, 172, 206, 192, 108, 65, 244, 114 }; // length 12
unsigned char npt[] = { 132, 156, 39, 215, 51, 63, 233, 251, 118, 151, 37, 176,
	242, 154, 107, 13, 151, 126, 80, 73, 118, 215, 9, 184, 182, 239, 84,
	46, 69, 85, 4, 162, 2, 67, 233, 255, 46, 167, 45, 168, 171, 112, 159,
	152, 63, 133, 52, 159, 12, 203, 99, 163, 195, 215, 2, 37, 184, 192, 99,
	5, 89, 36, 135, 25, 59, 133, 153, 196, 174, 238, 204, 81, 61, 159, 113,
	188, 226, 143, 160, 243, 169, 186, 91, 49, 15, 237, 48, 42, 54, 11,
	115, 231, 165, 70, 121, 63, 29, 215, 177, 124, 29, 252, 182, 52, 140,
	31, 45, 254, 134, 218, 182 };
unsigned char nadd[] = { 167, 224, 248, 6, 228, 255, 8, 41, 176, 253, 129, 66,
	248, 170, 38, 213, 161, 161, 195, 76, 222, 126, 35, 214, 91, 67, 203,
	195, 163, 205, 105, 43, 245, 129, 127, 104, 117, 107, 212, 107, 120,
	206, 243, 73, 3, 135, 156, 125, 89, 41, 233, 75, 75, 52, 112, 86, 79,
	68, 128, 49, 84, 150, 191, 15, 45, 102, 53, 138, 10, 209, 228, 162,
	220, 167, 248, 7, 192, 187, 116, 124, 161, 18, 102, 240, 78, 192, 29,
	198, 49, 203, 231, 1, 158, 168, 71, 155, 180, 31, 35, 197, 117, 0, 140,
	229, 75, 132, 16, 102, 215, 40, 6, 252, 12, 250, 136, 144, 94, 241, 68,
	77, 2, 236, 204, 188, 236, 83, 240, 78, 246, 95, 221, 66 };


// from padlock, padlock-something-openwall.txt
unsigned char ptn[] = { 91, 123, 34, 110, 97, 109, 101, 34, 58, 34, 116, 101,
	115, 116, 34, 44, 34, 102, 105, 101, 108, 100, 115, 34, 58, 91, 123,
	34, 110, 97, 109, 101, 34, 58, 34, 117, 115, 101, 114, 110, 97, 109,
	101, 34 , 44, 34, 118, 97, 108, 117, 101, 34, 58, 34, 34, 125, 44, 123,
	34, 110, 97, 109, 101, 34, 58, 34, 112, 97, 115, 115, 119, 111, 114,
	100, 34, 44, 34, 118, 97, 108, 117, 101, 34, 58, 34, 34, 125, 93, 44,
	34, 99, 97, 116, 101, 103, 111, 114, 121, 34, 58, 34, 34, 44, 34, 117,
	117, 105, 100, 34, 58, 34, 98, 99, 97, 53, 55, 48, 49, 101, 45, 51,
	102, 48, 100, 45, 52, 57, 97, 97, 45, 56, 99, 56, 54, 45, 52, 99, 52,
	54, 57, 55 , 54, 52, 100, 57, 99, 97, 34, 44, 34, 117, 112, 100, 97,
	116, 101, 100, 34, 58, 34, 50, 48, 49, 55, 45, 48, 51, 45, 49, 51, 84,
	48, 51, 58, 53, 52, 58, 49, 55, 46, 55, 50, 52, 90, 34, 125, 93 };
static int ptnlen = 187;
unsigned char addn[] = { 237, 193, 76, 71, 106, 18, 237, 193, 7, 172, 105, 79, 201, 203, 8, 98 };
static int addnlen = 16;
static unsigned char keyn[] = { 196, 207, 34, 224, 182, 57, 124, 160, 137, 16, 17, 116, 14, 245, 30, 183, 210, 252, 69, 41, 93, 115, 184, 61, 250, 47, 174, 143, 46, 40, 36, 82 };
unsigned char ivn[] = { 15, 183, 246, 116, 2, 11, 66, 35, 113, 80, 73, 165, 111, 165, 19, 202 };

#define mbedtls_printf printf

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}

int main()
{
	unsigned char out[512] = { 0 };
	size_t i;
	int ret;
	int verbose = 1;

	for (i = 0; i < NB_TESTS; i++)
	{
		if (verbose != 0)
			mbedtls_printf("  CCM-AES #%u: ", (unsigned int) i + 1);

		ret = aes_ccm_encrypt_and_tag(key, 128, msg_len[i], iv,
				iv_len[i], ad, add_len[i], msg, out, out +
				msg_len[i], tag_len[i]);
		if (ret != 0 || memcmp(out, res[i], msg_len[i] + tag_len[i]) != 0)
		{
			if (verbose != 0)
				mbedtls_printf("failed\n");
			return 1;
		}

		ret = aes_ccm_auth_decrypt(key, 128, msg_len[i], iv,
				iv_len[i], ad, add_len[i], res[i], out, res[i]
				+ msg_len[i], tag_len[i]);

		if (ret != 0 || memcmp( out, msg, msg_len[i] ) != 0)
		{
			if (verbose != 0)
				mbedtls_printf("failed\n");

			return 1;
		}

		if (verbose != 0)
			mbedtls_printf("passed\n");
	}

	if (verbose != 0)
		mbedtls_printf("\n");

	aes_ccm_encrypt_and_tag(nkey, 128, 111, niv, 12, nadd, 132, npt,
			out, out + 111, 16);
	print_hex(out + 111, 16); // print calculated tag, should be 8f27c1985372e9db7477be389e701c26
	print_hex(out, 111); // print ciphertext, should be 9f14fa396445bf0e206...b54f0e538c5ef

	printf("\n");

	memset(out, 0, 512);
	aes_ccm_encrypt_and_tag(keyn, 256, ptnlen, ivn, 13, addn, 16, ptn, // iv length of 13 is confirmed for padlock + sjcl
			out, out + ptnlen, 8);
	print_hex(out + ptnlen, 8); // is dc137019d4f171d6 according to correctly used sjcl and polarssl, padlock + sjcl says "4dd966f8e71653ae"
	print_hex(out, ptnlen); // print ciphertext, should be 8b2368a584a7fd96eb45adf226176a40477bc3c7300bb51f1e411721b5eeac2af382623bb18a8547cde12d1f21ee26e36a801f77246bbd6e6c3ee8a39f8161b2f7847f5a42a4573bf0de14413e1ce177a0f1

	return 0;
}

#endif

/*
 * This software is Copyright (c) 2017 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * ODF
 * The work is:
 *   pbk_key   = SHA1(password) (1 block)
 *   bf_key    = PBKDF2-HMAC-SHA1(pbk_key, salt, 1024 iterations)
 *   plaintext = Blowfish CFB64 decrypt(bf_key, content, len)
 *   output    = SHA1(plaintext) (17 blocks)
 *
 * NOTE for the above #3113 introduced bug-compatible code!
 *
 * ODF-AES
 * The work is:
 *   pbk_key   = SHA256(password) (1 block)
 *   aes_key   = PBKDF2-HMAC-SHA1(pbk_key, salt, 1024 iterations)
 *   plaintext = AES256_CBC_decrypt(aes_key, content, len)
 *   output    = SHA256(plaintext) (17 blocks)
 */
#define KEYLEN (256/8)
#include "pbkdf2_hmac_sha1_unsplit_kernel.cl"
#include "opencl_sha2.h"
#include "opencl_sha1.h"
#define AES_KEY_TYPE __global const
#define AES_SRC_TYPE __constant
#include "opencl_aes.h"
#define BF_KEY_TYPE __global const
#define BF_SRC_TYPE __constant
#include "opencl_blowfish.h"

typedef struct {
	const uchar v[PLAINTEXT_LENGTH + 1];
} odf_password;

typedef struct {
	uint32_t iterations;
	uint32_t outlen;
	uint32_t skip_bytes;
	uint8_t  content[CT_LEN]; /* ciphertext */
	uint32_t content_length;  /* actual data length (up to CT_LEN) */
	uint32_t original_length; /* actual actual data length (wth?) */
	uint8_t  iv[16];
	uint8_t  salt[64];
	uint32_t cipher_type;
	uint32_t  length;
} odf_salt;

typedef struct {
	uint v[256/32]; /* output from final SHA-1 or SHA-256 */
} odf_out;

inline void odf_bf(__global const uchar *password,
                   __constant odf_salt *salt,
                   __global uint *out)
{
	blowfish_context ctx;
	uchar iv[8];
	uint i, j, iv_off = 0;
	uint hash[160/32];
	uchar plaintext[CT_LEN];
	uint W[16] = { 0 };
	uchar *w = (uchar*)W;

	for (i = 0; password[i]; i++)
		w[i ^ 3] = password[i];
	w[i ^ 3] = 0x80;
	W[15] = i << 3;
	sha1_single(uint, W, hash);
	for (i = 0; i < 160/32; i++)
		out[i] = SWAP32(hash[i]);

	pbkdf2((__global uchar*)out, 160/8, salt->salt, salt->length,
	       salt->iterations, out, salt->outlen, salt->skip_bytes);

	for (i = 0; i < 8; i++)
		iv[i] = salt->iv[i];
	/* Blowfish key setup is very heavy */
	blowfish_setkey(&ctx, (__global uchar*)out, salt->outlen * 8);
	blowfish_crypt_cfb64(&ctx, BF_DECRYPT, salt->original_length, &iv_off, iv,
	                     salt->content, plaintext);

	sha1_init(hash);
	for (i = 0; i < salt->original_length; i++) {
		w[(i & 63) ^ 3] = plaintext[i];
		if ((i & 63) == 63)
			sha1_block(uint, W, hash);
	}
	for (j = i & 63; j < 64; j++)
		w[j ^ 3] = 0;
	w[(i & 63) ^ 3] = 0x80;

	if ((salt->original_length & 63) > 55) {
		sha1_block(uint, W, hash);
		for (j = 0; j < 15; j++)
			W[j] = 0;
		out[160/32] = 0;
	}
	else if ((salt->original_length & 63) >> 2 == 13) {
		/* StarOffice bug compatibility: See #3089 */
		uint WW[16];

		for (j = 0; j < 15; j++)
			WW[j] = W[j];
		sha1_block(uint, W, hash);
		for (j = 0; j < 15; j++)
			W[j] = 0;
		W[15] = i << 3;
		sha1_block(uint, W, hash);
		out[160/32] = SWAP32(hash[0]);
		for (j = 0; j < 15; j++)
			W[j] = WW[j];
	} else
		out[160/32] = 0;
	W[15] = i << 3;
	sha1_block(uint, W, hash);
	for (i = 0; i < 160/32; i++)
		out[i] = SWAP32(hash[i]);
}

inline void odf_aes(__global const uchar *password,
                    __constant odf_salt *salt,
                    __global uint *out)
{
	AES_KEY akey;
	uchar iv[16];
	uint i, j;
	uint hash[256/32];
	uchar plaintext[CT_LEN];
	union {
		uchar c[64];
		uint  w[16];
	} md;

	for (i = 0; i < 16; i++)
		md.w[i] = 0;
	for (i = 0; password[i]; i++)
		md.c[i ^ 3] = password[i];
	md.c[i ^ 3] = 0x80;
	md.w[15] = i << 3;
	sha256_init(hash);
	sha256_block(md.w, hash);
	for (i = 0; i < 256/32; i++)
		out[i] = SWAP32(hash[i]);

	pbkdf2((__global uchar*)out, 256/8, salt->salt, salt->length,
	       salt->iterations, out, salt->outlen, salt->skip_bytes);

	for (i = 0; i < 16; i++)
		iv[i] = salt->iv[i];
	AES_set_decrypt_key(out, 256, &akey);
	AES_cbc_decrypt(salt->content, plaintext, salt->content_length, &akey, iv);

	sha256_init(hash);
	for (i = 0; i < salt->content_length; i++) {
		md.c[(i & 63) ^ 3] = plaintext[i];
		if ((i & 63) == 63)
			sha256_block(md.w, hash);
	}
	for (j = i & 63; j < 64; j++)
		md.c[j ^ 3] = 0;
	md.c[(i & 63) ^ 3] = 0x80;
	if ((salt->content_length & 63) > 55) {
		sha256_block(md.w, hash);
		for (j = 0; j < 15; j++)
			md.w[j] = 0;
	}
	md.w[15] = i << 3;
	sha256_block(md.w, hash);
	for (i = 0; i < 256/32; i++)
		out[i] = SWAP32(hash[i]);
}

__kernel void odf(__global odf_password *password,
                  __constant odf_salt *salt,
                  __global odf_out *out)
{
	uint idx = get_global_id(0);

	if (salt->cipher_type == 0)
		odf_bf(password[idx].v, salt, out[idx].v);
	else
		odf_aes(password[idx].v, salt, out[idx].v);
}

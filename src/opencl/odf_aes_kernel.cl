/*
 * ODF-AES
 *
 * The work is:
 *   pbk_key   = SHA256(password) (1 block)
 *   aes_key   = PBKDF2-HMAC-SHA1(pbk_key, salt, 1024 iterations)
 *   plaintext = AES256_CBC_decrypt(aes_key, ciphertext, len 1024)
 *   output    = SHA256(plaintext) (17 blocks)
 *
 * This software is Copyright (c) 2017 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#include "opencl_sha2.h"
#include "pbkdf2_hmac_sha1_unsplit_kernel.cl"
#define OCL_AES_CBC_DECRYPT 1
#define AES_KEY_TYPE __global
#define AES_SRC_TYPE __constant
#include "opencl_aes.h"

typedef struct {
	const uchar v[PLAINTEXT_LENGTH + 1];
} odf_password;

typedef struct {
	uint v[KEYLEN / sizeof(uint)];
} odf_sha_key;

typedef struct {
	uint32_t iterations;
	uint32_t outlen;
	uint32_t skip_bytes;
	uint8_t  aes_ct[AES_LEN]; /* ciphertext */
	uint32_t aes_len;         /* actual data length (up to AES_LEN) */
	uint8_t  iv[16];
	uint8_t  salt[64];
	uint8_t  length;
} odf_salt;

typedef struct {
	uint v[256/32]; /* output from final SHA-256 */
} odf_out;

__kernel void dk_decrypt(__global odf_password *password,
                         __constant odf_salt *salt,
                         __global odf_out *odf_out,
                         __global odf_sha_key *sha_key)
{
	uint idx = get_global_id(0);
	AES_KEY akey;
	uchar iv[16];
	uint i, j;
	uint hash[256 / 8 / 4];
	uchar plaintext[AES_LEN];
	union {
		uchar c[64];
		uint  w[16];
	} md;

	for (i = 0; i < 16; i++)
		md.w[i] = 0;

	for (i = 0; password[idx].v[i]; i++)
		md.c[i ^ 3] = password[idx].v[i];
	md.c[i ^ 3] = 0x80;
	md.w[15] = i << 3;

	sha256_init(hash);
	sha256_block(md.w, hash);

	for (i = 0; i < 256/8/4; i++)
		sha_key[idx].v[i] = SWAP32(hash[i]);

	for (i = 0; i < 16; i++)
		iv[i] = salt->iv[i];

	pbkdf2((__global uchar*)sha_key[idx].v, 256/8, salt->salt, salt->length,
	       salt->iterations, odf_out[idx].v, salt->outlen,
	       salt->skip_bytes);

	AES_set_decrypt_key((__global uchar*)odf_out[idx].v, 256, &akey);
	AES_cbc_decrypt(salt->aes_ct, plaintext, salt->aes_len, &akey, iv);

	sha256_init(hash);
	for (i = 0; i < salt->aes_len; i++) {
		md.c[(i & 63) ^ 3] = plaintext[i];
		if ((i & 63) == 63)
			sha256_block(md.w, hash);
	}
	for (j = i & 63; j < 64; j++)
		md.c[j ^ 3] = 0;
	md.c[(i & 63) ^ 3] = 0x80;
	md.w[15] = i << 3;
	sha256_block(md.w, hash);
	for (i = 0; i < 256/8/4; i++)
		odf_out[idx].v[i] = SWAP32(hash[i]);
}

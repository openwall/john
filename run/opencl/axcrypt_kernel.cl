/*
 * This software is Copyright (c) 2018 Dhiru Kholia, Copyright (c) 2016
 * Fist0urs <eddy.maaalou at gmail.com>, Copyright (c) 2018 magnum, and it is
 * hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1_ctx.h"
#include "opencl_aes.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif

// input
typedef struct {
	uint length;
	uchar v[PLAINTEXT_LENGTH];
} axcrypt_password;

// input
typedef struct {
	uint version;
        uint key_wrapping_rounds;
        uint keyfile_length;
        uchar salt[16];
        uchar wrappedkey[24];
        uchar keyfile[4096];
} axcrypt_salt;

// output
typedef struct {
	uint cracked;
} axcrypt_out;

#define PUT_64BITS_XOR_MSB(cp, value) ( \
                (cp)[0] ^= (unsigned char)((value)), \
                (cp)[1] ^= (unsigned char)((value) >> 8), \
                (cp)[2] ^= (unsigned char)((value) >> 16), \
                (cp)[3] ^= (unsigned char)((value) >> 24 ) )

inline int axcrypt_decrypt(__global const axcrypt_password *inbuffer, uint gid, __constant axcrypt_salt *cur_salt, __global axcrypt_out *output)
{
	uchar password[PLAINTEXT_LENGTH];
	uchar keyfile[4096];
	int password_length = inbuffer[gid].length;
	uchar salt[16];
	unsigned char KEK[20];
        union {
		unsigned char b[16];
		uint32_t w[4];
	} lsb;
	union {
		unsigned char b[16];
		uint32_t w[4];
	} cipher;
	AES_KEY akey;
	SHA_CTX ctx;
	uint i;
	int j, nb_iterations = cur_salt->key_wrapping_rounds;

	memcpy_gp(password, inbuffer[gid].v, password_length);
	memcpy_macro(salt, cur_salt->salt, 16);
	if (cur_salt->keyfile_length != 0)
		memcpy_macro(keyfile, cur_salt->keyfile, cur_salt->keyfile_length);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, password, password_length);
	if (cur_salt->keyfile_length != 0) {
		SHA1_Update(&ctx, keyfile, cur_salt->keyfile_length);
	}
	SHA1_Final(KEK, &ctx);

	/* hash XOR salt => KEK */
	for (i = 0; i < sizeof(cur_salt->salt); i++)
		KEK[i] ^= salt[i];

	memcpy_macro(lsb.b, cur_salt->wrappedkey + 8, 16);

	AES_set_decrypt_key(KEK, 128, &akey);

	/* set msb */
	memcpy_macro(cipher.b, cur_salt->wrappedkey, 8);

	/* custom AES un-wrapping loop */
	for (j = nb_iterations - 1; j >= 0; j--) {
		/* 1st block treatment */
		/* MSB XOR (NUMBER_AES_BLOCKS * j + i) */
		PUT_64BITS_XOR_MSB(cipher.b, 2 * j + 2);
		/* R[i] */
		cipher.w[2] = lsb.w[2];
		cipher.w[3] = lsb.w[3];
		/* AES_ECB(KEK, (MSB XOR (NUMBER_AES_BLOCKS * j + i)) | R[i]) */
		AES_decrypt(cipher.b, cipher.b, &akey);
		lsb.w[2] = cipher.w[2];
		lsb.w[3] = cipher.w[3];

		/* 2nd block treatment */
		PUT_64BITS_XOR_MSB(cipher.b, 2 * j + 1);
		cipher.w[2] = lsb.w[0];
		cipher.w[3] = lsb.w[1];
		AES_decrypt(cipher.b, cipher.b, &akey);
		lsb.w[0] = cipher.w[2];
		lsb.w[1] = cipher.w[3];
	}

	for (i = 0; i < 8; i++) {
		if (cipher.b[i] != 0xa6)
			return 0;
	}

	return 1;
}

__kernel
void axcrypt(__global const axcrypt_password *inbuffer,
                __global axcrypt_out *out,
                __constant axcrypt_salt *salt)
{
	uint idx = get_global_id(0);

	out[idx].cracked = axcrypt_decrypt(inbuffer, idx, salt, out);
}

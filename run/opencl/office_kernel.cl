/*
 * Office 2007, 2010 and 2013 formats
 *
 * Copyright 2012-2021, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * This is thanks to Dhiru writing the CPU code first!
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1.h"
#include "opencl_sha2.h"
#define AES_SRC_TYPE __constant
#include "opencl_aes.h"

typedef struct ms_office_salt_t {
	union {
		uchar c[16];
		uint  w[16/4];
		ulong l[16/8];
	} salt;
	uint   version;
	uint   verifierHashSize;
	uint   keySize;
	uint   saltSize;
	uint   spinCount;
} ms_office_salt;

typedef struct ms_office_blob_t {
	uint8_t encryptedVerifier[16];
	uint8_t encryptedVerifierHash[32];
} ms_office_blob;

typedef struct {
	uint pass;
	uint dummy;
	union {
		uint  w[512/8/4];
		ulong l[512/8/8];
	} ctx;
} ms_office_state;

typedef struct {
	uint cracked;
} ms_office_out;

#if __OS_X__ && gpu_amd(DEVICE_INFO)
/* This is a workaround for driver/runtime bugs */
#define MAYBE_VOLATILE volatile
#else
#define MAYBE_VOLATILE
#endif

__kernel void GenerateSHA1pwhash(__global const uint *unicode_pw,
                                 __global const uint *pw_len,
                                 __constant ms_office_salt *salt,
                                 __global ms_office_state *state)
{
	uint i;
	uint W[16];
	uint output[5];
	const uint gid = get_global_id(0);

	/* Initial hash of salt + password */
	/* The ending 0x80 is already in the buffer */
	for (i = 0; i < 4; i++)
		W[i] = SWAP32(salt->salt.w[i]);
	for (i = 4; i < 16; i++)
		W[i] = SWAP32(unicode_pw[gid * (UNICODE_LENGTH>>2) + i - 4]);
	if (pw_len[gid] < 40) {
		W[14] = 0;
		W[15] = (pw_len[gid] + 16) << 3;
	}
	sha1_single(uint, W, output);

	if (pw_len[gid] >= 40) {
		for (i = 0; i < (UNICODE_LENGTH / 4 - 12); i++)
			W[i] = SWAP32(unicode_pw[gid * (UNICODE_LENGTH>>2) + i + 12]);
		for ( ; i < 15; i++)
			W[i] = 0;
		W[15] = (pw_len[gid] + 16) << 3;
		sha1_block(uint, W, output);
	}

	for (i = 0; i < 5; i++)
		state[gid].ctx.w[i] = output[i];
	state[gid].pass = 0;
}

__kernel
void HashLoop0710(__global ms_office_state *state)
{
	uint i, j;
	uint output[5];
	const uint gid = get_global_id(0);
	const uint base = state[gid].pass;

	for (i = 0; i < 5; i++)
		output[i] = state[gid].ctx.w[i];

	/* HASH_LOOPS0710 rounds of sha1(serial.last hash)
	 * We avoid byte-swapping back and forth */
	for (j = 0; j < HASH_LOOPS0710; j++)
	{
		uint W[16];

		W[0] = SWAP32(base + j);
		for (i = 1; i < 6; i++)
			W[i] = output[i - 1];
		W[6] = 0x80000000;
		W[15] = 24 << 3;
		sha1_single_192Z(uint, W, output);
	}
	for (i = 0; i < 5; i++)
		state[gid].ctx.w[i] = output[i];
	state[gid].pass += HASH_LOOPS0710;
}

__kernel
void Final2007(__global ms_office_state *state,
               __global ms_office_out *out,
               __constant ms_office_salt *salt,
               __constant ms_office_blob *blob)
{
	uint i;
	uint W[16];
	union {
		uchar c[20];
		uint  w[20/4];
	} output;
	union {
		uchar c[40];
		uint  w[40/4];
	} X3;
	uint gid = get_global_id(0);
	union {
		unsigned char c[16];
		uint w[4];
	} decryptedVerifier;
	union {
		unsigned char c[16];
		uint w[4];
	} decryptedVerifierHash;
	AES_KEY akey;
	uint result = 1;

#if (50000 % HASH_LOOPS0710)
	int j;

	for (i = 0; i < 5; i++)
		output.w[i] = state[gid].ctx.w[i];

	/* Remainder of sha1(serial.last hash) */
	for (j = 50000 - (50000 % HASH_LOOPS0710); j < 50000; j++)
	{
		W[0] = SWAP32(j);
		for (i = 1; i < 6; i++)
			W[i] = output.w[i - 1];
		W[6] = 0x80000000;
		W[15] = 24 << 3;
		sha1_single_192Z(uint, W, output.w);
	}

	/* Final hash */
	for (i = 0; i < 5; i++)
		W[i] = output.w[i];
#else
	/* Final hash */
	for (i = 0; i < 5; i++)
		W[i] = state[gid].ctx.w[i];
#endif

	W[5] = 0;
	W[6] = 0x80000000;
	W[15] = 24 << 3;
	sha1_single_192Z(uint, W, output.w);

	/* DeriveKey */
	for (i = 0; i < 5; i++)
		W[i] = output.w[i] ^ 0x36363636;
	for (i = 5; i < 16; i++)
		W[i] = 0x36363636;
	sha1_single(uint, W, X3.w);
	/* sha1_final (last block was 64 bytes) */
	W[0] = 0x80000000;
	for (i = 1; i < 6; i++)
		W[i] = 0;
	W[15] = 64 << 3;
	sha1_block_160Z(uint, W, X3.w);

	/* Endian-swap to output */
	for (i = 0; i < 5; i++)
		X3.w[i] = SWAP32(X3.w[i]); /* This is X1 in MS-OFFCRYPTO */

	if (salt->verifierHashSize < salt->keySize / 8) {
		uint *X2 = &X3.w[5];

		for (i = 0; i < 5; i++)
			W[i] = output.w[i] ^ 0x5c5c5c5c;
		for (i = 5; i < 16; i++)
			W[i] = 0x5c5c5c5c;
		sha1_single(uint, W, X2);
		/* sha1_final (last block was 64 bytes) */
		W[0] = 0x80000000;
		for (i = 1; i < 6; i++)
			W[i] = 0;
		W[15] = 64 << 3;
		sha1_block_160Z(uint, W, X2);

		/* Endian-swap to output */
		for (i = 0; i < 5; i++)
			X2[i] = SWAP32(X2[i]);
	}

	AES_set_decrypt_key(X3.c, salt->keySize, &akey);
	AES_ecb_decrypt(blob->encryptedVerifier, decryptedVerifier.c, 16, &akey);
	AES_ecb_decrypt(blob->encryptedVerifierHash, decryptedVerifierHash.c, 16, &akey);

	for (i = 0; i < 4; i++)
		W[i] = SWAP32(decryptedVerifier.w[i]);
	W[4] = 0x80000000;
	W[5] = 0;
	W[15] = 16 << 3;
	sha1_single_160Z(uint, W, output.w);

	for (i = 0; i < 16/4; i++) {
		if (decryptedVerifierHash.w[i] != SWAP32(output.w[i])) {
			result = 0;
			break;
		}
	}

	out[gid].cracked = result;
}

inline void Decrypt(__constant ms_office_salt *salt,
                    const uchar *verifierInputKey,
                    __constant uchar *encryptedVerifier,
                    uchar *decryptedVerifier,
                    const int length)
{
	uint i;
	uchar iv[16];
	AES_KEY akey;

	for (i = 0; i < 16; i++)
		iv[i] = salt->salt.c[i];

	AES_set_decrypt_key(verifierInputKey, salt->keySize, &akey);
	AES_cbc_decrypt(encryptedVerifier, decryptedVerifier, length, &akey, iv);
}

__constant uint InputBlockKeyInt[] = { 0xfea7d276, 0x3b4b9e79 };
__constant uint ValueBlockKeyInt[] = { 0xd7aa0f6d, 0x3061344e };

__kernel
void Generate2010key(__global ms_office_state *state,
                     __global ms_office_out *out,
                     __constant ms_office_salt *salt,
                     __constant ms_office_blob *blob)
{
	uint i, j, result = 1;
	uint W[16];
	union {
		uchar c[20];
		uint  w[20/4];
	} output[2];
	const uint gid = get_global_id(0);
	const uint base = state[gid].pass;
	const uint iterations = salt->spinCount % HASH_LOOPS0710;
	union {
		unsigned char c[16];
		uint w[4];
	} decryptedVerifierHashInputBytes;
	union {
		unsigned char c[32];
		uint w[8];
	} decryptedVerifierHashBytes;

	for (i = 0; i < 5; i++)
		output[1].w[i] = state[gid].ctx.w[i];

	/* Remainder of sha1(serial.last hash)
	 * We avoid byte-swapping back and forth */
	for (j = 0; j < iterations; j++)
	{
		W[0] = SWAP32(base + j);
		for (i = 1; i < 6; i++)
			W[i] = output[1].w[i - 1];
		W[6] = 0x80000000;
		W[15] = 24 << 3;
		sha1_single_192Z(uint, W, output[1].w);
	}

	/* We'll continue with output[1] later */
	for (i = 0; i < 5; i++)
		W[i] = output[1].w[i];

	/* Final hash 1 */
	W[5] = InputBlockKeyInt[0];
	W[6] = InputBlockKeyInt[1];
	W[7] = 0x80000000;
	for (i = 8; i < 15; i++)
		W[i] = 0;
	W[15] = 28 << 3;
	sha1_single(uint, W, output[0].w);

	/* Endian-swap to 1st hash (we only use 16 bytes) */
	for (i = 0; i < 4; i++)
		output[0].w[i] = SWAP32(output[0].w[i]);

	/* Final hash 2 */
	for (i = 0; i < 5; i++)
		W[i] = output[1].w[i];
	W[5] = ValueBlockKeyInt[0];
	W[6] = ValueBlockKeyInt[1];
	W[7] = 0x80000000;
	for (i = 8; i < 15; i++)
		W[i] = 0;
	W[15] = 28 << 3;
	sha1_single(MAYBE_VOLATILE uint, W, output[1].w);

	/* Endian-swap to 2nd hash (we only use 16 bytes) */
	for (i = 0; i < 4; i++)
		output[1].w[i] = SWAP32(output[1].w[i]);

	Decrypt(salt, output[0].c, blob->encryptedVerifier,
	        decryptedVerifierHashInputBytes.c, 16);

	Decrypt(salt, output[1].c, blob->encryptedVerifierHash,
	        decryptedVerifierHashBytes.c, 32);

	for (i = 0; i < 4; i++)
		W[i] = SWAP32(decryptedVerifierHashInputBytes.w[i]);
	W[4] = 0x80000000;
	for (i = 5; i < 15; i++)
		W[i] = 0;
	W[15] = 16 << 3;
	sha1_single(uint, W, output[0].w);

	for (i = 0; i < 20/4; i++) {
		if (decryptedVerifierHashBytes.w[i] != SWAP32(output[0].w[i])) {
			result = 0;
			break;
		}
	}

	out[gid].cracked = result;
}

__kernel void GenerateSHA512pwhash(__global const ulong *unicode_pw,
                                   __global const uint *pw_len,
                                   __constant ms_office_salt *salt,
                                   __global ms_office_state *state)
{
	uint i;
	ulong W[16];
	ulong output[8];
	const uint gid = get_global_id(0);

	/* Initial hash of salt + password */
	/* The ending 0x80 is already in the buffer */
	for (i = 0; i < 2; i++)
		W[i] = SWAP64(salt->salt.l[i]);
	for (i = 2; i < 14; i++)
		W[i] = SWAP64(unicode_pw[gid * (UNICODE_LENGTH >> 3) + i - 2]);
	W[14] = 0;
	W[15] = (ulong)(pw_len[gid] + 16) << 3;
	sha512_single_s(W, output);

	for (i = 0; i < 8; i++)
		state[gid].ctx.l[i] = output[i];
	state[gid].pass = 0;
}

__kernel
void HashLoop13(__global ms_office_state *state)
{
	uint i, j;
	ulong output[8];
	const uint gid = get_global_id(0);
	const uint base = state[gid].pass;

	for (i = 0; i < 8; i++)
		output[i] = state[gid].ctx.l[i];

	/* HASH_LOOPS13 rounds of sha512(serial.last hash)
	 * We avoid byte-swapping back and forth */
	for (j = 0; j < HASH_LOOPS13; j++)
	{
		ulong W[16];

		W[0] = ((ulong)SWAP32(base + j) << 32) | (output[0] >> 32);
		for (i = 1; i < 8; i++)
			W[i] = (output[i - 1] << 32) | (output[i] >> 32);
		W[8] = (output[7] << 32) | 0x80000000UL;
		W[15] = 68 << 3;
		sha512_single_zeros(W, output);
	}
	for (i = 0; i < 8; i++)
		state[gid].ctx.l[i] = output[i];
	state[gid].pass += HASH_LOOPS13;
}

__constant ulong InputBlockKeyLong = 0xfea7d2763b4b9e79UL;
__constant ulong ValueBlockKeyLong = 0xd7aa0f6d3061344eUL;

__kernel
void Generate2013key(__global ms_office_state *state,
                     __global ms_office_out *out,
                     __constant ms_office_salt *salt,
                     __constant ms_office_blob *blob)
{
	uint i, j, result = 1;
	ulong W[4][16];
	ulong output[4][64/8];
	const uint gid = get_global_id(0);
	const uint base = state[gid].pass;
	const uint iterations = salt->spinCount % HASH_LOOPS13;
	ulong decryptedVerifierHashInputBytes[16/8];
	ulong decryptedVerifierHashBytes[32/8];

	for (i = 0; i < 8; i++)
		output[0][i] = state[gid].ctx.l[i];

	/* Remainder of iterations */
	for (j = 0; j < iterations; j++)
	{
		W[0][0] = ((ulong)SWAP32(base + j) << 32) | (output[0][0] >> 32);
		for (i = 1; i < 8; i++)
			W[0][i] = (output[0][i - 1] << 32) | (output[0][i] >> 32);
		W[0][8] = (output[0][7] << 32) | 0x80000000UL;
		W[0][15] = 68 << 3;
		sha512_single_zeros(W[0], output[0]);
	}

	/* We'll continue with output[0] later */
	for (i = 0; i < 8; i++)
		W[1][i] = output[0][i];

	/* Final hash 1 */
	W[1][8] = InputBlockKeyLong;
	W[1][9] = 0x8000000000000000UL;
	for (i = 10; i < 15; i++)
		W[1][i] = 0;
	W[1][15] = 72 << 3;
	sha512_single(W[1], output[1]);

	/* Endian-swap to 1st hash output */
	for (i = 0; i < 8; i++)
		output[1][i] = SWAP64(output[1][i]);

	/* Final hash 2 */
	for (i = 0; i < 8; i++)
		W[2][i] = output[0][i];
	W[2][8] = ValueBlockKeyLong;
	W[2][9] = 0x8000000000000000UL;
	for (i = 10; i < 15; i++)
		W[2][i] = 0;
	W[2][15] = 72 << 3;
	sha512_single(W[2], output[2]);

	/* Endian-swap to 2nd hash output */
	for (i = 0; i < 8; i++)
		output[2][i] = SWAP64(output[2][i]);

	Decrypt(salt, (uchar*)output[1], blob->encryptedVerifier,
	        (uchar*)decryptedVerifierHashInputBytes, 16);

	Decrypt(salt, (uchar*)output[2], blob->encryptedVerifierHash,
	        (uchar*)decryptedVerifierHashBytes, 32);

	for (i = 0; i < 2; i++)
		W[3][i] = SWAP64(decryptedVerifierHashInputBytes[i]);
	W[3][2] = 0x8000000000000000UL;
	for (i = 3; i < 15; i++)
		W[3][i] = 0;
	W[3][15] = 16 << 3;
	sha512_single(W[3], output[3]);
	for (i = 0; i < 8; i++)
		output[3][i] = SWAP64(output[3][i]);

	for (i = 0; i < 32/8; i++) {
		if (decryptedVerifierHashBytes[i] != output[3][i]) {
			result = 0;
			break;
		}
	}

	out[gid].cracked = result;
}

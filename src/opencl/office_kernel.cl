/*
 * Office 2007, 2010 and 2013 formats
 *
 * Copyright 2012-2017, magnum
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
#define OCL_AES_ECB_DECRYPT 1
#define OCL_AES_CBC_DECRYPT 1
#define AES_KEY_TYPE __global
#define AES_SRC_TYPE __global
#include "opencl_aes.h"

typedef struct ms_office_salt_t {
	union {
		uchar c[16];
		uint  w[16/4];
		ulong l[16/8];
	} osalt;
	uchar encryptedVerifier[16];
	uchar encryptedVerifierHash[32];
	int   version;
	int   verifierHashSize;
	int   keySize;
	int   saltSize;
	int   spinCount;
} ms_office_salt;

typedef struct {
	uint pass;
	uint dummy;
	union {
		uint  w[512/8/4];
		ulong l[512/8/8];
	} ctx;
} ms_office_state;

typedef struct {
	volatile uint cracked;
	uint dummy;
	union {
		uchar c[64];
		uint  w[64/4];
		ulong l[64/8];
	} key[2];
} ms_office_out;

__kernel void GenerateSHA1pwhash(__global const uint *unicode_pw,
                                 __global const uint *pw_len,
                                 __global const ms_office_salt *salt,
                                 __global ms_office_state *state)
{
	uint i;
	uint W[16];
	uint output[5];
	const uint gid = get_global_id(0);

	/* Initial hash of salt + password */
	/* The ending 0x80 is already in the buffer */
	for (i = 0; i < 4; i++)
		W[i] = SWAP32(salt->osalt.w[i]);
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
               const __global ms_office_salt *salt)
{
	uint i;
	uint W[16];
	uint output[5];
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

	if (gid == 0)
		out[0].cracked = 0;

#if (50000 % HASH_LOOPS0710)
	int j;

	for (i = 0; i < 5; i++)
		output[i] = state[gid].ctx.w[i];

	/* Remainder of sha1(serial.last hash) */
	for (j = 50000 - (50000 % HASH_LOOPS0710); j < 50000; j++)
	{
		W[0] = SWAP32(j);
		for (i = 1; i < 6; i++)
			W[i] = output[i - 1];
		W[6] = 0x80000000;
		W[15] = 24 << 3;
		sha1_single_192Z(uint, W, output);
	}

	/* Final hash */
	for (i = 0; i < 5; i++)
		W[i] = output[i];
#else
	/* Final hash */
	for (i = 0; i < 5; i++)
		W[i] = state[gid].ctx.w[i];
#endif

	W[5] = 0;
	W[6] = 0x80000000;
	W[15] = 24 << 3;
	sha1_single_192Z(uint, W, output);

	/* DeriveKey */
	for (i = 0; i < 5; i++)
		W[i] = output[i] ^ 0x36363636;
	for (i = 5; i < 16; i++)
		W[i] = 0x36363636;
	sha1_single(uint, W, output);
	/* sha1_final (last block was 64 bytes) */
	W[0] = 0x80000000;
	for (i = 1; i < 6; i++)
		W[i] = 0;
	W[15] = 64 << 3;
	sha1_block_160Z(uint, W, output);

	/* Endian-swap to output (we only use 16 bytes) */
	for (i = 0; i < 4; i++)
		out[gid].key[0].w[i] = SWAP32(output[i]);

	AES_set_decrypt_key(out[gid].key[0].c, 128, &akey);
	AES_ecb_decrypt(salt->encryptedVerifier, decryptedVerifier.c, &akey);
	AES_set_decrypt_key(out[gid].key[0].c, 128, &akey);
	AES_ecb_decrypt(salt->encryptedVerifierHash, decryptedVerifierHash.c, &akey);

	for (i = 0; i < 4; i++)
		W[i] = SWAP32(decryptedVerifier.w[i]);
	W[4] = 0x80000000;
	W[5] = 0;
	W[15] = 16 << 3;
	sha1_init(output);
	sha1_block_160Z(uint, W, output);

	for (i = 0; i < 16/4; i++) {
		if (decryptedVerifierHash.w[i] != SWAP32(output[i])) {
			result = 0;
			break;
		}
	}

	if ( (out[gid + 1].cracked = result) )
		atomic_max(&out[0].cracked, gid + 1);
}

inline void Decrypt(const __global ms_office_salt *salt,
                    const AES_KEY_TYPE uchar *verifierInputKey,
                    const __global uchar *encryptedVerifier,
                    uchar *decryptedVerifier,
                    const int length)
{
	uint i;
	uchar iv[32];
	AES_KEY akey;

	for (i = 0; i < 16; i++)
		iv[i] = salt->osalt.c[i];
	for (; i < 32; i++)
		iv[i] = 0;

	AES_set_decrypt_key(verifierInputKey, salt->keySize, &akey);
	AES_cbc_decrypt(encryptedVerifier, decryptedVerifier, length, &akey, iv);
}

__constant uint InputBlockKeyInt[] = { 0xfea7d276, 0x3b4b9e79 };
__constant uint ValueBlockKeyInt[] = { 0xd7aa0f6d, 0x3061344e };

__kernel
void Generate2010key(__global ms_office_state *state,
                     __global ms_office_out *out,
                     const __global ms_office_salt *salt)
{
	uint i, j, result = 1;
	uint W[16], output[5], temp[5];
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

	if (gid == 0)
		out[0].cracked = 0;

	for (i = 0; i < 5; i++)
		output[i] = state[gid].ctx.w[i];
	/* Remainder of sha1(serial.last hash)
	 * We avoid byte-swapping back and forth */
	for (j = 0; j < iterations; j++)
	{
		W[0] = SWAP32(base + j);
		for (i = 1; i < 6; i++)
			W[i] = output[i - 1];
		W[6] = 0x80000000;
		W[15] = 24 << 3;
		sha1_single_192Z(uint, W, output);
	}

	/* Our sha1 destroys input so we store it in temp[] */
	for (i = 0; i < 5; i++)
		W[i] = temp[i] = output[i];

	/* Final hash 1 */
	W[5] = InputBlockKeyInt[0];
	W[6] = InputBlockKeyInt[1];
	W[7] = 0x80000000;
	for (i = 8; i < 15; i++)
		W[i] = 0;
	W[15] = 28 << 3;
	sha1_single(uint, W, output);

	/* Endian-swap to output (we only use 16 bytes) */
	for (i = 0; i < 4; i++)
		out[gid].key[0].w[i] = SWAP32(output[i]);

	/* Final hash 2 */
	for (i = 0; i < 5; i++)
		W[i] = temp[i];
	W[5] = ValueBlockKeyInt[0];
	W[6] = ValueBlockKeyInt[1];
	W[7] = 0x80000000;
	for (i = 8; i < 15; i++)
		W[i] = 0;
	W[15] = 28 << 3;
	sha1_single(uint, W, output);

	/* Endian-swap to output (we only use 16 bytes) */
	for (i = 0; i < 4; i++)
		out[gid].key[1].w[i] = SWAP32(output[i]);

	Decrypt(salt, out[gid].key[0].c, salt->encryptedVerifier,
	        decryptedVerifierHashInputBytes.c, 16);

	Decrypt(salt, out[gid].key[1].c, salt->encryptedVerifierHash,
	        decryptedVerifierHashBytes.c, 32);

	for (i = 0; i < 4; i++)
		W[i] = SWAP32(decryptedVerifierHashInputBytes.w[i]);
	W[4] = 0x80000000;
	for (i = 5; i < 15; i++)
		W[i] = 0;
	W[15] = 16 << 3;
	sha1_single(uint, W, output);

	for (i = 0; i < 20/4; i++) {
		if (decryptedVerifierHashBytes.w[i] != SWAP32(output[i])) {
			result = 0;
			break;
		}
	}

	if ( (out[gid + 1].cracked = result) )
		atomic_max(&out[0].cracked, gid + 1);
}

__kernel void GenerateSHA512pwhash(__global const ulong *unicode_pw,
                                   __global const uint *pw_len,
                                   __global const ms_office_salt *salt,
                                   __global ms_office_state *state)
{
	uint i;
	ulong W[16];
	ulong output[8];
	const uint gid = get_global_id(0);

	/* Initial hash of salt + password */
	/* The ending 0x80 is already in the buffer */
	for (i = 0; i < 2; i++)
		W[i] = SWAP64(salt->osalt.l[i]);
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
                     const __global ms_office_salt *salt)
{
	uint i, j, result = 1;
	ulong W[16], temp[8];
	ulong output[8];
	const uint gid = get_global_id(0);
	const uint base = state[gid].pass;
	const uint iterations = salt->spinCount % HASH_LOOPS13;
	union {
		unsigned char c[16];
		ulong l[16/8];
	} decryptedVerifierHashInputBytes;
	union {
		unsigned char c[32];
		ulong l[32/8];
	} decryptedVerifierHashBytes;

	if (gid == 0)
		out[0].cracked = 0;

	for (i = 0; i < 8; i++)
		output[i] = state[gid].ctx.l[i];

	/* Remainder of iterations */
	for (j = 0; j < iterations; j++)
	{
		W[0] = ((ulong)SWAP32(base + j) << 32) | (output[0] >> 32);
		for (i = 1; i < 8; i++)
			W[i] = (output[i - 1] << 32) | (output[i] >> 32);
		W[8] = (output[7] << 32) | 0x80000000UL;
		W[15] = 68 << 3;
		sha512_single_zeros(W, output);
	}

	/* Our sha512 destroys input so we store a needed portion in temp[] */
	for (i = 0; i < 8; i++)
		W[i] = temp[i] = output[i];

	/* Final hash 1 */
	W[8] = InputBlockKeyLong;
	W[9] = 0x8000000000000000UL;
	for (i = 10; i < 15; i++)
		W[i] = 0;
	W[15] = 72 << 3;
	sha512_single(W, output);

	/* Endian-swap to hash 1 output */
	for (i = 0; i < 8; i++)
		out[gid].key[0].l[i] = SWAP64(output[i]);

	/* Final hash 2 */
	for (i = 0; i < 8; i++)
		W[i] = temp[i];
	W[8] = ValueBlockKeyLong;
	W[9] = 0x8000000000000000UL;
	for (i = 10; i < 15; i++)
		W[i] = 0;
	W[15] = 72 << 3;
#if gpu_amd(DEVICE_INFO)
	/* Workaround for Catalyst 14.4-14.6 driver bug */
	barrier(CLK_GLOBAL_MEM_FENCE);
#endif
	sha512_single(W, output);

	/* Endian-swap to hash 2 output */
	for (i = 0; i < 8; i++)
		out[gid].key[1].l[i] = SWAP64(output[i]);

	Decrypt(salt, out[gid].key[0].c, salt->encryptedVerifier,
	        decryptedVerifierHashInputBytes.c, 16);

	Decrypt(salt, out[gid].key[1].c, salt->encryptedVerifierHash,
	        decryptedVerifierHashBytes.c, 32);

	for (i = 0; i < 2; i++)
		W[i] = SWAP64(decryptedVerifierHashInputBytes.l[i]);
	W[2] = 0x8000000000000000UL;
	for (i = 3; i < 15; i++)
		W[i] = 0;
	W[15] = 16 << 3;
	sha512_single(W, output);

	for (i = 0; i < 32/8; i++) {
		if (decryptedVerifierHashBytes.l[i] != SWAP64(output[i])) {
			result = 0;
			break;
		}
	}

	if ( (out[gid + 1].cracked = result) )
		atomic_max(&out[0].cracked, gid + 1);
}

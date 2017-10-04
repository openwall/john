/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for GPG format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Converted to use 'common' code, Feb29-Mar1 2016, JimF.
 *
 * Added SHA-256 based S2K support, October 2017, Dhiru.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1_ctx.h"
#include "opencl_sha2_ctx.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif
#ifndef SALT_LENGTH
#error SALT_LENGTH must be defined
#endif

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

typedef struct {
	uint length;
	uchar v[PLAINTEXT_LENGTH];
} gpg_password;

typedef struct {
	uchar v[32];
} gpg_hash;

typedef struct {
	uint length;
	uint count;
	uint key_len;
	uchar salt[SALT_LENGTH];
} gpg_salt;

// Slower on CPU
// 40% faster on Intel HD4000
// Bugs out on nvidia
#if !__CPU__ && !gpu_nvidia(DEVICE_INFO)
#define LEAN
#endif

#ifndef __MESA__
inline
#endif
void S2KItSaltedSHA1Generator(__global const uchar *password,
                                     uint password_length,
                                     __constant uchar *salt,
                                     uint _count,
                                     __global uchar *key,
                                     uint key_len)
{
	SHA_CTX ctx;
	const uint tl = password_length + SALT_LENGTH;
	uint i, j=0, n, count;

#ifdef LEAN
	uchar keybuf[128 + 64+1 + PLAINTEXT_LENGTH + SALT_LENGTH];
#else
	uchar keybuf[64 * (PLAINTEXT_LENGTH + SALT_LENGTH)];
	uint bs;
#endif

	for (i = 0; ; ++i) {
		count = _count;
		SHA1_Init(&ctx);
#ifdef LEAN
		for (j=0;j<i;++j)
			keybuf[j] = 0;
		n = j;
		memcpy_cp(keybuf + j, salt, SALT_LENGTH);
		memcpy_gp(keybuf + j + SALT_LENGTH, password, password_length);
		j += tl;

		while (j < 128 + 64+1) {
			memcpy_pp(keybuf + j, keybuf + n, tl);
			j += tl;
		}

		SHA1_Update(&ctx, keybuf, 64);
		count -= (64-i);
		j = 64;
		while (count >= 64) {
			SHA1_Update(&ctx, &keybuf[j], 64);
			count -= 64;
			j = j % tl + 64;
		}
		if (count) SHA1_Update(&ctx, &keybuf[j], count);
#else
		// Find multiplicator
		n = 1;
		while (n < tl && ((64 * n) % tl)) {
			++n;
		}
		// this is an optimization (surprisingly). I get about 10%
		// better on oSSL, and I can run this on my tahiti with this
		// optimization turned on, without crashing the video driver.
		// it is still slower than the LEAN code on the tahiti, but
		// only about 5% slower.  We might be able to find a sweet
		// spot, AND possibly improve times on the LEAN code, since
		// it is only processing 1 64 byte block per call.
#define BIGGER_SMALL_BUFS 1
#if BIGGER_SMALL_BUFS
		if (n < 7) {
			// evenly divisible multiples of each count. We simply want
			// to cut down on the calls to SHA1_Update, I think.
			const uint incs[] = {0,8,8,9,8,10,12};
			n = incs[n];
		}
#endif
		bs = n * 64;
		for (j = 0; j < i; j++) {
			keybuf[j] = 0;
		}
		n = j;

		memcpy_cp(keybuf + j, salt, SALT_LENGTH);
		memcpy_gp(keybuf + j + SALT_LENGTH, password, password_length);
		j += tl;
		while (j+i <= bs+64) { // bs+64 since we need 1 'pre' block that may be dirty.
			memcpy_pp(keybuf + j, keybuf + n, tl);
			j += tl;
		}
		// first buffer 'may' have appended nulls.  So we may actually
		// be processing LESS than 64 bytes of the count. Thus we have
		// -i in the count expression.
		SHA1_Update(&ctx, keybuf, 64);
		count -= (64-i);
		while (count > bs) {
			SHA1_Update(&ctx, keybuf + 64, bs);
			count -= bs;
		}
		if (count) SHA1_Update(&ctx, keybuf + 64, count);
#endif
		SHA1_Final(keybuf, &ctx);

		j = i * SHA_DIGEST_LENGTH;
		for (n = 0; j < key_len && n < SHA_DIGEST_LENGTH; ++j, ++n)
			key[j] = keybuf[n];
		if (j == key_len)
			return;
	}
}

__kernel void gpg(__global const gpg_password *inbuffer,
                  __global gpg_hash *outbuffer,
                  __constant gpg_salt *salt)
{
	uint idx = get_global_id(0);

	S2KItSaltedSHA1Generator(inbuffer[idx].v,
	                         inbuffer[idx].length,
	                         salt->salt,
	                         salt->count,
	                         outbuffer[idx].v,
	                         salt->key_len);
}

/* SHA-256 based S2K */

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

#ifndef __MESA__
inline
#endif
void S2KItSaltedSHA256Generator(__global const uchar *ipassword,
                                     uint password_length,
                                     __constant uchar *isalt,
                                     uint count, // iterations
                                     __global uchar *okey,
                                     uint key_length)
{
	// This code is based on "openpgp_s2k" function from Libgcrypt.
	const uint salt_length = 8; // fixed
	const uint num = (key_length - 1) / SHA256_DIGEST_LENGTH + 1;
	uchar password[PLAINTEXT_LENGTH];
	const uint b[1] = { 0 };
	uchar salt[8];
	uint bytes;
	uint i, j;

	bytes = password_length + salt_length;
	memcpy_cp(salt, isalt, 8);
	memcpy_gp(password, ipassword, password_length);
	if (count < bytes)
		count = bytes;

	for (i = 0; i < num; i++) { // runs only once when key_len <= 32
		SHA256_CTX ctx;
		uchar key[SHA256_DIGEST_LENGTH];

		SHA256_Init(&ctx);
		for (j = 0; j < i; j++) { // not really used
			SHA256_Update(&ctx, (uchar*)b, 1);
		}

		while (count > bytes) {
			SHA256_Update(&ctx, salt, salt_length);
			SHA256_Update(&ctx, password, password_length);
			count = count - bytes;
		}

		if (count < salt_length) {
			SHA256_Update(&ctx, salt, count);
		} else {
			SHA256_Update(&ctx, salt, salt_length);
			count = count - salt_length;
			SHA256_Update(&ctx, password, count);
		}
		SHA256_Final(key, &ctx);
		memcpy_pg(okey + (i * SHA256_DIGEST_LENGTH), key,
				MIN(key_length, SHA256_DIGEST_LENGTH));
	}
}

__kernel void gpg_sha256(__global const gpg_password *inbuffer,
		__global gpg_hash *outbuffer,
		__constant gpg_salt *salt)
{
	uint idx = get_global_id(0);

	S2KItSaltedSHA256Generator(inbuffer[idx].v,
			inbuffer[idx].length,
			salt->salt,
			salt->count,
			outbuffer[idx].v,
			salt->key_len);
}

/* SHA-512 based S2K */

#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64
#endif

#ifndef __MESA__
inline
#endif
void S2KItSaltedSHA512Generator(__global const uchar *ipassword,
                                     uint password_length,
                                     __constant uchar *isalt,
                                     uint count, // iterations
                                     __global uchar *okey,
                                     uint key_length)
{
	// This code is based on "openpgp_s2k" function from Libgcrypt.
	const uint salt_length = 8; // fixed
	const uint num = (key_length - 1) / SHA512_DIGEST_LENGTH + 1;
	uchar password[PLAINTEXT_LENGTH];
	const uint b[1] = { 0 };
	uchar salt[8];
	uint bytes;
	uint i, j;

	bytes = password_length + salt_length;
	memcpy_cp(salt, isalt, 8);
	memcpy_gp(password, ipassword, password_length);
	if (count < bytes)
		count = bytes;

	for (i = 0; i < num; i++) {
		SHA512_CTX ctx;
		uchar key[SHA512_DIGEST_LENGTH];

		SHA512_Init(&ctx);
		for (j = 0; j < i; j++) { // not really used
			SHA512_Update(&ctx, (uchar*)b, 1);
		}

		while (count > bytes) {
			SHA512_Update(&ctx, salt, salt_length);
			SHA512_Update(&ctx, password, password_length);
			count = count - bytes;
		}

		if (count < salt_length) {
			SHA512_Update(&ctx, salt, count);
		} else {
			SHA512_Update(&ctx, salt, salt_length);
			count = count - salt_length;
			SHA512_Update(&ctx, password, count);
		}
		SHA512_Final(key, &ctx);

		memcpy_pg(okey + (i * SHA512_DIGEST_LENGTH), key,
				MIN(key_length, 32));  // 32 bytes is the maximum?
	}
}

__kernel void gpg_sha512(__global const gpg_password *inbuffer,
		__global gpg_hash *outbuffer,
		__constant gpg_salt *salt)
{
	uint idx = get_global_id(0);

	S2KItSaltedSHA512Generator(inbuffer[idx].v,
			inbuffer[idx].length,
			salt->salt,
			salt->count,
			outbuffer[idx].v,
			salt->key_len);
}

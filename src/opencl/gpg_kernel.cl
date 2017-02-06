/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for GPG format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * converted to use 'common' code, Feb29-Mar1 2016, JimF.  Also, added
 * CPU handling of all 'types' which we do not yet have in GPU.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1_ctx.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif
#ifndef SALT_LENGTH
#error SALT_LENGTH must be defined
#endif

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

#ifndef _memcpy
#define _memcpy	memcpy_macro
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
                                     __global const uchar *salt,
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
		_memcpy(keybuf + j, salt, SALT_LENGTH);
		_memcpy(keybuf + j + SALT_LENGTH, password, password_length);
		j += tl;

		while (j < 128 + 64+1) {
			_memcpy(keybuf + j, keybuf + n, tl);
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

		_memcpy(keybuf + j, salt, SALT_LENGTH);
		_memcpy(keybuf + j + SALT_LENGTH, password, password_length);
		j += tl;
		while (j+i <= bs+64) { // bs+64 since we need 1 'pre' block that may be dirty.
			_memcpy(keybuf + j, keybuf + n, tl);
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

__kernel void gpg(__global const gpg_password * inbuffer,
                  __global gpg_hash * outbuffer,
                  __global const gpg_salt * salt)
{
	uint idx = get_global_id(0);

	S2KItSaltedSHA1Generator(inbuffer[idx].v,
	                         inbuffer[idx].length,
	                         salt->salt,
	                         salt->count,
	                         outbuffer[idx].v,
	                         salt->key_len);
}

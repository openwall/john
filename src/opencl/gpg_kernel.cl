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

#ifndef _memcpy
#define _memcpy	memcpy_macro
#endif

typedef struct {
        uint length;
        uchar v[PLAINTEXT_LENGTH];
} gpg_password;

typedef struct {
	uchar v[16];
} gpg_hash;

typedef struct {
        uint length;
	uint count;
        uchar salt[SALT_LENGTH];
} gpg_salt;

// Slower on CPU
// 40% faster on Intel HD4000
// Bugs out on nvidia
#if !__CPU__ && !gpu_nvidia(DEVICE_INFO)
#define LEAN
#endif

inline void S2KItSaltedSHA1Generator(__global const uchar *password,
                                     uint password_length,
                                     __global const uchar *salt,
                                     uint count,
                                     __global uchar *key)
{
	SHA_CTX ctx;
	const uint tl = password_length + SALT_LENGTH;
	uint n;
	uint bs;
#ifdef LEAN
	uchar keybuf[128 + PLAINTEXT_LENGTH + SALT_LENGTH];
#else
	uchar keybuf[64 * (PLAINTEXT_LENGTH + SALT_LENGTH)];
	uchar *bptr;
	uint mul;
#endif
	uchar *lkey = keybuf;	//uchar lkey[20];

	_memcpy(keybuf, salt, SALT_LENGTH);
	_memcpy(keybuf + SALT_LENGTH, password, password_length);

	SHA1_Init(&ctx);

#ifdef LEAN
	bs = tl;
	while (bs < 128) {
		_memcpy(keybuf + bs, keybuf, tl);
		bs += tl;
	}

	bs = 0;
	while (count > 64) {
		SHA1_Update(&ctx, &keybuf[bs], 64);
		count -= 64;
		bs = (bs + 64) % tl;
	}
	SHA1_Update(&ctx, &keybuf[bs], count);
#else
	// Find multiplicator
	mul = 1;
	while (mul < tl && ((64 * mul) % tl)) {
		++mul;
	}
	// Try to feed the hash function with 64-byte blocks
	bs = mul * 64;
	bptr = keybuf + tl;
	n = bs / tl;
	while (n-- > 1) {
		_memcpy(bptr, keybuf, tl);
		bptr += tl;
	}
	n = count / bs;
	while (n-- > 0) {
		SHA1_Update(&ctx, keybuf, bs);
	}
	SHA1_Update(&ctx, keybuf, count % bs);
#endif
	SHA1_Final(lkey, &ctx);

	for(n = 0; n < 16; n++)
		key[n] = lkey[n];
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
	                         outbuffer[idx].v);
}

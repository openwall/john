/*
 * This software is Copyright (c) 2012 Myrice <qqlddg at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha2.h"

typedef struct {
	uint32_t buffer[32];	//1024 bits
	uint32_t buflen;
} xsha512_ctx;

typedef struct {
	uint8_t length;
	char v[PLAINTEXT_LENGTH+1];
} xsha512_key;

inline void xsha512(__global const char *password, uint8_t pass_len,
	__global uint64_t *hash, uint32_t offset, __constant uint32_t *salt)
{
	__private xsha512_ctx ctx;
	uint32_t *b32 = ctx.buffer;

	//set salt to buffer
	*b32 = *salt;

	//set password to buffer
	for (uint32_t i = 0; i < pass_len; i++) {
		PUTCHAR(b32,i+SALT_SIZE,password[i]);
	}
	ctx.buflen = pass_len+SALT_SIZE;

	//append 1 to ctx buffer
	uint32_t length = ctx.buflen;
	PUTCHAR(b32, length, 0x80);
	while((++length & 3) != 0)  {
		PUTCHAR(b32, length, 0);
	}

	uint32_t *buffer32 = b32+(length>>2);
	for (uint32_t i = length; i < 128; i+=4) {// append 0 to 128
		*buffer32++=0;
	}

	//append length to buffer
	uint64_t *buffer64 = (uint64_t *)ctx.buffer;
	buffer64[15] = SWAP64((uint64_t) ctx.buflen * 8);

	// sha512 main
	int i;

	uint64_t a = 0x6a09e667f3bcc908UL;
	uint64_t b = 0xbb67ae8584caa73bUL;
	uint64_t c = 0x3c6ef372fe94f82bUL;
	uint64_t d = 0xa54ff53a5f1d36f1UL;
	uint64_t e = 0x510e527fade682d1UL;
	uint64_t f = 0x9b05688c2b3e6c1fUL;
	uint64_t g = 0x1f83d9abfb41bd6bUL;
	uint64_t h = 0x5be0cd19137e2179UL;

	__private uint64_t w[16];

	uint64_t *data = (uint64_t *) ctx.buffer;

#pragma unroll 16
	for (i = 0; i < 16; i++)
		w[i] = SWAP64(data[i]);

	uint64_t t1, t2;
#pragma unroll 16
	for (i = 0; i < 16; i++) {
		t1 = K[i] + w[i] + h + Sigma1_64(e) + Ch(e, f, g);
		t2 = Maj(a, b, c) + Sigma0_64(a);

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

#pragma unroll 61
	for (i = 16; i < 77; i++) {

		w[i & 15] =sigma1_64(w[(i - 2) & 15]) + sigma0_64(w[(i - 15) & 15]) + w[(i -16) & 15] + w[(i - 7) & 15];
		t1 = K[i] + w[i & 15] + h + Sigma1_64(e) + Ch(e, f, g);
		t2 = Maj(a, b, c) + Sigma0_64(a);

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
	hash[offset] = SWAP64(a);
}

__kernel void kernel_xsha512(
	__global const xsha512_key *password,
	__global uint64_t *hash,
	__constant uint32_t *salt)
{
	uint32_t idx = get_global_id(0);

	xsha512(password[idx].v, password[idx].length, hash, idx, salt);
}

__kernel void kernel_cmp(
	__constant uint64_t *binary,
	__global uint64_t *hash,
	__global uint32_t *result)
{
	uint32_t idx = get_global_id(0);

	if (idx == 0)
		*result = 0;

	barrier(CLK_GLOBAL_MEM_FENCE);

	if (*binary == hash[idx])
		*result = 1;
}

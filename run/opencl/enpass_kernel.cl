/*
 * This software is Copyright (c) 2017 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#define MAYBE_CONSTANT __global
#include "pbkdf2_hmac_sha1_kernel.cl"
#define AES_SRC_TYPE MAYBE_CONSTANT
#include "opencl_aes.h"

#define SQLITE_MAX_PAGE_SIZE    65536

typedef struct {
	uint cracked;
	uint key[((OUTLEN + 19) / 20) * 20 / sizeof(uint)];
} enpass_out;

typedef struct {
	uint  length;
	uint  outlen;
	uint  iterations;
	uchar salt[115];
	union {
		uchar c[16];
		uint  w[16 / 4];
	} iv;
	uchar data[16];
} enpass_salt;

__kernel
void enpass_final(MAYBE_CONSTANT enpass_salt *salt,
                  __global enpass_out *out,
                  __global pbkdf2_state *state)
{
	uint gid = get_global_id(0);
	uint i;
#if !OUTLEN || OUTLEN > 20
	uint base = state[gid].pass++ * 5;
	uint pass = state[gid].pass;
#else
#define base 0
#define pass 1
#endif
#ifndef OUTLEN
#define OUTLEN salt->outlen
#endif

	// First/next 20 bytes of output
	for (i = 0; i < 5; i++)
		out[gid].key[base + i] = SWAP32(state[gid].out[i]);

	/* Was this the last pass? If not, prepare for next one */
	if (4 * base + 20 < OUTLEN) {
		_phsk_hmac_sha1(state[gid].out, state[gid].ipad, state[gid].opad,
		                salt->salt, salt->length, 1 + pass);

		for (i = 0; i < 5; i++)
			state[gid].W[i] = state[gid].out[i];

#ifndef ITERATIONS
		state[gid].iter_cnt = salt->iterations - 1;
#endif
	} else {
		uint32_t pageSize;
		uint32_t usableSize;
		uchar data[16];
		AES_KEY akey;
		int success = 0;
		union {
			uchar c[256 / 8];
			uint  w[256 / 8 / 4];
		} hash;
		union {
			uchar c[16];
			uint  w[16 / 4];
		} iv;

		for (i = 0; i < 256/8/4; i++)
			hash.w[i] = out[gid].key[i];

		for (i = 0; i < 16/4; i++)
			iv.w[i] = salt->iv.w[i];

		AES_set_decrypt_key(hash.c, 256, &akey);
		AES_cbc_decrypt(salt->data, data, 16, &akey, iv.c);

		pageSize = (data[0] << 8) | (data[1] << 16);
		usableSize = pageSize - data[4];

		if ((data[3] <= 2) &&
		    (data[5] == 64 && data[6] == 32 && data[7] == 32) &&
		    (((pageSize - 1) & pageSize) == 0 &&
		     pageSize <= SQLITE_MAX_PAGE_SIZE && pageSize > 256) &&
		    ((pageSize & 7) == 0) &&
		    (usableSize >= 480)) {
			success = 1;
		}

		out[gid].cracked = success;
	}
}

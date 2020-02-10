/*
 * This software is Copyright (c) 2017-2020 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#define MAYBE_CONSTANT __global
#include "pbkdf2_hmac_sha1_kernel.cl"
#include "pbkdf2_hmac_sha512_kernel.cl"
#define AES_SRC_TYPE MAYBE_CONSTANT
#include "opencl_aes.h"

#define SQLITE_MAX_PAGE_SIZE    65536

typedef struct {
	uint32_t cracked;
	uint32_t key[((OUTLEN + 19) / 20) * 20 / sizeof(uint32_t)];
} enpass_out;

typedef struct {
	union {
		pbkdf2_salt s1;
		salt_t s512;
	} pbk_salt;
	union {
		uint8_t  c[16];
		uint32_t w[16/4];
	} iv;
	unsigned char data[16];
} enpass_salt;

inline uint verify_page(uchar *data)
{
	uint32_t pageSize;
	uint32_t usableSize;

	pageSize = (data[0] << 8) | (data[1] << 16);
	usableSize = pageSize - data[4];

	if ((data[3] <= 2) &&
	    (data[5] == 64 && data[6] == 32 && data[7] == 32) &&
	    (((pageSize - 1) & pageSize) == 0 &&
	     pageSize <= SQLITE_MAX_PAGE_SIZE && pageSize > 256) &&
	    ((pageSize & 7) == 0) &&
	    (usableSize >= 480)) {
		return 1;
	}
	return 0;
}

__kernel
void enpass5_final(MAYBE_CONSTANT enpass_salt *salt,
                   __global enpass_out *out,
                   __global pbkdf2_state *state)
{
	uint gid = get_global_id(0);
	uint i;
	uint base = state[gid].pass++ * 5;
	uint pass = state[gid].pass;

	// First/next 20 bytes of output
	for (i = 0; i < 5; i++)
		out[gid].key[base + i] = SWAP32(state[gid].out[i]);

#ifndef OUTLEN
#define OUTLEN salt->pbk_salt.s1.outlen
#endif
	/* Was this the last pass? If not, prepare for next one */
	if (4 * base + 20 < OUTLEN) {
		_phsk_hmac_sha1(state[gid].out, state[gid].ipad,
		                state[gid].opad,
		                salt->pbk_salt.s1.salt,
		                salt->pbk_salt.s1.length, 1 + pass);

		for (i = 0; i < 5; i++)
			state[gid].W[i] = state[gid].out[i];

#ifndef ITERATIONS
		state[gid].iter_cnt = salt->pbk_salt.s1.iterations - 1;
#endif
	} else {
		uchar data[16];
		AES_KEY akey;
		union {
			uchar c[256/8];
			uint  w[256/8/4];
		} hash;
		union {
			uchar c[16];
			uint  w[16/4];
		} iv;

		for (i = 0; i < 256/8/4; i++)
			hash.w[i] = out[gid].key[i];

		for (i = 0; i < 16/4; i++)
			iv.w[i] = salt->iv.w[i];

		AES_set_decrypt_key(hash.c, 256, &akey);
		AES_cbc_decrypt(salt->data, data, 16, &akey, iv.c);

		out[gid].cracked = verify_page(data);
	}
}

inline void _e6_preproc(__global const uint *key,
                        ulong *state, ulong padding)
{
	uint i;
	ulong W[16];
	ulong output[8];

	for (i = 0; i < 8; i++)
		W[i] = (((ulong)key[2 * i] << 32) | key[2 * i + 1]) ^ padding;
	for (; i < 16; i++)
		W[i] = padding;

	sha512_single(W, output);

	for (i = 0; i < 8; i++)
		state[i] = output[i];
}

__kernel
void enpass6_init(__global const uint *inbuffer,
                  __constant salt_t *gsalt,
                  __global state_t *state)
{
	ulong ipad_state[8];
	ulong opad_state[8];
	ulong tmp_out[8];
	uint  i;
	uint idx = get_global_id(0);
	__global const uint *pass = &inbuffer[idx * 16];
	__constant ulong *salt = gsalt->salt;
	uint saltlen = gsalt->length;

	state[idx].rounds = gsalt->rounds - 1;

	_e6_preproc(pass, ipad_state, 0x3636363636363636UL);
	_e6_preproc(pass, opad_state, 0x5c5c5c5c5c5c5c5cUL);

	_phs512_hmac(tmp_out, ipad_state, opad_state, salt, saltlen);

	for (i = 0; i < 8; i++) {
		state[idx].ipad[i] = ipad_state[i];
		state[idx].opad[i] = opad_state[i];
		state[idx].hash[i] = tmp_out[i];
		state[idx].W[i] = tmp_out[i];
	}
}

__kernel
void enpass6_final(MAYBE_CONSTANT enpass_salt *salt,
                   __global enpass_out *out,
                   __global crack_t *out512)
{
	uint gid = get_global_id(0);
	uint i;
	uchar data[16];
	AES_KEY akey;
	union {
		uchar c[256/8];
		ulong  w[256/8/8];
	} hash;
	union {
		uchar c[16];
		uint w[16/4];
	} iv;

	for (i = 0; i < 256/8/8; i++)
		hash.w[i] = SWAP64(out512[gid].hash[i]);

	for (i = 0; i < 16/4; i++)
		iv.w[i] = salt->iv.w[i];

	AES_set_decrypt_key(hash.c, 256, &akey);
	AES_cbc_decrypt(salt->data, data, 16, &akey, iv.c);

	out[gid].cracked = verify_page(data);
}

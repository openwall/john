/*
 * This software is Copyright (c) 2018 Dhiru Kholia, Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha512_kernel.cl"

typedef struct {
	salt_t pbkdf2;
	uint mnemonic_length;
	uchar mnemonic[128];
} tezos_salt_t;

inline void _phs512_preproc_(const ulong *key, uint keylen,
                            ulong *state, ulong mask)
{
	uint i, j;
	ulong W[16];
	ulong A, B, C, D, E, F, G, H, t;

	A = SHA2_INIT_A;
	B = SHA2_INIT_B;
	C = SHA2_INIT_C;
	D = SHA2_INIT_D;
	E = SHA2_INIT_E;
	F = SHA2_INIT_F;
	G = SHA2_INIT_G;
	H = SHA2_INIT_H;

	j = ((keylen+7)/8);
	for (i = 0; i < j; i++)
		W[i] = mask ^ SWAP64(key[i]);

	for (; i < 16; i++)
		W[i] = mask;

	SHA512(A, B, C, D, E, F, G, H, W);

	state[0] = A + SHA2_INIT_A;
	state[1] = B + SHA2_INIT_B;
	state[2] = C + SHA2_INIT_C;
	state[3] = D + SHA2_INIT_D;
	state[4] = E + SHA2_INIT_E;
	state[5] = F + SHA2_INIT_F;
	state[6] = G + SHA2_INIT_G;
	state[7] = H + SHA2_INIT_H;
}

inline void _phs512_hmac_(ulong *output, ulong *ipad_state, ulong *opad_state, ulong *salt, uint saltlen)
{
	uint i, j;
	ulong W[16] = { 0 };
	ulong A, B, C, D, E, F, G, H, t;

	j = ((saltlen + 7) / 8);
	for (i = 0; i < j; i++)
		W[i] = SWAP64(salt[i]);

	// saltlen contains the \0\0\0\1 and 0x80 byte.  The 0001 are part
	// of the salt length. the 0x80 is not, but is the end of hash
	// marker.  So we set legth to be 127+saltlen and not 128+saltlen.
	// 127+saltlen is correct, it just looks funny.
	W[15] = ((127 + saltlen) << 3);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];
	F = ipad_state[5];
	G = ipad_state[6];
	H = ipad_state[7];

	SHA512(A, B, C, D, E, F, G, H, W);

	W[0] = A + ipad_state[0];
	W[1] = B + ipad_state[1];
	W[2] = C + ipad_state[2];
	W[3] = D + ipad_state[3];
	W[4] = E + ipad_state[4];
	W[5] = F + ipad_state[5];
	W[6] = G + ipad_state[6];
	W[7] = H + ipad_state[7];
	W[8] = 0x8000000000000000UL;
	W[15] = 0x600;
	A = opad_state[0];
	B = opad_state[1];
	C = opad_state[2];
	D = opad_state[3];
	E = opad_state[4];
	F = opad_state[5];
	G = opad_state[6];
	H = opad_state[7];

	SHA512_ZEROS(A, B, C, D, E, F, G, H, W);

	A += opad_state[0];
	B += opad_state[1];
	C += opad_state[2];
	D += opad_state[3];
	E += opad_state[4];
	F += opad_state[5];
	G += opad_state[6];
	H += opad_state[7];

	output[0] = A;
	output[1] = B;
	output[2] = C;
	output[3] = D;
	output[4] = E;
	output[5] = F;
	output[6] = G;
	output[7] = H;
}

__kernel void pbkdf2_sha512_kernel_varying_salt(__global const pass_t *inbuffer,
                                   __constant tezos_salt_t *gsalt,
                                   __global state_t *state)
{
	ulong ipad_state[8];
	ulong opad_state[8];
	ulong tmp_out[8];
	uint i;
	uint idx = get_global_id(0);
	int passlen = gsalt->mnemonic_length;
	uint rounds = gsalt->pbkdf2.rounds;
	int saltlen;
	union {
		uchar bytes[8 + sizeof(gsalt->pbkdf2.salt) + 48 /* REAL_PLAINTEXT_LENGTH */];
		ulong data[(8 + sizeof(gsalt->pbkdf2.salt) + 48 + 7) / 8];
	} salt;

	union {
		uchar bytes[PLAINTEXT_LENGTH];
		ulong data[(PLAINTEXT_LENGTH + 7) / 8];
	} pass;

	// setup "password" buffer
	memcpy_macro(pass.data, inbuffer[idx].v, sizeof(inbuffer[idx].v) / 8);

	// create varying salt
	memcpy_macro(salt.bytes, "mnemonic", 8);
	memcpy_macro(&salt.data[1], gsalt->pbkdf2.salt, sizeof(gsalt->pbkdf2.salt) / 8);
	memcpy_macro(salt.bytes + 8 + gsalt->pbkdf2.length, pass.bytes, inbuffer[idx].length);
	saltlen = 8 + gsalt->pbkdf2.length + inbuffer[idx].length;

	// we append the count and eom here, one time, this hack is required by our peculiar opencl pbkdf2_sha512_kernel stuff
	memcpy_macro(salt.bytes + saltlen, "\x0\x0\x0\x1\x80", 5);
	saltlen = saltlen + 5;  // we include the x80 byte in our saltlen, but the .cl kernel knows to reduce saltlen by 1
	for (int i = saltlen; i < saltlen + (8 - saltlen % 8); i++)  // zeroize buffer correctly
            salt.bytes[i] = 0;

	state[idx].rounds = rounds - 1;

	memcpy_macro(pass.bytes, gsalt->mnemonic, passlen);  // actual password
	for (int i = passlen; i < passlen + (8 - passlen % 8); i++)  // zeroize buffer correctly
            pass.bytes[i] = 0;

	_phs512_preproc_(pass.data, passlen, ipad_state, 0x3636363636363636UL);
	_phs512_preproc_(pass.data, passlen, opad_state, 0x5c5c5c5c5c5c5c5cUL);

	_phs512_hmac_(tmp_out, ipad_state, opad_state, salt.data, saltlen);

	for (i = 0; i < 8; i++) {
		state[idx].ipad[i] = ipad_state[i];
		state[idx].opad[i] = opad_state[i];
		state[idx].hash[i] = tmp_out[i];
		state[idx].W[i] = tmp_out[i];
	}
}

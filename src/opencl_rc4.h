/*
 * OpenCL RC4
 *
 * Copyright (c) 2014, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#if !no_byte_addressable(DEVICE_INFO)
__constant uint rc4_iv[64] = { 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                               0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                               0x23222120, 0x27262524, 0x2b2a2928, 0x2f2e2d2c,
                               0x33323130, 0x37363534, 0x3b3a3938, 0x3f3e3d3c,
                               0x43424140, 0x47464544, 0x4b4a4948, 0x4f4e4d4c,
                               0x53525150, 0x57565554, 0x5b5a5958, 0x5f5e5d5c,
                               0x63626160, 0x67666564, 0x6b6a6968, 0x6f6e6d6c,
                               0x73727170, 0x77767574, 0x7b7a7978, 0x7f7e7d7c,
                               0x83828180, 0x87868584, 0x8b8a8988, 0x8f8e8d8c,
                               0x93929190, 0x97969594, 0x9b9a9998, 0x9f9e9d9c,
                               0xa3a2a1a0, 0xa7a6a5a4, 0xabaaa9a8, 0xafaeadac,
                               0xb3b2b1b0, 0xb7b6b5b4, 0xbbbab9b8, 0xbfbebdbc,
                               0xc3c2c1c0, 0xc7c6c5c4, 0xcbcac9c8, 0xcfcecdcc,
                               0xd3d2d1d0, 0xd7d6d5d4, 0xdbdad9d8, 0xdfdedddc,
                               0xe3e2e1e0, 0xe7e6e5e4, 0xebeae9e8, 0xefeeedec,
                               0xf3f2f1f0, 0xf7f6f5f4, 0xfbfaf9f8, 0xfffefdfc
};
#endif

#define swap_byte(a, b) {	  \
		uchar tmp = a; \
		a = b; \
		b = tmp; \
	}

#define swap_state(n) {	  \
		index2 = (key[index1] + state[(n)] + index2) & 255; \
		swap_byte(state[(n)], state[index2]); \
		index1 = (index1 + 1) & 15 /* (& 15 == % keylen) */; \
	}

/* One-shot rc4 with fixed key length and decrypt length of 16 */
inline void rc4_16_16(const uint *key_w, MAYBE_CONSTANT uint *in,
                __global uint *out)
{
	const uchar *key = (uchar*)key_w;
	uint x;
	uint y = 0;
	uint index1 = 0;
	uint index2 = 0;
#if no_byte_addressable(DEVICE_INFO)
	uint state[256];

	/* RC4_init() */
	for (x = 0; x < 256; x++)
		state[x] = x;
#else
	uint state_w[64];
	uchar *state = (uchar*)state_w;

	/* RC4_init() */
	for (x = 0; x < 64; x++)
		state_w[x] = rc4_iv[x];
#endif
#if 0
	/* RC4_set_key() */
	for (x = 0; x < 256; x++)
		swap_state(x);
#else
	/* RC4_set_key() */
	/* Unrolled hard-coded for key length 16 */
	for (x = 0; x < 256; x++) {
		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1++; x++;

		index2 = (key[index1] + state[x] + index2) & 255;
		swap_byte(state[x], state[index2]);
		index1 = 0;
	}
#endif

	/* RC4() */
	/* Unrolled for avoiding byte-addressed stores */
	for (x = 1; x <= 16 /* length */; x++) {
		uint xor_word;

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word = state[(state[x++] + state[y]) & 255];

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word |= state[(state[x++] + state[y]) & 255] << 8;

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word |= state[(state[x++] + state[y]) & 255] << 16;

		y = (state[x] + y) & 255;
		swap_byte(state[x], state[y]);
		xor_word |= state[(state[x] + state[y]) & 255] << 24;

		*out++ = *in++ ^ xor_word;
	}
}

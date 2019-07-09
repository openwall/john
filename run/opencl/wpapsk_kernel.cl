/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall.net>,
 * Copyright (c) 2012 Milen Rangelov and Copyright (c) 2012-2017 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_misc.h"
#include "opencl_md5.h"
#include "opencl_sha1.h"
#include "opencl_sha2_ctx.h"
#include "opencl_cmac.h"

typedef struct {
	uint keymic[16 / 4];
} mic_t;

typedef struct {
	uint  length;
	uint  eapol[(256 + 64) / 4];
	uint  eapol_size;
	uint  data[(64 + 12) / 4]; // pre-processed mac and nonce
	uchar salt[36]; // essid
} wpapsk_salt;

typedef struct {
	MAYBE_VECTOR_UINT W[5];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
	MAYBE_VECTOR_UINT out[5];
	MAYBE_VECTOR_UINT partial[5];
} wpapsk_state;

#ifdef WPAPMK

__kernel
void wpapmk_init(__global const uint *inbuffer,
                 __global wpapsk_state *state)
{
	uint gid = get_global_id(0);
	uint i;

	for (i = 0; i < 5; i++)
		state[gid].partial[i] = inbuffer[gid * 8 + i];
	for (i = 0; i < 3; i++)
		state[gid].out[i] = inbuffer[gid * 8 + 5 + i];
}

#else

inline void hmac_sha1(__global MAYBE_VECTOR_UINT *state,
                      __global MAYBE_VECTOR_UINT *ipad,
                      __global MAYBE_VECTOR_UINT *opad,
                      MAYBE_CONSTANT uchar *salt, uint saltlen, uchar add)
{
	uint i;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT output[5];

	for (i = 0; i < 5; i++)
		output[i] = ipad[i];

	for (i = 0; i < 15; i++)
		W[i] = 0;

	for (i = 0; i < saltlen; i++)
		PUTCHAR_BE(W, i, salt[i]);
	PUTCHAR_BE(W, saltlen + 3, add);
	PUTCHAR_BE(W, saltlen + 4, 0x80);
	W[15] = (64 + saltlen + 4) << 3;
	sha1_block(MAYBE_VECTOR_UINT, W, output);

	for (i = 0; i < 5; i++)
		W[i] = output[i];
	W[5] = 0x80000000;

	for (i = 0; i < 5; i++)
		output[i] = opad[i];
	W[15] = (64 + 20) << 3;
	sha1_block_160Z(MAYBE_VECTOR_UINT, W, output);
	for (i = 0; i < 5; i++)
		state[i] = output[i];
}

inline void preproc(__global const MAYBE_VECTOR_UINT *key,
                    __global MAYBE_VECTOR_UINT *state, uint padding)
{
	uint i;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT output[5];

	for (i = 0; i < 16; i++)
		W[i] = key[i] ^ padding;

	sha1_single(MAYBE_VECTOR_UINT, W, output);

	for (i = 0; i < 5; i++)
		state[i] = output[i];
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_init(__global const MAYBE_VECTOR_UINT *inbuffer,
                 MAYBE_CONSTANT wpapsk_salt *salt,
                 __global wpapsk_state *state)
{
	uint gid = get_global_id(0);
	uint i;

	preproc(&inbuffer[gid * 16], state[gid].ipad, 0x36363636);
	preproc(&inbuffer[gid * 16], state[gid].opad, 0x5c5c5c5c);

	hmac_sha1(state[gid].out, state[gid].ipad, state[gid].opad,
	          salt->salt, salt->length, 0x01);

	for (i = 0; i < 5; i++)
		state[gid].W[i] = state[gid].out[i];
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_loop(__global wpapsk_state *state)
{
	uint gid = get_global_id(0);
	uint i, j;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
	MAYBE_VECTOR_UINT output[5];
	MAYBE_VECTOR_UINT state_out[5];

	for (i = 0; i < 5; i++)
		W[i] = state[gid].W[i];
	for (i = 0; i < 5; i++)
		ipad[i] = state[gid].ipad[i];
	for (i = 0; i < 5; i++)
		opad[i] = state[gid].opad[i];
	for (i = 0; i < 5; i++)
		state_out[i] = state[gid].out[i];

	for (j = 0; j < HASH_LOOPS; j++) {
		for (i = 0; i < 5; i++)
			output[i] = ipad[i];
		W[5] = 0x80000000;
		W[15] = (64 + 20) << 3;
		sha1_block_160Z(MAYBE_VECTOR_UINT, W, output);
		for (i = 0; i < 5; i++)
			W[i] = output[i];
		W[5] = 0x80000000;
		for (i = 0; i < 5; i++)
			output[i] = opad[i];
		W[15] = (64 + 20) << 3;
		sha1_block_160Z(MAYBE_VECTOR_UINT, W, output);
		for (i = 0; i < 5; i++)
			W[i] = output[i];

		for (i = 0; i < 5; i++)
			state_out[i] ^= output[i];
	}

	for (i = 0; i < 5; i++)
		state[gid].W[i] = W[i];
	for (i = 0; i < 5; i++)
		state[gid].out[i] = state_out[i];
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_pass2(MAYBE_CONSTANT wpapsk_salt *salt,
                  __global wpapsk_state *state)
{
	uint gid = get_global_id(0);
	uint i;

	for (i = 0; i < 5; i++)
		state[gid].partial[i] = state[gid].out[i];
	for (i = 0; i < 5; i++)
		state[gid].out[i] = VSWAP32(state[gid].out[i]);

	hmac_sha1(state[gid].out, state[gid].ipad, state[gid].opad, salt->salt, salt->length, 0x02);

	for (i = 0; i < 5; i++)
		state[gid].W[i] = state[gid].out[i];
}
#endif /* WPAPMK */

//__constant uchar *text = "Pairwise key expansion\0";
//__constant uint text[6] = { 0x72696150, 0x65736977, 0x79656b20, 0x70786520, 0x69736e61, 0x00006e6f };
__constant uint text[6] = { 0x50616972, 0x77697365, 0x206b6579, 0x20657870, 0x616e7369, 0x6f6e0000 };

inline void prf_512(const MAYBE_VECTOR_UINT *key,
                    MAYBE_CONSTANT uint *data,
                    MAYBE_VECTOR_UINT *ret)
{
	uint i;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];

	// HMAC(sha1(), key, 32, (text.data), 100, ret, NULL);

	/* ipad */
	for (i = 0; i < 8; i++)
		W[i] = 0x36363636 ^ key[i]; // key is already swapped
	for (i = 8; i < 16; i++)
		W[i] = 0x36363636;
	sha1_single(MAYBE_VECTOR_UINT, W, ipad); // update(ipad)

	/* 64 first bytes */
	for (i = 0; i < 6; i++)
		W[i] = text[i];
	for (i = 5; i < 15; i++) {
		W[i] = (W[i] & 0xffffff00) | *data >> 24;
		W[i + 1] = *data++ << 8;
	}
	W[15] |= *data >> 24;
	sha1_block(MAYBE_VECTOR_UINT, W, ipad); // update(data)

	/* 36 remaining bytes */
	W[0] = *data++ << 8;
	for (i = 0; i < 8; i++) {
		W[i] = (W[i] & 0xffffff00) | *data >> 24;
		W[i + 1] = *data++ << 8;
	}
	W[9] = 0x80000000;
	for (i = 10; i < 15; i++)
		W[i] = 0;
	W[15] = (64 + 100) << 3;
	sha1_block(MAYBE_VECTOR_UINT, W, ipad); // update(data) + final

	/* opad */
	for (i = 0; i < 8; i++)
		W[i] = 0x5c5c5c5c ^ key[i];
	for (i = 8; i < 16; i++)
		W[i] = 0x5c5c5c5c;
	sha1_single(MAYBE_VECTOR_UINT, W, opad); // update(opad)

	for (i = 0; i < 5; i++)
		W[i] = ipad[i];
	W[5] = 0x80000000;
	W[15] = (64 + 20) << 3;
	sha1_block_160Z(MAYBE_VECTOR_UINT, W, opad);
	/* Only 16 bits used */
	for (i = 0; i < 4; i++)
		ret[i] = opad[i];
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_final_md5(__global wpapsk_state *state,
                      MAYBE_CONSTANT wpapsk_salt *salt,
                      __global mic_t *mic)
{
	uint gid = get_global_id(0);
	MAYBE_VECTOR_UINT outbuffer[8];
	MAYBE_VECTOR_UINT prf[4];
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[4], opad[4];
	uint i, eapol_blocks;
	MAYBE_CONSTANT uint *cp = salt->eapol;

	for (i = 0; i < 5; i++)
		outbuffer[i] = state[gid].partial[i];

	for (i = 0; i < 3; i++)
		outbuffer[5 + i] = state[gid].out[i];

	prf_512(outbuffer, salt->data, prf);

	// HMAC(md5(), prf, 16, hccap.eapol, hccap.eapol_size, mic[gid].keymic, NULL);
	// prf is the key (16 bytes)
	// eapol is the message (eapol_size blocks, already prepared with 0x80 and len)
	for (i = 0; i < 4; i++)
		W[i] = 0x36363636 ^ VSWAP32(prf[i]);
	for (i = 4; i < 16; i++)
		W[i] = 0x36363636;
	md5_init(ipad);
	md5_block(MAYBE_VECTOR_UINT, W, ipad); /* md5_update(ipad, 64) */

	/* eapol_blocks (of MD5),
	 * eapol data + 0x80, null padded and len set in set_salt() */
	eapol_blocks = 1 + (salt->eapol_size + 8) / 64;

	/* At least this will not diverge */
	while (eapol_blocks--) {
		for (i = 0; i < 16; i++)
			W[i] = *cp++;
		md5_block(MAYBE_VECTOR_UINT, W, ipad); /* md5_update(), md5_final() */
	}

	for (i = 0; i < 4; i++)
		W[i] = 0x5c5c5c5c ^ VSWAP32(prf[i]);
	for (i = 4; i < 16; i++)
		W[i] = 0x5c5c5c5c;
	md5_init(opad);
	md5_block(MAYBE_VECTOR_UINT, W, opad); /* md5_update(opad, 64) */

	for (i = 0; i < 4; i++)
		W[i] = ipad[i];
	W[4] = 0x80;
	for (i = 5; i < 14; i++)
		W[i] = 0;
	W[14] = (64 + 16) << 3;
	W[15] = 0;
	md5_block(MAYBE_VECTOR_UINT, W, opad); /* md5_update(ipad, 16), md5_final() */

	for (i = 0; i < 4; i++)
#ifdef SCALAR
		mic[gid].keymic[i] = opad[i];
#else

#define VEC_OUT(NUM)	  \
		mic[gid * V_WIDTH + 0x##NUM].keymic[i] = opad[i].s##NUM

	{
		VEC_OUT(0);
		VEC_OUT(1);
#if V_WIDTH > 2
		VEC_OUT(2);
#if V_WIDTH > 3
		VEC_OUT(3);
#if V_WIDTH > 4
		VEC_OUT(4);
		VEC_OUT(5);
		VEC_OUT(6);
		VEC_OUT(7);
#if V_WIDTH > 8
		VEC_OUT(8);
		VEC_OUT(9);
		VEC_OUT(a);
		VEC_OUT(b);
		VEC_OUT(c);
		VEC_OUT(d);
		VEC_OUT(e);
		VEC_OUT(f);
#endif
#endif
#endif
#endif
	}
#endif
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_final_sha1(__global wpapsk_state *state,
                       MAYBE_CONSTANT wpapsk_salt *salt,
                       __global mic_t *mic)
{
	MAYBE_VECTOR_UINT outbuffer[8];
	MAYBE_VECTOR_UINT prf[4];
	uint gid = get_global_id(0);
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
	uint i, eapol_blocks;
	MAYBE_CONSTANT uint *cp = salt->eapol;

	for (i = 0; i < 5; i++)
		outbuffer[i] = state[gid].partial[i];

	for (i = 0; i < 3; i++)
		outbuffer[5 + i] = state[gid].out[i];

	prf_512(outbuffer, salt->data, prf);

	// HMAC(sha1(), prf, 16, hccap.eapol, hccap.eapol_size, mic[gid].keymic, NULL);
	// prf is the key (16 bytes)
	// eapol is the message (eapol_size bytes)
	for (i = 0; i < 4; i++)
		W[i] = 0x36363636 ^ prf[i];
	for (i = 4; i < 16; i++)
		W[i] = 0x36363636;
	sha1_single(MAYBE_VECTOR_UINT, W, ipad);

	/* eapol_blocks (of SHA1),
	 * eapol data + 0x80, null padded and len set in set_salt() */
	eapol_blocks = 1 + (salt->eapol_size + 8) / 64;

	/* At least this will not diverge */
	while (eapol_blocks--) {
		for (i = 0; i < 16; i++)
			W[i] = *cp++;

		sha1_block(MAYBE_VECTOR_UINT, W, ipad);
	}

	for (i = 0; i < 4; i++)
		W[i] = 0x5c5c5c5c ^ prf[i];
	for (i = 4; i < 16; i++)
		W[i] = 0x5c5c5c5c;

	sha1_single(MAYBE_VECTOR_UINT, W, opad);

	for (i = 0; i < 5; i++)
		W[i] = ipad[i];
	W[5] = 0x80000000;
	W[15] = (64 + 20) << 3;
	sha1_block_160Z(MAYBE_VECTOR_UINT, W, opad);
	/* We only use 16 bytes */
	for (i = 0; i < 4; i++)
#ifdef SCALAR
		mic[gid].keymic[i] = SWAP32(opad[i]);
#else

#undef VEC_OUT
#define VEC_OUT(NUM)	  \
	mic[gid * V_WIDTH + 0x##NUM].keymic[i] = SWAP32(opad[i].s##NUM)

	{
		VEC_OUT(0);
		VEC_OUT(1);
#if V_WIDTH > 2
		VEC_OUT(2);
#if V_WIDTH > 3
		VEC_OUT(3);
#if V_WIDTH > 4
		VEC_OUT(4);
		VEC_OUT(5);
		VEC_OUT(6);
		VEC_OUT(7);
#if V_WIDTH > 8
		VEC_OUT(8);
		VEC_OUT(9);
		VEC_OUT(a);
		VEC_OUT(b);
		VEC_OUT(c);
		VEC_OUT(d);
		VEC_OUT(e);
		VEC_OUT(f);
#endif
#endif
#endif
#endif
	}
#endif
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_final_pmkid(__global wpapsk_state *state,
                        MAYBE_CONSTANT wpapsk_salt *salt,
                        __global mic_t *mic)
{
	MAYBE_VECTOR_UINT outbuffer[8];
	uint gid = get_global_id(0);
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
	uint i;
	MAYBE_CONSTANT uint *cp = salt->data;

	for (i = 0; i < 5; i++)
		outbuffer[i] = state[gid].partial[i];

	for (i = 0; i < 3; i++)
		outbuffer[5 + i] = state[gid].out[i];

	// HMAC(sha1(), PMK, 32, "PMK Name" . MAC_AP . MAC_STA)
	// PMK is the key (32 bytes)
	for (i = 0; i < 8; i++)
		W[i] = 0x36363636 ^ outbuffer[i];
	for (; i < 16; i++)
		W[i] = 0x36363636;
	sha1_single(MAYBE_VECTOR_UINT, W, ipad);

	// rest is the message (20 bytes)
	for (i = 0; i < 5; i++)
		W[i] = *cp++;
	W[5] = 0x80000000;
	W[15] = (64 + 20) << 3;
	sha1_block_160Z(MAYBE_VECTOR_UINT, W, ipad);

	for (i = 0; i < 8; i++)
		W[i] = 0x5c5c5c5c ^ outbuffer[i];
	for (; i < 16; i++)
		W[i] = 0x5c5c5c5c;
	sha1_single(MAYBE_VECTOR_UINT, W, opad);

	for (i = 0; i < 5; i++)
		W[i] = ipad[i];
	W[5] = 0x80000000;
	W[15] = (64 + 20) << 3;
	sha1_block_160Z(MAYBE_VECTOR_UINT, W, opad);

	/* We only use 16 bytes */
	for (i = 0; i < 4; i++)
#ifdef SCALAR
		mic[gid].keymic[i] = SWAP32(opad[i]);
#else

#undef VEC_OUT
#define VEC_OUT(NUM)	  \
	mic[gid * V_WIDTH + 0x##NUM].keymic[i] = SWAP32(opad[i].s##NUM)

	{
		VEC_OUT(0);
		VEC_OUT(1);
#if V_WIDTH > 2
		VEC_OUT(2);
#if V_WIDTH > 3
		VEC_OUT(3);
#if V_WIDTH > 4
		VEC_OUT(4);
		VEC_OUT(5);
		VEC_OUT(6);
		VEC_OUT(7);
#if V_WIDTH > 8
		VEC_OUT(8);
		VEC_OUT(9);
		VEC_OUT(a);
		VEC_OUT(b);
		VEC_OUT(c);
		VEC_OUT(d);
		VEC_OUT(e);
		VEC_OUT(f);
#endif
#endif
#endif
#endif
	}
#endif
}

#define SHA256_MAC_LEN 32

inline void
WPA_PUT_LE16(uchar *a, uint val)
{
	a[1] = (val >> 8) & 0xff;
	a[0] = val & 0xff;
}

inline void
sha256_vector(uint num_elem, const uchar *addr[], const uint *len, uchar *mac)
{
	SHA256_CTX ctx;
	uint i;

	SHA256_Init(&ctx);
	for (i = 0; i < num_elem; i++) {
		SHA256_Update(&ctx, addr[i], len[i]);
	}

	SHA256_Final(mac, &ctx);
}

inline void
hmac_sha256_vector(const uchar *key, uint key_len, uint num_elem,
                   const uchar *addr[], const uint *len, uchar *mac)
{
	uchar k_pad[64]; /* padding - key XORd with ipad/opad */
	const uchar *_addr[5];
	uint _len[5], i;

	/* the HMAC_SHA256 transform looks like:
	 *
	 * SHA256(K XOR opad, SHA256(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected */

	/* XOR key with ipad values */
	for (i = 0; i < key_len; i++)
		k_pad[i] = key[i] ^ 0x36;
	for (; i < 64; i++)
		k_pad[i] = 0x36;

	/* perform inner SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	for (i = 0; i < num_elem; i++) {
		_addr[i + 1] = addr[i];
		_len[i + 1] = len[i];
	}
	sha256_vector(1 + num_elem, _addr, _len, mac);

	/* XOR key with opad values */
	for (i = 0; i < key_len; i++)
		k_pad[i] = key[i] ^ 0x5c;
	for (; i < 64; i++)
		k_pad[i] = 0x5c;

	/* perform outer SHA256 */
	_addr[0] = k_pad;
	_len[0] = 64;
	_addr[1] = mac;
	_len[1] = SHA256_MAC_LEN;
	sha256_vector(2, _addr, _len, mac);
}

inline void
sha256_prf_bits(const uchar *key, uint key_len, MAYBE_CONSTANT uchar *data,
                uint data_len, uchar *buf, uint buf_len_bits)
{
	uint counter = 1;
	uint pos, plen;
	const uchar *addr[4];
	uint len[4];
	uchar counter_le[2], length_le[2];
	uint buf_len = (buf_len_bits + 7) / 8;
	const uchar label[] = "Pairwise key expansion";
	uchar pdata[64 + 12];
	uint i;

	for (i = 0; i < data_len; i++)
		pdata[i] = data[i];

	addr[0] = counter_le;
	len[0] = 2;
	addr[1] = label;
	len[1] = (sizeof(label) - 1);     /* strlen(label) */
	addr[2] = pdata;
	len[2] = data_len;
	addr[3] = length_le;
	len[3] = sizeof(length_le);

	WPA_PUT_LE16(length_le, buf_len_bits);
	pos = 0;

	while (pos < buf_len) {
		plen = buf_len - pos;
		WPA_PUT_LE16(counter_le, counter);
		if (plen >= SHA256_MAC_LEN) {
			hmac_sha256_vector(key, key_len, 4, addr, len, &buf[pos]);
			pos += SHA256_MAC_LEN;
		} else {
			uchar hash[SHA256_MAC_LEN];
			uint i;

			hmac_sha256_vector(key, key_len, 4, addr, len, hash);
			for (i = 0; i < plen; i++)
				buf[pos + i] = hash[i];
			pos += plen;
			break;
		}
		counter++;
	}

	/*
	 * Mask out unused bits in the last octet if it does not use all the
	 * bits.
	 */
	if (buf_len_bits % 8) {
		uchar mask = 0xff << (8 - buf_len_bits % 8);
		buf[pos - 1] &= mask;
	}
}

__kernel
void wpapsk_final_sha256(__global wpapsk_state *state,
                         MAYBE_CONSTANT wpapsk_salt *salt,
                         __global mic_t *mic)
{
	uchar ptk[48];
	uchar cmic[16];
	uint outbuffer[8];
	uint gid = get_global_id(0);
	uint i;
	AES_CMAC_CTX ctx;

	for (i = 0; i < 5; i++)
		outbuffer[i] = SWAP32(state[gid].partial[i]);

	for (i = 0; i < 3; i++)
		outbuffer[5 + i] = SWAP32(state[gid].out[i]);

	sha256_prf_bits((uchar*)outbuffer, 32, (MAYBE_CONSTANT uchar*)salt->data, 76, ptk, 48 * 8);

	/* CMAC is kinda like a HMAC but using AES */
	AES_CMAC_Init(&ctx);
	AES_CMAC_SetKey(&ctx, ptk);
	AES_CMAC_Update(&ctx, (MAYBE_CONSTANT uchar*)salt->eapol, salt->eapol_size);
	AES_CMAC_Final(cmic, &ctx);

	/* We only use 16 bytes */
	for (i = 0; i < 16; i++)
		((__global uchar*)mic[gid].keymic)[i] = cmic[i];
}

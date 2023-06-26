/*
 * This software is Copyright (c) 2018-2021 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_misc.h"
#define HMAC_MSG_TYPE __global const
#define HMAC_OUT_TYPE __global
#include "opencl_hmac_sha1.h"
#include "opencl_sha1.h"

#define WINZIP_BINARY_SIZE 10
#define BLK_SZ             SHA_DIGEST_LENGTH

typedef struct {
	uint32_t iterations;
	uint32_t key_len;
	uint32_t length;
	uint8_t  salt[64];
	uint32_t autotune;
	uint64_t comp_len;
	uchar    passverify[2];
} zip_salt;

typedef struct {
	uint in_idx;
	uchar v[BLK_SZ];
} zip_hash;

#define OUTLEN             SHA_DIGEST_LENGTH

/* avoid name clashes */
#define preproc   u_preproc
#define hmac_sha1 u_hmac_sha1
#define big_hmac_sha1 u_big_hmac_sha1

inline void preproc(const uchar *key, uint keylen, uint *state, uint padding)
{
	uint i;
	uint W[16];
	uint A, B, C, D, E, temp, r[16];

	for (i = 0; i < 16; i++)
		W[i] = padding;

	for (i = 0; i < keylen; i++)
		XORCHAR_BE(W, i, key[i]);

	A = INIT_A;
	B = INIT_B;
	C = INIT_C;
	D = INIT_D;
	E = INIT_E;

	SHA1(A, B, C, D, E, W);

	state[0] = A + INIT_A;
	state[1] = B + INIT_B;
	state[2] = C + INIT_C;
	state[3] = D + INIT_D;
	state[4] = E + INIT_E;
}

inline void hmac_sha1(uint *output, uint *ipad_state, uint *opad_state, __constant uchar *salt, int saltlen, uchar add)
{
	int i;
	uint W[16];
	uint A, B, C, D, E, temp, r[16];
	union {
		uchar c[64];
		uint w[64/4];
	} buf;

	for (i = 0; i < 16; i++)
		buf.w[i] = 0;
	memcpy_cp(buf.c, salt, saltlen);

	buf.c[saltlen + 4] = 0x80;
	buf.c[saltlen + 3] = add;
	PUT_UINT32BE((64 + saltlen + 4) << 3, buf.c, 60);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];

	for (i = 0; i < 16; i++)
		W[i] = SWAP32(buf.w[i]);

	SHA1(A, B, C, D, E, W);

	W[0] = A + ipad_state[0];
	W[1] = B + ipad_state[1];
	W[2] = C + ipad_state[2];
	W[3] = D + ipad_state[3];
	W[4] = E + ipad_state[4];
	W[5] = 0x80000000;
	W[15] = 0x2A0;

	A = opad_state[0];
	B = opad_state[1];
	C = opad_state[2];
	D = opad_state[3];
	E = opad_state[4];

	SHA1_160Z(A, B, C, D, E, W);

	A += opad_state[0];
	B += opad_state[1];
	C += opad_state[2];
	D += opad_state[3];
	E += opad_state[4];

	output[0] = A;
	output[1] = B;
	output[2] = C;
	output[3] = D;
	output[4] = E;
}

inline void big_hmac_sha1(uint *input, uint inputlen, uint *ipad_state, uint *opad_state, uint *tmp_out, uint iter)
{
	uint i;
	uint W[16];

	for (i = 0; i < 5; i++)
		W[i] = input[i];

	for (i = 1; i < iter; i++) {
		uint A, B, C, D, E, temp;

		A = ipad_state[0];
		B = ipad_state[1];
		C = ipad_state[2];
		D = ipad_state[3];
		E = ipad_state[4];

		W[5] = 0x80000000;
		W[15] = 0x2A0;

		SHA1_160Z(A, B, C, D, E, W);

		W[0] = A + ipad_state[0];
		W[1] = B + ipad_state[1];
		W[2] = C + ipad_state[2];
		W[3] = D + ipad_state[3];
		W[4] = E + ipad_state[4];
		W[5] = 0x80000000;
		W[15] = 0x2A0;

		A = opad_state[0];
		B = opad_state[1];
		C = opad_state[2];
		D = opad_state[3];
		E = opad_state[4];

		SHA1_160Z(A, B, C, D, E, W);

		A += opad_state[0];
		B += opad_state[1];
		C += opad_state[2];
		D += opad_state[3];
		E += opad_state[4];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;

		tmp_out[0] ^= A;
		tmp_out[1] ^= B;
		tmp_out[2] ^= C;
		tmp_out[3] ^= D;
		tmp_out[4] ^= E;
	}
}

inline void pbkdf2_hmac_sha1(const uchar *pass, const uint passlen,
                             __constant uchar *salt, const uint saltlen, const uint iterations,
                             uchar *out, const uint outlen, uint skip_bytes)
{
	uint ipad_state[5];
	uint opad_state[5];
#if gpu_nvidia(DEVICE_INFO)
	/* Nvidia driver bug workaround. Problem seen with 460.91.03 & 465.19.01 */
	volatile
#endif
		uint accum = 0;

	preproc(pass, passlen, ipad_state, 0x36363636);
	preproc(pass, passlen, opad_state, 0x5c5c5c5c);

	const uint loops = (skip_bytes + outlen + (BLK_SZ-1)) / BLK_SZ;
	uint loop = skip_bytes / BLK_SZ + 1;
	skip_bytes %= BLK_SZ;

	while (loop <= loops) {
		uint tmp_out[5];
		uint i;

		hmac_sha1(tmp_out, ipad_state, opad_state, salt, saltlen, loop);

		big_hmac_sha1(tmp_out, BLK_SZ, ipad_state, opad_state, tmp_out, iterations);

		for (i = skip_bytes; i < BLK_SZ && accum < outlen; i++, accum++)
			out[accum] = ((uchar*)tmp_out)[i ^ 3];

		loop++;
		skip_bytes = 0;
	}
}

#undef preproc
#undef hmac_sha1
#undef big_hmac_sha1

inline uint prepare(__global const uchar *pwbuf, __global const uint *buf_idx, uint index, uchar *password)
{
	uint i;
	uint base = buf_idx[index];
	uint len = buf_idx[index + 1] - base;

	pwbuf += base;

	/* Work-around for self-tests not always calling set_key() like IRL */
	if (len > PLAINTEXT_LENGTH)
		len = 0;

	for (i = 0; i < len; i++)
		password[i] = pwbuf[i];

	return len;
}

#define ITERATIONS 1000 /* salt->iterations */

__kernel void zip(__global const uchar *pwbuf,
                  __global const uint *buf_idx,
                  __constant zip_salt *salt,
                  volatile __global uint *crack_count_ret,
                  __global zip_hash *result)
{
	const uint gid = get_global_id(0);
	const int early_skip = 2 * salt->key_len / BLK_SZ * BLK_SZ;
	uchar password[PLAINTEXT_LENGTH];
	uchar pwd_ver[BLK_SZ];

	/* Fetch password from packed buffer */
	const uint len = prepare(pwbuf, buf_idx, gid, password);

	pbkdf2_hmac_sha1(password, len, salt->salt, salt->length, ITERATIONS, pwd_ver, BLK_SZ, early_skip);

	if (!memcmp_pc(pwd_ver + 2 * salt->key_len - early_skip, salt->passverify, 2) ||
	    (salt->autotune && !(gid & 0xffff)))
	{
		const uint out_idx = atomic_inc(crack_count_ret);

		result[out_idx].in_idx = gid;
		memcpy_pg(result[out_idx].v, pwd_ver, BLK_SZ);
	}
}

kernel void zip_final(__global const uchar *pwbuf,
                      __global const uint *buf_idx,
                      __constant zip_salt *salt,
                      __global const uchar *saltdata,
                      volatile __global uint *crack_count_ret,
                      __global zip_hash *result)
{
	const uint gid = get_global_id(0);
	const uint early_skip = 2 * salt->key_len / BLK_SZ * BLK_SZ;
	const uint late_skip = salt->key_len / BLK_SZ * BLK_SZ;
	const uint late_size = early_skip - late_skip;
	const uint comp_len = salt->autotune ? MIN(salt->comp_len, 0x1000000) : salt->comp_len;
	uchar password[PLAINTEXT_LENGTH];
	uchar pwd_ver[3 * BLK_SZ];

	if (gid >= *crack_count_ret)
		return;

	memcpy_gp(pwd_ver + early_skip - late_skip, result[gid].v, BLK_SZ);

	/* Fetch original index and then get the password from packed buffer */
	const uint len = prepare(pwbuf, buf_idx, result[gid].in_idx, password);

	pbkdf2_hmac_sha1(password, len, salt->salt, salt->length, ITERATIONS, pwd_ver, late_size, late_skip);

	hmac_sha1(pwd_ver + salt->key_len - late_skip, salt->key_len, saltdata, comp_len,
	          result[gid].v, WINZIP_BINARY_SIZE);
}

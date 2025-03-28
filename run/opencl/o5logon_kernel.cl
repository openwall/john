/*
 * Copyright (c) 2012-2025, magnum
 * Copyright (c) 2014 Harrison Neal
 * Copyright (c) 2011 by Samuele Giovanni Tonon, samu at linuxasylum dot net
 *
 * This program comes with ABSOLUTELY NO WARRANTY; express or
 * implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1.h"
#include "opencl_md5_ctx.h"
#include "opencl_mask.h"

// Workaround for UHD Graphics 630 version "1.2(Jan 10 2025 21:16:54)"
#if (__OS_X__ && gpu_intel(DEVICE_INFO))
#define AES_BITSLICE 1
#endif
#include "opencl_aes.h"

typedef struct {
	uint pw_len;                          /* AUTH_PASSWORD length (blocks) */
	uint salt[(SALT_LENGTH + 1 + 3) / 4]; /* AUTH_VFR_DATA */
	uchar ct[CIPHERTEXT_LENGTH];          /* Server's AUTH_SESSKEY */
	uchar csk[CIPHERTEXT_LENGTH];         /* Client's AUTH_SESSKEY */
	uchar pw[PLAINTEXT_LENGTH + 16];      /* Client's AUTH_PASSWORD, padded */
} o5logon_salt;

#define SECRET_LEN (CIPHERTEXT_LENGTH - 16)

__kernel void
o5logon_kernel(__global const uchar* key_buf, __global const uint* const key_idx,
               __constant o5logon_salt* salt,
               __global volatile uint* crack_count_ret,
               __global uint* const out_index,
               __global const uint* const int_key_loc,
               __global const uint* const int_keys)
{
	__local aes_local_t lt;
	AES_KEY akey; akey.lt = &lt;

	const uint gid = get_global_id(0);

#if NUM_INT_KEYS > 1 && !IS_STATIC_GPU_MASK
	const uint ikl = int_key_loc[gid];
	const uint loc0 = ikl & 0xff;
#if MASK_FMT_INT_PLHDR > 1
#if LOC_1 >= 0
	const uint loc1 = (ikl & 0xff00) >> 8;
#endif
#endif
#if MASK_FMT_INT_PLHDR > 2
#if LOC_2 >= 0
	const uint loc2 = (ikl & 0xff0000) >> 16;
#endif
#endif
#if MASK_FMT_INT_PLHDR > 3
#if LOC_3 >= 0
	const uint loc3 = (ikl & 0xff000000) >> 24;
#endif
#endif
#endif

#if !IS_STATIC_GPU_MASK
#define GPU_LOC_0 loc0
#define GPU_LOC_1 loc1
#define GPU_LOC_2 loc2
#define GPU_LOC_3 loc3
#else
#define GPU_LOC_0 LOC_0
#define GPU_LOC_1 LOC_1
#define GPU_LOC_2 LOC_2
#define GPU_LOC_3 LOC_3
#endif

	const uint base = key_idx[gid];
	const uint len = key_idx[gid + 1] - base;
	key_buf += base;

	const uint shift = len % 4;
	const uint sr = 8 * shift;
	const uint sl = 32 - sr;
	const uint sra = (0xffffffff - (1 << sr)) + 1;
	const uint sla = 0xffffffff - sra;

	// Endian swap salt
	uint salt_be[sizeof(salt->salt) / 4];
	for (uint i = 0; i < sizeof(salt->salt) / 4; i++)
		salt_be[i] = SWAP32(salt->salt[i]);

	for (uint idx = 0; idx < NUM_INT_KEYS; idx++) {
		const uint gidx = gid * NUM_INT_KEYS + idx;
		uchar password[PLAINTEXT_LENGTH] = { 0 };
		uint i;

		for (i = 0; i < len; i++)
			password[i] = key_buf[i];

#if NUM_INT_KEYS > 1
		password[GPU_LOC_0] = (int_keys[idx] & 0xff);
#if MASK_FMT_INT_PLHDR > 1
#if LOC_1 >= 0
		password[GPU_LOC_1] = (int_keys[idx] & 0xff >> 8);
#endif
#endif
#if MASK_FMT_INT_PLHDR > 2
#if LOC_2 >= 0
		password[GPU_LOC_2] = (int_keys[idx] & 0xff >> 16);
#endif
#endif
#if MASK_FMT_INT_PLHDR > 3
#if LOC_3 >= 0
		password[GPU_LOC_3] = (int_keys[idx] & 0xff >> 24);
#endif
#endif
#endif
		uint W[16] = { 0 };
		for (i = 0; i < PLAINTEXT_LENGTH / 4; i++)
			GET_UINT32BE(W[i], password, 4 * i);

		// Shift the salt bytes into place after the given key.
		W[len / 4] |= (salt_be[0] & sra) >> sr;
		W[len / 4 + 1] = ((salt_be[0] & sla) << sl) | ((salt_be[1] & sra) >> sr);
		W[len / 4 + 2] = ((salt_be[1] & sla) << sl) | ((salt_be[2] & sra) >> sr);
		W[len / 4 + 3] = (salt_be[2] & sla) << sl;

		// The Merkel-Damgård 0x80 ending byte was already added to the salt
		// on host side, here's the length.
		W[15] = (len + 10) << 3;

		uint output[160 / 32];
		sha1_single(uint, W, output);

		union {
			uchar c[192 / 8];
			uint w[0];
		} key;
		for (i = 0; i < 5; i++)
			key.w[i] = SWAP32(output[i]);
		key.w[5] = 0;

		uchar iv[16];

		AES_set_decrypt_key(key.c, 192, &akey);

		if (salt->pw_len) {
			const uint blen = (len + 15) / 16;

			// Early reject
			if (salt->pw_len != blen)
				return;

			memcpy_cp(iv, salt->ct, 16);
			uchar ct[SECRET_LEN];
			memcpy_cp(ct, salt->ct + 16, SECRET_LEN);

			uchar s_secret[SECRET_LEN];
			//AES_set_decrypt_key(key.c, 192, &akey);
			AES_cbc_decrypt(ct, s_secret, SECRET_LEN, &akey, iv);

			memcpy_cp(iv, salt->csk, 16);
			uchar csk[SECRET_LEN];
			memcpy_cp(csk, salt->csk + 16, SECRET_LEN);
			uchar c_secret[SECRET_LEN];
			//AES_set_decrypt_key(key.c, 192, &akey);
			AES_cbc_decrypt(csk, c_secret, SECRET_LEN, &akey, iv);

			uchar combined_sk[SECRET_LEN];
			for (i = 0; i < SECRET_LEN; i++)
				combined_sk[i] = s_secret[i] ^ c_secret[i];

			uchar final_key[32];
			MD5_CTX ctx;
			MD5_Init(&ctx);
			MD5_Update(&ctx, combined_sk, 16);
			MD5_Final(final_key, &ctx);
			MD5_Init(&ctx);
			MD5_Update(&ctx, combined_sk + 16, 8);
			MD5_Final(final_key + 16, &ctx);

			memcpy_cp(iv, salt->pw, 16);

			uchar pw[PLAINTEXT_LENGTH];
			memcpy_cp(pw, salt->pw + 16, PLAINTEXT_LENGTH);

			uchar dec_pw[PLAINTEXT_LENGTH + 16];
			AES_set_decrypt_key(final_key, 192, &akey);
			AES_cbc_decrypt(pw, dec_pw, salt->pw_len * 16, &akey, iv);

			if (!memcmp_pp(dec_pw, password, len) &&
			    check_pkcs_pad(dec_pw, salt->pw_len * 16, AES_BLOCK_SIZE))
				out_index[atomic_inc(crack_count_ret)] = gidx;
		} else {
			union {
				uchar c[16];
				ulong l[0];
			} pt;

			memcpy_cp(iv, &salt->ct[16], 16);
			uchar ct[16];
			memcpy_cp(ct, &salt->ct[32], 16);
			//AES_set_decrypt_key(key.c, 192, &akey);
			AES_cbc_decrypt(ct, pt.c, 16, &akey, iv);

			if (pt.l[1] == 0x0808080808080808UL)
				out_index[atomic_inc(crack_count_ret)] = gidx;
		}
	}
}

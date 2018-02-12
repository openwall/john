/*
 * This software is Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

typedef struct {
	uint dk[((OUTLEN + 19) / 20) * 20 / sizeof(uint)];
	uint cracked;
} dmg_out;

#define pbkdf2_out dmg_out
#include "pbkdf2_hmac_sha1_kernel.cl"
#define AES_SRC_TYPE MAYBE_CONSTANT
#include "opencl_aes.h"
#include "opencl_des.h"
#include "opencl_sha1_ctx.h"

typedef struct {
	pbkdf2_salt pbkdf2;
	uint headerver;
	uint ivlen;
	uchar iv[32];
	uint32_t encrypted_keyblob_size;
	uint8_t encrypted_keyblob[32];
	uint len_wrapped_aes_key;
	uchar wrapped_aes_key[296];
	uint len_hmac_sha1_key;
	uchar wrapped_hmac_sha1_key[300];
	int cno;
	int data_size;
	uchar chunk[8192];
	uint scp; /* start chunk present */
	uchar zchunk[4096]; /* chunk #0 */
} dmg_salt;

inline void hmac_sha1(const uchar *_key, uint key_len,
                      const uchar *data, uint data_len,
                      uchar *digest, uint digest_len)
{
	uint pW[16];
	uchar *buf = (uchar*)pW;
	uchar local_digest[20];
	SHA_CTX ctx;
	uint i;

#if HMAC_KEY_GT_64
	if (key_len > 64) {
		SHA1_Init(&ctx);
		while (key_len) {
			uchar pbuf[64];
			uint len = MIN(data_len, (uint)sizeof(pbuf));

			memcpy_macro(pbuf, _key, len);
			SHA1_Update(&ctx, pbuf, len);
			data_len -= len;
			_key += len;
		}
		SHA1_Final(buf, &ctx);
		pW[0] ^= 0x36363636;
		pW[1] ^= 0x36363636;
		pW[2] ^= 0x36363636;
		pW[3] ^= 0x36363636;
		pW[4] ^= 0x36363636;
		memset_p(&buf[20], 0x36, 44);
	} else
#endif
	{
		memcpy_macro(buf, _key, key_len);
		memset_p(&buf[key_len], 0, 64 - key_len);
		for (i = 0; i < 16; i++)
			pW[i] ^= 0x36363636;
	}
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, buf, 64);
	SHA1_Update(&ctx, data, data_len);
	SHA1_Final(local_digest, &ctx);
	for (i = 0; i < 16; i++)
		pW[i] ^= (0x36363636 ^ 0x5c5c5c5c);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, buf, 64);
	SHA1_Update(&ctx, local_digest, 20);
	if (digest_len < 20) {
		SHA1_Final(local_digest, &ctx);
		memcpy_pp(digest, local_digest, digest_len);
	} else
		SHA1_Final(digest, &ctx);
}

inline int check_pkcs_pad(const uchar *data, int len, int blocksize)
{
	int pad_len, padding, real_len;

	if (len & (blocksize - 1))
		return -1;

	if (len < blocksize)
		return -1;

	pad_len = data[len - 1];

	if (pad_len > blocksize)
		return -1;

	real_len = len - pad_len;
	data += real_len;

	padding = pad_len;

	while (pad_len--)
		if (*data++ != padding)
			return -1;

	return real_len;
}

inline int apple_des3_ede_unwrap_key1(MAYBE_CONSTANT uchar *wrapped_key,
                                      const int wrapped_key_len,
                                      const uchar *decryptKey)
{
	des3_context ks;
	uchar temp1[sizeof(((dmg_salt*)0)->wrapped_hmac_sha1_key)];
	uchar temp2[sizeof(((dmg_salt*)0)->wrapped_hmac_sha1_key)];
	uchar iv[8] = { 0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 };
	int outlen, i;

	des3_set3key_dec(&ks, decryptKey);
	des3_crypt_cbc(&ks, DES_DECRYPT, wrapped_key_len, iv,
	               MAYBE_CONSTANT, wrapped_key, temp1);

	outlen = check_pkcs_pad(temp1, wrapped_key_len, 8);
	if (outlen < 16 || outlen & 7)
		return 0;

	for (i = 0; i < outlen; i++)
		temp2[i] = temp1[outlen - i - 1];

	outlen -= 8;
	des3_crypt_cbc(&ks, DES_DECRYPT, outlen, temp2,
	               __private const, temp2 + 8, temp1);

	return (check_pkcs_pad(temp1, outlen, 8) >= 0);
}

/* Check for 64-bit NULL at 32-bit alignment */
inline int check_nulls(const void *buf, uint size)
{
	const uint *p = buf;

	size /= sizeof(size);

	while (--size)
		if (!*p++ && !*p++)
			return 1;
	return 0;
}

inline int check_v1hash(const uchar *derived_key,
                        MAYBE_CONSTANT dmg_salt *salt)
{
	if (!apple_des3_ede_unwrap_key1(salt->wrapped_aes_key,
	                                salt->len_wrapped_aes_key, derived_key))
			return 0;

	if (!apple_des3_ede_unwrap_key1(salt->wrapped_hmac_sha1_key,
	                                salt->len_hmac_sha1_key, derived_key))
			return 0;

	return 1;
}

inline int check_v2hash(const uchar *derived_key,
                        MAYBE_CONSTANT dmg_salt *salt)
{
	des3_context ks;
	AES_KEY aes_decrypt_key;
	uint buf[8192/4];
	uchar *outbuf = (uchar*)buf;
	uchar iv[20];
	uchar key[32];
	const int cno = salt->cno;

	des3_set3key_dec(&ks, derived_key);
	memcpy_macro(iv, salt->iv, 8);
	des3_crypt_cbc(&ks, DES_DECRYPT, 32, iv,
	               MAYBE_CONSTANT, salt->encrypted_keyblob, key);

	hmac_sha1(key, 20, (const uchar*)&cno, 4, iv, 20);
	if (salt->encrypted_keyblob_size == 48)
		AES_set_decrypt_key(key, 128, &aes_decrypt_key);
	else
		AES_set_decrypt_key(key, 256, &aes_decrypt_key);
	AES_cbc_decrypt(salt->chunk, outbuf, salt->data_size, &aes_decrypt_key, iv);

	/* 8 consecutive nulls */
	if (check_nulls(outbuf, salt->data_size))
		return 1;

	/* Second buffer. If present, *this* is the first block of the DMG */
	if (salt->scp == 1) {
		const int cno = 0;

		hmac_sha1(key, 20, (const uchar*)&cno, 4, iv, 20);
		if (salt->encrypted_keyblob_size == 48)
			AES_set_decrypt_key(key, 128, &aes_decrypt_key);
		else
			AES_set_decrypt_key(key, 256, &aes_decrypt_key);
		AES_cbc_decrypt(salt->zchunk, outbuf, 4096, &aes_decrypt_key, iv);

		/* 8 consecutive nulls */
		if (check_nulls(outbuf, 4096))
			return 1;
	}

	return 0;
}

__kernel
void dmg_final_v1(MAYBE_CONSTANT dmg_salt *salt,
                  __global dmg_out *out)
{
	uint gid = get_global_id(0);
	uint dk[OUTLEN / 4];

	memcpy_gp(dk, out[gid].dk, OUTLEN);

	out[gid].cracked = check_v1hash((uchar*)dk, salt);
}

__kernel
void dmg_final_v2(MAYBE_CONSTANT dmg_salt *salt,
                  __global dmg_out *out)
{
	uint gid = get_global_id(0);
	uint dk[OUTLEN / 4];

	memcpy_gp(dk, out[gid].dk, OUTLEN);

	out[gid].cracked = check_v2hash((uchar*)dk, salt);
}

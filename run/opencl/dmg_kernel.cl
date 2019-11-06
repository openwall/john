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
#if __OS_X__
#define AES_NO_BITSLICE
#endif
#define AES_SRC_TYPE MAYBE_CONSTANT
#include "opencl_aes.h"
#include "opencl_hmac_sha1.h"
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

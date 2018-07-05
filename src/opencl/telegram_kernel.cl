/*
 * This software is Copyright (c) 2018 Dhiru Kholia, Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha1_kernel.cl"
#include "opencl_aes.h"
#include "opencl_sha1_ctx.h"

typedef struct {
	uint cracked;
} telegram_out;

typedef struct {
	pbkdf2_salt pbkdf2;
	int encrypted_blob_length;
	uchar encrypted_blob[ENCRYPTED_BLOB_LEN];
} telegram_salt;

inline int telegram_decrypt(__global uchar *authkey, MAYBE_CONSTANT telegram_salt *salt)
{
	// variables
	uchar data_a[48];
	uchar data_b[48];
	uchar data_c[48];
	uchar data_d[48];
	uchar sha1_a[20];
	uchar sha1_b[20];
	uchar sha1_c[20];
	uchar sha1_d[20];
	uchar shaf[20];
	uchar message_key[16];
	uchar aes_key[32];
	uchar aes_iv[32];
	uchar encrypted_data[ENCRYPTED_BLOB_LEN];
	uchar decrypted_data[ENCRYPTED_BLOB_LEN];
	int encrypted_data_length = salt->encrypted_blob_length - 16;
	SHA_CTX ctx;
	SHA_CTX fctx;
	AES_KEY aeskey;
	int i;

	// setup buffers
	memcpy_macro(message_key, salt->encrypted_blob, 16);
	memcpy_macro(encrypted_data, salt->encrypted_blob + 16, encrypted_data_length);

	memcpy_macro(data_a, message_key, 16);
	memcpy_macro(data_b + 16, message_key, 16);
	memcpy_macro(data_c + 32, message_key, 16);
	memcpy_macro(data_d, message_key, 16);

	memcpy_macro(data_a + 16, authkey + 8, 32);
	memcpy_macro(data_b, authkey + 40, 16);
	memcpy_macro(data_b + 32, authkey + 56, 16);
	memcpy_macro(data_c, authkey + 72, 32);
	memcpy_macro(data_d + 16, authkey + 104, 32);

	// kdf
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data_a, 48);
	SHA1_Final(sha1_a, &ctx);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data_b, 48);
	SHA1_Final(sha1_b, &ctx);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data_c, 48);
	SHA1_Final(sha1_c, &ctx);


	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data_d, 48);
	SHA1_Final(sha1_d, &ctx);

	memcpy_macro(aes_key, sha1_a, 8);
	memcpy_macro(aes_key + 8, sha1_b + 8, 12);
	memcpy_macro(aes_key + 20, sha1_c + 4, 12);

	memcpy_macro(aes_iv, sha1_a + 8, 12);
	memcpy_macro(aes_iv + 12, sha1_b, 8);
	memcpy_macro(aes_iv + 20, sha1_c + 16, 4);
	memcpy_macro(aes_iv + 24, sha1_d, 8);

	// decrypt
	AES_set_decrypt_key(aes_key, 256, &aeskey);
	AES_ige_decrypt(encrypted_data, decrypted_data, encrypted_data_length, &aeskey, aes_iv);

	// verify
	SHA1_Init(&fctx);
	SHA1_Update(&fctx, decrypted_data, encrypted_data_length);
	SHA1_Final(shaf, &fctx);
	for (i = 0; i < 8; i++) {
		if (shaf[i] != message_key[i])
			return 0;
	}

	return 1;
}

__kernel
void telegram_final(MAYBE_CONSTANT telegram_salt *salt,
               __global pbkdf2_out *pbkdf2,
               __global telegram_out *out)
{
	uint gid = get_global_id(0);

	out[gid].cracked = telegram_decrypt((__global uchar*)pbkdf2[gid].dk, salt);
}

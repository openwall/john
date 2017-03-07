/*
 * agile keychain
 *
 * This software is Copyright (c) 2017 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#include "pbkdf2_hmac_sha1_unsplit_kernel.cl"
#define AES_KEY_TYPE __global
#define OCL_AES_CBC_DECRYPT 1
#define AES_SRC_TYPE __constant
#include "opencl_aes.h"

inline int check_pkcs_pad(const uchar *data, size_t len, uint blocksize)
{
	uint pad_len = data[len - 1];
	uint padding = pad_len;
	size_t real_len = len - pad_len;
	const uchar *p = data + real_len;

	if (len & (blocksize - 1))
		return -1;

	if (pad_len > blocksize || pad_len < 1)
		return -1;

	if (len < blocksize)
		return -1;

	while (pad_len--)
		if (*p++ != padding)
			return -1;

	return real_len;
}

typedef struct {
	uint  iterations;
	uint  outlen;
	uint  skip_bytes;
	uchar length;
	uchar salt[SALTLEN];
	uchar iv[16];
	uchar aes_ct[16];
} agile_salt;

typedef struct {
	uint cracked;
	uint key[16/4];
} agile_out;

__kernel void dk_decrypt(__global pbkdf2_password *password,
                         __global agile_out *agile_out,
                         __constant agile_salt *salt)
{
	uint idx = get_global_id(0);
	AES_KEY akey;
	uchar iv[16];
	uchar plaintext[16];
	uint i;
	int n;
	int success = 0;

	pbkdf2(password[idx].v, password[idx].length, salt->salt, salt->length,
	       salt->iterations, agile_out[idx].key, salt->outlen,
	       salt->skip_bytes);

	for (i = 0; i < 16; i++)
		iv[i] = salt->iv[i];

	AES_set_decrypt_key((__global uchar*)agile_out[idx].key, 128, &akey);
	AES_cbc_decrypt(salt->aes_ct, plaintext, 16, &akey, iv);

	n = check_pkcs_pad(plaintext, 16, 16);
	if (n >= 0) {
		int key_size = (1024 + n) / 8;

		if (key_size == 128 || key_size == 192 || key_size == 256)
			success = 1;
	}

	agile_out[idx].cracked = success;
}

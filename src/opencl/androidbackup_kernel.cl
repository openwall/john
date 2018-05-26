/*
 * This software is Copyright (c) 2018 Dhiru Kholia, Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha1_kernel.cl"
#define AES_KEY_TYPE __global const
#define AES_SRC_TYPE MAYBE_CONSTANT
#include "opencl_aes.h"

typedef struct {
	uint cracked;
} ab_out;

typedef struct {
	pbkdf2_salt pbkdf2;
	int masterkey_blob_length;
	uchar iv[16];
	uchar masterkey_blob[MAX_MASTERKEYBLOB_LEN];
} ab_salt;

inline int ab_decrypt(__global uchar *key, MAYBE_CONSTANT ab_salt *salt)
{
	uchar out[MAX_MASTERKEYBLOB_LEN];
	const int length = salt->masterkey_blob_length;
	uchar aiv[16];
	AES_KEY akey;
	int pad_byte;

	memcpy_macro(aiv, salt->iv, 16);
	AES_set_decrypt_key(key, 256, &akey);
	AES_cbc_decrypt(salt->masterkey_blob, out, length, &akey, aiv);

	if (out[0] != 16)
		return 0;

	if (check_pkcs_pad(out, length, 16) < 0)
		return 0;

	pad_byte = out[length - 1];
	if (pad_byte > 8)
		return 1;

	return 0;
}

__kernel
void ab_final(MAYBE_CONSTANT ab_salt *salt,
               __global pbkdf2_out *pbkdf2,
               __global ab_out *out)
{
	uint gid = get_global_id(0);

	out[gid].cracked = ab_decrypt((__global uchar*)pbkdf2[gid].dk, salt);
}

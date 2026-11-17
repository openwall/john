/*
 * This software is Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha1_unsplit_kernel.cl"
#include "opencl_des.h"

typedef struct {
	pbkdf2_salt pbkdf2;
	unsigned char iv[8];
	unsigned char ct[CTLEN];
	uint32_t has_symkey;
	uint32_t symkey_ct_len;
	unsigned char symkey_ct[SYMKEY_MAX_CTLEN];
} keychain_salt;

typedef struct {
	uint32_t cracked;
} keychain_out;

INLINE int symkey_verify(__constant keychain_salt *salt,
                         des3_context *ks, const uchar *dbkey)
{
	const uint len = salt->symkey_ct_len;
	const uint offset = len - 8;
	uchar iv[8] = { 0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 };
	uchar out[8];

	/* CBC padding is wholly contained in the final block. */
	if (len > 8)
		memcpy_cp(iv, &salt->symkey_ct[offset - 8], 8);

	des3_set3key_dec(ks, dbkey);
	des3_crypt_cbc(ks, DES_DECRYPT, 8, iv, __constant,
	               &salt->symkey_ct[offset], out);

	return check_pkcs_pad(out, 8, 8) >= 0;
}

__kernel void keychain(__global const pbkdf2_password *inbuffer,
                       __global pbkdf2_hash *dk,
                       __constant keychain_salt *salt,
                       __global keychain_out *out)
{
	uint idx = get_global_id(0);
	unsigned char buf[CTLEN];
	des3_context ks;
	uchar iv[8];
	uchar key[24];
	uint cracked;

	pbkdf2(inbuffer[idx].v, inbuffer[idx].length,
	       salt->pbkdf2.salt, salt->pbkdf2.length, salt->pbkdf2.iterations,
	       dk[idx].v, salt->pbkdf2.outlen, salt->pbkdf2.skip_bytes);

	memcpy_gp(key, dk[idx].v, 24);
	des3_set3key_dec(&ks, key);

	memcpy_cp(iv, salt->iv, 8);
	des3_crypt_cbc(&ks, DES_DECRYPT, CTLEN, iv, __constant, salt->ct, buf);

	cracked = (buf[47] == 4 && check_pkcs_pad(buf, CTLEN, 8) >= 0);
	if (cracked && salt->has_symkey)
		cracked = symkey_verify(salt, &ks, buf);

	out[idx].cracked = cracked;
}

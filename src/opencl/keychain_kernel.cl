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
} keychain_salt;

typedef struct {
	uint32_t cracked;
} keychain_out;

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

	pbkdf2(inbuffer[idx].v, inbuffer[idx].length,
	       salt->pbkdf2.salt, salt->pbkdf2.length, salt->pbkdf2.iterations,
	       dk[idx].v, salt->pbkdf2.outlen, salt->pbkdf2.skip_bytes);

	memcpy_gp(key, dk[idx].v, 24);
	des3_set3key_dec(&ks, key);

	memcpy_cp(iv, salt->iv, 8);
	des3_crypt_cbc(&ks, DES_DECRYPT, CTLEN, iv, __constant, salt->ct, buf);

	out[idx].cracked =
		(buf[47] == 4 && check_pkcs_pad(buf, CTLEN, 8) >= 0);
}

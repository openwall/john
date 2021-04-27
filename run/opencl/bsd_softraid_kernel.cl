/*
 * This software is Copyright (c) 2018 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha1_kernel.cl"
#define AES_SRC_TYPE MAYBE_CONSTANT
#include "opencl_aes.h"
#include "opencl_sha1_ctx.h"
#define HMAC_OUT_TYPE __global
#include "opencl_hmac_sha1.h"

#define OPENBSD_SOFTRAID_SALTLENGTH 128
#define OPENBSD_SOFTRAID_KEYS       32
#define OPENBSD_SOFTRAID_KEYLENGTH  64
#define OPENBSD_SOFTRAID_MACLENGTH  20

#define MASKED_KEY_SIZE OPENBSD_SOFTRAID_KEYLENGTH * OPENBSD_SOFTRAID_KEYS

typedef struct {
	pbkdf2_salt pbkdf2;
	int kdf_type;
	uchar masked_keys[MASKED_KEY_SIZE];
} softraid_salt;

__kernel
void softraid_final(MAYBE_CONSTANT softraid_salt *salt,
                    __global pbkdf2_out *out)
{
	uint gid = get_global_id(0);
	uint dk[OUTLEN / 4];
	uchar unmasked_keys[MASKED_KEY_SIZE];
	uchar hashed_mask_key[SHA1_DIGEST_LENGTH];
	AES_KEY akey;
	SHA_CTX ctx;

	memcpy_gp(dk, out[gid].dk, OUTLEN);

	AES_set_decrypt_key((uchar*)dk, 256, &akey);

	/* get SHA1 of mask_key */
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, (uchar*)dk, OUTLEN);
	SHA1_Final(hashed_mask_key, &ctx);

	AES_ecb_decrypt(salt->masked_keys, unmasked_keys,
	                MASKED_KEY_SIZE, &akey);

	/* We reuse out.dk as final output hash */
	hmac_sha1(hashed_mask_key, OPENBSD_SOFTRAID_MACLENGTH,
	          unmasked_keys, MASKED_KEY_SIZE,
	          out[gid].dk, OPENBSD_SOFTRAID_MACLENGTH);
}

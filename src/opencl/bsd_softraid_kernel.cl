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

typedef struct {
	pbkdf2_salt pbkdf2;
	int kdf_type;
	uchar masked_keys[OPENBSD_SOFTRAID_KEYLENGTH * OPENBSD_SOFTRAID_KEYS];
} softraid_salt;

__kernel
void softraid_final(MAYBE_CONSTANT softraid_salt *salt,
                    __global pbkdf2_out *out)
{
	uint gid = get_global_id(0);
	uint dk[OUTLEN / 4];
	uchar unmasked_keys[64 * 32];
	uchar hashed_mask_key[20];
	AES_KEY akey;
	SHA_CTX ctx;

	memcpy_gp(dk, out[gid].dk, OUTLEN);

	AES_set_decrypt_key((uchar*)dk, 256, &akey);

	memcpy_mcp(unmasked_keys, salt->masked_keys, 64 * 32);
	AES_Decrypt_ECB(&akey, unmasked_keys, unmasked_keys, 64 * 32 / 16);

	/* get SHA1 of mask_key */
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, (uchar*)dk, 32);
	SHA1_Final(hashed_mask_key, &ctx);

	/* We reuse out.dk as final output hash */
	hmac_sha1(hashed_mask_key, OPENBSD_SOFTRAID_MACLENGTH,
	          unmasked_keys, OPENBSD_SOFTRAID_KEYLENGTH * OPENBSD_SOFTRAID_KEYS,
	          out[gid].dk, 20);
}

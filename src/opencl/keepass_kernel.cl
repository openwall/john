/*
 * This software is Copyright (c) 2018 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#include "opencl_misc.h"
#define AES_KEY_TYPE __private
#define AES_SRC_TYPE __private
#define AES_DST_TYPE __private
#define OCL_AES_ENCRYPT 1
#define OCL_AES_CBC_DECRYPT 1
#include "opencl_aes.h"
#include "opencl_sha2_ctx.h"
#include "opencl_chacha.h"
#include "opencl_twofish.h"

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} keepass_password;

typedef struct {
	uint32_t cracked;
} keepass_result;

typedef struct {
	uint64_t offset;
	int version;
	int isinline;
	int keyfilesize;
	int have_keyfile;
	int contentsize;
	uint32_t key_transf_rounds;
	int algorithm;
	uchar final_randomseed[32];
	uchar enc_iv[16];
	uchar keyfile[32];
	uchar contents_hash[32];
	uchar transf_randomseed[32];
	uchar expected_bytes[32];
	uchar contents[MAX_CONT_SIZE];
} keepass_salt_t;

typedef struct {
	uint iterations;
	uchar hash[32];
	AES_KEY akey;
} keepass_state;

__kernel void keepass_init(__global const keepass_password *masterkey,
                           __constant keepass_salt_t *salt,
                           __global keepass_state *state)
{
	uint gid = get_global_id(0);
	uchar hash[32];
	uint pwlen = masterkey[gid].length;
	uchar pbuf[PLAINTEXT_LENGTH];
	SHA256_CTX ctx;
	AES_KEY akey;

	// We can afford some safety because only the loop kernel is significant
	if (pwlen > PLAINTEXT_LENGTH)
		pwlen = 0;

	memcpy_macro(pbuf, masterkey[gid].v, pwlen);

	// First, hash the masterkey
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, pbuf, pwlen);
	SHA256_Final(hash, &ctx);

	if (salt->have_keyfile) {
		memcpy_macro(pbuf, salt->keyfile, 32);
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, hash, 32);
		SHA256_Update(&ctx, pbuf, 32);
		SHA256_Final(hash, &ctx);
	} else if (salt->version == 2) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, hash, 32);
		SHA256_Final(hash, &ctx);
	}

	// Next, encrypt the hash using the random seed as key
	memcpy_macro(pbuf, salt->transf_randomseed, 32);
	AES_set_encrypt_key(pbuf, 256, &akey);

	// Save state for loop kernel.
	state[gid].iterations = salt->key_transf_rounds;
	memcpy_macro(state[gid].hash, hash, 32);
	memcpy_pg(&state[gid].akey, &akey, sizeof(AES_KEY));
}

// Here's the heavy part. NOTHING else is significant for performance!
__kernel void keepass_loop(__global keepass_state *state)
{
	uint gid = get_global_id(0);
	AES_KEY akey;
	uint i;
	uchar hash[32];

	i = MIN(state[gid].iterations, HASH_LOOPS);
	state[gid].iterations -= i;
	memcpy_macro(hash, state[gid].hash, 32);
	memcpy_gp(&akey, &state[gid].akey, sizeof(AES_KEY));

	while (i--) {
		AES_encrypt(hash, hash, &akey);
		AES_encrypt(hash + 16, hash + 16, &akey);
	}

	memcpy_macro(state[gid].hash, hash, 32);
}

__kernel void keepass_final(__global keepass_state *state,
                            __constant keepass_salt_t *salt,
                            __global keepass_result *result)
{
	uint gid = get_global_id(0);
	SHA256_CTX ctx;
	AES_KEY akey;
	uchar pbuf[32];
	uchar hash[32];
	uchar iv[16];

	memcpy_macro(hash, state[gid].hash, 32);

	// Finally, hash it again...
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, hash, 32);
	SHA256_Final(hash, &ctx);

	// ...and hash the result together with the random seed
	SHA256_Init(&ctx);
	if (salt->version == 1) {
		memcpy_macro(pbuf, salt->final_randomseed, 16);
		SHA256_Update(&ctx, pbuf, 16);
	} else {
		memcpy_macro(pbuf, salt->final_randomseed, 32);
		SHA256_Update(&ctx, pbuf, 32);
	}
	SHA256_Update(&ctx, hash, 32);
	SHA256_Final(hash, &ctx);

	memcpy_macro(iv, salt->enc_iv, 16);

	if (salt->version == 1) {
		uchar content[MAX_CONT_SIZE];
		int contentsize = salt->contentsize;
		int datasize;

		if (contentsize < 16 || contentsize > MAX_CONT_SIZE)
			contentsize = 16;

		memcpy_macro(content, salt->contents, contentsize);

		if (salt->algorithm == 0) {
			uint pad_byte;

			AES_set_decrypt_key(hash, 256, &akey);
			AES_cbc_decrypt(content, content, contentsize, &akey, iv);
			pad_byte = content[contentsize - 1];
			datasize = contentsize - pad_byte;
		} else /* if (salt->algorithm == 1) */ {
			Twofish_key tkey;

			Twofish_prepare_key(hash, 32, &tkey);
			datasize = Twofish_Decrypt(&tkey, content, content,
			                           contentsize, iv);

			if (datasize < 0 || datasize > contentsize)
				datasize = 0;
		}
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, content, datasize);
		SHA256_Final(hash, &ctx);
		result[gid].cracked = !memcmp_pc(hash, salt->contents_hash, 32);
	}
	else if (salt->version == 2) {
		uchar content[32];

		memcpy_macro(content, salt->contents, 32);

		if (salt->algorithm == 0) {
			AES_set_decrypt_key(hash, 256, &akey);
			AES_cbc_decrypt(content, hash, 32, &akey, iv);
		} else /* if (salt->algorithm == 2) */ {
			chacha_ctx ckey;

			chacha_keysetup(&ckey, hash, 256);
			chacha_ivsetup(&ckey, iv, 0, 12);
			chacha_decrypt_bytes(&ckey, content, hash, 32);
		}
		result[gid].cracked = !memcmp_pc(hash, salt->expected_bytes, 32);
	}
	else
		result[gid].cracked = 0; // We should never end up here
}

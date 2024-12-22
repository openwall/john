/*
 * This software is Copyright (c) 2018-2024 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if MAX_CONTENT_SIZE >= 0xff00
#define MAYBE_CONSTANT __global const	/* Override setting otherwise decided by opencl_misc.h */
#endif

#include "opencl_misc.h"

#if gpu_nvidia(DEVICE_INFO)
/*
 * 'volatile' as a bug workaround for nvidia runtime/driver ver. 435.21 while
 * [some] earlier versions worked fine without it.  No negative side-effects
 * (such as performance impact) seen.  Bug still in 465.19.01
 */
#define AES_SRC_TYPE volatile const
#define CHACHA_SRC_TYPE volatile const
#endif

#include "opencl_aes.h"
#include "opencl_chacha.h"
#include "opencl_twofish.h"
#include "opencl_sha2_ctx.h"
#define HMAC_MSG_TYPE	MAYBE_CONSTANT
#include "opencl_hmac_sha256.h"
#if KEEPASS_ARGON2_REF // Not present, used for testing
#include "argon2.h"
#else
typedef enum {
	dummy1 = 0,
} argon2_type;
typedef enum {
	dummy2 = 0,
} argon2_version;
#endif

/* This must match argon2-opencl */
#define ARGON2_SALT_SIZE            64

typedef struct {
	dyna_salt dsalt;
	uint32_t t_cost, m_cost, lanes;
	uint32_t hash_size;
	uint32_t salt_length;
	char salt[ARGON2_SALT_SIZE];
	argon2_type type;
	argon2_version version;
	/* The above must match argon2-opencl salt struct */
	int kdbx_ver;
	uint32_t kdf; // 0=AES, 1=Argon2
	uint32_t cipher; // 0=AES, 1=TwoFish, 2=ChaCha
	uint8_t enc_iv[16];   // KDBX3 and earlier
	union {
		uint8_t final_randomseed[32]; // KDBX3 and earlier
		uint8_t master_seed[32];      // KDBX4 and later
	};
	uint8_t transf_randomseed[32];
	uint8_t expected_bytes[32];    // KDBX3
	int have_keyfile;
	uint8_t keyfile[32];
	union {
		uint8_t contents_hash[32]; // KDBX3 and earlier
		uint8_t header_hmac[32];   // KDBX4 and later
	};
	int content_size;    // (KDBX4 header_size)
	uint8_t contents[1]; // (KDBX4 header) dynamic size
} keepass_salt_t;

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} keepass_password;

typedef struct {
	uint32_t cracked;
} keepass_result;

typedef struct {
#if KEEPASS_AES
	uint iterations;
#endif
	uint8_t hash[32];
} keepass_state;

INLINE void calc_hmac_base_key(const void *master_seed, const void *final_key, void *result)
{
	const uint8_t one_le[1] = "\x01";
	SHA512_CTX ctx;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, master_seed, 32);
	SHA512_Update(&ctx, final_key, 32);
	SHA512_Update(&ctx, one_le, 1);
	SHA512_Final(result, &ctx);
}

INLINE void calc_hmac_key(const void *block_index, const void *base_key, void *result)
{
	SHA512_CTX ctx;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, block_index, sizeof(uint64_t));
	SHA512_Update(&ctx, base_key, 64);
	SHA512_Final(result, &ctx);
}

__kernel void keepass_init(__global const keepass_password *masterkey,
                           MAYBE_CONSTANT keepass_salt_t *salt,
                           __global keepass_state *state)
{
	uint gid = get_global_id(0);
	uint pwlen = masterkey[gid].length;

	// We can afford some safety because only the loop kernel is significant
	if (pwlen > PLAINTEXT_LENGTH)
		pwlen = 0;

	uint8_t pbuf[PLAINTEXT_LENGTH];
	memcpy_macro(pbuf, masterkey[gid].v, pwlen);

	// First, hash the masterkey
	SHA256_CTX ctx;
	uint8_t hash[32];
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, pbuf, pwlen);
	SHA256_Final(hash, &ctx);

	if (salt->have_keyfile) {
		memcpy_macro(pbuf, salt->keyfile, 32);
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, hash, 32);
		SHA256_Update(&ctx, pbuf, 32);
		SHA256_Final(hash, &ctx);
	} else if (salt->kdbx_ver > 1) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, hash, 32);
		SHA256_Final(hash, &ctx);
	}

#if KEEPASS_AES
	if (salt->kdf == 0) {
		// Save state for loop kernel.
		state[gid].iterations = salt->t_cost;
	}
#endif

	memcpy_macro(state[gid].hash, hash, 32);
}

#if KEEPASS_AES
// Here's the heavy part. NOTHING else is significant for performance!
// Encrypt the hash using the random seed as key
__kernel void keepass_loop_aes(__global keepass_state *state, MAYBE_CONSTANT keepass_salt_t *salt)
{
	__local aes_local_t lt;
	AES_KEY akey; akey.lt = &lt;
	uint gid = get_global_id(0);
	uint i;
	uint8_t pbuf[32];

	i = MIN(state[gid].iterations, HASH_LOOPS);
	state[gid].iterations -= i;

	memcpy_macro(pbuf, salt->transf_randomseed, 32);

	AES_set_encrypt_key(pbuf, 256, &akey);

	uint8_t hash[32];
	memcpy_macro(hash, state[gid].hash, 32);

	while (i--)
		AES_ecb_encrypt(hash, hash, 32, &akey);

	memcpy_macro(state[gid].hash, hash, 32);
}
#endif

#if KEEPASS_ARGON2_REF
__kernel void keepass_argon2(__global keepass_state *state,
                             MAYBE_CONSTANT keepass_salt_t *salt,
                             __global uint8_t *argon2_memory_pool,
                             __constant int *autotune)
{
	uint gid = get_global_id(0);
	uint8_t transf_randomseed[32];
	uint8_t hash[32];
	int t_cost = *autotune ? 1 : salt->t_cost;

	memcpy_macro(transf_randomseed, salt->transf_randomseed, 32);
	memcpy_macro(hash, state[gid].hash, 32);

	argon2_hash(t_cost, salt->m_cost,
	            salt->lanes, hash, 32, // key
	            transf_randomseed, 32, // salt
	            hash, 32, // hash (out)
	            NULL, 0, // encoded
	            salt->type,
	            salt->version,
	            argon2_memory_pool);

	memcpy_macro(state[gid].hash, hash, 32);
}
#endif

__kernel void keepass_final(__global keepass_state *state,
                            MAYBE_CONSTANT keepass_salt_t *salt,
                            __global keepass_result *result)
{
	uint gid = get_global_id(0);
	uint8_t hash[32];

	memcpy_macro(hash, state[gid].hash, 32);

#if KEEPASS_AES
	__local aes_local_t lt;
	AES_KEY akey; akey.lt = &lt;
	SHA256_CTX ctx;
	uint8_t pbuf[32];
	uint8_t iv[16];

	// Finally, hash it again (only for AES-KDF)...
	if (salt->kdf == 0) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, hash, 32);
		SHA256_Final(hash, &ctx);
	}
#endif

	if (salt->kdbx_ver == 4) { // KDBX4
		uint8_t seed[32];
		memcpy_macro(seed, salt->master_seed, 32);

		uint8_t hmac_base_key[64];
		calc_hmac_base_key(seed, hash, hmac_base_key);

		uint8_t hmac_key[64];
		const uint8_t uint64_max[8] = "\xff\xff\xff\xff\xff\xff\xff\xff";
		calc_hmac_key(&uint64_max, hmac_base_key, hmac_key);

		uint8_t calc_hmac[32];
		hmac_sha256(hmac_key, 64, salt->contents, salt->content_size, calc_hmac, 32);

		result[gid].cracked = !memcmp_pmc(calc_hmac, salt->header_hmac, 32);
	}
#if KEEPASS_AES
	else {
		// ...hash the result together with the random seed
		SHA256_Init(&ctx);
		if (salt->kdbx_ver == 1) {
			memcpy_macro(pbuf, salt->final_randomseed, 16);
			SHA256_Update(&ctx, pbuf, 16);
		} else {
			memcpy_macro(pbuf, salt->final_randomseed, 32);
			SHA256_Update(&ctx, pbuf, 32);
		}
		SHA256_Update(&ctx, hash, 32);
		SHA256_Final(hash, &ctx);

		memcpy_macro(iv, salt->enc_iv, 16);

		if (salt->kdbx_ver == 1) { // <= KDBX2
			uint8_t content[256];
			int bufsize = (int)sizeof(content);
			MAYBE_CONSTANT uint8_t *saltp = salt->contents;
			int content_size = (uint)salt->content_size;
			int data_size;

			if (content_size < 16 || content_size > MAX_CONTENT_SIZE)
				content_size = 16;

			SHA256_Init(&ctx);

			if (salt->cipher == 0) {
				uint pad_byte;

				AES_set_decrypt_key(hash, 256, &akey);
				while (content_size > bufsize) {
					memcpy_macro(content, saltp, bufsize);
					AES_cbc_decrypt(content, content, bufsize, &akey, iv);
					SHA256_Update(&ctx, content, bufsize);
					content_size -= bufsize;
					saltp += bufsize;
				}
				memcpy_macro(content, saltp, content_size);
				AES_cbc_decrypt(content, content, content_size, &akey, iv);
				pad_byte = content[content_size - 1];
				data_size = content_size - pad_byte;
				if (pad_byte > 16 || data_size < 0 || data_size > content_size)
					data_size = 0;
				SHA256_Update(&ctx, content, data_size);
			} else /* if (salt->cipher == 1) */ {
				Twofish_key tkey;

				Twofish_prepare_key(hash, 32, &tkey);
				while (content_size > bufsize) {
					memcpy_macro(content, saltp, bufsize);
					Twofish_Decrypt(&tkey, content, content, bufsize, iv, 0);
					SHA256_Update(&ctx, content, bufsize);
					content_size -= bufsize;
					saltp += bufsize;
				}
				memcpy_macro(content, saltp, content_size);
				data_size = Twofish_Decrypt(&tkey, content, content, content_size, iv, 1);
				if (data_size < 0 || data_size > content_size)
					data_size = 0;
				SHA256_Update(&ctx, content, data_size);
			}

			SHA256_Final(hash, &ctx);
			result[gid].cracked = !memcmp_pmc(hash, salt->contents_hash, 32);
		}
		else if (salt->kdbx_ver == 2) { // KDBX3
#if gpu_nvidia(DEVICE_INFO)
			volatile /* See comment near top */
#endif
				uint8_t content[32];

			memcpy_macro(content, salt->contents, 32);

			if (salt->cipher == 0) {
				AES_set_decrypt_key(hash, 256, &akey);
				AES_cbc_decrypt(content, hash, 32, &akey, iv);
			} else /* if (salt->cipher == 2) */ {
				chacha_ctx ckey;

				chacha_keysetup(&ckey, hash, 256);
				chacha_ivsetup(&ckey, iv, 0, 12);
				chacha_decrypt_bytes(&ckey, content, hash, 32);
			}
			result[gid].cracked = !memcmp_pmc(hash, salt->expected_bytes, 32);
		}
	}
#endif
}

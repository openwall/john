/*
 * Copyright (c) 2014 Thiébaud Weksteen <thiebaud at weksteen dot fr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Fixed BE issues, and build problems (Fall 2014), JimF.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_openbsd_softraid;
#elif FMT_REGISTERS_H
john_register_one(&fmt_openbsd_softraid);
#else

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "common.h"
#include "formats.h"
#include "loader.h"
#include "aes.h"
#include "sha.h"
#include "hmac_sha.h"
#include "bcrypt_pbkdf.h"
#include "pbkdf2_hmac_sha1.h"
#include "openbsdsoftraid_common.h"
#define CPU_FORMAT                  1
#include "openbsdsoftraid_variable_code.h"

#define FORMAT_LABEL                "OpenBSD-SoftRAID"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME              "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME              "PBKDF2-SHA1 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT           ""
#define BENCHMARK_LENGTH            0x507
#define PLAINTEXT_LENGTH            125
#define SALT_SIZE                   sizeof(struct custom_salt)
#define SALT_ALIGN                  4
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT          SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT          SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT          1
#define MAX_KEYS_PER_CRYPT          1
#endif

#ifndef OMP_SCALE
#define OMP_SCALE                   1 // MKPC and scale tuned for i7
#endif

static char (*key_buffer)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	key_buffer = mem_calloc(sizeof(*key_buffer), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(key_buffer);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return openbsdsoftraid_valid(ciphertext, self, 1);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		AES_KEY akey;
		unsigned char mask_key[MIN_KEYS_PER_CRYPT][32];
		unsigned char unmasked_keys[OPENBSD_SOFTRAID_KEYLENGTH * OPENBSD_SOFTRAID_KEYS];
		unsigned char hashed_mask_key[20];
		int i, j;

		/* derive masking key from password */
		if (cur_salt->kdf_type == 1) {
#ifdef SSE_GROUP_SZ_SHA1
			int lens[SSE_GROUP_SZ_SHA1];
			unsigned char *pin[SSE_GROUP_SZ_SHA1], *pout[SSE_GROUP_SZ_SHA1];
			for (i = 0; i < SSE_GROUP_SZ_SHA1; ++i) {
				lens[i] = strlen(key_buffer[index+i]);
				pin[i] = (unsigned char*)key_buffer[index+i];
				pout[i] = mask_key[i];
			}
			pbkdf2_sha1_sse((const unsigned char **)pin, lens,
					cur_salt->salt, OPENBSD_SOFTRAID_SALTLENGTH,
					cur_salt->num_iterations, (unsigned char**)pout,
					32, 0);
#else
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				pbkdf2_sha1((const unsigned char*)(key_buffer[index+i]),
						strlen(key_buffer[index+i]),
						cur_salt->salt, OPENBSD_SOFTRAID_SALTLENGTH,
						cur_salt->num_iterations, mask_key[i],
						32, 0);
			}
#endif
		} else if (cur_salt->kdf_type == 3) {
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				bcrypt_pbkdf((const char*)key_buffer[index+i],
						strlen(key_buffer[index+i]),
						cur_salt->salt, OPENBSD_SOFTRAID_SALTLENGTH,
						mask_key[i], 32, cur_salt->num_iterations);
			}
		}

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			/* decrypt sector keys */
			AES_set_decrypt_key(mask_key[i], 256, &akey);
			for (j = 0; j < (OPENBSD_SOFTRAID_KEYLENGTH * OPENBSD_SOFTRAID_KEYS) / 16;  j++) {
				AES_decrypt(&cur_salt->masked_keys[16*j], &unmasked_keys[16*j], &akey);
			}

			/* get SHA1 of mask_key */
			SHA_CTX ctx;
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, mask_key[i], 32);
			SHA1_Final(hashed_mask_key, &ctx);

			hmac_sha1(hashed_mask_key, OPENBSD_SOFTRAID_MACLENGTH,
					unmasked_keys, OPENBSD_SOFTRAID_KEYLENGTH * OPENBSD_SOFTRAID_KEYS,
					(unsigned char*)crypt_out[index+i], 20);
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (*(uint32_t*)binary == *(uint32_t*)(crypt_out[index]))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (*(uint32_t*)binary == *(uint32_t*)(crypt_out[index]));
}

static int cmp_exact(char *source, int index)
{
	void *bin = openbsdsoftraid_get_binary(source);

	return !memcmp(bin, crypt_out[index], 20);
}

static void set_key(char* key, int index)
{
	strnzcpy(key_buffer[index], key, sizeof(*key_buffer));
}

static char *get_key(int index)
{
	return key_buffer[index];
}

struct fmt_main fmt_openbsd_softraid = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{
			"kdf",
			"iteration count",
		},
		{ FORMAT_TAG },
		tests_openbsdsoftraid
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		openbsdsoftraid_get_binary,
		openbsdsoftraid_get_salt,
		{
			openbsdsoftraid_get_kdf_type,
			openbsdsoftraid_get_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif

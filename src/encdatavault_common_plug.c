/*
 * Cracker for ENCSecurity Data Vault.
 *
 * This software is Copyright (c) 2021-2022 Sylvain Pelissier <sylvain.pelissier at kudelskisecurity.com>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This file is for common code between the two formats.
 *
 */
#include "encdatavault_common.h"

MAYBE_INLINE void enc_xor_block(uint64_t *dst, const uint64_t *src)
{
	dst[0] ^= src[0];
	dst[1] ^= src[1];
}

void enc_aes_ctr_iterated(const unsigned char *in, unsigned char *out, const unsigned char *key,
                                 buffer_128 ivs[ENC_MAX_KEY_NUM], size_t len, size_t nb_keys, uint64_t counter)
{
	AES_KEY aes_key;
	buffer_128 tmp_iv;
	buffer_128 tmp_out;
	int i, j;

	AES_set_encrypt_key(key, ENC_KEY_SIZE * 8, &aes_key);
	len >>= 4;
#if ARCH_LITTLE_ENDIAN
	counter <<= 56;
#endif

	for (i = 0; i < len; i++) {
		tmp_iv.u64[0] = ivs[0].u64[0];
		tmp_iv.u64[1] = counter;
		AES_encrypt(tmp_iv.u8, tmp_iv.u8, &aes_key);
		memcpy(tmp_out.u8, in, AES_BLOCK_SIZE);
		enc_xor_block(tmp_out.u64, tmp_iv.u64);

		for (j = 1; j < nb_keys; j++) {
			tmp_iv.u64[0] = ivs[j].u64[0];
			tmp_iv.u64[1] = counter;
			AES_encrypt(tmp_iv.u8, tmp_iv.u8, &aes_key);
			enc_xor_block(tmp_out.u64, tmp_iv.u64);
		}
		memcpy(out, tmp_out.u8, AES_BLOCK_SIZE);

		// Increment counter, only 255 block encryption is supported.
#if ARCH_LITTLE_ENDIAN
		counter += 0x0100000000000000;
#else
		counter++;
#endif
		out += AES_BLOCK_SIZE;
		in += AES_BLOCK_SIZE;
	}
}

int valid_common(char *ciphertext, struct fmt_main *self, int is_pbkdf2)
{
	char *p = ciphertext, *ctcopy, *keeptr;
	int extra, saltlen;

	if (is_pbkdf2) {
		if (strncmp(ciphertext, FORMAT_TAG_PBKDF2, FORMAT_TAG_PBKDF2_LENGTH) != 0)
			return 0;
		ctcopy = xstrdup(ciphertext);
		keeptr = ctcopy;
		ctcopy += FORMAT_TAG_PBKDF2_LENGTH;
	} else {
		if (strncmp(ciphertext, FORMAT_TAG_MD5, FORMAT_TAG_MD5_LENGTH) != 0)
			return 0;
		ctcopy = xstrdup(ciphertext);
		keeptr = ctcopy;
		ctcopy += FORMAT_TAG_MD5_LENGTH;
	}
	if ((p = strtokm(ctcopy, "$")) == NULL) // version
		goto err;
	if (!isdec(p))
		goto err;
	int version = atoi(p);

	if (version != 3 && version != 1) {
		static int warned;
		if (!self_test_running && !warned++)
			fprintf(stderr, "%s: Warning: version %d not supported, not loading such hashes!\n", self->params.label, version);
		goto err;
	}
	if ((p = strtokm(NULL, "$")) == NULL)   // algorithm id
		goto err;
	if (!isdec(p))
		goto err;
	if (atoi(p) > 4 || atoi(p) < 1) {
		static int warned;
		if (!warned++)
			fprintf(stderr, "%s: Warning: algorithm id %d not supported!\n", self->params.label, atoi(p));
		goto err;
	}
	if ((p = strtokm(NULL, "$")) == NULL)   // Nonce
		goto err;
	if (hexlenl(p, &extra) != ENC_NONCE_SIZE * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // Encrypted header
		goto err;
	if (hexlenl(p, &extra) > ENC_SIG_SIZE * 2 || extra)
		goto err;
	if (hexlenl(p, &extra) < (ENC_SIG_SIZE - 4) * 2 || extra)
		goto err;
	if (is_pbkdf2) {
		if ((p = strtokm(NULL, "$")) == NULL)   // Salt length
			goto err;
		if (!isdec(p))
			goto err;
		saltlen = atoi(p);
		if (saltlen > PBKDF2_32_MAX_SALT_SIZE) {
			static int warned;
			if (!warned++)
				fprintf(stderr, "%s: Warning: salt length %d too big!\n", self->params.label, saltlen);
			goto err;
		}
		if ((p = strtokm(NULL, "$")) == NULL)   // Salt
			goto err;
		if (hexlenl(p, &extra) != saltlen * 2 || extra)
			goto err;
		if ((p = strtokm(NULL, "$")) == NULL)   // Iterations
			goto err;
		if (!isdec(p))
			goto err;
	}
	if (version == 3) {
		if ((p = strtokm(NULL, "$")) == NULL)   // Keychain
			goto err;
		if (hexlenl(p, &extra) != ENC_KEYCHAIN_SIZE * 2 || extra)
			goto err;
	}
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;

}

void *get_salt_common(char *ciphertext, int is_pbkdf2)
{
	int i;
	char *p = ciphertext, *ctcopy, *keeptr;
	static custom_salt cs;
	int extra;

	memset(&cs, 0, sizeof(cs));
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	if (is_pbkdf2)
		ctcopy += FORMAT_TAG_PBKDF2_LENGTH;
	else
		ctcopy += FORMAT_TAG_MD5_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.version = atoi(p);
	p = strtokm(NULL, "$");
	cs.algo_id = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < ENC_IV_SIZE; i++)
		cs.iv[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	// Init AES CTR counter
	cs.iv[ENC_IV_SIZE - 1] = 1;

	p = strtokm(NULL, "$");
	cs.encrypted_data_length = hexlenl(p, &extra) / 2;
	for (i = 0; i < cs.encrypted_data_length; i++)
		cs.encrypted_data[i + 4] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	if (is_pbkdf2) {
		// Salt and iteration for latest versions
		p = strtokm(NULL, "$");
		cs.salt_length = atoi(p);
		p = strtokm(NULL, "$");
		for (i = 0; i < cs.salt_length; i++)
			cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
		p = strtokm(NULL, "$");
		cs.iterations = atoi(p);
	}

	// Keychain for version 3
	if ((cs.version & 0x0f) == 3) {
		p = strtokm(NULL, "$");
		for (i = 0; i < ENC_KEYCHAIN_SIZE; i++)
			cs.keychain[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	}
	MEM_FREE(keeptr);
	return (void *) &cs;
}

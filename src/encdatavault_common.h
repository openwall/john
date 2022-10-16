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
#include <string.h>

#include "aes.h"
#include "common.h"
#include "formats.h"

#define FORMAT_TAG_MD5            	"$encdv$"
#define FORMAT_TAG_MD5_LENGTH     	(sizeof(FORMAT_TAG_MD5) - 1)
#define FORMAT_TAG_PBKDF2         	"$encdv-pbkdf2$"
#define FORMAT_TAG_PBKDF2_LENGTH  	(sizeof(FORMAT_TAG_PBKDF2) - 1)

#define ENC_DEFAULT_MD5_ITERATIONS 	1000
#define ENC_SALT_SIZE 				16
#define ENC_IV_SIZE 				16
#define ENC_BLOCK_SIZE 				16
#define ENC_KEY_SIZE 				16
#define ENC_NONCE_SIZE 				8
#define ENC_SIG_SIZE 				8
#define ENC_MAX_KEY_NUM 			8
#define ENC_KEYCHAIN_SIZE 			128

#define PBKDF2_32_MAX_SALT_SIZE 	128

typedef union buffer_128_u {
	uint8_t u8[8];
	uint64_t u64[2];
} buffer_128;

typedef struct {
	unsigned int version;
	unsigned int algo_id;
	unsigned char iv[ENC_IV_SIZE];
	unsigned int salt_length;
	unsigned char salt[PBKDF2_32_MAX_SALT_SIZE];
	unsigned int iterations;
	unsigned char encrypted_data[ENC_BLOCK_SIZE];
	unsigned int encrypted_data_length;
	unsigned char keychain[ENC_KEYCHAIN_SIZE];
} custom_salt;

void enc_xor_block(uint64_t *dst, const uint64_t *src);
void enc_aes_ctr_iterated(const unsigned char *in, unsigned char *out, const unsigned char *key,
                                 buffer_128 ivs[ENC_MAX_KEY_NUM], size_t len, size_t nb_keys, uint64_t counter);
int valid_common(char *ciphertext, struct fmt_main *self, int is_pbkdf2);
void *get_salt_common(char *ciphertext, int is_pbkdf2);

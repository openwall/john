/*
 * This software is Copyright (c) 2013 Sébastien Kaczmarek <skaczmarek@quarkslab.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Fixed the format to crack multiple hashes + added OMP support (Dhiru
 * Kholia).
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_lotus_85;
#elif FMT_REGISTERS_H
john_register_one(&fmt_lotus_85);
#else

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "sha.h"
#include <openssl/rc2.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "formats.h"
#include "common.h"

/* Plugin definition */
#define FORMAT_LABEL          "lotus85"
#define FORMAT_NAME           "Lotus Notes/Domino 8.5"
#define ALGORITHM_NAME        "8/" ARCH_BITS_STR
#define BENCHMARK_COMMENT     ""
#define BENCHMARK_LENGTH      7
#define PLAINTEXT_LENGTH      32
#define CIPHERTEXT_LENGTH     (LOTUS85_MAX_BLOB_SIZE * 2)
#define BINARY_SIZE           0
#define BINARY_LENGTH         5
#define BINARY_ALIGN          1
#define SALT_SIZE             sizeof(struct custom_salt)
#define SALT_ALIGN            4
#define MIN_KEYS_PER_CRYPT    1
#define MAX_KEYS_PER_CRYPT    4

#ifndef OMP_SCALE
#define OMP_SCALE             16  // Tuned w/ MKPC for core i7
#endif

#define LOTUS85_MAX_BLOB_SIZE 0x64
#define LOTUS85_MIN_BLOB_SIZE 40 // XXX fictional value, but isn't this length fixed?

/* Globals */
static const char LOTUS85_UNIQUE_STRING[] = "Lotus Notes Password Pad Uniquifier";

static uint8_t ebits_to_num[256]=
{
	0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a,
	0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
	0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
	0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
	0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda,
	0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
	0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8,
	0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
	0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
	0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
	0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72,
	0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
	0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd,
	0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
	0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b,
	0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
	0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77,
	0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
	0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3,
	0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
	0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e,
	0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
	0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d,
	0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
	0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46,
	0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
	0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
	0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
	0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef,
	0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
	0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf,
	0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab,
};

static struct custom_salt {
	uint8_t lotus85_user_blob[LOTUS85_MAX_BLOB_SIZE];
	uint32_t lotus85_user_blob_len;
} *cur_salt;

/*
 * 5 bytes digest computed by the algorithm
 * As the password is used to derive a RC2 key and decipher the user blob
 * the reference digest is always different and we should track them all
 */
static uint8_t (*lotus85_last_binary_hash1)[BINARY_LENGTH];
static uint8_t (*lotus85_last_binary_hash2)[BINARY_LENGTH];

/* Plaintext passwords history requested by JtR engine */
static char (*lotus85_saved_passwords)[PLAINTEXT_LENGTH+1];


/* Decipher user.id user blob */
static void decipher_userid_blob(uint8_t *ciphered_blob, uint32_t len, uint8_t *userid_key, uint8_t *deciphered_blob)
{
	RC2_KEY rc_key;
	uint8_t buf[LOTUS85_MAX_BLOB_SIZE+8],rc_iv[8];

	memset(buf, 0x0, sizeof(buf));
	memset(rc_iv, 0, sizeof(rc_iv));

	RC2_set_key(&rc_key, 8, userid_key, 64);
	RC2_cbc_encrypt(ciphered_blob, buf, len, &rc_key, rc_iv, RC2_DECRYPT);

	memcpy(deciphered_blob, buf, len);
}

/* Custom hash transformation function */
static void custom_password_hash_trans(uint8_t *data, uint8_t *out, uint8_t *state)
{
	uint8_t buffer[48];
	size_t i, j;
	uint8_t c;

	memset(buffer, 0, sizeof(buffer));

	memcpy(buffer, state, 16);
	memcpy(buffer + 16, data, 16);

	for (i=0;i<16;i+=4)
	{
		buffer[32+i] = data[i] ^ state[i];
		buffer[32+i+1] = data[i+1] ^ state[i+1];
		buffer[32+i+2] = data[i+2] ^ state[i+2];
		buffer[32+i+3] = data[i+3] ^ state[i+3];
	}

	for (j=c=0;j<18;j++)
	{
		for (i=0;i<sizeof(buffer);i+=6)
		{
			buffer[i] ^= ebits_to_num[(c-i+48) & 0xFF];
			buffer[i+1] ^= ebits_to_num[(buffer[i]-i+47) & 0xFF];
			buffer[i+2] ^= ebits_to_num[(buffer[i+1]-i+46) & 0xFF];
			buffer[i+3] ^= ebits_to_num[(buffer[i+2]-i+45) & 0xFF];
			buffer[i+4] ^= ebits_to_num[(buffer[i+3]-i+44) & 0xFF];
			buffer[i+5] ^= ebits_to_num[(buffer[i+4]-i+43) & 0xFF];
			c = buffer[i+5];
		}
	}

	memcpy(state, buffer, 16);

	c = out[15];

	for (i=0;i<16;i+=4)
	{
		out[i] ^= ebits_to_num[data[i] ^ c];
		out[i+1] ^= ebits_to_num[data[i+1] ^ out[i]];
		out[i+2] ^= ebits_to_num[data[i+2] ^ out[i+1]];
		out[i+3] ^= ebits_to_num[data[i+3] ^ out[i+2]];
		c = out[i+3];
	}
}

/* Custom hash function */
static void custom_password_hash(const char *password, uint8_t *out)
{
	uint8_t block1[16], state[16], block2[16];
	size_t len, rlen, block_pos = 0;

	len = strlen(password);
	memset(state, 0, sizeof(state));
	memset(block2, 0, sizeof(block2));

	while((block_pos + 15) < len)
	{
		memcpy(block1, password+block_pos, sizeof(block1));
		custom_password_hash_trans(block1, state, block2);
		block_pos += 16;
	}

	if (block_pos != len)
	{
		rlen = len - block_pos;
		memcpy(block1, password+block_pos, rlen);
		memset(block1+rlen, 16-rlen, 16-rlen);
		custom_password_hash_trans(block1, state, block2);
	}
	else
	{
		memset(block1, sizeof(block1), sizeof(block1));
		custom_password_hash_trans(block1, state, block2);
	}

	custom_password_hash_trans(state, state, block2);

	memcpy(out, block2, sizeof(block2));
}

/* Hash cste::password with sha1 */
static void password_hash(const char *password, uint8_t *hash)
{
	SHA_CTX s_ctx;
	uint8_t digest[SHA_DIGEST_LENGTH];

	SHA1_Init(&s_ctx);

	SHA1_Update(&s_ctx, LOTUS85_UNIQUE_STRING, strlen(LOTUS85_UNIQUE_STRING));
	SHA1_Update(&s_ctx, password, strlen(password));

	SHA1_Final(digest, &s_ctx);

	memcpy(hash, digest, sizeof(digest));
}

/* Hash/checksum function used for key derivation from plaintext password */
static void compute_key_mac(uint8_t *key, size_t len, uint8_t *mac, size_t mac_len)
{
	size_t i, j, mlen=mac_len-1;
	uint8_t k;

	for (i=0;i<16;i++)
	{
		k = ebits_to_num[mac[0] ^ mac[1]];

		for (j=0;j<mlen;j++)
		{
			mac[j] = mac[j+1];
		}

		mac[mlen] = key[i] ^ k;
	}
}

/* Hash/checksum function used for digest storage */
static void compute_msg_mac(uint8_t *msg, size_t len, uint8_t *msg_mac)
{
	size_t i, j;
	uint8_t c;

	for (i=j=0;i<len;i++)
	{
		if (j!=4)
		{
			msg_mac[j] = msg[i] ^ ebits_to_num[msg_mac[j] ^ msg_mac[j+1]];
			j++;
		}
		else
		{
			msg_mac[j] = msg[i] ^ ebits_to_num[msg_mac[j] ^ msg_mac[0]];
			j = 0;
		}
	}

	c = msg_mac[0];
	for (i=0;i<4;i++)
	{
		msg_mac[i] = msg_mac[i+1];
	}

	msg_mac[i] = c;
}

/*
 * Derive password to retrieve the RC2 secret key
 * used when deciphering user blob stored in user.id file
 */
static void get_user_id_secret_key(const char *password, uint8_t *secret_key)
{
	uint8_t key[16+20], mac[8];

	memset(key, 0, sizeof(key));
	memset(mac, 0, sizeof(mac));

	custom_password_hash(password, key);
	password_hash(password, key+16);

	compute_key_mac(key, sizeof(key), mac, sizeof(mac));

	memcpy(secret_key, mac, sizeof(mac));
}

/* Plugin initialization */
static void lotus85_init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	lotus85_saved_passwords = mem_calloc(self->params.max_keys_per_crypt,
	                                     PLAINTEXT_LENGTH + 1);
	lotus85_last_binary_hash1 = mem_calloc(self->params.max_keys_per_crypt,
	                                       BINARY_LENGTH);
	lotus85_last_binary_hash2 = mem_calloc(self->params.max_keys_per_crypt,
	                                       BINARY_LENGTH);
}

static void done(void)
{
	MEM_FREE(lotus85_last_binary_hash2);
	MEM_FREE(lotus85_last_binary_hash1);
	MEM_FREE(lotus85_saved_passwords);
}

/* Check if given ciphertext (hash) format is valid */
static int lotus85_valid(char *ciphertext,struct fmt_main *self)
{
	int len, extra;

	len = strnlen(ciphertext, CIPHERTEXT_LENGTH + 1);

	if (len % 2)
		return 0;

	if ((len >> 1) > LOTUS85_MAX_BLOB_SIZE)
		return 0;

	if ((len >> 1) < LOTUS85_MIN_BLOB_SIZE)
		return 0;

	if (hexlenu(ciphertext, &extra)  != len || extra)
		return 0;

	return 1;
}

static void *get_salt(char *ciphertext)
{
	int i,len;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	len = strlen(ciphertext) >> 1;

	for (i = 0; i < len; i++)
		cs.lotus85_user_blob[i] = (atoi16[ARCH_INDEX(ciphertext[i << 1])] << 4) + atoi16[ARCH_INDEX(ciphertext[(i << 1) + 1])];

	cs.lotus85_user_blob_len = len;

	return (void*)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

/* Set password at given index */
static void lotus85_set_key(char *key,int index)
{
	strnzcpy(lotus85_saved_passwords[index],key,sizeof(lotus85_saved_passwords[index]));
}

/* Return password at given index as string */
static char *lotus85_get_key(int index)
{
	return lotus85_saved_passwords[index];
}

/* Main callback to compute lotus digest */
static int lotus85_crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

	/* Compute digest for all given plaintext passwords */
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		unsigned char user_key[8], deciphered_userid[LOTUS85_MAX_BLOB_SIZE];
		memset(lotus85_last_binary_hash1[index], 0, BINARY_LENGTH);
		memset(lotus85_last_binary_hash2[index], 0, BINARY_LENGTH);
		memset(user_key, 0, sizeof(user_key));
		memset(deciphered_userid, 0, sizeof(deciphered_userid));

		/* Derive password and retrieve RC2 key */
		get_user_id_secret_key(lotus85_saved_passwords[index], user_key);

		/* Deciphered user blob stored in user.id file */
		decipher_userid_blob(cur_salt->lotus85_user_blob, cur_salt->lotus85_user_blob_len, user_key, deciphered_userid);

		/* Store first deciphered digest */
		memcpy(lotus85_last_binary_hash1[index], deciphered_userid + cur_salt->lotus85_user_blob_len - BINARY_LENGTH, BINARY_LENGTH);

		/* Compute digest of deciphered message */
		compute_msg_mac(deciphered_userid, cur_salt->lotus85_user_blob_len - BINARY_LENGTH, lotus85_last_binary_hash2[index]);
	}
	return count;
}

/* Check if one of last computed hashs match */
static int lotus85_cmp_all(void *binary,int count)
{
	int i;

	for (i = 0; i < count; i++)
	{
		if (!memcmp(lotus85_last_binary_hash1[i],lotus85_last_binary_hash2[i],BINARY_LENGTH))
			return 1;
	}

	return 0;
}

/* Check if last computed hash match */
static int lotus85_cmp_one(void *binary,int index)
{
	return !memcmp(lotus85_last_binary_hash1[index],lotus85_last_binary_hash2[index],BINARY_LENGTH);
}

/* No ASCII ciphertext, thus returns true */
static int lotus85_cmp_exact(char *source,int index)
{
	return 1;
}

static struct fmt_tests lotus85_tests[] =
{
	{"0040B2B17C344C236953F955B28E4865014034D1F664489D7F42B35FB6928A94DCFFEF7750CE029F94C83A582A80B4662D49B3FA45816143", "notesisterrible"},
	{"CBCFC612FAE3154316223787C7CD29AD39BEDF4288FCDE310B32FD809C75F5FDC521667D5F6E7A047766F0E60952F7891593FFAF45AD0C15", "openwall"},
	{NULL}
};

/* JtR lotus 8.5 structure registration */
struct fmt_main fmt_lotus_85 =
{
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ NULL },
		lotus85_tests
	}, {
		lotus85_init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		lotus85_valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		lotus85_set_key,          /*  Set plaintext password  */
		lotus85_get_key,          /*  Get plaintext password  */
		fmt_default_clear_keys,
		lotus85_crypt_all,        /*  Main hash function       */
		{
			fmt_default_get_hash
		},
		lotus85_cmp_all,          /* Compare * hash (binary)  */
		lotus85_cmp_one,          /* Compare 1 hash (binary)  */
		lotus85_cmp_exact
	}
};

#endif /* plugin stanza */
#endif /* HAVE_LIBCRYPTO */

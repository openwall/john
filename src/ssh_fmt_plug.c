/*
 * Fast cracker for SSH RSA / DSA key files. Hacked together during October
 * of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * Support for cracking new openssh key format (bcrypt pbkdf) was added by
 * m3g9tr0n (Spiros Fraganastasis) and Dhiru Kholia in September of 2014. This
 * is dedicated to Raquel :-)
 *
 * Ideas borrowed from SSH2 protocol library, http://pypi.python.org/pypi/ssh
 * Copyright (C) 2011  Jeff Forcier <jeff@bitprophet.org>
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * This software is Copyright (c) 2020 Valeriy Khromov <valery.khromov at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ssh;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ssh);
#else

#include <string.h>
#include <stdint.h>
#include <openssl/conf.h>
#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "aes.h"
#include "jumbo.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "md5.h"
#include "bcrypt_pbkdf.h"
#include "asn1.h"
#define CPU_FORMAT          1
#include "ssh_common.h"
#include "ssh_variable_code.h"

#define FORMAT_LABEL        "SSH"
#define FORMAT_NAME         "SSH private key"
#define FORMAT_TAG          "$sshng$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME      "RSA/DSA/EC/OPENSSH 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x107
#define PLAINTEXT_LENGTH    32 // XXX
#define BINARY_SIZE         0
#define SALT_SIZE           sizeof(struct custom_salt)
#define BINARY_ALIGN        1
#define SALT_ALIGN          sizeof(int)
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  8

/*
 * For cost 1 using core i7, MKPC=8 and OMP_SCALE 128 works fine but that
 * is far too slow for cost 2, which needs them at 1/1. Let's always auto-tune.
 */
#ifndef OMP_SCALE
#define OMP_SCALE           0
#endif

// openssl asn1parse -in test_dsa.key; openssl asn1parse -in test_rsa.key
#define SAFETY_FACTOR       16  // enough to verify the initial ASN.1 structure (SEQUENCE, INTEGER, Big INTEGER) of RSA, and DSA keys?

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	cracked   = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*cracked));
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

inline static void generate_key_bytes(int nbytes, unsigned char *password, unsigned char *key)
{
	unsigned char digest[16];
	int len = strlen((const char*)password);
	int keyidx = 0;
	int digest_inited = 0;

	while (nbytes > 0) {
		MD5_CTX ctx;
		int i, size;

		MD5_Init(&ctx);
		if (digest_inited) {
			MD5_Update(&ctx, digest, 16);
		}
		MD5_Update(&ctx, password, len);
		/* use first 8 bytes of salt */
		MD5_Update(&ctx, cur_salt->salt, 8);
		MD5_Final(digest, &ctx);
		digest_inited = 1;
		if (nbytes > 16)
			size = 16;
		else
			size = nbytes;
		/* copy part of digest to keydata */
		for (i = 0; i < size; i++)
			key[keyidx++] = digest[i];
		nbytes -= size;
	}
}

inline static int check_structure_bcrypt(unsigned char *out, int length)
{
	return memcmp(out, out + 4, 4);
}

inline static int check_padding_and_structure_EC(unsigned char *out, int length, int strict_mode)
{
	struct asn1_hdr hdr;
	const uint8_t *pos, *end;

	// First check padding
	if (check_pkcs_pad(out, length, 16) < 0)
		return -1;

	/* check BER decoding, EC private key file contains:
	 *
	 * SEQUENCE, INTEGER (length 1), OCTET STRING, cont, OBJECT, cont, BIT STRING
	 *
	 * $ ssh-keygen -t ecdsa -f unencrypted_ecdsa_sample.key  # don't use a password for testing
	 * $ openssl asn1parse -in unencrypted_ecdsa_sample.key  # see the underlying structure
	*/

	// SEQUENCE
	if (asn1_get_next(out, length, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_SEQUENCE) {
		goto bad;
	}
	pos = hdr.payload;
	end = pos + hdr.length;

	// version Version (Version ::= INTEGER)
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_INTEGER) {
		goto bad;
	}
	pos = hdr.payload + hdr.length;
	if (hdr.length != 1)
		goto bad;

	// OCTET STRING
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_OCTETSTRING) {
		goto bad;
	}
	pos = hdr.payload + hdr.length;
	if (hdr.length < 8) // "secp112r1" curve uses 112 bit prime field, rest are bigger
		goto bad;

	// XXX add more structure checks!

	return 0;
bad:
	return -1;
}

inline static int check_padding_and_structure(unsigned char *out, int length, int strict_mode, int blocksize)
{
	struct asn1_hdr hdr;
	const uint8_t *pos, *end;

	// First check padding
	if (check_pkcs_pad(out, length, blocksize) < 0)
		return -1;

	/* check BER decoding, private key file contains:
	 *
	 * RSAPrivateKey = { version = 0, n, e, d, p, q, d mod p-1, d mod q-1, q**-1 mod p }
	 * DSAPrivateKey = { version = 0, p, q, g, y, x }
	 *
	 * openssl asn1parse -in test_rsa.key # this shows the structure nicely!
	 */

	// SEQUENCE
	if (asn1_get_next(out, length, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_SEQUENCE) {
		goto bad;
	}
	pos = hdr.payload;
	end = pos + hdr.length;

	// version Version (Version ::= INTEGER)
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_INTEGER) {
		goto bad;
	}
	pos = hdr.payload + hdr.length;

	// INTEGER (big one)
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_INTEGER) {
		goto bad;
	}
	pos = hdr.payload + hdr.length;
	/* NOTE: now this integer has to be big, is this always true?
	 * RSA (as used in ssh) uses big prime numbers, so this check should be OK
	 */
	if (hdr.length < 64) {
		goto bad;
	}

	if (strict_mode) {
		// INTEGER (small one)
		if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
				hdr.class != ASN1_CLASS_UNIVERSAL ||
				hdr.tag != ASN1_TAG_INTEGER) {
			goto bad;
		}
		pos = hdr.payload + hdr.length;

		// INTEGER (big one again)
		if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
				hdr.class != ASN1_CLASS_UNIVERSAL ||
				hdr.tag != ASN1_TAG_INTEGER) {
			goto bad;
		}
		pos = hdr.payload + hdr.length;
		if (hdr.length < 32) {
			goto bad;
		}
	}

	return 0;
bad:
	return -1;
}

inline static void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

inline static int AES_ctr_decrypt(unsigned char *ciphertext,
                                  int ciphertext_len, unsigned char *key,
                                  unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1)
		handleErrors();

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
		handleErrors();
	plaintext_len = len;

	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
		handleErrors();
	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

static void common_crypt_code(char *password, unsigned char *out, int full_decrypt)
{
	if (cur_salt->cipher == 0) {
		unsigned char key[24];
		DES_cblock key1, key2, key3;
		DES_cblock iv;
		DES_key_schedule ks1, ks2, ks3;

		memcpy(iv, cur_salt->salt, 8);
		generate_key_bytes(24, (unsigned char*)password, key);
		memcpy(key1, key, 8);
		memcpy(key2, key + 8, 8);
		memcpy(key3, key + 16, 8);
		DES_set_key_unchecked((DES_cblock *) key1, &ks1);
		DES_set_key_unchecked((DES_cblock *) key2, &ks2);
		DES_set_key_unchecked((DES_cblock *) key3, &ks3);
		if (full_decrypt) {
			DES_ede3_cbc_encrypt(cur_salt->ct, out, cur_salt->ctl, &ks1, &ks2, &ks3, &iv, DES_DECRYPT);
		} else {
			DES_ede3_cbc_encrypt(cur_salt->ct, out, SAFETY_FACTOR, &ks1, &ks2, &ks3, &iv, DES_DECRYPT);
			memcpy(iv, cur_salt->ct + cur_salt->ctl - 16, 8);
			DES_ede3_cbc_encrypt(cur_salt->ct + cur_salt->ctl - 8, out + cur_salt->ctl - 8, 8, &ks1, &ks2, &ks3, &iv, DES_DECRYPT);
		}
	} else if (cur_salt->cipher == 1) {
		unsigned char key[16];
		AES_KEY akey;
		unsigned char iv[16];

		memcpy(iv, cur_salt->salt, 16);
		generate_key_bytes(16, (unsigned char*)password, key);
		AES_set_decrypt_key(key, 128, &akey);
		if (full_decrypt) {
			AES_cbc_encrypt(cur_salt->ct, out, cur_salt->ctl, &akey, iv, AES_DECRYPT);
		} else {
			// are starting SAFETY_FACTOR bytes enough?
			AES_cbc_encrypt(cur_salt->ct, out, SAFETY_FACTOR, &akey, iv, AES_DECRYPT);
			memcpy(iv, cur_salt->ct + cur_salt->ctl - 32, 16);
			AES_cbc_encrypt(cur_salt->ct + cur_salt->ctl - 16, out + cur_salt->ctl - 16, 16, &akey, iv, AES_DECRYPT);
		}
	} else if (cur_salt->cipher == 2) {  /* new ssh key format handling with aes256-cbc */
		unsigned char key[32 + 16];
		AES_KEY akey;
		unsigned char iv[16];

		// derive (key length + iv length) bytes
		bcrypt_pbkdf(password, strlen((const char*)password), cur_salt->salt, 16, key, 32 + 16, cur_salt->rounds);
		AES_set_decrypt_key(key, 256, &akey);
		memcpy(iv, key + 32, 16);
		// decrypt one block for "check bytes" check
		AES_cbc_encrypt(cur_salt->ct + cur_salt->ciphertext_begin_offset, out, 16, &akey, iv, AES_DECRYPT);
		// Padding check is unreliable for this type
		// memcpy(iv, cur_salt->ct + cur_salt->ctl - 32, 16);
		// AES_cbc_encrypt(cur_salt->ct + cur_salt->ctl - 16, out + cur_salt->ctl - 16, 16, &akey, iv, AES_DECRYPT);
	} else if (cur_salt->cipher == 6) {  /* new ssh key format handling with aes256-ctr */
		unsigned char key[32 + 16];
		unsigned char iv[16];

		// derive (key length + iv length) bytes
		bcrypt_pbkdf(password, strlen((const char *)password), cur_salt->salt, 16, key,
		             32 + 16, cur_salt->rounds);
		memcpy(iv, key + 32, 16);
		AES_ctr_decrypt(cur_salt->ct + cur_salt->ciphertext_begin_offset, 16, key, iv,
		                out);
	} else if (cur_salt->cipher == 3) { // EC keys with AES-128
		unsigned char key[16];
		AES_KEY akey;
		unsigned char iv[16];

		memcpy(iv, cur_salt->salt, 16);
		generate_key_bytes(16, (unsigned char*)password, key);
		AES_set_decrypt_key(key, 128, &akey);
		// full decrypt
		AES_cbc_encrypt(cur_salt->ct, out, cur_salt->ctl, &akey, iv, AES_DECRYPT);
	} else if (cur_salt->cipher == 4) { // RSA/DSA keys with AES-192
		unsigned char key[24];
		AES_KEY akey;
		unsigned char iv[16];

		memcpy(iv, cur_salt->salt, 16);
		generate_key_bytes(24, (unsigned char*)password, key);
		AES_set_decrypt_key(key, 192, &akey);
		if (full_decrypt) {
			AES_cbc_encrypt(cur_salt->ct, out, cur_salt->ctl, &akey, iv, AES_DECRYPT);
		} else {
			// are starting SAFETY_FACTOR bytes enough?
			AES_cbc_encrypt(cur_salt->ct, out, SAFETY_FACTOR, &akey, iv, AES_DECRYPT);
			memcpy(iv, cur_salt->ct + cur_salt->ctl - 32, 16);
			AES_cbc_encrypt(cur_salt->ct + cur_salt->ctl - 16, out + cur_salt->ctl - 16, 16, &akey, iv, AES_DECRYPT);
		}
	} else if (cur_salt->cipher == 5) { // RSA/DSA keys with AES-256
		unsigned char key[32];
		AES_KEY akey;
		unsigned char iv[16];

		memcpy(iv, cur_salt->salt, 16);
		generate_key_bytes(32, (unsigned char*)password, key);
		AES_set_decrypt_key(key, 256, &akey);
		if (full_decrypt) {
			AES_cbc_encrypt(cur_salt->ct, out, cur_salt->ctl, &akey, iv, AES_DECRYPT);
		} else {
			// are starting SAFETY_FACTOR bytes enough?
			AES_cbc_encrypt(cur_salt->ct, out, SAFETY_FACTOR, &akey, iv, AES_DECRYPT);
			memcpy(iv, cur_salt->ct + cur_salt->ctl - 32, 16);
			AES_cbc_encrypt(cur_salt->ct + cur_salt->ctl - 16, out + cur_salt->ctl - 16, 16, &akey, iv, AES_DECRYPT);
		}
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char out[N];

		// don't do full decryption (except for EC keys)
		common_crypt_code(saved_key[index], out, 0);

		if (cur_salt->cipher == 0) { // 3DES
			cracked[index] =
				!check_padding_and_structure(out, cur_salt->ctl, 0, 8);
		} else if (cur_salt->cipher == 1) {
			cracked[index] =
				!check_padding_and_structure(out, cur_salt->ctl, 0, 16);
		} else if (cur_salt->cipher == 2 || cur_salt->cipher == 6) {  // new ssh key format handling
			cracked[index] =
				!check_structure_bcrypt(out, cur_salt->ctl);
		} else if (cur_salt->cipher == 3) { // EC keys
			cracked[index] =
				!check_padding_and_structure_EC(out, cur_salt->ctl, 0);
		} else if (cur_salt->cipher == 4) {  // AES-192
			cracked[index] =
				!check_padding_and_structure(out, cur_salt->ctl, 0, 16);
		} else if (cur_salt->cipher == 5) {  // AES-256
			cracked[index] =
				!check_padding_and_structure(out, cur_salt->ctl, 0, 16);
		}

	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	unsigned char out[N];

	common_crypt_code(saved_key[index], out, 1); // do full decryption!

	if (cur_salt->cipher == 0) { // 3DES
		return !check_padding_and_structure(out, cur_salt->ctl, 1, 8);
	} else if (cur_salt->cipher == 1) {
		return !check_padding_and_structure(out, cur_salt->ctl, 1, 16);
	} else if (cur_salt->cipher == 2 || cur_salt->cipher == 6) {  /* new ssh key format handling */
		return 1; // XXX add more checks!
	} else if (cur_salt->cipher == 3) { // EC keys
		return 1;
	} else if (cur_salt->cipher == 4) {
		return !check_padding_and_structure(out, cur_salt->ctl, 1, 16);
	} else if (cur_salt->cipher == 5) {
		return !check_padding_and_structure(out, cur_salt->ctl, 1, 16);
	}

	return 0;
}

#undef set_key /* OpenSSL DES clash */
static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_ssh = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_SPLIT_UNIFIES_CASE | FMT_HUGE_INPUT,
		{
			"KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]",
			"iteration count",
		},
		{ FORMAT_TAG },
		ssh_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		ssh_valid,
		ssh_split,
		fmt_default_binary,
		ssh_get_salt,
		{
			ssh_kdf,
			ssh_iteration_count,
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

#endif /* plugin stanza */
#endif /* HAVE_LIBCRYPTO */

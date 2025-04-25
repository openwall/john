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
 * Copyright (c) 2020 Valeriy Khromov <valery.khromov at gmail.com>,
 * Copyright (c) 2025 Solar Designer,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ssh;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ssh);
#else

#include <string.h>
#include <stdint.h>
#if HAVE_LIBCRYPTO
#include <openssl/des.h>
#endif

#ifdef _OPENMP
#include <omp.h>
#endif

#include "aes.h"

#ifndef MBEDTLS_CIPHER_MODE_CTR
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#endif

#include "arch.h"
#include "jumbo.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
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
#define ALGORITHM_NAME      "MD5/bcrypt-pbkdf/[3]DES/AES 32/" ARCH_BITS_STR
#define PLAINTEXT_LENGTH    125
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

static struct {
	uint8_t len;
	char key[PLAINTEXT_LENGTH + 1];
	char pad; /* to 128 bytes */
} *saved_key;
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(cracked_size, 1);
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

/* NB: keybytes is rounded up to a multiple of 16, need extra space for key */
static MAYBE_INLINE void generate_key(char *password, size_t password_len, unsigned char *key, int keybytes)
{
	unsigned char *p = key;

	do {
		MD5_CTX ctx;

		MD5_Init(&ctx);
		if (p > key)
			MD5_Update(&ctx, p - 16, 16);
		MD5_Update(&ctx, password, password_len);
		/* use first 8 bytes of salt */
		MD5_Update(&ctx, cur_salt->salt, 8);
		MD5_Final(p, &ctx);
		p += 16;
		keybytes -= 16;
	} while (keybytes > 0);
}

static MAYBE_INLINE int check_structure_bcrypt(unsigned char *out)
{
/*
 * OpenSSH PROTOCOL.key file says:
 *
 * uint32  checkint
 * uint32  checkint
 * byte[]  privatekey1
 *
 * where each private key is encoded using the same rules as used for SSH agent
 *
 * Apparently, it starts with a 32-bit length field, so we check that two most
 * significant bytes of that field are 0, and that the checkint fields match.
 */
	return out[8] || out[9] || memcmp(out, out + 4, 4);
}

static MAYBE_INLINE int check_structure_asn1(unsigned char *out, int length, int real_len)
{
	struct asn1_hdr hdr;
	const uint8_t *pos, *end;

	const unsigned int pad_byte = out[length - 1];
	unsigned int pad_need = 7; /* This many padding bytes is good enough on its own */
	if (pad_byte >= pad_need && !self_test_running)
		return 0;

	/*
	 * Check BER decoding, private key file contains:
	 *
	 * RSAPrivateKey = { version = 0, n, e, d, p, q, d mod p-1, d mod q-1, q**-1 mod p }
	 * DSAPrivateKey = { version = 0, p, q, g, y, x }
	 *
	 * openssl asn1parse -in test_rsa.key # this shows the structure nicely!
	 */

	/*
	 * "For tags with a number ranging from zero to 30 (inclusive), the
	 * identifier octets shall comprise a single octet" (X.690 BER spec),
	 * so we disallow (hdr.identifier & 0x1f) == 0x1f as that means the tag
	 * was extracted from multiple octets.  Since this is part of BER spec,
	 * we could as well patch an equivalent check into asn1_get_next().
	 *
	 * "In the long form, it is a sender's option whether to use more
	 * length octets than the minimum necessary." (BER), but "The definite
	 * form of length encoding shall be used, encoded in the minimum number
	 * of octets." (DER), so we could also impose this kind of check for
	 * lengths (if we assume this is indeed DER), but we currently don't.
	 */

	/* The content is a SEQUENCE, which per BER spec is always constructed */
	if (asn1_get_next(out, MIN(real_len, SAFETY_FACTOR), real_len, &hdr) < 0 ||
	    hdr.class != ASN1_CLASS_UNIVERSAL || hdr.tag != ASN1_TAG_SEQUENCE ||
	    !hdr.constructed ||
	    (hdr.identifier & 0x1f) == 0x1f)
		return -1;

	if (pad_byte >= --pad_need && !self_test_running)
		return 0;

	/* The SEQUENCE must occupy the rest of space until padding */
	if (hdr.payload - out + hdr.length != real_len)
		return -1;

	if (hdr.payload - out == 4) /* We extracted hdr.length from 2 bytes */
		pad_need--;
	if (pad_byte >= --pad_need && !self_test_running)
		return 0;

	pos = hdr.payload;
	end = pos + hdr.length;

	/* Version ::= INTEGER, which per BER spec is always primitive */
	if (asn1_get_next(pos, MIN(hdr.length, SAFETY_FACTOR), hdr.length, &hdr) < 0 ||
	    hdr.class != ASN1_CLASS_UNIVERSAL || hdr.tag != ASN1_TAG_INTEGER ||
	    hdr.constructed || hdr.length != 1 ||
	    (hdr.identifier & 0x1f) == 0x1f)
		return -1;

	if (pad_byte >= pad_need - 2 && !self_test_running)
		return 0;

	pos = hdr.payload + hdr.length;
	if (pos - out >= SAFETY_FACTOR)
		return -1;

	/* INTEGER (big one for RSA) or OCTET STRING (EC) or SEQUENCE */
	/* OCTET STRING per DER spec is always constructed for <= 1000 octets */
	if (asn1_get_next(pos, MIN(end - pos, SAFETY_FACTOR), end - pos, &hdr) < 0 ||
	    hdr.class != ASN1_CLASS_UNIVERSAL ||
	    (hdr.tag != ASN1_TAG_INTEGER && hdr.tag != ASN1_TAG_OCTETSTRING && hdr.tag != ASN1_TAG_SEQUENCE) ||
	    hdr.constructed != (hdr.tag == ASN1_TAG_SEQUENCE) ||
	    (hdr.identifier & 0x1f) == 0x1f)
		return -1;

	/* We've also checked 1 padding byte */
	return 0;
}

#ifndef MBEDTLS_CIPHER_MODE_CTR
static void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	error();
}
#endif

static MAYBE_INLINE void AES_ctr_decrypt(unsigned char *ciphertext, int ciphertext_len,
    unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
#ifdef MBEDTLS_CIPHER_MODE_CTR
	size_t nc_off = 0;
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_enc(&ctx, key, 256);
	mbedtls_aes_crypt_ctr(&ctx, ciphertext_len, &nc_off, iv, iv, ciphertext, plaintext);
#else
	EVP_CIPHER_CTX *ctx;

	int len;

	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1)
		handleErrors();

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
		handleErrors();

	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
		handleErrors();

	EVP_CIPHER_CTX_free(ctx);
#endif
}

static MAYBE_INLINE int common_crypt_code(char *password, size_t password_len)
{
	int real_len;
	unsigned char out[SAFETY_FACTOR + 16];

#ifdef DEBUG
	memset(out, 0x55, sizeof(out));
#endif

	switch (cur_salt->cipher) {
#if HAVE_LIBCRYPTO
	case 7: { /* RSA/DSA keys with DES */
		union {
			unsigned char uc[16];
			struct {
				DES_cblock key, iv;
			};
		} u;
		DES_key_schedule ks;

		generate_key(password, password_len, u.uc, 8);
		DES_set_key_unchecked(&u.key, &ks);
		memcpy(u.iv, cur_salt->ct + cur_salt->ctl - 16, 8);
		DES_cbc_encrypt(cur_salt->ct + cur_salt->ctl - 8, out + sizeof(out) - 8, 8, &ks, &u.iv, DES_DECRYPT);
		if ((real_len = check_pkcs_pad(out, sizeof(out), 8)) < 0)
			return -1;
		real_len += cur_salt->ctl - sizeof(out);
		memcpy(u.iv, cur_salt->salt, 8);
		DES_cbc_encrypt(cur_salt->ct, out, SAFETY_FACTOR, &ks, &u.iv, DES_DECRYPT);
		break;
	}
	case 0: { /* RSA/DSA keys with 3DES */
		union {
			unsigned char uc[32];
			struct {
				DES_cblock key1, key2, key3, iv;
			};
		} u;
		DES_key_schedule ks1, ks2, ks3;

		generate_key(password, password_len, u.uc, 24);
		DES_set_key_unchecked(&u.key1, &ks1);
		DES_set_key_unchecked(&u.key2, &ks2);
		DES_set_key_unchecked(&u.key3, &ks3);
		memcpy(u.iv, cur_salt->ct + cur_salt->ctl - 16, 8);
		DES_ede3_cbc_encrypt(cur_salt->ct + cur_salt->ctl - 8, out + sizeof(out) - 8, 8,
		    &ks1, &ks2, &ks3, &u.iv, DES_DECRYPT);
		if ((real_len = check_pkcs_pad(out, sizeof(out), 8)) < 0)
			return -1;
		real_len += cur_salt->ctl - sizeof(out);
		memcpy(u.iv, cur_salt->salt, 8);
		DES_ede3_cbc_encrypt(cur_salt->ct, out, SAFETY_FACTOR, &ks1, &ks2, &ks3, &u.iv, DES_DECRYPT);
		break;
	}
#endif
	case 1:   /* RSA/DSA keys with AES-128 */
	case 3:   /* EC keys with AES-128 */
	case 4:   /* RSA/DSA keys with AES-192 */
	case 5: { /* RSA/DSA keys with AES-256 */
		const unsigned int keybytes_all[5] = {16, 0, 16, 24, 32};
		unsigned int keybytes = keybytes_all[cur_salt->cipher - 1];
		unsigned char key[32];
		AES_KEY akey;
		unsigned char iv[16];

		generate_key(password, password_len, key, keybytes);
		AES_set_decrypt_key(key, keybytes << 3, &akey);
		memcpy(iv, cur_salt->ct + cur_salt->ctl - 32, 16);
		AES_cbc_encrypt(cur_salt->ct + cur_salt->ctl - 16, out + sizeof(out) - 16, 16, &akey, iv, AES_DECRYPT);
		if ((real_len = check_pkcs_pad(out, sizeof(out), 16)) < 0)
			return -1;
		real_len += cur_salt->ctl - sizeof(out);
		memcpy(iv, cur_salt->salt, 16);
		AES_cbc_encrypt(cur_salt->ct, out, SAFETY_FACTOR, &akey, iv, AES_DECRYPT);
		break;
	}
	case 2:   /* new ssh key format handling with aes256-cbc */
	case 6: { /* new ssh key format handling with aes256-ctr */
		unsigned char key[32 + 16];
		AES_KEY akey;
		unsigned char iv[16];

		// derive (key length + iv length) bytes
		bcrypt_pbkdf(password, password_len, cur_salt->salt, 16, key, 32 + 16, cur_salt->rounds);
		AES_set_decrypt_key(key, 256, &akey);
		memcpy(iv, key + 32, 16);
		// decrypt one block for "check bytes" check
		if (cur_salt->cipher == 2)
			AES_cbc_encrypt(cur_salt->ct + cur_salt->ciphertext_begin_offset, out, 16, &akey, iv, AES_DECRYPT);
		else
			AES_ctr_decrypt(cur_salt->ct + cur_salt->ciphertext_begin_offset, 16, key, iv, out);
		return check_structure_bcrypt(out);
	}
	default:
		error();
	}

	return check_structure_asn1(out, sizeof(out), real_len);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		if (!common_crypt_code(saved_key[index].key, saved_key[index].len)) {
			cracked[index] = 1;
			any_cracked = 1;
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

#undef set_key /* OpenSSL DES clash */
static void set_key(char *key, int index)
{
	saved_key[index].len = strnzcpyn(saved_key[index].key, key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index].key;
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
			"KDF/cipher [0:MD5/AES 1:MD5/[3]DES 2:bcrypt-pbkdf/AES]",
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

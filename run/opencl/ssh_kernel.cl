/*
 * This software is Copyright (c) 2018 Dhiru Kholia, Copyright (c) 2018 magnum,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_asn1.h"
#include "opencl_des.h"
#include "opencl_md5_ctx.h"
#define AES_SRC_TYPE MAYBE_CONSTANT
#include "opencl_aes.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif

// input
typedef struct {
	uint length;
	uchar v[PLAINTEXT_LENGTH];
} ssh_password;

// input
typedef struct {
	uchar salt[16];
	uchar ct[CTLEN];
	uint cipher;
	uint ctl;
	uint sl;
	uint rounds;
	uint ciphertext_begin_offset;
} ssh_salt;

// output
typedef struct {
	uint cracked;
} ssh_out;

inline void generate_key_bytes(int nbytes, uchar *password, uint32_t len, uchar *salt, uchar *key)
{
	uchar digest[16];
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
		MD5_Update(&ctx, salt, 8);
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

inline int check_padding_and_structure_EC(uchar *out, int length)
{
	struct asn1_hdr hdr;
	const uint8_t *pos, *end;

	// First check padding
	if (check_pkcs_pad(out, length, 16) < 0)
		return 0;

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
		return 0;
	}
	pos = hdr.payload;
	end = pos + hdr.length;

	// version Version (Version ::= INTEGER)
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_INTEGER) {
		return 0;
	}
	pos = hdr.payload + hdr.length;
	if (hdr.length != 1)
		return 0;

	// OCTET STRING
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_OCTETSTRING) {
		return 0;
	}
	pos = hdr.payload + hdr.length;
	if (hdr.length < 8) // "secp112r1" curve uses 112 bit prime field, rest are bigger
		return 0;

	// XXX add more structure checks!

	return 1;
}

inline int check_padding_and_structure(uchar *out, uint length, uint strict_mode, uint block_size)
{
	struct asn1_hdr hdr;
	const uint8_t *pos, *end;

	// First check padding
	if (check_pkcs_pad(out, length, block_size) < 0)
		return 0;

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
		return 0;
	}
	pos = hdr.payload;
	end = pos + hdr.length;

	// version Version (Version ::= INTEGER)
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_INTEGER) {
		return 0;
	}
	pos = hdr.payload + hdr.length;

	// INTEGER (big one)
	if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_INTEGER) {
		return 0;
	}
	pos = hdr.payload + hdr.length;
	/* NOTE: now this integer has to be big, is this always true?
	 * RSA (as used in ssh) uses big prime numbers, so this check should be OK
	 */
	if (hdr.length < 64) {
		return 0;
	}

	if (strict_mode) {
		// INTEGER (small one)
		if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
				hdr.class != ASN1_CLASS_UNIVERSAL ||
				hdr.tag != ASN1_TAG_INTEGER) {
			return 0;
		}
		pos = hdr.payload + hdr.length;

		// INTEGER (big one again)
		if (asn1_get_next(pos, end - pos, &hdr) < 0 ||
				hdr.class != ASN1_CLASS_UNIVERSAL ||
				hdr.tag != ASN1_TAG_INTEGER) {
			return 0;
		}
		pos = hdr.payload + hdr.length;
		if (hdr.length < 32) {
			return 0;
		}
	}


	return 1;
}

inline void common_crypt_code(uchar *password, uint len, __constant ssh_salt *osalt, uchar *out, uint full_decrypt)
{
	uchar salt[16];

	memcpy_macro(salt, osalt->salt, osalt->sl);

	if (osalt->cipher == 0) {
		des3_context ks;
		uchar iv[8];
		uchar key[24];

		generate_key_bytes(24, password, len, salt, key);
		memcpy_macro(iv, salt, 8);
		des3_set3key_dec(&ks, key);
		if (full_decrypt) {
			des3_crypt_cbc(&ks, DES_DECRYPT, osalt->ctl, iv, MAYBE_CONSTANT, osalt->ct, out);
		} else {
			des3_crypt_cbc(&ks, DES_DECRYPT, SAFETY_FACTOR, iv, MAYBE_CONSTANT, osalt->ct, out);
			memcpy_macro(iv, osalt->ct + osalt->ctl - 16, 8);
			des3_crypt_cbc(&ks, DES_DECRYPT, 8, iv, MAYBE_CONSTANT, osalt->ct + osalt->ctl - 8, out + osalt->ctl - 8);
		}
	} else if (osalt->cipher == 1) {  // RSA/DSA keys with AES-128
		uchar key[16];
		AES_KEY akey;
		uchar iv[16];

		memcpy_macro(iv, osalt->salt, 16);
		generate_key_bytes(16, password, len, salt, key);
		AES_set_decrypt_key(key, 128, &akey);
		if (full_decrypt) {
			AES_cbc_decrypt(osalt->ct, out, osalt->ctl, &akey, iv);
		} else {
			AES_cbc_decrypt(osalt->ct, out, SAFETY_FACTOR, &akey, iv);
			memcpy_macro(iv, osalt->ct + osalt->ctl - 32, 16);
			AES_cbc_decrypt(osalt->ct + osalt->ctl - 16, out + osalt->ctl - 16, 16, &akey, iv);
		}
#if 0
	} else if (osalt->cipher == 2) {  // bcrypt + AES256-CBC, not yet supported
	} else if (osalt->cipher == 6) {  // bcrypt + AES256-CTR, not yet supported
#endif
	} else if (osalt->cipher == 3) {  // EC keys with AES-128
		uchar key[16];
		AES_KEY akey;
		uchar iv[16];

		memcpy_macro(iv, osalt->salt, 16);
		generate_key_bytes(16, password, len, salt, key);
		AES_set_decrypt_key(key, 128, &akey);
		// Always full decrypt
		AES_cbc_decrypt(osalt->ct, out, osalt->ctl, &akey, iv);
	} else if (osalt->cipher == 4) {  // RSA/DSA keys with AES-192
		uchar key[24];
		AES_KEY akey;
		uchar iv[16];

		memcpy_macro(iv, osalt->salt, 16);
		generate_key_bytes(24, password, len, salt, key);
		AES_set_decrypt_key(key, 192, &akey);
		if (full_decrypt) {
			AES_cbc_decrypt(osalt->ct, out, osalt->ctl, &akey, iv);
		} else {
			AES_cbc_decrypt(osalt->ct, out, SAFETY_FACTOR, &akey, iv);
			memcpy_macro(iv, osalt->ct + osalt->ctl - 32, 16);
			AES_cbc_decrypt(osalt->ct + osalt->ctl - 16, out + osalt->ctl - 16, 16, &akey, iv);
		}
	} else if (osalt->cipher == 5) {  // RSA/DSA keys with AES-256
		uchar key[32];
		AES_KEY akey;
		uchar iv[16];

		memcpy_macro(iv, osalt->salt, 16);
		generate_key_bytes(32, password, len, salt, key);
		AES_set_decrypt_key(key, 256, &akey);
		if (full_decrypt) {
			AES_cbc_decrypt(osalt->ct, out, osalt->ctl, &akey, iv);
		} else {
			AES_cbc_decrypt(osalt->ct, out, SAFETY_FACTOR, &akey, iv);
			memcpy_macro(iv, osalt->ct + osalt->ctl - 32, 16);
			AES_cbc_decrypt(osalt->ct + osalt->ctl - 16, out + osalt->ctl - 16, 16, &akey, iv);
		}
	}
}

#define QUICK 0
#define FULL 1

inline int ssh_decrypt(uchar *password, uint len, __constant ssh_salt *osalt, __global ssh_out *output)
{
	uchar out[CTLEN];
	int block_size = osalt->cipher == 0 ? 8 : 16;

	common_crypt_code(password, len, osalt, out, QUICK);

	if (osalt->cipher == 3)  // EC keys with AES-128
		return check_padding_and_structure_EC(out, osalt->ctl);

	if (!check_padding_and_structure(out, osalt->ctl, QUICK, block_size))
		return 0;

	common_crypt_code(password, len, osalt, out, FULL);

	return check_padding_and_structure(out, osalt->ctl, FULL, block_size);
}

__kernel void ssh(__global const ssh_password *inbuffer,
                  __global ssh_out *out,
                  __constant ssh_salt *salt)
{
	uchar password[PLAINTEXT_LENGTH];
	uint gid = get_global_id(0);

	memcpy_gp(password, inbuffer[gid].v, inbuffer[gid].length);

	out[gid].cracked = ssh_decrypt(password, inbuffer[gid].length, salt, out);
}

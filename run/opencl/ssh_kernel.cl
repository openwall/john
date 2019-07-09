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

inline void generate_key_bytes(int nbytes, uchar *password, uint32_t len, uchar *salt, unsigned char *key)
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

inline int check_padding_and_structure_EC(unsigned char *out, int length, int strict_mode)
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

inline int check_padding_and_structure(uchar *out, uint length, uint block_size)
{
	struct asn1_hdr hdr;
	const uint8_t *pos, *end;
	uint strict_mode = 0;  // NOTE!

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

inline int ssh_decrypt(__global const ssh_password *inbuffer, uint gid, __constant ssh_salt *osalt, __global ssh_out *output)
{
	uchar out[CTLEN];
	int block_size = 8;
	uchar password[PLAINTEXT_LENGTH];
	uchar salt[16];

	memcpy_gp(password, inbuffer[gid].v, inbuffer[gid].length);
	memcpy_macro(salt, osalt->salt, osalt->sl);

	if (osalt->cipher == 0) {
		des3_context ks;
		uchar iv[8];
		uchar key[24];

		block_size = 8;
		generate_key_bytes(24, password, inbuffer[gid].length, salt, key);
		memcpy_macro(iv, salt, 8);
		des3_set3key_dec(&ks, key);
		des3_crypt_cbc(&ks, DES_DECRYPT, SAFETY_FACTOR, iv, MAYBE_CONSTANT, osalt->ct, out);
		memcpy_macro(iv, osalt->ct + osalt->ctl - 16, 8);
		des3_crypt_cbc(&ks, DES_DECRYPT, 8, iv, MAYBE_CONSTANT, osalt->ct + osalt->ctl - 8, out + osalt->ctl - 8);
	} else if (osalt->cipher == 1) {  // RSA/DSA keys with AES-128
		unsigned char key[16];
		AES_KEY akey;
		unsigned char iv[16];

		block_size = 16;
		memcpy_macro(iv, osalt->salt, 16);
		generate_key_bytes(16, password, inbuffer[gid].length, salt, key);
		AES_set_decrypt_key(key, 128, &akey);
		AES_cbc_decrypt(osalt->ct, out, SAFETY_FACTOR, &akey, iv);
		memcpy_macro(iv, osalt->ct + osalt->ctl - 32, 16);
		AES_cbc_decrypt(osalt->ct + osalt->ctl - 16, out + osalt->ctl - 16, 16, &akey, iv);
	} else if (osalt->cipher == 2) {  // unsupported
	} else if (osalt->cipher == 3) {  // EC keys with AES-128
		unsigned char key[16];
		AES_KEY akey;
		unsigned char iv[16];

		block_size = 16;
		memcpy_macro(iv, osalt->salt, 16);
		generate_key_bytes(16, password, inbuffer[gid].length, salt, key);
		AES_set_decrypt_key(key, 128, &akey);
		AES_cbc_decrypt(osalt->ct, out, osalt->ctl, &akey, iv);
		return check_padding_and_structure_EC(out, osalt->ctl, 0);
	} else if (osalt->cipher == 4) {  // RSA/DSA keys with AES-192
		unsigned char key[24];
		AES_KEY akey;
		unsigned char iv[16];

		block_size = 16;
		memcpy_macro(iv, osalt->salt, 16);
		generate_key_bytes(24, password, inbuffer[gid].length, salt, key);
		AES_set_decrypt_key(key, 192, &akey);
		AES_cbc_decrypt(osalt->ct, out, SAFETY_FACTOR, &akey, iv);
		memcpy_macro(iv, osalt->ct + osalt->ctl - 32, 16);
		AES_cbc_decrypt(osalt->ct + osalt->ctl - 16, out + osalt->ctl - 16, 16, &akey, iv);
	} else if (osalt->cipher == 5) {  // RSA/DSA keys with AES-256
		unsigned char key[32];
		AES_KEY akey;
		unsigned char iv[16];

		block_size = 16;
		memcpy_macro(iv, osalt->salt, 16);
		generate_key_bytes(32, password, inbuffer[gid].length, salt, key);
		AES_set_decrypt_key(key, 256, &akey);
		AES_cbc_decrypt(osalt->ct, out, SAFETY_FACTOR, &akey, iv);
		memcpy_macro(iv, osalt->ct + osalt->ctl - 32, 16);
		AES_cbc_decrypt(osalt->ct + osalt->ctl - 16, out + osalt->ctl - 16, 16, &akey, iv);
	}

	return check_padding_and_structure(out, osalt->ctl, block_size);
}

__kernel
void ssh(__global const ssh_password *inbuffer,
                __global ssh_out *out,
                __constant ssh_salt *salt)
{
	uint idx = get_global_id(0);

	out[idx].cracked = ssh_decrypt(inbuffer, idx, salt, out);
}

/*
 * This software is Copyright (c) 2018 Dhiru Kholia, Copyright (c) 2018 magnum,
 * Copyright (c) 2025 Solar Designer,
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
	uint self_test_running;
} ssh_salt;

// output
typedef struct {
	uint cracked;
} ssh_out;

/* NB: keybytes is rounded up to a multiple of 16, need extra space for key */
INLINE void generate_key(uchar *password, size_t password_len, uchar *salt, uchar *key, int keybytes)
{
	uchar *p = key;

	do {
		MD5_CTX ctx;

		MD5_Init(&ctx);
		if (p > key)
			MD5_Update(&ctx, p - 16, 16);
		MD5_Update(&ctx, password, password_len);
		/* use first 8 bytes of salt */
		MD5_Update(&ctx, salt, 8);
		MD5_Final(p, &ctx);
		p += 16;
		keybytes -= 16;
	} while (keybytes > 0);
}

INLINE int check_structure_asn1(unsigned char *out, int length, int real_len, uint self_test_running)
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

INLINE int common_crypt_code(uchar *password, size_t password_len, __constant ssh_salt *cur_salt, __local aes_local_t *lt)
{
	int real_len;
	unsigned char out[SAFETY_FACTOR + 16];

	switch (cur_salt->cipher) {
	case 7: { /* RSA/DSA keys with DES */
		uchar salt[8];
		uchar key[16];
		des_context ks;
		uchar iv[8];

		memcpy_macro(salt, cur_salt->salt, 8);
		generate_key(password, password_len, salt, key, 8);
		des_setkey_dec(&ks, key);
		memcpy_macro(iv, cur_salt->ct + cur_salt->ctl - 16, 8);
		memcpy_macro(out + sizeof(out) - 8, cur_salt->ct + cur_salt->ctl - 8, 8);
		des_crypt_cbc(&ks, DES_DECRYPT, 8, iv, out + sizeof(out) - 8, out + sizeof(out) - 8);
		if ((real_len = check_pkcs_pad(out, sizeof(out), 8)) < 0)
			return -1;
		real_len += cur_salt->ctl - sizeof(out);
		memcpy_macro(out, cur_salt->ct, SAFETY_FACTOR);
		des_crypt_cbc(&ks, DES_DECRYPT, SAFETY_FACTOR, salt, out, out);
		break;
	}
	case 0: { /* RSA/DSA keys with 3DES */
		uchar salt[8];
		uchar key[32];
		des3_context ks;
		uchar iv[8];

		memcpy_macro(salt, cur_salt->salt, 8);
		generate_key(password, password_len, salt, key, 24);
		des3_set3key_dec(&ks, key);
		memcpy_macro(iv, cur_salt->ct + cur_salt->ctl - 16, 8);
		des3_crypt_cbc(&ks, DES_DECRYPT, 8, iv, MAYBE_CONSTANT, cur_salt->ct + cur_salt->ctl - 8, out + sizeof(out) - 8);
		if ((real_len = check_pkcs_pad(out, sizeof(out), 8)) < 0)
			return -1;
		real_len += cur_salt->ctl - sizeof(out);
		des3_crypt_cbc(&ks, DES_DECRYPT, SAFETY_FACTOR, salt, MAYBE_CONSTANT, cur_salt->ct, out);
		break;
	}
	case 1:   /* RSA/DSA keys with AES-128 */
	case 3:   /* EC keys with AES-128 */
	case 4:   /* RSA/DSA keys with AES-192 */
	case 5: { /* RSA/DSA keys with AES-256 */
		uchar salt[16];
		const unsigned int keybytes_all[5] = {16, 0, 16, 24, 32};
		unsigned int keybytes = keybytes_all[cur_salt->cipher - 1];
		unsigned char key[32];
		AES_KEY akey; akey.lt = lt;
		unsigned char iv[16];

		memcpy_macro(salt, cur_salt->salt, 16);
		generate_key(password, password_len, salt, key, keybytes);
		AES_set_decrypt_key(key, keybytes << 3, &akey);
		memcpy_macro(iv, cur_salt->ct + cur_salt->ctl - 32, 16);
		AES_cbc_decrypt(cur_salt->ct + cur_salt->ctl - 16, out + sizeof(out) - 16, 16, &akey, iv);
		if ((real_len = check_pkcs_pad(out, sizeof(out), 16)) < 0)
			return -1;
		real_len += cur_salt->ctl - sizeof(out);
		AES_cbc_decrypt(cur_salt->ct, out, SAFETY_FACTOR, &akey, salt);
		break;
	}
	default:
		return -1;
	}

	return check_structure_asn1(out, sizeof(out), real_len, cur_salt->self_test_running);
}

__kernel void ssh(__global const ssh_password *inbuffer,
                  __global ssh_out *out,
                  __constant ssh_salt *salt)
{
	__local aes_local_t lt;
	uchar password[PLAINTEXT_LENGTH];
	uint gid = get_global_id(0);

	memcpy_gp(password, inbuffer[gid].v, inbuffer[gid].length);

	out[gid].cracked = !common_crypt_code(password, inbuffer[gid].length, salt, &lt);
}

/*
 * This software is Copyright (c) 2018 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha1_kernel.cl"
#include "opencl_asn1.h"
#include "opencl_des.h"
#define AES_KEY_TYPE __global const
#define AES_SRC_TYPE MAYBE_CONSTANT
#include "opencl_aes.h"

typedef struct {
	uint cracked;
} pem_out;

typedef struct {
	pbkdf2_salt pbkdf2;
	int ciphertext_length;
	int cid;
	uchar iv[16];
	uchar ciphertext[CTLEN];
} pem_salt;

inline int pem_decrypt(__global uchar *key, MAYBE_CONSTANT pem_salt *salt)
{
	uchar out[CTLEN];
	struct asn1_hdr hdr;
	const uint8_t *pos, *end;
	const int length = salt->ciphertext_length;
#ifdef __OS_X__
	volatile
#endif
	int block_size;

	if (salt->cid == 1) {
		des3_context ks;
		uchar ivec[8];
		uchar pkey[24];

		block_size = 8;
		memcpy_macro(ivec, salt->iv, 8);
		memcpy_macro(pkey, key, 24);
		des3_set3key_dec(&ks, pkey);
		des3_crypt_cbc(&ks, DES_DECRYPT, length, ivec,
		               MAYBE_CONSTANT, salt->ciphertext, out);
	} else {
		const uint aes_sz = salt->cid * 64;
		uchar aiv[16];
		AES_KEY akey;

		block_size = 16;
		memcpy_macro(aiv, salt->iv, 16);
		AES_set_decrypt_key(key, aes_sz, &akey);
		AES_cbc_decrypt(salt->ciphertext, out, length, &akey, aiv);
	}

	if (check_pkcs_pad(out, length, block_size) < 0)
		return 0;

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
	if (*(pos + 2)) // *(pos + 1) == header length
		return 0;
	if (hdr.length != 1)
		return 0;
	pos = hdr.payload + hdr.length;
	if (hdr.payload[0])
		return 0;

	// SEQUENCE
	if (asn1_get_next(pos, length, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_SEQUENCE) {
		return 0;
	}
	pos = hdr.payload; /* go inside this sequence */

	// OBJECT IDENTIFIER (with value 1.2.840.113549.1.1.1, 1.2.840.10040.4.1 for DSA)
	if (asn1_get_next(pos, length, &hdr) < 0 ||
			hdr.class != ASN1_CLASS_UNIVERSAL ||
			hdr.tag != ASN1_TAG_OID) {
		return 0;
	}
	if (memcmp_pc(hdr.payload, "\x2a\x86\x48\x86", 4) &&
	    memcmp_pc(hdr.payload, "\x2a\x86\x48\xce", 4))
		return 0;

	return 1;
}

__kernel
void pem_final(MAYBE_CONSTANT pem_salt *salt,
               __global pbkdf2_out *pbkdf2,
               __global pem_out *out)
{
	uint gid = get_global_id(0);

	out[gid].cracked = pem_decrypt((__global uchar*)pbkdf2[gid].dk, salt);
}

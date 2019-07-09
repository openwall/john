/*
 * This software is Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha512_kernel.cl"
#include "opencl_hmac_sha512.h"
#include "opencl_aes.h"

#define SHA512_MDLEN            64
#define G_ELI_MAXMKEYS          2
#define G_ELI_MAXKEYLEN         64
#define G_ELI_USERKEYLEN        G_ELI_MAXKEYLEN
#define G_ELI_DATAKEYLEN        G_ELI_MAXKEYLEN
#define G_ELI_AUTHKEYLEN        G_ELI_MAXKEYLEN
#define G_ELI_IVKEYLEN          G_ELI_MAXKEYLEN
#define G_ELI_SALTLEN           64
#define G_ELI_DATAIVKEYLEN      (G_ELI_DATAKEYLEN + G_ELI_IVKEYLEN)
#define G_ELI_MKEYLEN           (G_ELI_DATAIVKEYLEN + SHA512_MDLEN)

typedef struct {
	salt_t pbkdf2;
	uint32_t md_version;
	uint16_t md_ealgo;
	uint16_t md_keylen;
	uint16_t md_aalgo;
	uint8_t md_keys;
	uint8_t	md_mkeys[G_ELI_MAXMKEYS * G_ELI_MKEYLEN];
} geli_salt_t;

typedef struct {
	uint cracked;
} out_t;

__kernel void geli_final(__global crack_t *pbkdf2,
                         __constant geli_salt_t *salt,
                         __global out_t *out)
{
	uint gid = get_global_id(0);
	__constant uchar *mmkey;
	const uchar nullstring[1] = { 0 };
	const uchar onestring[1] = { 1 };
	uchar enckey[SHA512_MDLEN];
	union {
		ulong u[8];
		uchar c[64];
	} key;
	int i, nkey;

	// Final swap and copy the PBKDF2 result
	for (i = 0; i < 8; i++)
		key.u[i] = SWAP64(pbkdf2[gid].hash[i]);

	hmac_sha512(nullstring, 0, key.c, G_ELI_USERKEYLEN,
	            key.c, G_ELI_USERKEYLEN);

	// The key for encryption is: enckey = HMAC_SHA512(Derived-Key, 1)
	hmac_sha512(key.c, G_ELI_USERKEYLEN, onestring, 1,
	            enckey, SHA512_MDLEN);

	mmkey = salt->md_mkeys;
	for (nkey = 0; nkey < G_ELI_MAXMKEYS; nkey++, mmkey += G_ELI_MKEYLEN) {
		int bit = (1 << nkey);
		uchar iv[16] = { 0 };
		AES_KEY aes_decrypt_key;
		uchar tmpmkey[G_ELI_MKEYLEN];
		const uchar *odhmac; /* On-disk HMAC. */
		uchar chmac[SHA512_MDLEN]; /* Calculated HMAC. */
		uchar hmkey[SHA512_MDLEN]; /* Key for HMAC. */

		if (!(salt->md_keys & bit))
			continue;

		memcpy_macro(tmpmkey, mmkey, G_ELI_MKEYLEN);

		// decrypt tmpmkey in aes-cbc mode using enckey
		AES_set_decrypt_key(enckey, salt->md_keylen, &aes_decrypt_key);
		AES_cbc_decrypt(tmpmkey, tmpmkey, G_ELI_MKEYLEN, &aes_decrypt_key, iv);

		// verify stuff, tmpmkey and key are involved
		hmac_sha512(key.c, G_ELI_USERKEYLEN, nullstring, 1,
		            hmkey, SHA512_MDLEN);
		odhmac = tmpmkey + G_ELI_DATAIVKEYLEN;

		// Calculate HMAC from Data-Key and IV-Key.
		hmac_sha512(hmkey, SHA512_MDLEN, tmpmkey, G_ELI_DATAIVKEYLEN,
		            chmac, SHA512_MDLEN);

		if (!memcmp_pp(odhmac, chmac, 16)) {
			out[gid].cracked = 1;
			return;
		}
	}
	out[gid].cracked = 0;
}

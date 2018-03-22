/*
 * This software is Copyright (c) 2018 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha1_kernel.cl"
#define AES_CTS_SRC_TYPE MAYBE_CONSTANT
#define AES_CTS_DST_TYPE __global
#include "opencl_aes.h"
#define HMAC_MSG_TYPE __global const
#include "opencl_hmac_sha1.h"

typedef struct {
	pbkdf2_salt pbkdf2;
	uint32_t etype;
	uint32_t edata2len;
	uint8_t  edata1[16];
	// edata2 is a separate __global buffer of variable size
} asrep_salt;

typedef struct {
	uint cracked;
} asrep_out;

inline void dk(uchar *key_out, uchar *key_in, uint key_size,
               __constant uchar *ptext, uint ptext_size)
{
	uchar iv[32] = { 0 };
	uchar plaintext[32] = { 0 };
	AES_KEY ekey;

	memcpy_macro(plaintext, ptext, ptext_size);

	AES_set_encrypt_key(key_in, key_size * 8, &ekey);
	AES_cbc_encrypt(plaintext, key_out, key_size, &ekey, iv);
}

inline void krb_decrypt(MAYBE_CONSTANT uchar *ciphertext, uint ctext_size,
                        __global uchar *plaintext, const uchar *key,
                        uint key_size)
{
	uchar iv[32] = { 0 };
	AES_KEY ekey;

	AES_set_decrypt_key(key, key_size * 8, &ekey);
	AES_cts_decrypt(ciphertext, plaintext, ctext_size, &ekey, iv);
}

__const_a8 uchar co_input[] = {0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73,
                               0x7b, 0x9b, 0x5b, 0x2b, 0x93, 0x13, 0x2b, 0x93};
__const_a8 uchar ke_input[] = {0xbe, 0x34, 0x9a, 0x4d, 0x24, 0xbe, 0x50, 0x0e,
                               0xaf, 0x57, 0xab, 0xd5, 0xea, 0x80, 0x75, 0x7a};
__const_a8 uchar ki_input[] = {0x6b, 0x60, 0xb0, 0x58, 0x2a, 0x6b, 0xa8, 0x0d,
                               0x5a, 0xad, 0x56, 0xab, 0x55, 0x40, 0x6a, 0xd5};

__kernel void asrep_final(MAYBE_CONSTANT asrep_salt *salt,
                          __global pbkdf2_out *pbkdf2,
                          MAYBE_CONSTANT uchar *edata2,
                          __global uchar *plaintext,
                          __global asrep_out *out)
{
	uint gid = get_global_id(0);
	const int key_size = (salt->etype == 17) ? 16 : 32;
#if HAVE_LUT3
	/*
	 * Bug workaround for some nvidias. An alternative workaround is
	 * forcing vector width 2 but that's slower.
	 */
	volatile
#endif
	uchar base_key[32];
	uchar Ke[32];
	uchar Ki[32];
	uchar checksum[20];

	plaintext += (salt->edata2len + 31) / 32 * 32 * gid;
	memcpy_macro(base_key, ((__global uchar*)pbkdf2[gid].dk), key_size);

	dk(base_key, base_key, key_size, co_input, 16);

	dk(Ke, base_key, key_size, ke_input, 16);
	krb_decrypt(edata2, salt->edata2len, plaintext, Ke, key_size);

	dk(Ki, base_key, key_size, ki_input, 16);
	hmac_sha1(Ki, key_size, plaintext, salt->edata2len, checksum, 20);

	out[gid].cracked = !memcmp_pmc(checksum, salt->edata1, 12);
}

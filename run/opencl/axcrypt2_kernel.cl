/*
 * This software is Copyright (c) 2018 Dhiru Kholia (dhiru.kholia [at] gmail.com)
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#define AES_SRC_TYPE MAYBE_CONSTANT

#include "pbkdf2_hmac_sha512_kernel.cl"
#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1_ctx.h"
#include "opencl_aes.h"

#define PUT_64BITS_XOR_LSB(cp, value) ( \
		(cp)[4] ^= (unsigned char)((value) >> 24), \
		(cp)[5] ^= (unsigned char)((value) >> 16), \
		(cp)[6] ^= (unsigned char)((value) >> 8),  \
		(cp)[7] ^= (unsigned char)((value)) )

typedef struct {
	salt_t pbkdf2;
	uint key_wrapping_rounds;
	uchar salt[64];
	uchar wrappedkey[144];
} axcrypt2_salt_t;

typedef struct {
	uint cracked;
} out_t;

__kernel void axcrypt2_final(__global crack_t *pbkdf2,
                         __constant axcrypt2_salt_t *salt,
                         __global out_t *out)
{
	uint gid = get_global_id(0);

	int i, k, j, nb_iterations = salt->key_wrapping_rounds;

	union {
		ulong u[8];
		uchar c[64];
	} key;

	// Final swap and copy the PBKDF2 result
	for (i = 0; i < 8; i++)
		key.u[i] = SWAP64(pbkdf2[gid].hash[i]);

	unsigned char KEK[32];
	AES_KEY akey;
	int halfblocklen = 16 / 2;
	int wrappedkeylen = 56 - halfblocklen;
	unsigned char wrapped[144];
	unsigned char block[16];
	int t;

	memset_p(KEK, 0, 32);

	for (k = 0; k < 64 ; k++)
		KEK[k % 32] ^= key.c[k];

	for (k = 0; k < 32; k++)
		KEK[k] = KEK[k] ^ salt->salt[k];

	AES_set_decrypt_key(KEK, 256, &akey);

	memcpy_macro(wrapped, salt->wrappedkey, 56);

	/* custom AES un-wrapping loop */
	for (j = nb_iterations - 1; j >= 0; j--) {
		for (k = wrappedkeylen / halfblocklen; k >= 1; --k) {
			t = ((wrappedkeylen / halfblocklen) * j) + k;
			// MSB(B) = A XOR t
			memcpy_pp(block, wrapped, halfblocklen);
			PUT_64BITS_XOR_LSB(block, t);
			// LSB(B) = R[i]
			memcpy_pp(block + halfblocklen, wrapped + k * halfblocklen, halfblocklen);
			// B = AESD(K, X xor t | R[i]) where t = (n * j) + i
			AES_decrypt(block, block, &akey);
			// A = MSB(B)
			memcpy_pp(wrapped, block, halfblocklen);
			// R[i] = LSB(B)
			memcpy_pp(wrapped + k * halfblocklen, block + halfblocklen, halfblocklen);
		}
	}

	out[gid].cracked = !memcmp_pc(wrapped, "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6", 8);
}

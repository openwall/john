/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and Copyright (c) 2012-2017 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Pass this kernel -DKEYLEN=x -DOUTLEN=y -DSALTLEN=z for generic use.
 *
 * KEYLEN  should be PLAINTEXT_LENGTH for passwords or 20 for hash
 * OUTLEN  should be sizeof(outbuffer->v)
 * SALTLEN should be sizeof(currentsalt.salt)
 *
 * salt->skip_bytes means "skip leading output bytes" and can be given in
 * multiples of underlying hash size (in this case 20). So to calculate only
 * byte 21-40 (second chunk) you can say "salt->outlen=20 salt->skip_bytes=20"
 * for a 2x boost. The 1st byte of output array will then be 1st byte of second
 * chunk so its actual size can be 20 as opposed to 40.
 */

#include "pbkdf2_hmac_sha1_unsplit_kernel.cl"
#define AES_KEY_TYPE __global
#define AES_SRC_TYPE __constant
#include "opencl_aes.h"

typedef struct {
	uint cracked;
} blockchain_out;

typedef struct {
	pbkdf2_salt pbkdf2;
	uchar data[SAFETY_FACTOR];
	int length;
} blockchain_salt;

inline int blockchain_decrypt(__global uchar *derived_key,
                              __constant uchar *data)
{
	uchar out[SAFETY_FACTOR];
	AES_KEY akey;
	uchar iv[16];

	AES_set_decrypt_key(derived_key, 256, &akey);
	memcpy_cp(iv, data, 16);
	AES_cbc_decrypt(data + 16, out, 16, &akey, iv);

	/* various tests */
	if (out[0] != '{') // fast test
		return 0;

	// "guid" will be found in the first block
	if (memmem_pc(out, 16, "\"guid\"", 6)) {
		AES_cbc_decrypt(data + 32, out + 16, SAFETY_FACTOR - 16, &akey, iv);
		if (memmem_pc(out, SAFETY_FACTOR, "\"sharedKey\"", 11))
			// We have 2^144 confidence now
			return 1;
	}
	return 0;
}

__kernel void blockchain(__global const pbkdf2_password *inbuffer,
                         __global pbkdf2_hash *dk,
                         __constant blockchain_salt *salt,
                         __global blockchain_out *out)
{
	uint idx = get_global_id(0);

	pbkdf2(inbuffer[idx].v, inbuffer[idx].length,
	       salt->pbkdf2.salt, salt->pbkdf2.length, salt->pbkdf2.iterations,
	       dk[idx].v, salt->pbkdf2.outlen, salt->pbkdf2.skip_bytes);

	out[idx].cracked = blockchain_decrypt((__global uchar*)dk[idx].v, salt->data);
}

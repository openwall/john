/*
 * AES OpenCL XTS functions
 *
 * Copyright (c) 2017-2025, magnum.
 *
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#ifndef _OPENCL_AES_XTS_H_
#define _OPENCL_AES_XTS_H_

#ifdef _OPENCL_AES_H_
#error "opencl_aes_xts.h cannot be sourced after opencl_aes.h"
#endif

/* Tell the AES code we use two contexts simultaneously */
#define AES_SIMULTANEOUS_CTX_SHIFT    1
#include "opencl_aes.h"

INLINE void AES_256_XTS_first_sector(AES_SRC_TYPE uint *in, AES_DST_TYPE uint *out,
                                     AES_KEY_TYPE uchar *double_key,
                                     __local aes_local_t *lt1, __local aes_local_t *lt2)
{
	uint tweak[4] = { 0 };
	uint buf[4];
	int i;
	AES_KEY akey1, akey2; akey1.lt = lt1; akey2.lt = lt2;

	AES_set_decrypt_key(double_key, 256, &akey1);
	AES_set_encrypt_key(double_key + 32, 256, &akey2);

	AES_encrypt((uchar*)tweak, (uchar*)tweak, &akey2);

	for (i = 0; i < 4; i++)
		buf[i] = in[i] ^ tweak[i];

	AES_decrypt((uchar*)buf, (uchar*)buf, &akey1);

	for (i = 0; i < 4; i++)
		out[i] = buf[i] ^ tweak[i];
}

INLINE void AES_256_XTS_DiskCryptor(AES_SRC_TYPE uchar *data, AES_DST_TYPE uchar *output,
                                    AES_KEY_TYPE uchar *double_key, int len,
                                    __local aes_local_t *lt1, __local aes_local_t *lt2)
{
	uchar buf[16];
	int i, j, cnt;
	AES_KEY key1; key1.lt = lt1;
	AES_KEY key2; key2.lt = lt2;
	int bits = 256;
	uchar buffer[96];
	uchar *out = buffer;
	unsigned char tweak[16] = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	AES_set_decrypt_key(double_key, bits, &key1);
	AES_set_encrypt_key(&double_key[bits / 8], bits, &key2);

	// first aes tweak, we do it right over tweak
	AES_encrypt(tweak, tweak, &key2);

	cnt = len / 16;
	for (j = 0;;) {
		for (i = 0; i < 16; ++i) buf[i] = data[i]^tweak[i];
		AES_decrypt(buf, out, &key1);
		for (i = 0; i < 16; ++i) out[i] ^= tweak[i];
		++j;
		if (j == cnt)
			break;
		else {
			unsigned char Cin, Cout;
			unsigned x;
			Cin = 0;
			for (x = 0; x < 16; ++x) {
				Cout = (tweak[x] >> 7) & 1;
				tweak[x] = ((tweak[x] << 1) + Cin) & 0xFF;
				Cin = Cout;
			}
			if (Cout)
				tweak[0] ^= 135; // GF_128_FDBK;
		}
		data += 16;
		out += 16;
	}

	memcpy_macro(output, buffer, 96);
}

#endif	/* _OPENCL_AES_XTS_H_ */

/*
 * AES OpenCL functions
 *
 * Copyright (c) 2017-2018, magnum.
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#ifndef _OPENCL_AES_H_
#define _OPENCL_AES_H_

#include "opencl_misc.h"

/*
 * These all default to private (generic) but can be e.g. __global or __constant
 */
#ifndef AES_KEY_TYPE
#define AES_KEY_TYPE const
#endif

#if defined(AES_SRC_TYPE) || defined(AES_DST_TYPE)
#define DO_MEMCPY 1
#endif

#ifndef AES_SRC_TYPE
#define AES_SRC_TYPE const
#endif

#ifndef AES_DST_TYPE
#define AES_DST_TYPE
#endif

#ifndef AES_CTS_SRC_TYPE
#define AES_CTS_SRC_TYPE const
#endif

#ifndef AES_CTS_DST_TYPE
#define AES_CTS_DST_TYPE
#endif

#define AES_BLOCK_SIZE 16

/*
 * Source the basic AES code. We use a fancy bitsliced version that can
 * do two blocks in parallel except with some devices that are either too
 * buggy to use it, or actually perform slower with it.
 * CPU's seem to generally perform worse with it. Nvidia GPU's love it.
 * macOS may crash just trying to build it.
 */
#if defined(AES_NO_BITSLICE) || cpu(DEVICE_INFO) || (__OS_X__ && gpu_amd(DEVICE_INFO))
#include "opencl_aes_plain.h"
#else
#include "opencl_aes_bitslice.h"
#endif

/*
 * Here's some cipher mode alternatives. These support different OpenCL
 * memory types.
 *
 * The bitsliced code has its own ECB code that does two blocks in parallel.
 */

#ifndef AES_ecb_encrypt
inline void
AES_ecb_encrypt(AES_SRC_TYPE void *_in, AES_DST_TYPE void *_out, uint len,
                AES_KEY *akey)
{
	AES_SRC_TYPE uchar *in = _in;
	AES_DST_TYPE uchar *out = _out;
#ifdef DO_MEMCPY
	uchar tmp[16];
#endif

	while (len > 16) {
#ifdef DO_MEMCPY
		memcpy_macro(tmp, in, 16);
		AES_encrypt(tmp, tmp, akey);
		memcpy_macro(out, tmp, 16);
#else
		AES_encrypt(in, out, akey);
#endif
		len -= 16;
		in += 16;
		out += 16;
	}
#ifdef DO_MEMCPY
	memcpy_macro(tmp, in, len);
	AES_encrypt(tmp, tmp, akey);
	memcpy_macro(out, tmp, len);
#else
	AES_encrypt(in, out, akey);
#endif
}
#endif /* AES_ecb_encrypt */

#ifndef AES_ecb_decrypt
inline void
AES_ecb_decrypt(AES_SRC_TYPE void *_in, AES_DST_TYPE void *_out, uint len,
                AES_KEY *akey)
{
	AES_SRC_TYPE uchar *in = _in;
	AES_DST_TYPE uchar *out = _out;
#ifdef DO_MEMCPY
	uchar tmp[16];
#endif

	while (len > 16) {
#ifdef DO_MEMCPY
		memcpy_macro(tmp, in, 16);
		AES_decrypt(tmp, tmp, akey);
		memcpy_macro(out, tmp, 16);
#else
		AES_decrypt(in, out, akey);
#endif
		len -= 16;
		in += 16;
		out += 16;
	}
#ifdef DO_MEMCPY
	memcpy_macro(tmp, in, len);
	AES_decrypt(tmp, tmp, akey);
	memcpy_macro(out, tmp, len);
#else
	AES_decrypt(in, out, akey);
#endif
}
#endif /* AES_ecb_decrypt */

inline void
AES_cbc_encrypt(AES_SRC_TYPE void *_in, AES_DST_TYPE void *_out,
                uint len, AES_KEY *akey, void *_iv)
{
	AES_SRC_TYPE uchar *in = _in;
	AES_DST_TYPE uchar *out = _out;
	uchar *iv = _iv;
	uint n;
	const uchar *ivec = iv;
	uchar tmp[16];

	while (len) {
		for (n = 0; n < 16 && n < len; n++)
			tmp[n] = in[n] ^ ivec[n];
		for (; n<16; n++)
			tmp[n] = ivec[n];
		AES_encrypt(tmp, tmp, akey);
		memcpy_macro(out, tmp, 16);
		ivec = tmp;
		if (len <= 16)
			break;
		len -= 16;
		in  += 16;
		out += 16;
	}
	memcpy_macro(iv, ivec, 16);
}

inline void
AES_cbc_decrypt(AES_SRC_TYPE void *_in, AES_DST_TYPE void *_out,
                uint len, AES_KEY *akey,
                void *_iv)
{
	AES_SRC_TYPE uchar *in = _in;
	AES_DST_TYPE uchar *out = _out;
	uchar *iv = _iv;

	while (len) {
		uint n;
		uchar tmp[16];

		memcpy_macro(tmp, in, 16);
		AES_decrypt(tmp, tmp, akey);
		for (n = 0; n < 16 && n < len; ++n) {
			uchar c = in[n];
			out[n] = tmp[n] ^ iv[n];
			iv[n] = c;
		}
		if (len <= 16) {
			for (; n < 16; ++n)
				iv[n] = in[n];
			break;
		}
		len -= 16;
		in  += 16;
		out += 16;
	}
}

inline void
AES_cts_encrypt(AES_CTS_SRC_TYPE void *_in, AES_CTS_DST_TYPE void *_out,
                uint len, AES_KEY *akey, void *_iv)
{
	AES_CTS_SRC_TYPE uchar *in = _in;
	AES_CTS_DST_TYPE uchar *out = _out;
	uchar *iv = _iv;
	uint i;
	uchar tmp[AES_BLOCK_SIZE];

	while(len > AES_BLOCK_SIZE) {
		for (i = 0; i < AES_BLOCK_SIZE; i++)
			tmp[i] = in[i] ^ iv[i];
		AES_encrypt(tmp, tmp, akey);
		memcpy_macro(out, tmp, AES_BLOCK_SIZE);
		memcpy_macro(iv, tmp, AES_BLOCK_SIZE);
		len -= AES_BLOCK_SIZE;
		in += AES_BLOCK_SIZE;
		out += AES_BLOCK_SIZE;
	}
	for (i = 0; i < len; i++)
		tmp[i] = in[i] ^ iv[i];

	for (; i < AES_BLOCK_SIZE; i++)
		tmp[i] = 0 ^ iv[i];

	AES_encrypt(tmp, tmp, akey);
	memcpy_macro(out - AES_BLOCK_SIZE, tmp, AES_BLOCK_SIZE);
	memcpy_macro(out, iv, len);
	memcpy_macro(iv, out - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
}

inline void
AES_cts_decrypt(AES_CTS_SRC_TYPE void *_in, AES_CTS_DST_TYPE void *_out,
                uint len, AES_KEY *akey, void *_iv)
{
	AES_CTS_SRC_TYPE uchar *in = _in;
	AES_CTS_DST_TYPE uchar *out = _out;
	uchar *iv = _iv;
	uint i;
	uchar tmp[AES_BLOCK_SIZE];
	uchar tmp2[AES_BLOCK_SIZE];
	uchar tmp3[AES_BLOCK_SIZE];

	while(len > AES_BLOCK_SIZE * 2) {
		memcpy_macro(tmp, in, AES_BLOCK_SIZE);
		AES_decrypt(tmp, tmp2, akey);
		for (i = 0; i < AES_BLOCK_SIZE; i++)
			out[i] = tmp2[i] ^ iv[i];
		memcpy_macro(iv, tmp, AES_BLOCK_SIZE);
		len -= AES_BLOCK_SIZE;
		in += AES_BLOCK_SIZE;
		out += AES_BLOCK_SIZE;
	}

	len -= AES_BLOCK_SIZE;
	memcpy_macro(tmp, in, AES_BLOCK_SIZE); /* save last iv */
	AES_decrypt(tmp, tmp2, akey);
	memcpy_macro(tmp3, in + AES_BLOCK_SIZE, len);
	memcpy_macro(tmp3 + len, tmp2 + len, AES_BLOCK_SIZE - len); /* xor 0 */

	for (i = 0; i < len; i++)
		out[i + AES_BLOCK_SIZE] = tmp2[i] ^ tmp3[i];

	AES_decrypt(tmp3, tmp3, akey);
	for (i = 0; i < AES_BLOCK_SIZE; i++)
		out[i] = tmp3[i] ^ iv[i];
	memcpy_macro(iv, tmp, AES_BLOCK_SIZE);
}

inline void AES_cfb_decrypt(AES_SRC_TYPE void *_in,
                            AES_DST_TYPE void *_out,
                            uint len, AES_KEY *akey, void *_iv)
{
	AES_SRC_TYPE uchar *in = _in;
	AES_DST_TYPE uchar *out = _out;
	uchar *iv = _iv;
	int n = 0;

	while (len--) {
		uchar c;

		if (!n)
			AES_encrypt(iv, iv, akey);

		c = *in++;
		*out++ = c ^ iv[n];
		iv[n] = c;

		n = (n + 1) & 0x0f;
	}
}

inline void AES_256_XTS_first_sector(AES_SRC_TYPE uint *in,
                                     AES_DST_TYPE uint *out,
                                     AES_KEY_TYPE uchar *double_key)
{
	uint tweak[4] = { 0 };
	uint buf[4];
	int i;
	AES_KEY akey1, akey2;

	AES_set_decrypt_key(double_key, 256, &akey1);
	AES_set_encrypt_key(double_key + 32, 256, &akey2);

	AES_encrypt((uchar*)tweak, (uchar*)tweak, &akey2);

	for (i = 0; i < 4; i++)
		buf[i] = in[i] ^ tweak[i];

	AES_decrypt((uchar*)buf, (uchar*)buf, &akey1);

	for (i = 0; i < 4; i++)
		out[i] = buf[i] ^ tweak[i];
}

inline void AES_256_XTS_DiskCryptor(AES_SRC_TYPE uchar *data, AES_DST_TYPE uchar *output,
		AES_KEY_TYPE uchar *double_key, int len)
{
	uchar buf[16];
	int i, j, cnt;
	AES_KEY key1, key2;
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

#define N_WORDS (AES_BLOCK_SIZE / sizeof(unsigned long))

inline void
AES_ige_decrypt(AES_SRC_TYPE void *_in, AES_DST_TYPE void *_out,
                uint length, AES_KEY *akey, uchar *_iv)
{
	AES_SRC_TYPE uchar *in = _in;
	AES_DST_TYPE uchar *out = _out;

	typedef union aes_block_u {
		ulong data[N_WORDS];
		uchar bytes[AES_BLOCK_SIZE];
	} aes_block_t;

	aes_block_t tmp, tmp2;
	aes_block_t iv;
	aes_block_t iv2;

	uint n;
	uint len = length / AES_BLOCK_SIZE;

	memcpy_macro(iv.bytes, _iv, AES_BLOCK_SIZE);
	memcpy_macro(iv2.bytes, _iv + AES_BLOCK_SIZE, AES_BLOCK_SIZE);

	while (len) {
		memcpy_macro(tmp.bytes, in, AES_BLOCK_SIZE);
		tmp2 = tmp;
		for (n = 0; n < N_WORDS; ++n)
			tmp.data[n] ^= iv2.data[n];
		AES_decrypt((uchar*)tmp.data, (uchar*)tmp.data, akey);
		for (n = 0; n < N_WORDS; ++n)
			tmp.data[n] ^= iv.data[n];
		memcpy_macro(out, tmp.bytes, AES_BLOCK_SIZE);
		iv = tmp2;
		iv2 = tmp;
		--len;
		in += AES_BLOCK_SIZE;
		out += AES_BLOCK_SIZE;
	}

	// memcpy_macro(_iv, iv.bytes, AES_BLOCK_SIZE);
	// memcpy_macro(_iv + AES_BLOCK_SIZE, iv2.bytes, AES_BLOCK_SIZE);
}

#endif	/* _OPENCL_AES_H_ */

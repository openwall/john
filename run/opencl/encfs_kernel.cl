/*
 * This software is Copyright (c) 2018 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#include "pbkdf2_hmac_sha1_kernel.cl"
#include "opencl_aes.h"
#include "opencl_hmac_sha1.h"

typedef struct {
	pbkdf2_salt pbkdf2;
	uint keySize;
	uint ivLength;
	uint dataLen;
	uchar data[128];
} encfs_salt;

typedef struct {
	uint32_t cracked;
} encfs_out;

#define MAX_KEYLENGTH       32 // in bytes (256 bit)
#define MAX_IVLENGTH        20
#define KEY_CHECKSUM_BYTES  4

#define unshuffleBytes(buf, size) do \
	{ \
		uint i; \
		for (i = size - 1; i; --i) \
			buf[i] ^= buf[i - 1]; \
	} while(0)

inline void encfs_common_setIVec(MAYBE_CONSTANT encfs_salt *salt,
                                 uchar *ivec, uint64_t seed, uchar *key)
{
	uchar iv_and_seed[MAX_IVLENGTH+8];
	uint i;

	// combine ivec and seed with HMAC
	memcpy_pp(iv_and_seed, &key[salt->keySize], salt->ivLength);
	for (i = 0; i < 8; ++i) {
		iv_and_seed[i + salt->ivLength] = (uchar)(seed & 0xff);
		seed >>= 8;
	}

	hmac_sha1(key, salt->keySize, iv_and_seed, salt->ivLength + 8,
	          ivec, salt->ivLength);
}

inline void flipBytes(uchar *buf, uint size)
{
	uchar revBuf[64];
	uint bytesLeft = size;
	uint i;

	while (bytesLeft) {
		uint toFlip = MIN(sizeof(revBuf), bytesLeft);

		for (i = 0; i < toFlip; ++i)
			revBuf[i] = buf[toFlip - (i + 1)];
		memcpy_pp(buf, revBuf, toFlip);
		bytesLeft -= toFlip;
		buf += toFlip;
	}
}

inline uint64_t _checksum_64(MAYBE_CONSTANT encfs_salt *salt, uchar *key,
                             const uchar *data, uint dataLen,
                             uint64_t *chainedIV)
{
	uchar DataIV[128 + 8]; // max data len is 128
	uchar md[20];
	uint i;
	uchar h[8] = { 0 };
	uint64_t value;

	memcpy_pp(DataIV, data, dataLen);

	if (chainedIV) {
		// toss in the chained IV as well
		uint64_t tmp = *chainedIV;

		for (i = 0; i < 8; ++i) {
			DataIV[dataLen++] = (tmp & 0xff);
			tmp >>= 8;
		}
	}

	hmac_sha1(key, salt->keySize, DataIV, dataLen, md, 20);

	// chop this down to a 64bit value..
	for (i = 0; i < 19; ++i)
		h[i % 8] ^= (uchar)(md[i]);
	value = (uint64_t)h[0];
	for (i = 1; i < 8; ++i)
		value = (value << 8) | (uint64_t)h[i];

	return value;
}

inline uint64_t MAC_64(MAYBE_CONSTANT encfs_salt *salt,
                       const uchar *data,
                       uint len, uchar *key, uint64_t *chainedIV )
{
	uint64_t tmp = _checksum_64(salt, key, data, len, chainedIV);

	if (chainedIV)
		*chainedIV = tmp;

	return tmp;
}

inline uint encfs_common_MAC_32(MAYBE_CONSTANT encfs_salt *salt, uchar *src,
                                uint len, uchar *key)
{
	uint64_t *chainedIV = (void*)0;
	uint64_t mac64 = MAC_64(salt, src, len, key, chainedIV );
	uint mac32 = ((mac64 >> 32) & 0xffffffff) ^ (mac64 & 0xffffffff);

	return mac32;
}

inline void encfs_common_streamDecode(MAYBE_CONSTANT encfs_salt *salt,
                                      uchar *buf, uint size, uint64_t iv64,
                                      uchar *key)
{
	uchar ivec[MAX_IVLENGTH];
	AES_KEY akey;

	encfs_common_setIVec(salt, ivec, iv64 + 1, key);
	AES_set_encrypt_key(key, salt->keySize * 8, &akey);
	AES_cfb_decrypt(buf, buf, size, &akey, ivec);
	unshuffleBytes(buf, size);
	flipBytes(buf, size);

	encfs_common_setIVec(salt, ivec, iv64, key);
	AES_cfb_decrypt(buf, buf, size, &akey, ivec);
	unshuffleBytes(buf, size);
}

__kernel
void encfs_final(MAYBE_CONSTANT encfs_salt *salt,
                 __global pbkdf2_out *pbkdf2,
                 __global encfs_out *out)
{
	uint gid = get_global_id(0);
	uint i;
	uchar master[MAX_KEYLENGTH + MAX_IVLENGTH];
	uchar tmpBuf[MAX_DATALEN];
	uint checksum = 0;
	uint checksum2 = 0;

	memcpy_gp(master, pbkdf2[gid].dk, salt->keySize + salt->ivLength);

	// First N bytes are checksum bytes.
	for (i = 0; i < KEY_CHECKSUM_BYTES; ++i)
		checksum = (checksum << 8) | (uint)salt->data[i];

	memcpy_mcp(tmpBuf, salt->data + KEY_CHECKSUM_BYTES, salt->keySize + salt->ivLength);
	encfs_common_streamDecode(salt, tmpBuf, salt->keySize + salt->ivLength ,checksum, master);
	checksum2 = encfs_common_MAC_32(salt, tmpBuf, salt->keySize + salt->ivLength, master);

	out[gid].cracked = (checksum2 == checksum);
}

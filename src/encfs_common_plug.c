/*
 * Common code for EncFS format for JtR. 2014 by JimF.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "encfs_common.h"
#include "hmac_sha.h"

int encfs_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int res, extra;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* key size */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res < 128 || res > MAX_KEYLENGTH*8)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if (!isdecu(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* cipher */
		goto err;
	if (!isdecu(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt length */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res > 40)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra)/2 != res || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* data length */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res > 128)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* data */
		goto err;
	if (hexlenl(p, &extra)/2 != res || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *encfs_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static encfs_common_custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "*");
	cs.keySize = atoi(p);
	cs.keySize = cs.keySize / 8;
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.cipher = atoi(p);
	p = strtokm(NULL, "*");
	cs.saltLen = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.saltLen; i++)
		cs.salt[i] =
			atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.dataLen = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.dataLen; i++)
		cs.data[i] =
			atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];

	cs.ivLength = 16;
	MEM_FREE(keeptr);
	return (void *) &cs;
}

unsigned int encfs_common_iteration_count(void *salt)
{
	encfs_common_custom_salt *my_salt = (encfs_common_custom_salt *)salt;

	return (unsigned int) my_salt->iterations;
}

// Other 'common' functions for this format:
void encfs_common_setIVec(encfs_common_custom_salt *cur_salt, unsigned char *ivec, uint64_t seed, unsigned char *key)
{
	unsigned char iv_and_seed[MAX_IVLENGTH+8];
	int i;

	// combine ivec and seed with HMAC
	memcpy(iv_and_seed, &key[cur_salt->keySize], cur_salt->ivLength);
	for (i=0; i<8; ++i) {
		iv_and_seed[i+cur_salt->ivLength] = (unsigned char)(seed & 0xff);
		seed >>= 8;
	}
	hmac_sha1(key, cur_salt->keySize, iv_and_seed, cur_salt->ivLength+8, ivec, cur_salt->ivLength);
}

static void flipBytes(unsigned char *buf, int size)
{
	unsigned char revBuf[64];
	int bytesLeft = size;
	int i;

	while (bytesLeft) {
		int toFlip = MIN_(sizeof(revBuf), bytesLeft);
		for (i = 0; i < toFlip; ++i)
			revBuf[i] = buf[toFlip - (i+1)];
		memcpy( buf, revBuf, toFlip );
		bytesLeft -= toFlip;
		buf += toFlip;
	}
	memset(revBuf, 0, sizeof(revBuf));
}
static uint64_t _checksum_64(encfs_common_custom_salt *cur_salt, unsigned char *key, const unsigned char *data, int dataLen, uint64_t *chainedIV)
{
	unsigned char DataIV[128+8]; // max data len is 128
	unsigned char md[20];
	int i;
	unsigned char h[8] = {0,0,0,0,0,0,0,0};
	uint64_t value;

	memcpy(DataIV, data, dataLen);
	if (chainedIV) {
		// toss in the chained IV as well
		uint64_t tmp = *chainedIV;
		for (i = 0; i < 8; ++i) {
			DataIV[dataLen++] = (tmp & 0xff);
			tmp >>= 8;
		}
	}
	hmac_sha1(key, cur_salt->keySize, DataIV, dataLen, md, 20);

	// chop this down to a 64bit value..
	for (i = 0; i < 19; ++i)
		h[i%8] ^= (unsigned char)(md[i]);
	value = (uint64_t)h[0];
	for (i = 1; i < 8; ++i)
		value = (value << 8) | (uint64_t)h[i];

	return value;
}

static uint64_t MAC_64(encfs_common_custom_salt *cur_salt,  const unsigned char *data, int len, unsigned char *key, uint64_t *chainedIV )
{
	uint64_t tmp = _checksum_64(cur_salt, key, data, len, chainedIV );

	if (chainedIV)
		*chainedIV = tmp;

	return tmp;
}

unsigned int encfs_common_MAC_32(encfs_common_custom_salt *cur_salt, unsigned char *src, int len, unsigned char *key)
{
	uint64_t *chainedIV = NULL;
	uint64_t mac64 = MAC_64(cur_salt, src, len, key, chainedIV );
	unsigned int mac32 = ((mac64 >> 32) & 0xffffffff) ^ (mac64 & 0xffffffff);
	return mac32;
}

static void AES_cfb_decrypt(AES_KEY *akey, int len, unsigned char *iv,
                            const unsigned char *input, unsigned char *output)
{
	int n = 0;

	while (len--) {
		unsigned char c;

		if (!n)
			AES_ecb_encrypt(iv, iv, akey, AES_ENCRYPT);

		c = *input++;
		*output++ = c ^ iv[n];
		iv[n] = c;

		n = (n + 1) & 0x0f;
	}
}

void encfs_common_streamDecode(encfs_common_custom_salt *cur_salt,
                               unsigned char *buf, int size, uint64_t iv64,
                               unsigned char *key)
{
	unsigned char ivec[MAX_IVLENGTH];
	AES_KEY akey;

	encfs_common_setIVec(cur_salt, ivec, iv64 + 1, key);
	AES_set_encrypt_key(key, cur_salt->keySize * 8, &akey);
	AES_cfb_decrypt(&akey, size, ivec, buf, buf);
	unshuffleBytes(buf, size);
	flipBytes(buf, size);

	encfs_common_setIVec(cur_salt, ivec, iv64, key);
	AES_cfb_decrypt(&akey, size, ivec, buf, buf);
	unshuffleBytes(buf, size);
}

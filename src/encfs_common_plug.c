/* 
 * encfs JtR, common code. 2014 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "encfs_common.h"
#include <openssl/hmac.h>

int encfs_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int res;
	if (strncmp(ciphertext, "$encfs$", 7))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 7;
	if ((p = strtok(ctcopy, "*")) == NULL)	/* key size */
		goto err;
	res = atoi(p);
	if (res < 128 || res > MAX_KEYLENGTH*8)
		return 0;
	if ((p = strtok(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* cipher */
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* salt length */
		goto err;
	res = atoi(p);
	if (res > 40)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (res * 2 != strlen(p))
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* data length */
		goto err;
	res = atoi(p);
	if (res > 128)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* data */
		goto err;
	if (res * 2 != strlen(p))
		goto err;
	if (!ishex(p))
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *encfs_common_get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static encfs_common_custom_salt cs;
	ctcopy += 7;
	p = strtok(ctcopy, "*");
	cs.keySize = atoi(p);
	switch(cs.keySize)
	{
		case 128:
			cs.blockCipher = EVP_aes_128_cbc();
			cs.streamCipher = EVP_aes_128_cfb();
			break;

		case 192:
			cs.blockCipher = EVP_aes_192_cbc();
			cs.streamCipher = EVP_aes_192_cfb();
			break;
		case 256:
		default:
			cs.blockCipher = EVP_aes_256_cbc();
			cs.streamCipher = EVP_aes_256_cfb();
			break;
	}
	cs.keySize = cs.keySize / 8;
	p = strtok(NULL, "*");
	cs.iterations = atoi(p);
	p = strtok(NULL, "*");
	cs.cipher = atoi(p);
	p = strtok(NULL, "*");
	cs.saltLen = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.saltLen; i++)
		cs.salt[i] =
			atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.dataLen = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.dataLen; i++)
		cs.data[i] =
			atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];

	cs.ivLength = EVP_CIPHER_iv_length( cs.blockCipher );
	MEM_FREE(keeptr);
	return (void *) &cs;
}

#if FMT_MAIN_VERSION > 11
unsigned int encfs_common_iteration_count(void *salt)
{
	encfs_common_custom_salt *my_salt = (encfs_common_custom_salt *)salt;
	return (unsigned int) my_salt->iterations;
}
#endif

// Other 'common' functions for this format:
void encfs_common_setIVec(encfs_common_custom_salt *cur_salt, unsigned char *ivec, uint64_t seed, unsigned char *key)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdLen = EVP_MAX_MD_SIZE;
	int i;
	HMAC_CTX mac_ctx;

	memcpy( ivec, &key[cur_salt->keySize], cur_salt->ivLength );
	for(i=0; i<8; ++i) {
		md[i] = (unsigned char)(seed & 0xff);
		seed >>= 8;
	}
	// combine ivec and seed with HMAC
	HMAC_CTX_init(&mac_ctx);
	HMAC_Init_ex( &mac_ctx, key, cur_salt->keySize, EVP_sha1(), 0 );
	HMAC_Init_ex( &mac_ctx, 0, 0, 0, 0 );
	HMAC_Update( &mac_ctx, ivec, cur_salt->ivLength );
	HMAC_Update( &mac_ctx, md, 8 );
	HMAC_Final( &mac_ctx, md, &mdLen );
	HMAC_CTX_cleanup(&mac_ctx);
	memcpy( ivec, md, cur_salt->ivLength );
}

static void flipBytes(unsigned char *buf, int size)
{
	unsigned char revBuf[64];

	int bytesLeft = size;
	int i;
	while(bytesLeft) {
		int toFlip = MIN_( sizeof(revBuf), bytesLeft );
		for(i=0; i<toFlip; ++i)
			revBuf[i] = buf[toFlip - (i+1)];
		memcpy( buf, revBuf, toFlip );
		bytesLeft -= toFlip;
		buf += toFlip;
	}
	memset(revBuf, 0, sizeof(revBuf));
}
static uint64_t _checksum_64(encfs_common_custom_salt *cur_salt, unsigned char *key, const unsigned char *data, int dataLen, uint64_t *chainedIV)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdLen = EVP_MAX_MD_SIZE;
	int i;
	unsigned char h[8] = {0,0,0,0,0,0,0,0};
	uint64_t value;
	HMAC_CTX mac_ctx;

	HMAC_CTX_init(&mac_ctx);
	HMAC_Init_ex( &mac_ctx, key, cur_salt->keySize, EVP_sha1(), 0 );
	HMAC_Init_ex( &mac_ctx, 0, 0, 0, 0 );
	HMAC_Update( &mac_ctx, data, dataLen );
	if(chainedIV)
	{
	  // toss in the chained IV as well
		uint64_t tmp = *chainedIV;
		unsigned char h[8];
		for(i=0; i<8; ++i) {
			h[i] = tmp & 0xff;
			tmp >>= 8;
		}
		HMAC_Update( &mac_ctx, h, 8 );
	}
	HMAC_Final( &mac_ctx, md, &mdLen );
	HMAC_CTX_cleanup(&mac_ctx);

	// chop this down to a 64bit value..
	for(i=0; i < (mdLen - 1); ++i)
		h[i%8] ^= (unsigned char)(md[i]);

	value = (uint64_t)h[0];
	for(i=1; i<8; ++i)
		value = (value << 8) | (uint64_t)h[i];
	return value;
}

static uint64_t MAC_64(encfs_common_custom_salt *cur_salt,  const unsigned char *data, int len, unsigned char *key, uint64_t *chainedIV )
{
	uint64_t tmp = _checksum_64(cur_salt, key, data, len, chainedIV );
	if(chainedIV)
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

int encfs_common_streamDecode(encfs_common_custom_salt *cur_salt, unsigned char *buf, int size, uint64_t iv64, unsigned char *key)
{
	unsigned char ivec[ MAX_IVLENGTH ];
	int dstLen=0, tmpLen=0;
	EVP_CIPHER_CTX stream_dec;

	encfs_common_setIVec(cur_salt, ivec, iv64 + 1, key);
	EVP_CIPHER_CTX_init(&stream_dec);
	EVP_DecryptInit_ex( &stream_dec, cur_salt->streamCipher, NULL, NULL, NULL);
	EVP_CIPHER_CTX_set_key_length( &stream_dec, cur_salt->keySize );
	EVP_CIPHER_CTX_set_padding( &stream_dec, 0 );
	EVP_DecryptInit_ex( &stream_dec, NULL, NULL, key, NULL);

	EVP_DecryptInit_ex( &stream_dec, NULL, NULL, NULL, ivec);
	EVP_DecryptUpdate( &stream_dec, buf, &dstLen, buf, size );
	EVP_DecryptFinal_ex( &stream_dec, buf+dstLen, &tmpLen );
	unshuffleBytes( buf, size );
	flipBytes( buf, size );

	encfs_common_setIVec(cur_salt, ivec, iv64, key );
	EVP_DecryptInit_ex( &stream_dec, NULL, NULL, NULL, ivec);
	EVP_DecryptUpdate( &stream_dec, buf, &dstLen, buf, size );
	EVP_DecryptFinal_ex( &stream_dec, buf+dstLen, &tmpLen );
	EVP_CIPHER_CTX_cleanup(&stream_dec);

	unshuffleBytes( buf, size );
	dstLen += tmpLen;
	if(dstLen != size) {
	}

	return 1;
}

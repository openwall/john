/* EncFS cracker patch for JtR. Hacked together during July of 2012
 * by Dhiru Kholia <dhiru at openwall.com>
 *
 * This software is Copyright (c) 2011, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>
#include <string.h>

#include "arch.h"
#include "stdint.h"
#include "pbkdf2_hmac_sha1.h"
#include "options.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               1
#endif
#include "common.h"
#include "formats.h"
#include "params.h"
#include "misc.h"
#include "memdbg.h"

#define FORMAT_LABEL        "EncFS"
#define FORMAT_NAME         ""
#ifdef MMX_COEF
#define ALGORITHM_NAME      "PBKDF2-SHA1 AES/Blowfish " SHA1_N_STR MMX_TYPE
#else
#define ALGORITHM_NAME      "PBKDF2-SHA1 AES/Blowfish 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1001
#define BINARY_SIZE         0
#define PLAINTEXT_LENGTH	125
#define BINARY_ALIGN        MEM_ALIGN_NONE
#define SALT_SIZE           sizeof(struct custom_salt)
#define SALT_ALIGN          sizeof(int)
#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;

#define MAX_KEYLENGTH 32 // in bytes (256 bit)
#define MAX_IVLENGTH 20
#define KEY_CHECKSUM_BYTES 4

static struct custom_salt {
	unsigned int keySize;
	unsigned int iterations;
	unsigned int cipher;
	unsigned int saltLen;
	unsigned char salt[40];
	unsigned int dataLen;
	unsigned char data[128];
	unsigned int ivLength;
	const EVP_CIPHER *streamCipher;
	const EVP_CIPHER *blockCipher;
} *cur_salt;

static struct fmt_tests encfs_tests[] = {
	{"$encfs$192*181474*0*20*f1c413d9a20f7fdbc068c5a41524137a6e3fb231*44*9c0d4e2b990fac0fd78d62c3d2661272efa7d6c1744ee836a702a11525958f5f557b7a973aaad2fd14387b4f", "openwall"},
	{"$encfs$128*181317*0*20*e9a6d328b4c75293d07b093e8ec9846d04e22798*36*b9e83adb462ac8904695a60de2f3e6d57018ccac2227251d3f8fc6a8dd0cd7178ce7dc3f", "Jupiter"},
	{"$encfs$256*714949*0*20*472a967d35760775baca6aefd1278f026c0e520b*52*ac3b7ee4f774b4db17336058186ab78d209504f8a58a4272b5ebb25e868a50eaf73bcbc5e3ffd50846071c882feebf87b5a231b6", "Valient Gough"},
	{"$encfs$256*120918*0*20*e6eb9a85ee1c348bc2b507b07680f4f220caa763*52*9f75473ade3887bca7a7bb113fbc518ffffba631326a19c1e7823b4564ae5c0d1e4c7e4aec66d16924fa4c341cd52903cc75eec4", "Alo3San1t@nats"},
	{NULL}
};

static void setIVec( unsigned char *ivec, uint64_t seed,
        unsigned char *key)
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


static void unshuffleBytes(unsigned char *buf, int size)
{
	int i;
	for(i=size-1; i; --i)
		buf[i] ^= buf[i-1];
}

static int MIN_(int a, int b)
{
	return (a < b) ? a : b;
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

static uint64_t _checksum_64(unsigned char *key,
		const unsigned char *data, int dataLen, uint64_t *chainedIV)
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

static uint64_t MAC_64( const unsigned char *data, int len,
		unsigned char *key, uint64_t *chainedIV )
{
	uint64_t tmp = _checksum_64( key, data, len, chainedIV );
	if(chainedIV)
		*chainedIV = tmp;
	return tmp;
}

static unsigned int MAC_32( unsigned char *src, int len,
		unsigned char *key )
{
	uint64_t *chainedIV = NULL;
	uint64_t mac64 = MAC_64( src, len, key, chainedIV );
	unsigned int mac32 = ((mac64 >> 32) & 0xffffffff) ^ (mac64 & 0xffffffff);
	return mac32;
}

static int streamDecode(unsigned char *buf, int size,
		uint64_t iv64, unsigned char *key)
{
	unsigned char ivec[ MAX_IVLENGTH ];
	int dstLen=0, tmpLen=0;
	EVP_CIPHER_CTX stream_dec;

	setIVec( ivec, iv64 + 1, key);
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

	setIVec( ivec, iv64, key );
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

static void init(struct fmt_main *self)
{
	/* OpenSSL init, cleanup part is left to OS */
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

#if defined(_OPENMP) && OPENSSL_VERSION_NUMBER >= 0x10000000
	if (SSLeay() < 0x10000000) {
		fprintf(stderr, "Warning: compiled against OpenSSL 1.0+, "
		    "but running with an older version -\n"
		    "disabling OpenMP for SSH because of thread-safety issues "
		    "of older OpenSSL\n");
		self->params.min_keys_per_crypt =
		    self->params.max_keys_per_crypt = 1;
		self->params.flags &= ~FMT_OMP;
	}
	else {
		int omp_t = 1;
		omp_t = omp_get_max_threads();
		self->params.min_keys_per_crypt *= omp_t;
		omp_t *= OMP_SCALE;
		self->params.max_keys_per_crypt *= omp_t;
	}
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc_tiny(cracked_size, MEM_ALIGN_WORD);
}

static int ishex(char *q)
{
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q;
}

static int valid(char *ciphertext, struct fmt_main *self)
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

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
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

static void set_salt(void *salt)
{
	/* restore custom_salt back */
	cur_salt = (struct custom_salt *) salt;
}

static void encfs_set_key(char *key, int index)
{
	int len = strlen(key);
	if (len > PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, len);
	saved_key[index][len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;
	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		int i, j;
		unsigned char master[MAX_KEYS_PER_CRYPT][MAX_KEYLENGTH + MAX_IVLENGTH];
		unsigned char tmpBuf[sizeof(cur_salt->data)];
		unsigned int checksum = 0;
		unsigned int checksum2 = 0;
		unsigned char out[MAX_KEYS_PER_CRYPT][128];

#ifdef MMX_COEF
		int len[MAX_KEYS_PER_CRYPT];
		unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			len[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = out[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, len, cur_salt->salt, cur_salt->saltLen, cur_salt->iterations, pout, cur_salt->keySize + cur_salt->ivLength, 0);
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
			memcpy(master[i], out[i], cur_salt->keySize + cur_salt->ivLength);
#else
		pbkdf2_sha1((const unsigned char *)saved_key[index], strlen(saved_key[index]), cur_salt->salt, cur_salt->saltLen, cur_salt->iterations, out[0], cur_salt->keySize + cur_salt->ivLength, 0);
		memcpy(master[0], out[0], cur_salt->keySize + cur_salt->ivLength);
#endif
		for (j = 0; j < MAX_KEYS_PER_CRYPT; ++j) {
			// First N bytes are checksum bytes.
			for(i=0; i<KEY_CHECKSUM_BYTES; ++i)
				checksum = (checksum << 8) | (unsigned int)cur_salt->data[i];
			memcpy( tmpBuf, cur_salt->data+KEY_CHECKSUM_BYTES, cur_salt->keySize + cur_salt->ivLength );
			streamDecode(tmpBuf, cur_salt->keySize + cur_salt->ivLength ,checksum, master[j]);
			checksum2 = MAC_32( tmpBuf,  cur_salt->keySize + cur_salt->ivLength, master[j]);
			if(checksum2 == checksum) {
				any_cracked = cracked[index+j] = 1;
			}
		}
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
}

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->iterations;
}
#endif

struct fmt_main fmt_encfs = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		encfs_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		encfs_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

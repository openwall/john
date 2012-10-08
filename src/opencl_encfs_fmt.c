/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for Keychain format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted. */

#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>
#include "common-opencl.h"
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL		"encfs-opencl"
#define FORMAT_NAME		"EncFS PBKDF2 AES / Blowfish"
#define ALGORITHM_NAME		"OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define	KEYS_PER_CRYPT		1024*9
#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

#define BINARY_SIZE		16
#define PLAINTEXT_LENGTH	15
#define SALT_SIZE		sizeof(encfs_cpu_salt)

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

typedef struct {
	uint8_t length;
	uint8_t v[24];
} encfs_password;

typedef struct {
	uint32_t v[17];
} encfs_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[64];
	int iterations;
} encfs_salt;

static int *cracked;
static int any_cracked;
static size_t cracked_size;

static const int MAX_KEYLENGTH = 32; // in bytes (256 bit)
static const int MAX_IVLENGTH = 16;
static const int KEY_CHECKSUM_BYTES = 4;

typedef struct {
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
} encfs_cpu_salt;

encfs_cpu_salt *cur_salt;

static struct fmt_tests encfs_tests[] = {
	{"$encfs$192*181474*0*20*f1c413d9a20f7fdbc068c5a41524137a6e3fb231*44*9c0d4e2b990fac0fd78d62c3d2661272efa7d6c1744ee836a702a11525958f5f557b7a973aaad2fd14387b4f", "openwall"},
	{NULL}
};

static encfs_password *inbuffer;
static encfs_hash *outbuffer;
static encfs_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static size_t insize = sizeof(encfs_password) * KEYS_PER_CRYPT;
static size_t outsize = sizeof(encfs_hash) * KEYS_PER_CRYPT;
static size_t settingsize = sizeof(encfs_salt);

static void release_all(void)
{
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release Kernel");
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
	HANDLE_CLERROR(clReleaseCommandQueue(queue[ocl_gpu_id]), "Release Queue");
}

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
	for(i=0; i<(mdLen-1); ++i)
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
	cl_int cl_error;

	global_work_size = MAX_KEYS_PER_CRYPT;

	inbuffer =
	    (encfs_password *) malloc(sizeof(encfs_password) *
	    MAX_KEYS_PER_CRYPT);
	outbuffer =
	    (encfs_hash *) malloc(sizeof(encfs_hash) * MAX_KEYS_PER_CRYPT);

	/* Zeroize the lengths in case crypt_all() is called with some keys still
	 * not set.  This may happen during self-tests. */
	{
		int i;
		for (i = 0; i < MAX_KEYS_PER_CRYPT; i++)
			inbuffer[i].length = 0;
	}

	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc_tiny(cracked_size, MEM_ALIGN_WORD);

	//listOpenCLdevices();
	opencl_init("$JOHN/encfs_kernel.cl", ocl_gpu_id, platform_id);
	/// Alocate memory
	mem_in =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem in");
	mem_setting =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem setting");
	mem_out =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem out");

	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "encfs", &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating kernel");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
	opencl_find_best_workgroup(self);

	atexit(release_all);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$encfs$", 5);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static encfs_cpu_salt cs;
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
	cur_salt = (encfs_cpu_salt*)salt;
	memcpy((char*)currentsalt.salt, cur_salt->salt, cur_salt->saltLen);
	currentsalt.length = cur_salt->saltLen;
	currentsalt.iterations = cur_salt->iterations;
	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
}

#undef set_key
static void set_key(char *key, int index)
{
	uint8_t length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint8_t length = inbuffer[index].length;
	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static void crypt_all(int count)
{
	int index;
	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, NULL), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Copy setting to gpu");

	/// Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, &local_work_size, 0, NULL, profilingEvent),
	    "Run kernel");
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish");

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], mem_out, CL_FALSE, 0,
		outsize, outbuffer, 0, NULL, NULL), "Copy result back");

	/// Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish");

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#else
	for (index = 0; index < count; index++)
#endif
	{
		int i;
		unsigned char master[MAX_KEYLENGTH + MAX_IVLENGTH];
		unsigned char tmpBuf[cur_salt->dataLen];
		unsigned int checksum = 0;
		unsigned int checksum2 = 0;
		memcpy(master, outbuffer[index].v, cur_salt->keySize + cur_salt->ivLength);

		// First N bytes are checksum bytes.
		for(i=0; i<KEY_CHECKSUM_BYTES; ++i)
			checksum = (checksum << 8) | (unsigned int)cur_salt->data[i];
		memcpy( tmpBuf, cur_salt->data+KEY_CHECKSUM_BYTES, cur_salt->keySize + cur_salt->ivLength );
		streamDecode(tmpBuf, cur_salt->keySize + cur_salt->ivLength ,checksum, master);
		checksum2 = MAC_32( tmpBuf,  cur_salt->keySize + cur_salt->ivLength, master);
		if(checksum2 == checksum) {
			any_cracked = cracked[index] = 1;
		}
	}
}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_encfs = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		encfs_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		set_key,
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

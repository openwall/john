/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for GPG format.
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
#include <openssl/des.h>
#include "common-opencl.h"
#include <openssl/blowfish.h>
#include <openssl/aes.h>
#include <openssl/ripemd.h>
#include <openssl/cast.h>
#include <openssl/bn.h>
#include "sha2.h"
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL		"gpg-opencl"
#define FORMAT_NAME		"OpenPGP / GnuPG Secret Key"
#define ALGORITHM_NAME		"OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define	KEYS_PER_CRYPT		1024*9
#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define BINARY_SIZE		16
#define PLAINTEXT_LENGTH	15
#define SALT_SIZE		sizeof(struct custom_salt)

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

typedef struct {
        uint8_t length;
        uint8_t v[24];
} gpg_password;

typedef struct {
        uint8_t v[16];
} gpg_hash;

typedef struct {
        uint8_t length;
	int count;
        uint8_t salt[8];
} gpg_salt;

static int *cracked;


#define KEYBUFFER_LENGTH 8192
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

// Minimum number of bits when checking the first BN
#define MIN_BN_BITS 64

static int *cracked;

enum {
	SPEC_SIMPLE = 0,
	SPEC_SALTED = 1,
	SPEC_ITERATED_SALTED = 3
};


enum {
	PKA_UNKOWN = 0,
	PKA_RSA_ENCSIGN = 1,
	PKA_DSA = 17
};

enum {
	CIPHER_UNKOWN = -1,
	CIPHER_CAST5 = 3,
	CIPHER_BLOWFISH = 4,
	CIPHER_AES128 = 7,
	CIPHER_AES192 = 8,
	CIPHER_AES256 = 9
};

enum {
	HASH_UNKOWN = -1,
	HASH_MD5 = 1,
	HASH_SHA1 = 2,
	HASH_RIPEMD160 = 3,
	HASH_SHA256 = 8,
	HASH_SHA384 = 9,
	HASH_SHA512 = 10,
	HASH_SHA224 = 11
};

static struct custom_salt {
	int datalen;
	unsigned char data[4096];
	char spec;
	char pk_algorithm;
	char hash_algorithm;
	char cipher_algorithm;
	int usage;
	int bits;
	unsigned char salt[8];
	unsigned char iv[16];
	int ivlen;
	int count;
	void (*s2kfun)(char *, unsigned char*, int);
} *cur_salt;

static struct fmt_tests gpg_tests[] = {
	{"$gpg$*1*667*2048*387de4c9e2c1018aed84af75922ecaa92d1bc68d48042144c77dfe168de1fd654e4db77bfbc60ec68f283483382413cbfddddcfad714922b2d558f8729f705fbf973ab1839e756c26207a4bc8796eeb567bf9817f73a2a81728d3e4bc0894f62ad96e04e60752d84ebc01316703b0fd0f618f6120289373347027924606712610c583b25be57c8a130bc4dd796964f3f03188baa057d6b8b1fd36675af94d45847eeefe7fff63b755a32e8abe26b7f3f58bb091e5c7b9250afe2180b3d0abdd2c1db3d4fffe25e17d5b7d5b79367d98c523a6c280aafef5c1975a42fd97242ba86ced73c5e1a9bcab82adadd11ef2b64c3aad23bc930e62fc8def6b1d362e954795d87fa789e5bc2807bfdc69bba7e66065e3e3c2df0c25eab0fde39fbe54f32b26f07d88f8b05202e55874a1fa37d540a5af541e28370f27fe094ca8758cd7ff7b28df1cbc475713d7604b1af22fd758ebb3a83876ed83f003285bc8fdc7a5470f7c5a9e8a93929941692a9ff9f1bc146dcc02aab47e2679297d894f28b62da16c8baa95cd393d838fa63efc9d3f88de93dc970c67022d5dc88dce25decec8848f8e6f263d7c2c0238d36aa0013d7edefd43dac1299a54eb460d9b82cb53cf86fcb7c8d5dba95795a1adeb729a705b47b8317594ac3906424b2c0e425343eca019e53d927e6bc32688bd9e87ee808fb1d8eeee8ab938855131b839776c7da79a33a6d66e57eadb430ef04809009794e32a03a7e030b8792be5d53ceaf480ffd98633d1993c43f536a90bdbec8b9a827d0e0a49155450389beb53af5c214c4ec09712d83b175671358d8e9d54da7a8187f72aaaca5203372841af9b89a07b8aadecafc0f2901b8aec13a5382c6f94712d629333b301afdf52bdfa62534de2b10078cd4d0e781c88efdfe4e5252e39a236af449d4d62081cee630ab*3*254*2*3*8*b1fdf3772bb57e1f*65536*2127ccd55e721ba0", "polished"},
	{NULL}
};

static gpg_password *inbuffer;
static gpg_hash *outbuffer;
static gpg_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static size_t insize = sizeof(gpg_password) * KEYS_PER_CRYPT;
static size_t outsize = sizeof(gpg_hash) * KEYS_PER_CRYPT;
static size_t settingsize = sizeof(gpg_salt);

// Returns the block size (in bytes) of a given cipher
static uint32_t blockSize(char algorithm)
{
        switch (algorithm) {
                case CIPHER_CAST5:
                        return CAST_BLOCK;
                case CIPHER_BLOWFISH:
                        return BF_BLOCK;
                case CIPHER_AES128:
                case CIPHER_AES192:
                case CIPHER_AES256:
                        return AES_BLOCK_SIZE;
                default: break;
        }
        return 0;
}

// Returns the key size (in bytes) of a given cipher
static uint32_t keySize(char algorithm)
{
        switch (algorithm) {
                case CIPHER_CAST5:
                        return CAST_KEY_LENGTH;
                case CIPHER_BLOWFISH:
                        return 16;
                case CIPHER_AES128:
                        return 16;
                case CIPHER_AES192:
                        return 24;
                case CIPHER_AES256:
                        return 32;
                default: break;
        }
        return 0;
}

// Returns the digest size (in bytes) of a given hash algorithm
static uint32_t digestSize(char algorithm)
{
        switch (algorithm) {
                case HASH_MD5:
                        return 16;
                case HASH_SHA1:
                        return 20;
                case HASH_SHA512:
                        return 64;
                case HASH_SHA256:
                        return 32;
                case HASH_RIPEMD160:
                        return 20;
                default: break;
        }
        return 0;
}

static void release_all(void)
{
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release Kernel");
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
	HANDLE_CLERROR(clReleaseCommandQueue(queue[ocl_gpu_id]), "Release Queue");
}
static void init(struct fmt_main *self)
{
	cl_int cl_error;

	global_work_size = MAX_KEYS_PER_CRYPT;

	inbuffer =
	    (gpg_password *) malloc(sizeof(gpg_password) *
	    MAX_KEYS_PER_CRYPT);
	outbuffer =
	    (gpg_hash *) malloc(sizeof(gpg_hash) * MAX_KEYS_PER_CRYPT);

	/* Zeroize the lengths in case crypt_all() is called with some keys still
	 * not set.  This may happen during self-tests. */
	{
		int i;
		for (i = 0; i < MAX_KEYS_PER_CRYPT; i++)
			inbuffer[i].length = 0;
	}

	cracked = mem_calloc_tiny(sizeof(*cracked) *
			KEYS_PER_CRYPT, MEM_ALIGN_WORD);

	//listOpenCLdevices();
	opencl_init("$JOHN/gpg_kernel.cl", ocl_gpu_id, platform_id);
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

	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "gpg", &cl_error);
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
	return !strncmp(ciphertext, "$gpg$", 5);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
	ctcopy += 5;	/* skip over "$gpg$" marker */
	p = strtok(ctcopy, "*");
	cs.pk_algorithm = atoi(p);
	p = strtok(NULL, "*");
	cs.datalen = atoi(p);
	p = strtok(NULL, "*");
	cs.bits = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.datalen; i++)
		cs.data[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.spec = atoi(p);
	p = strtok(NULL, "*");
	cs.usage = atoi(p);
	p = strtok(NULL, "*");
	cs.hash_algorithm = atoi(p);
	p = strtok(NULL, "*");
	cs.cipher_algorithm = atoi(p);
	p = strtok(NULL, "*");
	cs.ivlen = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.ivlen; i++)
		cs.iv[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.count = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < 8; i++)
		cs.salt[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}


static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	memcpy((char*)currentsalt.salt, cur_salt->salt, 8);
	currentsalt.length = 8;;
	currentsalt.count = cur_salt->count;
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


static int check(unsigned char *keydata, int ks)
{
	// Decrypt first data block in order to check the first two bits of
	// the MPI. If they are correct, there's a good chance that the
	// password is correct, too.
	unsigned char ivec[32];
	unsigned char out[4096];
	int tmp = 0;
        uint32_t num_bits;
	int checksumOk;
	int i;

	// Quick Hack
	memcpy(ivec, cur_salt->iv, blockSize(cur_salt->cipher_algorithm));
	switch (cur_salt->cipher_algorithm) {
		case CIPHER_CAST5: {
					   CAST_KEY ck;
					   CAST_set_key(&ck, ks, keydata);
					   CAST_cfb64_encrypt(cur_salt->data, out, CAST_BLOCK, &ck, ivec, &tmp, CAST_DECRYPT);
				   }
				   break;
		case CIPHER_BLOWFISH: {
					      BF_KEY ck;
					      BF_set_key(&ck, ks, keydata);
					      BF_cfb64_encrypt(cur_salt->data, out, BF_BLOCK, &ck, ivec, &tmp, BF_DECRYPT);
				      }
				      break;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256: {
					    AES_KEY ck;
					    AES_set_encrypt_key(keydata, ks * 8, &ck);
					    AES_cfb128_encrypt(cur_salt->data, out, AES_BLOCK_SIZE, &ck, ivec, &tmp, AES_DECRYPT);
				    }
				    break;
		default:
				    break;
	}
	num_bits = ((out[0] << 8) | out[1]);
	if (num_bits < MIN_BN_BITS || num_bits > cur_salt->bits) {
		return 0;
	}
	// Decrypt all data
	memcpy(ivec, cur_salt->iv, blockSize(cur_salt->cipher_algorithm));
	tmp = 0;
	switch (cur_salt->cipher_algorithm) {
		case CIPHER_CAST5: {
					   CAST_KEY ck;
					   CAST_set_key(&ck, ks, keydata);
					   CAST_cfb64_encrypt(cur_salt->data, out, cur_salt->datalen, &ck, ivec, &tmp, CAST_DECRYPT);
				   }
				   break;
		case CIPHER_BLOWFISH: {
					      BF_KEY ck;
					      BF_set_key(&ck, ks, keydata);
					      BF_cfb64_encrypt(cur_salt->data, out, cur_salt->datalen, &ck, ivec, &tmp, BF_DECRYPT);
				      }
				      break;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256: {
					    AES_KEY ck;
					    AES_set_encrypt_key(keydata, ks * 8, &ck);
					    AES_cfb128_encrypt(cur_salt->data, out, cur_salt->datalen, &ck, ivec, &tmp, AES_DECRYPT);
				    }
				    break;
		default:
				    break;
	}

	// Verify
	checksumOk = 0;
	switch (cur_salt->usage) {
		case 254: {
				  uint8_t checksum[SHA_DIGEST_LENGTH];
				  SHA_CTX ctx;
				  SHA1_Init(&ctx);
				  SHA1_Update(&ctx, out, cur_salt->datalen - SHA_DIGEST_LENGTH);
				  SHA1_Final(checksum, &ctx);
				  if (memcmp(checksum, out + cur_salt->datalen - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH) == 0) {
					  checksumOk = 1;
				  }
			  } break;
		case 0:
		case 255: {
				  uint16_t sum = 0;
				  for (i = 0; i < cur_salt->datalen - 2; i++) {
					  sum += out[i];
				  }
				  if (sum == ((out[cur_salt->datalen - 2] << 8) | out[cur_salt->datalen - 1])) {
					  checksumOk = 1;
				  }
			  } break;
		default:
			  break;
	}
	// If the checksum is ok, try to parse the first MPI of the private key
	if (checksumOk) {
		BIGNUM *b = NULL;
		uint32_t blen = (num_bits + 7) / 8;
		if (blen < cur_salt->datalen && ((b = BN_bin2bn(out + 2, blen, NULL)) != NULL)) {
			BN_free(b);
			return 1;
		}
	}
	return 0;
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
		// allocate string2key buffer
		int res;
		int ks = keySize(cur_salt->cipher_algorithm);
		int ds = digestSize(cur_salt->hash_algorithm);
		unsigned char keydata[ds * ((ks + ds- 1) / ds)];
		memcpy(keydata, outbuffer[index].v, ks);
		res = check(keydata, ks);
		if(res)
			cracked[index] = 1;
		else
			cracked[index] = 0;
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

struct fmt_main fmt_opencl_gpg = {
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
		gpg_tests
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

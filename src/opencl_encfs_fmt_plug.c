/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for Keychain format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted. */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_encfs;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_encfs);
#else

#include <string.h>
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

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "options.h"
#include "misc.h"
#define OUTLEN (32 + 16)
#include "opencl_pbkdf2_hmac_sha1.h"

#define FORMAT_LABEL		"encfs-opencl"
#define FORMAT_NAME		"EncFS"
#define OCL_ALGORITHM_NAME	"PBKDF2-SHA1 OpenCL"
#define CPU_ALGORITHM_NAME	" AES/Blowfish"
#define ALGORITHM_NAME		OCL_ALGORITHM_NAME CPU_ALGORITHM_NAME
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define BINARY_SIZE		0
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(encfs_cpu_salt)
#define BINARY_ALIGN		MEM_ALIGN_WORD
#define SALT_ALIGN			MEM_ALIGN_WORD

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

#define MIN(a, b)		(((a) > (b)) ? (b) : (a))
#define MAX(a, b)		(((a) > (b)) ? (a) : (b))

/* This handles all widths */
#define GETPOS(i, index)	(((index) % v_width) * 4 + ((i) & ~3U) * v_width + (((i) & 3) ^ 3) + ((index) / v_width) * 64 * v_width)

static int *cracked;
static int any_cracked;

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

static encfs_cpu_salt *cur_salt;

static struct fmt_tests tests[] = {
	{"$encfs$192*181474*0*20*f1c413d9a20f7fdbc068c5a41524137a6e3fb231*44*9c0d4e2b990fac0fd78d62c3d2661272efa7d6c1744ee836a702a11525958f5f557b7a973aaad2fd14387b4f", "openwall"},
	{NULL}
};

static size_t key_buf_size;
static unsigned int *inbuffer;
static pbkdf2_out *output;
static pbkdf2_salt currentsalt;
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static unsigned int v_width = 1;	/* Vector width of kernel */
static size_t key_buf_size;
static int new_keys;

static cl_kernel pbkdf2_init, pbkdf2_loop, pbkdf2_final;

#define cracked_size (sizeof(*cracked) * global_work_size * v_width)

/*
 * HASH_LOOPS is ideally made by factors of (iteration count - 1) and should
 * be chosen for a kernel duration of not more than 200 ms
 */
#define HASH_LOOPS		(3 * 251)
#define ITERATIONS		181474 /* Just for auto tune */
#define LOOP_COUNT		(((currentsalt.iterations - 1 + HASH_LOOPS - 1)) / HASH_LOOPS)
#define OCL_CONFIG		"encfs"
#define STEP			0
#define SEED			128

static const char * warn[] = {
	"P xfer: "  ,  ", init: "   , ", loop: " , ", final: ", ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_init);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_loop));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_final));
	return s;
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
	if (cpu(device_info[gpu_id]))
		return get_platform_vendor_id(platform_id) == DEV_INTEL ?
			8 : 1;
	else
		return 64;
}

#if 0
struct fmt_main *me;
#endif

static void create_clobj(size_t gws, struct fmt_main *self)
{
	gws *= v_width;

	key_buf_size = 64 * gws;

	/// Allocate memory
	inbuffer = mem_calloc(key_buf_size);
	output = mem_alloc(sizeof(pbkdf2_out) * gws);
	cracked = mem_calloc(cracked_size);

	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem in");
	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(pbkdf2_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem setting");
	mem_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, sizeof(pbkdf2_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem out");

	mem_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(pbkdf2_state) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem_state");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_loop, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 1, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem setting");
	HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

	MEM_FREE(inbuffer);
	MEM_FREE(output);
	MEM_FREE(cracked);
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(pbkdf2_init), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(pbkdf2_loop), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(pbkdf2_final), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
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

static int crypt_all(int *pcount, struct db_salt *salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *salt);

static void init(struct fmt_main *self)
{
	char build_opts[64];
	static char valgo[sizeof(ALGORITHM_NAME) + 8] = "";

#if 0
	me = self;
#endif
	if ((v_width = opencl_get_vector_width(gpu_id,
	                                       sizeof(cl_int))) > 1) {
		/* Run vectorized kernel */
		snprintf(valgo, sizeof(valgo),
		         OCL_ALGORITHM_NAME " %ux" CPU_ALGORITHM_NAME, v_width);
		self->params.algorithm_name = valgo;
	}

	snprintf(build_opts, sizeof(build_opts),
	         "-DHASH_LOOPS=%u -DOUTLEN=%u "
	         "-DPLAINTEXT_LENGTH=%u -DV_WIDTH=%u",
	         HASH_LOOPS, OUTLEN, PLAINTEXT_LENGTH, v_width);
	opencl_init("$JOHN/kernels/pbkdf2_hmac_sha1_kernel.cl", gpu_id, build_opts);

	pbkdf2_init = clCreateKernel(program[gpu_id], "pbkdf2_init", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");
	crypt_kernel = pbkdf2_loop = clCreateKernel(program[gpu_id], "pbkdf2_loop", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");
	pbkdf2_final = clCreateKernel(program[gpu_id], "pbkdf2_final", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 2*HASH_LOOPS, split_events,
		warn, 2, self, create_clobj, release_clobj,
	        sizeof(pbkdf2_state), 0);

	//Auto tune execution from shared/included code.
	self->methods.crypt_all = crypt_all_benchmark;
	autotune_run(self, 2 * (ITERATIONS - 1) + 4, 0,
	             (cpu(device_info[gpu_id]) ? 1000000000 : 10000000000ULL));
	self->methods.crypt_all = crypt_all;

	self->params.min_keys_per_crypt = local_work_size * v_width;
	self->params.max_keys_per_crypt = global_work_size * v_width;
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
	currentsalt.outlen = cur_salt->keySize + cur_salt->ivLength;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0, sizeof(pbkdf2_salt), &currentsalt, 0, NULL, NULL), "Copy salt to gpu");
}

static void clear_keys(void) {
	memset(inbuffer, 0, key_buf_size);
}

static void set_key(char *key, int index)
{
	int i;
	int length = strlen(key);

	for (i = 0; i < length; i++)
		((char*)inbuffer)[GETPOS(i, index)] = key[i];

	new_keys = 1;
}

static char* get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	int i = 0;

	while (i < PLAINTEXT_LENGTH &&
	       (ret[i] = ((char*)inbuffer)[GETPOS(i, index)]))
		i++;
	ret[i] = 0;

	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int i, j, index;
	size_t scalar_gws;

	global_work_size = ((count + (v_width * local_work_size - 1)) / (v_width * local_work_size)) * local_work_size;
	scalar_gws = global_work_size * v_width;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	/// Copy data to gpu
	if (new_keys) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, NULL), "Copy data to gpu");
		new_keys = 0;
	}

	/// Run kernels
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_init, 1, NULL, &global_work_size, &local_work_size, 0, NULL, firstEvent), "Run initial kernel");

	for (j = 0; j < ((currentsalt.outlen + 19) / 20); j++) {
		for (i = 0; i < LOOP_COUNT; i++) {
			HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "Run loop kernel");
			HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			opencl_process_event();
		}

		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_final, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "Run intermediate kernel");
	}

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(pbkdf2_out) * scalar_gws, output, 0, NULL, NULL), "Copy result back");

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		int i;
		unsigned char master[MAX_KEYLENGTH + MAX_IVLENGTH];
		unsigned char tmpBuf[cur_salt->dataLen];
		unsigned int checksum = 0;
		unsigned int checksum2 = 0;
		memcpy(master, output[index].dk, cur_salt->keySize + cur_salt->ivLength);

		// First N bytes are checksum bytes.
		for(i=0; i<KEY_CHECKSUM_BYTES; ++i)
			checksum = (checksum << 8) | (unsigned int)cur_salt->data[i];
		memcpy( tmpBuf, cur_salt->data+KEY_CHECKSUM_BYTES, cur_salt->keySize + cur_salt->ivLength );
		streamDecode(tmpBuf, cur_salt->keySize + cur_salt->ivLength ,checksum, master);
		checksum2 = MAC_32( tmpBuf,  cur_salt->keySize + cur_salt->ivLength, master);
		if(checksum2 == checksum)
		{
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
		}
	}
	return count;
}

static int crypt_all_benchmark(int *pcount, struct db_salt *salt)
{
	size_t scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = local_work_size ? ((*pcount + (v_width * local_work_size - 1)) / (v_width * local_work_size)) * local_work_size : *pcount / v_width;
	scalar_gws = global_work_size * v_width;

#if 0
	fprintf(stderr, "%s(%d) lws %zu gws %zu sgws %zu kpc %d/%d\n", __FUNCTION__, *pcount, local_work_size, global_work_size, scalar_gws, me->params.min_keys_per_crypt, me->params.max_keys_per_crypt);
#endif

	/// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");

	/// Run kernels
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_init, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run initial kernel");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, lws, 0, NULL, NULL), "Run loop kernel");
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run loop kernel");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_final, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]), "Run intermediate kernel");

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(pbkdf2_out) * scalar_gws, output, 0, NULL, multi_profilingEvent[4]), "Copy result back");

	return *pcount;
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
	return 1;
}

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	encfs_cpu_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->iterations;
}
#endif

struct fmt_main fmt_opencl_encfs = {
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
		tests
	}, {
		init,
		done,
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
		set_key,
		get_key,
		clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */

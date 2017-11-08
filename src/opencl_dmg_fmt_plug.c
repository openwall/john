/*
 * This software is Copyright (c) 2017, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 *  Debug levels:
 *   1 show what "test" hits
 *   2 dump printables from the decrypted blocks
 *   3 dump hex from the decrypted blocks
 *   4 dump decrypted blocks to files (will overwrite with no mercy):
 *       dmg.debug.main   main block
 *       dmg.debug        alternate block (if present, this is the start block)
 */
//#define DMG_DEBUG		2

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_dmg;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_dmg);
#else

#include <stdint.h>
#include <string.h>
#include <openssl/des.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#ifdef DMG_DEBUG
#define NEED_OS_FLOCK
#include "os.h"
#endif
#include "arch.h"
#include "aes.h"
#include "hmac_sha.h"
#include "formats.h"
#include "common.h"
#include "options.h"
#include "jumbo.h"
#include "loader.h"
#include "dmg_common.h"
#include "common-opencl.h"
#define OUTLEN 32
#include "opencl_pbkdf2_hmac_sha1.h"

#define FORMAT_LABEL		"dmg-opencl"
#define FORMAT_NAME		"Apple DMG"
#define FORMAT_TAG           "$dmg$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME		"PBKDF2-SHA1 OpenCL 3DES/AES"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1001
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		sizeof(uint32_t)

#undef HTONL
#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
		((((unsigned long)(n) & 0xFF00)) << 8) | \
		((((unsigned long)(n) & 0xFF0000)) >> 8) | \
		((((unsigned long)(n) & 0xFF000000)) >> 24))

#ifdef DMG_DEBUG
	extern volatile int bench_running;
#endif

/* This handles all widths */
#define GETPOS(i, index)	(((index) % ocl_v_width) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 64 * ocl_v_width)

static int *cracked;
static int any_cracked;

static struct custom_salt {
	unsigned int saltlen;
	unsigned char salt[20];
	unsigned int ivlen;
	unsigned char iv[32];
	int headerver;
	unsigned char chunk[8192];
	uint32_t encrypted_keyblob_size;
	uint8_t encrypted_keyblob[128];
	unsigned int len_wrapped_aes_key;
	unsigned char wrapped_aes_key[296];
	unsigned int len_hmac_sha1_key;
	unsigned char wrapped_hmac_sha1_key[300];
	char scp; /* start chunk present */
	unsigned char zchunk[4096]; /* chunk #0 */
	int cno;
	int data_size;
	unsigned int iterations;
} *cur_salt;

static size_t key_buf_size;
static unsigned int *inbuffer;
static pbkdf2_out *output;
static pbkdf2_salt currentsalt;
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static int new_keys;
static struct fmt_main *self;

static cl_kernel pbkdf2_init, pbkdf2_loop, pbkdf2_final;

size_t insize, outsize, settingsize;

#define cracked_size (sizeof(*cracked) * global_work_size * ocl_v_width)

/*
 * HASH_LOOPS is ideally made by factors of (iteration count - 1) and should
 * be chosen for a kernel duration of not more than 200 ms
 */
#define HASH_LOOPS		(3 * 251)
#define LOOP_COUNT		(((currentsalt.iterations - 1 + HASH_LOOPS - 1)) / HASH_LOOPS)
#define STEP			0
#define SEED			128

static const char * warn[] = {
	"P xfer: "  ,  ", init: "   , ", loop: " , ", final: ", ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
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

static void create_clobj(size_t gws, struct fmt_main *self)
{
	gws *= ocl_v_width;

	key_buf_size = PLAINTEXT_LENGTH * gws;

	/// Allocate memory
	inbuffer = mem_calloc(1, key_buf_size);
	output = mem_alloc(sizeof(pbkdf2_out) * gws);
	cracked = mem_calloc(1, cracked_size);

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
	if (cracked) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(output);
		MEM_FREE(cracked);
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(pbkdf2_init), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_loop), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_final), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static void init(struct fmt_main *_self)
{
	static char valgo[sizeof(ALGORITHM_NAME) + 8] = "";

	self = _self;

	opencl_prepare_dev(gpu_id);
	/* VLIW5 does better with just 2x vectors due to GPR pressure */
	if (!options.v_width && amd_vliw5(device_info[gpu_id]))
		ocl_v_width = 2;
	else
		ocl_v_width = opencl_get_vector_width(gpu_id, sizeof(cl_int));

	if (ocl_v_width > 1) {
		/* Run vectorized kernel */
		snprintf(valgo, sizeof(valgo), ALGORITHM_NAME " %ux", ocl_v_width);
		self->params.algorithm_name = valgo;
	}
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		int iterations = 1000;
		char build_opts[64];

		if (db->real) {
			struct db_salt *s = db->real->salts;
			void *salt;

			while (s->next && s->cost[0] < db->max_cost[0])
				s = s->next;
			salt = s->salt;
			iterations = ((struct custom_salt*)salt)->iterations;
		}

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DOUTLEN=%u "
		         "-DPLAINTEXT_LENGTH=%u -DV_WIDTH=%u",
		         HASH_LOOPS, OUTLEN, PLAINTEXT_LENGTH, ocl_v_width);
		opencl_init("$JOHN/kernels/pbkdf2_hmac_sha1_kernel.cl", gpu_id, build_opts);

		pbkdf2_init = clCreateKernel(program[gpu_id], "pbkdf2_init", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		crypt_kernel = pbkdf2_loop = clCreateKernel(program[gpu_id], "pbkdf2_loop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		pbkdf2_final = clCreateKernel(program[gpu_id], "pbkdf2_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 2*HASH_LOOPS, split_events,
		                       warn, 2, self, create_clobj,
		                       release_clobj,
		                       ocl_v_width * sizeof(pbkdf2_state), 0, db);

		//Auto tune execution from shared/included code.
		autotune_run(self, 2 * (iterations - 1) + 4, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 200));
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr;
	char *p;
	int headerver;
	int res, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$dmg$" marker */
	if ((p = strtokm(ctcopy, "*")) == NULL)
		goto err;
	headerver = atoi(p);
	if (headerver == 2) {
		if ((p = strtokm(NULL, "*")) == NULL)	/* salt len */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > 20)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* ivlen */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (atoi(p) > 32)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* iv */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* encrypted_keyblob_size */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > 128)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* encrypted keyblob */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* chunk number */
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* data_size */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if ((p = strtokm(NULL, "*")) == NULL)	/* chunk */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		if (res > 8192)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* scp */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		/* FIXME: which values are allowed here? */
		if (res == 1) {
			if ((p = strtokm(NULL, "*")) == NULL)	/* zchunk */
				goto err;
			if (strlen(p) != 4096 * 2)
				goto err;
		}
	}
	else if (headerver == 1) {
		if ((p = strtokm(NULL, "*")) == NULL)	/* salt len */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > 20)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* len_wrapped_aes_key */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > 296)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* wrapped_aes_key  */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* len_hmac_sha1_key */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > 300)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* hmac_sha1_key */
			goto err;
		if (strlen(p) / 2 != res)
			goto err;
	}
	else
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

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "*");
	cs.headerver = atoi(p);
	if (cs.headerver == 2) {
		p = strtokm(NULL, "*");
		cs.saltlen = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.saltlen; i++)
			cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.ivlen = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.ivlen; i++)
			cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.encrypted_keyblob_size = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.encrypted_keyblob_size; i++)
			cs.encrypted_keyblob[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.cno = atoi(p);
		p = strtokm(NULL, "*");
		cs.data_size = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.data_size; i++)
			cs.chunk[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.scp = atoi(p);
		if (cs.scp == 1) {
			p = strtokm(NULL, "*");
			for (i = 0; i < 4096; i++)
				cs.zchunk[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
					+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}
		if ((p = strtokm(NULL, "*")))
			cs.iterations = atoi(p);
		else
			cs.iterations = 1000;
	}
	else {
		p = strtokm(NULL, "*");
		cs.saltlen = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.saltlen; i++)
			cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.len_wrapped_aes_key = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.len_wrapped_aes_key; i++)
			cs.wrapped_aes_key[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.len_hmac_sha1_key = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.len_hmac_sha1_key; i++)
			cs.wrapped_hmac_sha1_key[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		if ((p = strtokm(NULL, "*")))
			cs.iterations = atoi(p);
		else
			cs.iterations = 1000;
	}
	if (cs.iterations == 0)
		cs.iterations = 1000;
	MEM_FREE(keeptr);
	return (void*)&cs;
}


static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;
	memcpy((char*)currentsalt.salt, cur_salt->salt, 20);
	currentsalt.length = 20;
	currentsalt.outlen = 32;
	currentsalt.iterations = cur_salt->iterations;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0,
	                                    sizeof(pbkdf2_salt), &currentsalt, 0,
	                                    NULL, NULL), "Copy salt to gpu");
}

static void clear_keys(void) {
	memset(inbuffer, 0, key_buf_size);
}

#undef set_key
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

static int apple_des3_ede_unwrap_key1(const unsigned char *wrapped_key, const int wrapped_key_len, const unsigned char *decryptKey)
{
	DES_key_schedule ks1, ks2, ks3;
	unsigned char TEMP1[sizeof(cur_salt->wrapped_hmac_sha1_key)];
	unsigned char TEMP2[sizeof(cur_salt->wrapped_hmac_sha1_key)];
	unsigned char IV[8] = { 0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 };
	int outlen, i;

	DES_set_key((DES_cblock*)(decryptKey +  0), &ks1);
	DES_set_key((DES_cblock*)(decryptKey +  8), &ks2);
	DES_set_key((DES_cblock*)(decryptKey + 16), &ks3);
	DES_ede3_cbc_encrypt(wrapped_key, TEMP1, wrapped_key_len, &ks1, &ks2, &ks3,
	                     (DES_cblock*)IV, DES_DECRYPT);

	outlen = check_pkcs_pad(TEMP1, wrapped_key_len, 8);
	if (outlen < 0)
		return 0;

	for (i = 0; i < outlen; i++)
		TEMP2[i] = TEMP1[outlen - i - 1];

	outlen -= 8;
	DES_ede3_cbc_encrypt(TEMP2 + 8, TEMP1, outlen, &ks1, &ks2, &ks3,
	                     (DES_cblock*)TEMP2, DES_DECRYPT);

	outlen = check_pkcs_pad(TEMP1, outlen, 8);
	if (outlen < 0)
		return 0;

	return 1;
}

static int hash_plugin_check_hash(unsigned char *derived_key)
{
	unsigned char hmacsha1_key_[20];
	unsigned char aes_key_[32];
	int ret = 0;

	if (cur_salt->headerver == 1) {
		if (apple_des3_ede_unwrap_key1(cur_salt->wrapped_aes_key, cur_salt->len_wrapped_aes_key, derived_key) &&
		    apple_des3_ede_unwrap_key1(cur_salt->wrapped_hmac_sha1_key, cur_salt->len_hmac_sha1_key, derived_key)) {
			return 1;
		}
	}
	else {
		DES_key_schedule ks1, ks2, ks3;
		unsigned char TEMP1[sizeof(cur_salt->wrapped_hmac_sha1_key)];
		AES_KEY aes_decrypt_key;
		unsigned char outbuf[8192 + 1];
		unsigned char outbuf2[4096 + 1];
		unsigned char iv[20];
#ifdef DMG_DEBUG
		unsigned char *r;
#endif
		const char nulls[8] = { 0 };

		DES_set_key((DES_cblock*)(derived_key +  0), &ks1);
		DES_set_key((DES_cblock*)(derived_key +  8), &ks2);
		DES_set_key((DES_cblock*)(derived_key + 16), &ks3);
		memcpy(iv, cur_salt->iv, 8);
		DES_ede3_cbc_encrypt(cur_salt->encrypted_keyblob, TEMP1,
		                     cur_salt->encrypted_keyblob_size, &ks1, &ks2, &ks3,
		                     (DES_cblock*)iv, DES_DECRYPT);

		memcpy(aes_key_, TEMP1, 32);
		memcpy(hmacsha1_key_, TEMP1, 20);
		hmac_sha1(hmacsha1_key_, 20, (unsigned char*)&cur_salt->cno, 4, iv, 20);
		if (cur_salt->encrypted_keyblob_size == 48)
			AES_set_decrypt_key(aes_key_, 128, &aes_decrypt_key);
		else
			AES_set_decrypt_key(aes_key_, 128 * 2, &aes_decrypt_key);
		AES_cbc_encrypt(cur_salt->chunk, outbuf, cur_salt->data_size, &aes_decrypt_key, iv, AES_DECRYPT);

		/* 8 consecutive nulls */
		if (memmem(outbuf, cur_salt->data_size, (void*)nulls, 8)) {
#ifdef DMG_DEBUG
			if (!bench_running)
				fprintf(stderr, "NULLS found!\n\n");
#endif
			ret = 1;
		}

/* These tests seem to be obsoleted by the 8xNULL test */
#ifdef DMG_DEBUG
		/* </plist> is a pretty generic signature for Apple */
		if (memmem(outbuf, cur_salt->data_size, (void*)"</plist>", 8)) {
			if (!bench_running)
				fprintf(stderr, "</plist> found!\n\n");
			ret = 1;
		}

		/* Journalled HFS+ */
		if (memmem(outbuf, cur_salt->data_size, (void*)"jrnlhfs+", 8)) {
			if (!bench_running)
				fprintf(stderr, "jrnlhfs+ found!\n\n");
			ret = 1;
		}

		/* Handle compressed DMG files, CMIYC 2012 and self-made
		   samples. Is this test obsoleted by the </plist> one? */
		if ((r = memmem(outbuf, cur_salt->data_size, (void*)"koly", 4))) {
			unsigned int *u32Version = (unsigned int*)(r + 4);

			if (HTONL(*u32Version) == 4) {
				if (!bench_running)
					fprintf(stderr, "koly found!\n\n");
				ret = 1;
			}
		}

		/* Handle VileFault sample images */
		if (memmem(outbuf, cur_salt->data_size, (void*)"EFI PART", 8)) {
			if (!bench_running)
				fprintf(stderr, "EFI PART found!\n\n");
			ret = 1;
		}

		/* Apple is a good indication but it's short enough to
		   produce false positives */
		if (memmem(outbuf, cur_salt->data_size, (void*)"Apple", 5)) {
			if (!bench_running)
				fprintf(stderr, "Apple found!\n\n");
			ret = 1;
		}

#endif /* DMG_DEBUG */

		/* Second buffer test. If present, *this* is the very first block of the DMG */
		if (cur_salt->scp == 1) {
			int cno = 0;

			hmac_sha1(hmacsha1_key_, 20, (unsigned char*)&cno, 4, iv, 20);
			if (cur_salt->encrypted_keyblob_size == 48)
				AES_set_decrypt_key(aes_key_, 128, &aes_decrypt_key);
			else
				AES_set_decrypt_key(aes_key_, 128 * 2, &aes_decrypt_key);
			AES_cbc_encrypt(cur_salt->zchunk, outbuf2, 4096, &aes_decrypt_key, iv, AES_DECRYPT);

			/* 8 consecutive nulls */
			if (memmem(outbuf2, 4096, (void*)nulls, 8)) {
#ifdef DMG_DEBUG
				if (!bench_running)
					fprintf(stderr, "NULLS found in alternate block!\n\n");
#endif
				ret = 1;
			}
#ifdef DMG_DEBUG
			/* This test seem to be obsoleted by the 8xNULL test */
			if (memmem(outbuf2, 4096, (void*)"Press any key to reboot", 23)) {
				if (!bench_running)
					fprintf(stderr, "MS-DOS UDRW signature found in alternate block!\n\n");
				ret = 1;
			}
#endif /* DMG_DEBUG */
		}

#ifdef DMG_DEBUG
		/* Write block as hex, strings or raw to a file. */
		if (ret && !bench_running) {
#if DMG_DEBUG == 4
			int fd;

			if ((fd = open("dmg.debug.main", O_RDWR | O_CREAT | O_TRUNC, 0660)) == -1)
				perror("open()");
			else {
#if FCNTL_LOCKS
				struct flock lock = { 0 };

				lock.l_type = F_WRLCK;
				while (fcntl(fd, F_SETLKW, &lock)) {
					if (errno != EINTR)
						pexit("fcntl(F_WRLCK)");
				}
#elif OS_FLOCK
				while (flock(fd, LOCK_EX)) {
					if (errno != EINTR)
						pexit("flock(LOCK_EX)");
				}
#endif
				if ((write(fd, outbuf, cur_salt->data_size) == -1))
					perror("write()");
				if (cur_salt->scp == 1)
					if ((write(fd, outbuf2, 4096) == -1))
						perror("write()");
				if (close(fd))
					perror("close");
			}
#endif
#if DMG_DEBUG == 3
			dump_stuff(outbuf, cur_salt->data_size);
			if (cur_salt->scp == 1) {
				fprintf(stderr, "2nd block:\n");
				dump_stuff(outbuf2, 4096);
			}
#endif
#if DMG_DEBUG == 2
			dump_text(outbuf, cur_salt->data_size);
			if (cur_salt->scp == 1) {
				fprintf(stderr, "2nd block:\n");
				dump_text(outbuf2, 4096);
			}
#endif
		}
#endif /* DMG_DEBUG */
	}

	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i, j, index;
	size_t scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER_VW(count, local_work_size);
	scalar_gws = global_work_size * ocl_v_width;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	/// Copy data to gpu
	if (ocl_autotune_running || new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");
		new_keys = 0;
	}

	/// Run kernels
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_init, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run initial kernel");

	for (j = 0; j < (ocl_autotune_running ? 1 : (currentsalt.outlen + 19) / 20); j++) {
		for (i = 0; i < (ocl_autotune_running ? 1 : LOOP_COUNT); i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run loop kernel");
			BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			opencl_process_event();
		}

		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_final, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]), "Run intermediate kernel");
	}

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(pbkdf2_out) * scalar_gws, output, 0, NULL, multi_profilingEvent[4]), "Copy result back");

	if (ocl_autotune_running)
		return count;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	if (hash_plugin_check_hash((unsigned char*)output[index].dk) == 1)
	{
		cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
		any_cracked |= 1;
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
	return 1;
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->iterations;
}

struct fmt_main fmt_opencl_dmg = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#ifdef DMG_DEBUG
		FMT_NOT_EXACT |
#endif
		FMT_CASE | FMT_8_BIT | FMT_HUGE_INPUT | FMT_OMP,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		dmg_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
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

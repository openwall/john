/*
 *
 * This software is Copyright (c) 2012 Dhiru Kholia <dhiru at openwall.com>
 * with some code (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and improvements (c) 2014 by magnum and JimF.
 *
 * This is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_zip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_zip);
#else

#include <string.h>
#include <stdint.h>
#include <openssl/des.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "common-opencl.h"
#include "pkzip.h"
#include "dyna_salt.h"
#include "hmac_sha.h"
#include "options.h"
#define OPENCL_FORMAT 1
#include "pbkdf2_hmac_sha1.h"

#define FORMAT_LABEL		"zip-opencl"
#define FORMAT_NAME		"ZIP"
#define ALGORITHM_NAME		"PBKDF2-SHA1 OpenCL"
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
 #define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

#define BINARY_ALIGN		sizeof(uint32_t)
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(my_salt*)
#define SALT_ALIGN		sizeof(size_t)

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} zip_password;

typedef struct {
	uint32_t v[(2 * KEY_LENGTH(3) + PWD_VER_LENGTH + 3) / 4];
} zip_hash;

typedef struct {
	uint32_t iterations;
	uint32_t outlen;
	uint32_t skip_bytes;
	uint8_t  length;
	uint8_t  salt[64];
} zip_salt;

typedef struct my_salt_t {
	dyna_salt dsalt;
	uint32_t comp_len;
	struct {
		uint16_t type     : 4;
		uint16_t mode : 4;
	} v;
	unsigned char passverify[2];
	unsigned char salt[SALT_LENGTH(3)];
	//uint64_t data_key; // MSB of md5(data blob).  We lookup using this.
	unsigned char datablob[1];
} my_salt;

static my_salt *saved_salt;

static unsigned char (*crypt_key)[((WINZIP_BINARY_SIZE + 4)/4)*4]; // ensure 32-bit alignment

static cl_int cl_error;
static zip_password *inbuffer;
static zip_hash *outbuffer;
static zip_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static struct fmt_main *self;

static size_t insize, outsize, settingsize;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
#include "memdbg.h"

static const char * warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	insize = sizeof(zip_password) * gws;
	outsize = sizeof(zip_hash) * gws;
	settingsize = sizeof(zip_salt);

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);
	crypt_key = mem_calloc(gws, sizeof(*crypt_key));

	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_setting =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
}

static void release_clobj(void)
{
	if (crypt_key) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(crypt_key);
		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DKEYLEN=%d -DSALTLEN=%d -DOUTLEN=%d",
		         PLAINTEXT_LENGTH,
		         (int)sizeof(currentsalt.salt),
		         (int)sizeof(outbuffer->v));
		opencl_init("$JOHN/kernels/pbkdf2_hmac_sha1_unsplit_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "derive_key", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1,
		                       self, create_clobj, release_clobj,
		                       sizeof(zip_password), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 1000);
	}
}

static void *get_salt(char *ciphertext)
{
	int i;
	my_salt salt, *psalt;
	static unsigned char *ptr;
	/* extract data from "ciphertext" */
	c8 *copy_mem = strdup(ciphertext);
	c8 *cp, *p;

	if (!ptr) ptr = mem_alloc_tiny(sizeof(my_salt*),sizeof(my_salt*));
	p = copy_mem + WINZIP_TAG_LENGTH+1; /* skip over "$zip2$*" */
	memset(&salt, 0, sizeof(salt));
	cp = strtokm(p, "*"); // type
	salt.v.type = atoi((const char*)cp);
	cp = strtokm(NULL, "*"); // mode
	salt.v.mode = atoi((const char*)cp);
	cp = strtokm(NULL, "*"); // file_magic enum (ignored)
	cp = strtokm(NULL, "*"); // salt
	for (i = 0; i < SALT_LENGTH(salt.v.mode); i++)
		salt.salt[i] = (atoi16[ARCH_INDEX(cp[i<<1])]<<4) | atoi16[ARCH_INDEX(cp[(i<<1)+1])];
	cp = strtokm(NULL, "*");	// validator
	salt.passverify[0] = (atoi16[ARCH_INDEX(cp[0])]<<4) | atoi16[ARCH_INDEX(cp[1])];
	salt.passverify[1] = (atoi16[ARCH_INDEX(cp[2])]<<4) | atoi16[ARCH_INDEX(cp[3])];
	cp = strtokm(NULL, "*");	// data len
	sscanf((const char *)cp, "%x", &salt.comp_len);

	// later we will store the data blob in our own static data structure, and place the 64 bit LSB of the
	// MD5 of the data blob into a field in the salt. For the first POC I store the entire blob and just
	// make sure all my test data is small enough to fit.

	cp = strtokm(NULL, "*");	// data blob

	// Ok, now create the allocated salt record we are going to return back to John, using the dynamic
	// sized data buffer.
	psalt = (my_salt*)mem_calloc(1, sizeof(my_salt) + salt.comp_len);
	psalt->v.type = salt.v.type;
	psalt->v.mode = salt.v.mode;
	psalt->comp_len = salt.comp_len;
	psalt->dsalt.salt_alloc_needs_free = 1;  // we used mem_calloc, so JtR CAN free our pointer when done with them.
	memcpy(psalt->salt, salt.salt, sizeof(salt.salt));
	psalt->passverify[0] = salt.passverify[0];
	psalt->passverify[1] = salt.passverify[1];

	// set the JtR core linkage stuff for this dyna_salt
	psalt->dsalt.salt_cmp_offset = SALT_CMP_OFF(my_salt, comp_len);
	psalt->dsalt.salt_cmp_size = SALT_CMP_SIZE(my_salt, comp_len, datablob, psalt->comp_len);


	if (strcmp((const char*)cp, "ZFILE")) {
	for (i = 0; i < psalt->comp_len; i++)
		psalt->datablob[i] = (atoi16[ARCH_INDEX(cp[i<<1])]<<4) | atoi16[ARCH_INDEX(cp[(i<<1)+1])];
	} else {
		c8 *Fn, *Oh, *Ob;
		long len;
		uint32_t id;
		FILE *fp;

		Fn = strtokm(NULL, "*");
		Oh = strtokm(NULL, "*");
		Ob = strtokm(NULL, "*");

		fp = fopen((const char*)Fn, "rb");
		if (!fp) {
			psalt->v.type = 1; // this will tell the format to 'skip' this salt, it is garbage
			goto Bail;
		}
		sscanf((const char*)Oh, "%lx", &len);
		if (fseek(fp, len, SEEK_SET)) {
			fclose(fp);
			psalt->v.type = 1;
			goto Bail;
		}
		id = fget32LE(fp);
		if (id != 0x04034b50U) {
			fclose(fp);
			psalt->v.type = 1;
			goto Bail;
		}
		sscanf((const char*)Ob, "%lx", &len);
		if (fseek(fp, len, SEEK_SET)) {
			fclose(fp);
			psalt->v.type = 1;
			goto Bail;
		}
		if (fread(psalt->datablob, 1, psalt->comp_len, fp) != psalt->comp_len) {
			fclose(fp);
			psalt->v.type = 1;
			goto Bail;
		}
		fclose(fp);
	}
Bail:;
	MEM_FREE(copy_mem);

	memcpy(ptr, &psalt, sizeof(my_salt*));
	return (void*)ptr;
}

static void set_salt(void *salt)
{
	saved_salt = *((my_salt**)salt);

	memcpy((char*)currentsalt.salt, saved_salt->salt, SALT_LENGTH(saved_salt->v.mode));
	currentsalt.length = SALT_LENGTH(saved_salt->v.mode);
	currentsalt.iterations = KEYING_ITERATIONS;
	currentsalt.outlen = PWD_VER_LENGTH;
	currentsalt.skip_bytes = 2 * KEY_LENGTH(saved_salt->v.mode);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
	               CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	               "Copy setting to gpu");
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	if (saved_salt->v.type) {
		// This salt passed valid() but failed get_salt().
		// Should never happen.
		memset(crypt_key, 0, count * WINZIP_BINARY_SIZE);
		return count;
	}

	/// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
		"Copy data to gpu");

	/// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[1]),
		"Run kernel");

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]),
		"Copy result back");

	if (ocl_autotune_running)
		return count;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		if (!memcmp((unsigned char*)outbuffer[index].v,
		            saved_salt->passverify, 2)) {
			unsigned char pwd_ver[4+64];

			pbkdf2_sha1(inbuffer[index].v,
			            inbuffer[index].length, saved_salt->salt,
			            SALT_LENGTH(saved_salt->v.mode), KEYING_ITERATIONS,
			            pwd_ver, KEY_LENGTH(saved_salt->v.mode),
			            KEY_LENGTH(saved_salt->v.mode));
			hmac_sha1(pwd_ver,
			          KEY_LENGTH(saved_salt->v.mode),
			          (const unsigned char*)saved_salt->datablob,
			          saved_salt->comp_len,
			          crypt_key[index], WINZIP_BINARY_SIZE);
		}
		else
			memset(crypt_key[index], 0, WINZIP_BINARY_SIZE);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (((uint32_t*)&(crypt_key[i]))[0] == ((uint32_t*)binary)[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (((uint32_t*)&(crypt_key[index]))[0] == ((uint32_t*)binary)[0]);
}

static int cmp_exact(char *source, int index)
{
	void *b = winzip_common_binary(source);
	return !memcmp(b, crypt_key[index], sizeof(crypt_key[index]));
}

struct fmt_main fmt_opencl_zip = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		WINZIP_BENCHMARK_COMMENT,
		WINZIP_BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		WINZIP_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{ NULL },
		{ WINZIP_FORMAT_TAG },
		winzip_common_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		winzip_common_valid,
		winzip_common_split,
		winzip_common_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
		NULL,
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

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */

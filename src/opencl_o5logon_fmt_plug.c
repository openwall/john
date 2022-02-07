/*
 * Cracker for Oracle's O5LOGON protocol hashes. Hacked together during
 * September of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * O5LOGON is used since version 11g. CVE-2012-3137 applies to Oracle 11.1
 * and 11.2 databases. Oracle has "fixed" the problem in version 11.2.0.3.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

/*
 * Modifications (c) 2014 Harrison Neal.
 *
 * SHA-1 hashes are now computed with OpenCL.
 * Modifications are based on opencl_rawsha1_fmt.c and sha1_kernel.cl
 * and thus are licensed under the GPLv2.
 * Original files are (c) 2011 Samuele Giovanni Tonon and (c) 2012 magnum.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_o5logon;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_o5logon);
#else

#include <string.h>

#include "arch.h"
#include "sha.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "opencl_common.h"

#define FORMAT_LABEL            "o5logon-opencl"
#define FORMAT_NAME             "Oracle O5LOGON protocol"
#define FORMAT_TAG              "$o5logon$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "SHA1 AES OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        32
#define CIPHERTEXT_LENGTH       48
#define SALT_LENGTH             10
#define BINARY_SIZE             0
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              MEM_ALIGN_WORD

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

static struct fmt_tests o5logon_tests[] = {
	{"$o5logon$566499330E8896301A1D2711EFB59E756D41AF7A550488D82FE7C8A418E5BE08B4052C0DC404A805C1D7D43FE3350873*4F739806EBC1D7742BC6", "password"},
	{"$o5logon$3BB71A77E1DBB5FFCCC8FC8C4537F16584CB5113E4CCE3BAFF7B66D527E32D29DF5A69FA747C4E2C18C1837F750E5BA6*4F739806EBC1D7742BC6", "password"},
	{"$o5logon$ED91B97A04000F326F17430A65DACB30CD1EF788E6EC310742B811E32112C0C9CC39554C9C01A090CB95E95C94140C28*7FD52BC80AA5836695D4", "test1"},
	{"$o5logon$B7711CC7E805520CEAE8C1AC459F745639E6C9338F192F92204A9518B226ED39851C154CB384E4A58C444A6DF26146E4*3D14D54520BC9E6511F4", "openwall"},
	{"$o5logon$76F9BBAEEA9CF70F2A660A909F85F374F16F0A4B1BE1126A062AE9F0D3268821EF361BF08EBEF392F782F2D6D0192FD6*3D14D54520BC9E6511F4", "openwall"},
	{NULL}
};

static struct custom_salt {
	// Change the below to round up to the nearest uint boundary
	unsigned char salt[((SALT_LENGTH + 3)/4)*4]; /* AUTH_VFR_DATA */
	unsigned char ct[CIPHERTEXT_LENGTH]; /* AUTH_SESSKEY */
} cur_salt;

// Shared auto-tune stuff
#define STEP                    0
#define SEED                    65536
#define ROUNDS                  1

static const char * warn[] = {
	"pass xfer: ",  ", index xfer: ",  ", crypt: ",  ", result xfer: "
};

// Maximum UINT32s used by plaintext being SHA1'd
#define BUFSIZE                         ((PLAINTEXT_LENGTH+3)/4*4)

static cl_mem pinned_saved_keys, pinned_saved_idx, pinned_result, buffer_out;
static cl_mem buffer_keys, buffer_idx;
static cl_mem salt_buffer;
static cl_uint *result;
static int new_keys;
static unsigned int *saved_plain, *saved_idx;
static unsigned int key_idx;
static struct fmt_main *self;

#include "opencl_autotune.h" // Must come after auto-tune definitions

static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	pinned_saved_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, BUFSIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_plain = clEnqueueMapBuffer(queue[gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BUFSIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

	pinned_saved_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, 4 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx");
	saved_idx = clEnqueueMapBuffer(queue[gpu_id], pinned_saved_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 4 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx");

	pinned_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	result = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_result, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory result");

	buffer_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, BUFSIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer keys argument");
	buffer_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 4 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_idx");

	// Modification to add salt buffer
	salt_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(cur_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument salt");

	buffer_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, sizeof(cl_uint) * 5 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer out argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys), (void *) &buffer_keys), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(salt_buffer), (void *) &salt_buffer), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_idx), (void *) &buffer_idx), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(buffer_out), (void *) &buffer_out), "Error setting argument 3");
}

static void release_clobj(void)
{
	if (pinned_result) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_result, result, 0,NULL,NULL), "Error Unmapping result");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL), "Error Unmapping saved_plain");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Error Releasing buffer_keys");
		HANDLE_CLERROR(clReleaseMemObject(buffer_idx), "Error Releasing buffer_idx");
		HANDLE_CLERROR(clReleaseMemObject(buffer_out), "Error Releasing buffer_out");
		HANDLE_CLERROR(clReleaseMemObject(salt_buffer), "Error Releasing salt_buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_idx), "Error Releasing pinned_saved_idx");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys), "Error Releasing pinned_saved_keys");
		HANDLE_CLERROR(clReleaseMemObject(pinned_result), "Error Releasing pinned_result");

		pinned_result = NULL;
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;

	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		opencl_init("$JOHN/opencl/o5logon_kernel.cl", gpu_id, NULL);

		// create kernel to execute
		crypt_kernel = clCreateKernel(program[gpu_id], "o5logon_kernel", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	}

	// Current key_idx can only hold 26 bits of offset so
	// we can't reliably use a GWS higher than 4M or so.
	size_t gws_limit = MIN((1 << 26) * 4 / BUFSIZE,
	                       get_max_mem_alloc_size(gpu_id) / BUFSIZE);

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 2,
	                       self, create_clobj, release_clobj,
	                       2 * BUFSIZE, gws_limit, db);

	//Auto tune execution from shared/included code.
	autotune_run(self, ROUNDS, gws_limit, 200);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int extra;
	if (strncmp(ciphertext,  FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL) /* ciphertext */
		goto err;
	if (hexlenu(p, &extra) != CIPHERTEXT_LENGTH * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenu(p, &extra) != SALT_LENGTH * 2 || extra)
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$o5logon$" */
	p = strtokm(ctcopy, "*");
	for (i = 0; i < CIPHERTEXT_LENGTH; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < SALT_LENGTH; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	cs.salt[SALT_LENGTH] = 0x80;
	memset(&cs.salt[SALT_LENGTH+1], 0, sizeof(cs.salt)-(SALT_LENGTH+1));

	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	memcpy(&cur_salt, salt, sizeof(cur_salt));

	HANDLE_CLERROR(
		clEnqueueWriteBuffer(queue[gpu_id], salt_buffer, CL_FALSE, 0,
		                     sizeof(cur_salt), &cur_salt, 0, NULL, NULL),
		"Error updating contents of salt_buffer");

	HANDLE_CLERROR(
		clFlush(queue[gpu_id]),
		"Failed in clFlush");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	gws = GET_NEXT_MULTIPLE(count, local_work_size);

	if (new_keys && key_idx) {
		BENCH_CLERROR(
			clEnqueueWriteBuffer(queue[gpu_id], buffer_keys, CL_FALSE, 0, 4 * key_idx, saved_plain, 0, NULL, multi_profilingEvent[0]),
			"failed in clEnqueueWriteBuffer buffer_keys");

		BENCH_CLERROR(
			clEnqueueWriteBuffer(queue[gpu_id], buffer_idx, CL_FALSE, 0, 4 * gws, saved_idx, 0, NULL, multi_profilingEvent[1]),
			"failed in clEnqueueWriteBuffer buffer_idx");

		new_keys = 0;
	}

	BENCH_CLERROR(
		clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]),
		"failed in clEnqueueNDRangeKernel");

	BENCH_CLERROR(
		clEnqueueReadBuffer(queue[gpu_id], buffer_out, CL_TRUE, 0, sizeof(cl_uint) * gws, result, 0, NULL, multi_profilingEvent[3]),
		"failed in reading data back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (result[i])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return result[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void clear_keys(void)
{
	key_idx = 0;
}

static void set_key(char *_key, int index)
{
	const uint32_t *key = (uint32_t*)_key;
	int len = strlen(_key);

	saved_idx[index] = (key_idx << 6) | len;

	while (len > 4) {
		saved_plain[key_idx++] = *key++;
		len -= 4;
	}
	if (len)
		saved_plain[key_idx++] = *key & (0xffffffffU >> (32 - (len << 3)));

	new_keys = 1;
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = saved_idx[index] & 63;
	char *key = (char*)&saved_plain[saved_idx[index] >> 6];

	for (i = 0; i < len; i++)
		out[i] = key[i];
	out[i] = 0;
	return out;
}

struct fmt_main fmt_opencl_o5logon = {
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
		FMT_CASE | FMT_8_BIT, // Changed for OpenCL
		{ NULL },
		{ FORMAT_TAG },
		o5logon_tests
	}, {
		init,
		done, // Changed for OpenCL
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key, // Changed for OpenCL
		get_key,
		clear_keys, // Changed for OpenCL
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

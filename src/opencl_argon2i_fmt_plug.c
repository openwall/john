/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_argon2i;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_argon2i);
#else

#define CPU
#include <string.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "options.h"
#include "formats.h"
#include "common-opencl.h"
#include "opencl_argon2i.h"

#define FORMAT_LABEL            "argon2i-opencl"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "Blake2 OpenCL"

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0

#define PLAINTEXT_LENGTH	125
#define CIPHERTEXT_LENGTH	BINARY_SIZE*2

#define BINARY_SIZE             256
#define BINARY_ALIGN            1
#define SALT_SIZE		64
#define SALT_ALIGN              1

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define SEED 256


//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char *warn[] = {
	"xfer salt1: ", ", xfer salt2: ", ", xfer keys: ", ", xfer lengths: ",
	", crypt: ", ", xfer: "
};

static struct fmt_tests tests[] = {
	{"$argon2i$3$1536$1$damage_done$777B47BEDC8BDA4BB7A2F575ABACFB37F5AD0744A0216AA136D533468C096E86","cathode_ray_sunshine"},
	{"$argon2i$3$1536$1$damage_done$777B47BEDC8BDA4BB7A2F575ABACFB37F5AD0744A0216AA136D533468C096E86","cathode_ray_sunshine"},
	{"$argon2i$3$1536$5$damage_done$711822A7722B4699CB6716773FB59933B133FC78057E76A5CB0D53C0EA8D4DFA","monochromatic_stains"},
	{"$argon2i$3$1536$5$damage_done$711822A7722B4699CB6716773FB59933B133FC78057E76A5CB0D53C0EA8D4DFA","monochromatic_stains"},
	{"$argon2i$3$100$1$dark_tranquillity$978CBFF98323A594C16BF9BCBFDE2A51920947D8858538180B34833B09717D7F", "out_of_nothing"},
	{"$argon2i$3$100$1$dark_tranquillity$978CBFF98323A594C16BF9BCBFDE2A51920947D8858538180B34833B09717D7F", "out_of_nothing"},
	{"$argon2i$10$10$1$dark_tranquillity$FAD39774076A7A8B8FC8A9B4D98D424074978418EB3AB8413244952C03725D3D", "mind_matters"},
	{"$argon2i$5$50$1$salt_salt$54B4E568","i_am_the_void"},
	{NULL}
};

struct argon2i_salt {
	uint32_t t_cost,m_cost;
	uint8_t lanes;
	uint32_t hash_size;
	uint32_t salt_length;
	char salt[SALT_SIZE];
};

static char *saved_key;
static unsigned int *saved_lengths;
static cl_mem cl_saved_key, cl_saved_lengths, cl_result, cl_saved_salt, cl_memory;
static cl_mem pinned_key, pinned_lengths, pinned_result, pinned_salt;
static char *output;
static uint64_t MEM_SIZE;
static struct argon2i_salt *saved_salt;
static char *saved_key;
static int clobj_allocated;
static uint saved_gws;

static struct fmt_main *self;

static void *get_salt(char *ciphertext);

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	if (clobj_allocated)
		release_clobj();
	clobj_allocated = 1;

	saved_gws=gws;

	pinned_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_key = clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, PLAINTEXT_LENGTH * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	pinned_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(struct argon2i_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(struct argon2i_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_salt = clEnqueueMapBuffer(queue[gpu_id], pinned_salt, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(struct argon2i_salt), 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_salt");

	pinned_lengths = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_lengths = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(cl_uint) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_lengths = clEnqueueMapBuffer(queue[gpu_id], pinned_lengths, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_lengths");

	pinned_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, BINARY_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, BINARY_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	output = clEnqueueMapBuffer(queue[gpu_id], pinned_result, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BINARY_SIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping output");

	cl_memory = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, MEM_SIZE * gws, NULL, &ret_code);

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
		(void *)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
		(void *)&cl_saved_lengths), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
		(void *)&cl_result), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem),
		(void *)&cl_saved_salt), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(cl_mem),
		(void *)&cl_memory), "Error setting argument 4");
}

static void release_clobj(void)
{
	if (!clobj_allocated)
		return;
	clobj_allocated = 0;

	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_result, output, 0, NULL, NULL), "Error Unmapping output");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_salt, saved_salt, 0, NULL, NULL), "Error Unmapping saved_salt");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_lengths, saved_lengths, 0, NULL, NULL), "Error Unmapping saved_lengths");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(pinned_result), "Release pinned result buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_key), "Release pinned key buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_salt), "Release pinned key buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_lengths), "Release pinned index buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_result), "Release result buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_salt), "Release key buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_lengths), "Release index buffer");

	HANDLE_CLERROR(clReleaseMemObject(cl_memory), "Release memory buffer");
}


static void done(void)
{
	if(autotuned)
	{
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
	}
}


static void reset_(uint64_t mem_size)
{
	char build_opts[128];
	MEM_SIZE=mem_size;

	sprintf(build_opts,
	    "-DBINARY_SIZE=%d -DSALT_SIZE=%d -DPLAINTEXT_LENGTH=%d", BINARY_SIZE, SALT_SIZE, PLAINTEXT_LENGTH);

	opencl_init("$JOHN/kernels/argon2i_kernel.cl", gpu_id, build_opts);


	// create kernel to execute
	crypt_kernel =
	    clCreateKernel(program[gpu_id], "argon2i_crypt_kernel", &ret_code);
	HANDLE_CLERROR(ret_code,
	    "Error creating kernel. Double-check kernel name?");

	release_clobj();

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL,
	    warn, 4, self, create_clobj, release_clobj, MEM_SIZE, 0);

	//Auto tune execution from shared/included code.
	autotune_run(self, 1, 0, 1000);
}

static void print_memory(double memory)
{
	char s[]="\0kMGT";
	int i=0;
	while(memory>=1024)
	{
		memory/=1024;
		i++;
	}
	printf("memory per hash : %.2lf %cB\n",memory,s[i]);
}

static void reset(struct db_main *db)
{
	if(!autotuned)
	{
		int i;
		uint32_t m_cost, prev_m_cost;
		m_cost=prev_m_cost=0;
		if (!db) {
			for (i = 0; tests[i].ciphertext; i++)
			{
				struct argon2i_salt *salt;
				salt=get_salt(tests[i].ciphertext);
				m_cost = MAX(m_cost, salt->m_cost);
				if(i==0)
				{
					printf("\n");
					prev_m_cost=m_cost;
					print_memory(m_cost<<10);
				}
			}

			if(prev_m_cost!=m_cost)
			{
				printf("max ");
				print_memory(m_cost<<10);
			}
			reset_(m_cost<<10);
		} else {
			struct db_salt *salts = db->salts;
			while (salts != NULL) {
				struct argon2i_salt * salt=salts->salt;
				m_cost = MAX(m_cost, salt->m_cost);
				salts = salts->next;
			}

			printf("\n");
			print_memory(m_cost<<10);
			reset_(m_cost<<10);
		}
	}
}

static void init(struct fmt_main *_self)
{
	clobj_allocated = 0;
	self = _self;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	struct argon2i_salt *salt;
	char *next_dollar;
	char *i;

	if (strncmp(ciphertext, "$argon2i$", 9) &&
	    strncmp(ciphertext, "$argon2i$", 9))
		return 0;
	i = ciphertext + 9;
	//t_cost
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//m_cost
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//lanes
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	if(atoi(i)>255)
		return 0;
	i = next_dollar + 1;
	//salt
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > SALT_SIZE || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	if (strlen(i) > CIPHERTEXT_LENGTH || strlen(i) == 0)
		return 0;
	while (atoi16[ARCH_INDEX(*i)] != 0x7F)	//
		i++;
	if (*i)
		return 0;

	salt=get_salt(ciphertext);

	//minumum m_cost =8L blocks, where L is the number of lanes
	if (salt->m_cost < 2 * SYNC_POINTS*salt->lanes)
		return 0;
	if (salt->m_cost>MAX_MEMORY)
		return 0;

	salt->m_cost = (salt->m_cost / (salt->lanes*SYNC_POINTS))*(salt->lanes*SYNC_POINTS); //Ensure that all segments have equal length;

	//minimum t_cost =3
	if (salt->t_cost<MIN_TIME)
		return 0;

	if (salt->lanes<MIN_LANES)
		return 0;
	if (salt->lanes>salt->m_cost / BLOCK_SIZE_KILOBYTE)
		return 0;

	return 1;
}


static void set_key(char *key, int index)
{
	int i,len;
	len=strlen(key);
	if(len>PLAINTEXT_LENGTH)
		len=PLAINTEXT_LENGTH;

	for(i=0;i<len;i++)
		saved_key[PLAINTEXT_LENGTH*index+i] = key[i];

	saved_lengths[index]=len;
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = saved_lengths[index];
	char *key = (char *)&saved_key[PLAINTEXT_LENGTH*index];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	return out;
}

static void clear_keys(void)
{
	memset(saved_lengths,0,sizeof(cl_uint)*saved_gws);
}


static void char_to_bin(char *in, int char_length, char *bin)
{
	int i;
	for (i = 0; i < char_length; i += 2) {
		char a = in[i];
		char b = in[i + 1];
		if (a >= 65)
			a -= 55;
		else
			a -= 48;
		if (b >= 65)
			b -= 55;
		else
			b -= 48;
		bin[i / 2] = a << 4;
		bin[i / 2] += b;
	}
}

static void *get_binary(char *ciphertext)
{
	char *ii;
	static char out[BINARY_SIZE];
	memset(out, 0, BINARY_SIZE);

	ii = strrchr(ciphertext, '$');
	ii = ii + 1;
	char_to_bin(ii, strlen(ii), out);
	return out;
}

static void *get_salt(char *ciphertext)
{
	static struct argon2i_salt salt;
	char *i = ciphertext + 9;
	char *first_dollar,*second_dollar, *third_dollar;
	char *last_dollar = strrchr(ciphertext, '$');

	memset(salt.salt, 0, sizeof(salt.salt));

	salt.hash_size = strlen(last_dollar + 1) / 2;

	first_dollar = strchr(i, '$');
	second_dollar = strchr(first_dollar + 1, '$');
	third_dollar = strchr(second_dollar + 1, '$');

	salt.salt_length = last_dollar - third_dollar - 1;
	salt.t_cost = atoi(i);
	salt.m_cost = atoi(first_dollar+1);
	salt.lanes = atoi(second_dollar+1);

	memcpy(salt.salt, third_dollar + 1, salt.salt_length);

	return (void *)&salt;
}


static void set_salt(void *salt)
{
	memcpy(saved_salt,salt,sizeof(struct argon2i_salt));
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (!memcmp(binary,output + i * BINARY_SIZE, saved_salt->hash_size))
			return 1;
	}
	return 0;

}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, output + index * BINARY_SIZE,  saved_salt->hash_size);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size =
	    local_work_size ? (count + local_work_size -
	    1) / local_work_size * local_work_size : count;


	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_salt,
		CL_FALSE, 0, sizeof(struct argon2i_salt), saved_salt, 0, NULL,
		multi_profilingEvent[0]), "Failed transferring salt");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id],
		cl_saved_key, CL_FALSE, 0,
		count*PLAINTEXT_LENGTH, saved_key, 0, NULL,
		multi_profilingEvent[1]), "Failed transferring keys");


	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_lengths,
		CL_FALSE, 0, sizeof(cl_uint) * (global_work_size),
		saved_lengths, 0, NULL, multi_profilingEvent[2]), "Failed transferring index");


	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[3]), "failed in clEnqueueNDRangeKernel");


	// read back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_result, CL_TRUE,
		0, BINARY_SIZE * count, output, 0, NULL,
		multi_profilingEvent[4]), "failed in reading data back");


	return count;
}

static int get_hash_0(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0xF;
}

static int get_hash_1(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0xFF;
}

static int get_hash_2(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0xFFF;
}

static int get_hash_3(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * BINARY_SIZE);
	return crypt[0] & 0x7FFFFFF;
}

static int salt_hash(void *_salt)
{
	int i;
	struct argon2i_salt *salt = (struct argon2i_salt*)_salt;
	unsigned int hash = 0;
	char *p = salt->salt;

	for(i=0;i<salt->salt_length;i++) {
		hash <<= 1;
		hash += (unsigned char)*p++;
		if (hash >> SALT_HASH_LOG) {
			hash ^= hash >> SALT_HASH_LOG;
			hash &= (SALT_HASH_SIZE - 1);
		}
	}

	hash ^= hash >> SALT_HASH_LOG;
	hash &= (SALT_HASH_SIZE - 1);

	return hash;
}

#if FMT_MAIN_VERSION > 11

static unsigned int tunable_cost_t(void *_salt)
{
	struct argon2i_salt *salt=(struct argon2i_salt *)_salt;
	return salt->t_cost;
}

static unsigned int tunable_cost_m(void *_salt)
{
	struct argon2i_salt *salt=(struct argon2i_salt *)_salt;
	return salt->m_cost;
}

static unsigned int tunable_cost_l(void *_salt)
{
	struct argon2i_salt *salt=(struct argon2i_salt *)_salt;
	return salt->lanes;
}

#endif

struct fmt_main fmt_opencl_argon2i = {
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
		sizeof(struct argon2i_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
			"t",
			"m",
			"l"
		},
#endif
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			tunable_cost_t,
			tunable_cost_m,
			tunable_cost_l
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif				/* plugin stanza */

#endif				/* HAVE_OPENCL */

/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_lyra2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_lyra2);
#else

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "options.h"
#include "formats.h"
#include "common-opencl.h"
#include "opencl_lyra2.h"
#include "opencl_Sponge_Lyra2.h"

#define FORMAT_LABEL            "Lyra2-opencl"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "Lyra2 OpenCL"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE		256	//BINARY_SIZE in Lyra2 is unlimited

#define CIPHERTEXT_LENGTH	(2*BINARY_SIZE)

#define BINARY_ALIGN		1
#define SALT_SIZE		64

#define SALT_ALIGN		1

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define SEED 256

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char *warn[] = {
	"xfer salt1: ", ", xfer salt2: ", ", xfer keys: ", ", xfer idx: ",
	", crypt: ", ", xfer: "
};

static struct fmt_tests tests[] = {
	//{"$Lyra2$8$8$256$2$salt$03cafef9b80e74342b781e0c626db07f4783210c99e94e5271845fd48c8f80af", "password"},
	//{"$Lyra2$8$8$256$2$salt2$e61b2fc5a76d234c49188c2d6c234f5b5721382b127bea0177287bf5f765ec1a","password"},
	{"$Lyra2$1$12$256$3$salt$27a195d60ee962293622e2ee8c449102afe0e720e38cb0c4da948cfa1044250a","password"},
	//{"$Lyra2$8$8$256$2$salt$23ac37677486f032bf9960968318b53617354e406ac8afcd","password"},
	//{"$Lyra2$16$16$256$2$salt$f6ab1f65f93f2d491174f7f3c2a681fb95dadee998a014b90d78aae02bb099", "password"},
	//{"$Lyra2$1$8$256$1$one$4b84f7d57b1065f1bd21130152d9f46b71f4537b7f9f31710fac6b87e5f480cb","pass"},
	{NULL}
};

struct lyra2_salt {
	uint32_t t_cost,m_cost;
	uint32_t nCols,nParallel;
	uint32_t hash_size;
	uint32_t salt_length;
	uint64_t sizeSlicedRows;
	unsigned char salt[SALT_SIZE];
};

static char *saved_key;
static unsigned int *saved_lengths;
static cl_mem cl_saved_key, cl_saved_lengths, cl_saved_salt, cl_memMatrixGPU, cl_pKeysGPU, cl_stateThreadGPU, cl_stateIdxGPU, cl_saved_active_gws;
static cl_mem pinned_key, pinned_lengths,
     pinned_salt, pinned_pKeysGPU, pinned_active_gws;
static unsigned int M_COST, nPARALLEL, N_COLS;
static struct lyra2_salt *saved_salt;
static char *saved_key;
static char *pKeysGPU;
static int clobj_allocated;
static uint saved_gws;
static cl_kernel bootStrapAndAbsorb_kernel, reducedSqueezeRow0_kernel, reducedDuplexRow_kernel, setupPhaseWanderingGPU_kernel, setupPhaseWanderingGPU_P1_kernel;
static cl_uint saved_active_gws;

static struct fmt_main *self;

static void *get_salt(char *ciphertext);

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;
	s= autotune_get_task_max_work_group_size(FALSE, 0, bootStrapAndAbsorb_kernel);
	s= MIN(s,autotune_get_task_max_work_group_size(FALSE, 0, reducedSqueezeRow0_kernel));
	s= MIN(s,autotune_get_task_max_work_group_size(FALSE, 0, reducedDuplexRow_kernel));
	s= MIN(s,autotune_get_task_max_work_group_size(FALSE, 0, setupPhaseWanderingGPU_kernel));
	s= MIN(s,autotune_get_task_max_work_group_size(FALSE, 0, setupPhaseWanderingGPU_P1_kernel));
	return s;
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


static void create_clobj(size_t gws, struct fmt_main *self)
{
	if (clobj_allocated)
		release_clobj();

	clobj_allocated = 1;
	saved_gws=gws;

	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_memMatrixGPU =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
	    gws * M_COST * ROW_LEN_BYTES, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	pinned_pKeysGPU =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
	    gws * nPARALLEL * BINARY_SIZE, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_pKeysGPU =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
	    gws * nPARALLEL * BINARY_SIZE, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	pKeysGPU =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_pKeysGPU, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, gws * nPARALLEL * BINARY_SIZE, 0,
	    NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping memory");

	
	cl_stateThreadGPU =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
	    gws * nPARALLEL * STATESIZE_BYTES, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");


	cl_stateIdxGPU =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
	    gws * nPARALLEL * BLOCK_LEN_BLAKE2_SAFE_BYTES, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");


	pinned_key =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, PLAINTEXT_LENGTH * gws,
	    NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");


	pinned_salt =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(struct lyra2_salt), NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");


	cl_saved_key =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	    PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	cl_saved_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(struct lyra2_salt), NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	saved_key =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, PLAINTEXT_LENGTH * gws, 0, NULL,
	    NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	saved_salt =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_salt, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(struct lyra2_salt), 0, NULL, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_salt");

	pinned_lengths =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
	    sizeof(cl_uint) * gws , NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_lengths =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	    sizeof(cl_uint) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_lengths =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_lengths, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * gws, 0,
	    NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_lengths");

	pinned_active_gws =
	    clCreateBuffer(context[gpu_id],
	    CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint), NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_active_gws =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(cl_uint), NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_active_gws =
	    clEnqueueMapBuffer(queue[gpu_id], pinned_active_gws, CL_TRUE,
	    CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint), 0, NULL, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_salt");


	HANDLE_CLERROR(clSetKernelArg(bootStrapAndAbsorb_kernel, 0, sizeof(cl_mem),
		(void *)&cl_memMatrixGPU), "Error setting argument 0 in bootStrapAndAbsorb_kernel");
	HANDLE_CLERROR(clSetKernelArg(bootStrapAndAbsorb_kernel, 1, sizeof(cl_mem),
		(void *)&cl_pKeysGPU), "Error setting argument 1 in bootStrapAndAbsorb_kernel");
	HANDLE_CLERROR(clSetKernelArg(bootStrapAndAbsorb_kernel, 2, sizeof(cl_mem),
		(void *)&cl_saved_key), "Error setting argument 2 in bootStrapAndAbsorb_kernel");
	HANDLE_CLERROR(clSetKernelArg(bootStrapAndAbsorb_kernel, 3, sizeof(cl_mem),
		(void *)&cl_saved_lengths), "Error setting argument 3 in bootStrapAndAbsorb_kernel");
	HANDLE_CLERROR(clSetKernelArg(bootStrapAndAbsorb_kernel, 4, sizeof(cl_mem),
		(void *)&cl_saved_salt), "Error setting argument 4 in bootStrapAndAbsorb_kernel");
	HANDLE_CLERROR(clSetKernelArg(bootStrapAndAbsorb_kernel, 5, sizeof(cl_mem),
		(void *)&cl_stateThreadGPU), "Error setting argument 5 in bootStrapAndAbsorb_kernel");
	HANDLE_CLERROR(clSetKernelArg(bootStrapAndAbsorb_kernel, 6, sizeof(cl_mem),
		(void *)&cl_stateIdxGPU), "Error setting argument 6 in bootStrapAndAbsorb_kernel");
	HANDLE_CLERROR(clSetKernelArg(bootStrapAndAbsorb_kernel, 7, sizeof(cl_mem),
		(void *)&cl_saved_active_gws), "Error setting argument 7 in bootStrapAndAbsorb_kernel");

	HANDLE_CLERROR(clSetKernelArg(reducedSqueezeRow0_kernel, 0, sizeof(cl_mem),
		(void *)&cl_memMatrixGPU), "Error setting argument 0 in reducedSqueezeRow0_kernel");
	HANDLE_CLERROR(clSetKernelArg(reducedSqueezeRow0_kernel, 1, sizeof(cl_mem),
		(void *)&cl_stateThreadGPU), "Error setting argument 1 in reducedSqueezeRow0_kernel");
	HANDLE_CLERROR(clSetKernelArg(reducedSqueezeRow0_kernel, 2, sizeof(cl_mem),
		(void *)&cl_saved_salt), "Error setting argument 2 in reducedSqueezeRow0_kernel");
	HANDLE_CLERROR(clSetKernelArg(reducedSqueezeRow0_kernel, 3, sizeof(cl_mem),
		(void *)&cl_saved_active_gws), "Error setting argument 3 in reducedSqueezeRow0_kernel");

	HANDLE_CLERROR(clSetKernelArg(reducedDuplexRow_kernel, 0, sizeof(cl_mem),
		(void *)&cl_memMatrixGPU), "Error setting argument 0 in reducedSqueezeRow0_kernel");
	HANDLE_CLERROR(clSetKernelArg(reducedDuplexRow_kernel, 1, sizeof(cl_mem),
		(void *)&cl_stateThreadGPU), "Error setting argument 1 in reducedSqueezeRow0_kernel");
	HANDLE_CLERROR(clSetKernelArg(reducedDuplexRow_kernel, 2, sizeof(cl_mem),
		(void *)&cl_saved_salt), "Error setting argument 2 in reducedSqueezeRow0_kernel");
	HANDLE_CLERROR(clSetKernelArg(reducedDuplexRow_kernel, 3, sizeof(cl_mem),
		(void *)&cl_saved_active_gws), "Error setting argument 3 in reducedSqueezeRow0_kernel");


	HANDLE_CLERROR(clSetKernelArg(setupPhaseWanderingGPU_kernel, 0, sizeof(cl_mem),
		(void *)&cl_memMatrixGPU), "Error setting argument 0 in setupPhaseWanderingGPU_kernel");
	HANDLE_CLERROR(clSetKernelArg(setupPhaseWanderingGPU_kernel, 1, sizeof(cl_mem),
		(void *)&cl_stateThreadGPU), "Error setting argument 1 in setupPhaseWanderingGPU_kernel");
	HANDLE_CLERROR(clSetKernelArg(setupPhaseWanderingGPU_kernel, 2, sizeof(cl_mem),
		(void *)&cl_pKeysGPU), "Error setting argument 2 in setupPhaseWanderingGPU_P1_kernel");
	HANDLE_CLERROR(clSetKernelArg(setupPhaseWanderingGPU_kernel, 3, sizeof(cl_mem),
		(void *)&cl_saved_salt), "Error setting argument 3 in setupPhaseWanderingGPU_kernel");
	HANDLE_CLERROR(clSetKernelArg(setupPhaseWanderingGPU_kernel, 4, sizeof(cl_mem),
		(void *)&cl_saved_active_gws), "Error setting argument 4 in setupPhaseWanderingGPU_kernel");

	HANDLE_CLERROR(clSetKernelArg(setupPhaseWanderingGPU_P1_kernel, 0, sizeof(cl_mem),
		(void *)&cl_memMatrixGPU), "Error setting argument 0 in setupPhaseWanderingGPU_P1_kernel");
	HANDLE_CLERROR(clSetKernelArg(setupPhaseWanderingGPU_P1_kernel, 1, sizeof(cl_mem),
		(void *)&cl_stateThreadGPU), "Error setting argument 1 in setupPhaseWanderingGPU_P1_kernel");
	HANDLE_CLERROR(clSetKernelArg(setupPhaseWanderingGPU_P1_kernel, 2, sizeof(cl_mem),
		(void *)&cl_pKeysGPU), "Error setting argument 2 in setupPhaseWanderingGPU_P1_kernel");
	HANDLE_CLERROR(clSetKernelArg(setupPhaseWanderingGPU_P1_kernel, 3, sizeof(cl_mem),
		(void *)&cl_saved_salt), "Error setting argument 3 in setupPhaseWanderingGPU_P1_kernel");
	HANDLE_CLERROR(clSetKernelArg(setupPhaseWanderingGPU_P1_kernel, 4, sizeof(cl_mem),
		(void *)&cl_saved_active_gws), "Error setting argument 4 in setupPhaseWanderingGPU_P1_kernel");
}

static void release_clobj(void)
{
	if (!clobj_allocated)
		return;

	clobj_allocated = 0;

	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_key,
		saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_lengths,
		saved_lengths, 0, NULL, NULL), "Error Unmapping saved_lengths");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_salt,
		saved_salt, 0, NULL, NULL),
	    "Error Unmapping saved_salt");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_pKeysGPU,
		pKeysGPU, 0, NULL, NULL), "Error Unmapping pKeysGPU");

	HANDLE_CLERROR(clFinish(queue[gpu_id]),
	    "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(pinned_key),
	    "Release pinned key buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_lengths),
	    "Release pinned index buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_salt),
	    "Release pinned index buffer");	
	HANDLE_CLERROR(clReleaseMemObject(pinned_pKeysGPU),
	    "Release pinned pKeysGPU buffer");
	
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_lengths),
	    "Release index buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_salt),
	    "Release real salt");
	HANDLE_CLERROR(clReleaseMemObject(cl_memMatrixGPU), "Release memMatrixGPU");
	HANDLE_CLERROR(clReleaseMemObject(cl_pKeysGPU), "Release memMatrixGPU");
	HANDLE_CLERROR(clReleaseMemObject(cl_stateThreadGPU), "Release stateThreadGPU");
	HANDLE_CLERROR(clReleaseMemObject(cl_stateIdxGPU), "Release stateIdxGPU");
}


static void done(void)
{
	if(autotuned)
	{
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(bootStrapAndAbsorb_kernel), "Release bootStrapAndAbsorb_kernel");
		HANDLE_CLERROR(clReleaseKernel(reducedSqueezeRow0_kernel), "Release reducedSqueezeRow0_kernel");
		HANDLE_CLERROR(clReleaseKernel(reducedDuplexRow_kernel), "Release reducedDuplexRow_kernel");
		HANDLE_CLERROR(clReleaseKernel(setupPhaseWanderingGPU_kernel), "Release setupPhaseWanderingGPU_kernel");
		HANDLE_CLERROR(clReleaseKernel(setupPhaseWanderingGPU_P1_kernel), "Release setupPhaseWanderingGPU_kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
	}
}


static void reset_()
{
	char build_opts[128];

	sprintf(build_opts,
	    "-DBINARY_SIZE=%d -DSALT_SIZE=%d -DPLAINTEXT_LENGTH=%d", BINARY_SIZE, SALT_SIZE, PLAINTEXT_LENGTH);

	opencl_init("$JOHN/kernels/lyra2_kernel.cl", gpu_id, build_opts);

	bootStrapAndAbsorb_kernel =
	    clCreateKernel(program[gpu_id], "lyra2_bootStrapAndAbsorb", &ret_code);
	HANDLE_CLERROR(ret_code,
	    "Error creating kernel bootStrapAndAbsorb. Double-check kernel name?");


	reducedSqueezeRow0_kernel =
	    clCreateKernel(program[gpu_id], "lyra2_reducedSqueezeRow0", &ret_code);
	HANDLE_CLERROR(ret_code,
	    "Error creating kernel reducedSqueezeRow0. Double-check kernel name?");

	reducedDuplexRow_kernel =
	    clCreateKernel(program[gpu_id], "lyra2_reducedDuplexRow", &ret_code);
	HANDLE_CLERROR(ret_code,
	    "Error creating kernel reducedDuplexRow. Double-check kernel name?");


	setupPhaseWanderingGPU_P1_kernel =
	    clCreateKernel(program[gpu_id], "lyra2_setupPhaseWanderingGPU_P1", &ret_code);
	HANDLE_CLERROR(ret_code,
	    "Error creating kernel setupPhaseWanderingGPU_P1. Double-check kernel name?");

	crypt_kernel=setupPhaseWanderingGPU_kernel =
	    clCreateKernel(program[gpu_id], "lyra2_setupPhaseWanderingGPU", &ret_code);
	HANDLE_CLERROR(ret_code,
	    "Error creating kernel setupPhaseWanderingGPU. Double-check kernel name?");

	release_clobj();
	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL,
	    warn, 4, self, create_clobj, release_clobj, M_COST * ROW_LEN_BYTES, 0);

	//Auto tune execution from shared/included code.
	autotune_run(self, 1, 0, 1000);
}

static void reset(struct db_main *db)
{
	if(!autotuned)
	{
		unsigned int i, prev_M_COST=0;
		M_COST=0;
		nPARALLEL=0;
		N_COLS=0;
		if (!db) {
			for (i = 0; tests[i].ciphertext; i++)
			{ 
				struct lyra2_salt *salt=get_salt(tests[i].ciphertext); 
				M_COST = MAX(M_COST, salt->m_cost);
				N_COLS = MAX(N_COLS, salt->nCols);
				nPARALLEL = MAX(nPARALLEL, salt->nParallel);
				if(i==0)
				{
					printf("\n");
					print_memory(M_COST * ROW_LEN_BYTES);
					prev_M_COST=M_COST;
				}
			}
			if(prev_M_COST!=M_COST)
			{
				printf("max ");
				print_memory(M_COST * ROW_LEN_BYTES);
			}
			reset_();
		} else {
			struct db_salt *salts = db->salts;
			M_COST = 0;
			while (salts != NULL) {
				struct lyra2_salt *salt=salts->salt;
				M_COST = MAX(M_COST, salt->m_cost);
				N_COLS = MAX(N_COLS, salt->nCols);
				nPARALLEL = MAX(nPARALLEL, salt->nParallel);
				salts = salts->next;
			}
			printf("\n");
			print_memory(M_COST * ROW_LEN_BYTES);
			reset_();
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
	char *next_dollar;
	char *i;
	struct lyra2_salt *salt;

	if (strncmp(ciphertext, "$Lyra2$", 7) &&
	    strncmp(ciphertext, "$lyra2$", 7))
		return 0;
	i = ciphertext + 7;
	//t_cost
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > 4 || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//m_cost
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > 4 || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//nCols
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//nParallel
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	//salt
	next_dollar = strchr(i, '$');
	if (next_dollar == NULL || next_dollar - i > SALT_SIZE || next_dollar == i)
		return 0;
	i = next_dollar + 1;
	if (strlen(i) > CIPHERTEXT_LENGTH || strlen(i) == 0)
		return 0;
	while (atoi16[ARCH_INDEX(*i)] != 0x7F)	
		i++;
	if (*i)
		return 0;
	
	salt=get_salt(ciphertext);

	if (salt->m_cost < 3) 
		return 0;

	if ((salt->m_cost / 2) % salt->nParallel != 0) 
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
		if (a >= 97)
			a -= 87;
		else
			a -= 48;
		if (b >= 97)
			b -= 87;
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
	static struct lyra2_salt salt;
	char *i = ciphertext + 7;
	char *first_dollar,*second_dollar,*third_dollar,*fourth_dollar;
	char *last_dollar = strrchr(ciphertext, '$');

	memset(salt.salt, 0, sizeof(salt.salt));

	salt.hash_size = strlen(last_dollar + 1) / 2;

	first_dollar = strchr(i, '$');
	second_dollar = strchr(first_dollar + 1, '$');
	third_dollar = strchr(second_dollar + 1, '$');
	fourth_dollar = strchr(third_dollar + 1, '$');

	salt.salt_length = last_dollar - fourth_dollar - 1;
	salt.t_cost = atoi(i);
	salt.m_cost = atoi(first_dollar+1);
	salt.nCols = atoi(second_dollar+1);
	salt.nParallel = atoi(third_dollar+1);
	salt.sizeSlicedRows = (salt.m_cost / salt.nParallel) * (BLOCK_LEN_INT64 * salt.nCols);

	memcpy(salt.salt, fourth_dollar + 1, salt.salt_length);

	return (void *)&salt;
}


static void set_salt(void *salt)
{
	memcpy(saved_salt,salt,sizeof(struct lyra2_salt));
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (!memcmp(binary,pKeysGPU + i * saved_salt->hash_size, saved_salt->hash_size))
			return 1;
	}
	return 0;

}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, pKeysGPU + index * saved_salt->hash_size,  saved_salt->hash_size);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t real_gws, real_lws;
	int i,j,k;

	global_work_size =
	    local_work_size ? (count + local_work_size -
	    1) / local_work_size * local_work_size : count;//pomidor wyswietlic czy nParallel ma dobra wartosc

	printf("crypt all %d lws=%u, gws=%u\n",count,*lws,global_work_size);

	real_gws=global_work_size*saved_salt->nParallel;
	saved_active_gws=real_gws;
	real_lws=*lws;
	//must real_lws%saved_salt->nParallel==0
	if(real_lws)
	{
		real_lws-=real_lws%saved_salt->nParallel;
		if(real_lws==0)
			real_lws=saved_salt->nParallel;
	}
	//must real_gws%real_lws==0
	if(real_gws)
	{
		if(real_gws%real_lws)
		{
			real_gws+=real_lws;
			real_gws-=real_gws%real_lws;
		}
	}
	printf("real_gws=%u, real_lws=%u\n",real_gws,real_lws);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_salt,
		CL_FALSE, 0, sizeof(struct lyra2_salt), saved_salt, 0, NULL,
		multi_profilingEvent[0]), "Failed transferring salt");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_active_gws,
		CL_FALSE, 0, sizeof(cl_uint), &saved_active_gws, 0, NULL,
		multi_profilingEvent[0]), "Failed transferring active_gws");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id],
		cl_saved_key, CL_FALSE, 0,
		PLAINTEXT_LENGTH*count, saved_key, 0, NULL,
		multi_profilingEvent[1]), "Failed transferring keys");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_lengths,
		CL_FALSE, 0, sizeof(cl_uint) * (global_work_size),
		saved_lengths, 0, NULL, multi_profilingEvent[2]), "Failed transferring index");


	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], bootStrapAndAbsorb_kernel, 1,
		NULL, &real_gws, &real_lws, 0, NULL,
		multi_profilingEvent[3]), "failed in clEnqueueNDRangeKernel");


	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], reducedSqueezeRow0_kernel, 1,
		NULL, &real_gws, &real_lws, 0, NULL,
		multi_profilingEvent[4]), "failed in clEnqueueNDRangeKernel");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], reducedDuplexRow_kernel, 1,
		NULL, &real_gws, &real_lws, 0, NULL,
		multi_profilingEvent[5]), "failed in clEnqueueNDRangeKernel");

	if(saved_salt->nParallel==1)
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], setupPhaseWanderingGPU_P1_kernel, 1,
			NULL, &real_gws, &real_lws, 0, NULL,
			multi_profilingEvent[6]), "failed in clEnqueueNDRangeKernel");
	else
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], setupPhaseWanderingGPU_kernel, 1,
			NULL, &real_gws, &real_lws, 0, NULL,
			multi_profilingEvent[6]), "failed in clEnqueueNDRangeKernel");

	opencl_process_event();


	// read back 
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_pKeysGPU, CL_TRUE,
		0, saved_salt->hash_size * count * saved_salt->nParallel, pKeysGPU, 0, NULL,
		multi_profilingEvent[7]), "failed in reading data back");

	if (saved_salt->nParallel > 1)
	{
	    // XORs all Keys
	    for (k = 0; k < count; k++) {
		for (i = 1; i < saved_salt->nParallel; i++) {
		    for (j = 0; j < saved_salt->hash_size; j++) {
		        pKeysGPU[k * saved_salt->hash_size * saved_salt->nParallel + j] ^= pKeysGPU[k * saved_salt->hash_size * saved_salt->nParallel + i * saved_salt->hash_size + j];
		    }
		}
	    }

	    //Move the keys to proper place
	    for (k = 1; k < count; k++) {
		for (j = 0; j < saved_salt->hash_size; j++) {
		    pKeysGPU[k * saved_salt->hash_size + j] = pKeysGPU[k * saved_salt->hash_size * saved_salt->nParallel + j];
		}
	    }
	}

	return count;
}

static int get_hash_0(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (pKeysGPU + index * saved_salt->hash_size);
	return crypt[0] & 0xF;
}

static int get_hash_1(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (pKeysGPU + index * saved_salt->hash_size);
	return crypt[0] & 0xFF;
}

static int get_hash_2(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (pKeysGPU + index * saved_salt->hash_size);
	return crypt[0] & 0xFFF;
}

static int get_hash_3(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (pKeysGPU + index * saved_salt->hash_size);
	return crypt[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (pKeysGPU + index * saved_salt->hash_size);
	return crypt[0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (pKeysGPU + index * saved_salt->hash_size);
	return crypt[0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (pKeysGPU + index * saved_salt->hash_size);
	return crypt[0] & 0x7FFFFFF;
}

static int salt_hash(void *_salt)
{
	int i;
	struct lyra2_salt *salt = (struct lyra2_salt*)_salt;
	unsigned int hash = 0;
	unsigned char *p = salt->salt;

	for(i=0;i<salt->salt_length;i++) {
		hash <<= 1;
		hash += *p++;
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
	struct lyra2_salt *salt=(struct lyra2_salt *)_salt;
	return salt->t_cost;
}

static unsigned int tunable_cost_m(void *_salt)
{
	struct lyra2_salt *salt=(struct lyra2_salt *)_salt;
	return salt->m_cost;
}

static unsigned int tunable_cost_c(void *_salt)
{
	struct lyra2_salt *salt=(struct lyra2_salt *)_salt;
	return salt->nCols;
}

static unsigned int tunable_cost_p(void *_salt)
{
	struct lyra2_salt *salt=(struct lyra2_salt *)_salt;
	return salt->nParallel;
}

#endif

struct fmt_main fmt_opencl_lyra2 = {
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
		sizeof(struct lyra2_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
			"t",
			"m",
			"c",
			"p"
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
			tunable_cost_c,
			tunable_cost_p
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

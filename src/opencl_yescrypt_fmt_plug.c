/*
 * This software is Copyright (c) 2015 Agnieszka Bielec <bielecagnieszka8 at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_yescrypt;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_yescrypt);
#else

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "options.h"
#include "formats.h"
#include "common-opencl.h"
#include "yescrypt.h"
#include "opencl_yescrypt.h"

#define FORMAT_LABEL            "yescrypt-opencl"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "pwxform Salsa20/8 OpenCL"

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0

#define SETTING 		(4 + 1 + 5 + 5 + BYTES2CHARS(32) + 1)
#define HASH_SIZE		(HASH_LEN + 1)

#define PLAINTEXT_LENGTH        125

#define BINARY_SIZE             32
#define BINARY_ALIGN            1
#define SALT_SIZE		64
#define SALT_ALIGN              1
#define KEY_SIZE		PLAINTEXT_LENGTH

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define YESCRYPT_FLAGS 		YESCRYPT_RW
#define YESCRYPT_P 		11
#define YESCRYPT_PROM 		8

#define BYTES2CHARS(bytes) \
	((((bytes) * 8) + 5) / 6)

#define HASH_LEN BYTES2CHARS(BINARY_SIZE) /* base-64 chars */

#define SEED 256


//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char *warn[] = {
	"xfer salt1: ", ", xfer salt2: ", ", xfer keys: ", ", xfer idx: ",
	", crypt: ", ", xfer: "
};


struct yescrypt_salt {
	char salt[SALT_SIZE];
	uint32_t salt_length;
	uint64_t N;
	uint32_t r, p, t, g;
	yescrypt_flags_t flags;
	//ROM
	char ROM;
	char key[KEY_SIZE+1];
	uint64_t rom_size;
	uint64_t rom_N;
	uint32_t rom_r, rom_p;
};


static struct fmt_tests tests[] = {
	{"$0$0$7X$96....9....WZaPV7LSUEKMo34.$ZoMvPuaKOKqV3K2xNz3pPp.cWOIYJICPLdp6EFsv5Z0","pleaseletmein"},
	{"$0$0$7X$96....9....WZaPV7LSUEKMo34.$B28ZRktp61jee8VLhEOszvUak579EOfjz/bm1AkXUTC","x-men"},
	{"$0$0$7X$96....9....WZaPV7LSUEKMo34$gZ.es2fD1WJAqx5ioo6ZqERrWYzP8iH0uOsUCUJ9lVA","NSA"},
	{"$0$0$7X$96....9....WZaPV7LSUEKMo34$XqyoZHZjZ3KCuNUW4NP/WgG/aAv7jhvp19cSWYJPa86","keyboard"},
	{"$0$0$7X$96....9....WZaPV7LSUEKMo34.$etMpFbzahhNbJ0UPlAESnepEdKjs5VqpbpMEZyl.7H/","spiderman"},
	{"#local param#262144#8#8$0$0$7X$96....9....WZaPV7LSUEKMo34.$UcNa7Ee718f3x5cu4sdUK.VTVisbzjb/NPtUGJJlZb5","shared"},//rom
	//{"$1$1$7X$96....9....WZaPV7LSUEKMo34.$PIeIJHhlVeIEcM3.sIuIH85KdkqPPNCfZ3WJdTKpY81","spiderman"},
	//{"$1$1$7X$20....1....WZaPV7LSUEKMo34.$k4f1WRjcD7h/k1cO.D6IbsmUkeKATc9JsVtRLmxneFD","pleaseletmein"},//<-very low costs*/
	{NULL}
};


static char *saved_key;
static unsigned int *saved_lengths;
static cl_mem cl_saved_key, cl_saved_lengths, cl_result, cl_saved_salt, cl_V, cl_B, cl_XY, cl_S, cl_shared;
static cl_mem pinned_key, pinned_lengths, pinned_result,
     pinned_salt, pinned_shared;
static char *output;
static struct yescrypt_salt *saved_salt;
static char *saved_key;
static uint64_t N,r,p,g;
static yescrypt_flags_t flags;
static yescrypt_flags_t saved_flags;
static yescrypt_shared_t shared;
static char prev_key[KEY_SIZE+1];
static int clobj_allocated;
static uint saved_gws;

uint64_t prev_saved_rom_N;
uint32_t prev_saved_rom_r, prev_saved_rom_p;

static struct fmt_main *self;

extern int decode64_one(uint32_t * dst, uint8_t src);
extern const uint8_t * decode64_uint32(uint32_t * dst, uint32_t dstbits,
    const uint8_t * src);

static unsigned int tunable_cost_N(void *_salt);
static unsigned int tunable_cost_r(void *_salt);
static unsigned int tunable_cost_p(void *_salt);
static unsigned int tunable_cost_t(void *_salt);
static unsigned int tunable_cost_g(void *_salt);


static void *get_salt(char *ciphertext);

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
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
	uint64_t V_size=128*r*(N<<(g*2));
	uint64_t B_size=128*r*p;
	uint64_t XY_size=256*r+64;
	uint64_t S_size=Sbytes * p;

	if (clobj_allocated)
		release_clobj();
	clobj_allocated = 1;

	saved_gws=gws;
	cl_V = cl_B = cl_XY = cl_S = NULL;
	
	cl_B=clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, gws * B_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	cl_V=clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, gws * V_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	cl_XY=clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, gws * XY_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	
	if (flags & YESCRYPT_RW)
	{
		cl_S=clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, gws * S_size, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating device buffer");
	}
	
	saved_flags=flags;

	if(shared.aligned_size)
	{
		pinned_shared = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, shared.aligned_size , NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
		cl_shared = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, shared.aligned_size , NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating device buffer");
	}

	pinned_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_key = clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, PLAINTEXT_LENGTH * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	pinned_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(struct yescrypt_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(struct yescrypt_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_salt = clEnqueueMapBuffer(queue[gpu_id], pinned_salt, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(struct yescrypt_salt), 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_salt");

	pinned_lengths = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_lengths = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(cl_uint) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_lengths = clEnqueueMapBuffer(queue[gpu_id], pinned_lengths, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_lengths");

	pinned_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, HASH_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, HASH_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	output = clEnqueueMapBuffer(queue[gpu_id], pinned_result, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, HASH_SIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping output");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
		(void *)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
		(void *)&cl_saved_lengths), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
		(void *)&cl_result), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem),
		(void *)&cl_saved_salt), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(cl_mem),
		(void *)&cl_V), "Error setting argument 4");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(cl_mem),
		(void *)&cl_B), "Error setting argument 5");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 6, sizeof(cl_mem),
		(void *)&cl_XY), "Error setting argument 6");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 7, sizeof(cl_mem),
		(void *)&cl_S), "Error setting argument 7");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 8, sizeof(cl_mem),
		(void *)&cl_shared), "Error setting argument 8");
}

static void release_clobj(void)
{
	if (!clobj_allocated)
		return;
	clobj_allocated = 0;

	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_result, output, 0, NULL, NULL), "Error Unmapping output");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_lengths, saved_lengths, 0, NULL, NULL), "Error Unmapping saved_lengths");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_salt, saved_salt, 0, NULL, NULL), "Error Unmapping saved_salt");

	HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(pinned_result), "Release pinned result buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_key), "Release pinned key buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_lengths), "Release pinned index buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_salt), "Release pinned salt buffer");
	if(shared.aligned_size)
		HANDLE_CLERROR(clReleaseMemObject(pinned_shared), "Release pinned shared buffer");
	
	HANDLE_CLERROR(clReleaseMemObject(cl_result), "Release result buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_lengths), "Release index buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_salt), "Release salt");
	if(shared.aligned_size)
		HANDLE_CLERROR(clReleaseMemObject(cl_shared), "Release key buffer");

	HANDLE_CLERROR(clReleaseMemObject(cl_V), "Release memory");
	HANDLE_CLERROR(clReleaseMemObject(cl_B), "Release memory");
	HANDLE_CLERROR(clReleaseMemObject(cl_XY), "Release memory");
	if (saved_flags & YESCRYPT_RW)
		HANDLE_CLERROR(clReleaseMemObject(cl_S), "Release memory");
}


static void done(void)
{
	if(autotuned)
	{
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
	}
	if(prev_saved_rom_N || prev_saved_rom_r || prev_saved_rom_p)
	{
		yescrypt_free_shared(&shared);
	}
}

void init_rom(char *key, uint64_t N, uint32_t r, uint32_t p)
{
	if(
	prev_saved_rom_N==N &&
	prev_saved_rom_r==r &&
	prev_saved_rom_p==p &&
	!strcmp(prev_key,key)
	)
		return;
	else
	{
		if(prev_saved_rom_N || prev_saved_rom_r || prev_saved_rom_p)
		{
			yescrypt_free_shared(&shared);
		}
		if (yescrypt_init_shared(&shared,(uint8_t*)key, strlen(key),
		    N, r, p, YESCRYPT_SHARED_DEFAULTS,
		    NULL, 0)) {
			puts(" FAILED");
			exit(1);
		}
		prev_saved_rom_N=N;
		prev_saved_rom_r=r;
		prev_saved_rom_p=p;
		strcpy(prev_key,key);
	}
}

static uint64_t yescrypt_memory(uint64_t N, uint32_t r, uint32_t p, uint32_t g, yescrypt_flags_t flags)
{
	uint64_t V_size=128*r*(N<<(g*2));
	uint64_t B_size=128*r*p;
	uint64_t XY_size=256*r+64;
	uint64_t S_size=Sbytes * p;
	uint64_t need;

	need=V_size+B_size+XY_size;
	if (flags & YESCRYPT_RW)
		need+=S_size;

	return need;
}

static void reset_()
{
	uint64_t need;

	char build_opts[128];

	sprintf(build_opts,
	    "-DBINARY_SIZE=%d -DSALT_SIZE=%d -DPLAINTEXT_LENGTH=%d -DHASH_SIZE=%d -DKEY_SIZE=%d", BINARY_SIZE, SALT_SIZE, PLAINTEXT_LENGTH, HASH_SIZE, KEY_SIZE);


	opencl_init("$JOHN/kernels/yescrypt_kernel.cl", gpu_id, build_opts);


	// create kernel to execute
	crypt_kernel =
	    clCreateKernel(program[gpu_id], "yescrypt_crypt_kernel", &ret_code);
	HANDLE_CLERROR(ret_code,
	    "Error creating kernel. Double-check kernel name?");


	need=yescrypt_memory(N, r, p, g, flags);

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL,
	    warn, 4, self, create_clobj, release_clobj, need, 0);


	//Auto tune execution from shared/included code.
	autotune_run(self, 1, 0, 100000000000);
}

static void reset(struct db_main *db)
{
	if(!autotuned)
	{
		int i;
		char ROM=0;
		char *tmp_key=NULL;
		uint64_t rom_N;
		uint32_t rom_p, rom_r;
		uint64_t need, prev_need;
		N=p=r=g=flags=0;
		rom_N=rom_p=rom_r=0;
		need=prev_need=0;
		if (!db) {
			for (i = 0; tests[i].ciphertext; i++)
			{
				struct yescrypt_salt *salt;
				salt=get_salt(tests[i].ciphertext);
				N = MAX(N, salt->N);
				r = MAX(r, salt->r);
				g = MAX(g, salt->g);
				p = MAX(p, salt->p);
				ROM = MAX(ROM, salt->ROM);
				rom_N = MAX(rom_N, salt->rom_N);
				rom_r = MAX(rom_r, salt->rom_r);
				rom_p = MAX(rom_p, salt->rom_p);
				if(salt->ROM)
				{
					tmp_key=salt->key;
				}
				flags |= salt->flags;
				if(i==0)
				{
					printf("\n");
					prev_need=yescrypt_memory(N, r, p, g, flags);
					print_memory(prev_need);
				}
			}
			if(ROM)
				init_rom(tmp_key,rom_N,rom_r,rom_p);

			need=yescrypt_memory(N, r, p, g, flags);
			if(need!=prev_need)
			{
				printf("max ");
				print_memory(yescrypt_memory(N, r, p, g, flags));
			}
			reset_();
		} else {
			struct db_salt *salts = db->salts;
			while (salts != NULL) {
				struct yescrypt_salt * salt=salts->salt;
				N = MAX(N, salt->N);
				r = MAX(r, salt->r);
				g = MAX(g, salt->g);
				p = MAX(p, salt->p);
				ROM = MAX(ROM, salt->ROM);
				rom_N = MAX(rom_N, salt->rom_N);
				rom_r = MAX(rom_r, salt->rom_r);
				rom_p = MAX(rom_p, salt->rom_p);
				flags |= salt->flags;
				if(salt->ROM)
				{
					tmp_key=salt->key;
				}

				salts = salts->next;
			}
			if(ROM)
				init_rom(tmp_key,rom_N,rom_r,rom_p);

			printf("\n");
			print_memory(yescrypt_memory(N, r, p, g, flags));
			reset_();
		}
	}
}

static void init(struct fmt_main *_self)
{
	clobj_allocated = 0;
	self = _self;
	prev_saved_rom_N=prev_saved_rom_r=prev_saved_rom_p=0;
	memset(prev_key,0,KEY_SIZE+1);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int i;
	uint64_t N;
	uint32_t r, p, t;
	size_t prefixlen, saltlen, need;
	const char *src, *salt;
	struct yescrypt_salt * tmp_salt;
	yescrypt_flags_t flags;
	char *dollar=ciphertext;
	for(i=0;i<2;i++){
		dollar=strchr(dollar,'$');
		if(dollar==NULL)
			return 0;
		dollar++;
	}
	src=strchr(dollar,'$');
	for(i=0;i<3;i++){
		dollar=strchr(dollar,'$');
		if(dollar==NULL)
			return 0;
		dollar++;
	}
	if (src[0] != '$' || src[1] != '7')
		return 0;

	src+=2;
	if (*src != '$' && *src != 'X')
		return 0;

	if(*src == 'X')
		src++;
	if (*src != '$') {
		uint32_t decoded_flags;
		if (decode64_one(&decoded_flags, *src))
			return 0;
		if (*++src != '$')
			return 0;
	}
	src++;
	{
		uint32_t N_log2;
		if (decode64_one(&N_log2, *src))
			return 0;
		src++;
	}
	src = (char*)decode64_uint32(&r, 30, (uint8_t*)src);
	if (!src)
		return 0;

	src = (char*)decode64_uint32(&p, 30, (uint8_t*)src);
	if (!src)
		return 0;

	prefixlen = src - ciphertext;
	salt = src;
	src = strrchr((char *)salt, '$');

	if (src)
		saltlen = src - salt;
	else
		saltlen = strlen(salt);

	need = prefixlen + saltlen + 1 + HASH_LEN + 1;
	if (need < saltlen)
		return 0;

	if(saltlen>sizeof(saved_salt->salt))
		return 0;

	/* Sanity-check parameters */
	tmp_salt=(struct yescrypt_salt *)get_salt(ciphertext);
	flags=tmp_salt->flags;
	N=tmp_salt->N;
	r=tmp_salt->r;
	p=tmp_salt->p;
	t=tmp_salt->t;

	if ((flags & ~YESCRYPT_KNOWN_FLAGS) || (!flags && t)) {
		return 0;
	}

	if ((uint64_t)(r) * (uint64_t)(p) >= (1 << 30)) {
		return 0;
	}
	if (((N & (N - 1)) != 0) || (N <= 1) || (r < 1) || (p < 1)) {
		return 0;
	}
	if ((p > SIZE_MAX / ((size_t)256 * r + 64)) ||
#if SIZE_MAX / 256 <= UINT32_MAX
	    (r > SIZE_MAX / 256) ||
#endif
	    (N > SIZE_MAX / 128 / r)) {
		return 0;
	}
	if (N > UINT64_MAX / ((uint64_t)t + 1)) {
		return 0;
	}
	if (flags & YESCRYPT_RW) {
		if ((flags & YESCRYPT_WORM) || (N / p <= 1) || (r < rmin)) {
			return 0;
		}
		if (p > SIZE_MAX / Sbytes) {
			return 0;
		}
	}

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


static void *get_binary(char *ciphertext)
{
	char *ii;
	static char out[HASH_SIZE];
	memset(out, 0, HASH_SIZE);

	ii = strrchr(ciphertext, '$');
	ii = ii + 1;
	strcpy(out,ii);
	return out;
}

static void *get_salt(char *ciphertext)
{
	static struct yescrypt_salt salt;
	const char * src, * salt_src;
	size_t saltlen;
	uint64_t N;
	uint32_t r, p;
	yescrypt_flags_t flags = 0;
	
	memset(&salt,0,sizeof(struct yescrypt_salt));

	src=strchr(ciphertext,'$')+1;
	salt.t=atoi(src);
	src=strchr(src,'$')+1;
	salt.g=atoi(src);
	src=strchr(src,'$')+2;
	if(*src=='X')
	{
		src++;
		flags = YESCRYPT_RW;
	}

	if (*src != '$') {
		uint32_t decoded_flags;
		if (decode64_one(&decoded_flags, *src))
			return NULL;
		flags = decoded_flags;
		if (*++src != '$')
			return NULL;
	}
	src++;

	{
		uint32_t N_log2;
		if (decode64_one(&N_log2, *src))
			return NULL;
		src++;
		N = (uint64_t)1 << N_log2;
	}

	src = (char*)decode64_uint32(&r, 30, (uint8_t*)src);


	src = (char*)decode64_uint32(&p, 30, (uint8_t*)src);

	salt_src = src;
	src = strrchr((char *)salt_src, '$');
	if (src)
		saltlen = src - salt_src;
	else
		saltlen = strlen((char *)salt_src);

	memset(salt.salt,0,sizeof(salt.salt));
	strncpy(salt.salt,salt_src,saltlen);
	salt.salt_length=saltlen;
	salt.N=N;
	salt.r=r;
	salt.p=p;
	salt.flags=flags;
	
	//ROM
	if(ciphertext[0]=='#')
	{
		char *sharp=strchr(ciphertext+1,'#');
		memset(&salt.key,0,KEY_SIZE+1);
		memcpy(&salt.key,ciphertext+1,sharp-ciphertext-1);
		salt.ROM=1;
		salt.rom_N=atoi(sharp+1);
		sharp=strchr(sharp+1,'#');
		salt.rom_r=atoi(sharp+1);
		sharp=strchr(sharp+1,'#');
		salt.rom_p=atoi(sharp+1);
	}
	else
	{
		salt.ROM=salt.rom_N=salt.rom_r=salt.rom_p=0;
	}
	
	return (void *)&salt;
}


static void set_salt(void *salt)
{
	memcpy(saved_salt,salt,sizeof(struct yescrypt_salt));
	if(saved_salt->ROM)
		init_rom(saved_salt->key,saved_salt->rom_N, saved_salt->rom_r, saved_salt->rom_p);
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (!memcmp(binary,output + i * HASH_SIZE, HASH_SIZE))
			return 1;
	}
	return 0;

}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, output + index * HASH_SIZE,  HASH_SIZE);
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

	//ROM
	if(saved_salt->ROM)
	{
		saved_salt->rom_size=shared.aligned_size;
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_shared,
			CL_FALSE, 0, shared.aligned_size, shared.aligned, 0, NULL,
			multi_profilingEvent[0]), "Failed transferring ROM");
	}

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_salt,
		CL_FALSE, 0, sizeof(struct yescrypt_salt), saved_salt, 0, NULL,
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
		0, HASH_SIZE * count, output, 0, NULL,
		multi_profilingEvent[4]), "failed in reading data back");

	return count;
}

static int get_hash_0(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * HASH_SIZE);
	return crypt[0] & 0xF;
}

static int get_hash_1(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * HASH_SIZE);
	return crypt[0] & 0xFF;
}

static int get_hash_2(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * HASH_SIZE);
	return crypt[0] & 0xFFF;
}

static int get_hash_3(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * HASH_SIZE);
	return crypt[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * HASH_SIZE);
	return crypt[0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * HASH_SIZE);
	return crypt[0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	ARCH_WORD_32 *crypt = (ARCH_WORD_32 *) (output + index * HASH_SIZE);
	return crypt[0] & 0x7FFFFFF;
}

static int salt_hash(void *_salt)
{
	int i;
	struct yescrypt_salt *salt = (struct yescrypt_salt*)_salt;
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

static unsigned int tunable_cost_N(void *_salt)
{
	struct yescrypt_salt *salt=(struct yescrypt_salt *)_salt;
	return salt->N;
}

static unsigned int tunable_cost_r(void *_salt)
{
	struct yescrypt_salt *salt=(struct yescrypt_salt *)_salt;
	return salt->r;
}

static unsigned int tunable_cost_p(void *_salt)
{
	struct yescrypt_salt *salt=(struct yescrypt_salt *)_salt;
	return salt->p;
}

static unsigned int tunable_cost_t(void *_salt)
{
	struct yescrypt_salt *salt=(struct yescrypt_salt *)_salt;
	return salt->t;
}

static unsigned int tunable_cost_g(void *_salt)
{
	struct yescrypt_salt *salt=(struct yescrypt_salt *)_salt;
	return salt->g;
}

#endif

struct fmt_main fmt_opencl_yescrypt = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		HASH_SIZE,
		BINARY_ALIGN,
		sizeof(struct yescrypt_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
			"N",
			"r",
			"p",
			"t",
			"g"
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
			tunable_cost_N,
			tunable_cost_r,
			tunable_cost_p,
			tunable_cost_t,
			tunable_cost_g
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

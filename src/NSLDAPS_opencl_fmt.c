/*
 * Copyright (c) 2011 Samuele Giovanni Tonon
 * samu at linuxasylum dot net
 * Released under GPL license 
 */

#include <string.h>
#include <endian.h>


#include "path.h"
#include "misc.h"
#include "params.h"
#include "formats.h"
#include "common.h"

#include "sha.h"
#include "base64.h"
#include "common-opencl.h"

#define FORMAT_LABEL			"ssha-opencl"
#define FORMAT_NAME			"Netscape LDAP SSHA OPENCL"
#define SHA_TYPE                        "salted SHA-1"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define CIPHERTEXT_LENGTH		40

#define BINARY_SIZE			20
#define SALT_SIZE			8
#define NUM_BLOCKS			5

#define SHA_BLOCK			16
#define PLAINTEXT_LENGTH		SHA_BLOCK
#define SSHA_NUM_KEYS         		1024*2048
//#define SSHA_NUM_KEYS         		1024*16

#define MIN_KEYS_PER_CRYPT              1024*32
#define MAX_KEYS_PER_CRYPT		SSHA_NUM_KEYS


#ifndef uint32_t
#define uint32_t unsigned int
#endif

typedef struct {
    uint32_t h0,h1,h2,h3,h4;
} SHA_DEV_CTX;


#define NSLDAP_MAGIC "{ssha}"
#define NSLDAP_MAGIC_LENGTH 6

/*cl_platform_id platform;
cl_device_id devices;
cl_context context;
cl_program program;*/
cl_command_queue queue_prof;
cl_int ret_code;
cl_kernel ssha_crypt_kernel;
cl_mem pinned_saved_keys, pinned_partial_hashes, buffer_out, buffer_keys, len_buffer, data_info, mysalt, mycrypt;
static cl_uint *outbuffer; 
static cl_uint *outbuffer2;
static char *inbuffer;
static char saved_key[SSHA_NUM_KEYS][PLAINTEXT_LENGTH];
static char saved_salt[SALT_SIZE];
static unsigned int datai[2];
static unsigned int crypted_key[5];

static size_t global_work_size = SSHA_NUM_KEYS;

static struct fmt_tests tests[] = {
  {"{SSHA}8VKmzf3SqceSL8/CJ0bGz7ij+L0SQCxcHHYzBw==", "mabelove"},
  {"{SSHA}91PzTv0Wjs/QVzbQ9douCG3HK8gpV1ocqgbZUg==", "12345678"},
  {"{SSHA}DNPSSyXT0wzh4JiiX1D8RnltILQzUlFBuhKFcA==", "wildstar"},
  {"{SSHA}yVEfRVwCJqVUBgLvgM89ExKgcfZ9QEFQgmobJg==", "zanzibar"},
  {"{SSHA}WTT3B9Jjr8gOt0Q7WMs9/XvukyhTQj0Ns0jMKQ==", "Password9"},
  {"{SSHA}cKFVqtf358j0FGpPsEIK1xh3T0mtDNV1kAaBNg==", "salles"},
  {"{SSHA}y9Nc5vOnK12ppTjHo35lxM1pMFnLZMwqqwH6Eg==", "00000000"},
  {"{SSHA}W3ipFGmzS3+j6/FhT7ZC39MIfqFcct9Ep0KEGA==", "asddsa123"},



#if 0
/*
 * These two were found in john-1.6-nsldaps4.diff.gz and apparently they were
 * supported by that version of they code, but they are not anymore.
 */
  {"{SSHA}/EExmSfmhQSPHDJaTxwQSdb/uPpzYWx0ZXI=", "secret"},
  {"{SSHA}gVK8WC9YyFT1gMsQHTGCgT3sSv5zYWx0", "secret"},
#endif
  {NULL}
};

static void find_best_workgroup(void){
	cl_event myEvent;
	cl_ulong startTime, endTime, kernelExecTimeNs = CL_ULONG_MAX;
	size_t my_work_group = 1;
	cl_int ret_code;
	int i = 0;
	size_t max_group_size;

	clGetDeviceInfo(devices,CL_DEVICE_MAX_WORK_GROUP_SIZE,sizeof(max_group_size),&max_group_size,NULL );
	queue_prof = clCreateCommandQueue( context, devices, CL_QUEUE_PROFILING_ENABLE, &ret_code);
	printf("Max Group Work Size %d ",(int)max_group_size);
	local_work_size = 1;

	// Set keys
	for (; i < SSHA_NUM_KEYS; i++){
		memcpy(&(inbuffer[i*SHA_BLOCK]),"aaaaaaaa",SHA_BLOCK);
		inbuffer[i*SHA_BLOCK+8] = 0x80;
	}
        clEnqueueWriteBuffer(queue_prof, data_info, CL_TRUE, 0, sizeof(unsigned int)*2, datai, 0, NULL, NULL);
        clEnqueueWriteBuffer(queue_prof, mysalt, CL_TRUE, 0, SALT_SIZE, saved_salt, 0, NULL, NULL);
	clEnqueueWriteBuffer(queue_prof, buffer_keys, CL_TRUE, 0, (SHA_BLOCK) * SSHA_NUM_KEYS, inbuffer, 0, NULL, NULL);

	// Find minimum time
	for(my_work_group=1 ;(int) my_work_group <= (int) max_group_size; my_work_group*=2){
    		ret_code = clEnqueueNDRangeKernel( queue_prof, ssha_crypt_kernel, 1, NULL, &global_work_size, &my_work_group, 0, NULL, &myEvent);
		clFinish(queue_prof);

		if(ret_code != CL_SUCCESS){
			printf("Errore %d\n",ret_code);
			continue;
		}

		clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
		clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END  , sizeof(cl_ulong), &endTime  , NULL);

		if((endTime-startTime) < kernelExecTimeNs) {
			kernelExecTimeNs = endTime-startTime;
			local_work_size = my_work_group;
		}
		//printf("%d time=%ld\n",(int) my_work_group, endTime-startTime);
		//printf("wgS = %d\n",(int)my_work_group);
	}
	printf("Optimal Group work Size = %d\n",(int)local_work_size);
	clReleaseCommandQueue(queue_prof);
}


// TODO: free resources at exit
static void fmt_ssha_init(struct fmt_main *pFmt)
{
    opencl_init("$JOHN/ssha_opencl_kernel.cl", CL_DEVICE_TYPE_GPU);

    // create kernel to execute
    ssha_crypt_kernel = clCreateKernel(program, "sha1_crypt_kernel", &ret_code);
    if_error_log(ret_code, "Error creating kernel. Double-check kernel name?");

    // create Page-Locked (Pinned) memory for higher bandwidth between host and device (Nvidia Best Practices)
    pinned_saved_keys = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, (SHA_BLOCK)*SSHA_NUM_KEYS, NULL, &ret_code);
    if_error_log (ret_code, "Error creating page-locked memory");
    inbuffer = (char*)clEnqueueMapBuffer(queue, pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0, (SHA_BLOCK)*SSHA_NUM_KEYS, 0, NULL, NULL, &ret_code);
    if_error_log (ret_code, "Error mapping page-locked memory inbuffer");

    memset(inbuffer,0,SHA_BLOCK*SSHA_NUM_KEYS);
    outbuffer2 = malloc(sizeof(cl_uint) * 4 * SSHA_NUM_KEYS);

    pinned_partial_hashes = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint)*SSHA_NUM_KEYS, NULL, &ret_code);

    if_error_log (ret_code, "Error creating page-locked memory");

    outbuffer = (cl_uint *)clEnqueueMapBuffer(queue, pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, sizeof(cl_uint)*SSHA_NUM_KEYS, 0, NULL, NULL, &ret_code);
    if_error_log (ret_code, "Error mapping page-locked memory outbuffer");

    // create and set arguments
    buffer_keys = clCreateBuffer(context, CL_MEM_READ_ONLY, (SHA_BLOCK)*SSHA_NUM_KEYS, NULL, &ret_code);
    if_error_log (ret_code, "Error creating buffer keys argument");

    buffer_out  = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(cl_uint)*5*SSHA_NUM_KEYS, NULL, &ret_code);
    if_error_log (ret_code,"Error creating buffer out argument");


    data_info = clCreateBuffer(context, CL_MEM_READ_ONLY, sizeof(unsigned int)*2, NULL, &ret_code);
    if_error_log (ret_code,"Error creating data_info out argument");

    mysalt = clCreateBuffer(context, CL_MEM_READ_ONLY, SALT_SIZE, NULL, &ret_code);
    if_error_log (ret_code,"Error creating mysalt out argument");

    //mycrypt = clCreateBuffer(context, CL_MEM_READ_ONLY, BINARY_SIZE, NULL, &ret_code);
    //if_error_log (ret_code,"Error creating mycrypt out argument");

    ret_code = clSetKernelArg(ssha_crypt_kernel, 0, sizeof(data_info), (void*) &data_info);
    if_error_log (ret_code, "Error setting argument 0");

    ret_code = clSetKernelArg(ssha_crypt_kernel, 1, sizeof(mysalt), (void*) &mysalt);
    if_error_log (ret_code, "Error setting argument 1");

    //ret_code = clSetKernelArg(ssha_crypt_kernel, 2, sizeof(mycrypt), (void*) &mycrypt);
    //if_error_log (ret_code, "Error setting argument 2");

    ret_code = clSetKernelArg(ssha_crypt_kernel, 2, sizeof(buffer_keys), (void*) &buffer_keys);
    if_error_log (ret_code, "Error setting argument 2");

    ret_code = clSetKernelArg(ssha_crypt_kernel, 3, sizeof(buffer_out ), (void*) &buffer_out);
    if_error_log (ret_code, "Error setting argument 3");

    datai[0]=SHA_BLOCK;
    datai[1]=SSHA_NUM_KEYS;
    find_best_workgroup();
    //local_work_size = 64; // TODO: detect dynamically
}


static void * binary(char *ciphertext) {
    static char realcipher[BINARY_SIZE + SALT_SIZE + 9];

    memset(realcipher, 0, sizeof(realcipher));
    base64_decode(NSLDAP_MAGIC_LENGTH+ciphertext, CIPHERTEXT_LENGTH, realcipher);
    //memcpy(crypted_key,realcipher,BINARY_SIZE);
    return (void *)realcipher;
}

static void * get_salt(char * ciphertext){
    static char realcipher[BINARY_SIZE + SALT_SIZE + 9];
    memset(realcipher, 0, sizeof(realcipher));
    base64_decode(NSLDAP_MAGIC_LENGTH+ciphertext, CIPHERTEXT_LENGTH, realcipher);
    return (void*)&realcipher[BINARY_SIZE];
}

static int valid(char *ciphertext, struct fmt_main *pFmt){
    if(ciphertext && strlen(ciphertext) == CIPHERTEXT_LENGTH + NSLDAP_MAGIC_LENGTH)
	return !strncasecmp(ciphertext, NSLDAP_MAGIC, NSLDAP_MAGIC_LENGTH);
    return 0;
}

static int get_hash_0(int index){ return outbuffer[index] & 0xF; }
static int get_hash_1(int index){ return outbuffer[index] & 0xFF; }
static int get_hash_2(int index){ return outbuffer[index] & 0xFFF; }
static int get_hash_3(int index){ return outbuffer[index] & 0xFFFF; }
static int get_hash_4(int index){ return outbuffer[index] & 0xFFFFF; }

static int binary_hash_0(void *binary){ return ((ARCH_WORD_32 *)binary)[0] & 0xF; }
static int binary_hash_1(void *binary){ return ((ARCH_WORD_32 *)binary)[0] & 0xFF; }
static int binary_hash_2(void *binary){ return ((ARCH_WORD_32 *)binary)[0] & 0xFFF; }
static int binary_hash_3(void *binary){ return ((ARCH_WORD_32 *)binary)[0] & 0xFFFF; }
static int binary_hash_4(void *binary){ return ((ARCH_WORD_32 *)binary)[0] & 0xFFFFF; }


static int salt_hash(void *salt)
{
    return *((ARCH_WORD_32 *)salt) & (SALT_HASH_SIZE - 1);
}

static void set_key(char *key, int index){
    memset(saved_key[index],0,PLAINTEXT_LENGTH);
    strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH);
}

static void set_salt(void *salt){
    memcpy(saved_salt, salt, SALT_SIZE);
}

static char *get_key(int index){
    return saved_key[index];
}

static int cmp_all(void *binary, int index) {
   unsigned int i = 0;
   unsigned int b = ((unsigned int *)binary)[0];

   for(; i<index; i++){
	if(b==outbuffer[i]){
	   bzero(outbuffer2,SSHA_NUM_KEYS*4*sizeof(cl_uint));
    	   clEnqueueReadBuffer(queue, buffer_out, CL_TRUE, sizeof(cl_uint)*(SSHA_NUM_KEYS), sizeof(cl_uint)*4*SSHA_NUM_KEYS, outbuffer2, 0, NULL, NULL);
	   return 1;
	} else {
	}
  }
   return 0;
}

static int cmp_exact(char *source, int index) {
   return 1;
}

static int cmp_one(void * binary, int index) {
   unsigned int *t=(unsigned int *)binary;

   if (t[1]!=outbuffer2[index])
       return 0;
   if (t[2]!=outbuffer2[1*SSHA_NUM_KEYS+index])
       return 0;
   if (t[3]!=outbuffer2[2*SSHA_NUM_KEYS+index])
       return 0;
   return t[4]==outbuffer2[3*SSHA_NUM_KEYS+index]; 
   
}


static void crypt_all(int count)
{
    cl_int code;
    int i;
    int lenpwd;
   
    for(i=0;i<count;i++){
	    lenpwd = strlen(saved_key[i]);
	    memcpy(&(inbuffer[i*SHA_BLOCK]),saved_key[i],SHA_BLOCK);
	    inbuffer[i*SHA_BLOCK+lenpwd] = 0x80;
    }
    code = clEnqueueWriteBuffer(queue, data_info, CL_TRUE, 0, sizeof(unsigned int)*2, datai, 0, NULL, NULL);
    if(code != CL_SUCCESS) {
       	printf("failed in clEnqueueWriteBuffer data_info with code %d\n", code);
       	exit(-1);
    }
    code = clEnqueueWriteBuffer(queue, mysalt, CL_TRUE, 0, SALT_SIZE, saved_salt, 0, NULL, NULL);
    if(code != CL_SUCCESS) {
       	printf("failed in clEnqueueWriteBuffer mysalt with code %d\n", code);
       	exit(-1);
    }
    code = clEnqueueWriteBuffer(queue, buffer_keys, CL_TRUE, 0, (SHA_BLOCK) * SSHA_NUM_KEYS, inbuffer, 0, NULL, NULL);
    if(code != CL_SUCCESS) {
       	printf("failed in clEnqueueWriteBuffer inbuffer with code %d\n", code);
       	exit(-1);
    }
    code = clEnqueueNDRangeKernel(queue, ssha_crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL);
    if(code != CL_SUCCESS) {
	    printf("failed in clEnqueueNDRangeKernel with code %d\n", code);
	    exit(-1);
    }
    clFinish(queue);
    // read back partial hashes
    clEnqueueReadBuffer(queue, buffer_out, CL_TRUE, 0, sizeof(cl_uint)*SSHA_NUM_KEYS, outbuffer, 0, NULL, NULL);
}

struct fmt_main fmt_opencl_NSLDAPS = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		SHA_TYPE,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		fmt_ssha_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

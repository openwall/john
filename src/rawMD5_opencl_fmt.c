/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 *
 * MD5 OpenCL code is based on Alain Espinosa's OpenCL patches.
 */

#include <string.h>

#include "arch.h"
#include "params.h"
#include "path.h"
#include "common.h"
#include "formats.h"
#include "common-opencl.h"

#define MD5
#include "opencl-tweaks.h"

#define FORMAT_LABEL        "raw-md5-opencl"
#define FORMAT_NAME         "Raw MD5"
#define ALGORITHM_NAME      "raw-md5-opencl"
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define CIPHERTEXT_LENGTH   32
#define BINARY_SIZE         16
#define SALT_SIZE           0

cl_command_queue queue_prof;
cl_mem pinned_saved_keys, pinned_partial_hashes, buffer_out, buffer_keys;
static cl_uint *partial_hashes;
static char *saved_plain;
static char get_key_saved[PLAINTEXT_LENGTH+1];
#define MIN_KEYS_PER_CRYPT      MD5_NUM_KEYS
#define MAX_KEYS_PER_CRYPT      MD5_NUM_KEYS
static size_t global_work_size = MD5_NUM_KEYS;
//static size_t local_work_size;

static struct fmt_tests tests[] = {
    {"098f6bcd4621d373cade4e832627b4f6", "test"},
    {"d41d8cd98f00b204e9800998ecf8427e", ""},
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
	for (; i < MD5_NUM_KEYS; i++){
		memcpy(&(saved_plain[i*(PLAINTEXT_LENGTH+1)]),"aaaaaaaa",PLAINTEXT_LENGTH+1);
		saved_plain[i*(PLAINTEXT_LENGTH+1)+8] = 0x80;
	}
	clEnqueueWriteBuffer(queue_prof, buffer_keys, CL_TRUE, 0, (PLAINTEXT_LENGTH+1) * MD5_NUM_KEYS, saved_plain, 0, NULL, NULL);

	// Find minimum time
	for(my_work_group=1 ;(int) my_work_group <= (int) max_group_size; my_work_group*=2){
    		ret_code = clEnqueueNDRangeKernel( queue_prof, crypt_kernel, 1, NULL, &global_work_size, &my_work_group, 0, NULL, &myEvent);
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
static void fmt_MD5_init(struct fmt_main *pFmt)
{
    // opencl init (common stuff is taken care of here)
    opencl_init("$JOHN/md5_opencl_kernel.cl", CL_DEVICE_TYPE_GPU);

    // create kernel to execute
    crypt_kernel = clCreateKernel(program, "md5", &ret_code);
    if_error_log(ret_code, "Error creating kernel. Double-check kernel name?");

    // create Page-Locked (Pinned) memory for higher bandwidth between host and device (Nvidia Best Practices)
    pinned_saved_keys = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
            (PLAINTEXT_LENGTH+1)*MD5_NUM_KEYS, NULL, &ret_code);
    if_error_log (ret_code, "Error creating page-locked memory");
    pinned_partial_hashes = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 4*MD5_NUM_KEYS, NULL, &ret_code);

    if_error_log (ret_code, "Error creating page-locked memory");
    saved_plain = (char*)clEnqueueMapBuffer(queue, pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0,
            (PLAINTEXT_LENGTH+1)*MD5_NUM_KEYS, 0, NULL, NULL, &ret_code);
    if_error_log (ret_code, "Error mapping page-locked memory");
    partial_hashes = (cl_uint*)clEnqueueMapBuffer(queue, pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, 4*MD5_NUM_KEYS, 0, NULL, NULL, &ret_code);
    if_error_log (ret_code, "Error mapping page-locked memory");

    // create and set arguments
    buffer_keys = clCreateBuffer(context, CL_MEM_READ_ONLY, (PLAINTEXT_LENGTH+1)*MD5_NUM_KEYS, NULL, &ret_code);
    if_error_log (ret_code, "Error creating buffer argument");
    buffer_out  = clCreateBuffer(context, CL_MEM_WRITE_ONLY, BINARY_SIZE*MD5_NUM_KEYS, NULL, &ret_code);
    if_error_log (ret_code,"Error creating buffer argument");

    ret_code = clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys), (void*) &buffer_keys);
    if_error_log (ret_code, "Error setting argument 1");
    ret_code = clSetKernelArg(crypt_kernel, 1, sizeof(buffer_out ), (void*) &buffer_out);
    if_error_log (ret_code, "Error setting argument 2");

    //local_work_size = 256; // TODO: detect dynamically
    find_best_workgroup();
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
    char *p, *q;

    p = ciphertext;
    if (!strncmp(p, "$MD5$", 5))
        p += 5;

    q = p;
    while (atoi16[ARCH_INDEX(*q)] != 0x7F)
        q++;
    return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index)
{
    static char out[5 + CIPHERTEXT_LENGTH + 1];

    if (!strncmp(ciphertext, "$MD5$", 5))
        return ciphertext;

    memcpy(out, "$MD5$", 5);
    memcpy(out + 5, ciphertext, CIPHERTEXT_LENGTH + 1);
    return out;
}

static void *get_binary(char *ciphertext)
{
    static unsigned char out[BINARY_SIZE];
    char *p;
    int i;

    p = ciphertext + 5;
    for (i = 0; i < sizeof(out); i++) {
        out[i] =
            (atoi16[ARCH_INDEX(*p)] << 4) |
            atoi16[ARCH_INDEX(p[1])];
        p += 2;
    }

    return out;
}

static int binary_hash_0(void *binary)
{
    return *(ARCH_WORD_32 *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
    return *(ARCH_WORD_32 *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
    return *(ARCH_WORD_32 *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
    return *(ARCH_WORD_32 *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
    return *(ARCH_WORD_32 *)binary & 0xFFFFF;
}

static int get_hash_0(int index)
{
#ifdef DEBUG
    printf("* in get_hash0, index : %d, hash : ", index);
    int i;
    for(i = 0; i < 4; i++)
        printf("%02x ", partial_hashes[i*MD5_NUM_KEYS + index]);
    printf("\n");
#endif
    return partial_hashes[index] & 0x0F;
}

static int get_hash_1(int index)
{
    return partial_hashes[index] & 0xFF;
}

static int get_hash_2(int index)
{
    return partial_hashes[index] & 0xFFF;
}

static int get_hash_3(int index)
{
    return partial_hashes[index] & 0xFFFF;
}

static int get_hash_4(int index)
{
    return partial_hashes[index] & 0xFFFFF;
}

static void set_salt(void *salt)
{
}

static void set_key(char *key, int index)
{
    int length = -1;
    int base = index * (PLAINTEXT_LENGTH+1);
    do
    {
        length++;
        saved_plain[base + length] = key[length];
    }
    while(key[length]);
    memset(&saved_plain[base + length+1], 0, 7); // ugly hack which "should" work!
}

static char *get_key(int index)
{
    int length = -1;
    int base = index * (PLAINTEXT_LENGTH+1);
    do
    {
        length++;
        get_key_saved[length] = saved_plain[base + length];
    }
    while(get_key_saved[length]);
    get_key_saved[length]= 0;
    return get_key_saved;
}

static void crypt_all(int count)
{
#ifdef DEBUGVERBOSE
    int i, j;
    unsigned char *p = (unsigned char*)saved_plain;
    count--;
    for(i=0; i<count+1; i++) {
        printf("\npassword : ");
        for(j=0; j < 64; j++) {
            printf("%02x ", p[i*64 + j]);
        }
    }
    printf("\n");
#endif
    cl_int code;
    // copy keys to the device
    code = clEnqueueWriteBuffer(queue, buffer_keys, CL_TRUE, 0, (PLAINTEXT_LENGTH+1) * MD5_NUM_KEYS, saved_plain, 0, NULL, NULL);
    if(code != CL_SUCCESS) {
        printf("failed in clEnqueueWriteBuffer with code %d\n", code);
        exit(-1);
    }
    // execute md4 kernel
    code = clEnqueueNDRangeKernel(queue, crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL);
    if(code != CL_SUCCESS) {
        printf("failed in clEnqueueNDRangeKernel with code %d\n", code);
        exit(-1);
    }
    clFinish(queue);
    // read back partial hashes
    clEnqueueReadBuffer(queue, buffer_out, CL_TRUE, 0, 4*MD5_NUM_KEYS, partial_hashes, 0, NULL, NULL);

#ifdef DEBUGVERBOSE
    p = (unsigned char *)partial_hashes;
    for(i=0; i<2; i++) {
        printf("\n\npartial_hashes : ");
        for(j=0; j < 16; j++)
            printf("%02x ", p[i*16 + j]);
    }
    printf("\n");;
#endif
}

static int cmp_one(void * binary, int index)
{
    unsigned int *t=(unsigned int *)binary;
    unsigned int a;
    unsigned int c;
    unsigned int d;

    // b
    clEnqueueReadBuffer(queue, buffer_out, CL_TRUE,  sizeof(cl_uint)*(1*MD5_NUM_KEYS+index), sizeof(a), (void*)&a, 0, NULL, NULL);
    if (t[1]!=a)
        return 0;
    // c
    clEnqueueReadBuffer(queue, buffer_out, CL_TRUE,  sizeof(cl_uint)*(2*MD5_NUM_KEYS+index), sizeof(c), (void*)&c, 0, NULL, NULL);
    if (t[2]!=c)
        return 0;
    // d
    clEnqueueReadBuffer(queue, buffer_out, CL_TRUE,  sizeof(cl_uint)*(3*MD5_NUM_KEYS+index), sizeof(d), (void*)&d, 0, NULL, NULL);
    return t[3]==d;

}

static int cmp_all(void *binary, int count)
{
   unsigned int i = 0;
   unsigned int b = ((unsigned int *)binary)[0];
   for(; i<count; i++)
       if(b==partial_hashes[i])
           return 1;
    return 0;
}

static int cmp_exact(char *source, int index)
{
    return 1;
}

struct fmt_main fmt_opencl_rawMD5 = {
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
        FMT_CASE | FMT_8_BIT,
        tests
    }, {
        fmt_MD5_init,
	fmt_default_prepare,
        valid,
        split,
        get_binary,
        fmt_default_salt,
        {
            binary_hash_0,
            binary_hash_1,
            binary_hash_2,
            binary_hash_3,
            binary_hash_4
        },
        fmt_default_salt_hash,
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

/*
 * Copyright (c) 2012 Samuele Giovanni Tonon
 * samu at linuxasylum dot net, and
 * Copyright (c) 2012, 2013 magnum
 * This program comes with ABSOLUTELY NO WARRANTY; express or
 * implied.
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include <string.h>

#include "path.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "common-opencl.h"

#define FORMAT_LABEL			"mysql-sha1-opencl"
#define FORMAT_NAME			"MySQL 4.1+ double-SHA-1"
#define ALGORITHM_NAME			"OpenCL (inefficient, development use only)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		41

#define BINARY_SIZE			20
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		1024*2048
#define MAX_KEYS_PER_CRYPT		MIN_KEYS_PER_CRYPT

typedef struct {
	unsigned int h0,h1,h2,h3,h4;
} SHA_DEV_CTX;


cl_command_queue queue_prof;
cl_int ret_code;
cl_mem pinned_msha_keys, pin_part_msha_hashes, buf_msha_out, buf_msha_keys;
static cl_uint *par_msha_hashes;
static cl_uint *res_hashes;
static char *mysqlsha_plain;
static int have_full_hashes;

static struct fmt_tests tests[] = {
	{"*5AD8F88516BD021DD43F171E2C785C69F8E54ADB", "tere"},
	{"*2c905879f74f28f8570989947d06a8429fb943e6", "verysecretpassword"},
	{"*A8A397146B1A5F8C8CF26404668EFD762A1B7B82", "________________________________"},
	{"*F9F1470004E888963FB466A5452C9CBD9DF6239C", "12345678123456781234567812345678"},
	{"*97CF7A3ACBE0CA58D5391AC8377B5D9AC11D46D9", "' OR 1 /*'"},
	{"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", "password"},
	{"*7534F9EAEE5B69A586D1E9C1ACE3E3F9F6FCC446", "5"},
	{"*be1bdec0aa74b4dcb079943e70528096cca985f8", ""},
	{"*0D3CED9BEC10A777AEC23CCC353A8C08A633045E", "abc"},
	{"*18E70DF2758EE4C0BD954910E5808A686BC38C6A", "VAwJsrUcrchdG9"},
	{"*440F91919FD39C01A9BC5EDB6E1FE626D2BFBA2F", "lMUXgJFc2rNnn"},
	{"*171A78FB2E228A08B74A70FE7401C807B234D6C9", "TkUDsVJC"},
	{"*F7D70FD3341C2D268E98119ED2799185F9106F5C", "tVDZsHSG"},
	{NULL}
};

static void create_clobj(int gws)
{
	pinned_msha_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, (PLAINTEXT_LENGTH)*gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	mysqlsha_plain = (char*)clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_msha_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0, (PLAINTEXT_LENGTH)*gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory mysqlsha_plain");
	memset(mysqlsha_plain, 0, PLAINTEXT_LENGTH * gws);

	res_hashes = mem_alloc(sizeof(cl_uint) * 4 * gws);

	pin_part_msha_hashes = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	par_msha_hashes = (cl_uint *) clEnqueueMapBuffer(queue[ocl_gpu_id], pin_part_msha_hashes, CL_TRUE, CL_MAP_READ,0,sizeof(cl_uint)*gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory par_msha_hashes");

	buf_msha_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,(PLAINTEXT_LENGTH)*gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer keys argument");

	buf_msha_out = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY,sizeof(cl_uint)*5*gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer out argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buf_msha_keys), (void *) &buf_msha_keys),"Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buf_msha_out), (void *) &buf_msha_out), "Error setting argument 1");

	global_work_size = gws;
}

static void release_clobj(void){
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pin_part_msha_hashes, par_msha_hashes, 0, NULL,NULL), "Error Unmapping par_msha_hashes");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_msha_keys, mysqlsha_plain, 0, NULL, NULL), "Error Unmapping mysqlsha_plain");
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "Error unmapping buffers");

	HANDLE_CLERROR(clReleaseMemObject(buf_msha_keys), "Error Releasing buf_msha_keys");
	HANDLE_CLERROR(clReleaseMemObject(buf_msha_out), "Error Releasing buf_msha_out");
	HANDLE_CLERROR(clReleaseMemObject(pinned_msha_keys), "Error Releasing pinned_msha_keys");
	HANDLE_CLERROR(clReleaseMemObject(pin_part_msha_hashes), "Error Releasing pin_part_msha_hashes");

	MEM_FREE(res_hashes);

	global_work_size = 0;
}

/* this function could be used to calculated the best num
of keys per crypt for the given format
*/
static void find_best_kpc(void){
    int num;
    cl_event myEvent;
    cl_ulong startTime, endTime, tmpTime;
    int kernelExecTimeNs = 6969;
    cl_int ret_code;
    int optimal_kpc=2048;
    int i = 0;
    cl_uint *tmpbuffer;

    fprintf(stderr, "Calculating best keys per crypt, this will take a while ");
    for( num=MAX_KEYS_PER_CRYPT; num > 4096 ; num -= 4096){
        release_clobj();
	create_clobj(num);
	advance_cursor();
	queue_prof = clCreateCommandQueue( context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	for (i=0; i < num; i++){
		memcpy(&(mysqlsha_plain[i*PLAINTEXT_LENGTH]),"abacaeaf",PLAINTEXT_LENGTH);
	}
	clEnqueueWriteBuffer(queue_prof, buf_msha_keys, CL_TRUE, 0, (PLAINTEXT_LENGTH) * num, mysqlsha_plain, 0, NULL, NULL);
	ret_code = clEnqueueNDRangeKernel( queue_prof, crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &myEvent);
	if(ret_code != CL_SUCCESS){
		fprintf(stderr, "Error %d\n",ret_code);
		continue;
	}
	clFinish(queue_prof);
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END  , sizeof(cl_ulong), &endTime  , NULL);
	tmpTime = endTime-startTime;
	tmpbuffer = mem_alloc(sizeof(cl_uint) * num);
	clEnqueueReadBuffer(queue_prof, buf_msha_out, CL_TRUE, 0, sizeof(cl_uint) * num, tmpbuffer, 0, NULL, &myEvent);
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END  , sizeof(cl_ulong), &endTime  , NULL);
	tmpTime = tmpTime + (endTime-startTime);
	if( ((int)( ((float) (tmpTime) / num) * 10 )) <= kernelExecTimeNs) {
		kernelExecTimeNs = ((int) (((float) (tmpTime) / num) * 10) ) ;
		optimal_kpc = num;
	}
	MEM_FREE(tmpbuffer);
	clReleaseCommandQueue(queue_prof);
    }
    fprintf(stderr, "Optimal keys per crypt %d\n(to avoid this test on next run do export GWS=%d)\n",optimal_kpc,optimal_kpc);
    global_work_size = optimal_kpc;
    release_clobj();
    create_clobj(optimal_kpc);
}

static int valid(char *ciphertext, struct fmt_main *self){
	int i;

	if (ciphertext[0] != '*')
		return 0;
	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	for (i = 1; i < CIPHERTEXT_LENGTH; i++) {
		if (!( (('0' <= ciphertext[i])&&(ciphertext[i] <= '9'))
		       || (('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
		       || (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
		{
			return 0;
		}
	}
	return 1;
}

static char *split(char *ciphertext, int index)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	strnzcpy(out, ciphertext, sizeof(out));
	strupr(out);
	return out;
}

static void init(struct fmt_main *self)
{
	char build_opts[64];
	char *temp;
	cl_ulong maxsize;

	local_work_size = global_work_size = 0;

	snprintf(build_opts, sizeof(build_opts),
	         "-DKEY_LENGTH=%d", PLAINTEXT_LENGTH);
	opencl_init_opt("$JOHN/kernels/msha_kernel.cl", ocl_gpu_id,
	                platform_id, build_opts);

	// create kernel to execute
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "sha1_crypt_kernel", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	/* Note: we ask for the kernels' max sizes, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max workgroup size");

	if ((temp = getenv("LWS"))) {
		local_work_size = atoi(temp);

		while (local_work_size > maxsize)
			local_work_size >>= 1;
	}

	if (!local_work_size) {
		create_clobj(MAX_KEYS_PER_CRYPT);
		opencl_find_best_workgroup_limit(self, maxsize);
		release_clobj();
	}

	if ((temp = getenv("GWS")))
		global_work_size = atoi(temp);
	else
		global_work_size = MAX_KEYS_PER_CRYPT;

	if (!global_work_size) {
		global_work_size = MAX_KEYS_PER_CRYPT;
		create_clobj(MAX_KEYS_PER_CRYPT);
		find_best_kpc();
	} else {
		create_clobj(global_work_size);
	}

	fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n",(int)local_work_size, (int)global_work_size);

	self->params.max_keys_per_crypt = global_work_size;

	self->params.min_keys_per_crypt = local_work_size;
}

static void set_key(char *key, int index) {
	memcpy(&(mysqlsha_plain[index*PLAINTEXT_LENGTH]), key, PLAINTEXT_LENGTH);
}

static char *get_key(int index) {
	int length = 0;
	static char out[PLAINTEXT_LENGTH + 1];
	char *key = &mysqlsha_plain[index * PLAINTEXT_LENGTH];

	while (length < PLAINTEXT_LENGTH && *key)
		out[length++] = *key++;
	out[length] = 0;
	return out;
}

static void *binary(char *ciphertext)
{
	static char realcipher[BINARY_SIZE];
	int i;

	ciphertext += 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		realcipher[i] =
		    atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
	}
	return (void *) realcipher;
}

static int cmp_all(void *binary, int index)
{
	unsigned int i = 0;
	unsigned int b = ((unsigned int *) binary)[0];

	for(; i<index; i++){
		if(b==par_msha_hashes[i])
			return 1;
	}
	return 0;
}

static int cmp_exact(char *source, int count) {
	unsigned int *t = (unsigned int *) binary(source);

	if (!have_full_hashes){
		clEnqueueReadBuffer(queue[ocl_gpu_id], buf_msha_out, CL_TRUE,
			sizeof(cl_uint) * (global_work_size),
			sizeof(cl_uint) * 4 * global_work_size, res_hashes, 0,
			NULL, NULL);
		have_full_hashes = 1;
	}

	if (t[1]!=res_hashes[count])
		return 0;
	if (t[2]!=res_hashes[1*global_work_size+count])
		return 0;
	if (t[3]!=res_hashes[2*global_work_size+count])
		return 0;
	if (t[4]!=res_hashes[3*global_work_size+count])
		return 0;
	return 1;
}

static int cmp_one(void *binary, int index){
	unsigned int *t = (unsigned int *) binary;

	if (t[0] == par_msha_hashes[index])
		return 1;
	return 0;

}

static void crypt_all(int count) {
	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buf_msha_keys, CL_FALSE, 0, (PLAINTEXT_LENGTH) * global_work_size, mysqlsha_plain, 0, NULL, NULL), "failed in clEnqueueWriteBuffer mysqlsha_plain");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, profilingEvent), "failed in clEnqueueNDRangeKernel");

	// read back partial hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buf_msha_out, CL_TRUE, 0, sizeof(cl_uint) * global_work_size, par_msha_hashes, 0, NULL, NULL), "failed in reading data back");
	have_full_hashes = 0;
}


static int binary_hash_0(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xf; }
static int binary_hash_1(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xff; }
static int binary_hash_2(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfff; }
static int binary_hash_3(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffff; }
static int binary_hash_4(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfffff; }
static int binary_hash_5(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffffff; }
static int binary_hash_6(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0x7ffffff; }

static int get_hash_0(int index) { return par_msha_hashes[index] & 0xF; }
static int get_hash_1(int index) { return par_msha_hashes[index] & 0xFF; }
static int get_hash_2(int index) { return par_msha_hashes[index] & 0xFFF; }
static int get_hash_3(int index) { return par_msha_hashes[index] & 0xFFFF; }
static int get_hash_4(int index) { return par_msha_hashes[index] & 0xFFFFF; }
static int get_hash_5(int index) { return par_msha_hashes[index] & 0xFFFFFF; }
static int get_hash_6(int index) { return par_msha_hashes[index] & 0x7FFFFFF; }

struct fmt_main fmt_opencl_mysqlsha1 = {
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
		init,
		fmt_default_prepare,
		valid,
		split,
		binary,
		fmt_default_salt,
		{
		     	binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
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

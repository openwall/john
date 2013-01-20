/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
 *
 * Note: using myrice idea.
 * Please note that in current comparison function, we use computed a77
 * compares with ciphertext d80. For more details, refer to:
 * http://www.openwall.com/lists/john-dev/2012/04/11/13
 *
 * Copyright (c) 2011 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include <string.h>
#include "common-opencl.h"
#include "config.h"
#include "opencl_rawsha512-ng.h"
#include "sha2.h"

#define FORMAT_LABEL			"raw-sha512-ng-opencl"
#define FORMAT_NAME			"Raw SHA-512 (pwlen < " PLAINTEXT_TEXT ")"
#define ALGORITHM_NAME			"OpenCL (inefficient, development use mostly)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define CONFIG_NAME			"rawsha512"

//Checks for source code to pick (parameters, sizes, kernels to execute, etc.)
#define _USE_CPU_SOURCE			(cpu(source_in_use))
#define _USE_GPU_SOURCE			(gpu(source_in_use))
#define _USE_LOCAL_SOURCE		(amd_gcn(source_in_use) || use_local(source_in_use))

static sha512_password     * plaintext;             // plaintext ciphertexts
static uint32_t            * calculated_hash;       // calculated (partial) hashes

static cl_mem pass_buffer;        //Plaintext buffer.
static cl_mem hash_buffer;        //Partial hash keys (output).
static cl_mem p_binary_buffer;    //To compare partial binary ([3]).
static cl_mem result_buffer;      //To get the if a hash was found.
static cl_mem pinned_saved_keys, pinned_partial_hashes;

static cl_kernel cmp_kernel;
static int hash_found, source_in_use;

static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt);

static struct fmt_tests tests[] = {
    {"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "password"},
    {"$SHA512$fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe", "12345678"},
    {"$SHA512$cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", ""},
#ifdef DEBUG //Special test cases.
    {"2c80f4c2b3db6b677d328775be4d38c8d8cd9a4464c3b6273644fb148f855e3db51bc33b54f3f6fa1f5f52060509f0e4d350bb0c7f51947728303999c6eff446", "john-user"},
#endif
    {NULL}
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size(){
    size_t max_available;

    if (_USE_LOCAL_SOURCE)
        max_available = get_local_memory_size(ocl_gpu_id) /
                (sizeof(sha512_ctx_buffer));
    else
        max_available = get_max_work_group_size(ocl_gpu_id);

    if (max_available > get_current_work_group_size(ocl_gpu_id, crypt_kernel))
        return get_current_work_group_size(ocl_gpu_id, crypt_kernel);

    return max_available;
}

static size_t get_task_max_size(){
    size_t max_available;
    max_available = get_max_compute_units(ocl_gpu_id);

    if (cpu(device_info[ocl_gpu_id]))
        return max_available * KEYS_PER_CORE_CPU;

    else
        return max_available * KEYS_PER_CORE_GPU *
                get_current_work_group_size(ocl_gpu_id, crypt_kernel);
}

static size_t get_default_workgroup(){

    if (cpu(device_info[ocl_gpu_id]))
        return 1;
    else
        return 128;
}

static void crypt_one(int index, sha512_hash * hash) {
    SHA512_CTX ctx;

    SHA512_Init(&ctx);
    SHA512_Update(&ctx, plaintext[index].pass, plaintext[index].length);
    SHA512_Final((unsigned char *) (hash), &ctx);
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(int gws, struct fmt_main * self) {
    self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = gws;

    pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id],
            CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
            sizeof(sha512_password) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

    plaintext = (sha512_password *) clEnqueueMapBuffer(queue[ocl_gpu_id],
            pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0,
            sizeof(sha512_password) * gws, 0, NULL, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

    pinned_partial_hashes = clCreateBuffer(context[ocl_gpu_id],
            CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
            sizeof(uint32_t) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

    calculated_hash = (uint32_t *) clEnqueueMapBuffer(queue[ocl_gpu_id],
            pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
            sizeof(uint32_t) * gws, 0, NULL, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

    // create arguments (buffers)
    pass_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
            sizeof(sha512_password) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

    hash_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY,
            sizeof(uint32_t) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument hash_buffer");

    p_binary_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
            sizeof(uint32_t), NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument p_binary_buffer");

    result_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
            sizeof(int), NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument result_buffer");

    //Set kernel arguments
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
            (void *) &pass_buffer), "Error setting argument 0");
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
            (void *) &hash_buffer), "Error setting argument 1");

    HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 0, sizeof(cl_mem),
            (void *) &hash_buffer), "Error setting argument 0");
    HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 1, sizeof(cl_mem),
            (void *) &p_binary_buffer), "Error setting argument 1");
    HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 2, sizeof(cl_mem),
            (void *) &result_buffer), "Error setting argument 2");

    if (_USE_LOCAL_SOURCE) {
        //Fast working memory.
        HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2,
           sizeof(sha512_ctx_buffer) * local_work_size,
           NULL), "Error setting argument 2");
    }
    memset(plaintext, '\0', sizeof(sha512_password) * gws);
}

static void release_clobj(void) {
    cl_int ret_code;

    ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys,
            plaintext, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Unmapping saved_plain");

    ret_code = clReleaseMemObject(pass_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing buffer_keys");
    ret_code = clReleaseMemObject(hash_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing hash_buffer");

    ret_code = clReleaseMemObject(p_binary_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing p_binary_buffer");
    ret_code = clReleaseMemObject(result_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing result_buffer");

    ret_code = clReleaseMemObject(pinned_saved_keys);
    HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_keys");
    ret_code = clReleaseMemObject(pinned_partial_hashes);
    HANDLE_CLERROR(ret_code, "Error Releasing pinned_partial_hashes");
}

/* ------- Key functions ------- */
static void set_key(char * key, int index) {
    int len;

    //Assure buffer has no "trash data".
    memset(plaintext[index].pass, '\0', PLAINTEXT_LENGTH);
    len = strlen(key);

    //Put the tranfered key on password buffer.
    memcpy(plaintext[index].pass, key, len);
    plaintext[index].length = len ;

    /* Prepare for GPU */
    plaintext[index].pass->mem_08[len] = 0x80;
}

static char * get_key(int index) {
    static char ret[PLAINTEXT_LENGTH + 1];
    memcpy(ret, plaintext[index].pass, PLAINTEXT_LENGTH);
    ret[plaintext[index].length] = '\0';
    return ret;
}

/* ------- Try to find the best configuration ------- */
/* --
  This function could be used to calculated the best num
  for the workgroup
  Work-items that make up a work-group (also referred to
  as the size of the work-group)
  LWS should never be a big number since every work-item
  uses about 400 bytes of local memory. Local memory
  is usually 32 KB
-- */
static void find_best_lws(struct fmt_main * self, int sequential_id) {

    size_t max_group_size;

    max_group_size = get_task_max_work_group_size();
    fprintf(stderr, "Max local worksize %d, ", (int) max_group_size);

    //Call the default function.
    opencl_find_best_lws(
            max_group_size, sequential_id, crypt_kernel);

    fprintf(stderr, "Optimal local worksize %d\n", (int) local_work_size);
    fprintf(stderr, "(to avoid this test on next run, put \""
        CONFIG_NAME LWS_CONFIG_NAME " = %d\" in john.conf, section [" SECTION_OPTIONS
        SUBSECTION_OPENCL "])\n", (int)local_work_size);
}

/* --
  This function could be used to calculated the best num
  of keys per crypt for the given format
-- */
static void find_best_gws(struct fmt_main * self, int sequential_id) {

    int step = STEP;
    int show_speed = 0, show_details = 0;
    unsigned long long int max_run_time = cpu(device_info[ocl_gpu_id]) ? 500000000ULL : 1000000000ULL;
    char *tmp_value;

    if (getenv("DETAILS")){
        show_details = 1;
    }

    if ((tmp_value = getenv("STEP"))){
        step = atoi(tmp_value);
        show_speed = 1;
    }
    step = GET_MULTIPLE(step, local_work_size);

    //Call the default function.
    opencl_find_best_gws(
        step, show_speed, show_details, max_run_time, sequential_id, 1);

    fprintf(stderr, "Optimal global worksize %zd\n", global_work_size);
    fprintf(stderr, "(to avoid this test on next run, put \""
        CONFIG_NAME GWS_CONFIG_NAME " = %zd\" in john.conf, section [" SECTION_OPTIONS
        SUBSECTION_OPENCL "])\n", global_work_size);

    create_clobj(global_work_size, self);
}

/* ------- Initialization  ------- */
static void init(struct fmt_main * self) {
    char * tmp_value;
    char * task = "$JOHN/kernels/sha512-ng_kernel.cl";

    opencl_init_dev(ocl_gpu_id);
    source_in_use = device_info[ocl_gpu_id];

    if ((tmp_value = getenv("_TYPE")))
        source_in_use = atoi(tmp_value);

    if (_USE_LOCAL_SOURCE)
        task = "$JOHN/kernels/sha512-ng_kernel_LOCAL.cl";
    opencl_build_kernel_save(task, ocl_gpu_id, NULL, 1, 1);

    // create kernel(s) to execute
    crypt_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_crypt", &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
    cmp_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_cmp", &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating kernel_cmp. Double-check kernel name?");

    global_work_size = get_task_max_size();
    local_work_size = get_default_workgroup();
    opencl_get_user_preferences(CONFIG_NAME);

    //Initialize openCL tuning (library) for this format.
    opencl_init_auto_setup(STEP, 0, 3,
        NULL, CONFIG_NAME DUR_CONFIG_NAME,
        warn, &multi_profilingEvent[1], self, create_clobj, release_clobj,
        sizeof(sha512_password));

    self->methods.crypt_all = crypt_all_benchmark;

    if (source_in_use != device_info[ocl_gpu_id]) {
        fprintf(stderr, "Selected runtime id %d, source (%s)\n", source_in_use, task);
    }

    //Check if local_work_size is a valid number.
    if (local_work_size > get_task_max_work_group_size()){
        fprintf(stderr, "Error: invalid local worksize (LWS). Max value allowed is: %zd\n" ,
               get_task_max_work_group_size());
        local_work_size = 0; //Force find a valid number.
    }
    self->params.max_keys_per_crypt = (global_work_size ? global_work_size: get_task_max_size());

    if (!local_work_size) {
        local_work_size = get_task_max_work_group_size();
        create_clobj(self->params.max_keys_per_crypt, self);
        find_best_lws(self, ocl_gpu_id);
        release_clobj();
    }

    if (global_work_size)
        create_clobj(global_work_size, self);

    else {
        //user chose to die of boredom
        find_best_gws(self, ocl_gpu_id);
    }
    fprintf(stderr, "Local worksize (LWS) %zd, global worksize (GWS) %zd\n",
           local_work_size, global_work_size);
    self->params.min_keys_per_crypt = local_work_size;
    self->params.max_keys_per_crypt = global_work_size;
    self->methods.crypt_all = crypt_all;
}

static void done(void) {
    release_clobj();

    HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
    HANDLE_CLERROR(clReleaseKernel(cmp_kernel), "Release kernel");
    HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
}

/* ------- Check if the ciphertext if a valid SHA-512 ------- */
static int valid(char * ciphertext, struct fmt_main * self) {
    char *p, *q;

    p = ciphertext;
    if (!strncmp(p, "$SHA512$", 8))
        p += 8;

    q = p;
    while (atoi16[ARCH_INDEX(*q)] != 0x7F)
        q++;
    return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *pFmt) {

    static char out[8 + CIPHERTEXT_LENGTH + 1];

    if (!strncmp(ciphertext, "$SHA512$", 8))
        return ciphertext;

    memcpy(out, "$SHA512$", 8);
    memcpy(out + 8, ciphertext, CIPHERTEXT_LENGTH + 1);
    strlwr(out + 8);
    return out;
}

/* ------- To binary functions ------- */
static void * get_binary(char *ciphertext) {
    static unsigned char *out;
    uint64_t * b;
    char *p;
    int i;

    if (!out) out = mem_alloc_tiny(FULL_BINARY_SIZE, MEM_ALIGN_WORD);

    p = ciphertext + 8;
    for (i = 0; i < FULL_BINARY_SIZE; i++) {
        out[i] =
                (atoi16[ARCH_INDEX(*p)] << 4) |
                 atoi16[ARCH_INDEX(p[1])];
        p += 2;
    }
    b = (uint64_t *) out;
    b[0] = SWAP64((unsigned long long) b[3]) - H3;

    return out;
}

static void * get_full_binary(char *ciphertext) {
    static unsigned char *out;
    char *p;
    int i;

    if (!out) out = mem_alloc_tiny(FULL_BINARY_SIZE, MEM_ALIGN_WORD);

    p = ciphertext + 8;
    for (i = 0; i < FULL_BINARY_SIZE; i++) {
        out[i] =
                (atoi16[ARCH_INDEX(*p)] << 4) |
                 atoi16[ARCH_INDEX(p[1])];
        p += 2;
    }

    return out;
}

/* ------- Crypt function ------- */
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt) {
    int count = *pcount;
    size_t gws;

    gws = GET_MULTIPLE_BIGGER(count, local_work_size);

    //Send data to device.
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], pass_buffer, CL_FALSE, 0,
                sizeof(sha512_password) * gws, plaintext, 0, NULL, &multi_profilingEvent[0]),
                "failed in clEnqueueWriteBuffer pass_buffer");

    //Enqueue the kernel
    HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL,
            &gws, &local_work_size, 0, NULL, &multi_profilingEvent[1]),
            "failed in clEnqueueNDRangeKernel");

    //Read back hashes
    HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], hash_buffer, CL_FALSE, 0,
            sizeof(uint32_t) * gws, calculated_hash, 0, NULL, &multi_profilingEvent[2]),
            "failed in reading data back");

    //Do the work
    HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "failed in clFinish");

    return count;
}

static int crypt_all(int *pcount, struct db_salt *_salt) {
    int count = *pcount;
    size_t gws;

    gws = GET_MULTIPLE_BIGGER(count, local_work_size);

    //Send data to device.
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], pass_buffer, CL_FALSE, 0,
                sizeof(sha512_password) * gws, plaintext, 0, NULL, NULL),
                "failed in clEnqueueWriteBuffer pass_buffer");

    //Enqueue the kernel
    HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL,
            &gws, &local_work_size, 0, NULL, profilingEvent),
            "failed in clEnqueueNDRangeKernel");

    //Read back hashes
    HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], hash_buffer, CL_FALSE, 0,
            sizeof(uint32_t) * gws, calculated_hash, 0, NULL, NULL),
            "failed in reading data back");

    //Do the work
    HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "failed in clFinish");

    return count;
}

/* ------- Compare functins ------- */
static int cmp_all(void * binary, int count) {
    uint32_t partial_binary;
    size_t gws;

    gws = GET_MULTIPLE_BIGGER(count, local_work_size);
    partial_binary = (int) ((uint64_t *) binary)[0];
    hash_found = 0;

    //Send data to device.
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], p_binary_buffer, CL_FALSE, 0,
            sizeof(uint32_t), &partial_binary, 0, NULL, NULL),
            "failed in clEnqueueWriteBuffer p_binary_buffer");
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], result_buffer, CL_FALSE, 0,
            sizeof(int), &hash_found, 0, NULL, NULL),
            "failed in clEnqueueWriteBuffer p_binary_buffer");

    //Enqueue the kernel
    HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], cmp_kernel, 1, NULL,
            &gws, &local_work_size, 0, NULL, NULL),
            "failed in clEnqueueNDRangeKernel");

    //Read results back.
    HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], result_buffer, CL_FALSE, 0,
            sizeof(int), &hash_found, 0, NULL, NULL),
            "failed in reading data back");

    //Do the work
    HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "failed in clFinish");

    return hash_found;
}

static int cmp_one(void *binary, int index) {
    return (calculated_hash[index] == (int) ((uint64_t *) binary)[0]);
}

static int cmp_exact(char *source, int index) {
    //I don't know why, but this is called and i have to recheck.
    //If i skip this final test i get:
    //form=raw-sha512-ng-opencl         guesses: 1468 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]
    //.pot CHK:raw-sha512-ng-opencl     guesses: 1452 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]

    uint64_t * binary;
    sha512_hash full_hash;

    crypt_one(index, &full_hash);

    binary = (uint64_t *) get_full_binary(source);
    return !memcmp(binary, (void *) &full_hash, FULL_BINARY_SIZE);
}

/* ------- Binary Hash functions group ------- */
#ifdef DEBUG
static void print_binary(void * binary) {
    uint64_t *bin = binary;
    int i;

    for (i = 0; i < 8; i++)
        fprintf(stderr, "%016lx ", bin[i]);
    puts("(Ok)");
}

static void print_hash(int index) {
    int i;
    sha512_hash hash;
    crypt_one(index, &hash);

    fprintf(stderr, "\n");
    for (i = 0; i < 8; i++)
        fprintf(stderr, "%016lx ", hash.v[i]);
    puts("");
}
#endif

static int binary_hash_0(void * binary) {
#ifdef DEBUG
    print_binary(binary);
#endif
    return *(ARCH_WORD_32 *) binary & 0xF;
}
static int binary_hash_1(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFF; }
static int binary_hash_2(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFF; }
static int binary_hash_3(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFFF; }
static int binary_hash_4(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFF; }
static int binary_hash_5(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFFF; }
static int binary_hash_6(void * binary) { return *(ARCH_WORD_32 *) binary & 0x7FFFFFF; }

//Get Hash functions group.
static int get_hash_0(int index) {
#ifdef DEBUG
    print_hash(index);
#endif
    return calculated_hash[index] & 0xF;
}
static int get_hash_1(int index) { return calculated_hash[index] & 0xFF; }
static int get_hash_2(int index) { return calculated_hash[index] & 0xFFF; }
static int get_hash_3(int index) { return calculated_hash[index] & 0xFFFF; }
static int get_hash_4(int index) { return calculated_hash[index] & 0xFFFFF; }
static int get_hash_5(int index) { return calculated_hash[index] & 0xFFFFFF; }
static int get_hash_6(int index) { return calculated_hash[index] & 0x7FFFFFF; }

/* ------- Format structure ------- */
struct fmt_main fmt_opencl_rawsha512_ng = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
                PLAINTEXT_LENGTH - 1,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
                split,
		get_binary,
                fmt_default_salt,
		fmt_default_source,
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

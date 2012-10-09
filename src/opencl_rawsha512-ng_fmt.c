/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
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
#define ALGORITHM_NAME			"OpenCL"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define LWS_CONFIG			"rawsha512_LWS"
#define GWS_CONFIG			"rawsha512_GWS"
#define DUR_CONFIG			"rawsha512_MaxDuration"

static sha512_password     * plaintext;             // plaintext ciphertexts
static uint32_t            * calculated_hash;       // calculated (partial) hashes

cl_mem pass_buffer;        //Plaintext buffer.
cl_mem hash_buffer;        //Partial hash keys (output).
cl_mem p_binary_buffer;    //To compare partial binary ([3]).
cl_mem result_buffer;      //To get the if a hash was found.
cl_mem pinned_saved_keys, pinned_partial_hashes;

cl_command_queue queue_prof;
cl_kernel crypt_kernel, cmp_kernel;
static int hash_found;

static struct fmt_tests tests[] = {
    {"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "password"},
    {"$SHA512$fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe", "12345678"},
#ifdef DEBUG //Special test cases.
    {"2c80f4c2b3db6b677d328775be4d38c8d8cd9a4464c3b6273644fb148f855e3db51bc33b54f3f6fa1f5f52060509f0e4d350bb0c7f51947728303999c6eff446", "john-user"},
#endif
    {NULL}
};

/* ------- Helper functions ------- */
static unsigned int get_multiple(unsigned int dividend, unsigned int divisor){

    return (dividend / divisor) * divisor;
}

static size_t get_task_max_work_group_size(){
    size_t max_available;

    if (amd_gcn(device_info[ocl_gpu_id]))
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

static void crypt_one(int index, sha512_hash * hash) {
    SHA512_CTX ctx;

    SHA512_Init(&ctx);
    SHA512_Update(&ctx, plaintext[index].pass, plaintext[index].length);
    SHA512_Final((unsigned char *) (hash), &ctx);
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(int gws) {
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
            sizeof(uint64_t) * gws, NULL, &ret_code);
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

    if (amd_gcn(device_info[ocl_gpu_id]) && !
        no_byte_addressable(gpu_amd(device_info[ocl_gpu_id]))) {
        //Fast working memory.
        HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2,
           sizeof(sha512_ctx_buffer) * local_work_size,
           NULL), "Error setting argument 2");
    }
    memset(plaintext, '\0', sizeof(sha512_password) * gws);
    global_work_size = gws;
}

static void release_clobj(void) {
    cl_int ret_code;

    ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys,
            plaintext, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Ummapping saved_plain");

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
static void find_best_workgroup(struct fmt_main *self) {

    size_t max_group_size;

    max_group_size = get_task_max_work_group_size();
    fprintf(stderr, "Max local work size %d, ", (int) max_group_size);

    //Call the default function.
    opencl_find_best_workgroup_limit(self, max_group_size);

    fprintf(stderr, "Optimal local work size %d\n", (int) local_work_size);
    fprintf(stderr, "(to avoid this test on next run, put \""
        LWS_CONFIG " = %d\" in john.conf, section [" SECTION_OPTIONS
        SUBSECTION_OPENCL "])\n", (int)local_work_size);
}

//Allow me to have a configurable step size.
static int get_step(size_t num, int step, int startup){

    if (startup) {

        if (step == 0)
            return STEP;
        else
            return step;
    }

    if (step < 1)
        return num * 2;

    return num + step;
}

//Do the proper test using different sizes.
static cl_ulong gws_test(size_t num) {

    cl_event myEvent;
    cl_int ret_code;
    cl_uint *tmpbuffer;
    cl_ulong startTime, endTime, runtime;
    int i;

    //Prepare buffers.
    create_clobj(num);

    tmpbuffer = mem_alloc(sizeof(sha512_hash) * num);

    if (tmpbuffer == NULL) {
        fprintf(stderr, "Malloc failure in find_best_gws\n");
        exit(EXIT_FAILURE);
    }

    queue_prof = clCreateCommandQueue(context[ocl_gpu_id], devices[ocl_gpu_id],
            CL_QUEUE_PROFILING_ENABLE, &ret_code);
    HANDLE_CLERROR(ret_code, "Failed in clCreateCommandQueue");

    // Set keys
    for (i = 0; i < num; i++) {
        set_key("aaabaabaaa", i);
    }
    //** Get execution time **//
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, pass_buffer, CL_FALSE, 0,
            sizeof(sha512_password) * num, plaintext, 0, NULL, &myEvent),
            "Failed in clEnqueueWriteBuffer");

    HANDLE_CLERROR(clFinish(queue_prof), "Failed in clFinish");
    HANDLE_CLERROR(clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT,
            sizeof(cl_ulong), &startTime, NULL),
            "Failed in clGetEventProfilingInfo I");
    HANDLE_CLERROR(clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END,
            sizeof(cl_ulong), &endTime, NULL),
            "Failed in clGetEventProfilingInfo II");
    HANDLE_CLERROR(clReleaseEvent(myEvent), "Failed in clReleaseEvent");
    runtime = endTime - startTime;

    //** Get execution time **//
    ret_code = clEnqueueNDRangeKernel(queue_prof, crypt_kernel,
            1, NULL, &num, &local_work_size, 0, NULL, &myEvent);

    HANDLE_CLERROR(clFinish(queue_prof), "Failed in clFinish");
    HANDLE_CLERROR(clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT,
            sizeof(cl_ulong), &startTime, NULL),
            "Failed in clGetEventProfilingInfo I");
    HANDLE_CLERROR(clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END,
            sizeof(cl_ulong), &endTime, NULL),
            "Failed in clGetEventProfilingInfo II");
    HANDLE_CLERROR(clReleaseEvent(myEvent), "Failed in clReleaseEvent");
    runtime += endTime - startTime;

    //** Get execution time **//
    HANDLE_CLERROR(clEnqueueReadBuffer(queue_prof, hash_buffer, CL_FALSE, 0,
            sizeof(uint32_t) * num, tmpbuffer, 0, NULL, &myEvent),
            "Failed in clEnqueueReadBuffer");

    HANDLE_CLERROR(clFinish(queue_prof), "Failed in clFinish");
    HANDLE_CLERROR(clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT,
            sizeof(cl_ulong), &startTime, NULL),
            "Failed in clGetEventProfilingInfo I");
    HANDLE_CLERROR(clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END,
            sizeof(cl_ulong), &endTime, NULL),
            "Failed in clGetEventProfilingInfo II");
    HANDLE_CLERROR(clReleaseEvent(myEvent), "Failed in clReleaseEvent");
    runtime += endTime - startTime;

    MEM_FREE(tmpbuffer);
    HANDLE_CLERROR(clReleaseCommandQueue(queue_prof),
            "Failed in clReleaseCommandQueue");
    release_clobj();

     if (ret_code != CL_SUCCESS) {

        if (ret_code != CL_INVALID_WORK_GROUP_SIZE)
            fprintf(stderr, "Error %d\n", ret_code);
        return 0;
    }
    return runtime;
}

/* --
  This function could be used to calculated the best num
  of keys per crypt for the given format
-- */
static void find_best_gws(void) {
    size_t num = 0;
    cl_ulong run_time, min_time = CL_ULONG_MAX;

    int optimal_gws = MIN_KEYS_PER_CRYPT, step = STEP;
    int do_benchmark = 0;
    unsigned int SHAspeed, bestSHAspeed = 0;
    unsigned long long int max_run_time = 1000000000ULL;
    char *tmp_value;

    if ((tmp_value = getenv("STEP"))){
        step = atoi(tmp_value);
        step = get_multiple(step, local_work_size);
        do_benchmark = 1;
    }

    if ((tmp_value = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, DUR_CONFIG)))
        max_run_time = atoi(tmp_value) * 1000000000UL;

    fprintf(stderr, "Calculating best global work size (GWS) for LWS=%zd and max. %llu s duration.\n\n",
            local_work_size, max_run_time / 1000000000ULL);

    if (do_benchmark)
        fprintf(stderr, "Raw speed figures including buffer transfers:\n");

    for (num = get_step(num, step, 1); num < MAX_KEYS_PER_CRYPT;
         num = get_step(num, step, 0)) {
        //Check if hardware can handle the size we are going to try now.
        if (sizeof(sha512_password) * num * 1.2 > get_max_mem_alloc_size(ocl_gpu_id))
            break;

	if (! (run_time = gws_test(num)))
            continue;

        if (!do_benchmark)
            advance_cursor();

        SHAspeed = num / (run_time / 1000000000.);

        if (run_time < min_time)
            min_time = run_time;

        if (do_benchmark) {
            fprintf(stderr, "gws: %8zu\t%12lu c/s %8.3f ms per crypt_all()",
                    num, (long) (num / (run_time / 1000000000.)),
                    (float) run_time / 1000000.);

            if (run_time > max_run_time) {
                fprintf(stderr, " - too slow\n");
                break;
            }
        } else {
            if (run_time > min_time * 20 || run_time > max_run_time)
                break;
        }
        if (((long) SHAspeed - bestSHAspeed) > 10000) {
            if (do_benchmark)
                fprintf(stderr, "+");
            bestSHAspeed = SHAspeed;
            optimal_gws = num;
        }
        if (do_benchmark)
            fprintf(stderr, "\n");
    }
    fprintf(stderr, "Optimal global work size %d\n", optimal_gws);
    fprintf(stderr, "(to avoid this test on next run, put \""
        GWS_CONFIG " = %d\" in john.conf, section [" SECTION_OPTIONS
        SUBSECTION_OPENCL "])\n", optimal_gws);
    global_work_size = optimal_gws;
    create_clobj(optimal_gws);
}

/* ------- Initialization  ------- */
static void init(struct fmt_main *self) {
    int source_in_use;
    char * tmp_value;
    char * task = "$JOHN/sha512-ng_kernel.cl";

    opencl_init_dev(ocl_gpu_id, platform_id);
    source_in_use = device_info[ocl_gpu_id];

    if ((tmp_value = getenv("_TYPE")))
        source_in_use = atoi(tmp_value);

    if (amd_gcn(source_in_use))
        task = "$JOHN/sha512-ng_kernel_LOCAL.cl";
    opencl_build_kernel(task, ocl_gpu_id);

    // create kernel(s) to execute
    crypt_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_crypt", &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
    cmp_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_cmp", &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating kernel_cmp. Double-check kernel name?");

    global_work_size = get_task_max_size();
    local_work_size = 0;

    if (source_in_use != device_info[ocl_gpu_id]) {
        device_info[ocl_gpu_id] = source_in_use;
        fprintf(stderr, "Selected runtime id %d, source (%s)\n", source_in_use, task);
    }

    if ((tmp_value = cfg_get_param(SECTION_OPTIONS,
                                   SUBSECTION_OPENCL, LWS_CONFIG)))
        local_work_size = atoi(tmp_value);

    if ((tmp_value = getenv("LWS")))
        local_work_size = atoi(tmp_value);

    //Check if local_work_size is a valid number.
    if (local_work_size > get_task_max_work_group_size()){
        fprintf(stderr, "Error: invalid local work size (LWS). Max value allowed is: %zd\n" ,
               get_task_max_work_group_size());
        local_work_size = 0; //Force find a valid number.
    }
    self->params.max_keys_per_crypt = global_work_size;

    if (!local_work_size) {
        local_work_size = get_task_max_work_group_size();
        create_clobj(global_work_size);
        find_best_workgroup(self);
        release_clobj();
    }

    if ((tmp_value = cfg_get_param(SECTION_OPTIONS,
                                   SUBSECTION_OPENCL, GWS_CONFIG)))
        global_work_size = atoi(tmp_value);

    if ((tmp_value = getenv("GWS")))
        global_work_size = atoi(tmp_value);

    if (global_work_size)
        create_clobj(global_work_size);

    else {
        //user chose to die of boredom
        global_work_size = get_task_max_size();
        find_best_gws();
    }
    fprintf(stderr, "Local work size (LWS) %d, global work size (GWS) %zd\n",
           (int) local_work_size, global_work_size);
    self->params.max_keys_per_crypt = global_work_size;
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

static char * split(char * ciphertext, int index) {
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
    b[0] = SWAP64((unsigned long long) b[3]) - 0xa54ff53a5f1d36f1ULL;

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
static void crypt_all(int count) {
    //Send data to device.
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], pass_buffer, CL_FALSE, 0,
                sizeof(sha512_password) * global_work_size, plaintext, 0, NULL, NULL),
                "failed in clEnqueueWriteBuffer pass_buffer");

    //Enqueue the kernel
    HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL,
            &global_work_size, &local_work_size, 0, NULL, profilingEvent),
            "failed in clEnqueueNDRangeKernel");

    //Read back hashes
    HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], hash_buffer, CL_FALSE, 0,
            sizeof(uint32_t) * global_work_size, calculated_hash, 0, NULL, NULL),
            "failed in reading data back");

    //Do the work
    HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "failed in clFinish");
}

/* ------- Compare functins ------- */
static int cmp_all(void * binary, int count) {
    uint32_t partial_binary;

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
            &global_work_size, &local_work_size, 0, NULL, NULL),
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
        SALT_SIZE,
        MIN_KEYS_PER_CRYPT,
        MAX_KEYS_PER_CRYPT,
        FMT_CASE | FMT_8_BIT,
        tests
    },
    {
        init,
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

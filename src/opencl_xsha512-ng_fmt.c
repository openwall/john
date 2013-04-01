/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-XSHA-512
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
#include "opencl_xsha512-ng.h"
#include "sha2.h"

#define FORMAT_LABEL			"xsha512-ng-opencl"
#define FORMAT_NAME			"Mac OS X 10.7+ salted SHA-512 (pwlen < " PLAINTEXT_TEXT ")"
#define ALGORITHM_NAME			"OpenCL (inefficient, development use mostly)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define LWS_CONFIG			"xsha512_LWS"
#define GWS_CONFIG			"xsha512_GWS"
#define DUR_CONFIG			"xsha512_MaxDuration"

static sha512_salt         * salt;
static sha512_password     * plaintext;             // plaintext ciphertexts
static uint32_t            * calculated_hash;       // calculated (partial) hashes

cl_mem salt_buffer;        //Salt information.
cl_mem pass_buffer;        //Plaintext buffer.
cl_mem hash_buffer;        //Partial hash keys (output).
cl_mem p_binary_buffer;    //To compare partial binary ([3]).
cl_mem result_buffer;      //To get the if a hash was found.
cl_mem pinned_saved_keys, pinned_partial_hashes;

cl_command_queue queue_prof;
cl_kernel crypt_kernel, cmp_kernel;
static int new_keys, hash_found;

static struct fmt_tests tests[] = {
    {"$LION$bb0489df7b073e715f19f83fd52d08ede24243554450f7159dd65c100298a5820525b55320f48182491b72b4c4ba50d7b0e281c1d98e06591a5e9c6167f42a742f0359c7", "password"},
    {"$LION$74911f723bd2f66a3255e0af4b85c639776d510b63f0b939c432ab6e082286c47586f19b4e2f3aab74229ae124ccb11e916a7a1c9b29c64bd6b0fd6cbd22e7b1f0ba1673", "hello"},
    {"5e3ab14c8bd0f210eddafbe3c57c0003147d376bf4caf75dbffa65d1891e39b82c383d19da392d3fcc64ea16bf8203b1fc3f2b14ab82c095141bb6643de507e18ebe7489", "boobies"},
    {NULL}
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size(){
    size_t max_available;

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
    SHA512_Update(&ctx, salt->salt, SALT_SIZE);
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
    salt_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
            sizeof(sha512_salt), NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating salt_buffer out argument");

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
            (void *) &salt_buffer), "Error setting argument 0");
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
            (void *) &pass_buffer), "Error setting argument 1");
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
            (void *) &hash_buffer), "Error setting argument 2");

    HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 0, sizeof(cl_mem),
            (void *) &hash_buffer), "Error setting argument 0");
    HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 1, sizeof(cl_mem),
            (void *) &p_binary_buffer), "Error setting argument 1");
    HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 2, sizeof(cl_mem),
            (void *) &result_buffer), "Error setting argument 2");

    memset(plaintext, '\0', sizeof(sha512_password) * gws);
    global_work_size = gws;
}

static void release_clobj(void) {
    cl_int ret_code;

    ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys,
            plaintext, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Unmapping saved_plain");

    ret_code = clReleaseMemObject(salt_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing data_info");
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
/* ------- Salt functions ------- */
static void * get_salt(char *ciphertext) {
    static unsigned char out[SALT_SIZE];
    char *p;
    int i;

    ciphertext += 6;
    p = ciphertext;
    for (i = 0; i < sizeof (out); i++) {
        out[i] =
                (atoi16[ARCH_INDEX(*p)] << 4) |
                atoi16[ARCH_INDEX(p[1])];
        p += 2;
    }

    return out;
}

static void set_salt(void * salt_info) {

    salt = salt_info;
}

// Public domain hash function by DJ Bernstein
// We are hashing almost the entire struct
static int salt_hash(void * salt) {
    unsigned char *s = salt;
    unsigned int hash = 5381;
    unsigned int i;

    for (i = 0; i < SALT_SIZE; i++)
        hash = ((hash << 5) + hash) ^ s[i];

    return hash & (SALT_HASH_SIZE - 1);
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

    new_keys = 1;
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
    fprintf(stderr, "Max local worksize %d, ", (int) max_group_size);

    //Call the default function.
    opencl_find_best_workgroup_limit(self, max_group_size);

    fprintf(stderr, "Optimal local worksize %d\n", (int) local_work_size);
}

//Allow me to have a configurable step size.
static int get_step(size_t num, int step, int startup){

    if (startup) {

        if (step == 0)
            return GET_MULTIPLE(STEP, local_work_size);
        else
            return GET_MULTIPLE(step, local_work_size);
    }

    if (step < 1)
        return num * 2;

    return num + step;
}

//Do the proper test using different sizes.
static cl_ulong gws_test(size_t num, struct fmt_main * self, int do_details) {

    cl_event myEvent[4];
    cl_int ret_code;
    cl_uint *tmpbuffer;
    cl_ulong startTime, endTime, runtime = 0;
    int i, loops;

    //Prepare buffers.
    create_clobj(num, self);

    tmpbuffer = mem_alloc(sizeof(sha512_hash) * num);

    if (tmpbuffer == NULL) {
        fprintf(stderr, "Malloc failure in find_best_gws\n");
        exit(EXIT_FAILURE);
    }

    queue_prof = clCreateCommandQueue(context[ocl_gpu_id], devices[ocl_gpu_id],
            CL_QUEUE_PROFILING_ENABLE, &ret_code);
    HANDLE_CLERROR(ret_code, "Failed in clCreateCommandQueue");

    // Set salt.
    set_salt(get_salt("$LION$salt"));

    // Set keys
    for (i = 0; i < num; i++) {
        set_key("aaabaabaaa", i);
    }
    //Send data to device.
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, salt_buffer, CL_FALSE, 0,
            sizeof(sha512_salt), salt, 0, NULL, &myEvent[0]),
            "Failed in clEnqueueWriteBuffer");
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, pass_buffer, CL_FALSE, 0,
            sizeof(sha512_password) * num, plaintext, 0, NULL, &myEvent[1]),
            "Failed in clEnqueueWriteBuffer");

    //Enqueue the kernel
    ret_code = clEnqueueNDRangeKernel(queue_prof, crypt_kernel,
        1, NULL, &num, &local_work_size, 0, NULL, &myEvent[2]);

    //Read hashes back
    HANDLE_CLERROR(clEnqueueReadBuffer(queue_prof, hash_buffer, CL_FALSE, 0,
            sizeof(uint32_t) * num, tmpbuffer, 0, NULL, &myEvent[3]),
            "Failed in clEnqueueReadBuffer");

    loops = 4;
    HANDLE_CLERROR(clFinish(queue_prof), "Failed in clFinish");

    //** Get execution time **//
    for (i = 0; i < loops; i++) {
        HANDLE_CLERROR(clGetEventProfilingInfo(myEvent[i], CL_PROFILING_COMMAND_START,
                sizeof(cl_ulong), &startTime, NULL), "Failed in clGetEventProfilingInfo I");
        HANDLE_CLERROR(clGetEventProfilingInfo(myEvent[i], CL_PROFILING_COMMAND_END,
                sizeof(cl_ulong), &endTime, NULL), "Failed in clGetEventProfilingInfo II");

        runtime += (endTime - startTime);

        if (do_details)
            fprintf(stderr, "%s%.2f ms", warn[i], (double)(endTime-startTime)/1000000.);
    }
    if (do_details)
        fprintf(stderr, "\n");

    // Free resources.
    for (i = 0; i < loops; i++)
        HANDLE_CLERROR(clReleaseEvent(myEvent[i]), "Failed in clReleaseEvent");

    release_clobj();
    MEM_FREE(tmpbuffer);
    HANDLE_CLERROR(clReleaseCommandQueue(queue_prof), "Failed in clReleaseCommandQueue");

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
static void find_best_gws(struct fmt_main * self) {
    size_t num = 0;
    cl_ulong run_time, min_time = CL_ULONG_MAX;

    int optimal_gws = local_work_size, step = STEP;
    int do_benchmark = 0, do_details = 0;
    unsigned int SHAspeed, bestSHAspeed = 0;
    unsigned long long int max_run_time = cpu(device_info[ocl_gpu_id]) ? 500000000ULL : 1000000000ULL;
    char *tmp_value;

    if (getenv("DETAILS")){
        do_details = 1;
    }

    if ((tmp_value = getenv("STEP"))){
        step = atoi(tmp_value);
        do_benchmark = 1;
    }
    step = GET_MULTIPLE(step, local_work_size);

    if ((tmp_value = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, DUR_CONFIG)))
        max_run_time = atoi(tmp_value) * 1000000000ULL;

    fprintf(stderr, "Calculating best global worksize (GWS) for LWS=%zd and max. %llu s duration.\n\n",
            local_work_size, max_run_time / 1000000000ULL);

    if (do_benchmark)
        fprintf(stderr, "Raw speed figures including buffer transfers:\n");

    for (num = get_step(num, step, 1); num; num = get_step(num, step, 0)) {
        //Check if hardware can handle the size we are going to try now.
        if (sizeof(sha512_password) * num * 1.2 > get_max_mem_alloc_size(ocl_gpu_id))
            break;

	if (! (run_time = gws_test(num, self, do_details)))
            continue;

        if (!do_benchmark && !do_details)
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
    fprintf(stderr, "Optimal global worksize %d\n", optimal_gws);
    fprintf(stderr, "(to avoid this test on next run, put \""
        GWS_CONFIG " = %d\" in john.conf, section [" SECTION_OPTIONS
        SUBSECTION_OPENCL "])\n", optimal_gws);
    global_work_size = optimal_gws;
    create_clobj(optimal_gws, self);
}

/* ------- Initialization  ------- */
static void init(struct fmt_main * self) {
    char * tmp_value;
    char * task = "$JOHN/kernels/xsha512-ng_kernel.cl";

    opencl_init_dev(ocl_gpu_id, platform_id);
    opencl_build_kernel_save(task, ocl_gpu_id, NULL, 1, 1);

    // create kernel(s) to execute
    crypt_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_crypt", &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
    cmp_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_cmp", &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating kernel_cmp. Double-check kernel name?");

    global_work_size = get_task_max_size();
    local_work_size = 0;

    if ((tmp_value = cfg_get_param(SECTION_OPTIONS,
                                   SUBSECTION_OPENCL, LWS_CONFIG)))
        local_work_size = atoi(tmp_value);

    if ((tmp_value = getenv("LWS")))
        local_work_size = atoi(tmp_value);

    //Check if local_work_size is a valid number.
    if (local_work_size > get_task_max_work_group_size()){
        local_work_size = 0; //Force find a valid number.
    }
    self->params.max_keys_per_crypt = global_work_size;

    if (!local_work_size) {
        local_work_size = get_task_max_work_group_size();
        create_clobj(global_work_size, self);
        find_best_workgroup(self);
        release_clobj();
    }

    if ((tmp_value = cfg_get_param(SECTION_OPTIONS,
                                   SUBSECTION_OPENCL, GWS_CONFIG)))
        global_work_size = atoi(tmp_value);

    if ((tmp_value = getenv("GWS")))
        global_work_size = atoi(tmp_value);

    //Check if a valid multiple is used.
    global_work_size = GET_MULTIPLE(global_work_size, local_work_size);

    if (global_work_size)
        create_clobj(global_work_size, self);

    else {
        //user chose to die of boredom
        global_work_size = get_task_max_size();
        find_best_gws(self);
    }
    fprintf(stderr, "Local worksize (LWS) %d, global worksize (GWS) %zd\n",
           (int) local_work_size, global_work_size);
    self->params.min_keys_per_crypt = local_work_size;
    self->params.max_keys_per_crypt = global_work_size;
}
#if 0
static void done(void) {
    release_clobj();

    HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
    HANDLE_CLERROR(clReleaseKernel(cmp_kernel), "Release kernel");
    HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
    HANDLE_CLERROR(clReleaseCommandQueue(queue[ocl_gpu_id]), "Release Queue");
    HANDLE_CLERROR(clReleaseContext(context[ocl_gpu_id]), "Release Context");
}
#endif
/* ------- Check if the ciphertext if a valid SHA-512 ------- */
static int valid(char * ciphertext, struct fmt_main * self) {
    char *p, *q;

    p = ciphertext;
    if (!strncmp(p, "$LION$", 6))
        p += 6;

    q = p;
    while (atoi16[ARCH_INDEX(*q)] != 0x7F)
        q++;
    return !*q && q - p == CIPHERTEXT_LENGTH;
}

#if FMT_MAIN_VERSION > 9
static char *split(char *ciphertext, int index, struct fmt_main *pFmt) {
#else
static char * split(char * ciphertext, int index) {
#endif
    static char out[8 + CIPHERTEXT_LENGTH + 1];

    if (!strncmp(ciphertext, "$LION$", 6))
        return ciphertext;

    memcpy(out, "$LION$", 6);
    memcpy(out + 6, ciphertext, CIPHERTEXT_LENGTH + 1);
    strlwr(out + 6);
    return out;
}

/* ------- To binary functions ------- */
static void * get_binary(char *ciphertext) {
    static unsigned char *out;
    uint64_t * b;
    char *p;
    int i;

    if (!out) out = mem_alloc_tiny(FULL_BINARY_SIZE, MEM_ALIGN_WORD);

    ciphertext += 6;
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

    ciphertext += 6;
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
    size_t gws;

    gws = GET_MULTIPLE_BIGGER(count, local_work_size);

    //Send data to device.
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], salt_buffer, CL_FALSE, 0,
            sizeof(sha512_salt), salt, 0, NULL, NULL),
            "failed in clEnqueueWriteBuffer salt_buffer");

    if (new_keys)
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
    new_keys = 0;
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
struct fmt_main fmt_opencl_xsha512_ng = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
                PLAINTEXT_LENGTH - 1,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		tests
	}, {
		init,
#if 0
		done,
#endif

		fmt_default_prepare,
		valid,
                split,
		get_binary,
                get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
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
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

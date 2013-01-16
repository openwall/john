/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-256
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
#include "opencl_cryptsha256.h"
#include "cuda_cryptsha256.h"

#define FORMAT_LABEL			"sha256crypt-ng-opencl"
#define FORMAT_NAME			"sha256crypt"
#define ALGORITHM_NAME			"OpenCL"

#define BENCHMARK_COMMENT		" (rounds=5000)"
#define BENCHMARK_LENGTH		-1

#define LWS_CONFIG			"sha256crypt_LWS"
#define GWS_CONFIG			"sha256crypt_GWS"
#define DUR_CONFIG			"sha256crypt_MaxDuration"

//Checks for source code to pick (parameters, sizes, kernels to execute, etc.)
#define _USE_CPU_SOURCE			(cpu(source_in_use))
#define _USE_GPU_SOURCE			(gpu(source_in_use))
#define _USE_LOCAL_SOURCE		(use_local(source_in_use) || amd_vliw5(source_in_use))
#define _SPLIT_KERNEL_IN_USE		(gpu(source_in_use) || use_local(source_in_use) || amd_vliw5(source_in_use))

static sha256_salt         * salt;
static sha256_password     * plaintext;        // plaintext ciphertexts
static sha256_hash         * calculated_hash;  // calculated hashes

static cl_mem salt_buffer;        //Salt information.
static cl_mem pass_buffer;        //Plaintext buffer.
static cl_mem hash_buffer;        //Hash keys (output).
static cl_mem work_buffer;        //Temporary buffer
static cl_mem pinned_saved_keys, pinned_partial_hashes;

static cl_kernel prepare_kernel[MAXGPUS], main_kernel[MAXGPUS], final_kernel[MAXGPUS];

static int new_keys, source_in_use;
static int split_events[3] = {2, 5, 6 };

static void crypt_all(int count);
static void crypt_all_benchmark(int count);

static struct fmt_tests tests[] = {
    {"$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9", "U*U*U*U*"},
    {"$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A", "U*U***U*"},
    {"$5$9mx1HkCz7G1xho50$O7V7YgleJKLUhcfk9pgzdh3RapEaWqMtEp9UUBAKIPA", "*U*U*U*U"},
    {"$5$V8UMZ8/8.j$GGzeGHZy60318qdLiocMj7DddCnfr7jIcLMDIRy9Tr0", "password"},
    {NULL}
};

/*********
static struct fmt_tests tests[] = {
    {"$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9", "U*U*U*U*"},
    {"$5$LKO/Ute40T3FNF95$fdgfoJEBoMajNxCv3Ru9LyQ0xZgv0OBMQoq80LQ/Qd.", "U*U***U"},
    {"$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A", "U*U***U*"},
    {"$5$9mx1HkCz7G1xho50$O7V7YgleJKLUhcfk9pgzdh3RapEaWqMtEp9UUBAKIPA", "*U*U*U*U"},
    {"$5$kc7lRD1fpYg0g.IP$d7CMTcEqJyTXyeq8hTdu/jB/I6DGkoo62NXbHIR7S43", ""},
#ifdef DEBUG //Special test cases.
    {"$5$EKt.VLXiPjwyv.xe$52wdOp9ixFXMsHDI1JcCw8KJ83IakDP6J7MIEV2OUk0", "1234567"},
    {"$5$V8UMZ8/8.j$GGzeGHZy60318qdLiocMj7DddCnfr7jIcLMDIRy9Tr0", "password"},
#endif
    {NULL}
};
****/

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size(){
    size_t max_available;

    if (_USE_LOCAL_SOURCE)
        max_available = get_local_memory_size(ocl_gpu_id) /
                (sizeof(sha256_ctx) + sizeof(sha256_buffers) + 1);
    else
        max_available = get_max_work_group_size(ocl_gpu_id);

    if (max_available > get_current_work_group_size(ocl_gpu_id, main_kernel[ocl_gpu_id]))
        return get_current_work_group_size(ocl_gpu_id, main_kernel[ocl_gpu_id]);

    return max_available;
}

static size_t get_task_max_size(){
    size_t max_available, multiplier = 3;
    max_available = get_max_compute_units(ocl_gpu_id);

    if amd_gcn(device_info[ocl_gpu_id])
        multiplier = 10;

    if (cpu(device_info[ocl_gpu_id]))
        return max_available * KEYS_PER_CORE_CPU;

    else
        return max_available * multiplier *
                get_current_work_group_size(ocl_gpu_id, main_kernel[ocl_gpu_id]);
}

static size_t get_default_workgroup(){

    if (cpu(device_info[ocl_gpu_id]))
        return 1;
    else
        return 128;
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(int gws, struct fmt_main * self) {
    self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = gws;

    pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id],
            CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
            sizeof(sha256_password) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

    plaintext = (sha256_password *) clEnqueueMapBuffer(queue[ocl_gpu_id],
            pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0,
            sizeof(sha256_password) * gws, 0, NULL, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

    pinned_partial_hashes = clCreateBuffer(context[ocl_gpu_id],
            CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
            sizeof(sha256_hash) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

    calculated_hash = (sha256_hash *) clEnqueueMapBuffer(queue[ocl_gpu_id],
            pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
            sizeof(sha256_hash) * gws, 0, NULL, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

    // create arguments (buffers)
    salt_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
            sizeof(sha256_salt), NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating salt_buffer out argument");

    pass_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
            sizeof(sha256_password) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

    hash_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY,
            sizeof(sha256_hash) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

    work_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE,
            sizeof(sha256_buffers) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument work_area");

    //Set kernel arguments
    HANDLE_CLERROR(clSetKernelArg(main_kernel[ocl_gpu_id], 0, sizeof(cl_mem),
            (void *) &salt_buffer), "Error setting argument 0");
    HANDLE_CLERROR(clSetKernelArg(main_kernel[ocl_gpu_id], 1, sizeof(cl_mem),
            (void *) &pass_buffer), "Error setting argument 1");
    HANDLE_CLERROR(clSetKernelArg(main_kernel[ocl_gpu_id], 2, sizeof(cl_mem),
            (void *) &hash_buffer), "Error setting argument 2");

    if (_SPLIT_KERNEL_IN_USE) {
        //Set prepare kernel arguments
        HANDLE_CLERROR(clSetKernelArg(prepare_kernel[ocl_gpu_id], 0, sizeof(cl_mem),
            (void *) &salt_buffer), "Error setting argument 0");
        HANDLE_CLERROR(clSetKernelArg(prepare_kernel[ocl_gpu_id], 1, sizeof(cl_mem),
            (void *) &pass_buffer), "Error setting argument 1");
        HANDLE_CLERROR(clSetKernelArg(prepare_kernel[ocl_gpu_id], 2, sizeof(cl_mem),
            (void *) &work_buffer), "Error setting argument 2");

        if (_USE_LOCAL_SOURCE) {
            HANDLE_CLERROR(clSetKernelArg(prepare_kernel[ocl_gpu_id], 3,
                sizeof(sha256_buffers) * local_work_size,
                NULL), "Error setting argument 3");
            HANDLE_CLERROR(clSetKernelArg(prepare_kernel[ocl_gpu_id], 4,
                sizeof(sha256_ctx) * local_work_size,
                NULL), "Error setting argument 4");
        }
        //Set crypt kernel arguments
        HANDLE_CLERROR(clSetKernelArg(main_kernel[ocl_gpu_id], 3, sizeof(cl_mem),
            (void *) &work_buffer), "Error setting argument crypt_kernel (3)");

        if (_USE_LOCAL_SOURCE) {
            //Fast working memory.
            HANDLE_CLERROR(clSetKernelArg(main_kernel[ocl_gpu_id], 4,
                sizeof(sha256_buffers) * local_work_size,
                NULL), "Error setting argument 4");
            HANDLE_CLERROR(clSetKernelArg(main_kernel[ocl_gpu_id], 5,
                sizeof(sha256_ctx) * local_work_size,
                NULL), "Error setting argument 5");
        }
        //Set final kernel arguments
        HANDLE_CLERROR(clSetKernelArg(final_kernel[ocl_gpu_id], 0, sizeof(cl_mem),
                (void *) &salt_buffer), "Error setting argument 0");
        HANDLE_CLERROR(clSetKernelArg(final_kernel[ocl_gpu_id], 1, sizeof(cl_mem),
                (void *) &pass_buffer), "Error setting argument 1");
        HANDLE_CLERROR(clSetKernelArg(final_kernel[ocl_gpu_id], 2, sizeof(cl_mem),
                (void *) &hash_buffer), "Error setting argument 2");
        HANDLE_CLERROR(clSetKernelArg(final_kernel[ocl_gpu_id], 3, sizeof(cl_mem),
            (void *) &work_buffer), "Error setting argument crypt_kernel (3)");

        if (_USE_LOCAL_SOURCE) {
            //Fast working memory.
            HANDLE_CLERROR(clSetKernelArg(final_kernel[ocl_gpu_id], 4,
                sizeof(sha256_buffers) * local_work_size,
                NULL), "Error setting argument 4");
            HANDLE_CLERROR(clSetKernelArg(final_kernel[ocl_gpu_id], 5,
                sizeof(sha256_ctx) * local_work_size,
                NULL), "Error setting argument 5");
        }
    }
    memset(plaintext, '\0', sizeof(sha256_password) * gws);
    global_work_size = gws;
}

static void release_clobj(void) {
    cl_int ret_code;

    ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_partial_hashes,
            calculated_hash, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Unmapping out_hashes");

    ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys,
            plaintext, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Unmapping saved_plain");

    ret_code = clReleaseMemObject(salt_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing data_info");
    ret_code = clReleaseMemObject(pass_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing buffer_keys");
    ret_code = clReleaseMemObject(hash_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing buffer_out");
    ret_code = clReleaseMemObject(work_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing work_out");

    ret_code = clReleaseMemObject(pinned_saved_keys);
    HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_keys");

    ret_code = clReleaseMemObject(pinned_partial_hashes);
    HANDLE_CLERROR(ret_code, "Error Releasing pinned_partial_hashes");
}

/* ------- Salt functions ------- */
static void * get_salt(char *ciphertext) {
    static sha256_salt out;
    int len;

    out.rounds = ROUNDS_DEFAULT;
    ciphertext += 3;
    if (!strncmp(ciphertext, ROUNDS_PREFIX,
            sizeof(ROUNDS_PREFIX) - 1)) {
        const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
        char *endp;
        unsigned long int srounds = strtoul(num, &endp, 10);

        if (*endp == '$') {
            ciphertext = endp + 1;
            srounds = srounds < ROUNDS_MIN ?
                    ROUNDS_MIN : srounds;
            out.rounds = srounds > ROUNDS_MAX ?
                    ROUNDS_MAX : srounds;
        }
    }
    for (len = 0; ciphertext[len] != '$'; len++);
    //Assure buffer has no "trash data".
    memset(out.salt, '\0', SALT_LENGTH);
    len = (len > SALT_LENGTH ? SALT_LENGTH : len);

    //Put the tranfered salt on salt buffer.
    memcpy(out.salt, ciphertext, len);
    out.length = len;
    out.final = out.rounds - GET_MULTIPLE(out.rounds, HASH_LOOPS);

    return &out;
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
    len = (len > PLAINTEXT_LENGTH ? PLAINTEXT_LENGTH : len);

    //Put the tranfered key on password buffer.
    memcpy(plaintext[index].pass, key, len);
    plaintext[index].length = len ;
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
static void find_best_lws(struct fmt_main * self, int sequential_id) {

    size_t max_group_size;

    max_group_size = get_task_max_work_group_size();
    fprintf(stderr, "Max local worksize %d, ", (int) max_group_size);

    //Call the default function.
    opencl_find_best_lws(
            max_group_size, sequential_id, main_kernel[sequential_id]);

    fprintf(stderr, "Optimal local worksize %d\n", (int) local_work_size);
    fprintf(stderr, "(to avoid this test on next run, put \""
        LWS_CONFIG " = %d\" in john.conf, section [" SECTION_OPTIONS
        SUBSECTION_OPENCL "])\n", (int)local_work_size);
}

/* --
  This function could be used to calculated the best num
  of keys per crypt for the given format
-- */
static void find_best_gws(struct fmt_main * self, int sequential_id) {

    int step = STEP;
    int show_speed = 0, show_details = 0;
    unsigned long long int max_run_time = cpu(device_info[ocl_gpu_id]) ? 2000000000ULL : 7000000000ULL;
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
        step, show_speed, show_details, max_run_time, sequential_id, ROUNDS_DEFAULT);

    fprintf(stderr, "Optimal global worksize %zd\n", global_work_size);
    fprintf(stderr, "(to avoid this test on next run, put \""
        GWS_CONFIG " = %zd\" in john.conf, section [" SECTION_OPTIONS
        SUBSECTION_OPENCL "])\n", global_work_size);

    create_clobj(global_work_size, self);
}

/* ------- Initialization  ------- */
static void build_kernel(char * task, int sequential_id) {

    opencl_build_kernel_save(task, sequential_id, NULL, 1, 1);

    // create kernel(s) to execute
    main_kernel[sequential_id] = clCreateKernel(program[sequential_id], "kernel_crypt", &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

    if (_SPLIT_KERNEL_IN_USE) {
        prepare_kernel[sequential_id] = clCreateKernel(program[sequential_id], "kernel_prepare", &ret_code);
        HANDLE_CLERROR(ret_code, "Error creating kernel_prepare. Double-check kernel name?");
        final_kernel[sequential_id] = clCreateKernel(program[sequential_id], "kernel_final", &ret_code);
        HANDLE_CLERROR(ret_code, "Error creating kernel_final. Double-check kernel name?");
    }
}

static void init(struct fmt_main * self) {
    int i;
    char * tmp_value;
    char * task;

    for (i = 0; i < get_devices_being_used(); i++) {
        task = "$JOHN/kernels/cryptsha256_kernel_DEFAULT.cl";
        opencl_init_dev(ocl_device_list[i]);
        source_in_use = device_info[ocl_device_list[i]];

        if ((tmp_value = getenv("_TYPE")))
            source_in_use = atoi(tmp_value);

        if (_USE_LOCAL_SOURCE)
            task = "$JOHN/kernels/cryptsha256_kernel_LOCAL.cl";

        else if (_USE_GPU_SOURCE)
            task = "$JOHN/kernels/cryptsha256_kernel_GPU.cl";

        build_kernel(task, ocl_device_list[i]);
    }
    source_in_use = device_info[ocl_gpu_id];
    global_work_size = get_task_max_size();
    local_work_size = get_default_workgroup();

    //Initialize openCL tunning (library) for this format.
    opencl_init_auto_setup(STEP, HASH_LOOPS, ((_SPLIT_KERNEL_IN_USE) ? 8 : 4),
        ((_SPLIT_KERNEL_IN_USE) ? split_events : NULL), DUR_CONFIG,
        warn, &multi_profilingEvent[2], self, create_clobj, release_clobj);

    self->methods.crypt_all = crypt_all_benchmark;

    if (source_in_use != device_info[ocl_gpu_id])
        fprintf(stderr, "Selected runtime id %d, source (%s)\n", source_in_use, task);

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
        find_best_lws(self, ocl_gpu_id);
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

    HANDLE_CLERROR(clReleaseKernel(main_kernel[ocl_gpu_id]), "Release kernel");

    if (_SPLIT_KERNEL_IN_USE) {
        HANDLE_CLERROR(clReleaseKernel(prepare_kernel[ocl_gpu_id]), "Release kernel");
        HANDLE_CLERROR(clReleaseKernel(final_kernel[ocl_gpu_id]), "Release kernel");
    }
    HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
}

/* ------- Check if the ciphertext if a valid SHA-256 crypt ------- */
static int valid(char * ciphertext, struct fmt_main * self) {
    char *pos, *start;

    if (strncmp(ciphertext, "$5$", 3))
            return 0;

    ciphertext += 3;

    if (!strncmp(ciphertext, ROUNDS_PREFIX,
            sizeof(ROUNDS_PREFIX) - 1)) {
        const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
        char *endp;
        if (!strtoul(num, &endp, 10))
                    return 0;
        if (*endp == '$')
            ciphertext = endp + 1;
            }
    for (pos = ciphertext; *pos && *pos != '$'; pos++);
    if (!*pos || pos < ciphertext || pos > &ciphertext[SALT_LENGTH]) return 0;

    start = ++pos;
    while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
    if (*pos || pos - start != CIPHERTEXT_LENGTH) return 0;
    return 1;
}

/* ------- To binary functions ------- */
#define TO_BINARY(b1, b2, b3) \
	value = (ARCH_WORD_32)atoi64[ARCH_INDEX(pos[0])] | \
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out[b1] = value >> 16; \
	out[b2] = value >> 8; \
	out[b3] = value;

static void * get_binary(char * ciphertext) {
    static ARCH_WORD_32 outbuf[BINARY_SIZE / 4];
    ARCH_WORD_32 value;
    char *pos;
    unsigned char *out = (unsigned char*) outbuf;

    pos = strrchr(ciphertext, '$') + 1;

    TO_BINARY(0, 10, 20);
    TO_BINARY(21, 1, 11);
    TO_BINARY(12, 22, 2);
    TO_BINARY(3, 13, 23);
    TO_BINARY(24, 4, 14);
    TO_BINARY(15, 25, 5);
    TO_BINARY(6, 16, 26);
    TO_BINARY(27, 7, 17);
    TO_BINARY(18, 28, 8);
    TO_BINARY(9, 19, 29);
    value = (ARCH_WORD_32) atoi64[ARCH_INDEX(pos[0])] |
            ((ARCH_WORD_32) atoi64[ARCH_INDEX(pos[1])] << 6) |
            ((ARCH_WORD_32) atoi64[ARCH_INDEX(pos[2])] << 12);
    out[31] = value >> 8; \
	out[30] = value; \
    return (void *) out;
}

/* ------- Compare functins ------- */
static int cmp_all(void * binary, int count) {
    uint32_t i;
    uint32_t b = ((uint32_t *) binary)[0];

    for (i = 0; i < count; i++)
        if (b == calculated_hash[i].v[0])
            return 1;
    return 0;
}

static int cmp_one(void * binary, int index) {
    return !memcmp(binary, (void *) &calculated_hash[index], BINARY_SIZE);
}

static int cmp_exact(char * source, int count) {
    return 1;
}

/* ------- Crypt function ------- */
static void crypt_all_benchmark(int count) {
    int i;

    //Send data to device.
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], salt_buffer, CL_FALSE, 0,
            sizeof(sha256_salt), salt, 0, NULL, &multi_profilingEvent[0]),
            "failed in clEnqueueWriteBuffer salt_buffer");

    HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], pass_buffer, CL_FALSE, 0,
            sizeof(sha256_password) * global_work_size, plaintext, 0, NULL, &multi_profilingEvent[1]),
            "failed in clEnqueueWriteBuffer pass_buffer");

    //Enqueue the kernel
    if (_SPLIT_KERNEL_IN_USE) {
        HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], prepare_kernel[ocl_gpu_id], 1, NULL,
            &global_work_size, &local_work_size, 0, NULL, &multi_profilingEvent[4]),
            "failed in clEnqueueNDRangeKernel I");

        for (i = 0; i < 3; i++) {
            HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], main_kernel[ocl_gpu_id], 1, NULL,
                &global_work_size, &local_work_size, 0, NULL,
                &multi_profilingEvent[split_events[i]]),  //2 ,5 ,6
                "failed in clEnqueueNDRangeKernel");
        }
        HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], final_kernel[ocl_gpu_id], 1, NULL,
            &global_work_size, &local_work_size, 0, NULL, &multi_profilingEvent[7]),
            "failed in clEnqueueNDRangeKernel II");
    } else
        HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], main_kernel[ocl_gpu_id], 1, NULL,
            &global_work_size, &local_work_size, 0, NULL, &multi_profilingEvent[2]),
            "failed in clEnqueueNDRangeKernel");

    //Read back hashes
    HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], hash_buffer, CL_FALSE, 0,
            sizeof(sha256_hash) * global_work_size, calculated_hash, 0, NULL, &multi_profilingEvent[3]),
            "failed in reading data back");

    //Do the work
    HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "failed in clFinish");
}

static void crypt_all(int count) {
    int i;
    size_t gws;

    gws = GET_MULTIPLE_BIGGER(count, local_work_size);

    //Send data to device.
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], salt_buffer, CL_FALSE, 0,
            sizeof(sha256_salt), salt, 0, NULL, NULL),
            "failed in clEnqueueWriteBuffer salt_buffer");

    if (new_keys)
        HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], pass_buffer, CL_FALSE, 0,
                sizeof(sha256_password) * gws, plaintext, 0, NULL, NULL),
                "failed in clEnqueueWriteBuffer pass_buffer");

    //Enqueue the kernel
    if (_SPLIT_KERNEL_IN_USE) {
        HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], prepare_kernel[ocl_gpu_id], 1, NULL,
            &gws, &local_work_size, 0, NULL, NULL),
            "failed in clEnqueueNDRangeKernel I");

        for (i = 0; i < (salt->rounds / HASH_LOOPS); i++) {
            HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], main_kernel[ocl_gpu_id], 1, NULL,
                &gws, &local_work_size, 0, NULL, profilingEvent),
                "failed in clEnqueueNDRangeKernel");
            HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "Error running loop kernel");
            opencl_process_event();
        }
        HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], final_kernel[ocl_gpu_id], 1, NULL,
            &gws, &local_work_size, 0, NULL, NULL),
            "failed in clEnqueueNDRangeKernel II");
    } else
        HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], main_kernel[ocl_gpu_id], 1, NULL,
            &gws, &local_work_size, 0, NULL, profilingEvent),
            "failed in clEnqueueNDRangeKernel");

    //Read back hashes
    HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], hash_buffer, CL_FALSE, 0,
            sizeof(sha256_hash) * gws, calculated_hash, 0, NULL, NULL),
            "failed in reading data back");

    //Do the work
    HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "failed in clFinish");
    new_keys = 0;
}

/* ------- Binary Hash functions group ------- */
#ifdef DEBUG
static void print_binary(void * binary) {
    uint32_t *bin = binary;
    int i;

    for (i = 0; i < 8; i++)
        fprintf(stderr, "%016x ", bin[i]);
    puts("(Ok)");
}

static void print_hash() {
    int i;

    fprintf(stderr, "\n");
    for (i = 0; i < 8; i++)
        fprintf(stderr, "%016x ", calculated_hash[0].v[i]);
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
    return calculated_hash[index].v[0] & 0xF;
}
static int get_hash_1(int index) { return calculated_hash[index].v[0] & 0xFF; }
static int get_hash_2(int index) { return calculated_hash[index].v[0] & 0xFFF; }
static int get_hash_3(int index) { return calculated_hash[index].v[0] & 0xFFFF; }
static int get_hash_4(int index) { return calculated_hash[index].v[0] & 0xFFFFF; }
static int get_hash_5(int index) { return calculated_hash[index].v[0] & 0xFFFFFF; }
static int get_hash_6(int index) { return calculated_hash[index].v[0] & 0x7FFFFFF; }

/* ------- Format structure ------- */
struct fmt_main fmt_opencl_cryptsha256_ng = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
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
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		done,
		fmt_default_prepare,
		valid,
		fmt_default_split,
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
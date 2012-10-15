/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-512
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
#include "opencl_cryptsha512.h"
#include <time.h>

#define FORMAT_LABEL			"sha512crypt-opencl"
#define FORMAT_NAME			"sha512crypt"
#define ALGORITHM_NAME			"OpenCL"

#define BENCHMARK_COMMENT		" (rounds=5000)"
#define BENCHMARK_LENGTH		-1

#define LWS_CONFIG			"sha512crypt_LWS"
#define GWS_CONFIG			"sha512crypt_GWS"
#define DUR_CONFIG			"sha512crypt_MaxDuration"

static sha512_salt         * salt;
static sha512_password     * plaintext;        // plaintext ciphertexts
static sha512_hash         * calculated_hash;  // calculated hashes
static int                 fast_mode = FALSE;

cl_mem salt_buffer;        //Salt information.
cl_mem pass_buffer;        //Plaintext buffer.
cl_mem hash_buffer;        //Hash keys (output).
cl_mem work_buffer;        //Temporary buffer
cl_mem pinned_saved_keys, pinned_partial_hashes;

cl_command_queue queue_prof;
cl_kernel prepare_kernel, crypt_kernel, final_kernel;

static int new_keys, source_in_use;

static struct fmt_tests tests[] = {
    {"$6$LKO/Ute40T3FNF95$6S/6T2YuOIHY0N3XpLKABJ3soYcXD9mB7uVbtEZDj/LNscVhZoZ9DEH.sBciDrMsHOWOoASbNLTypH/5X26gN0", "U*U*U*U*"},
    {"$6$LKO/Ute40T3FNF95$wK80cNqkiAUzFuVGxW6eFe8J.fSVI65MD5yEm8EjYMaJuDrhwe5XXpHDJpwF/kY.afsUs1LlgQAaOapVNbggZ1", "U*U***U"},
    {"$6$LKO/Ute40T3FNF95$YS81pp1uhOHTgKLhSMtQCr2cDiUiN03Ud3gyD4ameviK1Zqz.w3oXsMgO6LrqmIEcG3hiqaUqHi/WEE2zrZqa/", "U*U***U*"},
    {"$6$OmBOuxFYBZCYAadG$WCckkSZok9xhp4U1shIZEV7CCVwQUwMVea7L3A77th6SaE9jOPupEMJB.z0vIWCDiN9WLh2m9Oszrj5G.gt330", "*U*U*U*U"},
    {"$6$ojWH1AiTee9x1peC$QVEnTvRVlPRhcLQCk/HnHaZmlGAAjCfrAN0FtOsOnUk5K5Bn/9eLHHiRzrTzaIKjW9NTLNIBUCtNVOowWS2mN.", ""},
#ifdef DEBUG //Special test cases.
    {"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1", "Hello world!"},
    {"$6$rounds=391939$saltstring$P5HDSEq.sTdSBNmknrLQpg6UHp.9.vuEv6QibJNP8ecoNGo9Wa.3XuR7LKu8FprtxGDpGv17Y27RfTHvER4kI0", "amy"},
    {"$6$rounds=391939$saltstring$JAjUHgEFBJB1lSM25mYGFdH42OOBZ8eytTvKCleaR4jI5cSs0KbATSYyhLj3tkMhmU.fUKfsZkT5y0EYbTLcr1", "amy99"},
    {"$6$TtrrO3IN$D7Qz38n3JOn4Cc6y0340giveWD8uUvBAdPeCI0iC1cGYCmYHDrVXUEoSf3Qp5TRgo7x0BXN4lKNEj7KOvFTZV1", ">7fSy+N\\W=o@Wd&"},
    {"$6$yRihAbCh$V5Gr/BhMSMkl6.fBt4TV5lWYY6MhjqApHxDL04HeTgeAX.mZT/0pDDYvArvmCfmMVa/XxzzOBXf1s7TGa2FDL0", "0H@<:IS:BfM\"V"},
    {"$6$rounds=4900$saltstring$p3pnU2njiDujK0Pp5us7qlUvkjVaAM0GilTprwyZ1ZiyGKvsfNyDCnlmc.9ahKmDqyqKXMH3frK1I/oEiEbTK/", "Hello world!"},
#endif
    {NULL}
};

/* ------- Helper functions ------- */
static unsigned int get_multiple(unsigned int dividend, unsigned int divisor){

    return (dividend / divisor) * divisor;
}

static size_t get_task_max_work_group_size(){
    size_t max_available;

    if (use_local(source_in_use))
        max_available = get_local_memory_size(ocl_gpu_id) /
                (sizeof(sha512_password) + sizeof(sha512_ctx) +
                 sizeof(sha512_buffers)) - 1;
    else if (gpu(source_in_use))
        max_available = get_local_memory_size(ocl_gpu_id) /
                sizeof(sha512_password);
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
        return max_available * get_current_work_group_size(ocl_gpu_id, crypt_kernel) * 2;
}

static size_t get_safe_workgroup(){

    if (cpu(device_info[ocl_gpu_id]))
        return 1;

    else
        return 64;
}

static size_t get_default_workgroup(){
    size_t max_available;
    max_available = get_task_max_work_group_size();

    if (gpu_nvidia(device_info[ocl_gpu_id]) ||
       (!cpu(device_info[ocl_gpu_id]) && fast_mode)) {
        global_work_size = get_multiple(global_work_size, max_available);
        return max_available;

    } else
        return get_safe_workgroup();
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
            sizeof(sha512_hash) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

    calculated_hash = (sha512_hash *) clEnqueueMapBuffer(queue[ocl_gpu_id],
            pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
            sizeof(sha512_hash) * gws, 0, NULL, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

    // create arguments (buffers)
    salt_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
            sizeof(sha512_salt), NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating salt_buffer out argument");

    pass_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
            sizeof(sha512_password) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

    hash_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY,
            sizeof(sha512_hash) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

    work_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE,
            sizeof(sha512_buffers) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument work_area");

    //Set kernel arguments
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
            (void *) &salt_buffer), "Error setting argument 0");
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
            (void *) &pass_buffer), "Error setting argument 1");
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
            (void *) &hash_buffer), "Error setting argument 2");

    if (gpu(source_in_use) || use_local(source_in_use)) {
        //Set prepare kernel arguments
        HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 0, sizeof(cl_mem),
            (void *) &salt_buffer), "Error setting argument 0");
        HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 1, sizeof(cl_mem),
            (void *) &pass_buffer), "Error setting argument 1");
        HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 2, sizeof(cl_mem),
            (void *) &work_buffer), "Error setting argument 2");

        //Fast working memory.
        HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 3,
            sizeof(sha512_password) * local_work_size,
            NULL), "Error setting argument 3");

        if (use_local(source_in_use)) {
            HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 4,
                sizeof(sha512_buffers) * local_work_size,
                NULL), "Error setting argument 4");
            HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 5,
                sizeof(sha512_ctx) * local_work_size,
                NULL), "Error setting argument 5");
        }
        //Set crypt kernel arguments
        HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem),
            (void *) &work_buffer), "Error setting argument crypt_kernel (3)");

        if (use_local(source_in_use)) {
            //Fast working memory.
            HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4,
                sizeof(sha512_buffers) * local_work_size,
                NULL), "Error setting argument 4");
            HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5,
                sizeof(sha512_ctx) * local_work_size,
                NULL), "Error setting argument 5");
        }
        //Set final kernel arguments
        HANDLE_CLERROR(clSetKernelArg(final_kernel, 0, sizeof(cl_mem),
                (void *) &salt_buffer), "Error setting argument 0");
        HANDLE_CLERROR(clSetKernelArg(final_kernel, 1, sizeof(cl_mem),
                (void *) &pass_buffer), "Error setting argument 1");
        HANDLE_CLERROR(clSetKernelArg(final_kernel, 2, sizeof(cl_mem),
                (void *) &hash_buffer), "Error setting argument 2");
        HANDLE_CLERROR(clSetKernelArg(final_kernel, 3, sizeof(cl_mem),
            (void *) &work_buffer), "Error setting argument crypt_kernel (3)");

        if (use_local(source_in_use)) {
            //Fast working memory.
            HANDLE_CLERROR(clSetKernelArg(final_kernel, 4,
                sizeof(sha512_buffers) * local_work_size,
                NULL), "Error setting argument 4");
            HANDLE_CLERROR(clSetKernelArg(final_kernel, 5,
                sizeof(sha512_ctx) * local_work_size,
                NULL), "Error setting argument 5");
        }
    }
    memset(plaintext, '\0', sizeof(sha512_password) * gws);
    global_work_size = gws;
}

static void release_clobj(void) {
    cl_int ret_code;

    ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_partial_hashes,
            calculated_hash, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Ummapping out_hashes");

    ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys,
            plaintext, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Ummapping saved_plain");

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
    static sha512_salt out;
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
            out.rounds = srounds < ROUNDS_MIN ?
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
    out.initial = get_multiple(out.rounds, HASH_LOOPS);

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
    int i, loops;

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

    // Set salt.
    set_salt(get_salt("$6$saltstring$"));
    salt->initial = salt->rounds - get_multiple(salt->rounds, HASH_LOOPS);

    // Set keys
    for (i = 0; i < num; i++) {
        set_key("aaabaabaaa", i);
    }
    //** Get execution time **//
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, salt_buffer, CL_FALSE, 0,
            sizeof(sha512_salt), salt, 0, NULL, &myEvent),
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
    runtime += endTime - startTime;

    //** Get execution time **//
    if (gpu(source_in_use) || use_local(source_in_use)) {
        ret_code = clEnqueueNDRangeKernel(queue_prof, prepare_kernel,
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
    }

    loops = gpu(source_in_use) || use_local(source_in_use) ? (salt->rounds / HASH_LOOPS) : 1;

    //** Get execution time **//
    for (i = 0; i < loops; i++)
    {
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
    }

    //** Get execution time **//
    HANDLE_CLERROR(clEnqueueReadBuffer(queue_prof, hash_buffer, CL_FALSE, 0,
            sizeof(sha512_hash) * num, tmpbuffer, 0, NULL, &myEvent),
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
    unsigned long long int max_run_time = 10000000000ULL;
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

	if (! (run_time = gws_test(num)))
            continue;

        if (!do_benchmark)
            advance_cursor();

        SHAspeed = 5000 * num / (run_time / 1000000000.);

        if (run_time < min_time)
            min_time = run_time;

        if (do_benchmark) {
            fprintf(stderr, "gws: %6zu\t%6lu c/s%10u rounds/s%8.3f sec per crypt_all()",
                    num, (long) (num / (run_time / 1000000000.)), SHAspeed,
                    (float) run_time / 1000000000.);

            if (run_time > max_run_time) {
                fprintf(stderr, " - too slow\n");
                break;
            }
        } else {
            if (run_time > min_time * 10 || run_time > max_run_time)
                break;
        }
        if (SHAspeed > (1.01 * bestSHAspeed)) {
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
static void init(struct fmt_main * self) {
    char * tmp_value;
    char * task = "$JOHN/cryptsha512_kernel_DEFAULT.cl";
    uint64_t startTime, runtime;

    opencl_init_dev(ocl_gpu_id, platform_id);
    startTime = (unsigned long) time(NULL);
    source_in_use = device_info[ocl_gpu_id];

    if ((tmp_value = getenv("_TYPE")))
        source_in_use = atoi(tmp_value);

    if ((tmp_value = getenv("_FAST")))
        fast_mode = TRUE;

    if (use_local(source_in_use))
            task = "$JOHN/cryptsha512_kernel_LOCAL.cl";
    else if (gpu(source_in_use)) {
        fprintf(stderr, "Building the kernel, this could take a while\n");
        task = "$JOHN/cryptsha512_kernel_GPU.cl";
    }
    fflush(stdout);
    opencl_build_kernel(task, ocl_gpu_id);

    if ((runtime = (unsigned long) (time(NULL) - startTime)) > 2UL)
        fprintf(stderr, "Elapsed time: %lu seconds\n", runtime);
    fflush(stdout);

    // create kernel(s) to execute
    crypt_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_crypt", &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

    if (gpu(source_in_use) || use_local(source_in_use)) {
        prepare_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_prepare", &ret_code);
        HANDLE_CLERROR(ret_code, "Error creating kernel_prepare. Double-check kernel name?");
        final_kernel = clCreateKernel(program[ocl_gpu_id], "kernel_final", &ret_code);
        HANDLE_CLERROR(ret_code, "Error creating kernel_final. Double-check kernel name?");
    }
    global_work_size = get_task_max_size();
    local_work_size = get_default_workgroup();

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
        create_clobj(global_work_size);
        find_best_workgroup(self);
        release_clobj();
    }

    if ((tmp_value = cfg_get_param(SECTION_OPTIONS,
                                   SUBSECTION_OPENCL, GWS_CONFIG)))
        global_work_size = atoi(tmp_value);

    if ((tmp_value = getenv("GWS")))
        global_work_size = atoi(tmp_value);

    //Check if a valid multiple is used.
    global_work_size = get_multiple(global_work_size, local_work_size);

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

/* ------- Check if the ciphertext if a valid SHA-512 crypt ------- */
static int valid(char * ciphertext, struct fmt_main * self) {
    char *pos, *start;

    if (strncmp(ciphertext, "$6$", 3))
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
    char *pos = strrchr(ciphertext, '$') + 1;
    unsigned char *out = (unsigned char*) outbuf;
    int i = 0;

    do {
        TO_BINARY(i, (i + 21) % 63, (i + 42) % 63);
        i = (i + 22) % 63;
    } while (i != 21);

    value = (ARCH_WORD_32) atoi64[ARCH_INDEX(pos[0])] |
            ((ARCH_WORD_32) atoi64[ARCH_INDEX(pos[1])] << 6) |
            ((ARCH_WORD_32) atoi64[ARCH_INDEX(pos[2])] << 12);
    out[63] = value;

    return (void *) out;
}

/* ------- Compare functins ------- */
static int cmp_all(void * binary, int count) {
    uint32_t i;
    uint64_t b = ((uint64_t *) binary)[0];

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
static void crypt_all(int count) {
    int i;

    //Send data to device.
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], salt_buffer, CL_FALSE, 0,
            sizeof(sha512_salt), salt, 0, NULL, NULL),
            "failed in clEnqueueWriteBuffer salt_buffer");

    if (new_keys)
        HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], pass_buffer, CL_FALSE, 0,
                sizeof(sha512_password) * global_work_size, plaintext, 0, NULL, NULL),
                "failed in clEnqueueWriteBuffer pass_buffer");

    //Enqueue the kernel
    if (gpu(source_in_use) || use_local(source_in_use)) {
        HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], prepare_kernel, 1, NULL,
            &global_work_size, &local_work_size, 0, NULL, NULL),
            "failed in clEnqueueNDRangeKernel I");

        for (i = 0; i < (salt->rounds / HASH_LOOPS); i++) {
            HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL,
                &global_work_size, &local_work_size, 0, NULL, profilingEvent),
                "failed in clEnqueueNDRangeKernel");
        }
        HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], final_kernel, 1, NULL,
            &global_work_size, &local_work_size, 0, NULL, NULL),
            "failed in clEnqueueNDRangeKernel II");
    } else
        HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL,
            &global_work_size, &local_work_size, 0, NULL, profilingEvent),
            "failed in clEnqueueNDRangeKernel");

    //Read back hashes
    HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], hash_buffer, CL_FALSE, 0,
            sizeof(sha512_hash) * global_work_size, calculated_hash, 0, NULL, NULL),
            "failed in reading data back");

    //Do the work
    HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "failed in clFinish");
    new_keys = 0;
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

static void print_hash() {
    int i;

    fprintf(stderr, "\n");
    for (i = 0; i < 8; i++)
        fprintf(stderr, "%016lx ", calculated_hash[0].v[i]);
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
struct fmt_main fmt_opencl_cryptsha512 = {
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
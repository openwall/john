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

#define LWS_CONFIG			"cryptsha512_LWS"
#define GWS_CONFIG			"cryptsha512_GWS"

static sha512_salt         salt;
static sha512_password     *plaintext;        // plaintext ciphertexts
static sha512_hash         *calculated_hash;  // calculated hashes

cl_mem salt_buffer;        //Salt information.
cl_mem pass_buffer;        //Plaintext buffer.
cl_mem hash_buffer;        //Hash keys (output)
cl_mem pinned_saved_keys, pinned_partial_hashes;

cl_command_queue queue_prof;
cl_kernel crypt_kernel;

static int new_keys, new_salt;

static struct fmt_tests tests[] = {
    {"$6$LKO/Ute40T3FNF95$6S/6T2YuOIHY0N3XpLKABJ3soYcXD9mB7uVbtEZDj/LNscVhZoZ9DEH.sBciDrMsHOWOoASbNLTypH/5X26gN0", "U*U*U*U*"},
    {"$6$LKO/Ute40T3FNF95$wK80cNqkiAUzFuVGxW6eFe8J.fSVI65MD5yEm8EjYMaJuDrhwe5XXpHDJpwF/kY.afsUs1LlgQAaOapVNbggZ1", "U*U***U"},
    {"$6$LKO/Ute40T3FNF95$YS81pp1uhOHTgKLhSMtQCr2cDiUiN03Ud3gyD4ameviK1Zqz.w3oXsMgO6LrqmIEcG3hiqaUqHi/WEE2zrZqa/", "U*U***U*"},
    {"$6$OmBOuxFYBZCYAadG$WCckkSZok9xhp4U1shIZEV7CCVwQUwMVea7L3A77th6SaE9jOPupEMJB.z0vIWCDiN9WLh2m9Oszrj5G.gt330", "*U*U*U*U"},
    {"$6$ojWH1AiTee9x1peC$QVEnTvRVlPRhcLQCk/HnHaZmlGAAjCfrAN0FtOsOnUk5K5Bn/9eLHHiRzrTzaIKjW9NTLNIBUCtNVOowWS2mN.", ""},
    {NULL}
};

/*** Special test cases.
 * static struct fmt_tests extended_tests[] = {
 *     {"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1", "Hello world!"},
 *     {"$6$rounds=391939$saltstring$P5HDSEq.sTdSBNmknrLQpg6UHp.9.vuEv6QibJNP8ecoNGo9Wa.3XuR7LKu8FprtxGDpGv17Y27RfTHvER4kI0", "amy"},
 *     {"$6$rounds=391939$saltstring$JAjUHgEFBJB1lSM25mYGFdH42OOBZ8eytTvKCleaR4jI5cSs0KbATSYyhLj3tkMhmU.fUKfsZkT5y0EYbTLcr1", "amy99"},
 *     {"$6$TtrrO3IN$D7Qz38n3JOn4Cc6y0340giveWD8uUvBAdPeCI0iC1cGYCmYHDrVXUEoSf3Qp5TRgo7x0BXN4lKNEj7KOvFTZV1", ">7fSy+N\\W=o@Wd&"},
 *     {"$6$yRihAbCh$V5Gr/BhMSMkl6.fBt4TV5lWYY6MhjqApHxDL04HeTgeAX.mZT/0pDDYvArvmCfmMVa/XxzzOBXf1s7TGa2FDL0", "0H@<:IS:BfM\"V"},
 *     {"$6$rounds=4900$saltstring$p3pnU2njiDujK0Pp5us7qlUvkjVaAM0GilTprwyZ1ZiyGKvsfNyDCnlmc.9ahKmDqyqKXMH3frK1I/oEiEbTK/", "Hello world!"},
 *     {NULL}
 * };
 ***/ 

/* ------- Helper functions ------- */
unsigned int get_task_max_work_group_size(){
    unsigned int max_available;

    if (gpu_amd(device_info[gpu_id]))
        max_available = (get_local_memory_size(gpu_id) -
                sizeof(sha512_salt)) /
                sizeof(working_memory);
    else if (gpu_nvidia(device_info[gpu_id]))
        max_available = (get_local_memory_size(gpu_id) -
                sizeof(sha512_salt)) /
                sizeof(sha512_password);
    else
        max_available = get_max_work_group_size(gpu_id);

    if (max_available > get_current_work_group_size(gpu_id, crypt_kernel))
        return get_current_work_group_size(gpu_id, crypt_kernel);

    return max_available;
}

unsigned int get_task_max_size(){
    unsigned int max_available;
    max_available = get_max_compute_units(gpu_id);

    if (cpu(device_info[gpu_id]))
        return max_available * KEYS_PER_CORE_CPU;

    return max_available * KEYS_PER_CORE_GPU;
}

size_t get_safe_workgroup(){

    if (cpu(device_info[gpu_id]))
        return 1;

    else
        return 32;
}

size_t get_default_workgroup(){
    unsigned int max_available;
    max_available = get_task_max_work_group_size();

    if (gpu_nvidia(device_info[gpu_id])) {
        global_work_size = (global_work_size / max_available) * max_available; //Find a multiple.
        return max_available;

    } else
        return get_safe_workgroup();
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(int gws) {
    pinned_saved_keys = clCreateBuffer(context[gpu_id],
            CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
            sizeof(sha512_password) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

    plaintext = (sha512_password *) clEnqueueMapBuffer(queue[gpu_id],
            pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0,
            sizeof(sha512_password) * gws, 0, NULL, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

    pinned_partial_hashes = clCreateBuffer(context[gpu_id],
            CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
            sizeof(sha512_hash) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

    calculated_hash = (sha512_hash *) clEnqueueMapBuffer(queue[gpu_id],
            pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
            sizeof(sha512_hash) * gws, 0, NULL, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

    // create arguments (buffers)
    salt_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
            sizeof(sha512_salt), NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating data_info out argument");

    pass_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
            sizeof(sha512_password) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

    hash_buffer = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
            sizeof(sha512_hash) * gws, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

    //Set kernel arguments
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof (cl_mem),
            (void *) &salt_buffer), "Error setting argument 0");
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof (cl_mem),
            (void *) &pass_buffer), "Error setting argument 1");
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof (cl_mem),
            (void *) &hash_buffer), "Error setting argument 2");

    if (gpu_amd(device_info[gpu_id])) {
        HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3,   //Fast working memory.
           sizeof (sha512_salt),
           NULL), "Error setting argument 3");
        HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4,   //Fast working memory.
           sizeof (working_memory) * local_work_size,
           NULL), "Error setting argument 4");

    } else if (gpu_nvidia(device_info[gpu_id])) {
        HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3,   //Fast working memory.
           sizeof (sha512_salt),
           NULL), "Error setting argument 3");
        HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4,   //Fast working memory.
           sizeof (sha512_password) * local_work_size,
           NULL), "Error setting argument 4");
    }
    memset(plaintext, '\0', sizeof(sha512_password) * gws);
    memset(&salt, '\0', sizeof(sha512_salt));
    global_work_size = gws;
}

static void release_clobj(void) {
    cl_int ret_code;

    ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_partial_hashes,
            calculated_hash, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Ummapping out_hashes");

    ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys,
            plaintext, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Ummapping saved_plain");

    ret_code = clReleaseMemObject(salt_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing data_info");
    ret_code = clReleaseMemObject(pass_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing buffer_keys");
    ret_code = clReleaseMemObject(hash_buffer);
    HANDLE_CLERROR(ret_code, "Error Releasing buffer_out");

    ret_code = clReleaseMemObject(pinned_saved_keys);
    HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_keys");

    ret_code = clReleaseMemObject(pinned_partial_hashes);
    HANDLE_CLERROR(ret_code, "Error Releasing pinned_partial_hashes");
}

/* ------- Salt functions ------- */
static void *get_salt(char *ciphertext) {
    int end = 0, i, len = strlen(ciphertext);
    static unsigned char ret[50];
    for (i = len - 1; i >= 0; i--)
        if (ciphertext[i] == '$') {
            end = i;
            break;
        }

    for (i = 0; i < end; i++)
        ret[i] = ciphertext[i];
    ret[end] = 0;
    return (void *) ret;
}

static void set_salt(void *salt_info) {
    int len = strlen(salt_info);
    unsigned char offset = 0;
    static char currentsalt[64];

    memcpy(currentsalt, (char *) salt_info, len + 1);
    salt.rounds = ROUNDS_DEFAULT;

    if (strncmp((char *) "$6$", (char *) currentsalt, 3) == 0)
        offset += 3;

    if (strncmp((char *) currentsalt + offset, (char *) "rounds=", 7) == 0) {
        const char *num = currentsalt + offset + 7;
        char *endp;
        unsigned long int srounds = strtoul(num, &endp, 10);

        if (*endp == '$') {
            endp += 1;
            salt.rounds =
                    MAX(ROUNDS_MIN, MIN(srounds, ROUNDS_MAX));
        }
        offset = endp - currentsalt;
    }
    //Assure buffer has no "trash data".	
    memset(salt.salt, '\0', SALT_LENGTH);
    len = strlen(currentsalt + offset);
    len = (len > SALT_LENGTH ? SALT_LENGTH : len);

    //Put the tranfered salt on salt buffer.
    memcpy(salt.salt, currentsalt + offset, len);
    salt.length = len ;
    new_salt = 1;          
}

/* ------- Key functions ------- */
static void set_key(char *key, int index) {
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

static char *get_key(int index) {
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
static void find_best_workgroup(void) {
    cl_event myEvent;
    cl_ulong startTime, endTime, min_time = CL_ULONG_MAX;
    size_t my_work_group = 1;
    cl_int ret_code;
    int i;
    size_t max_group_size;

    max_group_size = get_max_work_group_size(gpu_id);
    queue_prof = clCreateCommandQueue(context[gpu_id], devices[gpu_id],
            CL_QUEUE_PROFILING_ENABLE, &ret_code);
    HANDLE_CLERROR(ret_code, "Failed in clCreateCommandQueue");
    fprintf(stderr, "Max local work size %d ", (int) max_group_size);
    local_work_size = 1;
    max_group_size = get_task_max_work_group_size();

    // Set salt.
    set_salt("$6$saltstring$");

    // Set keys
    for (i = 0; i < global_work_size; i++) {
        set_key("aaabaabaaa", i);
    }
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, salt_buffer, CL_TRUE, 0,
            sizeof (sha512_salt), &salt, 0, NULL, NULL),
            "Failed in clEnqueueWriteBuffer I");
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, pass_buffer, CL_TRUE, 0,
            sizeof (sha512_password) * global_work_size,
            plaintext, 0, NULL, NULL),
            "Failed in clEnqueueWriteBuffer II");

    my_work_group = get_safe_workgroup();

    // Find minimum time
    for (; (int) my_work_group <= (int) max_group_size;
         my_work_group *= 2) {
        advance_cursor();
        ret_code = clEnqueueNDRangeKernel(queue_prof, crypt_kernel,
                1, NULL, &global_work_size, &my_work_group, 0, NULL, &myEvent);
        HANDLE_CLERROR(clFinish(queue_prof), "Failed in clFinish");

        if (ret_code != CL_SUCCESS) {

            if (ret_code != CL_INVALID_WORK_GROUP_SIZE)
                fprintf(stderr, "Error %d\n", ret_code);
            continue;
        }
        //Get profile information
        HANDLE_CLERROR(clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT,
                sizeof (cl_ulong), &startTime, NULL),
                "Failed in clGetEventProfilingInfo I");
        HANDLE_CLERROR(clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END,
                sizeof (cl_ulong), &endTime, NULL),
                "Failed in clGetEventProfilingInfo II");
        HANDLE_CLERROR(clReleaseEvent(myEvent), "Failed in clReleaseEvent");

        if ((endTime - startTime) * 1.01 < min_time) {
            min_time = endTime - startTime;
            local_work_size = my_work_group;
        }
    }
    fprintf(stderr, "Optimal local work size %d\n", (int) local_work_size);
    fprintf(stderr, "(to avoid this test on next run, put \""
        LWS_CONFIG " = %d\" in john.conf, section [" SECTION_OPTIONS
        SUBSECTION_OPENCL "])\n", (int)local_work_size);
    HANDLE_CLERROR(clReleaseCommandQueue(queue_prof),
            "Failed in clReleaseCommandQueue");
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

/* --
  This function could be used to calculated the best num
  of keys per crypt for the given format
-- */
static void find_best_gws(void) {
    size_t num;
    cl_event myEvent;
    cl_ulong startTime, endTime, run_time, min_time = CL_ULONG_MAX;
    cl_int ret_code;
    cl_uint *tmpbuffer;
    int optimal_gws = MIN_KEYS_PER_CRYPT, i, step = STEP;
    int do_benchmark = 0;
    unsigned int SHAspeed, bestSHAspeed = 0;
    char *tmp_value;

    fprintf(stderr, "Calculating best global work size, this will take a while ");

    if ((tmp_value = getenv("STEP"))){
        step = atoi(tmp_value);
        do_benchmark = 1;
    }

    for (num = get_step(num, step, 1); num < MAX_KEYS_PER_CRYPT;
         num = get_step(num, step, 0)) {
        release_clobj();
        create_clobj(num);

        if (! do_benchmark)
            advance_cursor();

        tmpbuffer = malloc(sizeof (sha512_hash) * num);

        if (tmpbuffer == NULL) {
            printf ("Malloc failure in find_best_gws\n");
            exit (EXIT_FAILURE);
        }

        queue_prof = clCreateCommandQueue(context[gpu_id], devices[gpu_id],
                CL_QUEUE_PROFILING_ENABLE, &ret_code);
        HANDLE_CLERROR(ret_code, "Failed in clCreateCommandQueue");

        // Set salt.
        set_salt("$6$saltstring$");

        // Set keys
        for (i = 0; i < num; i++) {
            set_key("aaabaabaaa", i);
        }
        HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, salt_buffer, CL_FALSE, 0,
                sizeof (sha512_salt), &salt, 0, NULL, NULL),
                "Failed in clEnqueueWriteBuffer I");
        HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, pass_buffer, CL_FALSE, 0,
                sizeof (sha512_password) * num, plaintext, 0, NULL, NULL),
                "Failed in clEnqueueWriteBuffer II");
        ret_code = clEnqueueNDRangeKernel(queue_prof, crypt_kernel,
                1, NULL, &num, &local_work_size, 0, NULL, &myEvent);
        HANDLE_CLERROR(clEnqueueReadBuffer(queue_prof, hash_buffer, CL_FALSE, 0,
                sizeof (sha512_hash) * num, tmpbuffer, 0, NULL, NULL),
                "Failed in clEnqueueReadBuffer");
        HANDLE_CLERROR(clFinish(queue_prof), "Failed in clFinish");

        if (ret_code != CL_SUCCESS) {
            fprintf(stderr, "Error %d\n", ret_code);
            continue;
        }
        HANDLE_CLERROR(clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT,
                sizeof (cl_ulong), &startTime, NULL),
                "Failed in clGetEventProfilingInfo I");
        HANDLE_CLERROR(clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END,
                sizeof (cl_ulong), &endTime, NULL),
                "Failed in clGetEventProfilingInfo II");

        free(tmpbuffer);
        HANDLE_CLERROR(clReleaseCommandQueue(queue_prof),
            "Failed in clReleaseCommandQueue");
        HANDLE_CLERROR(clReleaseEvent(myEvent), "Failed in clReleaseEvent");

        run_time = endTime - startTime;
	SHAspeed = 5000 * num / (run_time / 1000000000.);

        if (run_time < min_time)
            min_time = run_time;

        if (do_benchmark) {
            fprintf(stderr, "gws: %6zu\t%4lu c/s%14u rounds/s%8.3f sec per crypt_all()",
                    num, (long) (num / (run_time / 1000000000.)), SHAspeed,
                    (float) run_time / 1000000000.);

            if (run_time > 10000000000UL) {
                fprintf(stderr, " - too slow\n");
                break;
            }
        } else {
            if (run_time > min_time * 10 || run_time > 10000000000UL)
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
    release_clobj();
    create_clobj(optimal_gws);
}

/* ------- Initialization  ------- */
static void init(struct fmt_main *pFmt) {
    char *tmp_value;
    uint64_t startTime, runtime;
    char * task;

    global_work_size = 0;

    opencl_init_dev(gpu_id, platform_id);
    startTime = (unsigned long) time(NULL);

    if (cpu(device_info[gpu_id]))
        task = "$JOHN/cryptsha512_kernel_CPU.cl";

    else {
        fprintf(stderr, "Building the kernel, this could take a while\n");

        if (gpu_nvidia(device_info[gpu_id]))
            task = "$JOHN/cryptsha512_kernel_NVIDIA.cl";
        else
            task = "$JOHN/cryptsha512_kernel_AMD.cl";
    }
    fflush(stdout);
    opencl_build_kernel(task, gpu_id);

    if ((runtime = (unsigned long) (time(NULL) - startTime)) > 2UL)
        fprintf(stderr, "Elapsed time: %lu seconds\n", runtime);
    fflush(stdout);

    // create kernel to execute
    crypt_kernel = clCreateKernel(program[gpu_id], "kernel_crypt", &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

    global_work_size = get_task_max_size();
    local_work_size = get_default_workgroup();

    if ((tmp_value = cfg_get_param(SECTION_OPTIONS,
                                   SUBSECTION_OPENCL, LWS_CONFIG)))
        local_work_size = atoi(tmp_value);

    if ((tmp_value = getenv("LWS")))
        local_work_size = atoi(tmp_value);

    //Check if local_work_size is a valid number.
    if (local_work_size > get_task_max_work_group_size()){
        fprintf(stderr, "Error: invalid local work size (LWS). Max value allowed is: %u\n" ,
               get_task_max_work_group_size());
        local_work_size = 0; //Force find a valid number.
    }

    if (!local_work_size) {
        local_work_size = get_task_max_work_group_size();
        create_clobj(global_work_size);
        find_best_workgroup();
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
        create_clobj(global_work_size);
        find_best_gws();
    }
    fprintf(stderr, "Local work size (LWS) %d, global work size (GWS) %Zd\n",
           (int) local_work_size, global_work_size);
    pFmt->params.max_keys_per_crypt = global_work_size;
}

/* ------- Check if the ciphertext if a valid SHA-512 crypt ------- */
static int valid(char *ciphertext, struct fmt_main *pFmt) {
    uint32_t i, j;
    int len = strlen(ciphertext);
    char *p = strrchr(ciphertext, '$');

    if (strncmp(ciphertext, "$6$", 3) != 0)
            return 0;

    for (i = p - ciphertext + 1; i < len; i++) {
            int found = 0;
            for (j = 0; j < 64; j++)
                    if (itoa64[j] == ARCH_INDEX(ciphertext[i]))
                            found = 1;
            if (found == 0) {
                    puts("not found");
                    return 0;
            }
    }
    if (len - (p - ciphertext + 1) != 86)
            return 0;
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

static void * get_binary(char *ciphertext) {
	static ARCH_WORD_32 outbuf[BINARY_SIZE/4];
	ARCH_WORD_32 value;
	char *pos;
	unsigned char *out = (unsigned char*)outbuf;

	pos = strrchr(ciphertext, '$') + 1;

	TO_BINARY(0, 21, 42);
	TO_BINARY(22, 43, 1);
	TO_BINARY(44, 2, 23);
	TO_BINARY(3, 24, 45);
	TO_BINARY(25, 46, 4);
	TO_BINARY(47, 5, 26);
	TO_BINARY(6, 27, 48);
	TO_BINARY(28, 49, 7);
	TO_BINARY(50, 8, 29);
	TO_BINARY(9, 30, 51);
	TO_BINARY(31, 52, 10);
	TO_BINARY(53, 11, 32);
	TO_BINARY(12, 33, 54);
	TO_BINARY(34, 55, 13);
	TO_BINARY(56, 14, 35);
	TO_BINARY(15, 36, 57);
	TO_BINARY(37, 58, 16);
	TO_BINARY(59, 17, 38);
	TO_BINARY(18, 39, 60);
	TO_BINARY(40, 61, 19);
	TO_BINARY(62, 20, 41);
	value = (ARCH_WORD_32)atoi64[ARCH_INDEX(pos[0])] |
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[1])] << 6) |
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[2])] << 12);
	out[63] = value; \
	return (void *) out;
}

/* ------- Compare functins ------- */
static int cmp_all(void *binary, int count) {
    uint32_t i;
    uint64_t b = ((uint64_t *) binary)[0];

    for (i = 0; i < count; i++)
        if (b == calculated_hash[i].v[0])
            return 1;
    return 0;
}

static int cmp_one(void *binary, int index) {
    int i;
    uint64_t *t = (uint64_t *) binary;

    for (i = 0; i < 8; i++) {
        if (t[i] != calculated_hash[index].v[i])
            return 0;
    }
    return 1;
}

static int cmp_exact(char *source, int count) {
    return 1;
}

/* ------- Crypt function ------- */
static void crypt_all(int count) {
    //Send data to the dispositive
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], salt_buffer, CL_FALSE, 0,
            sizeof (sha512_salt), &salt, 0, NULL, NULL),
            "failed in clEnqueueWriteBuffer data_info");
    if (new_keys)
        HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer, CL_FALSE, 0,
                sizeof(sha512_password) * global_work_size, plaintext, 0, NULL, NULL),
                "failed in clEnqueueWriteBuffer buffer_in");

    //Enqueue the kernel
    HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
            &global_work_size, &local_work_size, 0, NULL, NULL),
            "failed in clEnqueueNDRangeKernel");

    //Read back hashes
    HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], hash_buffer, CL_FALSE, 0,
            sizeof(sha512_hash) * global_work_size, calculated_hash, 0, NULL, NULL),
            "failed in reading data back");

    //Do the work
    HANDLE_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
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

    for (i = 0; i < global_work_size; i++)
        if (calculated_hash[i].v[0] == 12)
            fprintf(stderr, "Value: %lu, %d\n ", calculated_hash[i].v[0], i);

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
        fmt_default_split,
        get_binary,
        get_salt,
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

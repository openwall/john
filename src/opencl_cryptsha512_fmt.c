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

#define FORMAT_LABEL			"cryptsha512-opencl"
#define FORMAT_NAME			"crypt SHA-512"
#define ALGORITHM_NAME			"OpenCL"
#define SHA_TYPE                        "SHA512"

#define BENCHMARK_COMMENT		" (rounds=5000)"
#define BENCHMARK_LENGTH		-1

#define LWS_CONFIG			"cryptsha512_LWS"
#define KPC_CONFIG			"cryptsha512_KPC"

static sha512_salt                salt;
static sha512_password            *plaintext;        // plaintext ciphertexts
static sha512_hash                *calculated_hash;  // calculated hashes

cl_mem salt_buffer;        //Salt information.
cl_mem pass_buffer;        //Plaintext buffer.
cl_mem hash_buffer;        //Hash keys (output)
cl_mem pinned_saved_keys, pinned_partial_hashes;

cl_command_queue queue_prof;
cl_kernel crypt_kernel;

static size_t max_keys_per_crypt; //TODO: move to common-opencl? local_work_size is there.
static int new_keys;

static struct fmt_tests tests[] = {
    {"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1", "Hello world!"},
    {"$6$LKO/Ute40T3FNF95$6S/6T2YuOIHY0N3XpLKABJ3soYcXD9mB7uVbtEZDj/LNscVhZoZ9DEH.sBciDrMsHOWOoASbNLTypH/5X26gN0", "U*U*U*U*"},
    {"$6$LKO/Ute40T3FNF95$wK80cNqkiAUzFuVGxW6eFe8J.fSVI65MD5yEm8EjYMaJuDrhwe5XXpHDJpwF/kY.afsUs1LlgQAaOapVNbggZ1", "U*U***U"},
    {"$6$OmBOuxFYBZCYAadG$WCckkSZok9xhp4U1shIZEV7CCVwQUwMVea7L3A77th6SaE9jOPupEMJB.z0vIWCDiN9WLh2m9Oszrj5G.gt330", "*U*U*U*U"},
    {"$6$ojWH1AiTee9x1peC$QVEnTvRVlPRhcLQCk/HnHaZmlGAAjCfrAN0FtOsOnUk5K5Bn/9eLHHiRzrTzaIKjW9NTLNIBUCtNVOowWS2mN.", ""},
    {"$6$rounds=4900$saltstring$p3pnU2njiDujK0Pp5us7qlUvkjVaAM0GilTprwyZ1ZiyGKvsfNyDCnlmc.9ahKmDqyqKXMH3frK1I/oEiEbTK/", "Hello world!"},
    {NULL}
};

/* ------- Helper functions ------- */
unsigned int get_task_max_work_group_size(){
    unsigned int max_available;

    if (gpu_amd(device_info[gpu_id]))
        max_available = (get_local_memory_size(gpu_id) -
                sizeof(sha512_salt)) /
                sizeof(working_memory);
    else
        max_available = (get_local_memory_size(gpu_id) -
                sizeof(sha512_salt)) /
                sizeof(sha512_password);

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

size_t get_default_workgroup(){

    if (cpu(device_info[gpu_id]))
        return 1;

    else
        return 32;
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(int kpc) {
    pinned_saved_keys = clCreateBuffer(context[gpu_id],
            CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
            sizeof(sha512_password) * kpc, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

    plaintext = (sha512_password *) clEnqueueMapBuffer(queue[gpu_id],
            pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0,
            sizeof(sha512_password) * kpc, 0, NULL, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

    pinned_partial_hashes = clCreateBuffer(context[gpu_id],
            CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
            sizeof(sha512_hash) * kpc, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

    calculated_hash = (sha512_hash *) clEnqueueMapBuffer(queue[gpu_id],
            pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
            sizeof(sha512_hash) * kpc, 0, NULL, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

    // create arguments (buffers)
    salt_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
            sizeof(sha512_salt), NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating data_info out argument");

    pass_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
            sizeof(sha512_password) * kpc, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

    hash_buffer = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
            sizeof(sha512_hash) * kpc, NULL, &ret_code);
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
    }
    memset(plaintext, '\0', sizeof(sha512_password) * kpc);
    memset(&salt, '\0', sizeof(sha512_salt));
    max_keys_per_crypt = kpc;
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
    for (i = len - 1; i >= 0; i--)
        if (ciphertext[i] == '$') {
            end = i;
            break;
        }

    static unsigned char ret[50];
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
    memcpy(salt.salt, currentsalt + offset, SALT_LENGTH);
    salt.length = strlen((char *) salt.salt);
    salt.length = (salt.length > SALT_LENGTH ? SALT_LENGTH : salt.length);
}

/* ------- Key functions ------- */
static void set_key(char *key, int index) {
    int len = strlen(key);
    char buf[PLAINTEXT_LENGTH];
    memset(buf, '\0', PLAINTEXT_LENGTH);

    plaintext[index].length = len;
    memcpy(buf, key, len);  //Assure all buffer is clean.
    memcpy(plaintext[index].pass, buf, PLAINTEXT_LENGTH);
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
    printf("Max Group Work Size %d ", (int) max_group_size);
    local_work_size = 1;
    max_group_size = get_task_max_work_group_size();

    // Set salt.
    set_salt("$6$saltstring$");

    // Set keys
    for (i = 0; i < max_keys_per_crypt; i++) {
        set_key("aaabaabaaa", i);
    }
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, salt_buffer, CL_TRUE, 0,
            sizeof (sha512_salt), &salt, 0, NULL, NULL),
            "Failed in clEnqueueWriteBuffer I");
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, pass_buffer, CL_TRUE, 0,
            sizeof (sha512_password) * max_keys_per_crypt,
            plaintext, 0, NULL, NULL),
            "Failed in clEnqueueWriteBuffer II");

    my_work_group = get_default_workgroup();

    // Find minimum time
    for (; (int) my_work_group <= (int) max_group_size;
         my_work_group *= 2) {
        advance_cursor();
        ret_code = clEnqueueNDRangeKernel(queue_prof, crypt_kernel,
                1, NULL, &max_keys_per_crypt, &my_work_group, 0, NULL, &myEvent);
        HANDLE_CLERROR(clFinish(queue_prof), "Failed in clFinish");

        if (ret_code != CL_SUCCESS) {

            if (ret_code != CL_INVALID_WORK_GROUP_SIZE)
                printf("Error %d\n", ret_code);
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
    printf("Optimal local work size %d\n", (int) local_work_size);
    printf("(to avoid this test on next run, put \""
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
static void find_best_kpc(void) {
    size_t num;
    cl_event myEvent;
    cl_ulong startTime, endTime, run_time, min_time = CL_ULONG_MAX;
    cl_int ret_code;
    cl_uint *tmpbuffer;
    int optimal_kpc = MIN_KEYS_PER_CRYPT, i, step = STEP;
    int do_benchmark = 0;
    unsigned int SHAspeed, bestSHAspeed = 0;
    char *tmp_value;

    printf("Calculating best keys per crypt, this will take a while ");

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
            printf ("Malloc failure in find_best_kpc\n");
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
            printf("Error %d\n", ret_code);
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
            fprintf(stderr, "kpc: %6zu\t%4lu c/s%14u rounds/s%8.3f sec per crypt_all()",
                    num, (long) (num / (run_time / 1000000000.)), SHAspeed,
                    (float) run_time / 1000000000.);

            if (run_time > 10000000000) {
                fprintf(stderr, " - too slow\n");
                break;
            }
        } else {
            if (run_time > min_time * 7 || run_time > 10000000000)
                break;
        }
        if (SHAspeed > (1.01 * bestSHAspeed)) {
            if (do_benchmark)
                fprintf(stderr, "+");
            bestSHAspeed = SHAspeed;
            optimal_kpc = num;
        }
        if (do_benchmark)
            fprintf(stderr, "\n");
    }
    printf("Optimal keys per crypt %d\n", optimal_kpc);
    printf("(to avoid this test on next run, put \""
        KPC_CONFIG " = %d\" in john.conf, section [" SECTION_OPTIONS
        SUBSECTION_OPENCL "])\n", optimal_kpc);
    max_keys_per_crypt = optimal_kpc;
    release_clobj();
    create_clobj(optimal_kpc);
}

/* ------- Initialization  ------- */
static void init(struct fmt_main *pFmt) {
    char *tmp_value;
    opencl_init_dev(gpu_id, platform_id);

    uint64_t startTime, runtime;
    char * task;
    startTime = (unsigned long) time(NULL);

    if (cpu(device_info[gpu_id]))
        task = "$JOHN/cryptsha512_kernel_CPU.cl";

    else {
        printf("Building the kernel, this could take a while\n");

        if (gpu_nvidia(device_info[gpu_id]))
            task = "$JOHN/cryptsha512_kernel_NVIDIA.cl";
        else
            task = "$JOHN/cryptsha512_kernel_AMD_V1.cl";
    }
    fflush(stdout);
    opencl_build_kernel(task, gpu_id);

    if ((runtime = (unsigned long) (time(NULL) - startTime)) > 2UL)
        printf("Elapsed time: %lu seconds\n", runtime);
    fflush(stdout);

    max_keys_per_crypt = get_task_max_size();
    local_work_size = get_default_workgroup();

    // create kernel to execute
    crypt_kernel = clCreateKernel(program[gpu_id], "kernel_crypt", &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

    if ((tmp_value = cfg_get_param(SECTION_OPTIONS,
                                   SUBSECTION_OPENCL, LWS_CONFIG)))
        local_work_size = atoi(tmp_value);

    if ((tmp_value = getenv("LWS")))
        local_work_size = atoi(tmp_value);

    //Check if local_work_size is a valid number.
    if (local_work_size > get_task_max_work_group_size()){
        printf("Error: invalid local work size (LWS). Max value allowed is: %u\n" ,
               get_task_max_work_group_size());
        local_work_size = 0; //Force find a valid number.
    }

    if (!local_work_size) {
        local_work_size = get_task_max_work_group_size();
        create_clobj(max_keys_per_crypt);
        find_best_workgroup();
        release_clobj();
    }

    if ((tmp_value = cfg_get_param(SECTION_OPTIONS,
                                   SUBSECTION_OPENCL, KPC_CONFIG)))
        max_keys_per_crypt = atoi(tmp_value);

    if ((tmp_value = getenv("KPC")))
        max_keys_per_crypt = atoi(tmp_value);

    if (max_keys_per_crypt)
        create_clobj(max_keys_per_crypt);

    else {
        //user chose to die of boredom
        max_keys_per_crypt = get_task_max_size();
        create_clobj(max_keys_per_crypt);
        find_best_kpc();
    }
    printf("Local work size (LWS) %d, Keys per crypt (KPC) %Zd\n",
           (int) local_work_size, max_keys_per_crypt);
    pFmt->params.max_keys_per_crypt = max_keys_per_crypt;
}

/* ------- Check if the ciphertext if a valid SHA-512 crypt ------- */
static int valid(char *ciphertext, struct fmt_main *pFmt) {
    uint32_t i, j;
    int len = strlen(ciphertext);

    if (strncmp(ciphertext, "$6$", 3) != 0)
            return 0;
    char *p = strrchr(ciphertext, '$');
    if (p == NULL)
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
static int findb64(char c) {
    int ret = ARCH_INDEX(atoi64[(uint8_t) c]);
    return ret != 0x7f ? ret : 0;
}

static void magic(char *crypt, unsigned char *alt) {
#define _24bit_from_b64(I,B2,B1,B0) \
    {\
        unsigned char c1=findb64(crypt[I+0]);\
        unsigned char c2=findb64(crypt[I+1]);\
        unsigned char c3=findb64(crypt[I+2]);\
        unsigned char c4=findb64(crypt[I+3]);\
        unsigned int w=c4<<18|c3<<12|c2<<6|c1;\
        unsigned char b2=w&0xff;w>>=8;\
        unsigned char b1=w&0xff;w>>=8;\
        unsigned char b0=w&0xff;w>>=8;\
        alt[B2]=b0;\
        alt[B1]=b1;\
        alt[B0]=b2;\
    }
    _24bit_from_b64(0, 0, 21, 42);
    _24bit_from_b64(4, 22, 43, 1);
    _24bit_from_b64(8, 44, 2, 23);
    _24bit_from_b64(12, 3, 24, 45);
    _24bit_from_b64(16, 25, 46, 4);
    _24bit_from_b64(20, 47, 5, 26);
    _24bit_from_b64(24, 6, 27, 48);
    _24bit_from_b64(28, 28, 49, 7);
    _24bit_from_b64(32, 50, 8, 29);
    _24bit_from_b64(36, 9, 30, 51);
    _24bit_from_b64(40, 31, 52, 10);
    _24bit_from_b64(44, 53, 11, 32);
    _24bit_from_b64(48, 12, 33, 54);
    _24bit_from_b64(52, 34, 55, 13);
    _24bit_from_b64(56, 56, 14, 35);
    _24bit_from_b64(60, 15, 36, 57);
    _24bit_from_b64(64, 37, 58, 16);
    _24bit_from_b64(68, 59, 17, 38);
    _24bit_from_b64(72, 18, 39, 60);
    _24bit_from_b64(76, 40, 61, 19);
    _24bit_from_b64(80, 62, 20, 41);

    uint32_t w = findb64(crypt[85]) << 6 | findb64(crypt[84]) << 0;
    alt[63] = (w & 0xff);
}

static void * get_binary(char *ciphertext) {
    static unsigned char b[BINARY_SIZE];
    memset(b, 0, BINARY_SIZE);
    char *p = strrchr(ciphertext, '$');

    if (p != NULL)
        magic(p + 1, b);
    return (void *) b;
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
                sizeof(sha512_password) * max_keys_per_crypt, plaintext, 0, NULL, NULL),
                "failed in clEnqueueWriteBuffer buffer_in");

    //Enqueue the kernel
    HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
            &max_keys_per_crypt, &local_work_size, 0, NULL, NULL),
            "failed in clEnqueueNDRangeKernel");

    //Read back hashes
    HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], hash_buffer, CL_FALSE, 0,
            sizeof(sha512_hash) * max_keys_per_crypt, calculated_hash, 0, NULL, NULL),
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
        printf("%016lx ", bin[i]);
    puts("(Ok)");
}

static void print_hash() {
    int i;

    for (i = 0; i < max_keys_per_crypt; i++)
        if (calculated_hash[i].v[0] == 12)
            printf("Value: %lu, %d\n ", calculated_hash[i].v[0], i);

    printf("\n");
    for (i = 0; i < 8; i++)
        printf("%016lx ", calculated_hash[0].v[i]);
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
        cmp_exact,
		fmt_default_get_source
    }
};

/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012   
 * Based on source code provided by Samuele Giovanni Tonon
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

#define FORMAT_LABEL			"cryptsha512-opencl" 
#define FORMAT_NAME			"crypt SHA-512"
#define ALGORITHM_NAME			"OpenCL"
#define SHA_TYPE                        "SHA512"

#define BENCHMARK_COMMENT		" (rounds=5000)"
#define BENCHMARK_LENGTH		-1

#define LWS_CONFIG			"cryptsha512_LWS"
#define KPC_CONFIG			"cryptsha512_KPC"

static crypt_sha512_password            *plaintext;     // plaintext ciphertexts
static crypt_sha512_hash                *out_hashes;    // calculated hashes
static crypt_sha512_salt                salt_data;

cl_mem salt_info;       //Salt information.
cl_mem buffer_in;       //Plaintext buffer.
cl_mem buffer_out;      //Hash keys (output)
cl_mem pinned_saved_keys, pinned_partial_hashes;

cl_command_queue queue_prof;
cl_kernel crypt_kernel;

static size_t max_keys_per_crypt; //TODO: move to common-opencl? local_work_size is there.

static struct fmt_tests tests[] = {
    {"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1", "Hello world!"},
    {"$6$LKO/Ute40T3FNF95$6S/6T2YuOIHY0N3XpLKABJ3soYcXD9mB7uVbtEZDj/LNscVhZoZ9DEH.sBciDrMsHOWOoASbNLTypH/5X26gN0", "U*U*U*U*"},
    {"$6$LKO/Ute40T3FNF95$wK80cNqkiAUzFuVGxW6eFe8J.fSVI65MD5yEm8EjYMaJuDrhwe5XXpHDJpwF/kY.afsUs1LlgQAaOapVNbggZ1", "U*U***U"},
    {"$6$OmBOuxFYBZCYAadG$WCckkSZok9xhp4U1shIZEV7CCVwQUwMVea7L3A77th6SaE9jOPupEMJB.z0vIWCDiN9WLh2m9Oszrj5G.gt330", "*U*U*U*U"},
    {"$6$ojWH1AiTee9x1peC$QVEnTvRVlPRhcLQCk/HnHaZmlGAAjCfrAN0FtOsOnUk5K5Bn/9eLHHiRzrTzaIKjW9NTLNIBUCtNVOowWS2mN.", ""},
    {NULL}
}; 

/* ------- Helper functions ------- */
uint get_task_max_work_group_size(){
    uint max_available;
    max_available = get_local_memory_size(gpu_id) / sizeof(working_memory);
    
    if (max_available > get_max_work_group_size(gpu_id))
        return get_max_work_group_size(gpu_id);
    
    return max_available;
}

uint get_task_max_size(){ 
    uint max_available;
    max_available = get_max_compute_units(gpu_id);

    if (get_device_type(gpu_id) == CL_DEVICE_TYPE_CPU)
        return max_available * KEYS_PER_CORE_CPU;
    
    return max_available * KEYS_PER_CORE_GPU;
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(int kpc) {           
    pinned_saved_keys = clCreateBuffer(context[gpu_id], 
            CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
            sizeof(crypt_sha512_password) * kpc, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

    plaintext = (crypt_sha512_password *) clEnqueueMapBuffer(queue[gpu_id], 
            pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0,
            sizeof(crypt_sha512_password) * kpc, 0, NULL, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");
    
    pinned_partial_hashes = clCreateBuffer(context[gpu_id],
            CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 
            sizeof(crypt_sha512_hash) * kpc, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

    out_hashes = (crypt_sha512_hash *) clEnqueueMapBuffer(queue[gpu_id],
            pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, 
            sizeof(crypt_sha512_hash) * kpc, 0, NULL, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

    // create arguments (buffers)
    salt_info = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 
            sizeof(crypt_sha512_salt), NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating data_info out argument");
     
    buffer_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
            sizeof(crypt_sha512_password) * kpc, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

    buffer_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
            sizeof(crypt_sha512_hash) * kpc, NULL, &ret_code);
    HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

    //Set kernel arguments
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof (cl_mem),
            (void *) &salt_info), "Error setting argument 0");
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof (cl_mem),
            (void *) &buffer_in), "Error setting argument 1");
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof (cl_mem),
            (void *) &buffer_out), "Error setting argument 2");     
    HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3,   //Fast working memory.
            sizeof (working_memory) * local_work_size,
            NULL), "Error setting argument 3");   
 
    memset(plaintext, '\0', sizeof(crypt_sha512_password) * kpc);
    salt_data.saltlen = 0;
    salt_data.rounds = 0;
    max_keys_per_crypt = kpc;
}

static void release_clobj(void) {
    cl_int ret_code;

    ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_partial_hashes,
            out_hashes, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Ummapping out_hashes");
    
    ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys,
            plaintext, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Ummapping saved_plain");
    
    ret_code = clReleaseMemObject(salt_info);
    HANDLE_CLERROR(ret_code, "Error Releasing data_info");
    ret_code = clReleaseMemObject(buffer_in);
    HANDLE_CLERROR(ret_code, "Error Releasing buffer_keys");
    ret_code = clReleaseMemObject(buffer_out);
    HANDLE_CLERROR(ret_code, "Error Releasing buffer_out");
    
    ret_code = clReleaseMemObject(pinned_saved_keys);
    HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_keys");
    
    ret_code = clReleaseMemObject(pinned_partial_hashes);
    HANDLE_CLERROR(ret_code, "Error Releasing pinned_partial_hashes");
}

/* ------- Key functions ------- */
static void set_key(char *key, int index) {
    int len = strlen(key);
    plaintext[index].length = len;
    memcpy(plaintext[index].v, key, len); 
}

static char *get_key(int index) {
    static char ret[PLAINTEXT_LENGTH + 1];
    memcpy(ret, plaintext[index].v, PLAINTEXT_LENGTH);
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
    cl_ulong startTime, endTime, kernelExecTimeNs = CL_ULONG_MAX;
    size_t my_work_group = 1;
    cl_int ret_code;
    int i;
    size_t max_group_size;

    max_group_size = get_max_work_group_size(gpu_id);
    queue_prof = clCreateCommandQueue(context[gpu_id], devices[gpu_id], 
            CL_QUEUE_PROFILING_ENABLE, &ret_code);
    printf("Max Group Work Size %d ", (int) max_group_size);
    local_work_size = 1;

    // Set keys
    for (i = 0; i < get_task_max_size(); i++) {
        set_key("aaabaabaaa", i);
    }
    clEnqueueWriteBuffer(queue[gpu_id], salt_info, CL_TRUE, 0,
            sizeof (crypt_sha512_salt), &salt_data, 0, NULL, NULL);
    clEnqueueWriteBuffer(queue_prof, buffer_in, CL_TRUE, 0, 
            sizeof (crypt_sha512_password) * get_task_max_size(), 
            plaintext, 0, NULL, NULL);

    // Find minimum time
    for (my_work_group = 1; (int) my_work_group <= (int) get_task_max_work_group_size(); 
         my_work_group *= 2) {
        ret_code = clEnqueueNDRangeKernel(queue_prof, crypt_kernel, 
                1, NULL, &max_keys_per_crypt, &my_work_group, 0, NULL, &myEvent);
        clFinish(queue_prof);

        if (ret_code != CL_SUCCESS) {
            printf("Error %d\n", ret_code); ///Better commented by default.
            break;
        }
        //Get profile information
        clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, 
                sizeof (cl_ulong), &startTime, NULL);
        clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END, 
                sizeof (cl_ulong), &endTime, NULL);
        clReleaseEvent (myEvent);
        
        if ((endTime - startTime) < kernelExecTimeNs) {
            kernelExecTimeNs = endTime - startTime;
            local_work_size = my_work_group;
        }
    }
    printf("Optimal local work size %d\n", (int) local_work_size);
    printf("(to avoid this test on next run, put \""
        LWS_CONFIG " = %d\" in john.conf, section [" SECTION_OPTIONS
        SUBSECTION_OPENCL "])\n", (int)local_work_size);    
    clReleaseCommandQueue(queue_prof);
}

/* --
  This function could be used to calculated the best num
  of keys per crypt for the given format
-- */
static void find_best_kpc(void) {
    size_t num;
    cl_event myEvent;
    cl_ulong startTime, endTime, tmpTime;
    cl_ulong kernelExecTimeNs = CL_ULONG_MAX;
    cl_int ret_code;
    int optimal_kpc = MIN_KEYS_PER_CRYPT;
    int i;
    cl_uint *tmpbuffer;

    printf("Calculating best keys per crypt, this will take a while ");
    
    for (num = get_task_max_size(); (int) num > MIN_KEYS_PER_CRYPT; num -= 4096) {
        release_clobj();
        create_clobj(num);
        advance_cursor();
        tmpbuffer = malloc(sizeof (crypt_sha512_hash) * num);
        queue_prof = clCreateCommandQueue(context[gpu_id], devices[gpu_id], 
                CL_QUEUE_PROFILING_ENABLE, &ret_code);

        // Set keys
        for (i = 0; i < num; i++) {
            set_key("aaabaabaaa", i);
        }
        clEnqueueWriteBuffer(queue[gpu_id], salt_info, CL_FALSE, 0,
                sizeof (crypt_sha512_salt), &salt_data, 0, NULL, NULL);
        clEnqueueWriteBuffer(queue_prof, buffer_in, CL_FALSE, 0, 
                sizeof (crypt_sha512_password) * num, plaintext, 0, NULL, NULL); 
        ret_code = clEnqueueNDRangeKernel(queue_prof, crypt_kernel, 
                1, NULL, &num, &local_work_size, 0, NULL, &myEvent);
        clEnqueueReadBuffer(queue_prof, buffer_out, CL_FALSE, 0,
                sizeof (crypt_sha512_hash) * num, tmpbuffer, 0, NULL, NULL);
        clFinish(queue_prof);
            
        if (ret_code != CL_SUCCESS) {
            printf("Error %d\n", ret_code);
            continue;
        }       
        clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, 
                sizeof (cl_ulong), &startTime, NULL);
        clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END, 
                sizeof (cl_ulong), &endTime, NULL);
        
        clReleaseEvent (myEvent);
        tmpTime = endTime - startTime;

        if (((int) (((float) (tmpTime) / num) * 10)) <= kernelExecTimeNs) {
            kernelExecTimeNs = ((int) (((float) (tmpTime) / num) * 10));
            optimal_kpc = num;
        }
        free(tmpbuffer);
        clReleaseCommandQueue(queue_prof);
    }
    printf("Optimal keys per crypt %d\n", optimal_kpc);
    printf("to avoid this test on next run, put \""
        KPC_CONFIG " = %d\" in john.conf, section [" SECTION_OPTIONS
        SUBSECTION_OPENCL "])\n", optimal_kpc);
    max_keys_per_crypt = optimal_kpc;
    release_clobj();
    create_clobj(optimal_kpc);
}

/* ------- Initialization  ------- */
static void init(struct fmt_main *pFmt) {
    char *tmp_value;
    opencl_init("$JOHN/cryptsha512_kernel.cl", gpu_id, platform_id);
    max_keys_per_crypt = get_task_max_size();
    local_work_size = 0;

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

static void set_salt(void *salt) {
    unsigned char *s = salt;
    int len = strlen(salt);
    static char currentsalt[64];
    memcpy(currentsalt, s, len + 1);
    unsigned char offset = 0;
    salt_data.rounds = ROUNDS_DEFAULT;

    if (strncmp((char *) "$6$", (char *) currentsalt, 3) == 0)
        offset += 3;

    if (strncmp((char *) currentsalt + offset, (char *) "rounds=", 7) == 0) {
        const char *num = currentsalt + offset + 7;
        char *endp;
        unsigned long int srounds = strtoul(num, &endp, 10);

        if (*endp == '$') {
            endp += 1;
            salt_data.rounds =
                    MAX(ROUNDS_MIN, MIN(srounds, ROUNDS_MAX));
        }
        offset = endp - currentsalt;
    }
    memcpy(salt_data.salt, currentsalt + offset, SALT_SIZE);
    salt_data.saltlen = strlen((char *) salt_data.salt);
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
        if (b == out_hashes[i].v[0])
            return 1;
    return 0;
}

static int cmp_one(void *binary, int index) { 
    int i;
    uint64_t *t = (uint64_t *) binary;
    
    for (i = 0; i < 8; i++) {
        if (t[i] != out_hashes[index].v[i])
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
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], salt_info, CL_FALSE, 0,
            sizeof (crypt_sha512_salt), &salt_data, 0, NULL, NULL),
            "failed in clEnqueueWriteBuffer data_info");
    HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_in, CL_FALSE, 0,
            sizeof(crypt_sha512_password) * max_keys_per_crypt, plaintext, 0, NULL, NULL),
            "failed in clEnqueueWriteBuffer buffer_in");

    //Enqueue the kernel
    HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
            &max_keys_per_crypt, &local_work_size, 0, NULL, NULL),
            "failed in clEnqueueNDRangeKernel");

    //Read back hashes
    HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_out, CL_FALSE, 0,
            sizeof(crypt_sha512_hash) * max_keys_per_crypt, out_hashes, 0, NULL, NULL),
            "failed in reading data back");
 
    //Do the work
    HANDLE_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
}

/* ------- Binary Hash functions group ------- */
static int binary_hash_0(void * binary) { return *(ARCH_WORD_32 *) binary & 0xF; } 
static int binary_hash_1(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFF; }
static int binary_hash_2(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFF; }
static int binary_hash_3(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFFF; }
static int binary_hash_4(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFF; }
static int binary_hash_5(void * binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFFF; }
static int binary_hash_6(void * binary) { return *(ARCH_WORD_32 *) binary & 0x7FFFFFF; }

//Get Hash functions group.
static int get_hash_0(int index) { return out_hashes[index].v[0] & 0xF; }
static int get_hash_1(int index) { return out_hashes[index].v[0] & 0xFF; }
static int get_hash_2(int index) { return out_hashes[index].v[0] & 0xFFF; }
static int get_hash_3(int index) { return out_hashes[index].v[0] & 0xFFFF; }
static int get_hash_4(int index) { return out_hashes[index].v[0] & 0xFFFFF; }
static int get_hash_5(int index) { return out_hashes[index].v[0] & 0xFFFFFF; }
static int get_hash_6(int index) { return out_hashes[index].v[0] & 0x7FFFFFF; }

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
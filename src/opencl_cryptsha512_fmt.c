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
#include "options.h"
#include "opencl_cryptsha512.h"
#include "cryptsha512_common.h"
#include "memdbg.h"

#define FORMAT_LABEL			"sha512crypt-opencl"
#define ALGORITHM_NAME			"SHA512 OpenCL"
#define OCL_CONFIG			"sha512crypt"

//Checks for source code to pick (parameters, sizes, kernels to execute, etc.)
#define _USE_CPU_SOURCE			(cpu(source_in_use))
#define _USE_GPU_SOURCE			(gpu(source_in_use))
#define _SPLIT_KERNEL_IN_USE		(gpu(source_in_use))

static sha512_salt			* salt;
static sha512_password	 		* plaintext;			// plaintext ciphertexts
static sha512_hash			* calculated_hash;		// calculated hashes

static cl_mem salt_buffer;		//Salt information.
static cl_mem pass_buffer;		//Plaintext buffer.
static cl_mem hash_buffer;		//Hash keys (output).
static cl_mem work_buffer;		//Temporary buffer
static cl_mem pinned_saved_keys, pinned_partial_hashes;

static cl_kernel prepare_kernel, final_kernel;

static int new_keys, source_in_use;
static int split_events[3] = { 1, 4, 5 };

static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt);

//This file contains auto-tuning routine(s). Have to included after formats definitions.
#include "opencl_autotune.h"

static struct fmt_tests tests[] = {
	{"$6$LKO/Ute40T3FNF95$6S/6T2YuOIHY0N3XpLKABJ3soYcXD9mB7uVbtEZDj/LNscVhZoZ9DEH.sBciDrMsHOWOoASbNLTypH/5X26gN0", "U*U*U*U*"},
	{"$6$LKO/Ute40T3FNF95$wK80cNqkiAUzFuVGxW6eFe8J.fSVI65MD5yEm8EjYMaJuDrhwe5XXpHDJpwF/kY.afsUs1LlgQAaOapVNbggZ1", "U*U***U"},
	{"$6$LKO/Ute40T3FNF95$YS81pp1uhOHTgKLhSMtQCr2cDiUiN03Ud3gyD4ameviK1Zqz.w3oXsMgO6LrqmIEcG3hiqaUqHi/WEE2zrZqa/", "U*U***U*"},
	{"$6$OmBOuxFYBZCYAadG$WCckkSZok9xhp4U1shIZEV7CCVwQUwMVea7L3A77th6SaE9jOPupEMJB.z0vIWCDiN9WLh2m9Oszrj5G.gt330", "*U*U*U*U"},
	{"$6$ojWH1AiTee9x1peC$QVEnTvRVlPRhcLQCk/HnHaZmlGAAjCfrAN0FtOsOnUk5K5Bn/9eLHHiRzrTzaIKjW9NTLNIBUCtNVOowWS2mN.", ""},
#ifdef DEBUG //Special test cases.
	//{"$6$va2Z2zTYTtF$1CzJmk3A2FO6aH.UrF2BU99oZOYcFlJu5ewPz7ZFvq0w3yCC2G9y4EsymHZxXe5e6Q7bPbyk4BQ5bekdVbmZ20", "123456789012345678901234"},
	//{"$6$1234567890123456$938IMfPJvgxpgwvaqbFcmpz9i/yfYSClzgfwcdDcAdjlj6ZH1fVA9BUe4GDGYN/68UiaR2.pLq4gXFfLZxpMr.", "123456789012345678901234"},
	{"$6$mwt2GD73BqSk4$ol0oMY1zzm59tnAFnH0OM9R/7SL4gi3VJ42AIVQNcGrYx5S1rlZggq5TBqvOGNiNQ0AmjmUMPc.70kL8Lqost.", "password"},
	{"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1", "Hello world!"},
	{"$6$rounds=391939$saltstring$P5HDSEq.sTdSBNmknrLQpg6UHp.9.vuEv6QibJNP8ecoNGo9Wa.3XuR7LKu8FprtxGDpGv17Y27RfTHvER4kI0", "amy"},
	{"$6$rounds=391939$saltstring$JAjUHgEFBJB1lSM25mYGFdH42OOBZ8eytTvKCleaR4jI5cSs0KbATSYyhLj3tkMhmU.fUKfsZkT5y0EYbTLcr1", "amy99"},
	{"$6$TtrrO3IN$D7Qz38n3JOn4Cc6y0340giveWD8uUvBAdPeCI0iC1cGYCmYHDrVXUEoSf3Qp5TRgo7x0BXN4lKNEj7KOvFTZV1", ">7fSy+N\\W=o@Wd&"},
	{"$6$yRihAbCh$V5Gr/BhMSMkl6.fBt4TV5lWYY6MhjqApHxDL04HeTgeAX.mZT/0pDDYvArvmCfmMVa/XxzzOBXf1s7TGa2FDL0", "0H@<:IS:BfM\"V"},
	{"$6$rounds=4900$saltstring$p3pnU2njiDujK0Pp5us7qlUvkjVaAM0GilTprwyZ1ZiyGKvsfNyDCnlmc.9ahKmDqyqKXMH3frK1I/oEiEbTK/", "Hello world!"},
	{"$6$saltstring$fgNTR89zXnDUV97U5dkWayBBRaB0WIBnu6s4T7T8Tz1SbUyewwiHjho25yWVkph2p18CmUkqXh4aIyjPnxdgl0","john"},
	{"$6$saltstring$MO53nAXQUKXVLlsbiXyPgMsR6q10N7eF7sPvanwdXnEeCj5kE3eYaRvFv0wVW1UZ4SnNTzc1v4OCOq1ASDQZY0","a"},
	{"$6$saltstring$q.eQ9PCFPe/tOHJPT7lQwnVQ9znjTT89hsg1NWHCRCAMsbtpBLbg1FLq7xo1BaCM0y/z46pXv4CGESVWQlOk30","ab"},
	{"$6$saltstring$pClZZISU0lxEwKr1z81EuJdiMLwWncjShXap25hiDGVMnCvlF5zS3ysvBdVRZqPDCdSTj06rwjrLX3bOS1Cak/","abc"},
	{"$6$saltstring$FJJAXr3hydAPJXM311wrzFhzheQ6LJHrufrYl2kBMnRD2pUi6jdS.fSBJ2J1Qfhcz9tPnlJOzeL7aIYi/dytg.","abcd"},
	{"$6$saltstring$XDecvJ/rq8tgbE1Pfuu1cTiZlhnbF5OA/vyP6HRPpDengVqhB38vbZTK/BDfPP6XBgvMzE.q9rj6Ck5blj/FK.","abcde"},
	{"$6$saltstring$hYPEYaHik6xSMGV1lDWhF0EerSUyCsC150POu9ksaftUWKWwV8TuqSeSLZUkUhjGy7cn.max5qd5IPSICeklL1","abcdef"},
	{"$6$saltstring$YBQ5J5EMRuC6k7B2GTsNaXx8u/957XMB.slQmY/lOjKd1zTIQF.ulLmy8O0VnJJ3cV.1pjP.KCgEjjMpz4pnS1","abcdefg"},
	{"$6$saltstring$AQapizZGhnIjtXF8OCvbSxQJBuOKvpzf1solf9b76wXFX0VRkqids5AC4YSibbhMSX0z4463sq1uAd9LvKNuO/","abcdefgh"},
	{"$6$saltstring$xc66FVXO.Zvv5pS02B4bCmJh5FCBAZpqTK3NoFxTU9U5b6BokbHwmeqQfMqrrkB3j9CXhCzgvC/pvoGPM1xgM1","abcdefghi"},
	{"$6$saltstring$Xet3A8EEzzSuL9hZZ31SfDVPT87qz3a.xxcH7eU50aqARlmXywdlfJ.6Cp/TFG1RcguqwrfUbZBbFn1BQ93Kv.","abcdefghij"},
	{"$6$saltstring$MeML1shJ8psyh5R9YJUZNYNqKzYeBvIsITqc/VqJfUDs8xO5YoUhCn4Db7CXuarMDVkBzIUfYq1d8Tj/T1WBU0","abcdefghijk"},
	{"$6$saltstring$i/3NHph8ZV2klLuOc5yX5kOnJWj9zuWbKiaa/NNEkYpNyamdQS1c7n2XQS3.B2Cs/eVyKwHf62PnOayqLLTOZ.","abcdefghijkl"},
	{"$6$saltstring$l2IxCS4o2S/vud70F1S5Z7H1WE67QFIXCYqskySdLFjjorEJdAnAp1ZqdgfNuZj2orjmeVDTsTXHpZ1IoxSKd.","abcdefghijklm"},
	{"$6$saltstring$PFzjspQs/CDXWALauDTav3u5bHB3n21xWrfwjnjpFO5eM5vuP0qKwDCXmlyZ5svEgsIH1oiZiGlRqkcBP5PiB.","abcdefghijklmn"},
	{"$6$saltstring$rdREv5Pd9C9YGtg.zXEQMb6m0sPeq4b6zFW9oWY9w4ZltmjH3yzMLgl9iBuez9DFFUvF5nJH3Y2xidiq1dH9M.","abcdefghijklmno"},
#endif
	{NULL}
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size(){

	return common_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static size_t get_task_max_size(){

	return common_get_task_max_size((amd_gcn(device_info[gpu_id]) ? 4 : 2),
		KEYS_PER_CORE_CPU, KEYS_PER_CORE_GPU, crypt_kernel);
}

static size_t get_safe_workgroup(){

	if (cpu(device_info[gpu_id]))
		return 1;

	else
		return 64;
}

static size_t get_default_workgroup(){
	size_t max_available;
	max_available = get_task_max_work_group_size();

	if (gpu_nvidia(device_info[gpu_id])) {
		global_work_size = GET_MULTIPLE(global_work_size, max_available);
		return max_available;

	} else
		return get_safe_workgroup();
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(size_t gws, struct fmt_main * self)
{
	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = gws;

	pinned_saved_keys = clCreateBuffer(context[gpu_id],
			CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(sha512_password) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

	plaintext = (sha512_password *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_saved_keys, CL_TRUE, CL_MAP_WRITE, 0,
			sizeof(sha512_password) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

	pinned_partial_hashes = clCreateBuffer(context[gpu_id],
			CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(sha512_hash) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

	calculated_hash = (sha512_hash *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
			sizeof(sha512_hash) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

	// create arguments (buffers)
	salt_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
			sizeof(sha512_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating salt_buffer out argument");

	pass_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
			sizeof(sha512_password) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

	hash_buffer = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
			sizeof(sha512_hash) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

	work_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
			sizeof(sha512_buffers) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument work_area");

	//Set kernel arguments
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
			(void *) &salt_buffer), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
			(void *) &pass_buffer), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
			(void *) &hash_buffer), "Error setting argument 2");

	if (_SPLIT_KERNEL_IN_USE) {
		//Set prepare kernel arguments
		HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 0, sizeof(cl_mem),
			(void *) &salt_buffer), "Error setting argument 0");
		HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 1, sizeof(cl_mem),
			(void *) &pass_buffer), "Error setting argument 1");
		HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 2, sizeof(cl_mem),
			(void *) &work_buffer), "Error setting argument 2");

		//Set crypt kernel arguments
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem),
			(void *) &work_buffer), "Error setting argument crypt_kernel (3)");

		//Set final kernel arguments
		HANDLE_CLERROR(clSetKernelArg(final_kernel, 0, sizeof(cl_mem),
				(void *) &salt_buffer), "Error setting argument 0");
		HANDLE_CLERROR(clSetKernelArg(final_kernel, 1, sizeof(cl_mem),
				(void *) &pass_buffer), "Error setting argument 1");
		HANDLE_CLERROR(clSetKernelArg(final_kernel, 2, sizeof(cl_mem),
				(void *) &hash_buffer), "Error setting argument 2");
		HANDLE_CLERROR(clSetKernelArg(final_kernel, 3, sizeof(cl_mem),
				(void *) &work_buffer), "Error setting argument 3");
	}
	memset(plaintext, '\0', sizeof(sha512_password) * gws);
}

static void release_clobj(void) {
	cl_int ret_code;

	ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_partial_hashes,
			calculated_hash, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping out_hashes");

	ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys,
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

	//Send salt information to GPU.
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], salt_buffer, CL_FALSE, 0,
		sizeof(sha512_salt), salt, 0, NULL, NULL),
		"failed in clEnqueueWriteBuffer salt_buffer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
}

static int salt_hash(void * salt) {

	return common_salt_hash(salt, SALT_SIZE, SALT_HASH_SIZE);
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

/* ------- Initialization  ------- */
static void build_kernel(char * task) {

	opencl_build_kernel(task, gpu_id, NULL, 1);

	// create kernel(s) to execute
	crypt_kernel = clCreateKernel(program[gpu_id], "kernel_crypt", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	if (_SPLIT_KERNEL_IN_USE) {
		prepare_kernel = clCreateKernel(program[gpu_id], "kernel_prepare", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel_prepare. Double-check kernel name?");
		final_kernel = clCreateKernel(program[gpu_id], "kernel_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel_final. Double-check kernel name?");
	}
}

static void init(struct fmt_main * self) {
	char * tmp_value;
	char * task = "$JOHN/kernels/cryptsha512_kernel_DEFAULT.cl";

	opencl_prepare_dev(gpu_id);
	source_in_use = device_info[gpu_id];

	if ((tmp_value = getenv("_TYPE")))
		source_in_use = atoi(tmp_value);

	if (_USE_GPU_SOURCE)
		task = "$JOHN/kernels/cryptsha512_kernel_GPU.cl";

	build_kernel(task);

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(STEP, HASH_LOOPS, ((_SPLIT_KERNEL_IN_USE) ? 7 : 3),
		((_SPLIT_KERNEL_IN_USE) ? split_events : NULL),
		warn, 1, self, create_clobj, release_clobj,
		sizeof(sha512_password), 0);

	if (source_in_use != device_info[gpu_id])
		fprintf(stderr, "Selected runtime id %d, source (%s)\n", source_in_use, task);

	//Auto tune execution from shared/included code.
	self->methods.crypt_all = crypt_all_benchmark;
	common_run_auto_tune(self, ROUNDS_DEFAULT, 0,
		(cpu(device_info[gpu_id]) ? 2000000000ULL : 7000000000ULL));
	self->methods.crypt_all = crypt_all;
}

static void done(void) {
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");

	if (_SPLIT_KERNEL_IN_USE) {
		HANDLE_CLERROR(clReleaseKernel(prepare_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(final_kernel), "Release kernel");
	}
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
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
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt) {
	int count = *pcount;
	int i;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	gws = GET_MULTIPLE_BIGGER(count, local_work_size);

	//Send data to device.
	if (new_keys)
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer, CL_FALSE, 0,
			sizeof(sha512_password) * gws, plaintext, 0, NULL, multi_profilingEvent[0]),
			"failed in clEnqueueWriteBuffer pass_buffer");

	//Enqueue the kernel
	if (_SPLIT_KERNEL_IN_USE) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], prepare_kernel, 1, NULL,
			&gws, lws, 0, NULL, multi_profilingEvent[3]),
			"failed in clEnqueueNDRangeKernel I");

		for (i = 0; i < 3; i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
				&gws, lws, 0, NULL,
				multi_profilingEvent[split_events[i]]),  //1, 4, 5
				"failed in clEnqueueNDRangeKernel");
		}
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], final_kernel, 1, NULL,
			&gws, lws, 0, NULL, multi_profilingEvent[6]),
			"failed in clEnqueueNDRangeKernel II");
	} else
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
			&gws, lws, 0, NULL, multi_profilingEvent[1]),
			"failed in clEnqueueNDRangeKernel");

	//Read back hashes
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], hash_buffer, CL_FALSE, 0,
			sizeof(sha512_hash) * gws, calculated_hash, 0, NULL, multi_profilingEvent[2]),
			"failed in reading data back");

	//Do the work
	BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	new_keys = 0;

	return count;
}

static int crypt_all(int *pcount, struct db_salt *_salt)
{
	int count = *pcount;
	int i;
	size_t gws;

	gws = GET_MULTIPLE_BIGGER(count, local_work_size);

	//Send data to device.
	if (new_keys)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer, CL_FALSE, 0,
			sizeof(sha512_password) * gws, plaintext, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer pass_buffer");

	//Enqueue the kernel
	if (_SPLIT_KERNEL_IN_USE) {
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], prepare_kernel, 1, NULL,
			&gws, &local_work_size, 0, NULL, NULL),
			"failed in clEnqueueNDRangeKernel I");

		for (i = 0; i < (salt->rounds / HASH_LOOPS); i++) {
			HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
				&gws, &local_work_size, 0, NULL, NULL),
				"failed in clEnqueueNDRangeKernel");
			HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			opencl_process_event();
		}
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], final_kernel, 1, NULL,
			&gws, &local_work_size, 0, NULL, NULL),
			"failed in clEnqueueNDRangeKernel II");
	} else
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
			&gws, &local_work_size, 0, NULL, NULL),
			"failed in clEnqueueNDRangeKernel");

	//Read back hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], hash_buffer, CL_FALSE, 0,
			sizeof(sha512_hash) * gws, calculated_hash, 0, NULL, NULL),
			"failed in reading data back");

	//Do the work
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	new_keys = 0;

	return count;
}

/* ------- Binary Hash functions group ------- */
static int get_hash_0(int index) { return calculated_hash[index].v[0] & 0xf; }
static int get_hash_1(int index) { return calculated_hash[index].v[0] & 0xff; }
static int get_hash_2(int index) { return calculated_hash[index].v[0] & 0xfff; }
static int get_hash_3(int index) { return calculated_hash[index].v[0] & 0xffff; }
static int get_hash_4(int index) { return calculated_hash[index].v[0] & 0xfffff; }
static int get_hash_5(int index) { return calculated_hash[index].v[0] & 0xffffff; }
static int get_hash_6(int index) { return calculated_hash[index].v[0] & 0x7ffffff; }

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	sha512_salt *sha512crypt_salt;
	sha512crypt_salt = salt;
	return (unsigned int)sha512crypt_salt->rounds;
}
#endif

/* ------- Format structure ------- */
struct fmt_main fmt_opencl_cryptsha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH - 1,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
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

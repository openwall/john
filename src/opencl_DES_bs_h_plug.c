/*
 * This software is Copyright (c) 2012-2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#ifdef HAVE_OPENCL

#include <string.h>
#include <sys/time.h>

#if _OPENMP
#include <omp.h>
#endif

#include "options.h"
#include "opencl_DES_bs.h"
#include "../run/opencl/opencl_DES_hst_dev_shared.h"
#include "mask_ext.h"
#include "john.h"

#define PADDING 	2048

#if JOHN_SYSTEMWIDE
#define CONFIG_FILE	JOHN_PRIVATE_HOME "/opencl/DES_bs_kernel_h_%s.config"
#define BINARY_FILE	JOHN_PRIVATE_HOME "/opencl/DES_bs_kernel_h_"Zu"_%s_%d.bin"
#else
#define CONFIG_FILE	"$JOHN/opencl/DES_bs_kernel_h_%s.config"
#define BINARY_FILE	"$JOHN/opencl/DES_bs_kernel_h_"Zu"_%s_%d.bin"
#endif

static cl_kernel **kernels;
static cl_mem buffer_map, buffer_bs_keys, buffer_unchecked_hashes;
static WORD *marked_salts, current_salt;
static unsigned int *processed_salts;
static int mask_mode;

static int des_crypt_25(int *pcount, struct db_salt *salt);

static void create_clobj_kpc(size_t gws)
{
	unsigned int iter_count = (mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH;

	create_keys_buffer(gws, PADDING);

	buffer_bs_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (gws * iter_count + PADDING) * sizeof(DES_bs_vector) * 56, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_bs_keys failed.\n");

	buffer_unchecked_hashes = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (gws * iter_count + PADDING) * sizeof(DES_bs_vector) * 64, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_unchecked_hashes failed.\n");
}

static void release_clobj_kpc()
{
	if (buffer_bs_keys != (cl_mem)0) {
		release_keys_buffer();
		HANDLE_CLERROR(clReleaseMemObject(buffer_bs_keys), "Release buffer_bs_keys failed.\n");
		HANDLE_CLERROR(clReleaseMemObject(buffer_unchecked_hashes), "Release buffer_unchecked_hashes failed.\n");
		buffer_bs_keys = (cl_mem)0;
	}
}

static void create_clobj(struct db_main *db)
{
	int i;

	marked_salts = (WORD *) mem_alloc(4096 * sizeof(WORD));

	for (i = 0; i < 4096; i++)
		marked_salts[i] = 0x7fffffff;

	opencl_DES_bs_init_index();

	buffer_map = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 768 * sizeof(unsigned int), opencl_DES_bs_index768, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_map.\n");

	create_int_keys_buffer();
	build_tables(db);
}

static void release_clobj()
{
	int i;

	if (buffer_map) {
		MEM_FREE(marked_salts);
		HANDLE_CLERROR(clReleaseMemObject(buffer_map), "Release buffer_map failed.\n");
		release_tables();
		release_int_keys_buffer();
		buffer_map = 0;
	}

	for (i = 0; i < 4096; i++)
		if (kernels[gpu_id][i]) {
			HANDLE_CLERROR(clReleaseKernel(kernels[gpu_id][i]), "Release kernel(crypt(i)) failed.\n");
			kernels[gpu_id][i] = 0;
		}
}

static void clean_all_buffers()
{
	int i;

	release_clobj();
	release_clobj_kpc();

	for ( i = 0; i < 4096; i++)
		if (kernels[gpu_id][i])
		HANDLE_CLERROR(clReleaseKernel(kernels[gpu_id][i]), "Error releasing kernel");

	if (program[gpu_id]) {
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Error releasing Program");
		program[gpu_id] = NULL;
	}

	for (i = 0; i < MAX_GPU_DEVICES; i++)
		MEM_FREE(kernels[i]);

	MEM_FREE(kernels);
	MEM_FREE(processed_salts);

	finish_checking();
}

/* First call must use salt = 0, to initialize processed_salts. */
static void build_salt(WORD salt)
{
	WORD new;
	static WORD old = 0xffffff;
	int dst;

	new = salt;
	for (dst = 0; dst < 24; dst++) {
		if ((new ^ old) & 1) {
			DES_bs_vector sp1, sp2;
			int src1 = dst;
			int src2 = dst + 24;
			if (new & 1) {
				src1 = src2;
				src2 = dst;
			}
			sp1 = opencl_DES_E[src1];
			sp2 = opencl_DES_E[src2];
			processed_salts[4096 * 96 + dst] = sp1;
			processed_salts[4096 * 96 + dst + 24] = sp2;
			processed_salts[4096 * 96 + dst + 48] = sp1 + 32;
			processed_salts[4096 * 96 + dst + 72] = sp2 + 32;
		}
		new >>= 1;
		old >>= 1;
		if (new == old)
			break;
	}
	old = salt;
	memcpy(&processed_salts[salt * 96], &processed_salts[4096 * 96], 96 * sizeof(unsigned int));
}

static void init_global_variables()
{
	int i;

	processed_salts = (unsigned int *) mem_calloc(4097, 96 * sizeof(unsigned int));

	kernels = (cl_kernel **) mem_calloc(MAX_GPU_DEVICES, sizeof(cl_kernel *));

	for (i = 0; i < MAX_GPU_DEVICES; i++)
		kernels[i] = (cl_kernel *) mem_calloc(4096, sizeof(cl_kernel));

	init_checking();

	mask_int_cand_target = opencl_speed_index(gpu_id) / 3000;
}

static char* enc_salt(WORD salt_val)
{
	unsigned int  index[48]  = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
				24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
				48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
				72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83};

	char *build_opts;
	unsigned int i, j;

	build_opts = (char *)mem_calloc(1000, sizeof(char));

	for (i = 0, j = 0; i < 48; i++) {
		sprintf(build_opts + j, "-D index%u=%u ", index[i], processed_salts[salt_val * 96 + index[i]]);
		j = strlen(build_opts);
	}

	return build_opts;
}

static void set_salt(void *salt)
{
	current_salt = *(WORD *)salt;
}

static void modify_build_save_restore(WORD salt_val, int id_gpu, int save_binary, int force_build, size_t lws, cl_program *program_ptr) {
	char kernel_bin_name[200];
	char *kernel_source = NULL;
	char *d_name, *full_path;
	FILE *file;

	sprintf(kernel_bin_name, BINARY_FILE, lws, d_name = get_device_name(id_gpu), salt_val);
	MEM_FREE(d_name);

	file = fopen(full_path = (char*)path_expand_safe(kernel_bin_name), "r");
	MEM_FREE(full_path);

	if (file == NULL || force_build) {
		char build_opts[10000];
		char *encoded_salt;
		char *kernel_filename = "$JOHN/opencl/DES_bs_kernel_h.cl";

		encoded_salt = enc_salt(salt_val);

		opencl_read_source(kernel_filename, &kernel_source);
		if (get_platform_vendor_id(get_platform_id(id_gpu)) != DEV_AMD)
			sprintf(build_opts, "-D WORK_GROUP_SIZE="Zu" %s", lws, encoded_salt);
		else
			sprintf(build_opts, "-D WORK_GROUP_SIZE="Zu" -fno-bin-amdil -fno-bin-source -fbin-exe %s", lws, encoded_salt);

		MEM_FREE(encoded_salt);
		opencl_build(id_gpu, build_opts, save_binary, kernel_bin_name, program_ptr, kernel_filename, kernel_source);

		if (options.verbosity > VERB_DEFAULT)
			fprintf(stderr, "Salt compiled from Source:%d\n", salt_val);

	}
	else {
		size_t program_size;
		fclose(file);
		program_size = opencl_read_source(kernel_bin_name, &kernel_source);
		HANDLE_CLERROR(opencl_build_from_binary(id_gpu, program_ptr, kernel_source, program_size), "kernel build failed");

		if (options.verbosity > VERB_DEFAULT)
			fprintf(stderr, "Salt compiled from Binary:%d\n", salt_val);
	}
	MEM_FREE(kernel_source);
}


static void init_kernel(WORD salt_val, int id_gpu, int save_binary, int force_build, size_t lws)
{
	cl_program program;
	cl_int err_code;

	if (marked_salts[salt_val] == salt_val) return;

	modify_build_save_restore(salt_val, id_gpu, save_binary, force_build, lws, &program);

	kernels[id_gpu][salt_val] = clCreateKernel(program, "DES_bs_25", &err_code);
	HANDLE_CLERROR(err_code, "Create Kernel DES_bs_25 failed.\n");
#if _OPENMP
#pragma omp critical
#endif
{
	HANDLE_CLERROR(clSetKernelArg(kernels[id_gpu][salt_val], 0, sizeof(cl_mem), &buffer_map), "Failed setting kernel argument buffer_map, kernel DES_bs_25.\n");
}
	marked_salts[salt_val] = salt_val;

	HANDLE_CLERROR(clReleaseProgram(program), "Error releasing Program");
}

static void set_kernel_args_kpc()
{
	int i;

	for (i = 0; i < 4096; i++) {
		if (marked_salts[i] == i) {
			HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][i], 1, sizeof(cl_mem), &buffer_bs_keys), "Failed setting kernel argument buffer_bs_keys, kernel DES_bs_25.\n");
			HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][i], 2, sizeof(cl_mem), &buffer_unchecked_hashes), "Failed setting kernel argument buffer_unchecked_hashes, kernel DES_bs_25.\n");
		}
	}

	set_common_kernel_args_kpc(buffer_unchecked_hashes, buffer_bs_keys);
}

/* if returns 0x800000, means there is no restriction on lws due to local memory limitations.*/
/* if returns 0, means local memory shouldn't be allocated.*/
static size_t find_smem_lws_limit(unsigned int force_global_keys)
{
	cl_ulong s_mem_sz = get_local_memory_size(gpu_id);
	size_t expected_lws_limit;
	cl_uint warp_size;

	if (force_global_keys)
		return 0x800000;

	if (!s_mem_sz)
		return 0;

	if (gpu_amd(device_info[gpu_id])) {
		if (clGetDeviceInfo(devices[gpu_id], CL_DEVICE_WAVEFRONT_WIDTH_AMD,
		                    sizeof(cl_uint), &warp_size, 0) != CL_SUCCESS)
			warp_size = 64;
	}
	else if (gpu_nvidia(device_info[gpu_id])) {
		if (clGetDeviceInfo(devices[gpu_id], CL_DEVICE_WARP_SIZE_NV,
		                    sizeof(cl_uint), &warp_size, 0) != CL_SUCCESS)
			warp_size = 32;
	}
	else
		warp_size = 1;

	expected_lws_limit = s_mem_sz /
			(sizeof(DES_bs_vector) * 56);
	if (!expected_lws_limit)
		return 0;
	expected_lws_limit = GET_MULTIPLE_OR_ZERO(
			expected_lws_limit, warp_size);

	if (warp_size == 1 && expected_lws_limit & (expected_lws_limit - 1)) {
		get_power_of_two(expected_lws_limit);
		expected_lws_limit >>= 1;
	}

	return expected_lws_limit;
}

#define calc_ms(start, end)	\
		((long double)(end.tv_sec - start.tv_sec) * 1000.000 + \
			(long double)(end.tv_usec - start.tv_usec) / 1000.000)

/* Sets global_work_size and max_keys_per_crypt. */
static void gws_tune(size_t gws_init, long double kernel_run_ms, int gws_tune_flag, struct fmt_main *format, WORD test_salt, int mask_mode)
{
	unsigned int i;
	char key[PLAINTEXT_LENGTH + 1] = "alterit";

	struct timeval startc, endc;
	long double time_ms = 0;
	int pcount;
	unsigned int des_log_depth = mask_mode ? 0 : DES_LOG_DEPTH;
	size_t iter_count = (mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH;

	size_t gws_limit = get_max_mem_alloc_size(gpu_id) / (sizeof(opencl_DES_bs_transfer) * iter_count) ;
	if (gws_limit > PADDING)
		gws_limit -= PADDING;

	if (gws_limit & (gws_limit - 1)) {
		get_power_of_two(gws_limit);
		gws_limit >>= 1;
	}

#if SIZEOF_SIZE_T > 4
	/* We can't process more than 4G keys per crypt() */
	while (gws_limit * mask_int_cand.num_int_cand > 0xffffffffUL)
		gws_limit >>= 1;
#endif

	if (gws_tune_flag)
		global_work_size = gws_init;

	if (global_work_size > gws_limit)
		global_work_size = gws_limit;

	if (gws_tune_flag) {
		release_clobj_kpc();
		create_clobj_kpc(global_work_size);
		set_kernel_args_kpc();

		format->methods.clear_keys();
		for (i = 0; i < (global_work_size << des_log_depth); i++) {
			key[i & 3] = i & 255;
			key[(i & 3) + 3] = i ^ 0x3E;
			format->methods.set_key(key, i);
		}
		set_salt(&test_salt);

		gettimeofday(&startc, NULL);
		pcount = (int)(global_work_size << des_log_depth);
		des_crypt_25((int *)&pcount, NULL);
		gettimeofday(&endc, NULL);

		time_ms = calc_ms(startc, endc);
		global_work_size = (size_t)((kernel_run_ms / time_ms) * (long double)global_work_size);
	}

	if (global_work_size < local_work_size)
		global_work_size = local_work_size;

	get_power_of_two(global_work_size);

	if (global_work_size > gws_limit)
		global_work_size = gws_limit;

	release_clobj_kpc();
	create_clobj_kpc(global_work_size);
	set_kernel_args_kpc();

	/* for hash_ids[2*x + 1], 27 bits for storing gid and 5 bits for bs depth. */
	//assert(global_work_size <= ((1U << 28) - 1));
	fmt_opencl_DES.params.max_keys_per_crypt =
		global_work_size << des_log_depth;

	fmt_opencl_DES.params.min_keys_per_crypt =
		opencl_calc_min_kpc(local_work_size,
		                    global_work_size,
		                    1 << des_log_depth);
}

static void release_kernels()
{
	int i;

	for (i = 0; i < 4096; i++)
	if (marked_salts[i] == i) {
		HANDLE_CLERROR(clReleaseKernel(kernels[gpu_id][i]), "Release kernel(crypt(i)) failed.\n");
		kernels[gpu_id][i] = 0;
		marked_salts[i] = 0x7fffffff;
		}
}

static void auto_tune_all(long double kernel_run_ms, struct fmt_main *format, WORD test_salt, int mask_mode, size_t extern_lws_limit, unsigned int *forced_global_keys)
{
	unsigned int force_global_keys = 1;
	unsigned int gws_tune_flag = 1;
	unsigned int lws_tune_flag = 1;

	size_t s_mem_limited_lws;

	struct timeval startc, endc;
	long double time_ms = 0;

	char key[PLAINTEXT_LENGTH + 1] = "alterit";

	unsigned int des_log_depth = mask_mode ? 0 : DES_LOG_DEPTH;

	if (cpu(device_info[gpu_id])) {
		if (get_platform_vendor_id(platform_id) == DEV_AMD)
			force_global_keys = 0;
		else
			force_global_keys = 1;
		kernel_run_ms = 5;
	}
	else if (amd_vliw4(device_info[gpu_id]) || amd_vliw5(device_info[gpu_id]) || gpu_intel(device_info[gpu_id])) {
		force_global_keys = 0;
	}
	else if (gpu_nvidia(device_info[gpu_id])) {
		force_global_keys = 1;
	}
	else if (gpu(device_info[gpu_id])) {
		force_global_keys = 0;
	}
	else {
		force_global_keys = 1;
		kernel_run_ms = 40;
	}

	local_work_size = 0;
	global_work_size = 0;
	gws_tune_flag = 1;
	lws_tune_flag = 1;
	opencl_get_user_preferences(FORMAT_LABEL);
	if (global_work_size)
		gws_tune_flag = 0;
	if (local_work_size || restore_lws_config(CONFIG_FILE, gpu_id, &local_work_size, extern_lws_limit, forced_global_keys)) {
		lws_tune_flag = 0;
		if (local_work_size & (local_work_size - 1)) {
			get_power_of_two(local_work_size);
		}
	}

	s_mem_limited_lws = find_smem_lws_limit(force_global_keys);
#if 0
	fprintf(stdout, "Limit_smem:"Zu", Force global keys:%u,"
		s_mem_limited_lws, force_global_keys);
#endif

	if (s_mem_limited_lws == 0x800000 || !s_mem_limited_lws) {
		long double best_time_ms;
		size_t best_lws, lws_limit;

		*forced_global_keys = 1;

		release_kernels();
		init_kernel(test_salt, gpu_id, 0, 1, 0);

		gws_tune(1024, 2 * kernel_run_ms, gws_tune_flag, format, test_salt, mask_mode);
		gws_tune(global_work_size, kernel_run_ms, gws_tune_flag, format, test_salt, mask_mode);

		lws_limit = get_kernel_max_lws(gpu_id, kernels[gpu_id][test_salt]);

		if (lws_limit > global_work_size)
			lws_limit = global_work_size;
		if (lws_limit > extern_lws_limit)
			lws_limit = extern_lws_limit;

		if (lws_tune_flag) {
			if (gpu(device_info[gpu_id]) && lws_limit >= 32)
				local_work_size = 32;
			else
				local_work_size = get_kernel_preferred_multiple(gpu_id, kernels[gpu_id][test_salt]);
		}
		if (local_work_size > lws_limit)
			local_work_size = lws_limit;

		if (lws_tune_flag) {
			time_ms = 0;
			best_time_ms = 999999.00;
			best_lws = local_work_size;
			while (local_work_size <= lws_limit &&
				local_work_size <= PADDING) {
				int pcount, i;

				format->methods.clear_keys();
				for (i = 0; i < (global_work_size << des_log_depth); i++) {
					key[i & 3] = i & 255;
					key[(i & 3) + 3] = i ^ 0x3F;
					format->methods.set_key(key, i);
				}
				set_salt(&test_salt);

				gettimeofday(&startc, NULL);
				pcount = (int)(global_work_size << des_log_depth);
				des_crypt_25((int *)&pcount, NULL);
				gettimeofday(&endc, NULL);

				time_ms = calc_ms(startc, endc);

				if (time_ms < best_time_ms) {
					best_lws = local_work_size;
					best_time_ms = time_ms;
				}
#if 0
	fprintf(stdout, "GWS: "Zu", LWS: "Zu", Limit_smem:"Zu", Limit_kernel:"Zu","
		"Current time:%Lf, Best time:%Lf\n",
		global_work_size, local_work_size, s_mem_limited_lws,
		get_kernel_max_lws(gpu_id, kernels[gpu_id][test_salt]), time_ms,
		best_time_ms);
#endif
				local_work_size *= 2;
			}
			local_work_size = best_lws;
			gws_tune(global_work_size, kernel_run_ms, gws_tune_flag, format, test_salt, mask_mode);
		}
	}

	else {
		long double best_time_ms;
		size_t best_lws;
		cl_uint warp_size;

		if (gpu_amd(device_info[gpu_id])) {
			if (clGetDeviceInfo(devices[gpu_id], CL_DEVICE_WAVEFRONT_WIDTH_AMD,
			                    sizeof(cl_uint), &warp_size, 0) != CL_SUCCESS)
				warp_size = 64;
		}
		else if (gpu_nvidia(device_info[gpu_id])) {
			if (clGetDeviceInfo(devices[gpu_id], CL_DEVICE_WARP_SIZE_NV,
			                    sizeof(cl_uint), &warp_size, 0) != CL_SUCCESS)
				warp_size = 32;
		}
		else {
			warp_size = 1;
			//if (!(cpu(device_info[gpu_id]) || gpu_intel(device_info[gpu_id])))
				//fprintf(stderr, "Possible auto_tune fail!!.\n");
		}

		if (lws_tune_flag)
			local_work_size = warp_size;
		if (s_mem_limited_lws > extern_lws_limit)
			s_mem_limited_lws = extern_lws_limit;
		if (local_work_size > s_mem_limited_lws)
			local_work_size = s_mem_limited_lws;

		release_kernels();
		init_kernel(test_salt, gpu_id, 0, 1, local_work_size);

		if (local_work_size > get_kernel_max_lws(gpu_id, kernels[gpu_id][test_salt])) {
			local_work_size = get_kernel_max_lws(gpu_id, kernels[gpu_id][test_salt]);
			release_kernels();
			init_kernel(test_salt, gpu_id, 0, 1, local_work_size);
		}

		gws_tune(1024, 2 * kernel_run_ms, gws_tune_flag, format, test_salt, mask_mode);
		gws_tune(global_work_size, kernel_run_ms, gws_tune_flag, format, test_salt, mask_mode);

		if (global_work_size < s_mem_limited_lws) {
			s_mem_limited_lws = global_work_size;
			if (local_work_size > s_mem_limited_lws)
				local_work_size = s_mem_limited_lws;
		}

		if (lws_tune_flag) {
			best_time_ms = 999999.00;
			best_lws = local_work_size;
			while (local_work_size <= s_mem_limited_lws &&
				local_work_size <= PADDING) {
				int pcount, i;

				release_kernels();
				init_kernel(test_salt, gpu_id, 0, 1, local_work_size);
				set_kernel_args_kpc();

				format->methods.clear_keys();
				for (i = 0; i < (global_work_size << des_log_depth); i++) {
					key[i & 3] = i & 255;
					key[(i & 3) + 3] = i ^ 0x3E;
					format->methods.set_key(key, i);
				}
				set_salt(&test_salt);

				gettimeofday(&startc, NULL);
				pcount = (int)(global_work_size << des_log_depth);
				des_crypt_25((int *)&pcount, NULL);
				gettimeofday(&endc, NULL);
				time_ms = calc_ms(startc, endc);

				if (time_ms < best_time_ms &&
				  local_work_size <= get_kernel_max_lws(
				    gpu_id, kernels[gpu_id][test_salt])) {
					best_lws = local_work_size;
					best_time_ms = time_ms;
				}
#if 0
	fprintf(stdout, "GWS: "Zu", LWS: "Zu", Limit_smem:"Zu", Limit_kernel:"Zu","
		"Current time:%Lf, Best time:%Lf\n",
		global_work_size, local_work_size, s_mem_limited_lws,
		get_kernel_max_lws(gpu_id, kernels[gpu_id][test_salt]), time_ms,
		best_time_ms);
#endif
				if (gpu_amd(device_info[gpu_id]) || gpu_nvidia(device_info[gpu_id])) {
					if (local_work_size < 16)
						local_work_size = 16;
					else if (local_work_size < 32)
						local_work_size = 32;
					else if (local_work_size < 64)
						local_work_size = 64;
					else if (local_work_size < 96)
						local_work_size = 96;
					else if (local_work_size < 128)
						local_work_size = 128;
					else
						local_work_size += warp_size;
				}
				else
					local_work_size *= 2;
			}
			local_work_size = best_lws;
			release_kernels();
			init_kernel(test_salt, gpu_id, 0, 1, local_work_size);
			set_kernel_args_kpc();
			gws_tune(global_work_size, kernel_run_ms, gws_tune_flag, format, test_salt, mask_mode);
		}
	}
	release_kernels();
	if (lws_tune_flag)
		save_lws_config(CONFIG_FILE, gpu_id, local_work_size, *forced_global_keys);

	if ((!self_test_running && options.verbosity >= VERB_DEFAULT) || ocl_always_show_ws) {
		if (mask_int_cand.num_int_cand > 1)
			fprintf(stderr, "LWS="Zu" GWS="Zu" x%d%s", local_work_size,
			        global_work_size, mask_int_cand.num_int_cand, (options.flags & FLG_TEST_CHK) ? " " : "\n");
		else
			fprintf(stderr, "LWS="Zu" GWS="Zu"%s", local_work_size,
			        global_work_size, (options.flags & FLG_TEST_CHK) ? " " : "\n");
	}
}

static void reset(struct db_main *db)
{
	static int initialized;
	int i;
	size_t extern_lws_limit, limit_temp;
	unsigned int forced_global_keys = 0;

	if (initialized) {
		struct db_salt *salt;
		WORD salt_list[4096];
		unsigned int num_salts, i;

		release_clobj_kpc();
		release_clobj();

		if ((options.flags & FLG_MASK_CHK) && mask_int_cand.num_int_cand > 1)
			mask_mode = 1;

		create_clobj(db);
		if (!mask_mode)
			create_clobj_kpc(global_work_size);

		extern_lws_limit = create_checking_kernel_set_args();
		limit_temp = create_keys_kernel_set_args(mask_mode);
		if (limit_temp < extern_lws_limit)
			extern_lws_limit = limit_temp;

		if (mask_mode) {
			unsigned int max_uncracked_hashes = 0;
			WORD test_salt = 0;

			salt = db->salts;
			max_uncracked_hashes = 0;
			do {
				if (salt->count > max_uncracked_hashes) {
					max_uncracked_hashes = salt->count;
					test_salt = *(WORD *)salt->salt;
				}

			} while ((salt = salt->next));

			forced_global_keys = 0;
			auto_tune_all(100, &fmt_opencl_DES, test_salt, mask_mode, extern_lws_limit, &forced_global_keys);
		}

		salt = db->salts;
		num_salts = 0;
		do {
			salt_list[num_salts++] = (*(WORD *)salt->salt);
		} while ((salt = salt->next));

		if (num_salts > 10 && !ocl_any_test_running && john_main_process)
			fprintf(stderr, "Building %d per-salt kernels, one dot per three salts done: ", num_salts);

#if _OPENMP && PARALLEL_BUILD
#pragma omp parallel for
#endif
		for (i = 0; i < num_salts; i++) {
			init_kernel(salt_list[i], gpu_id, 1, 0, forced_global_keys ? 0 :local_work_size);

#if _OPENMP && PARALLEL_BUILD
			if (omp_get_thread_num() == 0)
#endif
			{
				opencl_process_event();
			}
			if (num_salts > 10 && (i % 3) == 2 && !ocl_any_test_running && john_main_process)
				fprintf(stderr, ".");
		}
		if (num_salts > 10 && !ocl_any_test_running && john_main_process)
			fprintf(stderr, " Done!\n");
		set_kernel_args_kpc();
	}
	else {
		char *ciphertext;
		WORD salt_val;

		create_clobj(NULL);

		extern_lws_limit = create_checking_kernel_set_args();
		limit_temp = create_keys_kernel_set_args(0);
		if (limit_temp < extern_lws_limit)
			extern_lws_limit = limit_temp;

		for (i = 0; i < 4096; i++)
			build_salt((WORD)i);

		salt_val = *(WORD *)fmt_opencl_DES.methods.salt(fmt_opencl_DES.methods.split(
			fmt_opencl_DES.params.tests[0].ciphertext, 0, &fmt_opencl_DES));

		auto_tune_all(300, &fmt_opencl_DES, salt_val, 0, extern_lws_limit, &forced_global_keys);

		i = 0;
		while (fmt_opencl_DES.params.tests[i].ciphertext) {
			ciphertext = fmt_opencl_DES.methods.split(fmt_opencl_DES.params.tests[i].ciphertext, 0, &fmt_opencl_DES);
			salt_val = *(WORD *)fmt_opencl_DES.methods.salt(ciphertext);
			init_kernel(salt_val, gpu_id, 1, 0, forced_global_keys ? 0 :local_work_size);
			i++;
		}

		set_kernel_args_kpc();

		initialized++;
	}
}

static int des_crypt_25(int *pcount, struct db_salt *salt)
{
	const int count = mask_mode ? *pcount : (*pcount + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t current_gws = local_work_size ? (count + local_work_size - 1) / local_work_size * local_work_size : count;
	size_t iter_count = (mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH;

	process_keys(current_gws, lws);

	if (salt && num_uncracked_hashes(current_salt) != salt->count &&
	/* In case there are duplicate hashes, num_uncracked_hashes is always less than salt->count, as
	 * num_uncracked_hashes tracks only unique hashes. */
		num_uncracked_hashes(current_salt) > salt->count)
		update_buffer(salt);

	current_gws *= iter_count;
	ret_code = clEnqueueNDRangeKernel(queue[gpu_id], kernels[gpu_id][current_salt], 1, NULL, &current_gws, lws, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Enqueue kernel DES_bs_25 failed.\n");

	*pcount = mask_mode ? *pcount * mask_int_cand.num_int_cand : *pcount;

	return extract_info(current_gws, lws, current_salt);
}

void opencl_DES_bs_h_register_functions(struct fmt_main *fmt)
{
	fmt->methods.done = &clean_all_buffers;
	fmt->methods.reset = &reset;
	fmt->methods.set_salt = &set_salt;
	fmt->methods.crypt_all = &des_crypt_25;

	opencl_DES_bs_init_global_variables = &init_global_variables;
}
#endif /* HAVE_OPENCL */

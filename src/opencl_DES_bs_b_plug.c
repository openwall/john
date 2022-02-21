/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#ifdef HAVE_OPENCL

#include <string.h>
#include <sys/time.h>

#include "options.h"
#include "opencl_DES_bs.h"
#include "../run/opencl/opencl_DES_hst_dev_shared.h"
#include "mask_ext.h"

#if JOHN_SYSTEMWIDE
#define CONFIG_FILE	JOHN_PRIVATE_HOME "/opencl/DES_bs_kernel_b_%s.config"
#else
#define CONFIG_FILE	"$JOHN/opencl/DES_bs_kernel_b_%s.config"
#endif

#define PADDING 	2048

static cl_kernel **kernels;
static cl_mem buffer_map, buffer_bs_keys, *buffer_processed_salts, buffer_unchecked_hashes;
static WORD current_salt;

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

	buffer_processed_salts = (cl_mem *) mem_alloc(4096 * sizeof(cl_mem));

	for (i = 0; i < 4096; i++) {
		buffer_processed_salts[i] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 48 * sizeof(unsigned int), NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Create buffer_processed_salts failed.\n");
	}

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
		HANDLE_CLERROR(clReleaseMemObject(buffer_map), "Release buffer_map failed.\n");
		release_tables();
		release_int_keys_buffer();
		for (i = 0; i < 4096; i++)
			if (buffer_processed_salts[i] != (cl_mem)0)
				HANDLE_CLERROR(clReleaseMemObject(buffer_processed_salts[i]), "Release buffer_processed_salts failed.\n");
		MEM_FREE(buffer_processed_salts);
		buffer_map = 0;
	}
}

static void clean_all_buffers()
{
	int i;

	release_clobj();
	release_clobj_kpc();

	for ( i = 0; i < 1; i++) {
		if (kernels[gpu_id][i]) {
			HANDLE_CLERROR(clReleaseKernel(kernels[gpu_id][i]), "Error releasing kernel");
			kernels[gpu_id][i] = NULL;
		}
	}

	if (program[gpu_id]) {
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Error releasing Program");
		program[gpu_id] = NULL;
	}

	for (i = 0; i < MAX_GPU_DEVICES; i++)
		MEM_FREE(kernels[i]);

	MEM_FREE(kernels);

	finish_checking();
}

/* First call must use salt = 0, to initialize processed_salt. */
static void build_salt(WORD salt)
{
	WORD new;
	static WORD old = 0xffffff;
	static unsigned int processed_salt[96];
	unsigned int transfer[48];
	unsigned int  index[48]  = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
				24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
				48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
				72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83};
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
			processed_salt[dst] = sp1;
			processed_salt[dst + 24] = sp2;
			processed_salt[dst + 48] = sp1 + 32;
			processed_salt[dst + 72] = sp2 + 32;
		}
		new >>= 1;
		old >>= 1;
		if (new == old)
			break;
	}
	old = salt;
	for (dst = 0; dst < 48; dst++)
		transfer[dst] = processed_salt[index[dst]];
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_processed_salts[salt], CL_TRUE, 0, 48 * sizeof(unsigned int), transfer, 0, NULL, NULL), "Failed to write buffer buffer_processed_salts.\n");
}

static void set_kernel_args_kpc()
{
	HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 2, sizeof(cl_mem), &buffer_bs_keys), "Failed setting kernel argument buffer_bs_keys, kernel DES_bs_25_b.\n");
	HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 3, sizeof(cl_mem), &buffer_unchecked_hashes), "Failed setting kernel argument buffer_unchecked_hashes, kernel DES_bs_25_b.\n");

	set_common_kernel_args_kpc(buffer_unchecked_hashes, buffer_bs_keys);
}

static void set_salt(void *salt)
{
	current_salt = *(WORD *)salt;
}

static void init_kernel(int id_gpu, size_t s_mem_lws, unsigned int use_local_mem)
{
	char build_opts[600];

	sprintf(build_opts, "-D WORK_GROUP_SIZE="Zu" -D USE_LOCAL_MEM=%u", s_mem_lws, use_local_mem);;
	opencl_build_kernel("$JOHN/opencl/DES_bs_kernel.cl",
	                    id_gpu, build_opts, 0);
	kernels[id_gpu][0] = clCreateKernel(program[id_gpu], "DES_bs_25_b", &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating kernel DES_bs_25_b.\n");

	HANDLE_CLERROR(clSetKernelArg(kernels[id_gpu][0], 0, sizeof(cl_mem), &buffer_map), "Failed setting kernel argument buffer_map, kernel DES_bs_25_b.\n");
}

/* if returns 0x800000, means there is no restriction on lws due to local memory limitations.*/
/* if returns 0, means local memory shouldn't be allocated.*/
static size_t find_smem_lws_limit(unsigned int use_local_mem, unsigned int force_global_keys)
{
	cl_ulong s_mem_sz = get_local_memory_size(gpu_id);
	size_t expected_lws_limit;
	cl_uint warp_size;

	if (force_global_keys) {
		if (s_mem_sz > 768 * sizeof(cl_short))
			return 0x800000;
		else
			return 0;
	}

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

	if (!use_local_mem) {
		expected_lws_limit = s_mem_sz /
				(sizeof(DES_bs_vector) * 56);
		if (!expected_lws_limit)
			return 0;
		expected_lws_limit = GET_MULTIPLE_OR_ZERO(
				expected_lws_limit, warp_size);
	}
	else {
		if (s_mem_sz > 768 * sizeof(cl_short)) {
			s_mem_sz -= 768 * sizeof(cl_short);
			expected_lws_limit = s_mem_sz /
					(sizeof(DES_bs_vector) * 56);
			if (!expected_lws_limit)
				return 0x800000;
			expected_lws_limit = GET_MULTIPLE_OR_ZERO(
				expected_lws_limit, warp_size);
		}
		else
			return 0;
	}

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
			key[(i & 3) + 3] = i | 0x3F;
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
		opencl_calc_min_kpc(local_work_size, global_work_size,
		                    1 << des_log_depth);
}

static void release_kernel()
{
	if (kernels[gpu_id][0]) {
		HANDLE_CLERROR(clReleaseKernel(kernels[gpu_id][0]), "Release kernel(crypt(i)) failed.\n");
		kernels[gpu_id][0] = 0;
	}
}

static void auto_tune_all(long double kernel_run_ms, struct fmt_main *format, WORD test_salt, int mask_mode, size_t extern_lws_limit)
{
	unsigned int force_global_keys = 1;
	unsigned int use_local_mem = 1;
	unsigned int gws_tune_flag = 1;
	unsigned int lws_tune_flag = 1;

	size_t s_mem_limited_lws;

	struct timeval startc, endc;
	long double time_ms = 0;

	char key[PLAINTEXT_LENGTH + 1] = "alterit";

	unsigned int des_log_depth = mask_mode ? 0 : DES_LOG_DEPTH;

	unsigned int cc_major = 0, cc_minor = 0;
	get_compute_capability(gpu_id, &cc_major, &cc_minor);

	if (cpu(device_info[gpu_id])) {
		if (get_platform_vendor_id(platform_id) == DEV_AMD) {
			force_global_keys = 0;
			use_local_mem = 1;
		}
		else {
			force_global_keys = 1;
			use_local_mem = 0;
		}
		kernel_run_ms = 5;
	}
	else if (amd_vliw4(device_info[gpu_id]) || amd_vliw5(device_info[gpu_id]) || gpu_intel(device_info[gpu_id])) {
		force_global_keys = 0;
		use_local_mem = 1;
	}
	else if (gpu_nvidia(device_info[gpu_id]) && cc_major >= 7) {
		force_global_keys = 1;
		use_local_mem = 0;
	}
	else if (gpu(device_info[gpu_id])) {
		force_global_keys = 0;
		use_local_mem = 1;
	}
	else {
		force_global_keys = 1;
		use_local_mem = 0;
		kernel_run_ms = 40;
	}

	local_work_size = 0;
	global_work_size = 0;
	gws_tune_flag = 1;
	lws_tune_flag = 1;
	opencl_get_user_preferences(FORMAT_LABEL);
	if (global_work_size)
		gws_tune_flag = 0;
	if (local_work_size || restore_lws_config(CONFIG_FILE, gpu_id, &local_work_size, extern_lws_limit, NULL)) {
		lws_tune_flag = 0;
		if (local_work_size & (local_work_size - 1)) {
			get_power_of_two(local_work_size);
		}
	}

	s_mem_limited_lws = find_smem_lws_limit(use_local_mem, force_global_keys);
#if 0
	fprintf(stdout, "Limit_smem:"Zu", Force global keys:%u",
		s_mem_limited_lws, force_global_keys);
#endif

	if (s_mem_limited_lws == 0x800000 || !s_mem_limited_lws) {
		long double best_time_ms;
		size_t best_lws, lws_limit;

		release_kernel();
		init_kernel(gpu_id, 0, use_local_mem && s_mem_limited_lws);

		gws_tune(1024, 2 * kernel_run_ms, gws_tune_flag, format, test_salt, mask_mode);
		gws_tune(global_work_size, kernel_run_ms, gws_tune_flag, format, test_salt, mask_mode);

		lws_limit = get_kernel_max_lws(gpu_id, kernels[gpu_id][0]);

		if (lws_limit > global_work_size)
			lws_limit = global_work_size;
		if (lws_limit > extern_lws_limit)
			lws_limit = extern_lws_limit;

		if (lws_tune_flag) {
			if (gpu(device_info[gpu_id]) && lws_limit >= 32)
				local_work_size = 32;
			else
				local_work_size = get_kernel_preferred_multiple(gpu_id, kernels[gpu_id][0]);
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
		get_kernel_max_lws(gpu_id, kernels[gpu_id][0]), time_ms,
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

		release_kernel();
		init_kernel(gpu_id, local_work_size, use_local_mem);

		if (local_work_size > get_kernel_max_lws(gpu_id, kernels[gpu_id][0])) {
			local_work_size = get_kernel_max_lws(gpu_id, kernels[gpu_id][0]);
			release_kernel();
			init_kernel(gpu_id, local_work_size, use_local_mem);
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

				release_kernel();
				init_kernel(gpu_id, local_work_size, use_local_mem);
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
				    gpu_id, kernels[gpu_id][0])) {
					best_lws = local_work_size;
					best_time_ms = time_ms;
				}
#if 0
	fprintf(stdout, "GWS: "Zu", LWS: "Zu", Limit_smem:"Zu", Limit_kernel:"Zu","
		"Current time:%Lf, Best time:%Lf\n",
		global_work_size, local_work_size, s_mem_limited_lws,
		get_kernel_max_lws(gpu_id, kernels[gpu_id][0]), time_ms,
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
			release_kernel();
			init_kernel(gpu_id, local_work_size, use_local_mem);
			gws_tune(global_work_size, kernel_run_ms, gws_tune_flag, format, test_salt, mask_mode);
		}
	}
	if (lws_tune_flag)
		save_lws_config(CONFIG_FILE, gpu_id, local_work_size, 0);

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
	size_t extern_lws_limit, limit_temp;
	WORD salt_val = 0;

	if (initialized) {
		struct db_salt *salt;

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

		build_salt(0);

		salt = db->salts;
		do {
			salt_val = *(WORD *)(salt->salt);
			build_salt(salt_val);
		} while((salt = salt->next));

		if (mask_mode) {
			release_kernel();
			auto_tune_all(100, &fmt_opencl_DES, salt_val, mask_mode, extern_lws_limit);
		}

		set_kernel_args_kpc();
	}
	else {
		int i;

		create_clobj(NULL);

		extern_lws_limit = create_checking_kernel_set_args();
		limit_temp = create_keys_kernel_set_args(0);
		if (limit_temp < extern_lws_limit)
			extern_lws_limit = limit_temp;

		build_salt(0);
		i = 0;
		while (fmt_opencl_DES.params.tests[i].ciphertext) {
			char *ciphertext = fmt_opencl_DES.methods.split(fmt_opencl_DES.params.tests[i].ciphertext, 0, &fmt_opencl_DES);
			salt_val = *(WORD *)fmt_opencl_DES.methods.salt(ciphertext);
			build_salt(salt_val);
			i++;
		}

		auto_tune_all(300, &fmt_opencl_DES, salt_val, 0, extern_lws_limit);

		set_kernel_args_kpc();

		initialized++;
	}
}

static void init_global_variables()
{
	int i;

	kernels = (cl_kernel **) mem_calloc(MAX_GPU_DEVICES, sizeof(cl_kernel *));

	for (i = 0; i < MAX_GPU_DEVICES; i++)
		kernels[i] = (cl_kernel *) mem_calloc(1, sizeof(cl_kernel));

	init_checking();

	mask_int_cand_target = opencl_speed_index(gpu_id) / 3000;
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

	HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 1, sizeof(cl_mem), &buffer_processed_salts[current_salt]), "Failed setting kernel argument buffer_processed_salts, kernel DES_bs_25_b.\n");

	current_gws *= iter_count;
	ret_code = clEnqueueNDRangeKernel(queue[gpu_id], kernels[gpu_id][0], 1, NULL, &current_gws, lws, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Enqueue kernel DES_bs_25_b failed.\n");

	*pcount = mask_mode ? *pcount * mask_int_cand.num_int_cand : *pcount;

	return extract_info(current_gws, lws, current_salt);
}

void opencl_DES_bs_b_register_functions(struct fmt_main *fmt)
{
	fmt->methods.done = &clean_all_buffers;
	fmt->methods.reset = &reset;
	fmt->methods.set_salt = &set_salt;
	fmt->methods.crypt_all = &des_crypt_25;

	opencl_DES_bs_init_global_variables = &init_global_variables;
}
#endif /* HAVE_OPENCL */

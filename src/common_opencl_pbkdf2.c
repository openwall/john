/* This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
* This format supports salts upto 19 characters. Origial S3nf implementation supports only upto 8 charcters.
*/

#include <string.h>
#include <math.h>

#include "common_opencl_pbkdf2.h"
#include "memory.h"
#include "options.h"
#include "memdbg.h"

typedef struct {
	cl_kernel	krnl[4];
	size_t		lws;
	gpu_mem_buffer	gpu_buffer;
	long double 	exec_time_inv;
} globalData;

static globalData 	globalObj[MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM];
static cl_event 	events[MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM];
static int 		event_ctr = 0;
static cl_ulong 	kernelExecTimeNs = CL_ULONG_MAX;
static char 		PROFILE = 0;
static unsigned int 	active_dev_ctr = 0;

typedef struct {
	unsigned int 	istate[5];
	unsigned int 	ostate[5];
	unsigned int 	buf[5];
	unsigned int 	out[4];
} temp_buf;

static gpu_mem_buffer exec_pbkdf2(cl_uint *, cl_uint *, cl_uint, unsigned int, cl_uint *, cl_uint, int, cl_command_queue, cl_uint *);

static void clean_gpu_buffer(gpu_mem_buffer *pThis) {
	const char 	*errMsg = "Release Memory Object FAILED.";

	HANDLE_CLERROR(clReleaseMemObject(pThis -> pass_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(pThis -> hash_out_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(pThis -> salt_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(pThis -> temp_buf_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(pThis -> hmac_sha1_gpu), errMsg);
}

void clean_all_buffer() {
	int 	i;

	for (i = 0; i < active_dev_ctr; i++) {
		clean_gpu_buffer(&globalObj[gpu_device_list[i]].gpu_buffer);
		HANDLE_CLERROR(clReleaseKernel(globalObj[gpu_device_list[i]].krnl[0]), "Error releasing kernel pbkdf2_preprocess_short");
		HANDLE_CLERROR(clReleaseKernel(globalObj[gpu_device_list[i]].krnl[1]), "Error releasing kernel pbkdf2_preprocess_long");
		HANDLE_CLERROR(clReleaseKernel(globalObj[gpu_device_list[i]].krnl[2]), "Error releasing kernel pbkdf2_iter");
		HANDLE_CLERROR(clReleaseKernel(globalObj[gpu_device_list[i]].krnl[3]), "Error releasing kernel pbkdf2_postprocess");
	 }
}

static void find_best_workgroup(int jtrUniqDevNo, unsigned int gpu_perf) {
        size_t 		 _lws=0;
	cl_device_type 	 dTyp;
	cl_command_queue cmdq;
	cl_int 		 err;
	unsigned int 	 max_kpc
		       = get_max_mem_alloc_size(jtrUniqDevNo) / sizeof(temp_buf) < MAX_KEYS_PER_CRYPT ?
			 ((get_max_mem_alloc_size(jtrUniqDevNo) / sizeof(temp_buf)) / 8192 - 1) * 8192 :
			 MAX_KEYS_PER_CRYPT;
	cl_uint 	 *dcc_hash_host
		       = (cl_uint*)mem_alloc(4 * sizeof(cl_uint) * ((max_kpc < 65536) ? max_kpc : 65536));
	cl_uint 	 *dcc2_hash_host
		       = (cl_uint*)mem_alloc(4 * sizeof(cl_uint) * ((max_kpc < 65536) ? max_kpc : 65536));
	cl_uint		*hmac_sha1_out
		       = (cl_uint*)mem_alloc(5 * sizeof(cl_uint) * ((max_kpc < 65536) ? max_kpc : 65536));
	cl_uint salt_api[9], length = 10;

	event_ctr = 0;

	//HANDLE_CLERROR(clGetDeviceInfo(devices[jtrUniqDevNo], CL_DEVICE_TYPE, sizeof(cl_device_type), &dTyp, NULL), "Failed Device Info");
	dTyp = get_device_type(jtrUniqDevNo);
	if (dTyp == CL_DEVICE_TYPE_CPU)
		globalObj[jtrUniqDevNo].lws = 1;
	else
		globalObj[jtrUniqDevNo].lws = 16;

	///Set Dummy DCC hash , unicode salt and ascii salt(username) length
	memset(dcc_hash_host, 0xb5, 4 * sizeof(cl_uint) * ((max_kpc < 65536) ? max_kpc : 65536));
	memset(salt_api, 0xfe, 9 * sizeof(cl_uint));

	cmdq = clCreateCommandQueue(context[jtrUniqDevNo], devices[jtrUniqDevNo], CL_QUEUE_PROFILING_ENABLE, &err);
	HANDLE_CLERROR(err, "Error creating command queue");

	PROFILE = 1;
	kernelExecTimeNs = CL_ULONG_MAX;

	///Find best local work size
	while (1) {
		_lws = globalObj[jtrUniqDevNo].lws;
		if (dTyp == CL_DEVICE_TYPE_CPU)
			exec_pbkdf2(dcc_hash_host, salt_api, length, 10240, dcc2_hash_host, 4096, jtrUniqDevNo, cmdq, hmac_sha1_out);
		else
			exec_pbkdf2(dcc_hash_host, salt_api, length, 10240, dcc2_hash_host, (((max_kpc < 65536) ? max_kpc : 65536) / gpu_perf), jtrUniqDevNo, cmdq, hmac_sha1_out);

		if (globalObj[jtrUniqDevNo].lws <= _lws)
			break;
	}

	if (dTyp == CL_DEVICE_TYPE_CPU)
		globalObj[jtrUniqDevNo].exec_time_inv = globalObj[jtrUniqDevNo].exec_time_inv / 16;
	else
		globalObj[jtrUniqDevNo].exec_time_inv *= (((max_kpc < 65536) ? max_kpc : 65536) / (long double) gpu_perf) / 65536;

	PROFILE = 0;

	if (options.verbosity > 2) {
		fprintf(stderr, "Optimal Work Group Size:%d\n", (int)globalObj[jtrUniqDevNo].lws);
		fprintf(stderr, "Kernel Execution Speed (Higher is better):%Lf\n", globalObj[jtrUniqDevNo].exec_time_inv);
	}

	MEM_FREE(dcc_hash_host);
	MEM_FREE(dcc2_hash_host);
	HANDLE_CLERROR(clReleaseCommandQueue(cmdq), "Release Command Queue:Failed");
}

static unsigned int quick_bechmark(int jtrUniqDevNo) {
        cl_device_type 	 dTyp;
	cl_command_queue cmdq;
	cl_int 		 err;
	cl_uint 	 *dcc_hash_host
		       = (cl_uint*)mem_alloc(4 * sizeof(cl_uint) * 4096);
	cl_uint 	 *dcc2_hash_host
		       = (cl_uint*)mem_alloc(4 * sizeof(cl_uint) * 4096);
	cl_uint		*hmac_sha1_out
		       = (cl_uint*)mem_alloc(5 * sizeof(cl_uint) * 4096);
	cl_uint salt_api[9], length = 10;

	event_ctr = 0;

	//HANDLE_CLERROR(clGetDeviceInfo(devices[jtrUniqDevNo], CL_DEVICE_TYPE, sizeof(cl_device_type), &dTyp, NULL), "Failed Device Info");
	dTyp = get_device_type(jtrUniqDevNo);
	if (dTyp == CL_DEVICE_TYPE_CPU)
		globalObj[jtrUniqDevNo].lws = 1;
	else
		globalObj[jtrUniqDevNo].lws = 64;

	///Set Dummy DCC hash , unicode salt and ascii salt(username) length
	memset(dcc_hash_host, 0xb5, 4 * sizeof(cl_uint) * 4096);
	memset(salt_api, 0xfe, 9 * sizeof(cl_uint));

	cmdq = clCreateCommandQueue(context[jtrUniqDevNo], devices[jtrUniqDevNo], CL_QUEUE_PROFILING_ENABLE, &err);
	HANDLE_CLERROR(err, "Error creating command queue");

	PROFILE = 1;
	kernelExecTimeNs = CL_ULONG_MAX;

	exec_pbkdf2(dcc_hash_host, salt_api, length, 2048, dcc2_hash_host, 4096, jtrUniqDevNo, cmdq, hmac_sha1_out);

	PROFILE = 0;

	if (globalObj[jtrUniqDevNo].exec_time_inv < 15)
		return 4;
	else if (globalObj[jtrUniqDevNo].exec_time_inv < 25)
		return 2;
	else
		return 1;

	MEM_FREE(dcc_hash_host);
	MEM_FREE(dcc2_hash_host);
	HANDLE_CLERROR(clReleaseCommandQueue(cmdq), "Release Command Queue:Failed");
}

static size_t max_lws() {
	int 	i;
	size_t 	max = 0;

	for (i = 0; i < active_dev_ctr; ++i)
		if (max < globalObj[gpu_device_list[i]].lws)
			max = globalObj[gpu_device_list[i]].lws;

	return max;
}

static void find_best_gws(int jtrUniqDevNo, struct fmt_main *fmt) {

	long int 		gds_size, device_gds_size;
	static long double 	total_exec_time_inv;

	device_gds_size = (long int)globalObj[jtrUniqDevNo].exec_time_inv * 163840;
	if (device_gds_size * sizeof(temp_buf) > get_max_mem_alloc_size(jtrUniqDevNo)) {
		device_gds_size = ((get_max_mem_alloc_size(jtrUniqDevNo) / sizeof(temp_buf)) / 8192) * 8192;
		gds_size = (long int)(total_exec_time_inv * 163840) + device_gds_size;
		gds_size = (gds_size / 8192 - 1 ) * 8192;
		total_exec_time_inv +=  globalObj[jtrUniqDevNo].exec_time_inv;
	}

	else {
		total_exec_time_inv +=  globalObj[jtrUniqDevNo].exec_time_inv;
		gds_size = (long int)(total_exec_time_inv * 163840);
		gds_size = (gds_size / 8192 + 1 ) * 8192;
	}

	gds_size = (gds_size < (MAX_KEYS_PER_CRYPT - 8192)) ? gds_size : (MAX_KEYS_PER_CRYPT - 8192);
	gds_size = (gds_size > 8192) ? gds_size : 8192;

	if (options.verbosity > 2)
		fprintf(stderr, "Optimal Global Work Size:%ld\n", gds_size);

	fmt -> params.max_keys_per_crypt = gds_size;
	fmt -> params.min_keys_per_crypt = max_lws();
}

size_t 	select_device(int jtrUniqDevNo, struct fmt_main *fmt) {
	cl_int 		err;
	const char  	*errMsg;
	size_t	 	memAllocSz;

	active_dev_ctr++;

	opencl_init("$JOHN/kernels/pbkdf2_kernel.cl", jtrUniqDevNo, NULL);

	globalObj[jtrUniqDevNo].krnl[0] = clCreateKernel(program[jtrUniqDevNo], "pbkdf2_preprocess_short", &err);
	if (err) {
		fprintf(stderr, "Create Kernel pbkdf2_preprocess_short FAILED\n");
		return 0;
	}
	globalObj[jtrUniqDevNo].krnl[1] = clCreateKernel(program[jtrUniqDevNo], "pbkdf2_preprocess_long", &err);
	if (err) {
		fprintf(stderr, "Create Kernel pbkdf2_preprocess_long FAILED\n");
		return 0;
	}
	globalObj[jtrUniqDevNo].krnl[2] = clCreateKernel(program[jtrUniqDevNo], "pbkdf2_iter", &err);
	if (err) {
		fprintf(stderr, "Create Kernel pbkdf2_iter FAILED\n");
		return 0;
	}
	globalObj[jtrUniqDevNo].krnl[3] = clCreateKernel(program[jtrUniqDevNo], "pbkdf2_postprocess", &err);
	if (err) {
		fprintf(stderr, "Create Kernel pbkdf2_postprocess FAILED\n");
		return 0;
	}

	errMsg = "Create Buffer FAILED";

	memAllocSz = 4 * MAX_KEYS_PER_CRYPT * sizeof(cl_uint);
	memAllocSz = memAllocSz < get_max_mem_alloc_size(jtrUniqDevNo) ? memAllocSz : get_max_mem_alloc_size(jtrUniqDevNo) / 4 * 4;
	globalObj[jtrUniqDevNo].gpu_buffer.pass_gpu = clCreateBuffer(context[jtrUniqDevNo], CL_MEM_READ_ONLY, memAllocSz, NULL, &err);
	if (globalObj[jtrUniqDevNo].gpu_buffer.pass_gpu == (cl_mem)0)
		HANDLE_CLERROR(err,errMsg );
	globalObj[jtrUniqDevNo].gpu_buffer.salt_gpu = clCreateBuffer(context[jtrUniqDevNo], CL_MEM_READ_ONLY, (MAX_SALT_LENGTH / 2 + 1) * sizeof(cl_uint), NULL, &err);
	if (globalObj[jtrUniqDevNo].gpu_buffer.salt_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);
	globalObj[jtrUniqDevNo].gpu_buffer.hash_out_gpu = clCreateBuffer(context[jtrUniqDevNo], CL_MEM_WRITE_ONLY, memAllocSz, NULL, &err);
	if (globalObj[jtrUniqDevNo].gpu_buffer.hash_out_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);
	memAllocSz = MAX_KEYS_PER_CRYPT * sizeof(temp_buf);
	memAllocSz = memAllocSz < get_max_mem_alloc_size(jtrUniqDevNo) ? memAllocSz : get_max_mem_alloc_size(jtrUniqDevNo) / 4 * 4;
	globalObj[jtrUniqDevNo].gpu_buffer.temp_buf_gpu = clCreateBuffer(context[jtrUniqDevNo], CL_MEM_READ_WRITE, memAllocSz, NULL, &err);
	if (globalObj[jtrUniqDevNo].gpu_buffer.temp_buf_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);
	memAllocSz = 5 * MAX_KEYS_PER_CRYPT * sizeof(cl_uint);
	memAllocSz = memAllocSz < get_max_mem_alloc_size(jtrUniqDevNo) ? memAllocSz : get_max_mem_alloc_size(jtrUniqDevNo) / 4 * 4;
	globalObj[jtrUniqDevNo].gpu_buffer.hmac_sha1_gpu = clCreateBuffer(context[jtrUniqDevNo], CL_MEM_READ_WRITE, memAllocSz, NULL, &err);
	if (globalObj[jtrUniqDevNo].gpu_buffer.temp_buf_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);


	HANDLE_CLERROR(clSetKernelArg(globalObj[jtrUniqDevNo].krnl[0], 0, sizeof(cl_mem), &globalObj[jtrUniqDevNo].gpu_buffer.pass_gpu), "Set Kernel 0 Arg 0 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(globalObj[jtrUniqDevNo].krnl[0], 1, sizeof(cl_mem), &globalObj[jtrUniqDevNo].gpu_buffer.salt_gpu), "Set Kernel 0 Arg 1 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(globalObj[jtrUniqDevNo].krnl[0], 3, sizeof(cl_mem), &globalObj[jtrUniqDevNo].gpu_buffer.temp_buf_gpu), "Set Kernel 0 Arg 3 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(globalObj[jtrUniqDevNo].krnl[1], 0, sizeof(cl_mem), &globalObj[jtrUniqDevNo].gpu_buffer.pass_gpu), "Set Kernel 1 Arg 0 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(globalObj[jtrUniqDevNo].krnl[1], 1, sizeof(cl_mem), &globalObj[jtrUniqDevNo].gpu_buffer.temp_buf_gpu), "Set Kernel 1 Arg 1 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(globalObj[jtrUniqDevNo].krnl[1], 2, sizeof(cl_mem), &globalObj[jtrUniqDevNo].gpu_buffer.hmac_sha1_gpu), "Set Kernel 1 Arg 2 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(globalObj[jtrUniqDevNo].krnl[2], 0, sizeof(cl_mem), &globalObj[jtrUniqDevNo].gpu_buffer.temp_buf_gpu), "Set Kernel 2 Arg 0 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(globalObj[jtrUniqDevNo].krnl[3], 0, sizeof(cl_mem), &globalObj[jtrUniqDevNo].gpu_buffer.temp_buf_gpu), "Set Kernel 3 Arg 0 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(globalObj[jtrUniqDevNo].krnl[3], 1, sizeof(cl_mem), &globalObj[jtrUniqDevNo].gpu_buffer.hash_out_gpu), "Set Kernel 3 Arg 1 :FAILED");

	if (!local_work_size)
		find_best_workgroup(jtrUniqDevNo, quick_bechmark(jtrUniqDevNo));

	else {
		size_t 		maxsize, maxsize2;

		globalObj[jtrUniqDevNo].lws = local_work_size;

		// Obey limits
		HANDLE_CLERROR(clGetKernelWorkGroupInfo(globalObj[jtrUniqDevNo].krnl[0], devices[jtrUniqDevNo], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Error querying max LWS");
		HANDLE_CLERROR(clGetKernelWorkGroupInfo(globalObj[jtrUniqDevNo].krnl[1], devices[jtrUniqDevNo], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize2), &maxsize2, NULL), "Error querying max LWS");
		if (maxsize2 > maxsize)
			maxsize = maxsize2;
		HANDLE_CLERROR(clGetKernelWorkGroupInfo(globalObj[jtrUniqDevNo].krnl[2], devices[jtrUniqDevNo], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize2), &maxsize2, NULL), "Error querying max LWS");
		if (maxsize2 > maxsize)
			maxsize = maxsize2;
		HANDLE_CLERROR(clGetKernelWorkGroupInfo(globalObj[jtrUniqDevNo].krnl[3], devices[jtrUniqDevNo], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize2), &maxsize2, NULL), "Error querying max LWS");
		if (maxsize2 > maxsize)
			maxsize = maxsize2;

		while (globalObj[jtrUniqDevNo].lws > maxsize)
			globalObj[jtrUniqDevNo].lws /= 2;

		if (options.verbosity > 3)
			fprintf(stderr, "Local worksize (LWS) forced to %zu\n", globalObj[jtrUniqDevNo].lws);

		globalObj[jtrUniqDevNo].exec_time_inv = 1;
	}

	if (!global_work_size)
		find_best_gws(jtrUniqDevNo, fmt);

	else {
		if (options.verbosity > 3)
			fprintf(stderr, "Global worksize (GWS) forced to %zu\n", global_work_size);

		fmt -> params.max_keys_per_crypt = global_work_size;
		fmt -> params.min_keys_per_crypt = max_lws();
	}

	return globalObj[jtrUniqDevNo].lws;
}

size_t select_default_device(struct fmt_main *fmt) {
	return select_device(0, fmt);
}

void dcc2_warning() {
	double 		total_exec_time_inv=0;
	int 		i;

	for (i = 0; i < active_dev_ctr; ++i)
		total_exec_time_inv += globalObj[gpu_device_list[i]].exec_time_inv;

	for (i = 0; i < active_dev_ctr; ++i)
		if (globalObj[gpu_device_list[i]].exec_time_inv / total_exec_time_inv < 0.01)
			fprintf(stderr, "WARNING: Device %d is too slow and might cause degradation in performance.\n", gpu_device_list[i]);
}

void pbkdf2_divide_work(cl_uint *pass_api, cl_uint *salt_api, cl_uint saltlen_api, unsigned int iter_cnt, cl_uint *hash_out_api, cl_uint *hmac_sha1_api, cl_uint num) {
	double 		total_exec_time_inv = 0;
	int 		i;
	unsigned int 	work_part, work_offset = 0, lws_max = max_lws();
	cl_int 		ret;

#ifdef  _DEBUG
	struct timeval startc, endc;
#endif

	event_ctr = 0;
	memset(hash_out_api, 0, num * sizeof(cl_uint));

	/// Make num multiple of lws_max
	if (num % lws_max != 0)
		num = (num / lws_max + 1) * lws_max;

	///Divide work only if number of keys is greater than 8192, else use first device selected
	if (num > 8192) {
		///Calculates t0tal Kernel Execution Speed
		for (i = 0; i < active_dev_ctr; ++i)
			total_exec_time_inv += globalObj[gpu_device_list[i]].exec_time_inv;

		///Calculate work division ratio
		for (i = 0; i < active_dev_ctr; ++i)
			globalObj[gpu_device_list[i]].exec_time_inv /= total_exec_time_inv;

		///Divide memory and work
		for (i = 0; i < active_dev_ctr; ++i) {
			if (i == active_dev_ctr - 1) {
				work_part = num - work_offset;
				if (work_part % lws_max != 0)
					work_part = (work_part / lws_max + 1) * lws_max;
			}
			else {
				work_part = num * globalObj[gpu_device_list[i]].exec_time_inv;
				if (work_part % lws_max != 0)
					work_part = (work_part / lws_max + 1) * lws_max;
			}

			if ((int)work_part <= 0)
				work_part = lws_max;

#ifdef  _DEBUG
			gettimeofday(&startc, NULL) ;
			fprintf(stderr, "Work Offset:%d  Work Part Size:%d Event No:%d",work_offset,work_part,event_ctr);
#endif

			///call to exec_pbkdf2()
			exec_pbkdf2(pass_api + 4 * work_offset, salt_api, saltlen_api, iter_cnt, hash_out_api + 4 * work_offset, work_part, gpu_device_list[i], queue[gpu_device_list[i]], hmac_sha1_api + 5 * work_offset);
			work_offset += work_part;

#ifdef  _DEBUG
			gettimeofday(&endc, NULL);
			fprintf(stderr, "GPU enqueue time:%f\n",(endc.tv_sec - startc.tv_sec) + (double)(endc.tv_usec - startc.tv_usec) / 1000000.000) ;
#endif
		}

		///Synchronize all kernels
		for (i = active_dev_ctr - 1; i >= 0; --i)
			HANDLE_CLERROR(clFlush(queue[gpu_device_list[i]]), "Flush Error");

		for (i = 0; i < active_dev_ctr; ++i) {
			while (1) {
				HANDLE_CLERROR(clGetEventInfo(events[i], CL_EVENT_COMMAND_EXECUTION_STATUS, sizeof(cl_int), &ret, NULL), "Error in Get Event Info");
				if ((ret) == CL_COMPLETE)
					break;
#ifdef  _DEBUG
				 printf("%d%d ", ret, i);
#endif
			}
		}

		event_ctr = work_part = work_offset = 0;

		///Read results back from all kernels
		for (i = 0; i < active_dev_ctr; ++i) {
			if (i == active_dev_ctr - 1) {
				work_part = num - work_offset;
				if (work_part % lws_max != 0)
					work_part = (work_part / lws_max + 1) * lws_max;
			}
			else {
				work_part = num * globalObj[gpu_device_list[i]].exec_time_inv;
				if (work_part % lws_max != 0)
					work_part = (work_part / lws_max + 1) * lws_max;
			}

			if ((int)work_part <= 0)
				work_part = lws_max;

#ifdef  _DEBUG
			gettimeofday(&startc, NULL) ;
			fprintf(stderr, "Work Offset:%d  Work Part Size:%d Event No:%d",work_offset,work_part,event_ctr);
#endif

			///Read results back from device
			HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_device_list[i]],
							   globalObj[gpu_device_list[i]].gpu_buffer.hash_out_gpu,
							   CL_FALSE, 0,
							   4 * work_part * sizeof(cl_uint),
							   hash_out_api + 4 * work_offset,
							   0,
							   NULL,
							   &events[event_ctr++]), "Write :FAILED");
			work_offset += work_part;

#ifdef  _DEBUG
			gettimeofday(&endc, NULL);
			fprintf(stderr, "GPU enqueue time:%f\n",(endc.tv_sec - startc.tv_sec) + (double)(endc.tv_usec - startc.tv_usec) / 1000000.000) ;
#endif
		}

		for (i = 0; i < active_dev_ctr; ++i)
			HANDLE_CLERROR(clFinish(queue[gpu_device_list[i]]), "Finish Error");

	 }

	 else {
		exec_pbkdf2(pass_api, salt_api, saltlen_api, iter_cnt, hash_out_api, num, gpu_device_list[0], queue[gpu_device_list[0]], hmac_sha1_api);
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_device_list[0]], globalObj[gpu_device_list[0]].gpu_buffer.hash_out_gpu, CL_FALSE, 0, 4*num*sizeof(cl_uint), hash_out_api, 0, NULL, NULL), "Write :FAILED");
		HANDLE_CLERROR(clFinish(queue[gpu_device_list[0]]), "Finish Error");
	}
}

static gpu_mem_buffer exec_pbkdf2(cl_uint *pass_api, cl_uint *salt_api, cl_uint saltlen_api, unsigned int iter_cnt, cl_uint *hash_out_api, cl_uint num, int jtrUniqDevNo, cl_command_queue cmdq, cl_uint *hmac_sha1_api )
{
	cl_event 	evnt;
	size_t 		N = num, M = globalObj[jtrUniqDevNo].lws;
	cl_int 		err;
	unsigned int 	i, itrCntKrnl = ITERATION_COUNT_PER_CALL;
	cl_ulong 	_kernelExecTimeNs = 0;

	HANDLE_CLERROR(clEnqueueWriteBuffer(cmdq, globalObj[jtrUniqDevNo].gpu_buffer.pass_gpu, CL_FALSE, 0, 4 * num * sizeof(cl_uint), pass_api, 0, NULL, NULL ), "Copy data to gpu");
	if(saltlen_api > 22)
		HANDLE_CLERROR(clEnqueueWriteBuffer(cmdq, globalObj[jtrUniqDevNo].gpu_buffer.hmac_sha1_gpu, CL_FALSE, 0, 5 * num * sizeof(cl_uint), hmac_sha1_api, 0, NULL, NULL ), "Copy data to gpu");
	else
	      HANDLE_CLERROR(clSetKernelArg(globalObj[jtrUniqDevNo].krnl[0], 2, sizeof(cl_uint), &saltlen_api), "Set Kernel 0 Arg 2 :FAILED");

	HANDLE_CLERROR(clEnqueueWriteBuffer(cmdq, globalObj[jtrUniqDevNo].gpu_buffer.salt_gpu, CL_FALSE, 0, (MAX_SALT_LENGTH / 2 + 1) * sizeof(cl_uint), salt_api, 0, NULL, NULL ), "Copy data to gpu");

	if(saltlen_api < 23)
		err = clEnqueueNDRangeKernel(cmdq, globalObj[jtrUniqDevNo].krnl[0], 1, NULL, &N, &M, 0, NULL, &evnt);
	else
		err = clEnqueueNDRangeKernel(cmdq, globalObj[jtrUniqDevNo].krnl[1], 1, NULL, &N, &M, 0, NULL, &evnt);

	if (err) {
		if (PROFILE)
			globalObj[jtrUniqDevNo].lws = globalObj[jtrUniqDevNo].lws / 2;
	  	else
			HANDLE_CLERROR(err, "Enqueue Kernel Failed");

		return globalObj[jtrUniqDevNo].gpu_buffer;
	}

	if (PROFILE) {

		cl_ulong 	startTime, endTime;

		HANDLE_CLERROR(clWaitForEvents(1, &evnt), "Sync :FAILED");
		HANDLE_CLERROR(clFinish(cmdq), "clFinish error");

		clGetEventProfilingInfo(evnt, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
		clGetEventProfilingInfo(evnt, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL);
		_kernelExecTimeNs = endTime - startTime;
	}

	for (i = 0; i < iter_cnt - 1; i += itrCntKrnl ) {
		if (i + itrCntKrnl >= iter_cnt)
			itrCntKrnl = iter_cnt - i - 1;

		HANDLE_CLERROR(clSetKernelArg(globalObj[jtrUniqDevNo].krnl[2], 1, sizeof(cl_uint), &itrCntKrnl), "Set Kernel 1 Arg 1 :FAILED");

		err = clEnqueueNDRangeKernel(cmdq, globalObj[jtrUniqDevNo].krnl[2], 1, NULL, &N, &M, 0, NULL, &evnt);

		if (err) {
			if (PROFILE)
				globalObj[jtrUniqDevNo].lws = globalObj[jtrUniqDevNo].lws / 2;
			else
				HANDLE_CLERROR(err, "Enqueue Kernel Failed");

			return globalObj[jtrUniqDevNo].gpu_buffer;
		}

		opencl_process_event();

		if (PROFILE) {
			cl_ulong 	startTime, endTime;

			HANDLE_CLERROR(clWaitForEvents(1, &evnt), "Sync FAILED");
			HANDLE_CLERROR(clFinish(cmdq), "clFinish error");

			clGetEventProfilingInfo(evnt, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
			clGetEventProfilingInfo(evnt, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL);

			_kernelExecTimeNs += endTime - startTime;
		}

	}

	err = clEnqueueNDRangeKernel(cmdq, globalObj[jtrUniqDevNo].krnl[3], 1, NULL, &N, &M, 0, NULL, &events[event_ctr]);

	if (err) {
		if (PROFILE)
			globalObj[jtrUniqDevNo].lws = globalObj[jtrUniqDevNo].lws / 2;
	  	else
			HANDLE_CLERROR(err, "Enqueue Kernel Failed");

		return globalObj[jtrUniqDevNo].gpu_buffer;
	}

	if (PROFILE) {
			cl_ulong 	startTime, endTime;
			HANDLE_CLERROR(clWaitForEvents(1, &events[event_ctr]), "Sync :FAILED");
			HANDLE_CLERROR(clFinish(cmdq), "clFinish error");

			clGetEventProfilingInfo(events[event_ctr], CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
			clGetEventProfilingInfo(events[event_ctr], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL);

			_kernelExecTimeNs += endTime - startTime;

			if (_kernelExecTimeNs < kernelExecTimeNs) {
				kernelExecTimeNs = _kernelExecTimeNs;

				//printf("%d\n",(int)kernelExecTimeNs);

				globalObj[jtrUniqDevNo].lws  = globalObj[jtrUniqDevNo].lws * 2;
				globalObj[jtrUniqDevNo].exec_time_inv =  (long double)pow(10, 9) / (long double)kernelExecTimeNs;
			}

         }

         else
		event_ctr++;

         return globalObj[jtrUniqDevNo].gpu_buffer;
}

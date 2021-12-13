/*
* This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on Solar Designer implementation of bf_std.c in jtr-v1.7.8
*/

#ifdef HAVE_OPENCL

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <math.h>

#include "arch.h"
#include "common.h"
#include "options.h"
#include "opencl_bf_std.h"

#define INDEX				[index]
#define pos_S(row,col)			\
	_index_S + (row * 256 + col) * (CHANNEL_INTERLEAVE)

#define for_each_index() 		\
	for (index = 0; index < BF_N; index++)

#define pos_P(i)			\
        _index_P + i

static unsigned int 	*BF_current_S ;
static unsigned int 	*BF_current_P ;
static unsigned int 	*BF_init_key ;
BF_binary 		*opencl_BF_out ;

typedef struct {
	cl_mem salt_gpu ;
	cl_mem P_box_gpu ;
	cl_mem S_box_gpu ;
	cl_mem out_gpu ;
	cl_mem BF_current_S_gpu ;
	cl_mem BF_current_P_gpu ;
} gpu_buffer;

static cl_kernel 	krnl[MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM];
static gpu_buffer 	buffers[MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM];

#define BF_ROUND(ctx_S, ctx_P, L, R, N, tmp1, tmp2, tmp3, tmp4) 	\
	tmp1 = L & 0xFF ; 						\
	tmp2 = L >> 8 ; 						\
	tmp2 &= 0xFF ; 							\
	tmp3 = L >> 16 ; 						\
	tmp3 &= 0xFF ; 							\
	tmp4 = L >> 24 ; 						\
	tmp1 = ctx_S[pos_S(3,tmp1)] ; 					\
	tmp2 = ctx_S[pos_S(2,tmp2)] ; 					\
	tmp3 = ctx_S[pos_S(1,tmp3)] ; 					\
	tmp3 += ctx_S[pos_S(0,tmp4)] ; 					\
	tmp3 ^= tmp2 ; 							\
	R ^= ctx_P[pos_P((N + 1))] ; 					\
	tmp3 += tmp1 ; 							\
	R ^= tmp3 ;

/*
 * Encrypt one block, BF_ROUNDS is hardcoded here.
 */
#define BF_ENCRYPT(ctx_S, ctx_P, L, R) 					\
	L ^= ctx_P[pos_P(0)]; 						\
	BF_ROUND(ctx_S, ctx_P, L, R, 0, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 1, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 2, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 3, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 4, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 5, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 6, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 7, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 8, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 9, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 10, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 11, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 12, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 13, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 14, u1, u2, u3, u4) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 15, u1, u2, u3, u4) ; 		\
	u4 = R ; 							\
	R = L ;								\
	L = u4 ^ ctx_P[pos_P((BF_ROUNDS+1))] ;

static void clean_gpu_buffer(gpu_buffer *pThis)
{
	const char *errMsg = "Release Memory Object FAILED." ;

	if (pThis->salt_gpu) {
		HANDLE_CLERROR(clReleaseMemObject(pThis->salt_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(pThis-> P_box_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(pThis-> S_box_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(pThis->out_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(pThis->BF_current_S_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(pThis->BF_current_P_gpu), errMsg);
	}
}

void BF_clear_buffer() {
	clean_gpu_buffer(&buffers[gpu_id]);
	MEM_FREE(BF_current_S) ;
	MEM_FREE(BF_current_P) ;
	MEM_FREE(BF_init_key) ;
	MEM_FREE(opencl_BF_out) ;

	if (program[gpu_id]) {
		HANDLE_CLERROR(clReleaseKernel(krnl[gpu_id]), "Error releasing kernel") ;

		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Error releasing Program");
	}
}

static void find_best_gws(struct fmt_main *fmt) {
	struct timeval 	start,end ;
	double 		savetime, diff ;
	size_t	 	count = local_work_size;
	double 		speed = 999999 ;
	BF_salt 	random_salt ;

	random_salt.salt[0] = 0x12345678 ;
	random_salt.salt[1] = 0x87654321 ;
	random_salt.salt[2] = 0x21876543 ;
	random_salt.salt[3] = 0x98765432 ;
	random_salt.rounds  = 5 ;
	random_salt.subtype = 'x' ;

	gettimeofday(&start,NULL) ;
	opencl_BF_std_crypt(&random_salt,count) ;
	gettimeofday(&end, NULL) ;
	savetime = (end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 1000000.000;
	speed = ((double)count) / savetime ;

	do {
		count *= 2 ;
		if (count > BF_N) {
			count = count >> 1 ;
			break ;
		}
		gettimeofday(&start,NULL) ;
		opencl_BF_std_crypt(&random_salt,count) ;
		gettimeofday(&end, NULL) ;
		savetime = (end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 1000000.000 ;
		diff = (((double)count) / savetime) / speed ;
		if (diff < 1) {
		  count = count	>> 1 ;
		  break ;
		}
		diff = diff - 1 ;
		diff = (diff < 0)? (-diff): diff ;
		speed = ((double)count) / savetime ;
	} while (diff > 0.01) ;

	fmt->params.max_keys_per_crypt = global_work_size = count;
}

void BF_select_device(struct fmt_main *fmt) {
	cl_int 		err;
	const char 	*errMsg;
	const int	lmem_per_th = ((1024 + 4) * sizeof(cl_uint) + 64);
	char		buildopts[32];

	BF_current_S = 	(unsigned int*)mem_alloc(BF_N * 1024 * sizeof(unsigned int)) ;
	BF_current_P = 	(unsigned int*)mem_alloc(BF_N * 18 * sizeof(unsigned int)) ;
	BF_init_key = 	(unsigned int*)mem_alloc(BF_N * 18 * sizeof(unsigned int)) ;
	opencl_BF_out = (BF_binary*)mem_alloc(BF_N * sizeof(BF_binary)) ;

	if (!local_work_size)
		local_work_size = DEFAULT_LWS;

	/* device max, regardless of kernel */
	if (local_work_size > get_device_max_lws(gpu_id))
		local_work_size = get_device_max_lws(gpu_id);

	/* For GPU kernel, our use of local memory sets a limit for LWS.
	   In extreme cases we even fallback to using CPU kernel. */
	if ((get_device_type(gpu_id) != CL_DEVICE_TYPE_CPU) &&
	    lmem_per_th < get_local_memory_size(gpu_id))
		while (local_work_size >
		       get_local_memory_size(gpu_id) / lmem_per_th)
			local_work_size >>= 1;

	if ((get_device_type(gpu_id) == CL_DEVICE_TYPE_CPU) ||
	    amd_vliw5(device_info[gpu_id]) ||
	    (get_local_memory_size(gpu_id) < local_work_size * lmem_per_th) ||
	    (gpu_intel(device_info[gpu_id]) && platform_apple(platform_id)))
	{
	        if (CHANNEL_INTERLEAVE == 1)
		        opencl_init("$JOHN/opencl/bf_cpu_kernel.cl", gpu_id, NULL);
	        else {
		        fprintf(stderr, "Please set NUM_CHANNELS and "
		                "WAVEFRONT_SIZE to 1 in opencl_bf_std.h");
		        error();
	        }
	}
	else {
		snprintf(buildopts, sizeof(buildopts),
		         "-DWORK_GROUP_SIZE="Zu, local_work_size);
		opencl_init("$JOHN/opencl/bf_kernel.cl",
		            gpu_id, buildopts);
	}

	krnl[gpu_id] = clCreateKernel(program[gpu_id], "blowfish", &err) ;
	if (err) {
		fprintf(stderr, "Create Kernel blowfish FAILED\n") ;
		return ;
	}

	/* This time we ask about max size for this very kernel */
	if (local_work_size > get_kernel_max_lws(gpu_id, krnl[gpu_id]))
		local_work_size =
			get_kernel_max_lws(gpu_id, krnl[gpu_id]);

	errMsg = "Create Buffer Failed" ;

	buffers[gpu_id].salt_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 4 * sizeof(cl_uint), NULL, &err) ;
	if (buffers[gpu_id].salt_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg) ;

	buffers[gpu_id].P_box_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY|CL_MEM_COPY_HOST_PTR, sizeof(cl_uint) * 18, BF_init_state.P, &err) ;
	if (buffers[gpu_id].P_box_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg) ;

	buffers[gpu_id].S_box_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY|CL_MEM_COPY_HOST_PTR, sizeof(cl_uint) * 1024, BF_init_state.S, &err) ;
	if (buffers[gpu_id].S_box_gpu==(cl_mem)0)
		HANDLE_CLERROR(err, errMsg) ;

	buffers[gpu_id].out_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, BF_N * sizeof(cl_uint) * 2, NULL, &err) ;
	if (buffers[gpu_id].out_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg) ;

	buffers[gpu_id].BF_current_S_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, BF_N * 1024 * sizeof(unsigned int), NULL, &err) ;
	if (buffers[gpu_id].BF_current_S_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg) ;

	buffers[gpu_id].BF_current_P_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, BF_N * sizeof(unsigned int) * 18, NULL, &err) ;
	if (buffers[gpu_id].BF_current_P_gpu==(cl_mem)0)
		HANDLE_CLERROR(err, errMsg) ;

	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id], 0, sizeof(cl_mem), &buffers[gpu_id].salt_gpu), "Set Kernel Arg FAILED arg0") ;
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id], 1, sizeof(cl_mem), &buffers[gpu_id].P_box_gpu), "Set Kernel Arg FAILED arg1") ;
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id], 2, sizeof(cl_mem), &buffers[gpu_id].out_gpu), "Set Kernel Arg FAILED arg2") ;
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id], 3, sizeof(cl_mem), &buffers[gpu_id].BF_current_S_gpu), "Set Kernel Arg FAILED arg3") ;
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id], 4, sizeof(cl_mem), &buffers[gpu_id].BF_current_P_gpu), "Set Kernel Arg FAILED arg4");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id], 6, sizeof(cl_mem), &buffers[gpu_id].S_box_gpu), "Set Kernel Arg FAILED arg6") ;

	if (global_work_size) {
		global_work_size = MIN(global_work_size / local_work_size * local_work_size, BF_N);
		fmt->params.max_keys_per_crypt = global_work_size;
	} else
		find_best_gws(fmt);

	if (ocl_always_show_ws || !self_test_running) {
		if (options.node_count)
			fprintf(stderr, "%u: ", NODE);
		fprintf(stderr, "LWS="Zu" GWS="Zu" ("Zu" blocks)%c",
		        local_work_size, global_work_size, global_work_size / local_work_size,
		        (options.flags & FLG_TEST_CHK) ? ' ' : '\n');
	}

	fmt->params.min_keys_per_crypt = opencl_calc_min_kpc(local_work_size, global_work_size, 1);
}

void opencl_BF_std_set_key(char *key, int index, int sign_extension_bug) {
	char 	*ptr = key ;
	int 	i, j, _index_P = index * 18 ;
	BF_word tmp ;

	for (i = 0; i < BF_ROUNDS + 2; i++) {
		tmp = 0 ;
		for (j = 0; j < 4; j++) {
			tmp <<= 8 ;
			if (sign_extension_bug)
				tmp |= (int)(signed char)*ptr ;
			else
				tmp |= (unsigned char)*ptr ;

			if (!*ptr) ptr = key ; else ptr++ ;
		}

		BF_init_key[pos_P(i)] = BF_init_state.P[i] ^ tmp ;
	}
}

void exec_bf(cl_uint *salt_api, cl_uint *BF_out, cl_uint rounds, int n) {
	cl_event 	evnt ;
	cl_int 		err ;
	size_t 		N, M = local_work_size;
	double 		temp ;
	const char 	*errMsg ;

	temp = log((double)n) / log((double)2) ;
	n = (int)temp ;

	///Make sure amount of work isn't unnecessarily doubled
	if ((temp - n) != 0) {
		if ((temp - n) < 0.00001)
			n = (int)pow((double)2, (double)n) ;
		else if ((n + 1 - temp) < 0.00001)
			n = (int)pow((double)2, (double)n) ;
		else
			n = (int)pow((double)2, (double)(n+1)) ;
	}

	else
		n = (int)pow((double)2, (double)n) ;

	n = (n > BF_N)? BF_N: n ;
	n = (n < (2*M))? 2*M: n ;

	if (CL_DEVICE_TYPE_CPU == get_device_type(gpu_id))
		N = n/2 ;  ///Two hashes per crypt call for cpu
	else
		N = n ;

	/* N has to be a multiple of M */
	N = (N + M - 1) / M * M;

	errMsg = "Copy data to device: Failed" ;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffers[gpu_id].salt_gpu, CL_TRUE, 0, 4 * sizeof(cl_uint), salt_api, 0, NULL, NULL ), errMsg) ;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffers[gpu_id].BF_current_P_gpu, CL_TRUE, 0, BF_N*sizeof(unsigned int)*18, BF_init_key, 0, NULL, NULL ), errMsg) ;
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id], 5, sizeof(cl_uint), &rounds),"Set Kernel Arg FAILED arg5");

	err = clEnqueueNDRangeKernel(queue[gpu_id], krnl[gpu_id], 1, NULL, &N, &M, 0, NULL, &evnt) ;
	HANDLE_CLERROR(err, "Enqueue Kernel Failed") ;

	HANDLE_CLERROR(clWaitForEvents(1, &evnt), "Sync :FAILED") ;
	clReleaseEvent(evnt);

	errMsg = "Read data from device: Failed" ;
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffers[gpu_id].out_gpu, CL_FALSE, 0, 2 * BF_N * sizeof(cl_uint), BF_out, 0, NULL, NULL), errMsg) ;
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffers[gpu_id].BF_current_P_gpu, CL_FALSE, 0, BF_N * sizeof(unsigned int) * 18, BF_current_P, 0, NULL, NULL), errMsg)  ;
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffers[gpu_id].BF_current_S_gpu, CL_TRUE, 0, BF_N * 1024 * sizeof(unsigned int), BF_current_S, 0, NULL, NULL), errMsg) ;

	HANDLE_CLERROR(clFinish(queue[gpu_id]), "Finish Error") ;
}

void opencl_BF_std_crypt(BF_salt *salt, int n)
{
	int 			index=0,j ;
	static unsigned int 	salt_api[4] ;
	unsigned int 		rounds = salt->rounds ;
	static unsigned int 	BF_out[2*BF_N] ;

	salt_api[0] = salt->salt[0] ;
	salt_api[1] = salt->salt[1] ;
	salt_api[2] = salt->salt[2] ;
	salt_api[3] = salt->salt[3] ;

	exec_bf(salt_api, BF_out, rounds, n) ;

	for_each_index(){ j=2*index ;
		 opencl_BF_out INDEX[0] = BF_out[j++] ;
		 opencl_BF_out INDEX[1] = BF_out[j] ;
	}

}

void opencl_BF_std_crypt_exact(int index) {
	BF_word L, R;
	BF_word u1, u2, u3, u4;
	BF_word count;
	int 	i, _index_S = (index / (CHANNEL_INTERLEAVE)) * (CHANNEL_INTERLEAVE) * 1024 + index % (CHANNEL_INTERLEAVE),
		_index_P = index * 18 ;

	memcpy(&opencl_BF_out[index][2], &BF_magic_w[2], sizeof(BF_word) * 4) ;

	count = 64 ;
	do
	for (i = 2; i < 6; i += 2) {
		L = opencl_BF_out[index][i] ;
		R = opencl_BF_out[index][i + 1] ;
		BF_ENCRYPT(BF_current_S,BF_current_P, L, R) ;
		opencl_BF_out[index][i] = L ;
		opencl_BF_out[index][i + 1] = R ;
	} while (--count) ;

/* This has to be bug-compatible with the original implementation :-) */
	opencl_BF_out[index][5] &= ~(BF_word)0xFF ;
}

#endif /* HAVE_OPENCL */

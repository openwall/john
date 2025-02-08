/*
 * This software is Copyright (c) 2024 magnum and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 */
#ifndef OPENCL_HELPER_MACROS_H
#define OPENCL_HELPER_MACROS_H

#define CL_RO    CL_MEM_READ_ONLY
#define CL_WO    CL_MEM_WRITE_ONLY
#define CL_RW    CL_MEM_READ_WRITE
#define CL_ALLOC CL_MEM_ALLOC_HOST_PTR
#define CL_COPY  CL_MEM_COPY_HOST_PTR

#define CLCREATEBUFFER(VAR, FLAGS, SIZE)	  \
	do { VAR = clCreateBuffer(context[gpu_id], FLAGS, SIZE, NULL, &ret_code); \
		HANDLE_CLERROR(ret_code, "Error allocating GPU memory"); } while(0)

/*
 * This creates a pinned (non pageable, can't be swapped) buffer, ensuring
 * fastest possible DMA transfer.  When not using pinned memory, an extra
 * step will happen in the background, where your (pageable) buffer is first
 * transfered to a temporary pinned buffer, then to GPU by means of DMA. When
 * your buffer is already using pinned memory, the extra step doesn't occur.
 *
 * It assumes you have defined three buffer variables with the same base
 * name. Example:
 *
 * unsigned char *data_blob;
 * cl_mem pinned_data_blob, cl_data_blob;
 * CLCREATEPINNED(data_blob, CL_RO, gws * some_size);
 * (...)
 * CLKERNELARG(crypt_kernel, 0, cl_data_blob);
 * (...)
 * CLWRITE(cl_data_blob, FALSE, 0, gws * some_size, data_blob, NULL);
 *
 * If the buffer can't be pinned, we silently fallback to a normal buffer.
 */
#define CLCREATEPINNED(VAR, FLAGS, SIZE)	  \
	do { \
		pinned_##VAR = clCreateBuffer(context[gpu_id], FLAGS | CL_ALLOC, SIZE, NULL, &ret_code); \
		if (ret_code != CL_SUCCESS) { \
			VAR = mem_alloc(SIZE); \
			if (VAR == NULL) \
				HANDLE_CLERROR(ret_code, "Error allocating pinned buffer"); \
		} else { \
			VAR = clEnqueueMapBuffer(queue[gpu_id], pinned_##VAR, CL_TRUE, \
			                         CL_MAP_READ | CL_MAP_WRITE, 0, SIZE, 0, NULL, NULL, &ret_code); \
			HANDLE_CLERROR(ret_code, "Error mapping buffer"); \
			CLCREATEBUFFER(cl_##VAR, FLAGS, SIZE); \
		} \
	} while(0)

#define CLCREATEBUFCOPY(VAR, FLAGS, SIZE, HOSTBUF)	  \
	do { VAR = clCreateBuffer(context[gpu_id], FLAGS | CL_COPY, SIZE, HOSTBUF, &ret_code); \
		HANDLE_CLERROR(ret_code, "Error copying host pointer for GPU"); } while(0)

#define CLKERNELARG(KERNEL, ID, ARG)	  \
	HANDLE_CLERROR(clSetKernelArg(KERNEL, ID, sizeof(ARG), &ARG), \
	               "Error setting kernel argument")

#define CLKRNARGLOC(KERNEL, ID, ARG)	  \
	HANDLE_CLERROR(clSetKernelArg(KERNEL, ID, sizeof(ARG), NULL), \
	               "Error setting kernel argument for local memory")

#define CLWRITE(GPU_VAR, WAIT, OFFSET, SIZE, HOST_VAR, EVENT)	  \
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], GPU_VAR, WAIT, OFFSET, SIZE, HOST_VAR, 0, NULL, EVENT), \
	               "Failed writing buffer")

#define CLWRITE_CRYPT(GPU_VAR, WAIT, OFFSET, SIZE, HOST_VAR, EVENT)	  \
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], GPU_VAR, WAIT, OFFSET, SIZE, HOST_VAR, 0, NULL, EVENT), \
	              "Failed writing buffer")

#define CLREAD_CRYPT(GPU_VAR, WAIT, OFFSET, SIZE, HOST_VAR, EVENT)	  \
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], GPU_VAR, WAIT, OFFSET, SIZE, HOST_VAR, 0, NULL, EVENT),\
	              "failed reading buffer")

#define CLFLUSH() HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush")
#define CLFINISH() HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish")

#define CLFLUSH_CRYPT() BENCH_CLERROR(clFlush(queue[gpu_id]), "clFlush")
#define CLFINISH_CRYPT() BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish")

#define CLRELEASEPINNED(VAR)	  \
	do { \
		if (pinned_##VAR) { \
			HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_##VAR, VAR, 0, NULL, NULL), \
			               "Error Unmapping buffer"); \
			CLFINISH(); VAR = NULL; \
		} else \
			MEM_FREE(VAR); \
		HANDLE_CLERROR(clReleaseMemObject(pinned_##VAR), "Error releasing pinned buffer"); \
		pinned_##VAR = NULL; \
		HANDLE_CLERROR(clReleaseMemObject(cl_##VAR), "Error releasing buffer"); \
		cl_##VAR = NULL; \
	} while(0);

#define CLRELEASEBUFFER(VAR)	\
	do { HANDLE_CLERROR(clReleaseMemObject(VAR), "Release buffer"); VAR = NULL; } while(0)

#define CLCREATEKERNEL(KERNEL, name)	  \
	do { KERNEL = clCreateKernel(program[gpu_id], name, &ret_code); \
		HANDLE_CLERROR(ret_code, name); } while(0);

#define CLRUNKERNEL(KERNEL, GWS, LWS, EVENT)	  \
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], KERNEL, 1, NULL, GWS, LWS, 0, NULL, EVENT), "Failed running kernel")

#endif	/* OPENCL_HELPER_MACROS_H */

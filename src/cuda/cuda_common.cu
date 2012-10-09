/*
* This software is Copyright (c) 2011-2012 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _CUDA_COMMON_CU
#define _CUDA_COMMON_CU

#include <stdio.h>
#include <assert.h>
#include "cuda_common.cuh"

extern "C" 
void HandleError(cudaError_t err, const char *file, int line)
{
	if (err != cudaSuccess) {
		fprintf(stderr, "%s in %s at line %d\n",
		    cudaGetErrorString(err), file, line);
		exit(EXIT_FAILURE);
	}
}

#define HANDLE_ERROR(err) (HandleError(err,__FILE__,__LINE__))

static char *human_format(size_t size)
{
	char pref[] = { ' ', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y' };
	int prefid = 0;
	static char ret[32];

	while (size > 1024) {
		size /= 1024;
		prefid++;
	}
	sprintf(ret, "%zd.%zd %cB", size, (size % 1024) / 100, pref[prefid]);
	return ret;
}

extern "C" 
void cuda_init(unsigned int cuda_gpu_id)
{
	int devices;
	HANDLE_ERROR(cudaGetDeviceCount(&devices));
	if (cuda_gpu_id < devices && devices > 0)
		cudaSetDevice(cuda_gpu_id);
	else {
		fprintf(stderr, "Invalid CUDA device id = %d\n", cuda_gpu_id);
		exit(1);
	}
}

extern "C" 
void cuda_device_list()
{
	int i, devices;
	cudaError_t ret;

	ret = cudaGetDeviceCount(&devices);
	if (ret == cudaErrorNoDevice) {
		puts("Error: No CUDA-capable devices were detected by the installed CUDA driver.\n");
		exit(1);
	}
	if (ret == cudaErrorInsufficientDriver) {
		puts("Error: The installed NVIDIA CUDA driver is older than the CUDA runtime library.\nThis is not a supported configuration. Update your display driver.\n");
		exit(1);
	}

	printf("%d CUDA devices found:\n", devices);
	for (i = 0; i < devices; i++) {
		cudaDeviceProp devProp;
		int arch_cores_sm[] = { 1, 8, 32, 192 };

		cudaGetDeviceProperties(&devProp, i);
		printf("\nCUDA Device #%d\n", i);
		printf("\tName:                          %s\n", devProp.name);
		printf("\tCompute capability:            sm_%d%d\n",
		    devProp.major, devProp.minor);
		if (devProp.major <= 3)
		printf("\tNumber of stream processors:   %d (%d x %d)\n",
		       devProp.multiProcessorCount * arch_cores_sm[devProp.major],
		       devProp.multiProcessorCount, arch_cores_sm[devProp.major]);
		else
		printf("\tNumber of multiprocessors:     %d\n",
		    devProp.multiProcessorCount);
		printf("\tClock rate:                    %d Mhz\n",
		    devProp.clockRate / 1024);
		printf("\tTotal global memory:           %s%s\n",
		    human_format(devProp.totalGlobalMem + 200000000),
		    devProp.ECCEnabled ? " (ECC)" : "");
		printf("\tTotal shared memory per block: %s\n",
		    human_format(devProp.sharedMemPerBlock));
		printf("\tTotal constant memory:         %s\n",
		    human_format(devProp.totalConstMem));
		printf("\tKernel execution timeout:      %s\n",
		    (devProp.kernelExecTimeoutEnabled ? "Yes" : "No"));
		printf("\tConcurrent copy and execution: %s\n",
		    (devProp.deviceOverlap ? "Yes" : "No"));
		printf("\tConcurrent kernels support:    %s\n",
		    (devProp.concurrentKernels ? "Yes" : "No"));
		printf("\tWarp size:                     %d\n",
		    devProp.warpSize);
		puts("");
	}
}

extern "C"
void *cuda_pageLockedMalloc(void *w, unsigned int size)
{
	HANDLE_ERROR(cudaHostAlloc((void **) &w, size, cudaHostAllocDefault));
	return w;
}

extern "C"
void cuda_pageLockedFree(void *w)
{
	HANDLE_ERROR(cudaFreeHost(w));
}

/* cuda init must be called first to set device */
extern "C"
int cuda_getAsyncEngineCount()
{
	cudaDeviceProp prop;
	int dev;
	cudaGetDevice(&dev);
	cudaGetDeviceProperties(&prop,dev);
	return prop.asyncEngineCount;
	//if CUDA<4.0 we should use prop.overlapSupported
}
#endif

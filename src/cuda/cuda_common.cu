/*
* This software is Copyright (c) 2011-2012 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _CUDA_COMMON_CU
#define _CUDA_COMMON_CU

#include <stdio.h>
#include <assert.h>

#include "../autoconfig.h"
#define HAVE_CUDA
#include "../common-gpu.h"
#include "cuda.h"
#include "cuda_common.cuh"

extern "C"
void HandleError(cudaError_t err, const char *file, int line)
{
	if (err != cudaSuccess) {
		fprintf(stderr, "%s in %s at line %d\n",
		    cudaGetErrorString(err), file, line);
		if (err == cudaErrorLaunchOutOfResources)
			fprintf(stderr, "Try decreasing THREADS in the corresponding cuda*h file. See doc/README-CUDA\n");
		exit(EXIT_FAILURE);
	}
}

#define HANDLE_ERROR(err) (HandleError(err,__FILE__,__LINE__))

extern "C"
char *get_cuda_header_version()
{
	unsigned int minor=((CUDA_VERSION%100)/10)%10;
	unsigned int major=(CUDA_VERSION/1000)%100;
	static char ret[8];
	snprintf(ret,8,"%d.%d",major,minor);
	return ret;
}

extern "C"
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
int cuda_id2nvml(int cuda_id)
{
#if __linux__ && HAVE_LIBDL
	cudaDeviceProp devProp;
	hw_bus pci_info;

	cudaGetDeviceProperties(&devProp, cuda_id);
	memset(pci_info.busId, 0, sizeof(pci_info.busId));
	sprintf(pci_info.busId, "%02x:%02x.%x",
	        devProp.pciBusID, devProp.pciDeviceID, devProp.pciDomainID);
	return id2nvml(pci_info);
#else
	return -1;
#endif
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

	printf("%d CUDA device%s found:\n", devices, devices > 1 ? "s" : "");
	nvidia_probe();
	for (i = 0; i < devices; i++) {
		cudaDeviceProp devProp;
		int arch_sm[] = { 1, 8, 32, 192, 0, 128 };

		cudaGetDeviceProperties(&devProp, i);
		printf("\nCUDA Device #%d\n", i);
		printf("\tName:                          %s\n", devProp.name);
		printf("\tType:                          %s%s\n",
		    devProp.integrated ? "integrated" : "discrete",
		    devProp.tccDriver ? " (Tesla running tcc)" : "");
		printf("\tCompute capability:            %d.%d (sm_%d%d)\n",
		       devProp.major, devProp.minor,
		       devProp.major, devProp.minor);

		if (devProp.major <= 5 && arch_sm[devProp.major])
		printf("\tNumber of stream processors:   %d (%d x %d)\n",
		    devProp.multiProcessorCount * arch_sm[devProp.major],
		    devProp.multiProcessorCount, arch_sm[devProp.major]);
		else /* We need to populate the arch_sm[] above */
		printf("\tNumber of multiprocessors:     %d\n",
		    devProp.multiProcessorCount);

		printf("\tClock rate:                    %d Mhz\n",
		    devProp.clockRate / 1000);
		printf("\tMemory clock rate (peak)       %d Mhz\n",
		    devProp.memoryClockRate / 1000);
		printf("\tMemory bus width               %d bits\n",
		    devProp.memoryBusWidth);
		printf("\tPeak memory bandwidth:         %u GB/s\n",
		    2 * devProp.memoryClockRate *
		    (devProp.memoryBusWidth / 8) /
		    1000000);
		printf("\tTotal global memory:           %s%s\n",
		    human_format(devProp.totalGlobalMem),
		    devProp.ECCEnabled ? " (ECC)" : "");
		printf("\tTotal shared memory per block: %s\n",
		    human_format(devProp.sharedMemPerBlock));
		printf("\tTotal constant memory:         %s\n",
		    human_format(devProp.totalConstMem));

		if (devProp.l2CacheSize)
		printf("\tL2 cache size                  %s\n",
		    human_format(devProp.l2CacheSize));
		else
		printf("\tL2 cache:                      No\n");

		printf("\tKernel execution timeout:      %s\n",
		    (devProp.kernelExecTimeoutEnabled ? "Yes" : "No"));
		printf("\tConcurrent copy and execution: %s\n",
		    (devProp.asyncEngineCount == 2 ?
		     "Bi-directional" : devProp.asyncEngineCount == 1 ?
		     "One direction" : "No"));
		printf("\tConcurrent kernels support:    %s\n",
		    (devProp.concurrentKernels ? "Yes" : "No"));
		printf("\tWarp size:                     %d\n",
		    devProp.warpSize);
		printf("\tMax. GPRs/thread block         %d\n",
		    devProp.regsPerBlock);
		printf("\tMax. threads per block         %d\n",
		    devProp.maxThreadsPerBlock);
		printf("\tMax. resident threads per MP   %d\n",
		    devProp.maxThreadsPerMultiProcessor);
		printf("\tPCI device topology:           %02x:%02x.%x\n",
		    devProp.pciBusID, devProp.pciDeviceID, devProp.pciDomainID);
#if __linux__ && HAVE_LIBDL
		if (nvml_lib) {
			int fan, temp, util;
			int nvml_id = cuda_id2nvml(i);

			printf("\tNVML id:                       %d\n",
			       nvml_id);
			fan = temp = util = -1;

			nvidia_get_temp(nvml_id, &temp, &fan, &util);
			if (fan >= 0)
				printf("\tFan speed:                     %d%%\n", fan);
			else
				printf("\tFan speed:                     n/a\n");
			if (temp >= 0)
				printf("\tGPU temp:                      %d"
				       DEGC "\n", temp);
			else
				printf("\tGPU temp:                      n/a\n");
			if (util >= 0)
				printf("\tUtilization:                   %d%%\n", util);
			else
				printf("\tUtilization:                   n/a\n");
		}
#endif
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

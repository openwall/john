/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _CUDA_COMMON_CU
#define _CUDA_COMMON_CU

#include <stdio.h>
#include "cuda_common.cuh"

extern "C" 
void HandleError(cudaError_t err, const char *file, int line)
{
	if (err != cudaSuccess) {
		printf("%s in %s at line %d\n", cudaGetErrorString(err), file,
		    line);
		exit(EXIT_FAILURE);
	}
}

#define HANDLE_ERROR(err) (HandleError(err,__FILE__,__LINE__))

extern "C" 
void cuda_init(unsigned int gpu_id)
{
	int devices;
	HANDLE_ERROR(cudaGetDeviceCount(&devices));
	if (gpu_id < devices && devices > 0 )
		cudaSetDevice(gpu_id);
	else {
		printf("Invalid CUDA device id = %u\n", gpu_id);
		//fprintf(stderr,
		exit(1);
	}
}

#endif
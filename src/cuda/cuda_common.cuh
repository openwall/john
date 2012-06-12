/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _CUDA_COMMON_CUH
#define _CUDA_COMMON_CUH

extern "C" 
void HandleError(cudaError_t err, const char *file, int line);

#define HANDLE_ERROR(err) (HandleError(err,__FILE__,__LINE__))

extern "C" 
void cuda_init(unsigned int gpu_id);
extern "C"
void cuda_device_list();
#endif
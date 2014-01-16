/*
* The software updates are Copyright (c) 2014 Muhammad Junaid Muzammil <mjunaidmuzammil at gmail dot com>,
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without
* modification, are permitted.
*/
/*
* This software is Copyright (c) 2011,2013 Lukas Odzioba <ukasz at openwall dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _CUDA_COMMON_H
#define _CUDA_COMMON_H

#include <cuda_runtime.h>

#include "common-gpu.h"

#define HANDLE_ERROR(err) (HandleError(err,__FILE__,__LINE__))
extern char *get_cuda_header_version();
extern void cuda_init();
extern void cuda_done(void);

#define check_mem_allocation(inbuffer,outbuffer)\
    if(inbuffer==NULL){\
      fprintf(stderr,"Cannot allocate memory for passwords file:%s line:%d\n",__FILE__,__LINE__);\
      exit(1);\
    }\
    if(outbuffer==NULL){\
      fprintf(stderr,"Cannot allocate memory for hashes file:%s line:%d\n",__FILE__,__LINE__);\
      exit(1);\
    }

extern void cuda_device_list();

extern void HandleError(cudaError_t err, const char *file, int line);

#endif

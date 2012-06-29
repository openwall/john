/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _CUDA_COMMON_H
#define _CUDA_COMMON_H

/*
* CUDA device id specified by -device parameter
*/
#ifdef CL_VERSION_1_0
extern int gpu_id;
#else
int gpu_id;
#endif

extern void cuda_init(unsigned int gpu_id);

#define check_mem_allocation(inbuffer,outbuffer)\
    if(inbuffer==NULL){\
      fprintf(stderr,"Cannot alocate memory for passwords file:%s line:%d\n",__FILE__,__LINE__);\
      exit(1);\
    }\
    if(inbuffer==NULL){\
      fprintf(stderr,"Cannot alocate memory for hashes file:%s line:%d\n",__FILE__,__LINE__);\
      exit(1);\
    }

#endif

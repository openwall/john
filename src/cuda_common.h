/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifndef _CUDA_COMMON_H
#define _CUDA_COMMON_H

/*
* CUDA device id specified by -gpu parameter
*/
unsigned int gpu_id;

extern void cuda_init(unsigned int gpu_id);


#endif
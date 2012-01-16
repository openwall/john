#ifndef _COMMON_OPENCL_H
#define _COMMON_OPENCL_H

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif
 
#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "path.h"

/* common OpenCL variables */
cl_platform_id platform;
cl_device_id devices;
cl_context context;
cl_program program;
cl_command_queue queue;
cl_int ret_code;
cl_kernel crypt_kernel;
size_t local_work_size;
size_t max_group_size;

void if_error_log(cl_int ret_code, const char *message);

void opencl_init(char *kernel_filename, cl_device_type device_type);

#endif

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

#define MAXGPUS	4
#define MAX_PLATFORMS	4
#define SUBSECTION_OPENCL	":OpenCL"

/* Comment if you do not want to see OpenCL warnings during kernel compilation */
#define REPORT_OPENCL_WARNINGS

/* Common OpenCL variables */
int gpu_id, platform_id;
cl_platform_id platform[MAX_PLATFORMS];
cl_device_id devices[MAXGPUS];
cl_context context[MAXGPUS];
cl_program program[MAXGPUS];
cl_command_queue queue[MAXGPUS];
cl_int ret_code;
cl_kernel crypt_kernel;
size_t local_work_size;
size_t max_group_size;

void opencl_init(char *kernel_filename, unsigned int dev_id,
                 unsigned int platform_id);

cl_ulong get_local_memory_size(int dev_id);
size_t get_max_work_group_size(int dev_id);
cl_uint get_max_compute_units(int dev_id);
cl_device_type get_device_type(int dev_id);

char *get_error_name(cl_int cl_error);

void handle_clerror(cl_int cl_error, const char *message, const char *file, int line);

void advance_cursor() ;
/* Use this macro for OpenCL Error handling */
#define HANDLE_CLERROR(cl_error, message) (handle_clerror(cl_error,message,__FILE__,__LINE__))

void listOpenCLdevices();

#endif

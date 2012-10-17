#ifndef _COMMON_OPENCL_H
#define _COMMON_OPENCL_H

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#include <OpenCL/cl_ext.h>
#else
#include <CL/cl.h>
#include <CL/cl_ext.h>
#endif

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "path.h"
#include "opencl_device_info.h"

#define MAXGPUS	8
#define MAX_PLATFORMS	8
#define SUBSECTION_OPENCL	":OpenCL"
#define MAX_OCLINFO_STRING_LEN	2048

#ifdef __APPLE__
#define OPENCLBUILDOPTIONS ""
#else
#define OPENCLBUILDOPTIONS "-cl-strict-aliasing -cl-mad-enable"
#endif

/* Comment if you do not want to see OpenCL warnings during kernel compilation */
#define REPORT_OPENCL_WARNINGS

/* Common OpenCL variables */
int ocl_gpu_id, platform_id;
cl_platform_id platform[MAX_PLATFORMS];
cl_device_id devices[MAXGPUS];
cl_context context[MAXGPUS];
cl_program program[MAXGPUS];
cl_command_queue queue[MAXGPUS];
cl_int ret_code;
cl_kernel crypt_kernel;
cl_event *profilingEvent, *firstEvent, *lastEvent;
size_t local_work_size;
size_t global_work_size;
size_t max_group_size;

int device_info[MAXGPUS];
int cores_per_MP[MAXGPUS];

cl_int oclGetDevCap(cl_device_id device, cl_int *iComputeCapMajor, cl_int *iComputeCapMinor);

void opencl_init_dev(unsigned int dev_id, unsigned int platform_id);
void opencl_init(char *kernel_filename, unsigned int dev_id,
                 unsigned int platform_id);
void opencl_init_opt(char *kernel_filename, unsigned int dev_id,
                     unsigned int platform_id, char *options);
void opencl_init_from_binary(char *kernel_filename, unsigned int dev_id,
                 unsigned int platform_id);
void opencl_build_kernel(char *kernel_filename, unsigned int dev_id);
void opencl_find_best_workgroup(struct fmt_main *self);
void opencl_find_best_workgroup_limit(struct fmt_main *self, size_t group_size_limit);

cl_device_type get_device_type(int dev_id);
cl_ulong get_local_memory_size(int dev_id);
cl_ulong get_global_memory_size(int dev_id);
size_t get_max_work_group_size(int dev_id);
cl_ulong get_max_mem_alloc_size(int dev_id);
size_t get_current_work_group_size(int dev_id, cl_kernel crypt_kernel);
cl_uint get_max_compute_units(int dev_id);
cl_uint get_processors_count(int dev_id);
cl_uint get_processor_family(int dev_id);
int get_vendor_id(int dev_id);
int get_platform_vendor_id(int platform_id);
int get_device_version(int dev_id);
int get_byte_addressable(int dev_id);

char *get_error_name(cl_int cl_error);

void handle_clerror(cl_int cl_error, const char *message, const char *file, int line);

void advance_cursor() ;
/* Use this macro for OpenCL Error handling */
#define HANDLE_CLERROR(cl_error, message) (handle_clerror(cl_error,message,__FILE__,__LINE__))

void listOpenCLdevices();

void opencl_find_gpu(int *dev_id, int *platform_id);

#endif

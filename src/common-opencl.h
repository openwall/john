#ifndef _COMMON_OPENCL_H
#define _COMMON_OPENCL_H

#ifdef __APPLE__
#include <OpenCL/opencl.h>
/* Should there be an alternative cl_ext.h here? */
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

#define MAXGPUS	8
#define MAX_PLATFORMS	8
#define SUBSECTION_OPENCL	":OpenCL"
#define MAX_OCLINFO_STRING_LEN	64

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
cl_event profilingEvent;
size_t local_work_size;
size_t max_group_size;

int device_info[MAXGPUS];
int cores_per_MP[MAXGPUS];

cl_int oclGetDevCap(cl_device_id device, cl_int *iComputeCapMajor, cl_int *iComputeCapMinor);

void opencl_init_dev(unsigned int dev_id, unsigned int platform_id);
void opencl_init(char *kernel_filename, unsigned int dev_id,
                 unsigned int platform_id);
void opencl_build_kernel(char *kernel_filename, unsigned int dev_id);
void opencl_find_best_workgroup(struct fmt_main *pFmt);


cl_device_type get_device_type(int dev_id);
cl_ulong get_local_memory_size(int dev_id);
size_t get_max_work_group_size(int dev_id);
size_t get_current_work_group_size(int dev_id, cl_kernel crypt_kernel);
cl_uint get_max_compute_units(int dev_id);
cl_uint get_processors_count(int dev_id);
cl_uint get_processor_family(int dev_id);
int get_vendor_id(int dev_id);

#define UNKNOWN                 0
#define CPU                     1
#define GPU                     2
#define ACCELERATOR             4
#define AMD                     64
#define NVIDIA                  128
#define INTEL                   256
#define AMD_GCN                 1024
#define AMD_VLIW4               2048
#define AMD_VLIW5               4096 
        
#define cpu(n)                  ((n & CPU) == (CPU))
#define gpu(n)                  ((n & GPU) == (GPU))
#define gpu_amd(n)              ((n & AMD) && gpu(n))
#define gpu_amd_64(n)           (0)
#define gpu_nvidia(n)           ((n & NVIDIA) && gpu(n))
#define gpu_intel(n)            ((n & INTEL) && gpu(n))
#define cpu_amd(n)              ((n & AMD) && cpu(n))
#define amd_gcn(n)              ((n & AMD_GCN) && gpu_amd(n))
#define amd_vliw4(n)            ((n & AMD_VLIW4) && gpu_amd(n))
#define amd_vliw5(n)            ((n & AMD_VLIW5) && gpu_amd(n))

char *get_error_name(cl_int cl_error);

void handle_clerror(cl_int cl_error, const char *message, const char *file, int line);

void advance_cursor() ;
/* Use this macro for OpenCL Error handling */
#define HANDLE_CLERROR(cl_error, message) (handle_clerror(cl_error,message,__FILE__,__LINE__))

void listOpenCLdevices();

#endif

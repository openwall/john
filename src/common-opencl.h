/* ***
 * This file is part of John the Ripper password cracker.
 *
 * Common OpenCL functions go in this file.
 *
 *
 * Copyright (c) 2013 by Claudio André <claudio.andre at correios.net.br>,
 * Copyright (c) 2012-2013 magnum,
 * Others and
 * is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 *** */

#ifndef _COMMON_OPENCL_H
#define _COMMON_OPENCL_H

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#include <OpenCL/cl_ext.h>
#else
#include <CL/cl.h>
#include <CL/cl_ext.h>
#endif

#include "common-gpu.h"
#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "path.h"
#include "stdint.h"
#include "opencl_device_info.h"

#define MAX_PLATFORMS	8
#define MAX_EVENTS 8
#define SUBSECTION_OPENCL	":OpenCL"
#define MAX_OCLINFO_STRING_LEN	2048

#define OPENCLBUILDOPTIONS "-cl-mad-enable"

#ifdef DEBUG_CL_ALLOC
static inline cl_mem john_clCreateBuffer (int l, char *f,
                                          cl_context context,
                                          cl_mem_flags flags, size_t size,
                                          void *host_ptr, cl_int *errcode_ret)
{
	fprintf(stderr, "allocating %zu bytes in line %d of %s\n", size, l, f);
	return clCreateBuffer(context, flags, size, host_ptr, errcode_ret);
}

#define clCreateBuffer(a, b, c, d, e)	john_clCreateBuffer(__LINE__, \
	                    __FILE__, a, b, c, d, e)
#endif

typedef struct {
	cl_platform_id			platform;
	int				num_devices;
} cl_platform;
cl_platform platforms[MAX_PLATFORMS];

/* Common OpenCL variables */
extern int platform_id;

extern cl_device_id devices[MAX_GPU_DEVICES];
extern cl_context context[MAX_GPU_DEVICES];
extern cl_program program[MAX_GPU_DEVICES];
extern cl_command_queue queue[MAX_GPU_DEVICES];
extern cl_int ret_code;
extern cl_kernel crypt_kernel;
extern size_t local_work_size;
extern size_t global_work_size;
extern size_t max_group_size;
extern unsigned int opencl_v_width;
extern char *kernel_source;

extern cl_event *profilingEvent, *firstEvent, *lastEvent;
extern cl_event *multi_profilingEvent[MAX_EVENTS];

extern int device_info[MAX_GPU_DEVICES];
extern int cores_per_MP[MAX_GPU_DEVICES];

#define LWS_CONFIG_NAME			"_LWS"
#define GWS_CONFIG_NAME			"_GWS"
#define DUR_CONFIG_NAME			"_MaxDuration"
#define FALSE				0

void opencl_read_source(char *kernel_filename);

/* Passive init: enumerate platforms and devices and parse options */
void opencl_preinit(void);

/* Tear-down. Safe to call even if no device was used */
void opencl_done(void);

/*
 * Returns preferred vector width for a given device. The --force-scalar
 * or --force-vector-width=N options and the ForceScalar config option may
 * affect the return value.
 */
unsigned int opencl_get_vector_width(int sequential_id, int size);

/* Returns number of selected devices */
int opencl_get_devices(void);

/* Initialize a specific device. If necessary, parse command line and get
 * information about all OpenCL devices. */
int opencl_prepare_dev(int sequential_id);

/* Initialize a device and build kernel. This invokes opencl_init_dev */
/* User can pass build options to the OpenCL compiler */
void opencl_init(char *kernel_filename, int sequential_id, char *options);

/* used by opencl_DES_bs_b.c */
void opencl_build(int sequential_id, char *opts, int save,
                  char *file_name, int showLog);

/* Build kernel (if not cached), and cache it */
void opencl_build_kernel(char *kernel_filename, int sequential_id,
                         char *options, int warn);

void opencl_find_best_workgroup(struct fmt_main *self);
void opencl_find_best_workgroup_limit(
	struct fmt_main *self, size_t group_size_limit, int sequential_id,
	cl_kernel crypt_kernel);

cl_device_type get_device_type(int sequential_id);
cl_ulong get_local_memory_size(int sequential_id);
cl_ulong get_global_memory_size(int sequential_id);
size_t get_device_max_lws(int sequential_id);
cl_ulong get_max_mem_alloc_size(int sequential_id);
size_t get_kernel_max_lws(int sequential_id, cl_kernel crypt_kernel);
cl_uint get_max_compute_units(int sequential_id);
cl_uint get_processors_count(int sequential_id);
cl_uint get_processor_family(int sequential_id);
int get_vendor_id(int sequential_id);
int get_platform_id(int sequential_id);
int get_platform_vendor_id(int platform_id);
int get_device_version(int sequential_id);
int get_byte_addressable(int sequential_id);
size_t get_kernel_preferred_multiple(int sequential_id, cl_kernel crypt_kernel);

void opencl_get_user_preferences(char * format);

/* Returns error name based on error codes list defined in cl.h */
char *get_error_name(cl_int cl_error);

/* Returns OpenCL version based on macro CL_VERSION_X_Y definded in cl.h */
char *get_opencl_header_version(void);

void handle_clerror(cl_int cl_error, const char *message, const char *file, int line);

/* List all available devices. For each one, shows a set of useful
 * hardware/software details */
void opencl_list_devices(void);

/* Call this to check for keypress etc. within kernel loops */
void opencl_process_event(void);

/* Use this macro for OpenCL Error handling */
#define HANDLE_CLERROR(cl_error, message) (handle_clerror(cl_error,message,__FILE__,__LINE__))

/* Use this macro for OpenCL Error handling in crypt_all_benchmark() */
#define BENCH_CLERROR(cl_error, message) {	  \
		if ((cl_error) != CL_SUCCESS) \
			return -1; \
	}

/* Macro for get a multiple of a given value */
#define GET_MULTIPLE(dividend, divisor)		((divisor) ? ((dividend / divisor) * divisor) : (dividend))

/*
 * Shared function to find 'the best' local work group size.
 *
 * - group_size_limit: the max work group size to be tested.
 *   Register pressure, __local memory usage, ..., will define the limiting value.
 * - sequential_id: the sequential number of the device in use.
 * - Your kernel (or main kernel) should be crypt_kernel.
 */
void opencl_find_best_lws(size_t group_size_limit, int sequential_id,
                          cl_kernel crypt_kernel);

/*
 * Shared function to find 'the best' global work group size (keys per crypt).
 *
 * - step: the step size to be used to define the next gws to be tested.
 *   Zero: starting from 512 multiply it by 2 (512, 1024, 2048, 4096, ...).
 *   N > 0: starting from N, use N as step (N, 2N, 3N, 4N...).
 *   E.g. step=1024 (1024, 2048, 3072, 4096, ...).
 * - max_run_time: maximum kernel runtime allowed (in ms).
 * - sequential_id: the sequential number of the device in use.
 * - rounds: the number of rounds used by the algorithm.
 *   For raw formats it should be 1. For sha512crypt it is 5000.
 */
void opencl_find_best_gws(int step, unsigned long long int max_run_time,
                          int sequential_id, unsigned int rounds);

/*
 * Shared function to initialize variables necessary by shared find(lws/gws) functions.
 *
 * - p_default_value: the default step size (see step in opencl_find_best_gws).
 * - p_hash_loops: the number of loops performed by a split-kernel. Zero otherwise.
 * - p_number_of_events: number of events that have to be benchmarked.
 *   For example: if you only transfer plaintext, compute the hash and tranfer hashes back,
 *   the number is 3.
 * - p_split_events: A pointer to a 3 elements array containing the position order of
 *   events that process the main part of a split-kernel. NULL have to be used for non split-kernel.
 *   Find best_gws will compute the split-kernel three times in order to get the 'real' runtime.
 *   Example:
 *       for (i = 0; i < 3; i++) {
 *           HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], main_kernel[gpu_id], 1, NULL,
 *               &gws, &local_work_size, 0, NULL,
 *               multi_profilingEvent[split_events[i]]),  //split_events contains: 2 ,5 ,6
 *               "failed in clEnqueueNDRangeKernel");
 *       }
 *
 * - p_warnings: array of strings to be used to show the execution details.
 *   For example to get a line like this:
 *     - pass xfer: 10.01 ms, crypt: 3.46 ms, result xfer: 1.84 ms
 *   An array like this have to be used:
 *     - "pass xfer: "  ,  ", crypt: ", ", result xfer: "
 * - p_to_profile_event: index of the main event to be profiled (in find_lws).
 * - p_self: a pointer to the format itself.
 * - p_create_clobj: function that (m)alloc all buffers needed by crypt_all.
 * - p_release_clobj: function that release all buffers needed by crypt_all.
 * - p_buffer_size: the size of the plaintext/the most important buffer to allocate.
 *   (needed to assure there is enough memory to handle a GWS that is going to be tested).
 * - p_gws_limit: the maximum number of global_work_size the format can handle.
 *   (needed to variable size plaintext formats).
 */
void opencl_init_auto_setup(
	int p_default_value, int p_hash_loops, int p_number_of_events,
	int * p_split_events, const char ** p_warnings,
	int p_to_profile_event, struct fmt_main * p_self,
	void (*p_create_clobj)(size_t gws, struct fmt_main * self),
	void (*p_release_clobj)(void), int p_buffer_size, size_t p_gws_limit);

#endif

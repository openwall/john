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

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "path.h"
#include "stdint.h"
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

/* Comment if you do not want to see OpenCL warnings during kernel compilation.
   Currently commented out for releases. The output will also be present if
   you define DEBUG so this may be deprecated anyway. */
#define REPORT_OPENCL_WARNINGS

/* Common OpenCL variables */
int ocl_gpu_id, platform_id;
int ocl_device_list[MAXGPUS];

typedef struct {
	cl_platform_id			platform;
	int				num_devices;
} cl_platform;
cl_platform platforms[MAX_PLATFORMS];

cl_platform_id platform[MAX_PLATFORMS];
cl_device_id devices[MAXGPUS];
cl_context context[MAXGPUS];
cl_program program[MAXGPUS];
cl_command_queue queue[MAXGPUS];
cl_int ret_code;
cl_kernel crypt_kernel;
size_t local_work_size;
size_t global_work_size;
size_t max_group_size;

char *kernel_source;
void opencl_read_source(char *kernel_filename);

#define EVENTS 8
cl_event *profilingEvent, *firstEvent, *lastEvent;
cl_event multi_profilingEvent[EVENTS];

#define LWS_CONFIG_NAME			"_LWS"
#define GWS_CONFIG_NAME			"_GWS"
#define DUR_CONFIG_NAME			"_MaxDuration"
#define FALSE				0

int device_info[MAXGPUS];
int cores_per_MP[MAXGPUS];

/* Passive init: enumerate platforms and devices and parse options */
void opencl_preinit(void);

/* Tear-down. Safe to call even if no device was used */
void opencl_done(void);

/* Returns number of selected devices */
int opencl_get_devices(void);

/* Initialize a specific device. Creates a queue and a context */
void opencl_init_dev(unsigned int sequential_id);

/* Initialize a device and build kernel. This invokes opencl_init_dev */
void opencl_init(char *kernel_filename, unsigned int sequential_id);

/* Same as above but pass options to OpenCL compiler */
void opencl_init_opt(char *kernel_filename, unsigned int sequential_id, char *options);

/* used by opencl_DES_bs_b.c */
void opencl_build(unsigned int sequential_id, char *opts, int save, char * file_name, int showLog);

/* Build kernel (if not cached), and cache it */
void opencl_build_kernel(char *kernel_filename, unsigned int sequential_id, char *options, int warn);

void opencl_find_best_workgroup(struct fmt_main *self);
void opencl_find_best_workgroup_limit(struct fmt_main *self, size_t group_size_limit, unsigned int sequential_id, cl_kernel crypt_kernel);

cl_device_type get_device_type(unsigned int sequential_id);
cl_ulong get_local_memory_size(unsigned int sequential_id);
cl_ulong get_global_memory_size(unsigned int sequential_id);
size_t get_max_work_group_size(unsigned int sequential_id);
cl_ulong get_max_mem_alloc_size(unsigned int sequential_id);
size_t get_current_work_group_size(unsigned int sequential_id, cl_kernel crypt_kernel);
cl_uint get_max_compute_units(unsigned int sequential_id);
cl_uint get_processors_count(unsigned int sequential_id);
cl_uint get_processor_family(unsigned int sequential_id);
int get_vendor_id(unsigned int sequential_id);
int get_platform_vendor_id(int platform_id);
int get_device_version(unsigned int sequential_id);
int get_byte_addressable(unsigned int sequential_id);
size_t get_kernel_preferred_work_group_size(unsigned int sequential_id, cl_kernel crypt_kernel);

void opencl_get_user_preferences(char * format);

/* Returns error name based on error codes list defined in cl.h */
char *get_error_name(cl_int cl_error);

/* Returns OpenCL version based on macro CL_VERSION_X_Y definded in cl.h */
char *get_opencl_header_version(void);

void handle_clerror(cl_int cl_error, const char *message, const char *file, int line);

/* Progress indicator "spinning wheel" */
void advance_cursor(void);

void listOpenCLdevices(void);

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
#define GET_MULTIPLE(dividend, divisor)		 ((unsigned int) ((dividend / divisor) * divisor))

/*
 * Shared function to find 'the best' local work group size.
 *
 * - show_details: shows messages giving more detailed information.
 * - group_size_limit: the max work group size to be tested.
 *   Register pressure, __local memory usage, ..., will define the limiting value.
 * - sequential_id: the sequential number of the device in use.
 * - Your kernel (or main kernel) should be crypt_kernel.
 */
void opencl_find_best_lws(
	int show_details, size_t group_size_limit,
	unsigned int sequential_id, cl_kernel crypt_kernel);

/*
 * Shared function to find 'the best' global work group size (keys per crypt).
 *
 * - step: the step size to be used to define the next gws to be tested.
 *   Zero: starting from 512 multiply it by 2 (512, 1024, 2048, 4096, ...).
 *   N > 0: starting from N, use N as step (N, 2N, 3N, 4N...).
 *   E.g. step=1024 (1024, 2048, 3072, 4096, ...).
 * - show_speep: shows the speed detail (like this):
 *   - gws:  16384      7068 c/s  35341675 rounds/s   2.318 sec per crypt_all()
 *   - and shows messages giving more detailed information.
 * - show_details: shows the time of execution for each part (like this):
 *   - pass xfer: 10.01 ms, crypt: 3.46 ms, result xfer: 1.84 ms
 * - max_run_time: maximum kernel runtime allowed (in ms).
 * - sequential_id: the sequential number of the device in use.
 * - rounds: the number of rounds used by the algorithm.
 *   For raw formats it should be 1. For sha512crypt it is 5000.
 */
void opencl_find_best_gws(
	int step, int show_speed, int show_details,
	unsigned long long int max_run_time, int sequential_id,
	unsigned int rounds);

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
 *           HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], main_kernel[ocl_gpu_id], 1, NULL,
 *               &gws, &local_work_size, 0, NULL,
 *               &multi_profilingEvent[split_events[i]]),  //split_events contains: 2 ,5 ,6
 *               "failed in clEnqueueNDRangeKernel");
 *       }
 *
 * - p_warnings: array os strings to be used by show_details.
 *   - "salt xfer: "  ,  ", pass xfer: "  ,  ", crypt: ", ...
 * - p_to_profile_event: pointer to the main event to be profiled (in find_lws).
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
	cl_event * p_to_profile_event, struct fmt_main * p_self,
	void (*p_create_clobj)(int gws, struct fmt_main * self),
	void (*p_release_clobj)(void), int p_buffer_size, size_t p_gws_limit);

#endif

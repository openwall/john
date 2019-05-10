/* ***
 * This file is part of John the Ripper password cracker.
 *
 * Common OpenCL functions go in this file.
 *
 *
 * Copyright (c) 2013-2015 Claudio André <claudioandre.br at gmail.com>,
 * Copyright (c) 2012-2013 magnum,
 * Others and
 * is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 *** */

#ifndef _COMMON_OPENCL_H
#define _COMMON_OPENCL_H

#if HAVE_OPENCL

#include <stdint.h>

#ifndef CL_TARGET_OPENCL_VERSION
#define CL_TARGET_OPENCL_VERSION 120
#endif

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#include <OpenCL/cl_ext.h>
#else
#include <CL/cl.h>
#include <CL/cl_ext.h>
#endif

#if !CL_VERSION_1_2
#error We need minimum OpenCL 1.2 to build with OpenCL support. The headers currently used does not comply.
#endif

#include "gpu_common.h"
#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "path.h"
#include "opencl_device_info.h"

#define MAX_PLATFORMS   8
#define MAX_EVENTS      0x3f
#define SUBSECTION_OPENCL   ":OpenCL"
#define MAX_OCLINFO_STRING_LEN  2048

#define OPENCLBUILDOPTIONS "-cl-mad-enable"

#ifndef CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV
#define CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV       0x4000
#endif

#ifndef CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV
#define CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV       0x4001
#endif

#ifndef CL_DEVICE_REGISTERS_PER_BLOCK_NV
#define CL_DEVICE_REGISTERS_PER_BLOCK_NV            0x4002
#endif

#ifndef CL_DEVICE_WARP_SIZE_NV
#define CL_DEVICE_WARP_SIZE_NV                      0x4003
#endif

#ifndef CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV
#define CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV            0x4005
#endif

#ifndef CL_DEVICE_PCI_BUS_ID_NV
#define CL_DEVICE_PCI_BUS_ID_NV                     0x4008
#endif

#ifndef CL_DEVICE_PCI_SLOT_ID_NV
#define CL_DEVICE_PCI_SLOT_ID_NV                    0x4009
#endif

#ifndef CL_DEVICE_TOPOLOGY_AMD
#define CL_DEVICE_TOPOLOGY_AMD                      0x4037
typedef union {
	struct {
		cl_uint type;
		cl_uint data[5];
	} raw;
	struct {
		cl_uint type;
		cl_char unused[17];
		cl_char bus;
		cl_char device;
		cl_char function;
	} pcie;
} cl_device_topology_amd;

#define CL_DEVICE_TOPOLOGY_TYPE_PCIE_AMD            1
#endif

#ifndef CL_DEVICE_BOARD_NAME_AMD
#define CL_DEVICE_BOARD_NAME_AMD                    0x4038
#endif

#ifndef CL_DEVICE_SIMD_WIDTH_AMD
#define CL_DEVICE_SIMD_WIDTH_AMD                    0x4041
#endif

#ifndef CL_DEVICE_WAVEFRONT_WIDTH_AMD
#define CL_DEVICE_WAVEFRONT_WIDTH_AMD               0x4043
#endif

#ifdef DEBUG_CL_ALLOC
inline static cl_mem
john_clCreateBuffer(int l, char *f, cl_context context, cl_mem_flags flags,
                    size_t size, void *host_ptr, cl_int *errcode_ret)
{
	fprintf(stderr, "allocating "Zu" bytes in line %d of %s\n", size, l, f);
	return clCreateBuffer(context, flags, size, host_ptr, errcode_ret);
}

#define clCreateBuffer(a, b, c, d, e)   john_clCreateBuffer(__LINE__, \
                __FILE__, a, b, c, d, e)
#endif

typedef struct {
	int device_info;
	int cores_per_MP;
	hw_bus pci_info;
} ocl_device_details;

/* Common OpenCL variables */
extern int platform_id;
extern int default_gpu_selected;
extern int default_device_selected;
extern int ocl_autotune_running;
extern size_t ocl_max_lws;
extern int autotune_real_db;

extern cl_device_id devices[MAX_GPU_DEVICES + 1];
extern cl_context context[MAX_GPU_DEVICES];
extern cl_program program[MAX_GPU_DEVICES];
extern cl_command_queue queue[MAX_GPU_DEVICES];
extern cl_int ret_code;
extern cl_kernel crypt_kernel;
extern size_t local_work_size;
extern size_t global_work_size;
extern size_t max_group_size;
extern unsigned int ocl_v_width;
extern unsigned long long global_speed;

extern cl_event *profilingEvent, *firstEvent, *lastEvent;
extern cl_event *multi_profilingEvent[MAX_EVENTS];

extern int device_info[MAX_GPU_DEVICES];

#define LWS_CONFIG_NAME         "_LWS"
#define GWS_CONFIG_NAME         "_GWS"
#define DUR_CONFIG_NAME         "_MaxDuration"
#define FALSE               0

size_t opencl_read_source(const char *kernel_filename, char **kernel_source);

/* Passive init: enumerate platforms and devices and parse options */
void opencl_load_environment(void);

/* Tear-down. Safe to call even if no device was used */
void opencl_done(void);

/*
 * Returns preferred vector width for a given device. The --force-scalar
 * or --force-vector-width=N options and the ForceScalar config option may
 * affect the return value.
 */
unsigned int opencl_get_vector_width(int sequential_id, int size);

/* Returns number of selected devices */
int get_number_of_devices_in_use(void);

/* Returns number of requested devices */
int get_number_of_requested_devices(void);

/* Initialize a specific device. If necessary, parse command line and get
 * information about all OpenCL devices. */
int opencl_prepare_dev(int sequential_id);

/* Initialize a device and build kernel. This invokes opencl_prepare_dev */
/* User can pass build options to the OpenCL compiler */
void opencl_init(const char *kernel_filename, int sequential_id, const char *options);

/* used by opencl_DES_bs_*.c */
void opencl_build(int sequential_id, const char *opts, int save, const char *file_name,
		  cl_program *program, const char *kernel_source_file, const char *kernel_source);
void opencl_build_from_binary(int sequential_id, cl_program *program, const char *kernel_source,
			      size_t program_size);

/* Build kernel (if not cached), and cache it */
void opencl_build_kernel(const char *kernel_filename, int sequential_id,
                         const char *options, int warn);

/* --
  This function get valid and sane values for LWS and GWS that can be used,
 * e.g, during self-test in a GPU mask mode run (the real tune happens later).
-- */
void opencl_get_sane_lws_gws_values();

cl_device_type get_device_type(int sequential_id);
cl_ulong get_local_memory_size(int sequential_id);
cl_ulong get_global_memory_size(int sequential_id);
size_t get_device_max_lws(int sequential_id);
cl_ulong get_max_mem_alloc_size(int sequential_id);
size_t get_kernel_max_lws(int sequential_id, cl_kernel crypt_kernel);
cl_uint get_max_compute_units(int sequential_id);
cl_uint get_processors_count(int sequential_id);
cl_uint get_processor_family(int sequential_id);
char* get_device_name_(int sequential_id);

/* Vendor id for hardware */
int get_vendor_id(int sequential_id);
int get_platform_id(int sequential_id);

/* Vendor id for openCL platform */
int get_platform_vendor_id(int platform_id);
int get_device_version(int sequential_id);
int get_byte_addressable(int sequential_id);
size_t get_kernel_preferred_multiple(int sequential_id,
                                     cl_kernel crypt_kernel);
void get_compute_capability(int sequential_id, unsigned int *major,
                            unsigned int *minor);

void opencl_get_user_preferences(const char *format);

/* Returns error name based on error codes list defined in cl.h */
char *get_error_name(cl_int cl_error);

/* Returns OpenCL version based on macro CL_VERSION_X_Y defined in cl.h */
char *get_opencl_header_version(void);

/* List all available devices. For each one, shows a set of useful
 * hardware/software details */
void opencl_list_devices(void);

/* Call this to check for keypress etc. within kernel loops */
void opencl_process_event(void);

/* Use this macro for OpenCL Error handling in crypt_all() */
#define BENCH_CLERROR(cl_error, message)	  \
	do { cl_int __err = (cl_error); \
		if (__err != CL_SUCCESS) { \
			if (!ocl_autotune_running || options.verbosity >= VERB_MAX) \
				fprintf(stderr, "%u: OpenCL %s error in %s:%d - %s\n", \
					NODE, get_error_name(__err), __FILE__, __LINE__, message); \
			else if (options.verbosity > VERB_LEGACY) \
				fprintf(stderr, " %u: %s\n", NODE, get_error_name(__err)); \
			if (!(ocl_autotune_running || bench_or_test_running)) \
				error(); \
			else \
				return -1; \
		} \
	} while (0)

/* Use this macro for OpenCL Error handling anywhere else */
#define HANDLE_CLERROR(cl_error, message)	  \
	do { cl_int __err = (cl_error); \
		if (__err != CL_SUCCESS) { \
			fprintf(stderr, "%u: OpenCL %s error in %s:%d - %s\n", \
				NODE, get_error_name(__err), __FILE__, __LINE__, (message)); \
			error(); \
		} \
	} while (0)

/* Non-fatal alternative */
#define SOFT_CLERROR(cl_error, message)	  \
	do { cl_int __err = (cl_error); \
		if (__err != CL_SUCCESS) { \
			fprintf(stderr, "%u: OpenCL %s error in %s:%d - %s\n", \
			    NODE, get_error_name(__err), __FILE__, __LINE__, (message)); \
		} \
	} while (0)

/* Macro for get a multiple of a given value */
#define GET_NEXT_MULTIPLE(dividend, divisor)	  \
	(divisor) ? ((dividend + (ocl_v_width * divisor - 1)) / (ocl_v_width * divisor)) * divisor : (dividend) / ocl_v_width;

#define GET_MULTIPLE_OR_ZERO(dividend, divisor)	  \
	((divisor) ? ((dividend / divisor) * divisor) : (dividend))

#define GET_EXACT_MULTIPLE(dividend, divisor)	  \
	(divisor) ? ((dividend > divisor) ? ((dividend / divisor) * divisor) : divisor) : dividend

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
 * - max_duration: maximum kernel runtime allowed (in ms).
 * - sequential_id: the sequential number of the device in use.
 * - rounds: the number of rounds used by the algorithm.
 *   For raw formats it should be 1. For sha512crypt it is 5000.
 */
void opencl_find_best_gws(int step, int max_duration,
                          int sequential_id, unsigned int rounds, int have_lws);

/*
 * Shared function to initialize variables necessary by shared find(lws/gws) functions.
 *
 * - p_default_value: the default step size (see step in opencl_find_best_gws).
 * - p_hash_loops: the number of loops performed by a split-kernel. Zero otherwise.
 *   For example: if you only transfer plaintext, compute the hash and transfer hashes back,
 *   the number is 3.
 * - p_split_events: A pointer to a 3 elements array containing the position order of
 *   events that process the main part of a split-kernel. NULL have to be used for non split-kernel.
 *   Find best_gws will compute the split-kernel three times in order to get the 'real' runtime.
 *   Example:
 *       for (i = 0; i < 3; i++) {
 *     BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], main_kernel[gpu_id], 1, NULL,
 *         &gws, &local_work_size, 0, NULL,
 *         multi_profilingEvent[split_events[i]]),  //split_events contains: 2 ,5 ,6
 *         "failed in clEnqueueNDRangeKernel");
 *       }
 *
 * - p_warnings: array of strings to be used to show the execution details.
 *   For example to get a line like this:
 *     - pass xfer: 10.01 ms, crypt: 3.46 ms, result xfer: 1.84 ms
 *   An array like this have to be used:
 *     - "pass xfer: ",  ", crypt: ", ", result xfer: "
 * - p_main_opencl_event: index of the main event to be profiled (in find_lws).
 * - p_self: a pointer to the format itself.
 * - p_create_clobj: function that (m)alloc all buffers needed by crypt_all.
 * - p_release_clobj: function that release all buffers needed by crypt_all.
 * - p_buffer_size: size of the largest single buffer to allocate per work item
 *   (needed to assure there is enough memory to handle a GWS that is going to
 *    be tested).
 * - p_gws_limit: the maximum number of global_work_size the format can handle.
 *   If non-zero, this will over-ride p_buffer_size when more fine control is needed.
 */
void opencl_init_auto_setup(int p_default_value, int p_hash_loops,
                            int *p_split_events, const char **p_warnings,
                            int p_main_opencl_event, struct fmt_main *p_self,
                            void (*p_create_clobj)(size_t gws, struct fmt_main *self),
                            void (*p_release_clobj)(void), int p_buffer_size, size_t p_gws_limit,
                            struct db_main *db);

/*
 * Shared function to get the OpenCL driver number.
 *
 * - sequential_id: the sequential number of the device in use.
 * - major: the major number of the driver version.
 * - minor: the minor number of the driver version.
 */
void opencl_driver_value(int sequential_id, int *major, int *minor);

/*
 * Rough "speed index" estimation for a device. Returns (clock * SP's) where
 * SP is number of cores multipled by "SP's per core" if known, or the native
 * vector width for 'int' otherwise.
 */
unsigned int opencl_speed_index(int sequential_id);

/*
 * Calculates the size of the bitmap used by the Bloom Filter buffer.
 */
uint32_t get_bitmap_size_bits(uint32_t num_elements, int sequential_id);

/*
 * Calculate optimal min. kpc for single mode for a given LWS and GWS.
 */
int opencl_calc_min_kpc(size_t lws, size_t gws, int v_width);

#endif /* HAVE_OPENCL */

#endif /* _COMMON_OPENCL_H */

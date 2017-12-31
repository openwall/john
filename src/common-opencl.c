/*
 * This file is part of John the Ripper password cracker.
 *
 * Common OpenCL functions.
 *
 * This software is
 * Copyright (c) 2010-2012 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2010-2013 Lukas Odzioba <ukasz@openwall.net>
 * Copyright (c) 2010-2015 magnum
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 *
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 */

#ifdef HAVE_OPENCL

#define _BSD_SOURCE 1           // setenv()
#define _DEFAULT_SOURCE 1       // setenv()
#define NEED_OS_TIMER
#define NEED_OS_FLOCK
#include "os.h"

#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <stdlib.h>
#if !AC_BUILT || HAVE_FCNTL_H
#include <fcntl.h>
#endif

// the 2 DJ_DOS builds currently set this (and do not build the header). If other environs
// can not build the header, then they will also have this value set.
#ifdef NO_JOHN_BLD
#define JOHN_BLD "unk-build-type"
#else
#include "john_build_rule.h"
#endif

#include "jumbo.h"
#include "options.h"
#include "config.h"
#include "common.h"
#include "logger.h"
#include "common-opencl.h"
#include "mask_ext.h"
#include "dyna_salt.h"
#include "signals.h"
#include "recovery.h"
#include "status.h"
#include "john.h"
#include "md5.h"
#ifdef HAVE_MPI
#include "john-mpi.h"
#endif
#include "memdbg.h"

#define LOG_SIZE 1024*16

#if !defined(__CYGWIN__)
// If true, use realpath(3) for translating eg. "-I./kernels" into an absolute
// path before submitting as JIT compile option to OpenCL.
#define I_REALPATH 1
#endif

// If we are a release build, only output OpenCL build log if
// there was a fatal error (or --verbosity was increased).
#ifdef JTR_RELEASE_BUILD
#define LOG_VERB VERB_LEGACY
#else
#define LOG_VERB VERB_DEFAULT
#endif

/* Common OpenCL variables */
int platform_id;
int default_gpu_selected;
int ocl_autotune_running;
size_t ocl_max_lws;

static char opencl_log[LOG_SIZE];
static int opencl_initialized;

extern volatile int bench_running;
static char* opencl_get_dev_info(int sequential_id);
static int find_valid_opencl_device();

// Used by auto-tuning to decide how GWS should changed between trials.
extern int autotune_get_next_gws_size(size_t num, int step, int startup,
                                      int default_value);

// Settings to use for auto-tuning.
static int buffer_size;
static int default_value;
static int hash_loops;
static unsigned long long int duration_time = 0;
static const char **warnings;
static int *split_events;
static int main_opencl_event;
static struct fmt_main *self;
static void (*create_clobj)(size_t gws, struct fmt_main *self);
static void (*release_clobj)(void);
static char fmt_base_name[128];
static size_t gws_limit;
static int printed_mask;
static struct db_main *autotune_db;
static struct db_salt *autotune_salts;

typedef struct {
	cl_platform_id platform;
	int num_devices;
} cl_platform;
static cl_platform platforms[MAX_PLATFORMS];


cl_device_id devices[MAX_GPU_DEVICES];
cl_context context[MAX_GPU_DEVICES];
cl_program program[MAX_GPU_DEVICES];
cl_command_queue queue[MAX_GPU_DEVICES];
cl_int ret_code;
cl_kernel crypt_kernel;
size_t local_work_size;
size_t global_work_size;
size_t max_group_size;
unsigned int ocl_v_width = 1;
unsigned long long global_speed;

cl_event *profilingEvent, *firstEvent, *lastEvent;
cl_event *multi_profilingEvent[MAX_EVENTS];

int device_info[MAX_GPU_DEVICES];
static ocl_device_details ocl_device_list[MAX_GPU_DEVICES];

void opencl_process_event(void)
{
	if (!ocl_autotune_running && !bench_running) {
#if !OS_TIMER
		sig_timer_emu_tick();
#endif
		if (event_pending) {
			if (event_save) {
				event_save = 0;
				rec_save();
			}

			if (event_status) {
				event_status = 0;
				status_print();
			}

			if (event_ticksafety) {
				event_ticksafety = 0;
				status_ticks_overflow_safety();
			}

			event_pending = (event_abort || event_poll_files || event_reload);
		}
	}
}

int get_number_of_available_platforms()
{
	int i = 0;

	while (platforms[i].platform)
		i++;

	return i;
}

int get_number_of_available_devices()
{
	int total = 0, i = 0;

	while (platforms[i].platform)
		total += platforms[i++].num_devices;

	return total;
}

int get_number_of_devices_in_use()
{
	int i = 0;

	while (gpu_device_list[i++] != -1);

	return --i;
}

int get_number_of_requested_devices()
{
	int i = 0;

	while (requested_devices[i++] != -1);

	return --i;
}

int get_platform_id(int sequential_id)
{
	int pos = 0, i = 0;

	while (platforms[i].platform) {
		pos += platforms[i].num_devices;

		if (sequential_id < pos)
			break;
		i++;
	}
	return (platforms[i].platform ? i : -1);
}

int get_device_id(int sequential_id)
{
	int pos = sequential_id, i = 0;

	while (platforms[i].platform && pos >= platforms[i].num_devices) {
		pos -= platforms[i].num_devices;
		i++;
	}
	return (platforms[i].platform ? pos : -1);
}

int get_sequential_id(unsigned int dev_id, unsigned int platform_id)
{
	int pos = 0, i = 0;

	while (platforms[i].platform && i < platform_id)
		pos += platforms[i++].num_devices;

	if (i == platform_id && dev_id >= platforms[i].num_devices)
		return -1;

	return (platforms[i].platform ? pos + dev_id : -1);
}

void opencl_driver_value(int sequential_id, int *major, int *minor)
{
	char dname[MAX_OCLINFO_STRING_LEN];
	char *p;

	*major = 0, *minor = 0;

	clGetDeviceInfo(devices[sequential_id], CL_DRIVER_VERSION,
	                sizeof(dname), dname, NULL);

	p = dname;
	while (*p && !isdigit((int)*p))
		p++;
	if (*p) {
		*major = atoi(p);
		while (*p && isdigit((int)*p))
			p++;
		while (*p && !isdigit((int)*p))
			p++;
		if (*p) {
			*minor = atoi(p);
		}
	}
}

static char *opencl_driver_ver(int sequential_id)
{
	static char ret[64];
	int major, minor;

	opencl_driver_value(sequential_id, &major, &minor);

	snprintf(ret, sizeof(ret), "-DDEV_VER_MAJOR=%d -DDEV_VER_MINOR=%d",
	         major, minor);

	return ret;
}

static char *remove_spaces(char *str) {

	char *out = str, *put = str;

	for (; *str; str++) {
		if (*str != ' ')
			*put++ = *str;
	}
	*put = '\0';

	return out;
}

static char *opencl_driver_info(int sequential_id)
{
	static char ret[64];
	char dname[MAX_OCLINFO_STRING_LEN], tmp[64], set[64];
	char *name, *recommendation = NULL;
	int major = 0, minor = 0, conf_major = 0, conf_minor = 0, found;
	struct cfg_list *list;
	struct cfg_line *line;

	clGetDeviceInfo(devices[sequential_id], CL_DRIVER_VERSION,
	                sizeof(dname), dname, NULL);
	opencl_driver_value(sequential_id, &major, &minor);
	name = ret;

	if ((list = cfg_get_list("List.OpenCL:", "Drivers")))
	if ((line = list->head))
	do {
		char *p;

		//Parse driver information.
		strncpy(set, line->data, 64);
		remove_spaces(set);

		p = strtokm(set, ",");
		conf_major = strtoul(p, NULL, 10);

		p = strtokm(NULL, ";");
		conf_minor = strtoul(p, NULL, 10);

		name = strtokm(NULL, ";");
		recommendation = strtokm(NULL, ";");

		if (gpu_amd(device_info[sequential_id]))
		if (conf_major == major && conf_minor == minor)
			break;

		if (gpu_nvidia(device_info[sequential_id]))
		if (recommendation && strstr(recommendation, "N"))
		if (conf_major <= major && conf_minor <= minor)
			break;

#ifdef OCL_DEBUG
		fprintf(stderr, "Driver: %i, %i -> %s , %s\n",
			conf_major, conf_minor, name, recommendation);
#endif
	} while ((line = line->next));

	if (gpu_amd(device_info[sequential_id])) {

		if (major < 1912)
			snprintf(ret, sizeof(ret), "%s - Catalyst %s", dname, name);
		else
			snprintf(ret, sizeof(ret), "%s - Crimson %s", dname, name);
		snprintf(tmp, sizeof(tmp), "%s", ret);
	} else
		snprintf(tmp, sizeof(tmp), "%s", dname);

	snprintf(dname, sizeof(dname), " ");

	if (recommendation) {
		//Check hardware
		found = (strstr(recommendation, "G") && amd_gcn(device_info[sequential_id]));
		found += (strstr(recommendation, "N") && gpu_nvidia(device_info[sequential_id]));
		found += (strstr(recommendation, "V") &&
			 (amd_vliw4(device_info[sequential_id]) ||
			  amd_vliw5(device_info[sequential_id])));

		//Check OS
		if (found) {
			found = (strstr(recommendation, "*") != NULL);
			found += (strstr(recommendation, "L") && strstr(JOHN_BLD, "linux"));
			found += (strstr(recommendation, "W") && strstr(JOHN_BLD, "windows"));
		}

		if (strstr(recommendation, "T"))
			snprintf(dname, sizeof(dname), " [known bad]");
		else if (found) {
			if (strstr(recommendation, "R"))
				snprintf(dname, sizeof(dname), " [recommended]");
			else if (strstr(recommendation, "S"))
				snprintf(dname, sizeof(dname), " [supported]");
		}
	}
	snprintf(ret, sizeof(ret), "%s%s", tmp, dname);

	return ret;
}

static char *ns2string(cl_ulong nanosec)
{
	char *buf = mem_alloc_tiny(16, MEM_ALIGN_NONE);
	int s, ms, us, ns;

	ns = nanosec % 1000;
	nanosec /= 1000;
	us = nanosec % 1000;
	nanosec /= 1000;
	ms = nanosec % 1000;
	s = nanosec / 1000;

	if (s) {
		if (ms)
			snprintf(buf, 16, "%d.%03ds", s, ms);
		else
			snprintf(buf, 16, "%ds", s);
	} else if (ms) {
		if (us)
			snprintf(buf, 16, "%d.%03dms", ms, us);
		else
			snprintf(buf, 16, "%dms", ms);
	} else if (us) {
		if (ns)
			snprintf(buf, 16, "%d.%03dus", us, ns);
		else
			snprintf(buf, 16, "%dus", us);
	} else
		snprintf(buf, 16, "%dns", ns);
	return buf;
}

static int get_if_device_is_in_use(int sequential_id)
{
	int i = 0, found = 0;
	int num_devices;

	if (sequential_id >= get_number_of_available_devices()) {
		return -1;
	}

	num_devices = get_number_of_devices_in_use();

	for (i = 0; i < num_devices && !found; i++) {
		if (sequential_id == gpu_device_list[i])
			found = 1;
	}
	return found;
}

static void start_opencl_environment()
{
	cl_platform_id platform_list[MAX_PLATFORMS];
	char opencl_data[LOG_SIZE];
	cl_uint num_platforms, device_num, device_pos = 0;
	int i, ret;

	/* Find OpenCL enabled devices. We ignore error here, in case
	 * there is no platform and we'd like to run a non-OpenCL format. */
	clGetPlatformIDs(MAX_PLATFORMS, platform_list, &num_platforms);

	for (i = 0; i < num_platforms; i++) {
		platforms[i].platform = platform_list[i];

		HANDLE_CLERROR(clGetPlatformInfo(platforms[i].platform,
		                                 CL_PLATFORM_NAME, sizeof(opencl_data), opencl_data, NULL),
		               "Error querying PLATFORM_NAME");

		// It is possible to have a platform without any devices
		ret = clGetDeviceIDs(platforms[i].platform, CL_DEVICE_TYPE_ALL,
		                     MAX_GPU_DEVICES, &devices[device_pos],
		                     &device_num);

		if ((ret != CL_SUCCESS || device_num < 1) &&
		        options.verbosity > VERB_LEGACY)
			fprintf(stderr, "No OpenCL devices was found on platform #%d\n", i);

		// Save platform and devices information
		platforms[i].num_devices = device_num;

		// Point to the end of the list
		device_pos += device_num;

#ifdef OCL_DEBUG
		fprintf(stderr, "OpenCL platform %d: %s, %d device(s).\n",
		        i, opencl_data, device_num);
#endif
	}
	// Set NULL to the final buffer position.
	platforms[i].platform = NULL;
	devices[device_pos] = NULL;
}

static cl_int get_pci_info(int sequential_id, hw_bus *hardware_info)
{

	cl_int ret;

	hardware_info->bus = -1;
	hardware_info->device = -1;
	hardware_info->function = -1;
	memset(hardware_info->busId, '\0', sizeof(hardware_info->busId));

	if (gpu_amd(device_info[sequential_id]) || cpu(device_info[sequential_id])) {
		cl_device_topology_amd topo;

		ret = clGetDeviceInfo(devices[sequential_id],
		                      CL_DEVICE_TOPOLOGY_AMD, sizeof(topo), &topo, NULL);

		if (ret == CL_SUCCESS) {
			hardware_info->bus = topo.pcie.bus & 0xff;
			hardware_info->device = topo.pcie.device & 0xff;
			hardware_info->function = topo.pcie.function & 0xff;
		} else if (cpu_intel(device_info[sequential_id]))
			return CL_SUCCESS;
		else
			return ret;
	} else if (gpu_nvidia(device_info[sequential_id])) {
		cl_uint entries;

		ret = clGetDeviceInfo(devices[sequential_id], CL_DEVICE_PCI_BUS_ID_NV,
		                      sizeof(cl_uint), &entries, NULL);

		if (ret == CL_SUCCESS)
			hardware_info->bus = entries;
		else
			return ret;

		ret = clGetDeviceInfo(devices[sequential_id], CL_DEVICE_PCI_SLOT_ID_NV,
		                      sizeof(cl_uint), &entries, NULL);

		if (ret == CL_SUCCESS) {
			hardware_info->device = entries >> 3;
			hardware_info->function = entries & 7;

		} else
			return ret;
	}

	sprintf(hardware_info->busId, "%02x:%02x.%x", hardware_info->bus,
	        hardware_info->device, hardware_info->function);
	return CL_SUCCESS;
}

static int start_opencl_device(int sequential_id, int *err_type)
{
	cl_context_properties properties[3];
	char opencl_data[LOG_SIZE];

	// Get the detailed information about the device
	// (populate device_info[d] bitfield).
	opencl_get_dev_info(sequential_id);

	// Get hardware bus/PCIE information.
	get_pci_info(sequential_id, &ocl_device_list[sequential_id].pci_info);

	// Map temp monitoring function and NVML/ADL id to our device id
	if (gpu_nvidia(device_info[sequential_id])) {
		temp_dev_id[sequential_id] =
		    id2nvml(ocl_device_list[sequential_id].pci_info);
		dev_get_temp[sequential_id] = nvml_lib ? nvidia_get_temp : NULL;
	} else if (gpu_amd(device_info[sequential_id])) {
		temp_dev_id[sequential_id] =
		    id2adl(ocl_device_list[sequential_id].pci_info);
		dev_get_temp[sequential_id] = adl_lib ? amd_get_temp : NULL;

		if (sequential_id > 0 &&
		    temp_dev_id[sequential_id] == temp_dev_id[sequential_id - 1]) {
			/* Kludge for 7990 > 14.9. We hates AMD. */
			ocl_device_list[sequential_id].pci_info.bus++;
			temp_dev_id[sequential_id] =
				id2adl(ocl_device_list[sequential_id].pci_info);
		}
	} else {
		temp_dev_id[sequential_id] = sequential_id;
		dev_get_temp[sequential_id] = NULL;
	}

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_NAME,
	                               sizeof(opencl_data), opencl_data, NULL),
	               "Error querying DEVICE_NAME");

	max_group_size = get_device_max_lws(sequential_id);

	// Get the platform properties
	properties[0] = CL_CONTEXT_PLATFORM;
	properties[1] = (cl_context_properties)
	                platforms[get_platform_id(sequential_id)].platform;
	properties[2] = 0;

	// Setup context and queue
	context[sequential_id] = clCreateContext(properties, 1,
	                         &devices[sequential_id], NULL, NULL, &ret_code);
	if (ret_code != CL_SUCCESS) {
#ifdef OCL_DEBUG
		fprintf(stderr, "Error creating context for device %d "
		        "(%d:%d): %s\n", sequential_id,
		        get_platform_id(sequential_id),
		        get_device_id(sequential_id), get_error_name(ret_code));
#endif
		platforms[get_platform_id(sequential_id)].num_devices--;
		*err_type = 1;
		return 0;
	}
	queue[sequential_id] = clCreateCommandQueue(context[sequential_id],
	                       devices[sequential_id], 0, &ret_code);
	if (ret_code != CL_SUCCESS) {
#ifdef OCL_DEBUG
		fprintf(stderr, "Error creating command queue for "
		        "device %d (%d:%d): %s\n", sequential_id,
		        get_platform_id(sequential_id),
		        get_device_id(sequential_id), get_error_name(ret_code));
#endif
		platforms[get_platform_id(sequential_id)].num_devices--;
		HANDLE_CLERROR(clReleaseContext(context[sequential_id]),
		               "Release Context");
		*err_type = 2;
		return 0;
	}
#ifdef OCL_DEBUG
	fprintf(stderr, "  Device %d: %s\n", sequential_id, opencl_data);
#endif
	// Success.
	return 1;
}

static void add_device_to_list(int sequential_id)
{
	int i = 0, found;

	found = get_if_device_is_in_use(sequential_id);

	if (found < 0) {
		fprintf(stderr, "Invalid OpenCL device id %d\n", sequential_id);
		error();
	}

	if (found == 0) {
		// Only requested and working devices should be started.
		if (john_main_process) {
			if (! start_opencl_device(sequential_id, &i)) {
				fprintf(stderr, "Device id %d not working correctly,"
					" skipping.\n", sequential_id);
				return;
			}
		}
		gpu_device_list[get_number_of_devices_in_use() + 1] = -1;
		gpu_device_list[get_number_of_devices_in_use()] = sequential_id;
	}
	// The full list of requested devices.
	requested_devices[get_number_of_requested_devices() + 1] = -1;
	requested_devices[get_number_of_requested_devices()] = sequential_id;
}

static void add_device_type(cl_ulong device_type)
{
	int i, j, sequence_nr = 0;
	cl_uint device_num;
	cl_ulong long_entries;
	cl_device_id devices[MAX_GPU_DEVICES];

	for (i = 0; platforms[i].platform; i++) {
		// Get all devices of informed type.
		HANDLE_CLERROR(clGetDeviceIDs(platforms[i].platform,
		                              CL_DEVICE_TYPE_ALL, MAX_GPU_DEVICES, devices, &device_num),
		               "No OpenCL device of that type exist");

		for (j = 0; j < device_num; j++, sequence_nr++) {
			clGetDeviceInfo(devices[j], CL_DEVICE_TYPE,
			                sizeof(cl_ulong), &long_entries, NULL);
			if (long_entries & device_type)
				add_device_to_list(sequence_nr);
		}
	}
}

static void build_device_list(char *device_list[MAX_GPU_DEVICES])
{
	int n = 0;

	while (device_list[n] && n < MAX_GPU_DEVICES) {
		int len = MAX(strlen(device_list[n]), 3);

		if (!strcmp(device_list[n], "all"))
			add_device_type(CL_DEVICE_TYPE_ALL);
		else if (!strcmp(device_list[n], "cpu"))
			add_device_type(CL_DEVICE_TYPE_CPU);
		else if (!strcmp(device_list[n], "gpu"))
			add_device_type(CL_DEVICE_TYPE_GPU);
		else if (!strncmp(device_list[n], "accelerator", len))
			add_device_type(CL_DEVICE_TYPE_ACCELERATOR);
		else if (!isdigit(ARCH_INDEX(device_list[n][0]))) {
			fprintf(stderr, "Error: --device must be numerical, "
			        "or one of \"all\", \"cpu\", \"gpu\" and\n"
			        "\"accelerator\".\n");
			error();
		} else
			add_device_to_list(atoi(device_list[n]));
		n++;
	}
}

void opencl_preinit(void)
{
	char *device_list[MAX_GPU_DEVICES], string[10];
	int n = 0, i;
	char *env;

	// Prefer COMPUTE over DISPLAY and lacking both, assume :0
	env = getenv("COMPUTE");
	if (env && *env)
		setenv("DISPLAY", env, 1);
	else {
		// We assume that 10 dot something is X11
		// forwarding so we override that too.
		env = getenv("DISPLAY");
		if (!env || !*env || strstr(env, ":10."))
			setenv("DISPLAY", ":0", 1);
	}

	if (!opencl_initialized) {
		nvidia_probe();
		amd_probe();
		device_list[0] = NULL;

		gpu_device_list[0] = -1;
		gpu_device_list[1] = -1;
		requested_devices[0] = -1;
		requested_devices[1] = -1;

		gpu_temp_limit = cfg_get_int(SECTION_OPTIONS, SUBSECTION_GPU,
		                             "AbortTemperature");

		for (i = 0; i < MAX_GPU_DEVICES; i++) {
			context[i] = NULL;
			queue[i] = NULL;
		}
		start_opencl_environment();
		{
			struct list_entry *current;

			/* New syntax, sequential --device */
			if ((current = options.acc_devices->head)) {
				do {
					device_list[n++] = current->data;
				} while ((current = current->next));

				device_list[n] = NULL;
			} else
				gpu_id = -1;
		}

		if (!options.acc_devices->head && gpu_id < 0) {
			char *devcfg;

			if ((devcfg = cfg_get_param(SECTION_OPTIONS,
			                            SUBSECTION_OPENCL, "Device"))) {
				gpu_id = atoi(devcfg);
				gpu_device_list[0] = gpu_id;
			}
		}

		if (!device_list[0]) {
			gpu_id = find_valid_opencl_device();

			sprintf(string, "%d", gpu_id);
			device_list[0] = string;
			device_list[1] = NULL;
			default_gpu_selected = 1;
		}

		if (get_number_of_available_devices() == 0) {
			fprintf(stderr, "No OpenCL devices found\n");
			error();
		}
		build_device_list(device_list);

		if (get_number_of_devices_in_use() == 0) {
			fprintf(stderr, "No OpenCL devices found\n");
			error();
		}
#ifdef HAVE_MPI
		// Poor man's multi-device support.
		if (mpi_p > 1 && mpi_p_local > 1) {
			// Pick device to use for this node
			gpu_id = gpu_device_list[mpi_id % get_number_of_devices_in_use()];

			// Hide any other devices from list
			gpu_device_list[0] = gpu_id;
			gpu_device_list[1] = -1;
		} else
#endif
			gpu_id = gpu_device_list[0];
		platform_id = get_platform_id(gpu_id);

		opencl_initialized = 1;
	}
}

unsigned int opencl_get_vector_width(int sequential_id, int size)
{
	/* --force-scalar option, or john.conf ForceScalar boolean */
	if (options.flags & FLG_SCALAR)
		options.v_width = 1;

	/* --force-vector-width=N */
	if (options.v_width) {
		ocl_v_width = options.v_width;
	} else {
		cl_uint v_width = 0;

		/* OK, we supply the real figure */
		opencl_preinit();
		switch (size) {
		case sizeof(cl_char):
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
			                               CL_DEVICE_PREFERRED_VECTOR_WIDTH_CHAR,
			                               sizeof(v_width), &v_width, NULL),
			               "Error asking for char vector width");
			break;
		case sizeof(cl_short):
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
			                               CL_DEVICE_PREFERRED_VECTOR_WIDTH_SHORT,
			                               sizeof(v_width), &v_width, NULL),
			               "Error asking for long vector width");
			break;
		case sizeof(cl_int):
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
			                               CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT,
			                               sizeof(v_width), &v_width, NULL),
			               "Error asking for int vector width");
			break;
		case sizeof(cl_long):
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
			                               CL_DEVICE_PREFERRED_VECTOR_WIDTH_LONG,
			                               sizeof(v_width), &v_width, NULL),
			               "Error asking for long vector width");
			break;
		default:
			fprintf(stderr, "%s() called with unknown type\n", __FUNCTION__);
			error();
		}
		ocl_v_width = v_width;
	}
	return ocl_v_width;
}

/* Called by core after calling format's done() */
void opencl_done()
{
	int i;
	int num_devices;

	printed_mask = 0;

	if (!opencl_initialized)
		return;

	num_devices = get_number_of_devices_in_use();

	for (i = 0; i < num_devices; i++) {
		if (queue[gpu_device_list[i]])
			HANDLE_CLERROR(clReleaseCommandQueue(queue[gpu_device_list[i]]),
			               "Release Queue");
		queue[gpu_device_list[i]] = NULL;
		if (context[gpu_device_list[i]])
			HANDLE_CLERROR(clReleaseContext(context[gpu_device_list[i]]),
			               "Release Context");
		context[gpu_device_list[i]] = NULL;
		program[gpu_device_list[i]] = NULL;
	}

	/* Reset in case we load another format after this */
	local_work_size = global_work_size = duration_time = 0;
	ocl_max_lws = 0;
	ocl_v_width = 1;
	fmt_base_name[0] = 0;
	opencl_initialized = 0;
	crypt_kernel = NULL;

	gpu_device_list[0] = gpu_device_list[1] = -1;
}

static char *opencl_get_config_name(char *format, char *config_name)
{
	static char config_item[128];

	snprintf(config_item, sizeof(config_item), "%s%s", format, config_name);
	return config_item;
}

void opencl_get_user_preferences(char *format)
{
	char *tmp_value;

	if (format) {
		snprintf(fmt_base_name, sizeof(fmt_base_name), "%s", format);
		if ((tmp_value = strrchr(fmt_base_name, (int)'-')))
			* tmp_value = 0;
		strlwr(fmt_base_name);
	} else
		fmt_base_name[0] = 0;

	if (format &&
	        (tmp_value = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL,
	                                   opencl_get_config_name(fmt_base_name, LWS_CONFIG_NAME))))
		local_work_size = atoi(tmp_value);

	if ((tmp_value = getenv("LWS")))
		local_work_size = atoi(tmp_value);

	if (format &&
	        (tmp_value = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL,
	                                   opencl_get_config_name(fmt_base_name, GWS_CONFIG_NAME))))
		global_work_size = atoi(tmp_value);

	if ((tmp_value = getenv("GWS")))
		global_work_size = atoi(tmp_value);

	if (local_work_size)
		// Ensure a valid multiple is used.
		global_work_size = GET_MULTIPLE_OR_ZERO(global_work_size,
		                                        local_work_size);

	if (format &&
	        (tmp_value = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL,
	                                   opencl_get_config_name(fmt_base_name, DUR_CONFIG_NAME))))
		duration_time = atoi(tmp_value) * 1000000ULL;
	else if ((tmp_value = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL,
	                                    "Global" DUR_CONFIG_NAME)))
		duration_time = atoi(tmp_value) * 1000000ULL;
}

void opencl_get_sane_lws_gws_values()
{
	if (!local_work_size) {
		if (cpu(device_info[gpu_id]))
			local_work_size =
				get_platform_vendor_id(platform_id) == DEV_INTEL ?
			8 : 1;
		else
			local_work_size = 64;
	}

	if (!global_work_size)
		global_work_size = 768;
}

char* get_device_name_(int sequential_id)
{
	static char device_name[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_NAME,
	                               sizeof(device_name), device_name, NULL),
	               "Error querying DEVICE_NAME");

	return device_name;
}

static void dev_init(int sequential_id)
{
	static int printed[MAX_GPU_DEVICES];
	char device_name[MAX_OCLINFO_STRING_LEN];
	cl_int ret_code;
	int len;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_NAME,
	                               sizeof(device_name), device_name, NULL),
	               "Error querying DEVICE_NAME");

	ret_code = clGetDeviceInfo(devices[sequential_id],
	                           CL_DEVICE_BOARD_NAME_AMD, sizeof(opencl_log), opencl_log, NULL);

	if (ret_code == CL_SUCCESS && (len = strlen(opencl_log))) {
		while (len > 0 && isspace(ARCH_INDEX(opencl_log[len - 1])))
			len--;
		opencl_log[len] = '\0';

		if (options.verbosity > 1 && !printed[sequential_id]++)
			fprintf(stderr, "Device %d%s%s: %s [%s]\n",
			        sequential_id,
#if HAVE_MPI
			        "@", mpi_name,
#else
			        "", "",
#endif
			        device_name, opencl_log);
		log_event("Device %d: %s [%s]", sequential_id, device_name, opencl_log);
	} else {
		char *dname = device_name;

		/* Skip leading whitespace seen on Intel */
		while (*dname == ' ')
			dname++;

		if (options.verbosity > 1 && !printed[sequential_id]++)
			fprintf(stderr, "Device %d%s%s: %s\n", sequential_id,
#if HAVE_MPI
			        "@", mpi_name,
#else
			        "", "",
#endif
			        dname);
		log_event("Device %d: %s", sequential_id, dname);
	}
}

/*
 * Given a string, return a newly allocated string that is a copy of
 * the original but quoted. The old string is freed.
 */
static char *quote_str(char *orig)
{
	char *new = mem_alloc(strlen(orig) + 3);
	char *s = orig;
	char *d = new;

	*d++ = '"';
	while (*s)
		*d++ = *s++;
	*d++ = '"';
	*d = 0;

	MEM_FREE(orig);

	return new;
}

static char *include_source(char *pathname, int sequential_id, char *opts)
{
	char *include, *full_path;
	char *global_opts;

#if I_REALPATH
	char *pex = path_expand_safe(pathname);

	if (!(full_path = realpath(pex, NULL)))
		pexit("realpath()");

	MEM_FREE(pex);
#else
	full_path = path_expand_safe(pathname);
#endif

	include = (char *) mem_calloc(PATH_BUFFER_SIZE, sizeof(char));

	if (!(global_opts = getenv("OPENCLBUILDOPTIONS")))
		if (!(global_opts = cfg_get_param(SECTION_OPTIONS,
		    SUBSECTION_OPENCL, "GlobalBuildOpts")))
			global_opts = OPENCLBUILDOPTIONS;

	if (strchr(full_path, ' ')) {
		full_path = quote_str(full_path);
	}

	sprintf(include, "-I %s %s %s%s%s%s%d %s%d %s -D_OPENCL_COMPILER %s",
	        full_path,
	        global_opts,
	        get_platform_vendor_id(get_platform_id(sequential_id)) == DEV_MESA ?
	            "-D__MESA__ " : opencl_get_dev_info(sequential_id),
#ifdef __APPLE__
	        "-D__OS_X__ ",
#else
	        (options.verbosity >= VERB_LEGACY && gpu_nvidia(device_info[sequential_id])) ? "-cl-nv-verbose " : "",
#endif
	        get_device_type(sequential_id) == CL_DEVICE_TYPE_CPU ? "-D__CPU__ "
	        : get_device_type(sequential_id) == CL_DEVICE_TYPE_GPU ? "-D__GPU__ " : "",
	        "-DDEVICE_INFO=", device_info[sequential_id],
	        "-DSIZEOF_SIZE_T=", (int)sizeof(size_t),
	        opencl_driver_ver(sequential_id),
	        opts ? opts : "");
#if I_REALPATH
	libc_free(full_path);
#else
	MEM_FREE(full_path);
#endif

	return include;
}

void opencl_build(int sequential_id, char *opts, int save, char *file_name, cl_program *program, char *kernel_source_file, char *kernel_source)
{
	cl_int build_code, err_code;
	char *build_log, *build_opts;
	size_t log_size;
	const char *srcptr[] = { kernel_source };

	/* This over-rides binary caching */
	if (getenv("DUMP_BINARY")) {
		char *bname = basename(kernel_source_file);
		char *ext = ".bin";
		int size = strlen(bname) + strlen(ext) + 1;
		char *name = mem_alloc_tiny(size, MEM_ALIGN_NONE);

		save = 1;
		snprintf(name, size, "%s%s", bname, ext);
		file_name = name;
	}

	*program =
	    clCreateProgramWithSource(context[sequential_id], 1, srcptr,
	                              NULL, &err_code);
	HANDLE_CLERROR(err_code, "Error while creating program");
	// include source is thread safe.
	build_opts = include_source("$JOHN/kernels", sequential_id, opts);

	if (options.verbosity > VERB_LEGACY)
		fprintf(stderr, "Options used: %s %s\n", build_opts, kernel_source_file);

	build_code = clBuildProgram(*program, 0, NULL,
	                            build_opts, NULL, NULL);

	HANDLE_CLERROR(clGetProgramBuildInfo(*program,
	                                     devices[sequential_id],
	                                     CL_PROGRAM_BUILD_LOG, 0, NULL,
	                                     &log_size), "Error while getting build info I");
	build_log = (char *)mem_calloc(1, log_size + 1);

	HANDLE_CLERROR(clGetProgramBuildInfo(*program,
	                                     devices[sequential_id],
	                                     CL_PROGRAM_BUILD_LOG, log_size + 1,
	                                     (void *)build_log, NULL), "Error while getting build info");

	// Report build errors and warnings
	if ((build_code != CL_SUCCESS)) {
		// Give us much info about error and exit
		if (options.verbosity <= VERB_LEGACY)
			fprintf(stderr, "Options used: %s %s\n", build_opts, kernel_source_file);
		fprintf(stderr, "Build log: %s\n", build_log);
		fprintf(stderr, "Error %d building kernel %s. DEVICE_INFO=%d\n",
		        build_code, kernel_source_file, device_info[sequential_id]);
		HANDLE_CLERROR(build_code, "clBuildProgram failed.");
	}
	// Nvidia may return a single '\n' that we ignore
	else if (options.verbosity >= LOG_VERB && strlen(build_log) > 1)
		fprintf(stderr, "Build log: %s\n", build_log);
	MEM_FREE(build_log);
	MEM_FREE(build_opts);

	if (save) {
		FILE *file;
		size_t source_size;
		char *source, *full_path;

		HANDLE_CLERROR(clGetProgramInfo(*program,
		                                CL_PROGRAM_BINARY_SIZES,
		                                sizeof(size_t), &source_size, NULL), "error");

		if (options.verbosity == VERB_MAX)
			fprintf(stderr, "binary size "Zu"\n", source_size);

		source = mem_calloc(1, source_size);

		HANDLE_CLERROR(clGetProgramInfo(*program,
		                                CL_PROGRAM_BINARIES, sizeof(char *), &source, NULL), "error");

		file = fopen(full_path = path_expand_safe(file_name), "w");
		MEM_FREE(full_path);

		if (file == NULL)
			fprintf(stderr, "Error creating binary file %s: %s\n",
			        file_name, strerror(errno));
		else {
#if OS_FLOCK || FCNTL_LOCKS
			{
#if FCNTL_LOCKS
				struct flock lock;

				memset(&lock, 0, sizeof(lock));
				lock.l_type = F_WRLCK;
				while (fcntl(fileno(file), F_SETLKW, &lock)) {
					if (errno != EINTR)
						pexit("fcntl(F_WRLCK)");
				}
#else
				while (flock(fileno(file), LOCK_EX)) {
					if (errno != EINTR)
						pexit("flock(LOCK_EX)");
				}
#endif
			}
#endif
			if (fwrite(source, source_size, 1, file) != 1)
				fprintf(stderr, "error writing binary\n");
			fclose(file);
		}
		MEM_FREE(source);
	}
}

void opencl_build_from_binary(int sequential_id, cl_program *program, char *kernel_source, size_t program_size)
{
	cl_int build_code, err_code;
	char *build_log;
	const char *srcptr[] = { kernel_source };

	build_log = (char *) mem_calloc(LOG_SIZE, sizeof(char));
	*program =
	    clCreateProgramWithBinary(context[sequential_id], 1,
	                              &devices[sequential_id], &program_size, (const unsigned char **)srcptr,
	                              NULL, &err_code);
	HANDLE_CLERROR(err_code,
	               "Error while creating program (using cached binary)");

	build_code = clBuildProgram(*program, 0,
	                            NULL, NULL, NULL, NULL);

	HANDLE_CLERROR(clGetProgramBuildInfo(*program,
	                                     devices[sequential_id],
	                                     CL_PROGRAM_BUILD_LOG, LOG_SIZE, (void *)build_log,
	                                     NULL), "Error while getting build info (using cached binary)");

	// Report build errors and warnings
	if (build_code != CL_SUCCESS) {
		// Give us much info about error and exit
		fprintf(stderr, "Binary build log: %s\n", build_log);
		fprintf(stderr, "Error %d building kernel using cached binary."
		        " DEVICE_INFO=%d\n", build_code, device_info[sequential_id]);
		HANDLE_CLERROR(build_code, "clBuildProgram failed.");
	}
	// Nvidia may return a single '\n' that we ignore
	else if (options.verbosity >= LOG_VERB && strlen(build_log) > 1)
		fprintf(stderr, "Binary Build log: %s\n", build_log);

	MEM_FREE(build_log);
}

// Do the proper test using different global work sizes.
static void clear_profiling_events()
{
	int i;

	// Release events
	for (i = 0; i < MAX_EVENTS; i++) {
		if (multi_profilingEvent[i] && *multi_profilingEvent[i])
			HANDLE_CLERROR(clReleaseEvent(*multi_profilingEvent[i]),
			               "Failed in clReleaseEvent");

		if (multi_profilingEvent[i])
			*multi_profilingEvent[i] = NULL;
		multi_profilingEvent[i] = NULL;
	}
}

// Do the proper test using different global work sizes.
static cl_ulong gws_test(size_t gws, unsigned int rounds, int sequential_id)
{
	cl_ulong startTime, endTime, runtime = 0, looptime = 0;
	int i, count, total = 0;
	size_t kpc = gws * ocl_v_width;
	cl_event benchEvent[MAX_EVENTS];
	int number_of_events = 0;
	void *salt;
	int amd_bug;

	for (i = 0; i < MAX_EVENTS; i++)
		benchEvent[i] = NULL;

	// Ensure format knows its GWS
	global_work_size = gws;

	// Prepare buffers.
	create_clobj(gws, self);


	// Set keys - unique printable length-8 keys
	self->methods.clear_keys();
	{
		union {
			char c[9];
			uint64_t w;
		} key;
		int len = MAX(MIN(self->params.plaintext_length, 8),
		              self->params.plaintext_min_length);

		key.w = 0x6161616161616161ULL;

		for (i = 0; i < kpc; i++) {
			int l = 0;

			key.c[len] = 0;
			self->methods.set_key(key.c, i);
			while (++key.c[l] > 0x7a)
				key.c[l++] = 0x20;
		}
	}

	// Set salt
	dyna_salt_init(self);
	if (self->methods.tunable_cost_value[0] && autotune_db->real) {
		struct db_main *db = autotune_db->real;
		struct db_salt *s = db->salts;

		while (s->next && s->cost[0] < db->max_cost[0])
			s = s->next;
		salt = s->salt;
	} else {
		char *ciphertext;

		if (!self->params.tests[0].fields[1])
			self->params.tests[0].fields[1] = self->params.tests[0].ciphertext;
		ciphertext = self->methods.prepare(self->params.tests[0].fields, self);
		ciphertext = self->methods.split(ciphertext, 0, self);
		salt = self->methods.salt(ciphertext);
		if (salt)
			dyna_salt_create(salt);
	}
	self->methods.set_salt(salt);

	// Activate events. Then clear them later.
	for (i = 0; i < MAX_EVENTS; i++)
		multi_profilingEvent[i] = &benchEvent[i];

	// Timing run
	count = kpc;
	if (self->methods.crypt_all(&count, autotune_salts) < 0) {
		runtime = looptime = 0;

		if (options.verbosity > VERB_LEGACY)
			fprintf(stderr, " (error occurred)");
		clear_profiling_events();
		release_clobj();
		if (!self->methods.tunable_cost_value[0] || !autotune_db->real)
			dyna_salt_remove(salt);
		return 0;
	}

	for (i = 0; (*multi_profilingEvent[i]); i++)
		number_of_events++;

	//** Get execution time **//
	for (i = 0; i < number_of_events; i++) {
		char mult[32] = "";

		amd_bug = 0;

		HANDLE_CLERROR(clWaitForEvents(1, multi_profilingEvent[i]),
		               "WaitForEvents failed");
		HANDLE_CLERROR(clGetEventProfilingInfo(*multi_profilingEvent[i],
		                                       CL_PROFILING_COMMAND_START,
		                                       sizeof(cl_ulong), &startTime,
		                                       NULL), "Failed in clGetEventProfilingInfo I");
		HANDLE_CLERROR(clGetEventProfilingInfo(*multi_profilingEvent[i],
		                                       CL_PROFILING_COMMAND_END,
		                                       sizeof(cl_ulong), &endTime,
		                                       NULL), "Failed in clGetEventProfilingInfo II");

		/* Work around AMD bug. It randomly claims that a kernel
		   run took less than a microsecond, fooling our auto tune */
		if (endTime - startTime < 1000) {
			amd_bug = 1;

			HANDLE_CLERROR(clGetEventProfilingInfo(*multi_profilingEvent[i],
			                                       CL_PROFILING_COMMAND_SUBMIT,
			                                       sizeof(cl_ulong), &startTime,
			                                       NULL), "Failed in clGetEventProfilingInfo I");
			HANDLE_CLERROR(clGetEventProfilingInfo(*multi_profilingEvent[i],
			                                       CL_PROFILING_COMMAND_END,
			                                       sizeof(cl_ulong), &endTime,
			                                       NULL), "Failed in clGetEventProfilingInfo II");
		}

		/* Work around OSX bug with HD4000 driver */
		if (endTime == 0)
			endTime = startTime;

		if ((split_events) && (i == split_events[0] ||
		                       i == split_events[1] || i == split_events[2])) {
			looptime += (endTime - startTime);
			total++;

			if (i == split_events[0])
				sprintf(mult, "%dx", rounds / hash_loops);
		} else
			runtime += (endTime - startTime);

		if (options.verbosity == VERB_MAX)
			fprintf(stderr, "%s%s%s%s", warnings[i], mult,
			        ns2string(endTime - startTime), (amd_bug) ? "*" : "");

		/* Single-invocation duration limit */
		if (duration_time && (endTime - startTime) > duration_time) {
			runtime = looptime = 0;

			if (options.verbosity == VERB_MAX)
				fprintf(stderr, " (exceeds %s)", ns2string(duration_time));
			break;
		}
	}
	if (options.verbosity == VERB_MAX)
		fprintf(stderr, "\n");

	if (total)
		runtime += (looptime * rounds) / (hash_loops * total);

	clear_profiling_events();
	release_clobj();

	if (!self->methods.tunable_cost_value[0] || !autotune_db->real)
		dyna_salt_remove(salt);

	return runtime;
}

void opencl_init_auto_setup(int p_default_value, int p_hash_loops,
                            int *p_split_events, const char **p_warnings,
                            int p_main_opencl_event, struct fmt_main *p_self,
                            void (*p_create_clobj)(size_t gws, struct fmt_main *self),
                            void (*p_release_clobj)(void), int p_buffer_size, size_t p_gws_limit,
                            struct db_main *db)
{
	// Initialize events
	clear_profiling_events();

	// Get parameters
	buffer_size = p_buffer_size;
	default_value = p_default_value;
	hash_loops = p_hash_loops;
	split_events = p_split_events;
	warnings = p_warnings;
	main_opencl_event = p_main_opencl_event;
	self = p_self;
	create_clobj = p_create_clobj;
	release_clobj = p_release_clobj;
	gws_limit = p_gws_limit;
	autotune_db = db;
	autotune_salts = db ? db->salts : NULL;
}

/*
 * Since opencl_find_best_gws() needs more event control (even more events) to
 * work properly, opencl_find_best_workgroup() cannot be used by formats that
 * are using it.  Therefore, despite the fact that opencl_find_best_lws() does
 * almost the same that opencl_find_best_workgroup() can do, it also handles
 * the necessary event(s) and can do a proper crypt_all() execution analysis
 * when shared GWS detection is used.
 */
void opencl_find_best_lws(size_t group_size_limit, int sequential_id,
                          cl_kernel crypt_kernel)
{
	size_t gws;
	cl_int ret_code;
	int i, j, numloops, count;
	size_t my_work_group, optimal_work_group;
	size_t max_group_size, wg_multiple, sumStartTime, sumEndTime;
	cl_ulong startTime, endTime, kernelExecTimeNs = CL_ULONG_MAX;
	cl_event benchEvent[MAX_EVENTS];
	void *salt;

	for (i = 0; i < MAX_EVENTS; i++)
		benchEvent[i] = NULL;

	gws = global_work_size;

	if (options.verbosity > VERB_LEGACY)
		fprintf(stderr, "Calculating best LWS for GWS="Zu"\n", gws);

	if (get_device_version(sequential_id) < 110) {
		if (get_device_type(sequential_id) == CL_DEVICE_TYPE_GPU)
			wg_multiple = 32;
		else if (get_platform_vendor_id(get_platform_id(sequential_id))
		         == DEV_INTEL)
			wg_multiple = 8;
		else
			wg_multiple = 1;
	} else
		wg_multiple = get_kernel_preferred_multiple(sequential_id,
		              crypt_kernel);

	if (platform_apple(platform_id) && cpu(device_info[sequential_id]))
		max_group_size = 1;
	else
		max_group_size = ocl_max_lws ?
			ocl_max_lws : get_kernel_max_lws(sequential_id, crypt_kernel);

	if (max_group_size > group_size_limit)
		// Needed to deal (at least) with cryptsha512-opencl limits.
		max_group_size = group_size_limit;

	// Safety harness
	if (wg_multiple > max_group_size)
		wg_multiple = max_group_size;

	// Change command queue to be used by crypt_all (profile needed)
	clReleaseCommandQueue(queue[sequential_id]);

	// Create a new queue with profiling enabled
	queue[sequential_id] =
	    clCreateCommandQueue(context[sequential_id],
	                         devices[sequential_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");

	// Set keys - unique printable length-8 keys
	self->methods.clear_keys();
	{
		union {
			char c[9];
			uint64_t w;
		} key;
		int len = MAX(MIN(self->params.plaintext_length, 8),
		              self->params.plaintext_min_length);

		key.w = 0x6161616161616161ULL;

		for (i = 0; i < global_work_size; i++) {
			int l = 0;

			key.c[len] = 0;
			self->methods.set_key(key.c, i);
			while (++key.c[l] > 0x7a)
				key.c[l++] = 0x20;
		}
	}

	// Set salt
	dyna_salt_init(self);
	if (self->methods.tunable_cost_value[0] && autotune_db->real) {
		struct db_main *db = autotune_db->real;
		struct db_salt *s = db->salts;

		while (s->next && s->cost[0] < db->max_cost[0])
			s = s->next;
		salt = s->salt;
	} else {
		char *ciphertext;

		if (!self->params.tests[0].fields[1])
			self->params.tests[0].fields[1] = self->params.tests[0].ciphertext;
		ciphertext = self->methods.prepare(self->params.tests[0].fields, self);
		ciphertext = self->methods.split(ciphertext, 0, self);
		salt = self->methods.salt(ciphertext);
		if (salt)
			dyna_salt_create(salt);
	}
	self->methods.set_salt(salt);

	// Warm-up run
	local_work_size = wg_multiple;
	count = global_work_size * ocl_v_width;
	self->methods.crypt_all(&count, autotune_salts);

	// Activate events. Then clear them later.
	for (i = 0; i < MAX_EVENTS; i++)
		multi_profilingEvent[i] = &benchEvent[i];

	// Timing run
	count = global_work_size * ocl_v_width;
	self->methods.crypt_all(&count, autotune_salts);

	HANDLE_CLERROR(clWaitForEvents(1, &benchEvent[main_opencl_event]),
	               "WaitForEvents failed");
	HANDLE_CLERROR(clFinish(queue[sequential_id]), "clFinish error");
	HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent[main_opencl_event],
	                                       CL_PROFILING_COMMAND_START,
	                                       sizeof(cl_ulong),
	                                       &startTime, NULL), "Failed to get profiling info");

	HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent[main_opencl_event],
	                                       CL_PROFILING_COMMAND_END,
	                                       sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");
	numloops = (int)(size_t)(200000000ULL / (endTime - startTime));

	clear_profiling_events();

	if (numloops < 1)
		numloops = 1;
	else if (numloops > 5)
		numloops = 5;

	// Find minimum time
	for (optimal_work_group = my_work_group = wg_multiple;
	        (int)my_work_group <= (int)max_group_size;
	        my_work_group += wg_multiple) {

		global_work_size = gws;
		if (gws % my_work_group != 0) {

			if (GET_EXACT_MULTIPLE(gws, my_work_group) > global_work_size)
			    continue;
			global_work_size = GET_EXACT_MULTIPLE(gws, my_work_group);
		}

		if (options.verbosity > VERB_LEGACY)
			fprintf(stderr, "Testing LWS=" Zu " GWS=" Zu " ...", my_work_group, global_work_size);

		sumStartTime = 0;
		sumEndTime = 0;

		for (i = 0; i < numloops; i++) {
			advance_cursor();
			local_work_size = my_work_group;

			// Activate events. Then clear them later.
			for (j = 0; j < MAX_EVENTS; j++)
				multi_profilingEvent[j] = &benchEvent[j];

			count = global_work_size * ocl_v_width;
			if (self->methods.crypt_all(&count, autotune_salts) < 0) {
				startTime = endTime = 0;
				break;
			}

			HANDLE_CLERROR(clWaitForEvents(1, &benchEvent[main_opencl_event]),
			               "WaitForEvents failed");
			HANDLE_CLERROR(clFinish(queue[sequential_id]), "clFinish error");
			HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent
			                                       [main_opencl_event], CL_PROFILING_COMMAND_START,
			                                       sizeof(cl_ulong), &startTime, NULL),
			               "Failed to get profiling info");
			HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent
			                                       [main_opencl_event], CL_PROFILING_COMMAND_END,
			                                       sizeof(cl_ulong), &endTime, NULL),
			               "Failed to get profiling info");

			sumStartTime += startTime;
			sumEndTime += endTime;

			clear_profiling_events();
		}
		if (!endTime)
			break;
		if (options.verbosity > VERB_LEGACY)
			fprintf(stderr, " %s%s\n", ns2string(sumEndTime - sumStartTime),
			    ((double)(sumEndTime - sumStartTime) / kernelExecTimeNs < 0.997)
			        ? "+" : "");
		if ((double)(sumEndTime - sumStartTime) / kernelExecTimeNs < 0.997) {
			kernelExecTimeNs = sumEndTime - sumStartTime;
			optimal_work_group = my_work_group;
		} else {
			if (my_work_group >= 256 ||
			    (my_work_group >= 8 && wg_multiple < 8)) {
				/* Jump to next power of 2 */
				size_t x, y;
				x = my_work_group;
				while ((y = x & (x - 1)))
					x = y;
				x *= 2;
				my_work_group =
				    GET_MULTIPLE_OR_BIGGER(x, wg_multiple);
				/* The loop logic will re-add wg_multiple */
				my_work_group -= wg_multiple;
			}
		}
	}
	// Release profiling queue and create new with profiling disabled
	HANDLE_CLERROR(clReleaseCommandQueue(queue[sequential_id]),
	               "Failed in clReleaseCommandQueue");
	queue[sequential_id] =
	    clCreateCommandQueue(context[sequential_id],
	                         devices[sequential_id], 0, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");
	local_work_size = optimal_work_group;
	global_work_size = GET_EXACT_MULTIPLE(gws, local_work_size);

	if (!self->methods.tunable_cost_value[0] || !autotune_db->real)
		dyna_salt_remove(salt);
}

static char *human_speed(unsigned long long int speed)
{
	static char out[32];
	char p = '\0';

	if (speed > 1000000) {
		speed /= 1000;
		p = 'K';
	}
	if (speed > 1000000) {
		speed /= 1000;
		p = 'M';
	}
	if (speed > 1000000) {
		speed /= 1000;
		p = 'G';
	}
	if (speed > 1000000) {
		speed /= 1000;
		p = 'T'; /* you wish */
	}
	if (p)
		snprintf(out, sizeof(out), "%llu%cc/s", speed, p);
	else
		snprintf(out, sizeof(out), "%lluc/s", speed);

	return out;
}

uint32_t get_bitmap_size_bits(uint32_t num_elements, int sequential_id)
{
	uint32_t size, elements = num_elements;
	//On super: 128MB , 1GB, 2GB
	cl_ulong memory_available = get_max_mem_alloc_size(sequential_id);

	get_power_of_two(elements);

	size = (elements * 8);

	if (num_elements < (16))
		size = (16 * 1024 * 8); //Cache?
	else if (num_elements < (128))
		size = (1024 * 1024 * 8 * 16);
	else if (num_elements < (16 * 1024))
		size *= 1024 * 4;
	else
		size *= 256;

	if (size > memory_available) {
		size = memory_available;
		get_power_of_two(size);

	}
	if (!size || size > INT_MAX)
		size = (uint)INT_MAX + 1U;

	return size;
}

unsigned int lcm(unsigned int x, unsigned int y)
{
	unsigned int tmp, a, b;

	a = MAX(x, y);
	b = MIN(x, y);

	while (b) {
		tmp = b;
		b = a % b;
		a = tmp;
	}
	return x / a * y;
}

void opencl_find_best_gws(int step, unsigned long long int max_run_time,
                          int sequential_id, unsigned int rounds, int have_lws)
{
	size_t num = 0;
	size_t optimal_gws = local_work_size, soft_limit = 0;
	unsigned long long speed, best_speed = 0, raw_speed;
	cl_ulong run_time, min_time = CL_ULONG_MAX;
	unsigned long long int save_duration_time = duration_time;
	cl_uint core_count = get_processors_count(sequential_id);

	if (have_lws) {
		if (core_count > 2)
			optimal_gws = lcm(core_count, optimal_gws);
		default_value = optimal_gws;
	} else {
		soft_limit = local_work_size * core_count * 128;
	}

	/*
	 * max_run_time is either:
	 *   - total running time for crypt_all(), in ns
	 *   - single duration of a kernel run, is ms (max. 1000)
	 */

	/* Does format specify max. single duration? */
	if (max_run_time <= 1000) {
		max_run_time *= 1000000;
		if (!duration_time || duration_time > max_run_time)
			duration_time = max_run_time;
		max_run_time = 0;
	}

	if (options.verbosity > VERB_LEGACY) {
		if (mask_int_cand.num_int_cand > 1 && !printed_mask++)
			fprintf(stderr, "Internal mask, multiplier: %u (target: %u)\n",
			        mask_int_cand.num_int_cand, mask_int_cand_target);
		else if (mask_int_cand_target > 1 && !printed_mask)
			fprintf(stderr, "Internal mask not utilized (target: %u)\n",
			        mask_int_cand_target);
		if (!max_run_time)
			fprintf(stderr, "Calculating best GWS for LWS="Zu"; "
			        "max. %s single kernel invocation.\n",
			        local_work_size,
			        ns2string(duration_time));
		else
			fprintf(stderr, "Calculating best GWS for LWS="Zu"; "
			        "max. %s total for crypt_all()\n",
			        local_work_size,
			        ns2string(max_run_time));
	}

	if (options.verbosity == VERB_MAX)
		fprintf(stderr, "Raw speed figures including buffer transfers:\n");

	// Change command queue to be used by crypt_all (profile needed)
	clReleaseCommandQueue(queue[sequential_id]);    // Delete old queue

	// Create a new queue with profiling enabled
	queue[sequential_id] =
	    clCreateCommandQueue(context[sequential_id],
	                         devices[sequential_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");

	for (num = autotune_get_next_gws_size(num, step, 1, default_value);;
	        num = autotune_get_next_gws_size(num, step, 0, default_value)) {
		size_t kpc = num * ocl_v_width;

		// Check if hardware can handle the size we are going
		// to try now.
		if ((soft_limit && (num > soft_limit)) ||
		    (gws_limit && (num > gws_limit)) || ((gws_limit == 0) &&
		    (buffer_size * kpc * 1.1 > get_max_mem_alloc_size(gpu_id)))) {
			if (!optimal_gws)
				optimal_gws = num;

			if (options.verbosity == VERB_MAX)
				fprintf(stderr, "Hardware resources exhausted\n");
			break;
		}

		if (!(run_time = gws_test(num, rounds, sequential_id)))
			break;

		if (options.verbosity <= VERB_LEGACY)
			advance_cursor();

		raw_speed = (kpc / (run_time / 1E9)) * mask_int_cand.num_int_cand;
		speed = rounds * raw_speed;

		if (run_time < min_time)
			min_time = run_time;

		if (options.verbosity > VERB_LEGACY)
			fprintf(stderr, "gws: %9zu\t%10s%12llu "
			        "rounds/s%10s per crypt_all()",
			        num, human_speed(raw_speed), speed, ns2string(run_time));

		if (best_speed && speed < 1.8 * best_speed &&
		        max_run_time && run_time > max_run_time) {
			if (!optimal_gws)
				optimal_gws = num;

			if (options.verbosity > VERB_LEGACY)
				fprintf(stderr, " - too slow\n");
			break;
		}

		if (speed > (1.01 * best_speed)) {
			if (options.verbosity > VERB_LEGACY)
				fprintf(stderr, (speed > 2 * best_speed) ? "!" : "+");
			best_speed = speed;
			global_speed = raw_speed;
			optimal_gws = num;
		}
		if (options.verbosity > VERB_LEGACY)
			fprintf(stderr, "\n");
	}
	// Release profiling queue and create new with profiling disabled
	HANDLE_CLERROR(clReleaseCommandQueue(queue[sequential_id]),
	               "Failed in clReleaseCommandQueue");
	queue[sequential_id] =
	    clCreateCommandQueue(context[sequential_id],
	                         devices[sequential_id], 0, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");
	global_work_size = optimal_gws;

	duration_time = save_duration_time;
}

static char* opencl_get_dev_info(int sequential_id)
{
	static char ret[32];
	cl_device_type device;
	unsigned int major = 0, minor = 0;

	device = get_device_type(sequential_id);

	ret[0] = 0;

	if (device == CL_DEVICE_TYPE_CPU)
		device_info[sequential_id] = DEV_CPU;
	else if (device == CL_DEVICE_TYPE_GPU)
		device_info[sequential_id] = DEV_GPU;
	else if (device == CL_DEVICE_TYPE_ACCELERATOR)
		device_info[sequential_id] = DEV_ACCELERATOR;

	device_info[sequential_id] += get_vendor_id(sequential_id);
	device_info[sequential_id] += get_processor_family(sequential_id);
	device_info[sequential_id] += get_byte_addressable(sequential_id);

	get_compute_capability(sequential_id, &major, &minor);

	if (major) {
		snprintf(ret, sizeof(ret), "-DSM_MAJOR=%d -DSM_MINOR=%d ",
		         major, minor);
		device_info[sequential_id] += (major == 2 ? DEV_NV_C2X : 0);
		device_info[sequential_id] +=
		    (major == 3 && minor == 0 ? DEV_NV_C30 : 0);
		device_info[sequential_id] +=
		    (major == 3 && minor == 2 ? DEV_NV_C32 : 0);
		device_info[sequential_id] +=
		    (major == 3 && minor == 5 ? DEV_NV_C35 : 0);
		device_info[sequential_id] += (major == 5 ? DEV_NV_MAXWELL : 0);
		device_info[sequential_id] += (major == 6 ? DEV_NV_PASCAL : 0);
	}

	return ret;
}

static int find_valid_opencl_device()
{
	int d, ret = 0, acc = 0, gpu_found = 0;
	unsigned int speed, best_1 = 0, best_2 = 0;
	int num_devices = get_number_of_available_devices();

	for (d = 0; d < num_devices; d++) {
		// Populate device_info[d] bitfield
		opencl_get_dev_info(d);

		if (device_info[d] &
		    (DEV_GPU | DEV_ACCELERATOR)) {
			speed = opencl_speed_index(d);

			if ((device_info[d] & DEV_GPU) && (speed > best_1)) {
				gpu_found = 1;
				best_1 = speed;
				ret = d;
			} else if ((device_info[d] & DEV_ACCELERATOR) && (speed > best_2)) {
				best_2 = speed;
				acc = d;
			}
		}
	}

	return gpu_found ? ret : acc;
}

size_t opencl_read_source(char *kernel_filename, char **kernel_source)
{
	FILE *fp;
	char *full_path;
	size_t source_size, read_size;

	fp = fopen(full_path = path_expand_safe(kernel_filename), "rb");
	MEM_FREE(full_path);

	if (!fp)
		pexit("Can't read source kernel");

#if OS_FLOCK || FCNTL_LOCKS
	{
#if FCNTL_LOCKS
		struct flock lock;

		memset(&lock, 0, sizeof(lock));
		lock.l_type = F_RDLCK;
		while (fcntl(fileno(fp), F_SETLKW, &lock)) {
			if (errno != EINTR)
				pexit("fcntl(F_RDLCK)");
		}
#else
		while (flock(fileno(fp), LOCK_SH)) {
			if (errno != EINTR)
				pexit("flock(LOCK_SH)");
		}
#endif
	}
#endif
	fseek(fp, 0, SEEK_END);
	source_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	MEM_FREE((*kernel_source));
	*kernel_source = mem_calloc(1, source_size + 1);
	read_size = fread(*kernel_source, sizeof(char), source_size, fp);
	if (read_size != source_size)
		fprintf(stderr,
		        "Error reading source: expected "Zu", got "Zu" bytes.\n",
		        source_size, read_size);
	fclose(fp);
	return source_size;
}

#if JOHN_SYSTEMWIDE
static char *replace_str(char *string, char *from, char *to)
{
	static char buffer[512];
	char *p;
	int len;

	if (!(p = strstr(string, from)))
		return string;

	len = p - string;
	strncpy(buffer, string, len);
	buffer[len] = '\0';

	sprintf(buffer + len, "%s%s", to, p + strlen(from));

	return buffer;
}
#endif


void opencl_build_kernel_opt(char *kernel_filename, int sequential_id,
                             char *opts)
{
	char *kernel_source = NULL;
	opencl_read_source(kernel_filename, &kernel_source);
	opencl_build(sequential_id, opts, 0, NULL, &program[sequential_id], kernel_filename, kernel_source);
	MEM_FREE(kernel_source);
}

#define md5add(string) MD5_Update(&ctx, (string), strlen(string))

void opencl_build_kernel(char *kernel_filename, int sequential_id, char *opts,
                         int warn)
{
	struct stat source_stat, bin_stat;
	char dev_name[512], bin_name[512], *tmp_name;
	unsigned char hash[16];
	char hash_str[33];
	uint64_t startTime, runtime;

	if ((!gpu_amd(device_info[sequential_id]) &&
	        !platform_apple(platform_id)) ||
	        stat(path_expand(kernel_filename), &source_stat))
		opencl_build_kernel_opt(kernel_filename, sequential_id, opts);
	else {
		int i;
		MD5_CTX ctx;
		char *kernel_source = NULL;
		char *global_opts;

		if (!(global_opts = getenv("OPENCLBUILDOPTIONS")))
			if (!(global_opts = cfg_get_param(SECTION_OPTIONS,
			    SUBSECTION_OPENCL, "GlobalBuildOpts")))
				global_opts = OPENCLBUILDOPTIONS;

		startTime = (unsigned long)time(NULL);

		// Get device name.
		HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
		                               CL_DEVICE_NAME, sizeof(dev_name),
		                               dev_name, NULL), "Error querying DEVICE_NAME");

/*
 * Create a hash of kernel source and parameters, and use as cache name.
 */
		MD5_Init(&ctx);
		md5add(kernel_filename);
		opencl_read_source(kernel_filename, &kernel_source);
		md5add(kernel_source);
		md5add(global_opts);
		if (opts)
			md5add(opts);
		md5add(opencl_driver_ver(sequential_id));
		md5add(dev_name);
		MD5_Update(&ctx, (char*)&platform_id, sizeof(platform_id));
		MD5_Final(hash, &ctx);

		for (i = 0; i < 16; i++) {
			hash_str[2 * i + 0] = itoa16[hash[i] >> 4];
			hash_str[2 * i + 1] = itoa16[hash[i] & 0xf];
		}
		hash_str[32] = 0;

#if JOHN_SYSTEMWIDE
		tmp_name = replace_str(kernel_filename, "$JOHN", JOHN_PRIVATE_HOME);
#else
		tmp_name = kernel_filename;
#endif
		snprintf(bin_name, sizeof(bin_name), "%s_%s.bin",
		         tmp_name, hash_str);

		// Select the kernel to run.
		if (!getenv("DUMP_BINARY") && !stat(path_expand(bin_name), &bin_stat) &&
			(source_stat.st_mtime < bin_stat.st_mtime)) {
			size_t program_size = opencl_read_source(bin_name, &kernel_source);
			opencl_build_from_binary(sequential_id, &program[sequential_id], kernel_source, program_size);
		} else {
			if (warn && options.verbosity > VERB_DEFAULT) {
				fprintf(stderr, "Building the kernel, this "
				        "could take a while\n");
				fflush(stdout);
			}
			opencl_read_source(kernel_filename, &kernel_source);
			opencl_build(sequential_id, opts, 1, bin_name, &program[sequential_id], kernel_filename, kernel_source);
		}
		if (warn && options.verbosity > VERB_DEFAULT) {
			if ((runtime = (unsigned long)(time(NULL) - startTime))
			        > 2UL)
				fprintf(stderr, "Build time: %lu seconds\n",
				        (unsigned long)runtime);
			fflush(stdout);
		}

		MEM_FREE(kernel_source);
	}
}

int opencl_prepare_dev(int sequential_id)
{
	int err_type = 0;

	opencl_preinit();

	if (sequential_id < 0)
		sequential_id = gpu_id;

	profilingEvent = firstEvent = lastEvent = NULL;
	if (!context[sequential_id])
		start_opencl_device(sequential_id, &err_type);
	dev_init(sequential_id);

	return sequential_id;
}

void opencl_init(char *kernel_filename, int sequential_id, char *opts)
{
	sequential_id = opencl_prepare_dev(sequential_id);
	opencl_build_kernel(kernel_filename, sequential_id, opts, 0);
}

cl_device_type get_device_type(int sequential_id)
{
	cl_device_type type;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_TYPE,
	                               sizeof(cl_device_type), &type, NULL),
	               "Error querying CL_DEVICE_TYPE");

	return type;
}

cl_ulong get_local_memory_size(int sequential_id)
{
	cl_ulong size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_LOCAL_MEM_SIZE,
	                               sizeof(cl_ulong), &size, NULL),
	               "Error querying CL_DEVICE_LOCAL_MEM_SIZE");

	return size;
}

cl_ulong get_global_memory_size(int sequential_id)
{
	cl_ulong size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_GLOBAL_MEM_SIZE,
	                               sizeof(cl_ulong), &size, NULL),
	               "Error querying CL_DEVICE_GLOBAL_MEM_SIZE");

	return size;
}

size_t get_device_max_lws(int sequential_id)
{
	size_t max_group_size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_MAX_WORK_GROUP_SIZE,
	                               sizeof(max_group_size),
	                               &max_group_size, NULL),
	               "Error querying CL_DEVICE_MAX_WORK_GROUP_SIZE");

	return max_group_size;
}

cl_ulong get_max_mem_alloc_size(int sequential_id)
{
	cl_ulong max_alloc_size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_MAX_MEM_ALLOC_SIZE,
	                               sizeof(max_alloc_size),
	                               &max_alloc_size, NULL),
	               "Error querying CL_DEVICE_MAX_MEM_ALLOC_SIZE");

	return max_alloc_size;
}

size_t get_kernel_max_lws(int sequential_id, cl_kernel crypt_kernel)
{
	size_t max_group_size;

	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel,
	                                        devices[sequential_id],
	                                        CL_KERNEL_WORK_GROUP_SIZE,
	                                        sizeof(max_group_size),
	                                        &max_group_size, NULL), "Error querying clGetKernelWorkGroupInfo");

	return max_group_size;
}

cl_uint get_max_compute_units(int sequential_id)
{
	cl_uint size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_MAX_COMPUTE_UNITS,
	                               sizeof(cl_uint), &size, NULL),
	               "Error querying CL_DEVICE_MAX_COMPUTE_UNITS");

	return size;
}

size_t get_kernel_preferred_multiple(int sequential_id, cl_kernel crypt_kernel)
{
	size_t size;

	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel,
	                                        devices[sequential_id],
	                                        CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE,
	                                        sizeof(size), &size, NULL),
	               "Error while getting CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE");

	return size;
}

void get_compute_capability(int sequential_id, unsigned int *major,
                            unsigned int *minor)
{
	clGetDeviceInfo(devices[sequential_id],
	                CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV, sizeof(cl_uint), major, NULL);
	clGetDeviceInfo(devices[sequential_id],
	                CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV, sizeof(cl_uint), minor, NULL);
}

cl_uint get_processors_count(int sequential_id)
{
	cl_uint core_count = get_max_compute_units(sequential_id);
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_NAME,
	                               sizeof(dname), dname, NULL), "Error querying CL_DEVICE_NAME");

	ocl_device_list[sequential_id].cores_per_MP = 0;

	if (gpu_nvidia(device_info[sequential_id])) {
		unsigned int major = 0, minor = 0;

		get_compute_capability(sequential_id, &major, &minor);
		if (major == 1)         // 1.x Tesla
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 8);
		else if (major == 2 && minor == 0)  // 2.0 Fermi
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 32);
		else if (major == 2 && minor >= 1)  // 2.1 Fermi
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 48);
		else if (major == 3)    // 3.x Kepler
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 192);
		else if (major == 5)    // 5.x Maxwell
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 128);
		else if (major == 6)    // 6.x Pascal
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 128);
/*
 * Apple, VCL and some other environments don't expose get_compute_capability()
 * so we need this crap - which is incomplete.
 * http://en.wikipedia.org/wiki/Comparison_of_Nvidia_graphics_processing_units
 *
 * This will produce a *guessed* figure
 */

		// Pascal
		else if (strstr(dname, "GTX 10"))
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 128);
		// Maxwell
		else if (strstr(dname, "GTX 9") || strstr(dname, "GTX TITAN X"))
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 128);
		// Kepler
		else if (strstr(dname, "GT 6") || strstr(dname, "GTX 6") ||
		         strstr(dname, "GT 7") || strstr(dname, "GTX 7") ||
		         strstr(dname, "GT 8") || strstr(dname, "GTX 8") ||
		         strstr(dname, "GTX TITAN"))
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 192);
		// Fermi
		else if (strstr(dname, "GT 5") || strstr(dname, "GTX 5"))
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 48);
	} else if (gpu_amd(device_info[sequential_id])) {
		// 16 thread proc * 5 SP
		core_count *= (ocl_device_list[sequential_id].cores_per_MP = (16 *
		               ((amd_gcn(device_info[sequential_id]) ||
		                 amd_vliw4(device_info[sequential_id])) ? 4 : 5)));
	} else {
		// Nothing else known, we use the native vector width for integer
		cl_uint v_width;

		HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
		                               CL_DEVICE_NATIVE_VECTOR_WIDTH_INT,
		                               sizeof(v_width), &v_width, NULL),
		               "Error querying CL_DEVICE_MAX_CLOCK_FREQUENCY");
		core_count *= (ocl_device_list[sequential_id].cores_per_MP = v_width);
	}

	return core_count;
}

unsigned int opencl_speed_index(int sequential_id)
{
	cl_uint clock;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_MAX_CLOCK_FREQUENCY,
	                               sizeof(clock), &clock, NULL),
	               "Error querying CL_DEVICE_MAX_CLOCK_FREQUENCY");

	return clock * get_processors_count(sequential_id);
}

cl_uint get_processor_family(int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_NAME,
	                               sizeof(dname), dname, NULL), "Error querying CL_DEVICE_NAME");

	/* Workaround for MESA. */
	if (*dname)
		strlwr(&dname[1]);

	if gpu_amd
	(device_info[sequential_id]) {

		if ((strstr(dname, "Cedar") ||  //AMD Radeon VLIW5
		        strstr(dname, "Redwood") || strstr(dname, "Juniper")
		        || strstr(dname, "Cypress") || strstr(dname, "Hemlock")
		        || strstr(dname, "Caicos") ||   //AMD Radeon VLIW5 Gen 2
		        strstr(dname, "Turks") || strstr(dname, "Barts") ||
		        strstr(dname, "Wrestler")
		        || strstr(dname, "Ontario") || strstr(dname, "Zacate")
		        || strstr(dname, "Winterpark") || strstr(dname, "Beavercreek")
		        || strstr(dname, "Cayman") ||   //AMD Radeon VLIW4
		        strstr(dname, "Antilles") || strstr(dname, "Devastator")
		        || strstr(dname, "R7")  //AMD Radeon VLIW4
		    )) {

			if (strstr(dname, "Cayman") ||
			        strstr(dname, "Antilles") ||
			        strstr(dname, "Devastator") || strstr(dname, "R7"))
				return DEV_AMD_VLIW4;
			else
				return DEV_AMD_VLIW5;

		} else {

			if (strstr(dname, "Capeverde") || strstr(dname, "Malta") ||
			        strstr(dname, "Oland") || strstr(dname, "Hainan") ||
			        strstr(dname, "Pitcairn") || strstr(dname, "Tahiti"))
				return DEV_AMD_GCN_10; //AMD Radeon GCN 1.0

			else if (strstr(dname, "Bonaire") || strstr(dname, "Hawaii") ||
				strstr(dname, "Vesuvius") || strstr(dname, "Grenada"))
				return DEV_AMD_GCN_11; //AMD Radeon GCN 1.1

			else if (strstr(dname, "Tonga") || strstr(dname, "Antigua") ||
				strstr(dname, "Fiji"))
				return DEV_AMD_GCN_12; //AMD Radeon GCN 1.2
			 /*
			 * Graphics IP v6:
			 *   - Cape Verde, Hainan, Oland, Pitcairn, Tahiti
			 * Graphics IP v7:
			 *   - Bonaire, Havaii, Kalindi, Mullins, Spectre, Spooky
			 * Graphics IP v8:
			 *   - Iceland
			 */
			return DEV_UNKNOWN;
		}
	}
	return DEV_UNKNOWN;
}

int get_byte_addressable(int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_EXTENSIONS,
	                               sizeof(dname), dname, NULL),
	               "Error querying CL_DEVICE_EXTENSIONS");

	if (strstr(dname, "cl_khr_byte_addressable_store") == NULL)
		return DEV_NO_BYTE_ADDRESSABLE;

	return DEV_UNKNOWN;
}

int get_vendor_id(int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_VENDOR,
	                               sizeof(dname), dname, NULL), "Error querying CL_DEVICE_VENDOR");

	if (strstr(dname, "NVIDIA"))
		return DEV_NVIDIA;

	if (strstr(dname, "Intel"))
		return DEV_INTEL;

	if (strstr(dname, "Advanced Micro") ||
	        strstr(dname, "AMD") || strstr(dname, "ATI"))
		return DEV_AMD;

	return DEV_UNKNOWN;
}

int get_platform_vendor_id(int platform_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];
	cl_platform_id platform[MAX_PLATFORMS];
	cl_uint num_platforms;

	HANDLE_CLERROR(clGetPlatformIDs(MAX_PLATFORMS, platform,
	                                &num_platforms), "No OpenCL platform found");

	HANDLE_CLERROR(clGetPlatformInfo(platform[platform_id], CL_PLATFORM_NAME,
	                                 sizeof(dname), dname, NULL), "Error querying CL_PLATFORM_NAME");

	if (strstr(dname, "NVIDIA"))
		return DEV_NVIDIA;

	if (strstr(dname, "Apple"))
		return PLATFORM_APPLE;

	if (strstr(dname, "Intel"))
		return DEV_INTEL;

	if (strstr(dname, "Advanced Micro") ||
	        strstr(dname, "AMD") || strstr(dname, "ATI"))
		return DEV_AMD;

	if ((strstr(dname, "MESA")) || (strstr(dname, "Mesa")))
		return DEV_MESA;

	HANDLE_CLERROR(clGetPlatformInfo(platform[platform_id], CL_PLATFORM_VERSION,
	                                 sizeof(dname), dname, NULL), "Error querying CL_PLATFORM_VERSION");

	if ((strstr(dname, "MESA")) || (strstr(dname, "Mesa")))
		return DEV_MESA;

	return DEV_UNKNOWN;
}

int get_device_version(int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];
	unsigned int major, minor;

	clGetDeviceInfo(devices[sequential_id], CL_DEVICE_VERSION,
	                MAX_OCLINFO_STRING_LEN, dname, NULL);

	if (sscanf(dname, "OpenCL %u.%u", &major, &minor) == 2)
		return major * 100 + minor * 10;

	return DEV_UNKNOWN;
}

char *get_opencl_header_version()
{
#ifdef CL_VERSION_2_2
	return "2.2";
#elif CL_VERSION_2_1
	return "2.1";
#elif CL_VERSION_2_0
	return "2.0";
#elif CL_VERSION_1_2
	return "1.2";
#elif CL_VERSION_1_1
	return "1.1";
#elif CL_VERSION_1_0
	return "1.0";
#else
	return "Unknown";
#endif
}

char *get_error_name(cl_int cl_error)
{
	char *message;
	static char out[128];
	static char *err_small[] = {
		"CL_SUCCESS", "CL_DEVICE_NOT_FOUND", "CL_DEVICE_NOT_AVAILABLE",
		"CL_COMPILER_NOT_AVAILABLE",
		"CL_MEM_OBJECT_ALLOCATION_FAILURE", "CL_OUT_OF_RESOURCES",
		"CL_OUT_OF_HOST_MEMORY",
		"CL_PROFILING_INFO_NOT_AVAILABLE", "CL_MEM_COPY_OVERLAP",
		"CL_IMAGE_FORMAT_MISMATCH",
		"CL_IMAGE_FORMAT_NOT_SUPPORTED", "CL_BUILD_PROGRAM_FAILURE",
		"CL_MAP_FAILURE", "CL_MISALIGNED_SUB_BUFFER_OFFSET",
		"CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST",
		"CL_COMPILE_PROGRAM_FAILURE", "CL_LINKER_NOT_AVAILABLE",
		"CL_LINK_PROGRAM_FAILURE", "CL_DEVICE_PARTITION_FAILED",
		"CL_KERNEL_ARG_INFO_NOT_AVAILABLE"
	};
	static char *err_invalid[] = {
		"CL_INVALID_VALUE", "CL_INVALID_DEVICE_TYPE",
		"CL_INVALID_PLATFORM", "CL_INVALID_DEVICE",
		"CL_INVALID_CONTEXT", "CL_INVALID_QUEUE_PROPERTIES",
		"CL_INVALID_COMMAND_QUEUE", "CL_INVALID_HOST_PTR",
		"CL_INVALID_MEM_OBJECT", "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR",
		"CL_INVALID_IMAGE_SIZE", "CL_INVALID_SAMPLER",
		"CL_INVALID_BINARY", "CL_INVALID_BUILD_OPTIONS",
		"CL_INVALID_PROGRAM", "CL_INVALID_PROGRAM_EXECUTABLE",
		"CL_INVALID_KERNEL_NAME", "CL_INVALID_KERNEL_DEFINITION",
		"CL_INVALID_KERNEL", "CL_INVALID_ARG_INDEX",
		"CL_INVALID_ARG_VALUE", "CL_INVALID_ARG_SIZE",
		"CL_INVALID_KERNEL_ARGS", "CL_INVALID_WORK_DIMENSION",
		"CL_INVALID_WORK_GROUP_SIZE", "CL_INVALID_WORK_ITEM_SIZE",
		"CL_INVALID_GLOBAL_OFFSET", "CL_INVALID_EVENT_WAIT_LIST",
		"CL_INVALID_EVENT", "CL_INVALID_OPERATION",
		"CL_INVALID_GL_OBJECT", "CL_INVALID_BUFFER_SIZE",
		"CL_INVALID_MIP_LEVEL", "CL_INVALID_GLOBAL_WORK_SIZE",
		"CL_INVALID_PROPERTY", "CL_INVALID_IMAGE_DESCRIPTOR",
		"CL_INVALID_COMPILER_OPTIONS", "CL_INVALID_LINKER_OPTIONS",
		"CL_INVALID_DEVICE_PARTITION_COUNT"
	};

	if (cl_error <= 0 && cl_error >= -19)
		message = err_small[-cl_error];
	else if (cl_error <= -30 && cl_error >= -68)
		message = err_invalid[-cl_error - 30];
	else
		message = "UNKNOWN OPENCL ERROR";
	sprintf(out, "%s (%d)", message, cl_error);
	return out;
}

static char *human_format(size_t size)
{
	char pref[] = { ' ', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y' };
	int prefid = 0;
	static char ret[32];

	while (size > 1024) {
		size /= 1024;
		prefid++;
	}
	sprintf(ret, ""Zu"."Zu" %cB", size, (size % 1024) / 100, pref[prefid]);
	return ret;
}

/***
 * Despite of whatever the user uses as -dev=N, I will always list devices in
 * their natural order as defined by the OpenCL libraries.
 *
 * In order to be able to know everything about the device and list it obeying
 * its natural sequence (defined by hardware, PCI slots sequence, ...) is better
 * to scan all OpenCL stuff and list only when needed. Otherwise, I might need
 * to reorder first and then list.
 ***/
void opencl_list_devices(void)
{
	char dname[MAX_OCLINFO_STRING_LEN];
	size_t z_entries;
	cl_uint entries;
	cl_ulong long_entries;
	int i, j, sequence_nr = 0, err_type = 0, platform_in_use = -1;
	size_t p_size;
	int available_devices = 0;
	cl_int ret;
	cl_platform_id platform_list[MAX_PLATFORMS];
	cl_uint num_platforms, num_devices;

	/* Obtain a list of available platforms */
	ret = clGetPlatformIDs(MAX_PLATFORMS, platform_list, &num_platforms);

	if (!num_platforms)
		fprintf(stderr, "Error: No OpenCL-capable platforms were detected"
		        " by the installed OpenCL driver.\n");

        if (ret != CL_SUCCESS && options.verbosity > VERB_LEGACY)
		fprintf(stderr, "Throw clError: clGetPlatformIDs() = %d\n", ret);

	for (i = 0; i < num_platforms; i++) {
		platforms[i].platform = platform_list[i];
		ret = clGetDeviceIDs(platforms[i].platform, CL_DEVICE_TYPE_ALL,
		                     MAX_GPU_DEVICES, &devices[available_devices],
		                     &num_devices);

		if ((ret != CL_SUCCESS || num_devices < 1) &&
		     options.verbosity > VERB_LEGACY)
			fprintf(stderr, "No OpenCL devices was found on platform #%d"
			                 ", clGetDeviceIDs() = %d\n", i, ret);

		available_devices += num_devices;
		platforms[i].num_devices = num_devices;
	}

	if (!available_devices) {
		fprintf(stderr, "Error: No OpenCL-capable devices were detected"
		        " by the installed OpenCL driver.\n\n");
		return;
	}
	/* Initialize OpenCL environment */
	if (!getenv("_SKIP_OCL_INITIALIZATION"))
		opencl_preinit();

	for (i = 0; platforms[i].platform; i++) {

		/* Query devices for information */
		for (j = 0; j < platforms[i].num_devices; j++, sequence_nr++) {
			cl_device_local_mem_type memtype;
			cl_bool boolean;
			char *p;
			int ret, cpu;
			int fan, temp, util, cl, ml;

			if (!getenv("_SKIP_OCL_INITIALIZATION") &&
			   (!default_gpu_selected && !get_if_device_is_in_use(sequence_nr)))
				/* Nothing to do, skipping */
				continue;

			if (platform_in_use != i) {
				/* Now, dealing with different platform. */
				/* Obtain information about platform */
				clGetPlatformInfo(platforms[i].platform,
				                  CL_PLATFORM_NAME, sizeof(dname), dname, NULL);
				printf("Platform #%d name: %s, ", i, dname);
				clGetPlatformInfo(platforms[i].platform,
				                  CL_PLATFORM_VERSION, sizeof(dname), dname, NULL);
				printf("version: %s\n", dname);

				clGetPlatformInfo(platforms[i].platform,
				                  CL_PLATFORM_EXTENSIONS, sizeof(dname), dname, NULL);
				if (options.verbosity > VERB_LEGACY)
					printf("    Platform extensions:    %s\n", dname);

				/* Obtain a list of devices available */
				if (!platforms[i].num_devices)
					printf("%d devices found\n", platforms[i].num_devices);

				platform_in_use = i;
			}
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_NAME,
			                sizeof(dname), dname, NULL);
			p = dname;
			while (isspace(ARCH_INDEX(*p))) /* Intel quirk */
				p++;
			printf("    Device #%d (%d) name:     %s\n", j, sequence_nr, p);

			// Check if device seems to be working.
			if (!start_opencl_device(sequence_nr, &err_type)) {

				if (err_type == 1)
					printf("    Status:                 %s (%s)\n",
					       "Context creation error", get_error_name(ret_code));
				else
					printf("    Status:                 %s (%s)\n",
					       "Queue creation error", get_error_name(ret_code));
			}

			ret = clGetDeviceInfo(devices[sequence_nr],
			                      CL_DEVICE_BOARD_NAME_AMD, sizeof(dname), dname, NULL);
			if (ret == CL_SUCCESS && strlen(dname))
				printf("    Board name:             %s\n", dname);

			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_VENDOR,
			                sizeof(dname), dname, NULL);
			printf("    Device vendor:          %s\n", dname);
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_TYPE,
			                sizeof(cl_ulong), &long_entries, NULL);
			printf("    Device type:            ");
			cpu = (long_entries & CL_DEVICE_TYPE_CPU);
			if (cpu)
				printf("CPU ");
			if (long_entries & CL_DEVICE_TYPE_GPU)
				printf("GPU ");
			if (long_entries & CL_DEVICE_TYPE_ACCELERATOR)
				printf("Accelerator ");
			if (long_entries & CL_DEVICE_TYPE_DEFAULT)
				printf("Default ");
			if (long_entries & ~(CL_DEVICE_TYPE_DEFAULT |
			                     CL_DEVICE_TYPE_ACCELERATOR |
			                     CL_DEVICE_TYPE_GPU | CL_DEVICE_TYPE_CPU))
				printf("Unknown ");
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_ENDIAN_LITTLE, sizeof(cl_bool), &boolean, NULL);
			printf("(%s)\n", boolean == CL_TRUE ? "LE" : "BE");
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_VERSION,
			                sizeof(dname), dname, NULL);
			printf("    Device version:         %s\n", dname);
			printf("    Driver version:         %s\n",
			       opencl_driver_info(sequence_nr));

			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_NATIVE_VECTOR_WIDTH_CHAR,
			                sizeof(cl_uint), &entries, NULL);
			printf("    Native vector widths:   char %d, ", entries);
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_NATIVE_VECTOR_WIDTH_SHORT,
			                sizeof(cl_uint), &entries, NULL);
			printf("short %d, ", entries);
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_NATIVE_VECTOR_WIDTH_INT,
			                sizeof(cl_uint), &entries, NULL);
			printf("int %d, ", entries);
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_NATIVE_VECTOR_WIDTH_LONG,
			                sizeof(cl_uint), &entries, NULL);
			printf("long %d\n", entries);

			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_PREFERRED_VECTOR_WIDTH_CHAR,
			                sizeof(cl_uint), &entries, NULL);
			printf("    Preferred vector width: char %d, ", entries);
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_PREFERRED_VECTOR_WIDTH_SHORT,
			                sizeof(cl_uint), &entries, NULL);
			printf("short %d, ", entries);
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT,
			                sizeof(cl_uint), &entries, NULL);
			printf("int %d, ", entries);
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_PREFERRED_VECTOR_WIDTH_LONG,
			                sizeof(cl_uint), &entries, NULL);
			printf("long %d\n", entries);

			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_GLOBAL_MEM_SIZE,
			                sizeof(cl_ulong), &long_entries, NULL);
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_ERROR_CORRECTION_SUPPORT,
			                sizeof(cl_bool), &boolean, NULL);
			printf("    Global Memory:          %s%s\n",
			       human_format((unsigned long long)long_entries),
			       boolean == CL_TRUE ? " (ECC)" : "");

			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_EXTENSIONS, sizeof(dname), dname, NULL);
			if (options.verbosity > VERB_LEGACY)
				printf("    Device extensions:      %s\n", dname);

			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_GLOBAL_MEM_CACHE_SIZE,
			                sizeof(cl_ulong), &long_entries, NULL);
			if (long_entries)
				printf("    Global Memory Cache:    %s\n",
				       human_format((unsigned long long)long_entries)
				      );
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_LOCAL_MEM_SIZE,
			                sizeof(cl_ulong), &long_entries, NULL);
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_LOCAL_MEM_TYPE,
			                sizeof(cl_device_local_mem_type), &memtype, NULL);
			printf("    Local Memory:           %s (%s)\n",
			       human_format((unsigned long long)long_entries),
			       memtype == CL_LOCAL ? "Local" : "Global");
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_MAX_MEM_ALLOC_SIZE,
			                sizeof(long_entries), &long_entries, NULL);
			printf("    Max memory alloc. size: %s\n",
			       human_format(long_entries));
			ret = clGetDeviceInfo(devices[sequence_nr],
			                      CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(cl_int), &entries, NULL);
			if (ret == CL_SUCCESS && entries)
				printf("    Max clock (MHz):        %u\n", entries);
			ret = clGetDeviceInfo(devices[sequence_nr],
			                      CL_DEVICE_PROFILING_TIMER_RESOLUTION,
			                      sizeof(size_t), &z_entries, NULL);
			if (ret == CL_SUCCESS && z_entries)
				printf("    Profiling timer res.:   "Zu" ns\n", z_entries);
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(size_t), &p_size, NULL);
			printf("    Max Work Group Size:    %d\n", (int)p_size);
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cl_uint), &entries, NULL);
			printf("    Parallel compute cores: %d\n", entries);

			long_entries = get_processors_count(sequence_nr);
			if (!cpu && ocl_device_list[sequence_nr].cores_per_MP > 1)
				printf("    %s      "LLu" "
				       " (%d x %d)\n",
					gpu_nvidia(device_info[sequence_nr]) ? "CUDA cores:       " : "Stream processors:",
				       (unsigned long long)long_entries,
				       entries, ocl_device_list[sequence_nr].cores_per_MP);
			printf("    Speed index:            %u\n",
			       opencl_speed_index(sequence_nr));

			ret = clGetDeviceInfo(devices[sequence_nr],
			                      CL_DEVICE_SIMD_WIDTH_AMD, sizeof(cl_uint),
			                      &long_entries, NULL);
			if (ret == CL_SUCCESS)
				printf("    SIMD width:             "LLu"\n",
				       (unsigned long long)long_entries);

			ret = clGetDeviceInfo(devices[sequence_nr],
			                      CL_DEVICE_WAVEFRONT_WIDTH_AMD,
			                      sizeof(cl_uint), &long_entries, NULL);
			if (ret == CL_SUCCESS)
				printf("    Wavefront width:        "LLu"\n",
				       (unsigned long long)long_entries);

			ret = clGetDeviceInfo(devices[sequence_nr],
			                      CL_DEVICE_WARP_SIZE_NV, sizeof(cl_uint),
			                      &long_entries, NULL);
			if (ret == CL_SUCCESS)
				printf("    Warp size:              "LLu"\n",
				       (unsigned long long)long_entries);

			ret = clGetDeviceInfo(devices[sequence_nr],
			                      CL_DEVICE_REGISTERS_PER_BLOCK_NV,
			                      sizeof(cl_uint), &long_entries, NULL);
			if (ret == CL_SUCCESS)
				printf("    Max. GPRs/work-group:   "LLu"\n",
				       (unsigned long long)long_entries);

			if (gpu_nvidia(device_info[sequence_nr])) {
				unsigned int major = 0, minor = 0;

				get_compute_capability(sequence_nr, &major, &minor);
				if (major && minor)
					printf("    Compute capability:     %u.%u "
					       "(sm_%u%u)\n", major, minor, major, minor);
			}
			ret = clGetDeviceInfo(devices[sequence_nr],
			                      CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV,
			                      sizeof(cl_bool), &boolean, NULL);
			if (ret == CL_SUCCESS)
				printf("    Kernel exec. timeout:   %s\n",
				       boolean ? "yes" : "no");

			fan = temp = util = cl = ml = -1;
#if HAVE_LIBDL
			if (nvml_lib && gpu_nvidia(device_info[sequence_nr]) &&
			    id2nvml(ocl_device_list[sequence_nr].pci_info) >= 0) {
				printf("    NVML id:                %d\n",
				       id2nvml(ocl_device_list[sequence_nr].pci_info));
				nvidia_get_temp(id2nvml(ocl_device_list[sequence_nr].pci_info),
				                &temp, &fan, &util, &cl, &ml);
			} else if (adl_lib && gpu_amd(device_info[sequence_nr])) {
				printf("    ADL:                    Overdrive%d, device id %d\n",
				       adl2od[id2adl(ocl_device_list[sequence_nr].pci_info)],
				       id2adl(ocl_device_list[sequence_nr].pci_info));
				amd_get_temp(id2adl(ocl_device_list[sequence_nr].pci_info),
				             &temp, &fan, &util, &cl, &ml);
			}
#endif
			if (ocl_device_list[sequence_nr].pci_info.bus >= 0) {
				printf("    PCI device topology:    %s\n",
				       ocl_device_list[sequence_nr].pci_info.busId);
			}
			if (cl >= 0)
				printf("    PCI lanes:              %d/%d\n", cl, ml);
			if (fan >= 0)
				printf("    Fan speed:              %u%%\n", fan);
			if (temp >= 0)
				printf("    Temperature:            %u%sC\n",
				       temp, gpu_degree_sign);
			if (util >= 0)
				printf("    Utilization:            %u%%\n", util);
			else if (temp >= 0)
				printf("    Utilization:            n/a\n");
			puts("");
		}
	}
	return;
}

#undef LOG_SIZE
#undef SRC_SIZE
#endif

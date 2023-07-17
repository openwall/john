/*
 * This file is part of John the Ripper password cracker.
 *
 * Common OpenCL functions.
 *
 * This software is
 * Copyright (c) 2010-2012 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2010-2013 Lukas Odzioba <ukasz@openwall.net>
 * Copyright (c) 2010-2019 magnum
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
#define NEED_OS_FORK
#include "os.h"

#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

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
#include "opencl_common.h"
#include "mask_ext.h"
#include "dyna_salt.h"
#include "signals.h"
#include "recovery.h"
#include "status.h"
#include "john.h"
#include "md4.h"
#include "misc.h"
#include "john_mpi.h"
#include "timer.h"

/* Set this to eg. 3 for some added debug and retry stuff */
#define RACE_CONDITION_DEBUG 0

#define LOG_SIZE 1024*16

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
int default_device_selected;
int ocl_autotune_running;
int ocl_always_show_ws;
size_t ocl_max_lws;

static char opencl_log[LOG_SIZE];
static int opencl_initialized;
int opencl_unavailable;
int opencl_avoid_busy_wait[MAX_GPU_DEVICES];

static void load_device_info(int sequential_id);
static char* get_device_capability(int sequential_id);

// Used by auto-tuning to decide how GWS should changed between trials.
extern int autotune_get_next_gws_size(size_t num, int step, int startup,
                                      int default_value);
extern int autotune_get_prev_gws_size(size_t num, int step);

// Settings to use for auto-tuning.
static int buffer_size;
static int default_value;
static int hash_loops;
static int duration_time = 0;
static const char **warnings;
static int *split_events;
static int main_opencl_event;
static struct fmt_main *self;
static void (*create_clobj)(size_t gws, struct fmt_main *self);
static void (*release_clobj)(void);
static char fmt_base_name[128];
static size_t gws_limit;
static int printed_mask;
struct db_main *ocl_autotune_db;
static struct db_salt *autotune_salts;
int autotune_real_db;

typedef struct {
	cl_platform_id platform;
	int num_devices;
} cl_platform;
static cl_platform platforms[MAX_PLATFORMS + 1];

cl_device_id devices[MAX_GPU_DEVICES + 1];
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
	if (!ocl_autotune_running && !bench_or_test_running) {
#if !OS_TIMER
		sig_timer_emu_tick();
#endif
		if (event_pending) {
			if (event_save) {
				event_save = 0;
				rec_save();
			}

			if (event_help)
				sig_help();

			if (event_status)
				status_print(0);

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

/* Get the number of available devices (all the OpenCL devices) */
int get_number_of_available_devices()
{
	int total = 0, i = 0;

	while (platforms[i].platform)
		total += platforms[i++].num_devices;

	return total;
}

/*
 * Get the total number of devices that were requested (do not count duplicates)
 * --device=2,2 result that "one" device is really in use;
 */
int get_number_of_devices_in_use()
{
	int i = 0;

	while (engaged_devices[i] != DEV_LIST_END)
		i++;

	return i;
}

/*
 * Get the total number of requested devices (count duplicates)
 * --device=2,2 result that "two" devices will be used. E.g., to split tasks;
 */
int get_number_of_requested_devices()
{
	int i = 0;

	while (requested_devices[i] != DEV_LIST_END)
		i++;

	return i;
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

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DRIVER_VERSION,
		sizeof(dname), dname, NULL), "clGetDeviceInfo for CL_DRIVER_VERSION");

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
	static char buf[64 + MAX_OCLINFO_STRING_LEN];
	char dname[MAX_OCLINFO_STRING_LEN], tmp[sizeof(buf)], set[64];
	static char output[sizeof(tmp) + sizeof(dname)];
	char *name, *recommendation = NULL;
	int major = 0, minor = 0, conf_major = 0, conf_minor = 0, found;
	struct cfg_list *list;
	struct cfg_line *line;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DRIVER_VERSION,
		sizeof(dname), dname, NULL), "clGetDeviceInfo for CL_DRIVER_VERSION");

	opencl_driver_value(sequential_id, &major, &minor);
	name = buf;

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

	if (gpu_amd(device_info[sequential_id]) &&
	    get_platform_vendor_id(get_platform_id(sequential_id)) == DEV_AMD) {

		if (major < 1912)
			snprintf(buf, sizeof(buf), "%s - Catalyst %s", dname, name);
		else if (major < 2500)
			snprintf(buf, sizeof(buf), "%s - Crimson %s", dname, name);
		else
			snprintf(buf, sizeof(buf), "%s - AMDGPU-Pro %s", dname, name);
		snprintf(tmp, sizeof(tmp), "%s", buf);
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
	snprintf(output, sizeof(output), "%s%s", tmp, dname);

	return output;
}

static char *ns2string(cl_ulong nanosec)
{
	return human_prefix_small(nanosec / 1E9);
}

static char *ms2string(int millisec)
{
	return human_prefix_small(millisec / 1E3);
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
		if (sequential_id == engaged_devices[i])
			found = 1;
	}
	return found;
}

/*
 * Load information about all platforms and devices available in the
 * running system
 */
static void load_opencl_environment()
{
	cl_platform_id platform_list[MAX_PLATFORMS];
	cl_uint num_platforms, device_pos = 0;
	int ret, i;

	/* Find OpenCL enabled devices. We ignore error here, in case
	 * there is no platform and we'd like to run a non-OpenCL format. */
	ret = clGetPlatformIDs(MAX_PLATFORMS, platform_list, &num_platforms);

	if (ret != CL_SUCCESS)
		num_platforms = 0;

	if (num_platforms < 1 && options.verbosity > VERB_LEGACY)
		fprintf(stderr, "%u: No OpenCL platforms were found: %s\n",
		        NODE, get_error_name(ret));

	for (i = 0; i < num_platforms; i++) {
		cl_uint num_devices;

		// It is possible to have a platform without any devices
		// Ignore error here too on purpose.
		ret = clGetDeviceIDs(platform_list[i], CL_DEVICE_TYPE_ALL,
			MAX_GPU_DEVICES - device_pos, /* avoid buffer overrun */
			&devices[device_pos], &num_devices);
		if (ret != CL_SUCCESS)
			num_devices = 0;

		if (num_devices < 1 && options.verbosity > VERB_LEGACY)
			fprintf(stderr,
			        "%u: No OpenCL devices were found on platform #%d: %s\n",
			        NODE, i, get_error_name(ret));

		// Save platform and devices information
		platforms[i].platform = platform_list[i];
		platforms[i].num_devices = num_devices;

		// Point to the end of the list
		device_pos += num_devices;

#ifdef OCL_DEBUG
	{
		char opencl_data[LOG_SIZE];

		SOFT_CLERROR(clGetPlatformInfo(platform_list[i],
			CL_PLATFORM_NAME, sizeof(opencl_data), opencl_data, NULL),
			"clGetPlatformInfo for CL_PLATFORM_NAME");

		fprintf(stderr, "%u: OpenCL platform %d: %s, %d device(s).\n",
		        NODE, i, opencl_data, num_devices);
	}
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

	if (gpu_amd(device_info[sequential_id]) ||
	    cpu_amd(device_info[sequential_id])) {
		cl_device_topology_amd topo;

		ret = clGetDeviceInfo(devices[sequential_id],
			CL_DEVICE_TOPOLOGY_AMD, sizeof(topo), &topo, NULL);

		if (ret == CL_SUCCESS) {
			hardware_info->bus = topo.pcie.bus & 0xff;
			hardware_info->device = topo.pcie.device & 0xff;
			hardware_info->function = topo.pcie.function & 0xff;
		} else
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
	} else
		return CL_SUCCESS;

	sprintf(hardware_info->busId, "%02x:%02x.%x", hardware_info->bus,
	        hardware_info->device, hardware_info->function);
	return CL_SUCCESS;
}

/*
 * Initialize an OpenCL device:
 * - create context and queue;
 * - get bus and map to monitoring stuff;
 */
static int start_opencl_device(int sequential_id, int *err_type)
{
	cl_context_properties properties[3];
	char opencl_data[LOG_SIZE];
	int retry = 0;

	// Get the detailed information about the device
	// (populate device_info[d] bitfield).
	load_device_info(sequential_id);

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
	               "clGetDeviceInfo for DEVICE_NAME");

	max_group_size = get_device_max_lws(sequential_id);

	do {
		// Get the platform properties
		properties[0] = CL_CONTEXT_PLATFORM;
		properties[1] = (cl_context_properties)
			platforms[get_platform_id(sequential_id)].platform;
		properties[2] = 0;

		// Setup context and queue
		context[sequential_id] = clCreateContext(properties, 1,
			&devices[sequential_id], NULL, NULL, &ret_code);

		if (ret_code != CL_SUCCESS) {
			fprintf(stderr, "%u: Error creating context for device %d "
			        "(%d:%d): %s, %s\n",
			        NODE, sequential_id + 1,
			        get_platform_id(sequential_id),
			        get_device_id(sequential_id), get_error_name(ret_code),
			        retry < RACE_CONDITION_DEBUG ? "retrying" : "giving up");
			if (++retry > RACE_CONDITION_DEBUG)
				error();
			usleep((retry + NODE) * 100);
		}
	} while (ret_code != CL_SUCCESS);

	retry = 0;
	do {
		queue[sequential_id] = clCreateCommandQueue(context[sequential_id],
		                       devices[sequential_id], 0, &ret_code);

		if (ret_code != CL_SUCCESS) {
			fprintf(stderr, "%u: Error creating command queue for "
			        "device %d (%d:%d): %s, %s\n", NODE,
			        sequential_id + 1, get_platform_id(sequential_id),
			        get_device_id(sequential_id), get_error_name(ret_code),
			        retry < RACE_CONDITION_DEBUG ? "retrying" : "giving up");
			if (++retry > RACE_CONDITION_DEBUG)
				error();
			usleep((retry + NODE) * 100);
		}
	} while (ret_code != CL_SUCCESS);

#ifdef OCL_DEBUG
	fprintf(stderr, "  Device %d: %s\n", sequential_id + 1, opencl_data);
#endif

	// Success.
	return 1;
}

/* Add one requested OpenCL device to the list of the requested devices
 * - it only adds a device that is working properly;
 * - so, the device is initialized inside the routine;
 */
static void add_device_to_list(int sequential_id)
{
	int i = 0, found;

	found = get_if_device_is_in_use(sequential_id);

	if (found < 0) {
#if HAVE_MPI
		if (mpi_p > 1)
			fprintf(stderr, "%u@%s: ", mpi_id + 1, mpi_name);
#elif OS_FORK
		if (options.fork)
			fprintf(stderr, "%u: ", options.node_min);
#endif
		fprintf(stderr, "Error: --device must be between 1 and %d "
		        "(the number of devices available).\n",
		        get_number_of_available_devices());
		error();
	}

	if (found == 0) {
		// Only requested and working devices should be started.
		if (! start_opencl_device(sequential_id, &i)) {
#if HAVE_MPI
			if (mpi_p > 1)
				fprintf(stderr, "%u@%s: ", mpi_id + 1, mpi_name);
#elif OS_FORK
			if (options.fork)
				fprintf(stderr, "%u: ", options.node_min);
#endif
			fprintf(stderr, "Device id %d not working correctly,"
			        " skipping.\n", sequential_id + 1);
			return;
		}
		engaged_devices[get_number_of_devices_in_use() + 1] = DEV_LIST_END;
		engaged_devices[get_number_of_devices_in_use()] = sequential_id;
	}
	// The full list of requested devices.
	requested_devices[get_number_of_requested_devices() + 1] = DEV_LIST_END;
	requested_devices[get_number_of_requested_devices()] = sequential_id;
}

/* Used below (inside add_device_type routine) to sort devices */
typedef struct {
	int index;
	cl_device_id ID;
	unsigned int value;
} speed_sort_t;

/* Used below (inside add_device_type routine) to sort devices */
static int comparator(const void *p1, const void *p2)
{
	const speed_sort_t *c1 = (const speed_sort_t *)p1;
	const speed_sort_t *c2 = (const speed_sort_t *)p2;
	int diff = (int)c2->value - (int)c1->value;
	if (diff)
		return diff;
	return c1->index - c2->index;
}

/* Add groups of devices to requested OpenCL devices list */
static void add_device_type(cl_ulong device_type, int top)
{
	int i, j, sequence_nr = 0;
	int found = 0;
	speed_sort_t dev[MAX_GPU_DEVICES];

	// Get all devices of requested type.
	for (i = 0; platforms[i].platform; i++) {
		cl_device_id devices[MAX_GPU_DEVICES];
		cl_uint device_num = 0;

		if (clGetDeviceIDs(platforms[i].platform, CL_DEVICE_TYPE_ALL,
				MAX_GPU_DEVICES, devices, &device_num) == CL_SUCCESS) {
			// Sort devices by speed
			for (j = 0; j < device_num && sequence_nr < MAX_GPU_DEVICES;
			     j++, sequence_nr++) {
				load_device_info(sequence_nr);
				dev[sequence_nr].index = sequence_nr;
				dev[sequence_nr].ID = devices[j];
				dev[sequence_nr].value = opencl_speed_index(sequence_nr);
			}
		}
	}

	// If there is something to sort, do it.
	if (sequence_nr > 1)
		qsort(dev, sequence_nr, sizeof(dev[0]), comparator);

	// Add the devices sorted by speed devices
	for (j = 0; j < sequence_nr; j++) {
		cl_ulong long_entries = 0;

		if (clGetDeviceInfo(dev[j].ID, CL_DEVICE_TYPE,
			sizeof(cl_ulong), &long_entries, NULL) == CL_SUCCESS) {
			if (long_entries & device_type) {
				found++;
				add_device_to_list(dev[j].index);

				// Only the best should be added
				if (top)
					break;
			}
		}
	}
	// If testing preferred devices, do not warn or fail
	if (!found && !default_device_selected)
		error_msg("No OpenCL device of that type found\n");
}

/* Build a list of the requested OpenCL devices */
static void build_device_list(const char *device_list[MAX_GPU_DEVICES])
{
	int n = 0;

	while (device_list[n] && n < MAX_GPU_DEVICES) {
		int len = MAX(strlen(device_list[n]), 3);
		/* Add devices in the preferable order: gpu,
		 * accelerator, and cpu. */
		cl_device_type trial_list[] = {
			CL_DEVICE_TYPE_GPU, CL_DEVICE_TYPE_ACCELERATOR,
			CL_DEVICE_TYPE_CPU, CL_DEVICE_TYPE_DEFAULT
		};

		if (!strcmp(device_list[n], "all"))
			add_device_type(CL_DEVICE_TYPE_ALL, 0);
		else if (!strcmp(device_list[n], "cpu"))
			add_device_type(CL_DEVICE_TYPE_CPU, 0);
		else if (!strcmp(device_list[n], "gpu"))
			add_device_type(CL_DEVICE_TYPE_GPU, 0);
		else if (!strncmp(device_list[n], "accelerator", len))
			add_device_type(CL_DEVICE_TYPE_ACCELERATOR, 0);
		else if (!strncmp(device_list[n], "best", len)) {
			int i = 0, top = (options.fork ? 0 : 1);

			/* Set a flag that JtR has changed the value of --devices. */
			default_device_selected = 1;
			if (top)
				default_gpu_selected = 1;

			do
				add_device_type(trial_list[i++], top);
			while (get_number_of_devices_in_use() == 0 &&
			         trial_list[i] != CL_DEVICE_TYPE_DEFAULT);
		}
		else if (!isdigit(ARCH_INDEX(device_list[n][0]))) {
			fprintf(stderr, "Error: --device must be numerical, "
			        "or one of \"all\", \"cpu\", \"gpu\" and\n"
			        "\"acc[elerator]\".\n");
			error();
		} else if (device_list[n][0] == '0') {
			fprintf(stderr, "Error: --device must be between 1 and %d "
			          "(the number of devices available).\n",
			          get_number_of_available_devices());
			error();
		} else
			add_device_to_list(atoi(device_list[n]) - 1);
		n++;
	}
}

/*
 * Load the OpenCL environment
 * - fill in the "existing" devices list (devices[] variable) and;
 * - fill in the "in use" devices list (engaged_devices[] variable);
 *   - device was initialized;
 *   - do not count duplicates;
 *     --device=2,2 result that "one" device is really in use;
 * - fill in the "all requested" devices list (requested_devices[] variable);
 *   - device was initialized;
 *   - count duplicates;
 *     --device=2,2 result that "two" devices will be used, e.g., to split tasks;
 *
 * Warn if no device is found
 * On MPI, hide devices from other instances
 */
void opencl_load_environment(void)
{
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
		int i;
		const char *cmdline_devices[MAX_GPU_DEVICES];

		nvidia_probe();
		amd_probe();

		// Initialize OpenCL global control variables
		cmdline_devices[0] = NULL;
		engaged_devices[0] = DEV_LIST_END;
		requested_devices[0] = DEV_LIST_END;

		for (i = 0; i < MAX_GPU_DEVICES; i++) {
			context[i] = NULL;
			queue[i] = NULL;
		}

		// Read the GPU temperature setting to abort
		if ((gpu_temp_limit = cfg_get_int(SECTION_OPTIONS, SUBSECTION_GPU,
		                                  "AbortTemperature")) < 0)
			gpu_temp_limit = 95;
		if ((cool_gpu_down = cfg_get_int(SECTION_OPTIONS, SUBSECTION_GPU,
		                                 "SleepOnTemperature")) < 0)
			cool_gpu_down = 1;

		// Load information about available platforms and devices
		load_opencl_environment();

		// Ensure that there is at least one OpenCL device available
		if (get_number_of_available_devices() == 0) {
			fprintf(stderr, "No OpenCL devices found\n");
			if (benchmark_running) {
				opencl_initialized = 1;
				opencl_unavailable = 1;
				return;
			}
			error();
		}

		// Get the "--device" list requested by the user
		{
			int n = 0;
			struct list_entry *current;

			if ((current = options.acc_devices->head)) {
				do {
					cmdline_devices[n++] = current->data;
				} while ((current = current->next) && n < MAX_GPU_DEVICES);

				cmdline_devices[n] = NULL;
			} else
				gpu_id = NO_GPU;
		}

		// If none selected, read the "--device" from the configuration file
		if (!options.acc_devices->head && gpu_id <= NO_GPU) {
			const char *devcfg;

			if ((devcfg = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL,
			                            "Device")) && *devcfg) {
				cmdline_devices[0] = devcfg;
				cmdline_devices[1] = NULL;
			}
		}

		// No "--device" requested. Pick the most powerful GPU as the default one.
		if (!cmdline_devices[0]) {
			cmdline_devices[0] = "best";
			cmdline_devices[1] = NULL;
		}

		// Build the list of requested (and working) OpenCL devices
		build_device_list(cmdline_devices);

		// No working OpenCL device was found
		if (get_number_of_devices_in_use() == 0) {
			fprintf(stderr, "No OpenCL devices found\n");
			error();
		}
#if OS_FORK
		// Poor man's multi-device support.
		if ((options.fork ? options.fork : 1) > 1 && options.acc_devices->count) {
			// Pick device to use for this node
			gpu_id = requested_devices[(options.node_min - 1) %
			    get_number_of_requested_devices()];

			// Hide any other devices from list
			engaged_devices[0] = gpu_id;
			engaged_devices[1] = DEV_LIST_END;
		} else
#endif

#ifdef HAVE_MPI
		// Poor man's multi-device support.
		if (mpi_p > 1 && mpi_p_local != 1) {
			// Pick device to use for this node
			gpu_id = engaged_devices[mpi_id % get_number_of_devices_in_use()];

			// Hide any other devices from list
			engaged_devices[0] = gpu_id;
			engaged_devices[1] = DEV_LIST_END;
		} else
#endif
			gpu_id = engaged_devices[0];
		platform_id = get_platform_id(gpu_id);

		opencl_initialized = 1;
	}
}

/*
 * Get the device preferred vector width.  The --force-scalar option, or
 * john.conf ForceScalar boolean, is taken care of in john.c and converted
 * to "options.v_width = 1".
 */
unsigned int opencl_get_vector_width(int sequential_id, int size)
{
	/* --force-vector-width=N */
	if (options.v_width) {
		ocl_v_width = options.v_width;
	} else {
		cl_uint v_width = 0;

		// If OpenCL has not yet been loaded, load it now
		opencl_load_environment();

		/* OK, we supply the real figure */
		switch (size) {
		case sizeof(cl_char):
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
				CL_DEVICE_PREFERRED_VECTOR_WIDTH_CHAR,
				sizeof(v_width), &v_width, NULL),
			               "clGetDeviceInfo for char vector width");
			break;
		case sizeof(cl_short):
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
				CL_DEVICE_PREFERRED_VECTOR_WIDTH_SHORT,
				sizeof(v_width), &v_width, NULL),
			               "clGetDeviceInfo for short vector width");
			break;
		case sizeof(cl_int):
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
				CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT,
				sizeof(v_width), &v_width, NULL),
			               "clGetDeviceInfo for int vector width");
			break;
		case sizeof(cl_long):
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
				CL_DEVICE_PREFERRED_VECTOR_WIDTH_LONG,
				sizeof(v_width), &v_width, NULL),
			               "clGetDeviceInfo for long vector width");
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
		if (queue[engaged_devices[i]])
			HANDLE_CLERROR(clReleaseCommandQueue(queue[engaged_devices[i]]),
			               "clReleaseCommandQueue");
		queue[engaged_devices[i]] = NULL;
		if (context[engaged_devices[i]])
			HANDLE_CLERROR(clReleaseContext(context[engaged_devices[i]]),
			               "clReleaseContext");
		context[engaged_devices[i]] = NULL;
		program[engaged_devices[i]] = NULL;
	}

	/* Reset in case we load another format after this */
	local_work_size = global_work_size = duration_time = 0;
	ocl_max_lws = 0;
	ocl_v_width = 1;
	fmt_base_name[0] = 0;
	opencl_initialized = 0;
	crypt_kernel = NULL;

	engaged_devices[0] = engaged_devices[1] = DEV_LIST_END;
}

static char *opencl_get_config_name(const char *format, const char *config_name)
{
	static char config_item[256];

	snprintf(config_item, sizeof(config_item), "%s%s", format, config_name);
	return config_item;
}

void opencl_get_user_preferences(const char *format)
{
	char *tmp_value;

	if (format) {
		snprintf(fmt_base_name, sizeof(fmt_base_name), "%s", format);
		if ((tmp_value = strrchr(fmt_base_name, (int)'-')))
			*tmp_value = 0;
		strlwr(fmt_base_name);
	} else
		fmt_base_name[0] = 0;

	if (format && (tmp_value = (char*)cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL,
			opencl_get_config_name(fmt_base_name, LWS_CONFIG_NAME))))
		local_work_size = atoi(tmp_value);

	if (options.lws)
		local_work_size = options.lws;
	else if ((tmp_value = getenv("LWS")))
		local_work_size = atoi(tmp_value);

	if (format && (tmp_value = (char*)cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL,
			opencl_get_config_name(fmt_base_name, GWS_CONFIG_NAME))))
		global_work_size = atoi(tmp_value);

	if (options.gws)
		global_work_size = options.gws;
	else if ((tmp_value = getenv("GWS")))
		global_work_size = atoi(tmp_value);

	if (local_work_size)
		// Ensure a valid multiple is used.
		global_work_size = GET_MULTIPLE_OR_ZERO(global_work_size,
		                                        local_work_size);

	if (format && (tmp_value = (char*)cfg_get_param(SECTION_OPTIONS,
		SUBSECTION_OPENCL, opencl_get_config_name(fmt_base_name,
		DUR_CONFIG_NAME))) && *tmp_value)
		duration_time = atoi(tmp_value);
	else if ((tmp_value = (char*)cfg_get_param(SECTION_OPTIONS,
		SUBSECTION_OPENCL, "Global" DUR_CONFIG_NAME)) && *tmp_value)
		duration_time = atoi(tmp_value);
}

void opencl_get_sane_lws_gws_values()
{
	if (self_test_running) {
		local_work_size = 7;
		global_work_size = 49;
	}

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
	               "clGetDeviceInfo for DEVICE_NAME");

	return device_name;
}

/* Print and log information about an OpenCL devide in use */
static void print_device_info(int sequential_id)
{
	static int printed[MAX_GPU_DEVICES];
	char device_name[MAX_OCLINFO_STRING_LEN];
	char board_name[LOG_SIZE] = "";
	cl_int ret_code;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_NAME,
	                               sizeof(device_name), device_name, NULL),
	               "clGetDeviceInfo for DEVICE_NAME");

	ret_code = clGetDeviceInfo(devices[sequential_id],
		CL_DEVICE_BOARD_NAME_AMD, sizeof(opencl_log), opencl_log, NULL);

	if (ret_code == CL_SUCCESS) {
		char *p = ltrim(rtrim(opencl_log));

		if  (strlen(p))
			sprintf(board_name, " [%s]", p);
	}

	if (options.verbosity > 1 && !printed[sequential_id]++)
		fprintf(stderr, "Device %d%s%s: %s%s\n",
		        sequential_id + 1,
#if HAVE_MPI
		        "@", mpi_name,
#else
		        "", "",
#endif
		        device_name, board_name);
	log_event("Device %d: %s%s", sequential_id + 1, device_name, board_name);
}

static char *get_build_opts(int sequential_id, const char *opts)
{
	char *build_opts = mem_alloc(LINE_BUFFER_SIZE);
	const char *global_opts;

	if (!(global_opts = getenv("OPENCLBUILDOPTIONS")))
		if (!(global_opts = cfg_get_param(SECTION_OPTIONS,
		    SUBSECTION_OPENCL, "GlobalBuildOpts")))
			global_opts = OPENCLBUILDOPTIONS;

	snprintf(build_opts, LINE_BUFFER_SIZE,
	         "-I opencl %s %s%s%s%s%s%d %s%d %s -D_OPENCL_COMPILER %s",
	        global_opts,
	        get_device_version(sequential_id) >= 200 ? "-cl-std=CL1.2 " : "",
#ifdef __APPLE__
	        "-D__OS_X__ ",
#else
	        (options.verbosity >= VERB_MAX &&
	         gpu_nvidia(device_info[sequential_id])) ?
	         "-cl-nv-verbose " : "",
#endif
	        get_platform_vendor_id(get_platform_id(sequential_id)) ==
	         PLATFORM_MESA ? "-D__MESA__ " :
	        get_platform_vendor_id(get_platform_id(sequential_id)) ==
	         PLATFORM_POCL ? "-D__POCL__ " :
	        get_platform_vendor_id(get_platform_id(sequential_id)) ==
	         PLATFORM_BEIGNET ?
	         "-D__BEIGNET__ " :
	        get_device_capability(sequential_id),
	        get_device_type(sequential_id) == CL_DEVICE_TYPE_CPU ? "-D__CPU__ "
	        : get_device_type(sequential_id) == CL_DEVICE_TYPE_GPU ? "-D__GPU__ " : "",
	        "-DDEVICE_INFO=", device_info[sequential_id],
	        "-D__SIZEOF_HOST_SIZE_T__=", (int)sizeof(size_t),
	        opencl_driver_ver(sequential_id),
	        opts ? opts : "");

	return build_opts;
}

void opencl_build(int sequential_id, const char *opts, int save, const char *file_name, cl_program *program, const char *kernel_source_file, const char *kernel_source)
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

	uint64_t start = john_get_nano();
	*program = clCreateProgramWithSource(context[sequential_id], 1, srcptr, NULL, &err_code);
	HANDLE_CLERROR(err_code, "clCreateProgramWithSource");

	build_opts = get_build_opts(sequential_id, opts);

	if (options.verbosity > VERB_LEGACY)
		fprintf(stderr, "Options used: %s %s\n", build_opts,
		        kernel_source_file);

	kernel_source_file = path_expand(kernel_source_file);

#if HAVE_MPI

	int kludge_file = 0;

	if (mpi_p > 1) {
#if RACE_CONDITION_DEBUG
		if (options.verbosity == VERB_DEBUG)
			fprintf(stderr, "Node %d %s kludge locking %s...\n",
			        NODE, __FUNCTION__, kernel_source_file);
#endif
		if ((kludge_file = open(kernel_source_file, O_RDWR | O_APPEND)) < 0)
			pexit("Error opening %s", kernel_source_file);
		else
			jtr_lock(kludge_file, F_SETLKW, F_WRLCK, kernel_source_file);

#if RACE_CONDITION_DEBUG
		if (options.verbosity == VERB_DEBUG)
			fprintf(stderr, "Node %d got a kludge lock\n", NODE);
#endif
	}
#endif /* HAVE_MPI */

/*
 * Build kernels having temporarily chdir'ed to John's home directory.
 *
 * This lets us use simply "-I opencl" instead of having to resolve a pathname,
 * which might contain spaces (which we'd have to quote) and was problematic on
 * Cygwin when run from Windows PowerShell (apparently, with Cygwin resolving
 * pathnames differently than the OpenCL backend would for the includes).
 *
 * Saving and restoring of the current directory here is incompatible with
 * concurrent kernel builds by multiple threads, like we'd do with the
 * PARALLEL_BUILD setting in descrypt-opencl (currently disabled and considered
 * unsupported).  We'd probably need to save and restore the directory
 * before/after all kernel builds, not before/after each.
 *
 * We primarily use open()/fchdir(), falling back to getcwd()/chdir() when
 * open() or/and fchdir() fails.
 */
	int old_cwd_fd = -1;
	char old_cwd[PATH_BUFFER_SIZE];
	old_cwd[0] = 0;
	char *john_home = (char *)path_expand_safe("$JOHN/");
	if (john_home[0] && strcmp(john_home, "./")) {
		old_cwd_fd = open(".", O_RDONLY);
		if (!getcwd(old_cwd, sizeof(old_cwd))) {
			old_cwd[0] = 0;
			if (old_cwd_fd < 0)
				fprintf(stderr, "Warning: Cannot save current directory: %s\n", strerror(errno));
		}
		if (chdir(john_home))
			pexit("chdir: %s", john_home);
	}
	MEM_FREE(john_home);
	build_code = clBuildProgram(*program, 0, NULL, build_opts, NULL, NULL);
	if ((old_cwd_fd >= 0 || old_cwd[0]) && /* We'll only have errno when we attempt a *chdir() here */
	    (old_cwd_fd < 0 || fchdir(old_cwd_fd)) && (!old_cwd[0] || chdir(old_cwd)))
		fprintf(stderr, "Warning: Cannot restore current directory: %s\n", strerror(errno));
	if (old_cwd_fd >= 0)
		close(old_cwd_fd);

	HANDLE_CLERROR(clGetProgramBuildInfo(*program,
	                                     devices[sequential_id],
	                                     CL_PROGRAM_BUILD_LOG, 0, NULL,
	                                     &log_size),
	               "clGetProgramBuildInfo I");
	build_log = (char *)mem_calloc(1, log_size + 1);

	HANDLE_CLERROR(clGetProgramBuildInfo(*program,
	                                     devices[sequential_id],
	                                     CL_PROGRAM_BUILD_LOG, log_size + 1,
	                                     (void *)build_log, NULL),
	               "clGetProgramBuildInfo II");

	uint64_t end = john_get_nano();
	log_event("- build time: %ss", ns2string(end - start));

	// Report build errors and warnings
	if (build_code != CL_SUCCESS) {
		// Give us info about error and exit (through HANDLE_CLERROR)
		if (options.verbosity <= VERB_LEGACY)
			fprintf(stderr, "Options used: %s %s\n",
			        build_opts, kernel_source_file);
		if (strlen(build_log) > 1)
			fprintf(stderr, "Build log: %s\n", build_log);
		fprintf(stderr, "Error building kernel %s. DEVICE_INFO=%d\n",
		        kernel_source_file, device_info[sequential_id]);
		HANDLE_CLERROR(build_code, "clBuildProgram");
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
		                                sizeof(size_t), &source_size, NULL),
		               "clGetProgramInfo for CL_PROGRAM_BINARY_SIZES");

		if (options.verbosity >= VERB_MAX)
			fprintf(stderr, "binary size "Zu"\n", source_size);

		source = mem_calloc(1, source_size);

		HANDLE_CLERROR(clGetProgramInfo(*program,
		                                CL_PROGRAM_BINARIES,
		                                sizeof(char *), &source, NULL),
		               "clGetProgramInfo for CL_PROGRAM_BINARIES");

		file = fopen(full_path = (char*)path_expand_safe(file_name), "w");
		MEM_FREE(full_path);

		if (file == NULL)
			perror("Error creating binary cache file");
		else {
#if RACE_CONDITION_DEBUG
			if (options.verbosity == VERB_DEBUG)
				fprintf(stderr, "Node %d %s locking %s...\n", NODE, __FUNCTION__, file_name);
#endif
			jtr_lock(fileno(file), F_SETLKW, F_WRLCK, file_name);

#if RACE_CONDITION_DEBUG
			if (options.verbosity == VERB_DEBUG)
				fprintf(stderr, "Node %d got a lock on %s\n", NODE, file_name);
#endif
			if (fwrite(source, source_size, 1, file) != 1)
				perror("Error caching kernel binary");
#if RACE_CONDITION_DEBUG
			if (options.verbosity == VERB_DEBUG)
				fprintf(stderr, "Node %d closing %s\n", NODE, file_name);
#endif
			fclose(file);
		}
		MEM_FREE(source);
	}

#if HAVE_MPI
#if RACE_CONDITION_DEBUG
	if (mpi_p > 1 && options.verbosity == VERB_DEBUG)
		fprintf(stderr, "Node %d releasing kludge lock\n", NODE);
#endif
	if (mpi_p > 1)
		close(kludge_file);
#endif /* HAVE_MPI */
}

cl_int opencl_build_from_binary(int sequential_id, cl_program *program, const char *kernel_source, size_t program_size)
{
	cl_int build_code;
	char *build_log;
	const char *srcptr[] = { kernel_source };

	build_log = mem_calloc(LOG_SIZE, sizeof(char));

	uint64_t start = john_get_nano();
	*program = clCreateProgramWithBinary(context[sequential_id], 1,
	                                     &devices[sequential_id], &program_size,
	                                     (const unsigned char **)srcptr,
	                                     NULL, &ret_code);
	if (ret_code != CL_SUCCESS) {
		MEM_FREE(build_log);
		return ret_code;
	}

	build_code = (clBuildProgram(*program, 0, NULL, NULL, NULL, NULL));

	HANDLE_CLERROR(clGetProgramBuildInfo(*program,
	                                     devices[sequential_id],
	                                     CL_PROGRAM_BUILD_LOG, LOG_SIZE,
	                                     (void *)build_log,
	                                     NULL), "clGetProgramBuildInfo (using cached binary - try clearing the cache)");

	uint64_t end = john_get_nano();

	// If it failed, don't show a log - we'll just rebuild without the cache
	if (build_code != CL_SUCCESS) {
		MEM_FREE(build_log);
		return build_code;
	}
	// Nvidia may return a single '\n' that we ignore
	else if (options.verbosity >= LOG_VERB && strlen(build_log) > 1)
		fprintf(stderr, "Binary Build log: %s\n", build_log);

	log_event("- build time: %ss", ns2string(end - start));
	MEM_FREE(build_log);
	return CL_SUCCESS;
}

// Do the proper test using different global work sizes.
static void clear_profiling_events()
{
	int i;

	// Release events
	for (i = 0; i < MAX_EVENTS; i++) {
		if (multi_profilingEvent[i] && *multi_profilingEvent[i])
			HANDLE_CLERROR(clReleaseEvent(*multi_profilingEvent[i]),
			               "clReleaseEvent");

		if (multi_profilingEvent[i])
			*multi_profilingEvent[i] = NULL;
		multi_profilingEvent[i] = NULL;
	}
}

// Fill [set_salt(), set_key()] the OpenCL device with data. Returns
// salt, and fills binary pointer.
static void* fill_opencl_device(size_t gws, void **binary)
{
	static int reported;
	int len = mask_add_len;
	int i;
	size_t kpc = gws * ocl_v_width;
	void *salt;

	// Set keys - unique printable length-7 keys
	self->methods.clear_keys();
	{
		char key[PLAINTEXT_BUFFER_SIZE];

		if (mask_add_len == 0 ||
		    options.req_minlength != -1 || options.req_maxlength != 0) {
			len = (self->params.benchmark_length & 0x7f);

			if (len < options.req_minlength)
				len = options.req_minlength;
			if (options.req_maxlength && len > options.req_maxlength)
				len = options.req_maxlength;
		}
		// Obey format's min and max length
		len = MAX(len, self->params.plaintext_min_length);
		len = MIN(len, self->params.plaintext_length);

		memset(key, 0x41, sizeof(key));
		key[len] = 0;

		for (i = 0; i < kpc; i++) {
			int l = len - 1;

			self->methods.set_key(key, i);
			while (l >= 0 && ++key[l] > 0x60)
				key[l--] = 0x21;
		}
	}

	// Set salt
	dyna_salt_init(self);
	if (self->methods.tunable_cost_value[0] && ocl_autotune_db->real) {
		struct db_main *db = ocl_autotune_db->real;
		struct db_salt *s = db->salts;

		while (s->next && s->cost[0] < db->max_cost[0])
			s = s->next;
		salt = s->salt;
		*binary = s->list->binary;

		if (options.verbosity >= VERB_MAX && !reported++)
			fprintf(stderr, "Tuning for %s of %u and password length %d\n",
			        db->format->params.tunable_cost_name[0], db->max_cost[0], len);
	} else {
		char *ciphertext;

		if (!self->params.tests[0].fields[1])
			self->params.tests[0].fields[1] = self->params.tests[0].ciphertext;
		ciphertext = self->methods.prepare(self->params.tests[0].fields, self);
		ciphertext = self->methods.split(ciphertext, 0, self);
		salt = self->methods.salt(ciphertext);
		*binary = self->methods.binary(ciphertext);
		if (salt)
			dyna_salt_create(salt);

		if (options.verbosity >= VERB_MAX && !reported++) {
			if (salt && self->methods.tunable_cost_value[0]) {
				struct db_main *db = ocl_autotune_db;
				fprintf(stderr, "Tuning for %s of %u and password length %d\n",
				        db->format->params.tunable_cost_name[0], self->methods.tunable_cost_value[0](salt), len);
			} else
				fprintf(stderr, "Tuning for password length %d\n", len);
		}
	}
	self->methods.set_salt(salt);

	return salt;
}

// Do a test run with a specific global work size, return total duration
// (or return zero for error or limits exceeded)
static cl_ulong gws_test(size_t gws, unsigned int rounds, int sequential_id)
{
	cl_ulong submitTime, startTime, endTime, runtime = 0, looptime = 0;
	int i, count, total = 0;
	size_t kpc = gws * ocl_v_width;
	cl_event benchEvent[MAX_EVENTS];
	int result, number_of_events = 0;
	void *salt, *binary;

	for (i = 0; i < MAX_EVENTS; i++)
		benchEvent[i] = NULL;

	// Ensure format knows its GWS
	global_work_size = gws;

	// Prepare buffers.
	create_clobj(gws, self);

	// Transfer data to the OpenCL device
	salt = fill_opencl_device(gws, &binary);

	// Activate events. Then clear them later.
	for (i = 0; i < MAX_EVENTS; i++)
		multi_profilingEvent[i] = &benchEvent[i];

	// Timing run
	count = kpc;
	result = self->methods.crypt_all(&count, autotune_salts);
	if (result < 0) {
		runtime = looptime = 0;

		if (options.verbosity > VERB_LEGACY)
			fprintf(stderr, " (error occurred)");
		clear_profiling_events();
		release_clobj();
		if (!self->methods.tunable_cost_value[0] || !ocl_autotune_db->real)
			dyna_salt_remove(salt);
		return 0;
	}
	result = self->methods.cmp_all(binary, result);
	BLOB_FREE(self, binary);
	if (result < 0) {
		runtime = looptime = 0;

		if (options.verbosity > VERB_LEGACY)
			fprintf(stderr, " (error occurred)");
		clear_profiling_events();
		release_clobj();
		if (!self->methods.tunable_cost_value[0] || !ocl_autotune_db->real)
			dyna_salt_remove(salt);
		return 0;
	}

	for (i = 0; (*multi_profilingEvent[i]); i++)
		number_of_events++;

	//** Get execution time **//
	for (i = 0; i < number_of_events; i++) {
		char mult[32] = "";

		int prof_bug = 0;

		if (clWaitForEvents(1, multi_profilingEvent[i]) != CL_SUCCESS) {
			if (options.verbosity > VERB_LEGACY)
				fprintf(stderr, "Profiling errors; Skipping results\n");
			return 0;
		}

		HANDLE_CLERROR(clGetEventProfilingInfo(*multi_profilingEvent[i],
		                                       CL_PROFILING_COMMAND_SUBMIT,
		                                       sizeof(cl_ulong), &submitTime,
		                                       NULL),
		               "clGetEventProfilingInfo submit");
		HANDLE_CLERROR(clGetEventProfilingInfo(*multi_profilingEvent[i],
		                                       CL_PROFILING_COMMAND_START,
		                                       sizeof(cl_ulong), &startTime,
		                                       NULL),
		               "clGetEventProfilingInfo start");
		HANDLE_CLERROR(clGetEventProfilingInfo(*multi_profilingEvent[i],
		                                       CL_PROFILING_COMMAND_END,
		                                       sizeof(cl_ulong), &endTime,
		                                       NULL),
		               "clGetEventProfilingInfo end");

		if (i == main_opencl_event && options.verbosity > VERB_MAX)
			fprintf(stderr, " [%lu, %lu, %lu, %u, %d]", (unsigned long)startTime,
			        (unsigned long)endTime, (unsigned long)submitTime, rounds, hash_loops);

		/* Work around OSX bug with HD4000 driver */
		if (endTime == 0)
			endTime = startTime;

		/*
		 * Work around driver bugs. Problems seen with old AMD and Apple M1.
		 * If startTime looks b0rken we use submitTime instead
		 *
		 * If the difference of submitTime and startTime is greater than 5s,
		 * submitTime is b0rken
		 */
		if (i == main_opencl_event && (startTime - submitTime < 5000000000ULL) &&
		   (endTime - submitTime) > 10 * (endTime - startTime)) {
			prof_bug = 1;

			startTime = submitTime;
		}

		if ((split_events) && (i == split_events[0] ||
		                       i == split_events[1] || i == split_events[2])) {
			looptime += (endTime - startTime);
			total++;

			if (i == split_events[0])
				sprintf(mult, "%dx", rounds / hash_loops);
		} else
			runtime += (endTime - startTime);

		if (options.verbosity >= VERB_MAX)
			fprintf(stderr, "%s%s%ss%s", warnings[i], mult,
			        ns2string(endTime - startTime), (prof_bug) ? "*" : "");

		/* Single-invocation duration limit */
		if (duration_time &&
		    (endTime - startTime) > 1000000ULL * duration_time) {
			runtime = looptime = 0;

			if (options.verbosity >= VERB_MAX)
				fprintf(stderr, " (exceeds %ss)", ms2string(duration_time));
			break;
		}
	}
	if (options.verbosity >= VERB_MAX)
		fprintf(stderr, "\n");

	if (total)
		runtime += (looptime * rounds) / (hash_loops * total);

	clear_profiling_events();
	release_clobj();

	if (!self->methods.tunable_cost_value[0] || !ocl_autotune_db->real)
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
	ocl_autotune_db = db;
	autotune_real_db = db && db->real && db->real == db;
	autotune_salts = db ? db->salts : NULL;

	/* We can't process more than 4G keys per crypt() */
	if (mask_int_cand.num_int_cand > 1)
		gws_limit = MIN(gws_limit, 0x100000000ULL / mask_int_cand.num_int_cand / ocl_v_width);
}

void opencl_find_best_lws(size_t group_size_limit, int sequential_id,
                          cl_kernel crypt_kernel)
{
	size_t gws;
	cl_int ret_code;
	int i, j, numloops, count, result;
	size_t my_work_group, optimal_work_group;
	size_t max_group_size, wg_multiple, sumRunTime;
	cl_ulong submitTime, startTime, endTime, kernelExecTimeNs = CL_ULONG_MAX;
	cl_event benchEvent[MAX_EVENTS];
	void *salt, *binary;

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

	// In case LWS would be greater than GWS, adjust LWS value.
	if (wg_multiple > global_work_size)
		wg_multiple = global_work_size;

	if (platform_apple(get_platform_id(sequential_id)) &&
	    cpu(device_info[sequential_id]))
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
	HANDLE_CLERROR(ret_code, "clCreateCommandQueue");

	// Transfer data to the OpenCL device
	salt = fill_opencl_device(gws, &binary);

	// Warm-up run
	local_work_size = wg_multiple;
	count = global_work_size * ocl_v_width;
	result = self->methods.crypt_all(&count, autotune_salts);
	if (result > 0)
		self->methods.cmp_all(binary, result);

	// Activate events. Then clear them later.
	for (i = 0; i < MAX_EVENTS; i++)
		multi_profilingEvent[i] = &benchEvent[i];

	// Timing run
	count = global_work_size * ocl_v_width;
	uint64_t wc_start = john_get_nano();
	result = self->methods.crypt_all(&count, autotune_salts);
	if (result > 0)
		self->methods.cmp_all(binary, result);
	uint64_t wc_end = john_get_nano();

	if ((clWaitForEvents(1, &benchEvent[main_opencl_event]) != CL_SUCCESS) ||
	    (clFinish(queue[sequential_id]) != CL_SUCCESS)) {
		if (options.verbosity > VERB_LEGACY)
			fprintf(stderr, "Profiling errors; Using wall-clock time instead\n");
		startTime = wc_start;
		endTime = wc_end;
	} else {
		HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent[main_opencl_event],
		                                       CL_PROFILING_COMMAND_SUBMIT,
		                                       sizeof(cl_ulong), &submitTime, NULL),
		               "clGetEventProfilingInfo submit");
		HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent[main_opencl_event],
		                                       CL_PROFILING_COMMAND_START,
		                                       sizeof(cl_ulong), &startTime, NULL),
		               "clGetEventProfilingInfo start");
		HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent[main_opencl_event],
		                                       CL_PROFILING_COMMAND_END,
		                                       sizeof(cl_ulong), &endTime, NULL),
		               "clGetEventProfilingInfo end");

		/*
		 * Work around driver bugs. Problems seen with old AMD and Apple M1.
		 * If startTime looks b0rken we use submitTime instead
		 */
		if ((endTime - submitTime) > 10 * (endTime - startTime)) {
			if (options.verbosity > VERB_LEGACY)
				fprintf(stderr, "Note: Profiling timers seem buggy\n");
			startTime = submitTime;
		}

		/*
		 * For numloops enumeration, we even double-check with wall clock time
		 * and if it drastically differs from the profile timer, use the former
		 * so we don't end up with a huge numloops where inappropriate.
		 */
		if ((wc_end - wc_start) > 10 * (endTime - startTime)) {
			if (options.verbosity > VERB_LEGACY)
				fprintf(stderr, "Note: Profiling timers seem to be way off\n");
			startTime = wc_start;
			endTime = wc_end;
		}
	}

	cl_ulong roundup = endTime - startTime - 1;
	numloops = (int)(size_t)((200000000ULL + roundup) / (endTime - startTime));

	clear_profiling_events();

	if (numloops < 1)
		numloops = 1;

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
			fprintf(stderr, "Testing LWS=" Zu " GWS=" Zu " ...", my_work_group,
			        global_work_size);

		sumRunTime = 0;

		for (i = 0; i < numloops; i++) {
			advance_cursor();
			local_work_size = my_work_group;

			// Activate events. Then clear them later.
			for (j = 0; j < MAX_EVENTS; j++)
				multi_profilingEvent[j] = &benchEvent[j];

			count = global_work_size * ocl_v_width;
			result = self->methods.crypt_all(&count, autotune_salts);
			if (result < 0) {
				startTime = endTime = 0;
				break;
			}
			result = self->methods.cmp_all(binary, result);
			if (result < 0) {
				startTime = endTime = 0;
				break;
			}

			if ((clWaitForEvents(1, &benchEvent[main_opencl_event]) != CL_SUCCESS) ||
			    (clFinish(queue[sequential_id]) != CL_SUCCESS)) {
				if (options.verbosity > VERB_LEGACY)
					fprintf(stderr, "Profiling errors; Skipping results\n");
				startTime = endTime = 0;
				break;
			}

			HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent
				[main_opencl_event], CL_PROFILING_COMMAND_SUBMIT,
				sizeof(cl_ulong), &submitTime, NULL),
			               "clGetEventProfilingInfo submit");
			HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent
				[main_opencl_event], CL_PROFILING_COMMAND_START,
				sizeof(cl_ulong), &startTime, NULL),
			               "clGetEventProfilingInfo start");
			HANDLE_CLERROR(clGetEventProfilingInfo(benchEvent
				[main_opencl_event], CL_PROFILING_COMMAND_END,
				sizeof(cl_ulong), &endTime, NULL),
			               "clGetEventProfilingInfo end");

			/*
			 * Work around driver bugs. Problems seen with old AMD and Apple M1.
			 * If startTime looks b0rken we use submitTime instead
			 */
			if ((endTime - submitTime) > 10 * (endTime - startTime))
				startTime = submitTime;

			clear_profiling_events();
			sumRunTime += endTime - startTime;
		}

		/* Erase the 'spinning wheel' cursor */
		if (john_main_process && isatty(fileno(stderr)))
			fprintf(stderr, " \b");

		if (!endTime)
			break;
		if (options.verbosity > VERB_LEGACY)
			fprintf(stderr, " %ss%s\n", ns2string(sumRunTime),
			    ((double)(sumRunTime) / kernelExecTimeNs < 0.997)
			        ? "+" : "");
		if (sumRunTime > 2 * kernelExecTimeNs)
			break;
		if ((double)(sumRunTime) / kernelExecTimeNs < 0.997) {
			kernelExecTimeNs = sumRunTime;
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
				    GET_NEXT_MULTIPLE(x, wg_multiple);
				/* The loop logic will re-add wg_multiple */
				my_work_group -= wg_multiple;
			}
		}
	}
	BLOB_FREE(self, binary);
	// Release profiling queue and create new with profiling disabled
	HANDLE_CLERROR(clReleaseCommandQueue(queue[sequential_id]),
	               "clReleaseCommandQueue");
	queue[sequential_id] =
	    clCreateCommandQueue(context[sequential_id],
	                         devices[sequential_id], 0, &ret_code);
	HANDLE_CLERROR(ret_code, "clCreateCommandQueue");
	local_work_size = optimal_work_group;
	global_work_size = GET_EXACT_MULTIPLE(gws, local_work_size);

	if (!self->methods.tunable_cost_value[0] || !ocl_autotune_db->real)
		dyna_salt_remove(salt);
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
		size = (uint32_t)INT_MAX + 1U;

	return size;
}

void opencl_find_best_gws(int step, int max_duration,
                          int sequential_id, unsigned int rounds, int have_lws)
{
	size_t num = 0;
	size_t optimal_gws = local_work_size, soft_limit = 0;
	unsigned long long speed, best_speed = 0, raw_speed;
	cl_ulong run_time;
	int save_duration_time = duration_time;
	cl_uint core_count = get_processors_count(sequential_id);

	/* Speed gain required to increase the GWS value */
	double regular_gain = 1.01;        //the default value is 1% gain
	double extra_gain = regular_gain;  //only applies when saving memory
	#define GWS_THRESHOLD 10000

	if (options.flags & FLG_SINGLE_CHK)
		/*
		 * Larger GWS is very expensive for single mode, so we try to
		 * keep it reasonable low.
		 */
		regular_gain = extra_gain = 1.25;
	else {
		if (mem_saving_level == 2)
			extra_gain = 1.10;
		if (mem_saving_level > 2)
			extra_gain = 1.20;
	}

	if (have_lws) {
		if (core_count > 2) {
			if (gws_limit)
				optimal_gws = MIN(gws_limit, lcm(core_count, optimal_gws));
			else
				optimal_gws = lcm(core_count, optimal_gws);
		}
		default_value = optimal_gws;
	} else {
		if (gws_limit)
			soft_limit = MIN(gws_limit, local_work_size * core_count * 128);
		else
			soft_limit = local_work_size * core_count * 128;
	}

	/* conf setting may override (decrease) code's max duration */
	if (!duration_time || max_duration < duration_time)
		duration_time = max_duration;

	if (options.verbosity > VERB_DEFAULT) {
		if (mask_int_cand.num_int_cand > 1 && !printed_mask++)
			fprintf(stderr, "Internal mask, multiplier: %u (target: %u)\n",
			        mask_int_cand.num_int_cand, mask_int_cand_target);
		else if (mask_int_cand_target > 1 && !printed_mask)
			fprintf(stderr, "Internal mask not utilized (target: %u)\n",
			        mask_int_cand_target);
	}
	if (options.verbosity > VERB_LEGACY) {
		fprintf(stderr, "Calculating best GWS for LWS="Zu"; "
		        "max. %ss single kernel invocation.\n",
		        local_work_size, ms2string(duration_time));
	}

	if (options.verbosity >= VERB_MAX)
		fprintf(stderr, "Raw speed figures including buffer transfers:\n");

	// Change command queue to be used by crypt_all (profile needed)
	clReleaseCommandQueue(queue[sequential_id]);    // Delete old queue

	// Create a new queue with profiling enabled
	queue[sequential_id] =
	    clCreateCommandQueue(context[sequential_id],
	                         devices[sequential_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	HANDLE_CLERROR(ret_code, "clCreateCommandQueue");

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

			if (options.verbosity >= VERB_MAX)
				fprintf(stderr, "Hardware resources exhausted for GWS=%zu\n", num);
			break;
		}

		if (!(run_time = gws_test(num, rounds, sequential_id)))
			break;

		if (options.verbosity <= VERB_LEGACY)
			advance_cursor();

		raw_speed = (kpc / (run_time / 1E9)) * mask_int_cand.num_int_cand;
		speed = rounds * raw_speed;

		if (options.verbosity > VERB_LEGACY)
			fprintf(stderr, "gws: %9zu%13s%12llu rounds/s%11ss per crypt_all()",
			        num, human_speed(raw_speed), speed, ns2string(run_time));

		/*
		 * Keep GWS low here by demanding a percentage gain
		 *   use higher threshold only for significant values in absolute terms
		 *   (e.g., at least 10240).
		 */
		if (speed >
		    ((num >= GWS_THRESHOLD ? extra_gain : regular_gain) * best_speed)) {
			if (options.verbosity > VERB_LEGACY)
				fprintf(stderr, (speed > 2 * best_speed) ? "!" : "+");
			best_speed = speed;
			global_speed = raw_speed;
			optimal_gws = num;
		}
		if (options.verbosity > VERB_LEGACY)
			fprintf(stderr, "\n");
	}

	/* Backward run */
	for (num = autotune_get_prev_gws_size(optimal_gws, step);;
	     num = autotune_get_prev_gws_size(num, step)) {
		size_t kpc = num * ocl_v_width;

		if (!(run_time = gws_test(num, rounds, sequential_id)))
			break;

		if (options.verbosity <= VERB_LEGACY)
			advance_cursor();

		raw_speed = (kpc / (run_time / 1E9)) * mask_int_cand.num_int_cand;
		speed = rounds * raw_speed;

		if (options.verbosity > VERB_LEGACY)
			fprintf(stderr, "gws: %9zu%13s%12llu rounds/s%11ss per crypt_all()",
			        num, human_speed(raw_speed), speed, ns2string(run_time));

		if (speed < best_speed) {
			if (options.verbosity > VERB_LEGACY)
				fprintf(stderr, "-\n");
			break;
		}
		best_speed = speed;
		global_speed = raw_speed;
		optimal_gws = num;
		if (options.verbosity > VERB_LEGACY)
			fprintf(stderr, "!!\n");
	}

	/* Erase any 'spinning wheel' cursor */
	if (john_main_process && isatty(fileno(stderr)))
		fprintf(stderr, " \b");

	// Release profiling queue and create new with profiling disabled
	HANDLE_CLERROR(clReleaseCommandQueue(queue[sequential_id]),
	               "clReleaseCommandQueue");
	queue[sequential_id] =
	    clCreateCommandQueue(context[sequential_id],
	                         devices[sequential_id], 0, &ret_code);
	HANDLE_CLERROR(ret_code, "clCreateCommandQueue");
	global_work_size = optimal_gws;

	duration_time = save_duration_time;
}

/* Get one device compute capability as a string */
static char* get_device_capability(int sequential_id)
{
	static char ret[32];
	unsigned int major = 0, minor = 0;

	ret[0] = '\0';

	get_compute_capability(sequential_id, &major, &minor);

	if (major) {
		snprintf(ret, sizeof(ret), "-DSM_MAJOR=%d -DSM_MINOR=%d ",
		         major, minor);
	}

	return ret;
}

/* Load detailed information about a device
 * - fill in the details of the OpenCL device (device_info[] bitfield variable);
 */
static void load_device_info(int sequential_id)
{
	cl_device_type device;
	unsigned int major = 0, minor = 0;

	device = get_device_type(sequential_id);

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
		device_info[sequential_id] += (major == 2 ? DEV_NV_C2X : 0);
		device_info[sequential_id] +=
		    (major == 3 && minor == 0 ? DEV_NV_C30 : 0);
		device_info[sequential_id] +=
		    (major == 3 && minor == 2 ? DEV_NV_C32 : 0);
		device_info[sequential_id] +=
		    (major == 3 && minor == 5 ? DEV_NV_C35 : 0);
		device_info[sequential_id] += (major == 5 ? DEV_NV_MAXWELL : 0);
		device_info[sequential_id] += (major >= 5 ? DEV_NV_MAXWELL_PLUS : 0);
	}
}

size_t opencl_read_source(const char *kernel_filename, char **kernel_source)
{
	FILE *fp;
	char *full_path;
	size_t source_size, read_size;

	fp = fopen(full_path = (char*)path_expand_safe(kernel_filename), "rb");
	MEM_FREE(full_path);

	if (!fp)
		pexit("Can't read source kernel");

#if RACE_CONDITION_DEBUG
	if (options.verbosity == VERB_DEBUG)
		fprintf(stderr, "Node %d %s() locking (shared) %s...\n", NODE, __FUNCTION__, kernel_filename);
#endif

	jtr_lock(fileno(fp), F_SETLKW, F_RDLCK, kernel_filename);

#if RACE_CONDITION_DEBUG
	if (options.verbosity == VERB_DEBUG)
		fprintf(stderr, "Node %d got a shared lock on %s\n", NODE, kernel_filename);
#endif

	fseek(fp, 0, SEEK_END);
	source_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	MEM_FREE((*kernel_source));
	*kernel_source = mem_calloc(1, source_size + 1);
	read_size = fread(*kernel_source, sizeof(char), source_size, fp);
	if (read_size != source_size)
		fprintf(stderr,
		        "Error reading source: expected "Zu", got "Zu" bytes (%s).\n",
		        source_size, read_size,
		        feof(fp) ? "EOF" : strerror(errno));
#if RACE_CONDITION_DEBUG
	if (options.verbosity == VERB_DEBUG)
		fprintf(stderr, "Node %d closing %s\n", NODE, kernel_filename);
#endif
	fclose(fp);
	return source_size;
}

#if JOHN_SYSTEMWIDE
static const char *replace_str(const char *string, char *from, char *to)
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


void opencl_build_kernel_opt(const char *kernel_filename, int sequential_id,
                             const char *opts)
{
	char *kernel_source = NULL;
	opencl_read_source(kernel_filename, &kernel_source);
	opencl_build(sequential_id, opts, 0, NULL, &program[sequential_id], kernel_filename, kernel_source);
	MEM_FREE(kernel_source);
}

#define md4add(string) MD4_Update(&ctx, (string), strlen(string))

void opencl_build_kernel(const char *kernel_filename, int sequential_id, const char *opts,
                         int warn)
{
	struct stat source_stat, bin_stat;
	char dev_name[512], bin_name[512];
	const char *tmp_name;
	unsigned char hash[16];
	char hash_str[33];
	int i, use_cache;
	MD4_CTX ctx;
	char *kernel_source = NULL;
	const char *global_opts;

#if HAVE_MPI
	static int once;
#endif

	if (!(global_opts = getenv("OPENCLBUILDOPTIONS")) &&
	    !(global_opts = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, "GlobalBuildOpts")))
		global_opts = OPENCLBUILDOPTIONS;

	// Get device name.
	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_NAME, sizeof(dev_name),
	                               dev_name, NULL),
	               "clGetDeviceInfo for DEVICE_NAME");

/*
 * Create a hash of kernel source and parameters, and use as cache name.
 */
	MD4_Init(&ctx);
	md4add(kernel_filename);
	opencl_read_source(kernel_filename, &kernel_source);
	md4add(kernel_source);
	md4add(global_opts);
	if (opts)
		md4add(opts);
	md4add(opencl_driver_ver(sequential_id));
	md4add(dev_name);
	MD4_Update(&ctx, (char*)&platform_id, sizeof(platform_id));
	MD4_Final(hash, &ctx);

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
	snprintf(bin_name, sizeof(bin_name), "%s_%s.bin", tmp_name, hash_str);

#if 1
	/*
	 * Disable binary caching for nvidia, they have their own in ~/.nv/ComputeCache
	 */
	if (gpu_nvidia(device_info[sequential_id]) && !platform_apple(get_platform_id(sequential_id))) {
		if (john_main_process || !cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI, "MPIAllGPUsSame", 0))
			log_event("- Kernel binary caching disabled for this platform/device");
		use_cache = 0;
	} else
#endif
	if (getenv("DUMP_BINARY")) {
		log_event("- DUMP_BINARY is set, ignoring cached kernel");
		use_cache = 0;
	} else {
		use_cache = !stat(path_expand(bin_name), &bin_stat);

		if (use_cache && !stat(path_expand(kernel_filename), &source_stat) &&
		    source_stat.st_mtime > bin_stat.st_mtime) {
			use_cache = 0;
			log_event("- cached kernel may be stale, ignoring");
		}
	}

	// Select the kernel to run.
	if (use_cache) {
		size_t program_size = opencl_read_source(bin_name, &kernel_source);

		log_event("- Building kernel from cached binary");
		ret_code = opencl_build_from_binary(sequential_id, &program[sequential_id], kernel_source, program_size);
		if (ret_code != CL_SUCCESS)
			log_event("- Build from cached binary failed");
	}

	if (!use_cache || ret_code != CL_SUCCESS) {
		log_event("- Building kernel from source and caching binary");
		if (warn && options.verbosity > VERB_DEFAULT) {
			fflush(stdout);
			fprintf(stderr, "Building the kernel, this could take a while\n");
		}
		opencl_read_source(kernel_filename, &kernel_source);
		opencl_build(sequential_id, opts, 1, bin_name, &program[sequential_id], kernel_filename, kernel_source);
	}

	MEM_FREE(kernel_source);

#if HAVE_MPI
	if (mpi_p > 1 && !once++) {
#if RACE_CONDITION_DEBUG || MPI_DEBUG
		if (options.verbosity == VERB_DEBUG)
			fprintf(stderr, "Node %d reached %s() MPI build barrier\n", NODE, __FUNCTION__);
#endif
		MPI_Barrier(MPI_COMM_WORLD);
		if (mpi_id == 0 && options.verbosity >= VERB_DEFAULT)
			fprintf(stderr, "All nodes done OpenCL build\n");
	}
#endif /* HAVE_MPI */
}

int opencl_prepare_dev(int sequential_id)
{
	int err_type = 0;
#ifdef HAVE_MPI
	static int once;
#endif

	// If OpenCL has not yet been loaded, load it now
	opencl_load_environment();

	if (sequential_id < 0)
		sequential_id = gpu_id;

	profilingEvent = firstEvent = lastEvent = NULL;
	if (!context[sequential_id])
		start_opencl_device(sequential_id, &err_type);
	print_device_info(sequential_id);

#if HAVE_MPI
	if (mpi_p > 1 && !once++) {
		// Avoid silly race conditions seen with nvidia
#if RACE_CONDITION_DEBUG || MPI_DEBUG
		if (options.verbosity == VERB_DEBUG)
			fprintf(stderr, "Node %d reached MPI prep barrier\n", NODE);
#endif
		MPI_Barrier(MPI_COMM_WORLD);
		if (mpi_id == 0 && options.verbosity == VERB_DEBUG)
			fprintf(stderr, "All nodes done OpenCL prepare\n");
	}
#endif

	if (options.verbosity >= VERB_MAX)
		ocl_always_show_ws = 1;
	else
		ocl_always_show_ws = cfg_get_bool(SECTION_OPTIONS, SUBSECTION_OPENCL,
		                                  "AlwaysShowWorksizes", 0);

#ifdef __linux__
	if (gpu_nvidia(device_info[sequential_id])) {
		opencl_avoid_busy_wait[sequential_id] = cfg_get_bool(SECTION_OPTIONS, SUBSECTION_GPU,
		                                                     "AvoidBusyWait", 1);
		static int warned;

		/* Remove next line once (nearly) all formats has got the macros */
		if (!opencl_avoid_busy_wait[sequential_id])
		if (!warned) {
			warned = 1;
			log_event("- Busy-wait reduction %sabled", opencl_avoid_busy_wait[sequential_id] ? "en" : "dis");
		}
	}
#endif

	return sequential_id;
}

void opencl_init(const char *kernel_filename, int sequential_id, const char *opts)
{
	sequential_id = opencl_prepare_dev(sequential_id);
	opencl_build_kernel(kernel_filename, sequential_id, opts, 0);
}

cl_device_type get_device_type(int sequential_id)
{
	cl_device_type type;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_TYPE,
	                               sizeof(cl_device_type), &type, NULL),
	               "clGetDeviceInfo for CL_DEVICE_TYPE");

	return type;
}

cl_ulong get_local_memory_size(int sequential_id)
{
	cl_ulong size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_LOCAL_MEM_SIZE,
	                               sizeof(cl_ulong), &size, NULL),
	               "clGetDeviceInfo for CL_DEVICE_LOCAL_MEM_SIZE");

	return size;
}

cl_ulong get_global_memory_size(int sequential_id)
{
	cl_ulong size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_GLOBAL_MEM_SIZE,
	                               sizeof(cl_ulong), &size, NULL),
	               "clGetDeviceInfo for CL_DEVICE_GLOBAL_MEM_SIZE");

	return size;
}

size_t get_device_max_lws(int sequential_id)
{
	size_t max_group_size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_MAX_WORK_GROUP_SIZE,
	                               sizeof(max_group_size),
	                               &max_group_size, NULL),
	               "clGetDeviceInfo for CL_DEVICE_MAX_WORK_GROUP_SIZE");

	return max_group_size;
}

cl_ulong get_max_mem_alloc_size(int sequential_id)
{
	cl_ulong max_alloc_size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_MAX_MEM_ALLOC_SIZE,
	                               sizeof(max_alloc_size),
	                               &max_alloc_size, NULL),
	               "clGetDeviceInfo for CL_DEVICE_MAX_MEM_ALLOC_SIZE");

	return max_alloc_size;
}

size_t get_kernel_max_lws(int sequential_id, cl_kernel crypt_kernel)
{
	size_t max_group_size;

	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel,
		devices[sequential_id],
		CL_KERNEL_WORK_GROUP_SIZE,
		sizeof(max_group_size),
		&max_group_size, NULL),
	               "clGetKernelWorkGroupInfo for CL_KERNEL_WORK_GROUP_SIZE");

	return max_group_size;
}

cl_uint get_max_compute_units(int sequential_id)
{
	cl_uint size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_MAX_COMPUTE_UNITS,
	                               sizeof(cl_uint), &size, NULL),
	               "clGetDeviceInfo for CL_DEVICE_MAX_COMPUTE_UNITS");

	return size;
}

size_t get_kernel_preferred_multiple(int sequential_id, cl_kernel crypt_kernel)
{
	size_t size;

	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel,
		devices[sequential_id],
		CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE,
		sizeof(size), &size, NULL),
		"clGetKernelWorkGroupInfo for CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE");

	return size;
}

void get_compute_capability(int sequential_id, unsigned int *major,
                            unsigned int *minor)
{
	clGetDeviceInfo(devices[sequential_id],
	                CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV,
	                sizeof(cl_uint), major, NULL);
	clGetDeviceInfo(devices[sequential_id],
	                CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV,
	                sizeof(cl_uint), minor, NULL);

	if (!major) {
/*
 * Apple, VCL and some other environments don't expose CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV
 * so we need this crap - which is incomplete, best effort matching.
 * http://en.wikipedia.org/wiki/Comparison_of_Nvidia_graphics_processing_units
 */
		char dname[MAX_OCLINFO_STRING_LEN];

		HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
		                               CL_DEVICE_NAME,
		                               sizeof(dname), dname, NULL),
		               "clGetDeviceInfo for CL_DEVICE_NAME");

		// Ampere 8.0
		if ((strstr(dname, "RTX 30") ||
		           (strstr(dname, "RTX A") && (dname[5] >= '1' && dname[5] <= '9')) ||
		     (dname[0] == 'A' && dname[1] >= '1' && dname[1] <= '9')))
			*major = 8;
		// Volta 7.0, Turing 7.5
		else if (strstr(dname, "TITAN V") || strstr(dname, "RTX 20")) {
			*major = 7;
			if (strstr(dname, "RTX 20"))
				*minor = 5;
		}
		// Pascal 6.x
		else if (strstr(dname, "GT 10") || strstr(dname, "GTX 10") || strcasestr(dname, "TITAN Xp"))
			*major = 6;
		// Maxwell 5.x
		else if (strstr(dname, "GT 9") || strstr(dname, "GTX 9") || strstr(dname, "GTX TITAN X"))
			*major = 5;
		// Kepler 3.x
		else if (strstr(dname, "GT 6") || strstr(dname, "GTX 6") ||
		         strstr(dname, "GT 7") || strstr(dname, "GTX 7") ||
		         strstr(dname, "GT 8") || strstr(dname, "GTX 8") ||
		         strstr(dname, "GTX TITAN"))
			*major = 3;
		// Fermi 2.0
		else if (strstr(dname, "GT 5") || strstr(dname, "GTX 5"))
			*major = 2;
	}
}

cl_uint get_processors_count(int sequential_id)
{
	cl_uint core_count = get_max_compute_units(sequential_id);
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
	                               CL_DEVICE_NAME,
	                               sizeof(dname), dname, NULL),
	               "clGetDeviceInfo for CL_DEVICE_NAME");

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
		else if (major >= 7)    // 7.0 Volta, 7.5 Turing, 8.x Ampere
			core_count *= (ocl_device_list[sequential_id].cores_per_MP = 64);
	} else if (gpu_intel(device_info[sequential_id])) {
		// It seems all current models are x 8
		core_count *= ocl_device_list[sequential_id].cores_per_MP = 8;
	} else if (!strcmp(dname, "Apple M1")) {
		// Each GPU core is split into 16 Execution Units, which each contain eight Arithmetic Logic Units (ALUs)
		core_count *= ocl_device_list[sequential_id].cores_per_MP = 16 * 8;
	} else if (gpu_amd(device_info[sequential_id])) {
		// 16 thread proc * 5 SP
		core_count *= (ocl_device_list[sequential_id].cores_per_MP = (16 *
		               ((amd_gcn(device_info[sequential_id]) ||
		                 amd_vliw4(device_info[sequential_id])) ? 4 : 5)));
	} else {
		// Nothing else known, we use the native vector width for long.
		cl_uint v_width;

		HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
		                               CL_DEVICE_NATIVE_VECTOR_WIDTH_LONG,
		                               sizeof(v_width), &v_width, NULL),
		              "clGetDeviceInfo for CL_DEVICE_NATIVE_VECTOR_WIDTH_LONG");
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
	               "clGetDeviceInfo for CL_DEVICE_MAX_CLOCK_FREQUENCY");

	return clock * get_processors_count(sequential_id);
}

cl_uint get_processor_family(int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_NAME,
	                               sizeof(dname), dname, NULL),
	               "clGetDeviceInfo for CL_DEVICE_NAME");

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
			/* All current GPUs are GCN so let's default to that */
			//return DEV_UNKNOWN;
			return DEV_AMD_GCN_12;
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
	               "clGetDeviceInfo for CL_DEVICE_EXTENSIONS");

	if (strstr(dname, "cl_khr_byte_addressable_store") == NULL)
		return DEV_NO_BYTE_ADDRESSABLE;

	return DEV_UNKNOWN;
}

int get_vendor_id(int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_VENDOR,
	                               sizeof(dname), dname, NULL),
	               "clGetDeviceInfo for CL_DEVICE_VENDOR");

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
	                                &num_platforms),
	               "clGetPlatformIDs");

	HANDLE_CLERROR(clGetPlatformInfo(platform[platform_id], CL_PLATFORM_NAME,
	                                 sizeof(dname), dname, NULL),
	               "clGetPlatformInfo for CL_PLATFORM_NAME");

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
		return PLATFORM_MESA;

	if (strstr(dname, "beignet"))
		return PLATFORM_BEIGNET;

	if (strstr(dname, "Portable Computing Language") || strstr(dname, "pocl"))
		return PLATFORM_POCL;

	/*
	 * If we found nothing recognized in the device name, look at
	 * device version string as well
	 */
	HANDLE_CLERROR(clGetPlatformInfo(platform[platform_id], CL_PLATFORM_VERSION,
	                                 sizeof(dname), dname, NULL),
	               "clGetPlatformInfo for CL_PLATFORM_VERSION");

	if ((strstr(dname, "MESA")) || (strstr(dname, "Mesa")))
		return PLATFORM_MESA;

	return DEV_UNKNOWN;
}

int get_device_version(int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];
	unsigned int major, minor;

	if ((clGetDeviceInfo(devices[sequential_id], CL_DEVICE_VERSION,
			MAX_OCLINFO_STRING_LEN, dname, NULL) == CL_SUCCESS) &&
			sscanf(dname, "OpenCL %u.%u", &major, &minor) == 2)
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

/*
 * We currently leave all of this to single.c instead but this function
 * remains for future functionality.
 */
int opencl_calc_min_kpc(size_t lws, size_t gws, int v_width)
{
	return gws * v_width;
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
		fprintf(stderr, "Throw clError: clGetPlatformIDs() = %s\n",
		        get_error_name(ret));

	for (i = 0; i < num_platforms; i++) {
		platforms[i].platform = platform_list[i];
		ret = clGetDeviceIDs(platforms[i].platform, CL_DEVICE_TYPE_ALL,
		                     MAX_GPU_DEVICES, &devices[available_devices],
		                     &num_devices);

		if ((ret != CL_SUCCESS || num_devices < 1) &&
		     options.verbosity > VERB_LEGACY)
			fprintf(stderr, "No OpenCL devices was found on platform #%d"
			                 ", clGetDeviceIDs() = %s\n",
			        i, get_error_name(ret));

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
		opencl_load_environment();

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
			p = ltrim(dname);
			printf("    Device #%d (%d) name:     %s\n", j, sequence_nr + 1, p);

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
			printf("    Device version:         %s", dname);
			/*
			 * JtR requires OpenCL 1.1+. It doesn't properly support devices
			 * that don't fully support OpenCL 1.1.
			 */
			if (strstr(dname, "OpenCL 1.0")) {
				printf(" <the minimum REQUIRED is OpenCL 1.1>");
			}
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_OPENCL_C_VERSION,
			                sizeof(dname), dname, NULL);
			printf("\n    OpenCL version support: %s\n", dname);
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
			printf("    Global Memory:          %sB%s\n",
			       human_prefix(long_entries),
			       boolean == CL_TRUE ? " (ECC)" : "");
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_EXTENSIONS, sizeof(dname), dname, NULL);
			if (options.verbosity > VERB_LEGACY)
				printf("    Device extensions:      %s\n", dname);

			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_GLOBAL_MEM_CACHE_SIZE,
			                sizeof(cl_ulong), &long_entries, NULL);
			if (long_entries)
				printf("    Global Memory Cache:    %sB\n",
				       human_prefix(long_entries)
				      );
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_LOCAL_MEM_SIZE,
			                sizeof(cl_ulong), &long_entries, NULL);
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_LOCAL_MEM_TYPE,
			                sizeof(cl_device_local_mem_type), &memtype, NULL);
			printf("    Local Memory:           %sB (%s)\n",
			       human_prefix(long_entries),
			       memtype == CL_LOCAL ? "Local" : "Global");
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE,
			                sizeof(cl_ulong), &long_entries, NULL);
			if (long_entries)
				printf("    Constant Buffer size:   %sB\n",
				       human_prefix(long_entries)
				      );
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_MAX_MEM_ALLOC_SIZE,
			                sizeof(long_entries), &long_entries, NULL);
			printf("    Max memory alloc. size: %sB\n",
			       human_prefix(long_entries));
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
				printf("    %s      "LLu"  (%d x %d)\n",
					gpu_nvidia(device_info[sequence_nr]) ? "CUDA INT32 cores: " : "Stream processors:",
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

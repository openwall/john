/* Common OpenCL functions go in this file */

#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>
#include "options.h"
#include "config.h"

#include "common-opencl.h"
#include "signals.h"
#include "recovery.h"
#include "status.h"
#include <signal.h>

#define LOG_SIZE 1024*16

static char opencl_log[LOG_SIZE];
static char *kernel_source;
static int kernel_loaded;
static size_t program_size;

extern volatile int bench_running;
static void opencl_get_dev_info(unsigned int sequential_id);

//Used by auto-tunning to decide how GWS should changed between trials.
extern int get_next_gws_size(size_t num, int step, int startup, int default_value);

//Settings to use for auto-tunning.
static int default_value;
static int hash_loops;
static char * duration_text;
static const char ** warnings;
static int number_of_events;
static int * split_events;
static cl_event * to_profile_event;
static struct fmt_main * self;
void (*create_clobj)(int gws, struct fmt_main * self);
void (*release_clobj)(void);

void opencl_process_event(void)
{
	if (!bench_running) {
#if !OS_TIMER
		sig_timer_emu_tick();
#endif
		if (event_pending) {

			event_pending = event_abort;

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
		}
	}
}

void advance_cursor()
{
	static int pos = 0;
	char cursor[4] = { '/', '-', '\\', '|' };
	fprintf(stderr, "%c\b", cursor[pos]);
	pos = (pos + 1) % 4;
}

void handle_clerror(cl_int cl_error, const char *message, const char *file, int line)
{
	if (cl_error != CL_SUCCESS) {
		fprintf(stderr,
		    "OpenCL error (%s) in file (%s) at line (%d) - (%s)\n",
		    get_error_name(cl_error), file, line, message);
		exit(EXIT_FAILURE);
	}
}

int get_number_of_available_platforms()
{
	int i = 0;

	while (platforms[i++].platform);

	return --i;
}

int get_number_of_available_devices()
{
	int total = 0, i = 0;

	while (platforms[i].platform)
		total += platforms[i++].num_devices;

	return total;
}

int get_devices_being_used()
{
	int i = 0;

	while (ocl_device_list[i++] != -1);

	return --i;
}

int get_platform_id(unsigned int sequential_id)
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

int get_device_id(unsigned int sequential_id)
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

static void start_opencl_devices()
{
	cl_platform_id platform_list[MAX_PLATFORMS];
	static char opencl_data[LOG_SIZE];
	cl_uint num_platforms, device_num, device_pos = 0;
	cl_context_properties properties[3];
	int i;

	///Find OpenCL enabled devices
	HANDLE_CLERROR(clGetPlatformIDs(MAX_PLATFORMS, platform_list,
		&num_platforms), "No OpenCL platform found");

	for (i = 0; i < num_platforms; i++) {
		platforms[i].platform = platform_list[i];

		HANDLE_CLERROR(clGetPlatformInfo(platforms[i].platform,
			CL_PLATFORM_NAME, sizeof(opencl_data), opencl_data, NULL),
			"Error querying PLATFORM_NAME");
		HANDLE_CLERROR(clGetDeviceIDs(platforms[i].platform,
			CL_DEVICE_TYPE_ALL, MAXGPUS, &devices[device_pos], &device_num),
			"No OpenCL device of that type exist");

		//Save plataform and devices information
		platforms[i].num_devices = device_num;

		//Point to the end of the list
		device_pos += device_num;

#ifdef DEBUG
	      	fprintf(stderr, "OpenCL platform %d: %s, %d device(s).\n",
			i, opencl_data, device_num);
#endif
	}
	//Set NULL to the final buffer position.
	platforms[i].platform = NULL;
	devices[device_pos] = NULL;

	//Get devices information
	for (i = 0; i < get_number_of_available_devices(); i++) {
		//Get the detailed information about the device.
		opencl_get_dev_info(i);

		HANDLE_CLERROR(clGetDeviceInfo(devices[i], CL_DEVICE_NAME,
			sizeof(opencl_data), opencl_data, NULL),
			"Error querying DEVICE_NAME");

		HANDLE_CLERROR(clGetDeviceInfo(devices[i],
			CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(max_group_size),
			&max_group_size, NULL), "Error querying MAX_WORK_GROUP_SIZE");

		//Get the plataform properties
		properties[0] = CL_CONTEXT_PLATFORM;
		properties[1] = (cl_context_properties) platforms[get_platform_id(i)].platform;
		properties[2] = 0;

		//Setup context and queue
		context[i] = clCreateContext(properties, 1, &devices[i],
			NULL, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating context");
		queue[i] = clCreateCommandQueue(context[i], devices[i],
			0, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating command queue");
#ifdef DEBUG
		fprintf(stderr, "  Device %d: %s\n", i, opencl_data);
#endif
	}
}

static void add_device_to_list(int sequential_id)
{
	int i = 0, found = 0;

	if (sequential_id >= get_number_of_available_devices()) {
		fprintf(stderr, "Invalid OpenCL device id %d\n", sequential_id);
		return;
	}

	for (i = 0; i < get_devices_being_used() && !found; i++) {

		if (sequential_id == ocl_device_list[i])
			found = 1;
	}
	if (!found) {
		ocl_device_list[get_devices_being_used() + 1] = -1;
		ocl_device_list[get_devices_being_used()] = sequential_id;
	}
}

static void add_device_type(cl_ulong device_type)
{
	int i, j, sequence_nr = 0;
	cl_uint device_num;
	cl_ulong long_entries;
	cl_device_id devices[MAXGPUS];

	for (i = 0; platforms[i].platform; i++) {
		//Get all devices of informed type.
		HANDLE_CLERROR(clGetDeviceIDs(platforms[i].platform,
			CL_DEVICE_TYPE_ALL, MAXGPUS, devices, &device_num),
			"No OpenCL device of that type exist");

		for (j = 0; j < device_num; j++, sequence_nr++) {
			clGetDeviceInfo(devices[j], CL_DEVICE_TYPE,
					sizeof(cl_ulong), &long_entries, NULL);
		    if (long_entries & device_type)
			add_device_to_list(sequence_nr);
		}
	}
}

static void build_device_list(char * device_list[MAXGPUS])
{
	int n = 0;

	while (device_list[n] && n < MAXGPUS) {

		if (!strcmp(device_list[n], "all"))
			add_device_type(CL_DEVICE_TYPE_ALL);
		else if (!strcmp(device_list[n], "cpu"))
			add_device_type(CL_DEVICE_TYPE_CPU);
		else if (!strcmp(device_list[n], "gpu"))
			add_device_type(CL_DEVICE_TYPE_GPU);
		else
			add_device_to_list(atoi(device_list[n]));
		n++;
	}
}

void init_opencl_devices(void)
{
	char * device_list[MAXGPUS], string[10];
	int n = 0;

	ocl_device_list[0] = -1;
	ocl_device_list[1] = -1;
	start_opencl_devices();

	if (options.ocl_platform) {
		struct list_entry *current;

		platform_id = atoi(options.ocl_platform);

		if (platform_id >= get_number_of_available_platforms()) {
			fprintf(stderr, "Invalid OpenCL platform id %d\n",
				platform_id);
			exit(1);
		}

		/* Legacy syntax --platform + --device */
		if ((current = options.gpu_devices->head)) {
			if (current->next) {
				fprintf(stderr, "Only one OpenCL device supported with --platform syntax.\n");
				exit(1);
			}
			if (!isdigit(current->data[0])) {
				fprintf(stderr, "Invalid OpenCL device id %s\n",
					current->data);
				exit(1);
			}
			ocl_gpu_id = get_sequential_id(atoi(current->data), platform_id);

			if (ocl_gpu_id < 0) {
				fprintf(stderr, "Invalid OpenCL device id %s\n",
					current->data);
				exit(1);
			}
			sprintf(string, "%d", ocl_gpu_id);
			device_list[n++] = string;
			device_list[n] = NULL;
			build_device_list(device_list);
		} else
			ocl_gpu_id = -1;
	} else 	{
		struct list_entry *current;

		/* New syntax, sequential --device */
		if ((current = options.gpu_devices->head)) {

			do {
				device_list[n++] = current->data;
			} while ((current = current->next));

			device_list[n] = NULL;
			build_device_list(device_list);
			ocl_gpu_id = ocl_device_list[0]; // FIXME?
			platform_id = get_platform_id(ocl_gpu_id);
		} else {
			ocl_gpu_id = -1;
			platform_id = -1;
    		}
	}

	//Use configuration file only JtR knows nothing about the environment.
	if (!options.ocl_platform && platform_id < 0) {
		char *devcfg;

		if ((devcfg =
		     cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL,
				   "Platform")))
			platform_id = atoi(devcfg);
	}

	if (!options.gpu_devices && ocl_gpu_id < 0) {
		char *devcfg;

		if ((devcfg = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL,
					    "Device"))) {
			ocl_gpu_id = atoi(devcfg);
			ocl_device_list[0] = ocl_gpu_id;
		}
	}

	if (platform_id == -1 || ocl_gpu_id == -1) {
		opencl_find_gpu(&ocl_gpu_id, &platform_id);
		ocl_device_list[0] = ocl_gpu_id;
	}

	//Use the sequential number on ocl_gpu_id.
	device_id = get_device_id(ocl_gpu_id);
}

void clean_opencl_devices()
{
	int i;

	for (i = 0; i < get_number_of_available_devices(); i++) {
		HANDLE_CLERROR(clReleaseCommandQueue(queue[i]), "Release Queue");
		HANDLE_CLERROR(clReleaseContext(context[i]), "Release Context");
	}
}

static void dev_init(unsigned int sequential_id)
{
	char device_name[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_NAME,
		sizeof(device_name), device_name, NULL),
	    "Error querying DEVICE_NAME");
	fprintf(stderr, "Device %d: %s ", sequential_id, device_name);

#ifdef CL_DEVICE_BOARD_NAME_AMD
	{
		cl_int ret_code;
	    	int len;

		ret_code = clGetDeviceInfo(devices[sequential_id],
			CL_DEVICE_BOARD_NAME_AMD,
			sizeof(opencl_log), opencl_log, NULL);

		if (ret_code == CL_SUCCESS && (len = strlen(opencl_log))) {

			while (len > 0 && isspace(opencl_log[len]))
				len--;

			opencl_log[len-1] = '\0';
			fprintf(stderr, "(%s)", opencl_log);
		}
	}
#endif
	fprintf(stderr, "\n");
}

static char *include_source(char *pathname, unsigned int sequential_id, char *options)
{
	static char include[PATH_BUFFER_SIZE];

	sprintf(include, "-I %s %s %s%d %s %s", path_expand(pathname),
		get_device_type(sequential_id) == CL_DEVICE_TYPE_CPU ?
		"-DDEVICE_IS_CPU" : "",
		"-DDEVICE_INFO=", device_info[sequential_id],
#ifdef __APPLE__
		"-DAPPLE",
#else
		gpu_nvidia(device_info[sequential_id]) ? "-cl-nv-verbose" : "",
#endif
		OPENCLBUILDOPTIONS);

	if (options) {
		strcat(include, " ");
		strcat(include, options);
	}

#ifdef DEBUG
	fprintf(stderr, "Options used: %s\n", include);
#endif
	return include;
}

static void build_kernel(unsigned int sequential_id, char *options, int save, char * file_name)
{
	cl_int build_code;
	char * build_log; size_t log_size;
	const char *srcptr[] = { kernel_source };
	assert(kernel_loaded);
	program[sequential_id] =
	    clCreateProgramWithSource(context[sequential_id], 1, srcptr, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while creating program");

	build_code = clBuildProgram(program[sequential_id], 0, NULL,
		include_source("$JOHN/kernels", sequential_id, options), NULL, NULL);

	HANDLE_CLERROR(clGetProgramBuildInfo(program[sequential_id], devices[sequential_id],
		CL_PROGRAM_BUILD_LOG, 0, NULL,
		&log_size), "Error while getting build info I");
	build_log = (char *) mem_alloc((log_size + 1));

	HANDLE_CLERROR(clGetProgramBuildInfo(program[sequential_id], devices[sequential_id],
		CL_PROGRAM_BUILD_LOG, log_size + 1, (void *) build_log,
		NULL), "Error while getting build info");

	///Report build errors and warnings
	if (build_code != CL_SUCCESS) {
		// Give us much info about error and exit
		fprintf(stderr, "Build log: %s\n", build_log);
		fprintf(stderr, "Error %d building kernel. DEVICE_INFO=%d\n", build_code, device_info[sequential_id]);
		HANDLE_CLERROR (build_code, "clBuildProgram failed.");
	}
#if defined(REPORT_OPENCL_WARNINGS) || defined(DEBUG)
	else if (strlen(build_log) > 1) // Nvidia may return a single '\n'
		fprintf(stderr, "Build log: %s\n", build_log);
#endif
	MEM_FREE(build_log);

	if (save) {
		FILE *file;
		size_t source_size;
		char *source;

		HANDLE_CLERROR(clGetProgramInfo(program[sequential_id],
			CL_PROGRAM_BINARY_SIZES,
			sizeof(size_t), &source_size, NULL), "error");
#if DEBUG
		fprintf(stderr, "source size %zu\n", source_size);
#endif
		source = mem_alloc(source_size);

		HANDLE_CLERROR(clGetProgramInfo(program[sequential_id],
			CL_PROGRAM_BINARIES, sizeof(char *), &source, NULL), "error");

		file = fopen(path_expand(file_name), "w");

		if (file == NULL)
			fprintf(stderr, "Error creating binary file %s\n", file_name);
		else {
			if (fwrite(source, source_size, 1, file) != 1)
				fprintf(stderr, "error writing binary\n");
			fclose(file);
		}
		MEM_FREE(source);
	}
}

static void build_kernel_from_binary(unsigned int sequential_id)
{
	cl_int build_code;
	const char *srcptr[] = { kernel_source };
	assert(kernel_loaded);
	program[sequential_id] = clCreateProgramWithBinary(context[sequential_id], 1,
		&devices[sequential_id], &program_size, (const unsigned char**)srcptr,
		NULL, &ret_code);
	HANDLE_CLERROR(ret_code,
		       "Error while creating program (using cached binary)");

	build_code = clBuildProgram(program[sequential_id], 0, NULL, NULL, NULL, NULL);

	HANDLE_CLERROR(clGetProgramBuildInfo(program[sequential_id], devices[sequential_id],
		CL_PROGRAM_BUILD_LOG, sizeof(opencl_log), (void *) opencl_log,
		NULL), "Error while getting build info (using cached binary)");

	///Report build errors and warnings
	if (build_code != CL_SUCCESS) {
		// Give us much info about error and exit
		fprintf(stderr, "Binary build log: %s\n", opencl_log);
		fprintf(stderr, "Error %d building kernel using cached binary."
			" DEVICE_INFO=%d\n", build_code, device_info[sequential_id]);
		HANDLE_CLERROR (build_code, "clBuildProgram failed.");
	}
#if defined(REPORT_OPENCL_WARNINGS) || defined(DEBUG)
	else if (strlen(opencl_log) > 1) // Nvidia may return a single '\n'
		fprintf(stderr, "Binary build log: %s\n", opencl_log);
#endif
}

/*
 *   NOTE: Requirements for using this function:
 *
 * - Your kernel (or main kernel) should be crypt_kernel.
 * - Use profilingEvent in your crypt_all() when enqueueing crypt_kernel.
 * - Do not use profilingEvent for transfers or other subkernels.
 * - For split kernels, use firstEvent and lastEvent instead.
 */
void opencl_find_best_workgroup(struct fmt_main *self)
{
	opencl_find_best_workgroup_limit(self, UINT_MAX, ocl_gpu_id, crypt_kernel);
}

void opencl_find_best_workgroup_limit(struct fmt_main *self, size_t group_size_limit,
	unsigned int sequential_id, cl_kernel crypt_kernel)
{
	cl_ulong startTime, endTime, kernelExecTimeNs = CL_ULONG_MAX;
	size_t my_work_group, optimal_work_group;
	cl_int ret_code;
	int i, numloops;
	size_t max_group_size, wg_multiple, sumStartTime, sumEndTime;
	cl_event benchEvent[2];
	size_t gws;

	gws = global_work_size ? global_work_size : self->params.max_keys_per_crypt;

	if (get_device_version(sequential_id) < 110) {
		if (get_device_type(sequential_id) == CL_DEVICE_TYPE_GPU)
			wg_multiple = 32;
		else if (get_platform_vendor_id(sequential_id) == DEV_INTEL)
			wg_multiple = 8;
		else
			wg_multiple = 1;
	} else {
		HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[sequential_id],
		    CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE,
		    sizeof(wg_multiple), &wg_multiple, NULL),
		"Error while getting CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE");
	}

	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[sequential_id],
		CL_KERNEL_WORK_GROUP_SIZE, sizeof(max_group_size),
		&max_group_size, NULL),
	    "Error while getting CL_KERNEL_WORK_GROUP_SIZE");

	if (max_group_size > group_size_limit)
	    //Needed to deal (at least) with cryptsha512-opencl limits.
	    max_group_size = group_size_limit;

	// Safety harness
	if (wg_multiple > max_group_size)
		wg_multiple = max_group_size;

	///Command Queue changing:
	///1) Delete old CQ
	clReleaseCommandQueue(queue[sequential_id]);
	///2) Create new CQ with profiling enabled
	queue[sequential_id] =
	    clCreateCommandQueue(context[sequential_id], devices[sequential_id],
	    CL_QUEUE_PROFILING_ENABLE, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");

	//fprintf(stderr, "Max local work size %d, ", (int) max_group_size);

	/// Set keys - first key from tests will be benchmarked
	for (i = 0; i < self->params.max_keys_per_crypt; i++) {
		self->methods.set_key(self->params.tests[0].plaintext, i);
	}
	/// Set salt
	self->methods.set_salt(self->methods.salt(self->params.tests[0].
		ciphertext));

	/// Warm-up run
	local_work_size = wg_multiple;
	self->methods.crypt_all(self->params.max_keys_per_crypt);

	// Activate events
	benchEvent[0] = benchEvent[1] = NULL;
	firstEvent = profilingEvent = &benchEvent[0];
	lastEvent = &benchEvent[1];

	// Some formats need this for "keys_dirty"
	self->methods.set_key(self->params.tests[0].plaintext, self->params.max_keys_per_crypt - 1);

	// Timing run
	self->methods.crypt_all(self->params.max_keys_per_crypt);

	if (*lastEvent == NULL)
		lastEvent = firstEvent;

	HANDLE_CLERROR(clFinish(queue[sequential_id]), "clFinish error");
	HANDLE_CLERROR(clGetEventProfilingInfo(*firstEvent,
			CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime,
			NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(*lastEvent,
			CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
			NULL), "Failed to get profiling info");
	numloops = (int)(size_t)(500000000ULL / (endTime-startTime));

	if (numloops < 1)
		numloops = 1;
	else if (numloops > 10)
		numloops = 10;
	//fprintf(stderr, "%zu, %zu, time: %zu, loops: %d\n", endTime, startTime, (endTime-startTime), numloops);

	/// Find minimum time
	for (optimal_work_group = my_work_group = wg_multiple;
	    (int) my_work_group <= (int) max_group_size;
	    my_work_group += wg_multiple) {

		if (gws % my_work_group != 0)
			continue;

		sumStartTime = 0;
		sumEndTime = 0;

		for (i = 0; i < numloops; i++) {
			advance_cursor();
			local_work_size = my_work_group;

			clReleaseEvent(benchEvent[0]);

			if (*lastEvent != *firstEvent)
				clReleaseEvent(benchEvent[1]);

			// Some formats need this for "keys_dirty"
			self->methods.set_key(self->params.tests[0].plaintext, self->params.max_keys_per_crypt - 1);

			self->methods.crypt_all(self->params.max_keys_per_crypt);

			HANDLE_CLERROR(clFinish(queue[sequential_id]), "clFinish error");
			HANDLE_CLERROR(clGetEventProfilingInfo(*firstEvent,
				       CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime,
				       NULL), "Failed to get profiling info");
			HANDLE_CLERROR(clGetEventProfilingInfo(*lastEvent,
				       CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
				       NULL), "Failed to get profiling info");
			//fprintf(stderr, "%zu, %zu, time: %zu\n", endTime, startTime, (endTime-startTime));
			sumStartTime += startTime;
			sumEndTime += endTime;
		}
		if ((sumEndTime - sumStartTime) < kernelExecTimeNs) {
			kernelExecTimeNs = sumEndTime - sumStartTime;
			optimal_work_group = my_work_group;
		}
		//fprintf(stderr, "LWS %d time=%llu ns\n",(int) my_work_group, (unsigned long long)sumEndTime-sumStartTime);
	}
	///Release profiling queue and create new with profiling disabled
	clReleaseCommandQueue(queue[sequential_id]);
	queue[sequential_id] =
	    clCreateCommandQueue(context[sequential_id], devices[sequential_id], 0,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");
	local_work_size = optimal_work_group;


	//fprintf(stderr, "Optimal local work size = %d\n", (int) local_work_size);
	// Release events
	clReleaseEvent(benchEvent[0]);
	if (benchEvent[1])
		clReleaseEvent(benchEvent[1]);

	// These ensure we don't get events from crypt_all() in real use
	profilingEvent = firstEvent = lastEvent = NULL;
}

//Do the proper test using different global work sizes.
static cl_ulong gws_test(
        size_t num, int show_details, unsigned int rounds)
{
        cl_ulong startTime, endTime, runtime = 0, looptime = 0;
        int i;

        //Prepare buffers.
        create_clobj(num, self);

        // Set keys (only the key[0] from tests will be benchmarked)
        for (i = 0; i < num; i++)
            self->methods.set_key(self->params.tests[0].plaintext, i);

        // Set salt
        self->methods.set_salt(self->methods.salt(self->params.tests[0].ciphertext));

        // Timing run
        self->methods.crypt_all(num);

        //** Get execution time **//
        for (i = 0; i < number_of_events; i++) {
            HANDLE_CLERROR(clGetEventProfilingInfo(multi_profilingEvent[i], CL_PROFILING_COMMAND_START,
                    sizeof (cl_ulong), &startTime, NULL), "Failed in clGetEventProfilingInfo I");
            HANDLE_CLERROR(clGetEventProfilingInfo(multi_profilingEvent[i], CL_PROFILING_COMMAND_END,
                    sizeof (cl_ulong), &endTime, NULL), "Failed in clGetEventProfilingInfo II");

            if ((split_events) && (i == split_events[0] || i == split_events[1] || i == split_events[2]))
                looptime += (endTime - startTime);
            else
                runtime += (endTime - startTime);

            if (show_details)
                fprintf(stderr, "%s%.2f ms", warnings[i], (double) (endTime - startTime) / 1000000.);
        }
        if (show_details)
            fprintf(stderr, "\n");

        if (split_events)
            runtime += ((looptime / 3) * (rounds / hash_loops));

        // Release events
        for (i = 0; i < EVENTS; i++) {
                if (multi_profilingEvent[i])
                        HANDLE_CLERROR(clReleaseEvent(multi_profilingEvent[i]), "Failed in clReleaseEvent");
        }
        release_clobj();
        return runtime;
}

void opencl_init_auto_setup(
        int p_default_value, int p_hash_loops, int p_number_of_events,
        int * p_split_events, char * p_duration_text, const char ** p_warnings,
        cl_event * p_to_profile_event, struct fmt_main * p_self,
        void (*p_create_clobj)(int gws, struct fmt_main * self),
        void (*p_release_clobj)(void))
{
        int i;

        // Initialize events
        for (i = 0; i < EVENTS; i++)
                multi_profilingEvent[i] = NULL;

        // Get parameters
        default_value = p_default_value;
        hash_loops = p_hash_loops;
        number_of_events = p_number_of_events;
        split_events = p_split_events;
        duration_text = p_duration_text;
        warnings = p_warnings;
        to_profile_event = p_to_profile_event;
        self = p_self;
        create_clobj = p_create_clobj;
        release_clobj = p_release_clobj;
}

void opencl_find_best_lws(
        size_t group_size_limit, unsigned int sequential_id, cl_kernel crypt_kernel)
{
	size_t gws;
	cl_int ret_code;
	int i, j, numloops;
	size_t my_work_group, optimal_work_group;
	size_t max_group_size, wg_multiple, sumStartTime, sumEndTime;
	cl_ulong startTime, endTime, kernelExecTimeNs = CL_ULONG_MAX;

	gws = global_work_size ? global_work_size : self->params.max_keys_per_crypt;

	if (get_device_version(sequential_id) < 110) {
		if (get_device_type(sequential_id) == CL_DEVICE_TYPE_GPU)
			wg_multiple = 32;
		else if (get_platform_vendor_id(sequential_id) == DEV_INTEL)
			wg_multiple = 8;
		else
			wg_multiple = 1;
	} else
		wg_multiple = get_kernel_preferred_work_group_size(sequential_id, crypt_kernel);

	max_group_size = get_current_work_group_size(sequential_id, crypt_kernel);

	if (max_group_size > group_size_limit)
	    //Needed to deal (at least) with cryptsha512-opencl limits.
	    max_group_size = group_size_limit;

	// Safety harness
	if (wg_multiple > max_group_size)
		wg_multiple = max_group_size;

	//Change command queue to be used by crypt_all (profile needed)
	clReleaseCommandQueue(queue[sequential_id]);

	//Create a new queue with profiling enabled
	queue[sequential_id] =
	    clCreateCommandQueue(context[sequential_id], devices[sequential_id],
	    CL_QUEUE_PROFILING_ENABLE, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");

	// Set keys (only the key[0] from tests will be benchmarked)
	for (i = 0; i < self->params.max_keys_per_crypt; i++)
		self->methods.set_key(self->params.tests[0].plaintext, i);

	// Set salt
	self->methods.set_salt(self->methods.salt(self->params.tests[0].ciphertext));

	// Warm-up run
	local_work_size = wg_multiple;
	self->methods.crypt_all(self->params.max_keys_per_crypt);

	// Activate events
	profilingEvent = to_profile_event;

	// Timing run
	self->methods.crypt_all(self->params.max_keys_per_crypt);

	HANDLE_CLERROR(clFinish(queue[sequential_id]), "clFinish error");
	HANDLE_CLERROR(clGetEventProfilingInfo(*profilingEvent,
			CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
			NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(*profilingEvent,
			CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
			NULL), "Failed to get profiling info");
	numloops = (int)(size_t)(500000000ULL / (endTime-startTime));

        // Release events
        for (i = 0; i < EVENTS; i++) {
                if (multi_profilingEvent[i])
                        HANDLE_CLERROR(clReleaseEvent(multi_profilingEvent[i]), "Failed in clReleaseEvent");
        }

	if (numloops < 1)
		numloops = 1;
	else if (numloops > 10)
		numloops = 10;

	/// Find minimum time
	for (optimal_work_group = my_work_group = wg_multiple;
	    (int) my_work_group <= (int) max_group_size;
	    my_work_group += wg_multiple) {

		if (gws % my_work_group != 0)
			continue;

		sumStartTime = 0;
		sumEndTime = 0;

		for (i = 0; i < numloops; i++) {
			advance_cursor();
			local_work_size = my_work_group;

			self->methods.crypt_all(self->params.max_keys_per_crypt);

			HANDLE_CLERROR(clFinish(queue[sequential_id]), "clFinish error");
			HANDLE_CLERROR(clGetEventProfilingInfo(*profilingEvent,
				       CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
				       NULL), "Failed to get profiling info");
			HANDLE_CLERROR(clGetEventProfilingInfo(*profilingEvent,
				       CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
				       NULL), "Failed to get profiling info");

			sumStartTime += startTime;
			sumEndTime += endTime;

                        // Release events
                        for (j = 0; j < EVENTS; j++) {
                                if (multi_profilingEvent[j])
                                        HANDLE_CLERROR(clReleaseEvent(multi_profilingEvent[j]), "Failed in clReleaseEvent");
                        }
		}
		if ((sumEndTime - sumStartTime) < kernelExecTimeNs) {
			kernelExecTimeNs = sumEndTime - sumStartTime;
			optimal_work_group = my_work_group;
		}
	}
	///Release profiling queue and create new with profiling disabled
	HANDLE_CLERROR(clReleaseCommandQueue(queue[sequential_id]), "Failed in clReleaseCommandQueue");
	queue[sequential_id] =
	    clCreateCommandQueue(context[sequential_id], devices[sequential_id], 0,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");
	local_work_size = optimal_work_group;

	// These ensure we don't get events from crypt_all() in real use
	profilingEvent = NULL;
}

void opencl_find_best_gws(
        int step, int show_speed, int show_details,
        unsigned long long int max_run_time, int sequential_id,
        unsigned int rounds)
{
        size_t num = 0;
        int optimal_gws = local_work_size;
        unsigned int speed, best_speed = 0;
        cl_ulong run_time, min_time = CL_ULONG_MAX;
        char * tmp_value;

        if ((tmp_value = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, duration_text)))
            max_run_time = atoi(tmp_value) * 1000000000ULL;

        fprintf(stderr, "Calculating best global worksize (GWS) for LWS=%zd and max. %llu s duration.\n\n",
                local_work_size, max_run_time / 1000000000ULL);

        if (show_speed)
            fprintf(stderr, "Raw speed figures including buffer transfers:\n");

        //Change command queue to be used by crypt_all (profile needed)
        clReleaseCommandQueue(queue[sequential_id]); // Delete old queue

        //Create a new queue with profiling enabled
        queue[sequential_id] =
                clCreateCommandQueue(context[sequential_id], devices[sequential_id],
                CL_QUEUE_PROFILING_ENABLE, &ret_code);
        HANDLE_CLERROR(ret_code, "Error creating command queue");

        for (num = get_next_gws_size(num, step, 1, default_value);;
                num = get_next_gws_size(num, step, 0, default_value)) {

            if (!(run_time = gws_test(num, show_details, rounds)))
                continue;

            if (!show_speed && !show_details)
                advance_cursor();

            speed = 5000 * num / (run_time / 1000000000.);

            if (run_time < min_time)
                min_time = run_time;

            if (show_speed) {
                fprintf(stderr, "gws: %6zu\t%6lu c/s%10u rounds/s%8.3f sec per crypt_all()",
                        num, (long) (num / (run_time / 1000000000.)), speed,
                        (float) run_time / 1000000000.);

                if (run_time > max_run_time) {
                    fprintf(stderr, " - too slow\n");
                    break;
                }
            } else {
                if (run_time > min_time * 10 || run_time > max_run_time)
                    break;
            }
            if (speed > (1.01 * best_speed)) {
                if (show_speed)
                    fprintf(stderr, "+");
                best_speed = speed;
                optimal_gws = num;
            }
            if (show_speed)
                fprintf(stderr, "\n");
        }
	///Release profiling queue and create new with profiling disabled
	HANDLE_CLERROR(clReleaseCommandQueue(queue[sequential_id]), "Failed in clReleaseCommandQueue");
	queue[sequential_id] =
	    clCreateCommandQueue(context[sequential_id], devices[sequential_id], 0,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");
        global_work_size = optimal_gws;
}

static void opencl_get_dev_info(unsigned int sequential_id)
{
	cl_device_type device;

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
}

void opencl_find_gpu(int *dev_id, int *platform_id)
{
	cl_platform_id platform[MAX_PLATFORMS];
	cl_device_id devices[MAXGPUS];
	cl_uint num_platforms, num_devices;
	cl_ulong long_entries;
	int i, d;

	if (clGetPlatformIDs(MAX_PLATFORMS, platform, &num_platforms) != CL_SUCCESS)
		goto err;

	if (*platform_id == -1)
		*platform_id = 0;
	else
		num_platforms = *platform_id + 1;

	for (i = *platform_id; i < num_platforms; i++) {
		clGetDeviceIDs(platform[i], CL_DEVICE_TYPE_ALL, MAXGPUS,
		    devices, &num_devices);

		if (!num_devices)
			continue;
		d = 0;
		if (*dev_id >= 0) {
			if (num_devices < *dev_id)
				continue;
			else
				*platform_id = i;
			d = *dev_id;
			num_devices = *dev_id + 1;
		}
		for (; d < num_devices; ++d) {
			clGetDeviceInfo(devices[d], CL_DEVICE_TYPE,
					sizeof(cl_ulong), &long_entries, NULL);
			if (long_entries & CL_DEVICE_TYPE_GPU) {
				*platform_id = i;
				*dev_id = d;
				return;
			}
		}
	}
err:
	if (*platform_id < 0)
		*platform_id = 0;
	if (*dev_id < 0)
		*dev_id = 0;
	return;
}

static void read_kernel_source(char *kernel_filename)
{
	char *kernel_path = path_expand(kernel_filename);
	FILE *fp = fopen(kernel_path, "r");
	size_t source_size, read_size;

	if (!fp)
		fp = fopen(kernel_path, "rb");

	if (!fp)
		HANDLE_CLERROR(!CL_SUCCESS, "Source kernel not found!");

	fseek(fp, 0, SEEK_END);
	source_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	MEM_FREE(kernel_source);
	kernel_source = mem_calloc(source_size + 1);
	read_size = fread(kernel_source, sizeof(char), source_size, fp);
	if (read_size != source_size)
		fprintf(stderr,
		    "Error reading source: expected %zu, got %zu bytes.\n",
		    source_size, read_size);
	fclose(fp);
	program_size = source_size;
	kernel_loaded = 1;
}

void opencl_build_kernel_opt(char *kernel_filename, unsigned int sequential_id, char *options)
{
	read_kernel_source(kernel_filename);
	build_kernel(sequential_id, options, 0, NULL);
}

// Only AMD gpu code, and OSX (including with nvidia)
// will benefit from this routine.
void opencl_build_kernel_save(char *kernel_filename, unsigned int sequential_id, char *options, int save, int warn) {
	struct stat source_stat, bin_stat;
	char dev_name[128], bin_name[128];
	char * p;
	uint64_t startTime, runtime;

	kernel_loaded = 0;

	if ((!gpu_amd(device_info[sequential_id]) && !platform_apple(platform_id)) || !save || stat(path_expand(kernel_filename), &source_stat))
		opencl_build_kernel_opt(kernel_filename, sequential_id, options);

	else {
		startTime = (unsigned long) time(NULL);

		//Get device name.
		HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_NAME,
			sizeof (dev_name), dev_name, NULL), "Error querying DEVICE_NAME");

		//Decide the binary name.
		strncpy(bin_name, kernel_filename, sizeof(bin_name));
		p = strstr(bin_name, ".cl");
		if (p) *p = 0;
		strcat(bin_name, "_");
		if (options) {
			strcat(bin_name, options);
			strcat(bin_name, "_");
		}
		strcat(bin_name, dev_name);
		strcat(bin_name, ".bin");

		// Change spaces to '_'
		while (p && *p) {
			if (isspace((unsigned char)(*p)))
				*p = '_';
			p++;
		}

		//Select the kernel to run.
		if (!stat(path_expand(bin_name), &bin_stat) && (source_stat.st_mtime < bin_stat.st_mtime)) {
			read_kernel_source(bin_name);
			build_kernel_from_binary(sequential_id);

		} else {

			if (warn) {
				fprintf(stderr, "Building the kernel, this could take a while\n");
				fflush(stdout);
			}
			read_kernel_source(kernel_filename);
			build_kernel(sequential_id, options, 1, bin_name);
		}
		if (warn) {
			if ((runtime = (unsigned long) (time(NULL) - startTime)) > 2UL)
				fprintf(stderr, "Build time: %lu seconds\n", (unsigned long)runtime);
			fflush(stdout);
		}
	}
}

void opencl_init_dev(unsigned int sequential_id)
{
	profilingEvent = firstEvent = lastEvent = NULL;
	dev_init(sequential_id);
}

void opencl_init_Sayantan(char *kernel_filename, unsigned int dev_id, unsigned int platform_id, char *options)
{
	//Shows the information about in use device(s).
	int sequential_id = get_sequential_id(dev_id, platform_id);

	kernel_loaded=0;
	opencl_init_dev(sequential_id);
	opencl_build_kernel_save(kernel_filename, sequential_id, options, 1, 0);
}

void opencl_init_opt(char *kernel_filename, unsigned int sequential_id, char *options)
{
	kernel_loaded=0;
	opencl_init_dev(sequential_id);
	opencl_build_kernel_save(kernel_filename, sequential_id, options, 1, 0);
}

void opencl_init(char *kernel_filename, unsigned int sequential_id)
{
	opencl_init_opt(kernel_filename, sequential_id, NULL);
}

cl_device_type get_device_type(unsigned int sequential_id)
{
	cl_device_type type;
	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_TYPE,
		sizeof(cl_device_type), &type, NULL),
	    "Error querying CL_DEVICE_TYPE");

	return type;
}

cl_ulong get_local_memory_size(unsigned int sequential_id)
{
	cl_ulong size;
	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
		CL_DEVICE_LOCAL_MEM_SIZE, sizeof(cl_ulong), &size, NULL),
	    "Error querying CL_DEVICE_LOCAL_MEM_SIZE");

	return size;
}

cl_ulong get_global_memory_size(unsigned int sequential_id)
{
	cl_ulong size;
	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
		CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(cl_ulong), &size, NULL),
	    "Error querying CL_DEVICE_GLOBAL_MEM_SIZE");

	return size;
}

size_t get_max_work_group_size(unsigned int sequential_id)
{
	size_t max_group_size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
		CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(max_group_size),
		&max_group_size, NULL),
	    "Error querying CL_DEVICE_MAX_WORK_GROUP_SIZE");

	return max_group_size;
}

cl_ulong get_max_mem_alloc_size(unsigned int sequential_id)
{
	cl_ulong max_alloc_size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
		CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(max_alloc_size),
		&max_alloc_size, NULL),
	    "Error querying CL_DEVICE_MAX_MEM_ALLOC_SIZE");

	return max_alloc_size;
}

size_t get_current_work_group_size(unsigned int sequential_id, cl_kernel crypt_kernel)
{
	size_t max_group_size;

	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[sequential_id],
		CL_KERNEL_WORK_GROUP_SIZE, sizeof(max_group_size),
		&max_group_size, NULL),
	    "Error querying clGetKernelWorkGroupInfo");

	return max_group_size;
}

cl_uint get_max_compute_units(unsigned int sequential_id)
{
	cl_uint size;
	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
		CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cl_uint), &size, NULL),
	    "Error querying CL_DEVICE_MAX_COMPUTE_UNITS");

	return size;
}

size_t get_kernel_preferred_work_group_size(unsigned int sequential_id, cl_kernel crypt_kernel)
{
	size_t size;

	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[sequential_id],
		    CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE,
		    sizeof(size), &size, NULL),
		"Error while getting CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE");

	return size;
}

#ifdef CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV
void get_compute_capability(unsigned int sequential_id, unsigned int *major,
    unsigned int *minor)
{
	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
		CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV,
		sizeof(cl_uint), major, NULL),
	    "Error querying CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV");
	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id],
		CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV,
		sizeof(cl_uint), minor, NULL),
	    "Error querying CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV");
}
#endif

cl_uint get_processors_count(unsigned int sequential_id)
{
	cl_uint core_count = get_max_compute_units(sequential_id);

	cores_per_MP[sequential_id] = 0;
	if (gpu_nvidia(device_info[sequential_id])) {
#ifdef CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV
		unsigned int major = 0, minor = 0;

		get_compute_capability(sequential_id, &major, &minor);
		if (major == 1)
			core_count *= (cores_per_MP[sequential_id] = 8);
		else if (major == 2 && minor == 0)
			core_count *= (cores_per_MP[sequential_id] = 32);	//2.0
		else if (major == 2 && minor >= 1)
			core_count *= (cores_per_MP[sequential_id] = 48);	//2.1
		else if (major == 3)
			core_count *= (cores_per_MP[sequential_id] = 192);	//3.0
#else
		/* Apple does not expose get_compute_capability() so we need
		   to find out using mory hacky approaches. This needs more
		   much more clauses to be correct but it's a MESS:
		   http://en.wikipedia.org/wiki/Comparison_of_Nvidia_graphics_processing_units

		   Anything that not hits these will be listed as x8, right
		   or wrong. Note that --list=cuda-devices will show the right
		   figure even under OSX. */
		char dname[MAX_OCLINFO_STRING_LEN];

		HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_NAME,
					       sizeof(dname), dname, NULL), "Error querying CL_DEVICE_NAME");

		if (strstr(dname, "GT 65") || strstr(dname, "GTX 65") ||
		    strstr(dname, "GT 66") || strstr(dname, "GTX 66") ||
		    strstr(dname, "GT 67") || strstr(dname, "GTX 67") ||
		    strstr(dname, "GT 68") || strstr(dname, "GTX 68") ||
		    strstr(dname, "GT 69") || strstr(dname, "GTX 69"))
			core_count *= (cores_per_MP[sequential_id] = 192); // Kepler
#endif
	} else
	if (gpu_amd(device_info[sequential_id])) {
		core_count *= (cores_per_MP[sequential_id] = (16 *	//16 thread proc * 5 SP
			((amd_gcn(device_info[sequential_id]) ||
				amd_vliw4(device_info[sequential_id])) ? 4 : 5)));
	} else if (gpu(device_info[sequential_id]))	//Any other GPU
		core_count *= (cores_per_MP[sequential_id] = 8);

	return core_count;
}

cl_uint get_processor_family(unsigned int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_NAME,
		sizeof(dname), dname, NULL), "Error querying CL_DEVICE_NAME");

	if gpu_amd(device_info[sequential_id]) {

		if ((strstr(dname, "Cedar") ||
			strstr(dname, "Redwood") ||
			strstr(dname, "Juniper") ||
			strstr(dname, "Cypress") ||
			strstr(dname, "Hemlock") ||
			strstr(dname, "Caicos") ||
			strstr(dname, "Turks") ||
			strstr(dname, "Barts") ||
			strstr(dname, "Cayman") ||
			strstr(dname, "Antilles") ||
			strstr(dname, "Wrestler") ||
			strstr(dname, "Zacate") ||
			strstr(dname, "WinterPark") ||
			strstr(dname, "BeaverCreek"))) {

			if (strstr(dname, "Cayman") ||
			    strstr(dname, "Antilles"))
				return DEV_AMD_VLIW4;
			else
				return DEV_AMD_VLIW5;

		} else
			return DEV_AMD_GCN;
	}
	return DEV_UNKNOWN;
}

int get_byte_addressable(unsigned int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_EXTENSIONS,
		sizeof(dname), dname, NULL),
	    "Error querying CL_DEVICE_EXTENSIONS");

	if (strstr(dname, "cl_khr_byte_addressable_store") == NULL)
		return DEV_NO_BYTE_ADDRESSABLE;

	return DEV_UNKNOWN;
}

int get_vendor_id(unsigned int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[sequential_id], CL_DEVICE_VENDOR,
		sizeof(dname), dname, NULL),
	    "Error querying CL_DEVICE_VENDOR");

	if (strstr(dname, "NVIDIA") != NULL)
		return DEV_NVIDIA;

	if (strstr(dname, "Intel") != NULL)
		return DEV_INTEL;

	if (strstr(dname, "Advanced Micro") != NULL ||
	    strstr(dname, "AMD") != NULL || strstr(dname, "ATI") != NULL)
		return DEV_AMD;

	return DEV_UNKNOWN;
}

int get_platform_vendor_id(int platform_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];
	cl_platform_id platform[MAX_PLATFORMS];
	cl_uint num_platforms;

	HANDLE_CLERROR(
		clGetPlatformIDs(MAX_PLATFORMS, platform,
				 &num_platforms),
		"No OpenCL platform found");

	HANDLE_CLERROR(
		clGetPlatformInfo(platform[platform_id], CL_PLATFORM_NAME,
				  sizeof(dname), dname, NULL),
		"Error querying CL_DEVICE_VENDOR");

	if (strstr(dname, "NVIDIA") != NULL)
		return DEV_NVIDIA;

	if (strstr(dname, "Apple") != NULL)
		return PLATFORM_APPLE;

	if (strstr(dname, "Intel") != NULL)
		return DEV_INTEL;

	if (strstr(dname, "Advanced Micro") != NULL ||
	    strstr(dname, "AMD") != NULL || strstr(dname, "ATI") != NULL)
		return DEV_AMD;

	return DEV_UNKNOWN;
}

int get_device_version(unsigned int sequential_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	clGetDeviceInfo(devices[sequential_id], CL_DEVICE_VERSION,
		MAX_OCLINFO_STRING_LEN, dname, NULL);

	if (strstr(dname, "1.0"))
		return 100;
	if (strstr(dname, "1.1"))
		return 110;
	if (strstr(dname, "1.2"))
		return 120;

	return DEV_UNKNOWN;
}

char *get_error_name(cl_int cl_error)
{
	static char *err_1[] =
	    { "CL_SUCCESS", "CL_DEVICE_NOT_FOUND", "CL_DEVICE_NOT_AVAILABLE",
		"CL_COMPILER_NOT_AVAILABLE",
		"CL_MEM_OBJECT_ALLOCATION_FAILURE", "CL_OUT_OF_RESOURCES",
		"CL_OUT_OF_HOST_MEMORY",
		"CL_PROFILING_INFO_NOT_AVAILABLE", "CL_MEM_COPY_OVERLAP",
		"CL_IMAGE_FORMAT_MISMATCH",
		"CL_IMAGE_FORMAT_NOT_SUPPORTED", "CL_BUILD_PROGRAM_FAILURE",
		"CL_MAP_FAILURE"
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
		"CL_INVALID_MIP_LEVEL", "CL_INVALID_GLOBAL_WORK_SIZE"
	};

	if (cl_error <= 0 && cl_error >= -12) {
		cl_error = -cl_error;
		return err_1[cl_error];
	}
	if (cl_error <= -30 && cl_error >= -63) {
		cl_error = -cl_error;
		return err_invalid[cl_error - 30];
	}

	return "UNKNOWN ERROR :(";
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
	sprintf(ret, "%zd.%zd %cB", size, (size % 1024) / 100, pref[prefid]);
	return ret;
}

void listOpenCLdevices(void)
{
	char dname[MAX_OCLINFO_STRING_LEN];
	cl_uint entries;
	cl_ulong long_entries;
	int i, j, sequence_nr = 0;
	size_t p_size;

	start_opencl_devices();

	/* Obtain list of platforms available */
	if (! platforms[0].platform) {
		fprintf(stderr, "Error: No OpenCL-capable devices were detected by the installed OpenCL driver.\n\n");
	}

	for (i = 0; platforms[i].platform; i++) {
		/* Obtain information about platform */
		clGetPlatformInfo(platforms[i].platform, CL_PLATFORM_NAME,
		    sizeof(dname), dname, NULL);
		printf("Platform #%d name: %s\n", i, dname);
		clGetPlatformInfo(platforms[i].platform, CL_PLATFORM_VERSION,
		    sizeof(dname), dname, NULL);
		printf("Platform version: %s\n", dname);

		/* Obtain list of devices available on platform */
		if (!platforms[i].num_devices)
			printf("%d devices found\n", platforms[i].num_devices);

		/* Query devices for information */
		for (j = 0; j < platforms[i].num_devices; j++, sequence_nr++) {
			cl_device_local_mem_type memtype;
			cl_bool boolean;
			char *p;
			int ret;

			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_NAME,
			    sizeof(dname), dname, NULL);
			p = dname;
			while (isspace(*p)) /* Intel quirk */
				p++;
			printf("\tDevice #%d (%d) name:\t%s\n", j, sequence_nr, p);
#ifdef CL_DEVICE_BOARD_NAME_AMD
			ret = clGetDeviceInfo(devices[sequence_nr],
					      CL_DEVICE_BOARD_NAME_AMD,
					      sizeof(dname), dname, NULL);
			if (ret == CL_SUCCESS && strlen(dname))
				printf("\tBoard name:\t\t%s\n", dname);
#endif
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_VENDOR,
			    sizeof(dname), dname, NULL);
			printf("\tDevice vendor:\t\t%s\n", dname);
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_TYPE,
			    sizeof(cl_ulong), &long_entries, NULL);
			printf("\tDevice type:\t\t");
			if (long_entries & CL_DEVICE_TYPE_CPU)
				printf("CPU ");
			if (long_entries & CL_DEVICE_TYPE_GPU)
				printf("GPU ");
			if (long_entries & CL_DEVICE_TYPE_ACCELERATOR)
				printf("Accelerator ");
			if (long_entries & CL_DEVICE_TYPE_DEFAULT)
				printf("Default ");
			if (long_entries & ~(CL_DEVICE_TYPE_DEFAULT |
				CL_DEVICE_TYPE_ACCELERATOR | CL_DEVICE_TYPE_GPU
				| CL_DEVICE_TYPE_CPU))
				printf("Unknown ");
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_ENDIAN_LITTLE,
			    sizeof(cl_bool), &boolean, NULL);
			printf("(%s)\n", boolean == CL_TRUE ? "LE" : "BE");
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_VERSION,
			    sizeof(dname), dname, NULL);
			printf("\tDevice version:\t\t%s\n", dname);
			clGetDeviceInfo(devices[sequence_nr], CL_DRIVER_VERSION,
			    sizeof(dname), dname, NULL);
			printf("\tDriver version:\t\t%s\n", dname);
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_GLOBAL_MEM_SIZE,
			    sizeof(cl_ulong), &long_entries, NULL);
			clGetDeviceInfo(devices[sequence_nr],
			    CL_DEVICE_ERROR_CORRECTION_SUPPORT,
			    sizeof(cl_bool), &boolean, NULL);
			printf("\tGlobal Memory:\t\t%s%s\n",
			    human_format((unsigned long long) long_entries),
			    boolean == CL_TRUE ? " (ECC)" : "");
#ifdef DEBUG
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_EXTENSIONS,
					sizeof(dname), dname, NULL);
			printf("\tDevice extensions:\t%s\n", dname);
#endif
			clGetDeviceInfo(devices[sequence_nr],
			    CL_DEVICE_GLOBAL_MEM_CACHE_SIZE, sizeof(cl_ulong),
			    &long_entries, NULL);
			if (long_entries)
				printf("\tGlobal Memory Cache:\t%s\n",
				       human_format((unsigned long long) long_entries));
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_LOCAL_MEM_SIZE,
			    sizeof(cl_ulong), &long_entries, NULL);
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_LOCAL_MEM_TYPE,
			    sizeof(cl_device_local_mem_type), &memtype, NULL);
			printf("\tLocal Memory:\t\t%s (%s)\n",
			    human_format((unsigned long long) long_entries),
			    memtype == CL_LOCAL ? "Local" : "Global");
			clGetDeviceInfo(devices[sequence_nr], CL_DEVICE_MAX_MEM_ALLOC_SIZE,
			    sizeof(long_entries), &long_entries, NULL);
			printf("\tMax memory alloc. size:\t%s\n",
			       human_format(long_entries));
			ret = clGetDeviceInfo(devices[sequence_nr],
			    CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(cl_ulong),
			    &long_entries, NULL);
			if (ret == CL_SUCCESS && long_entries)
				printf("\tMax clock (MHz) :\t%llu\n",
				       (unsigned long long) long_entries);
			clGetDeviceInfo(devices[sequence_nr],
			    CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(size_t),
			    &p_size, NULL);
			printf("\tMax Work Group Size:\t%d\n", (int) p_size);
			clGetDeviceInfo(devices[sequence_nr],
			    CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cl_uint),
			    &entries, NULL);
			printf("\tParallel compute cores:\t%d\n", entries);

			long_entries = get_processors_count(sequence_nr);
			if (cores_per_MP[sequence_nr])
				printf
				    ("\tStream processors:\t%llu  (%d x %d)\n",
				    (unsigned long long)long_entries, entries,
				     cores_per_MP[sequence_nr]);

#ifdef CL_DEVICE_REGISTERS_PER_BLOCK_NV
			ret = clGetDeviceInfo(devices[sequence_nr],
			    CL_DEVICE_WARP_SIZE_NV, sizeof(cl_uint),
			    &long_entries, NULL);
			if (ret == CL_SUCCESS)
				printf("\tWarp size:\t\t%llu\n",
				       (unsigned long long)long_entries);

			ret = clGetDeviceInfo(devices[sequence_nr],
				  CL_DEVICE_REGISTERS_PER_BLOCK_NV,
				  sizeof(cl_uint), &long_entries, NULL);
			if (ret == CL_SUCCESS)
				printf("\tMax. GPRs/work-group:\t%llu\n",
				       (unsigned long long)long_entries);

			if (gpu_nvidia(device_info[sequence_nr])) {
				unsigned int major = 0, minor = 0;
				get_compute_capability(j, &major, &minor);
				printf
				    ("\tCompute capability:\t%u.%u (sm_%u%u)\n",
				    major, minor, major, minor);
			}
			ret = clGetDeviceInfo(devices[sequence_nr],
			    CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV,
			    sizeof(cl_bool), &boolean, NULL);
			if (ret == CL_SUCCESS)
				printf("\tKernel exec. timeout:\t%s\n",
				       boolean ? "yes" : "no");
#endif
#if defined(CL_DEVICE_TOPOLOGY_AMD) && CL_DEVICE_TOPOLOGY_TYPE_PCIE_AMD == 1
			{
				cl_device_topology_amd topo;

				ret = clGetDeviceInfo(devices[sequence_nr],
				    CL_DEVICE_TOPOLOGY_AMD, sizeof(topo),
				    &topo, NULL);
				if (ret == CL_SUCCESS)
				printf("\tPCI device topology:\t%02d:%02d.%d\n",
				       topo.pcie.bus, topo.pcie.device,
				       topo.pcie.function);
			}
#endif
			puts("");
		}
	}
	return;
}

#undef LOG_SIZE
#undef SRC_SIZE

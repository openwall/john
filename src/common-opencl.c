/* Common OpenCL functions go in this file */

#include "common-opencl.h"
#include <assert.h>
#include <string.h>
#define LOG_SIZE 1024*16

static char opencl_log[LOG_SIZE];
static char *kernel_source;
static int kernel_loaded;
static size_t program_size;

void advance_cursor()
{
	static int pos = 0;
	char cursor[4] = { '/', '-', '\\', '|' };
	fprintf(stderr, "%c\b", cursor[pos]);
	fflush(stdout);
	pos = (pos + 1) % 4;
}

void handle_clerror(cl_int cl_error, const char *message, const char *file,
    int line)
{
	if (cl_error != CL_SUCCESS) {
		fprintf(stderr,
		    "OpenCL error (%s) in file (%s) at line (%d) - (%s)\n",
		    get_error_name(cl_error), file, line, message);
		exit(EXIT_FAILURE);
	}
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
	kernel_source = calloc(source_size + 1, 1);
	read_size = fread(kernel_source, sizeof(char), source_size, fp);
	if (read_size != source_size)
		fprintf(stderr,
		    "Error reading source: expected %zu, got %zu bytes.\n",
		    source_size, read_size);
	fclose(fp);
	program_size = source_size;
	kernel_loaded = 1;
}

static void dev_init(unsigned int dev_id, unsigned int platform_id)
{
	cl_platform_id platform[MAX_PLATFORMS];
	cl_uint num_platforms, device_num;
	cl_context_properties properties[3];
	assert(dev_id < MAXGPUS);
	///Find CPU's
	HANDLE_CLERROR(clGetPlatformIDs(MAX_PLATFORMS, platform,
		&num_platforms), "No OpenCL platform found");
	HANDLE_CLERROR(clGetPlatformInfo(platform[platform_id],
		CL_PLATFORM_NAME, sizeof(opencl_log), opencl_log, NULL),
	    "Error querying PLATFORM_NAME");
	HANDLE_CLERROR(clGetDeviceIDs(platform[platform_id],
		CL_DEVICE_TYPE_ALL, MAXGPUS, devices, &device_num),
	    "No OpenCL device of that type exist");
	fprintf(stderr, "OpenCL platform %d: %s, %d device(s).\n", platform_id,
	    opencl_log, device_num);

	properties[0] = CL_CONTEXT_PLATFORM;
	properties[1] = (cl_context_properties) platform[platform_id];
	properties[2] = 0;
	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id], CL_DEVICE_NAME,
		sizeof(opencl_log), opencl_log, NULL),
	    "Error querying DEVICE_NAME");
	fprintf(stderr, "Using device %d: %s\n", dev_id, opencl_log);
	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id],
		CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(max_group_size),
		&max_group_size, NULL), "Error querying MAX_WORK_GROUP_SIZE");
	///Setup context
	context[dev_id] =
	    clCreateContext(properties, 1, &devices[dev_id], NULL, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating context");
	queue[dev_id] =
	    clCreateCommandQueue(context[dev_id], devices[dev_id], 0,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");
}

static char *include_source(char *pathname, int dev_id, char *options)
{
	static char include[PATH_BUFFER_SIZE];

	sprintf(include, "-I %s %s %s%d %s %s", path_expand(pathname),
	        get_device_type(dev_id) == CL_DEVICE_TYPE_CPU ?
	        "-DDEVICE_IS_CPU" : "",
	        "-DDEVICE_INFO=", device_info[dev_id],
#ifdef __APPLE__
	        "-DAPPLE",
#else
	        gpu_nvidia(device_info[dev_id]) ? "-cl-nv-verbose" : "",
#endif
	        OPENCLBUILDOPTIONS);

	if (options) {
		strcat(include, " ");
		strcat(include, options);
	}

	//fprintf(stderr, "Options used: %s\n", include);
	return include;
}

static void build_kernel(int dev_id, char *options)
{
	cl_int build_code;
        char * build_log; size_t log_size;
	const char *srcptr[] = { kernel_source };
	assert(kernel_loaded);
	program[dev_id] =
	    clCreateProgramWithSource(context[dev_id], 1, srcptr, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while creating program");

	build_code = clBuildProgram(program[dev_id], 0, NULL,
		include_source("$JOHN/", dev_id, options), NULL, NULL);

        HANDLE_CLERROR(clGetProgramBuildInfo(program[dev_id], devices[dev_id],
                CL_PROGRAM_BUILD_LOG, 0, NULL,
                &log_size), "Error while getting build info I");
        build_log = (char *) mem_alloc((log_size + 1));

	HANDLE_CLERROR(clGetProgramBuildInfo(program[dev_id], devices[dev_id],
		CL_PROGRAM_BUILD_LOG, log_size + 1, (void *) build_log,
		NULL), "Error while getting build info");

	///Report build errors and warnings
	if (build_code != CL_SUCCESS) {
		// Give us much info about error and exit
		fprintf(stderr, "Compilation log: %s\n", build_log);
		fprintf(stderr, "Error building kernel. Returned build code: %d. DEVICE_INFO=%d\n", build_code, device_info[dev_id]);
		HANDLE_CLERROR (build_code, "clBuildProgram failed.");
	}
#ifdef REPORT_OPENCL_WARNINGS
	else if (strlen(build_log) > 1) // Nvidia may return a single '\n' which is not that interesting
		fprintf(stderr, "Compilation log: %s\n", build_log);
#endif
        MEM_FREE(build_log);
#if 0
	FILE *file;
	size_t source_size;
	char *source;

	HANDLE_CLERROR(clGetProgramInfo(program[dev_id],
		CL_PROGRAM_BINARY_SIZES,
		sizeof(size_t), &source_size, NULL), "error");
	fprintf(stderr, "source size %zu\n", source_size);
	source = malloc(source_size);

	HANDLE_CLERROR(clGetProgramInfo(program[dev_id],
		CL_PROGRAM_BINARIES, sizeof(char *), &source, NULL), "error");

	file = fopen("program.bin", "w");
	if (file == NULL)
		fprintf(stderr, "Error opening binary file\n");
	else if (fwrite(source, source_size, 1, file) != 1)
		fprintf(stderr, "error writing binary\n");
	fclose(file);
	MEM_FREE(source);
#endif
}

static void build_kernel_from_binary(int dev_id)
{
	cl_int build_code;
	const char *srcptr[] = { kernel_source };
	assert(kernel_loaded);
	program[dev_id] =
	    clCreateProgramWithBinary( context[dev_id], 1, &devices[dev_id], &program_size,
                                       (const unsigned char**)srcptr, NULL, &ret_code );
	HANDLE_CLERROR(ret_code, "Error while creating program");

	build_code = clBuildProgram(program[dev_id], 0, NULL,
		include_source("$JOHN/", dev_id, NULL), NULL, NULL);

	HANDLE_CLERROR(clGetProgramBuildInfo(program[dev_id], devices[dev_id],
		CL_PROGRAM_BUILD_LOG, sizeof(opencl_log), (void *) opencl_log,
		NULL), "Error while getting build info");

	///Report build errors and warnings
	if (build_code != CL_SUCCESS) {
		// Give us much info about error and exit
		fprintf(stderr, "Compilation log: %s\n", opencl_log);
		fprintf(stderr, "Error building kernel. Returned build code: %d. DEVICE_INFO=%d\n", build_code, device_info[dev_id]);
		HANDLE_CLERROR (build_code, "clBuildProgram failed.");
	}
#ifdef REPORT_OPENCL_WARNINGS
	else if (strlen(opencl_log) > 1)	// Nvidia may return a single '\n' which is not that interesting
		fprintf(stderr, "Compilation log: %s\n", opencl_log);
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
	opencl_find_best_workgroup_limit(self, UINT_MAX);
}

void opencl_find_best_workgroup_limit(struct fmt_main *self, size_t group_size_limit)
{
	cl_ulong startTime, endTime, kernelExecTimeNs = CL_ULONG_MAX;
	size_t my_work_group, optimal_work_group;
	cl_int ret_code;
	int i, numloops;
	size_t max_group_size, wg_multiple, sumStartTime, sumEndTime;
	char *temp;
	cl_event benchEvent[2];

	if (get_device_version(ocl_gpu_id) < 110) {
		if (get_device_type(ocl_gpu_id) == CL_DEVICE_TYPE_GPU)
			wg_multiple = 32;
		else if (get_platform_vendor_id(ocl_gpu_id) == DEV_INTEL)
			wg_multiple = 8;
		else
			wg_multiple = 1;
	} else {
		HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id],
		    CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE,
		    sizeof(wg_multiple), &wg_multiple, NULL),
	        "Error while getting CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE");
        }

	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id],
		CL_KERNEL_WORK_GROUP_SIZE, sizeof(max_group_size),
		&max_group_size, NULL),
	    "Error while getting CL_KERNEL_WORK_GROUP_SIZE");

        if (max_group_size > group_size_limit)
            //Needed to deal (at least) with cryptsha512-opencl limits.
            max_group_size = group_size_limit;

	// Environment variable override
	if ((temp = getenv("LWS"))) {
		local_work_size = atoi(temp);
		if (local_work_size > max_group_size) {
			fprintf(stderr, "LWS %d is too large for this GPU. Max allowed is %d, using that.\n",
			        (int)local_work_size, (int)max_group_size);
			local_work_size = max_group_size;
		}
		if (local_work_size > 0)
			return;
	}

	// Safety harness
	if (wg_multiple > max_group_size)
		wg_multiple = max_group_size;

	///Command Queue changing:
	///1) Delete old CQ
	clReleaseCommandQueue(queue[ocl_gpu_id]);
	///2) Create new CQ with profiling enabled
	queue[ocl_gpu_id] =
	    clCreateCommandQueue(context[ocl_gpu_id], devices[ocl_gpu_id],
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

	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish error");
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

		if (self->params.max_keys_per_crypt % my_work_group != 0)
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

			HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish error");
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
	clReleaseCommandQueue(queue[ocl_gpu_id]);
	queue[ocl_gpu_id] =
	    clCreateCommandQueue(context[ocl_gpu_id], devices[ocl_gpu_id], 0,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating command queue");
	local_work_size = optimal_work_group;


	//fprintf(stderr, "Optimal local work size = %d\n", (int) local_work_size);
	// Deactivate events (or we'll get a memory leak)
	clReleaseEvent(benchEvent[0]);
	clReleaseEvent(benchEvent[1]);
	profilingEvent = firstEvent = lastEvent = NULL;
}

void opencl_get_dev_info(unsigned int dev_id)
{
	cl_device_type device;

	device = get_device_type(dev_id);

	if (device == CL_DEVICE_TYPE_CPU)
		device_info[dev_id] = DEV_CPU;
	else if (device == CL_DEVICE_TYPE_GPU)
		device_info[dev_id] = DEV_GPU;
	else if (device == CL_DEVICE_TYPE_ACCELERATOR)
		device_info[dev_id] = DEV_ACCELERATOR;

	device_info[dev_id] += get_vendor_id(dev_id);
	device_info[dev_id] += get_processor_family(dev_id);
        device_info[dev_id] += get_byte_addressable(dev_id);
}

void opencl_find_gpu(int *dev_id, int *platform_id)
{
	cl_uint num_platforms, num_devices;
	cl_ulong long_entries;
	int i, d;

	HANDLE_CLERROR(clGetPlatformIDs(MAX_PLATFORMS, platform,
	                                &num_platforms),
	               "Error querying for platforms");

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
	if (*platform_id < 0)
		*platform_id = 0;
	if (*dev_id < 0)
		*dev_id = 0;
	return;
}

void opencl_init_dev(unsigned int dev_id, unsigned int platform_id)
{
	profilingEvent = firstEvent = lastEvent = NULL;
	dev_init(dev_id, platform_id);
	opencl_get_dev_info(dev_id);
}

void opencl_build_kernel_opt(char *kernel_filename, unsigned int dev_id, char *options)
{
	read_kernel_source(kernel_filename);
	build_kernel(dev_id, options);
}

void opencl_build_kernel(char *kernel_filename, unsigned int dev_id)
{
	opencl_build_kernel_opt(kernel_filename, dev_id, NULL);
}

void opencl_build_kernel_from_binary(char *kernel_filename, unsigned int dev_id)
{
	read_kernel_source(kernel_filename);
	build_kernel_from_binary(dev_id);
}

void opencl_init_opt(char *kernel_filename, unsigned int dev_id,
                     unsigned int platform_id, char *options)
{
	kernel_loaded=0;
	opencl_init_dev(dev_id, platform_id);
	opencl_build_kernel_opt(kernel_filename, dev_id, options);
}

void opencl_init(char *kernel_filename, unsigned int dev_id,
                 unsigned int platform_id)
{
	opencl_init_opt(kernel_filename, dev_id, platform_id, NULL);
}

void opencl_init_from_binary(char *kernel_filename, unsigned int dev_id,
    unsigned int platform_id)
{
	kernel_loaded=0;
	opencl_init_dev(dev_id, platform_id);
	opencl_build_kernel_from_binary(kernel_filename, dev_id);
}

cl_device_type get_device_type(int dev_id)
{
	cl_device_type type;
	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id], CL_DEVICE_TYPE,
		sizeof(cl_device_type), &type, NULL),
	    "Error querying CL_DEVICE_TYPE");

	return type;
}

cl_ulong get_local_memory_size(int dev_id)
{
	cl_ulong size;
	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id],
		CL_DEVICE_LOCAL_MEM_SIZE, sizeof(cl_ulong), &size, NULL),
	    "Error querying CL_DEVICE_LOCAL_MEM_SIZE");

	return size;
}

cl_ulong get_global_memory_size(int dev_id)
{
	cl_ulong size;
	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id],
		CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(cl_ulong), &size, NULL),
	    "Error querying CL_DEVICE_GLOBAL_MEM_SIZE");

	return size;
}

size_t get_max_work_group_size(int dev_id)
{
	size_t max_group_size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id],
		CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(max_group_size),
		&max_group_size, NULL),
	    "Error querying CL_DEVICE_MAX_WORK_GROUP_SIZE");

	return max_group_size;
}

cl_ulong get_max_mem_alloc_size(int dev_id)
{
	cl_ulong max_alloc_size;

	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id],
		CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(max_alloc_size),
		&max_alloc_size, NULL),
	    "Error querying CL_DEVICE_MAX_MEM_ALLOC_SIZE");

	return max_alloc_size;
}

size_t get_current_work_group_size(int dev_id, cl_kernel crypt_kernel)
{
	size_t max_group_size;

	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[dev_id],
		CL_KERNEL_WORK_GROUP_SIZE, sizeof(max_group_size),
		&max_group_size, NULL),
	    "Error querying clGetKernelWorkGroupInfo");

	return max_group_size;
}

cl_uint get_max_compute_units(int dev_id)
{
	cl_uint size;
	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id],
		CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cl_uint), &size, NULL),
	    "Error querying CL_DEVICE_MAX_COMPUTE_UNITS");

	return size;
}

#ifdef CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV
void get_compute_capability(int dev_id, unsigned int *major,
    unsigned int *minor)
{
	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id],
		CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV,
		sizeof(cl_uint), major, NULL),
	    "Error querying CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV");
	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id],
		CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV,
		sizeof(cl_uint), minor, NULL),
	    "Error querying CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV");
}
#endif

cl_uint get_processors_count(int dev_id)
{
	cl_uint core_count = get_max_compute_units(dev_id);

	cores_per_MP[dev_id] = 0;
#ifdef CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV
	if (gpu_nvidia(device_info[dev_id])) {
		unsigned int major = 0, minor = 0;

		get_compute_capability(dev_id, &major, &minor);
		if (major == 1)
			core_count *= (cores_per_MP[dev_id] = 8);
		else if (major == 2 && minor == 0)
			core_count *= (cores_per_MP[dev_id] = 32);	//2.0
		else if (major == 2 && minor >= 1)
			core_count *= (cores_per_MP[dev_id] = 48);	//2.1
		else if (major == 3)
			core_count *= (cores_per_MP[dev_id] = 192);	//3.0
	} else
#endif
	if (gpu_amd(device_info[dev_id])) {
		core_count *= (cores_per_MP[dev_id] = (16 *	//16 thread proc * 5 SP
			((amd_gcn(device_info[dev_id]) ||
				amd_vliw4(device_info[dev_id])) ? 4 : 5)));
	} else if (gpu(device_info[dev_id]))	//Any other GPU
		core_count *= (cores_per_MP[dev_id] = 8);

	return core_count;
}

cl_uint get_processor_family(int dev_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id], CL_DEVICE_NAME,
		sizeof(dname), dname, NULL), "Error querying CL_DEVICE_NAME");

	if gpu_amd(device_info[dev_id]) {

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

int get_byte_addressable(int dev_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id], CL_DEVICE_EXTENSIONS,
		sizeof(dname), dname, NULL),
	    "Error querying CL_DEVICE_EXTENSIONS");

	if (strstr(dname, "cl_khr_byte_addressable_store") == NULL)
		return DEV_NO_BYTE_ADDRESSABLE;

	return DEV_UNKNOWN;
}

int get_vendor_id(int dev_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id], CL_DEVICE_VENDOR,
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
		return DEV_APPLE;

	if (strstr(dname, "Intel") != NULL)
		return DEV_INTEL;

	if (strstr(dname, "Advanced Micro") != NULL ||
	    strstr(dname, "AMD") != NULL || strstr(dname, "ATI") != NULL)
		return DEV_AMD;

	return DEV_UNKNOWN;
}

int get_device_version(int dev_id)
{
	char dname[MAX_OCLINFO_STRING_LEN];

        clGetDeviceInfo(devices[dev_id], CL_DEVICE_VERSION,
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
	cl_uint num_platforms, num_devices, entries;
	cl_ulong long_entries;
	int i, d;
	cl_int err;
	size_t p_size;

	/* Obtain list of platforms available */
	err = clGetPlatformIDs(MAX_PLATFORMS, platform, &num_platforms);
	if (err != CL_SUCCESS) {
		fprintf(stderr,
		    "Error: Failure in clGetPlatformIDs, error code=%d \n",
		    err);
		return;
	}
	//printf("%d platforms found\n", num_platforms);

	for (i = 0; i < num_platforms; i++) {
		/* Obtain information about platform */
		clGetPlatformInfo(platform[i], CL_PLATFORM_NAME,
		    MAX_OCLINFO_STRING_LEN, dname, NULL);
		printf("Platform #%d name: %s\n", i, dname);
		clGetPlatformInfo(platform[i], CL_PLATFORM_VERSION,
		    MAX_OCLINFO_STRING_LEN, dname, NULL);
		printf("Platform version: %s\n", dname);

		/* Obtain list of devices available on platform */
		clGetDeviceIDs(platform[i], CL_DEVICE_TYPE_ALL, MAXGPUS,
		    devices, &num_devices);
		if (!num_devices)
			printf("%d devices found\n", num_devices);

		/* Query devices for information */
		for (d = 0; d < num_devices; ++d) {
			cl_device_local_mem_type memtype;
			cl_bool boolean;

			clGetDeviceInfo(devices[d], CL_DEVICE_NAME,
			    MAX_OCLINFO_STRING_LEN, dname, NULL);
			printf("\tDevice #%d name:\t\t%s\n", d, dname);
			clGetDeviceInfo(devices[d], CL_DEVICE_VENDOR,
			    MAX_OCLINFO_STRING_LEN, dname, NULL);
			printf("\tDevice vendor:\t\t%s\n", dname);
			clGetDeviceInfo(devices[d], CL_DEVICE_TYPE,
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
			clGetDeviceInfo(devices[d], CL_DEVICE_ENDIAN_LITTLE,
			    sizeof(cl_bool), &boolean, NULL);
			printf("(%s)\n", boolean == CL_TRUE ? "LE" : "BE");
			clGetDeviceInfo(devices[d], CL_DEVICE_VERSION,
			    MAX_OCLINFO_STRING_LEN, dname, NULL);
			printf("\tDevice version:\t\t%s\n", dname);
			clGetDeviceInfo(devices[d], CL_DRIVER_VERSION,
			    MAX_OCLINFO_STRING_LEN, dname, NULL);
			printf("\tDriver version:\t\t%s\n", dname);
			clGetDeviceInfo(devices[d], CL_DEVICE_GLOBAL_MEM_SIZE,
			    sizeof(cl_ulong), &long_entries, NULL);
			clGetDeviceInfo(devices[d],
			    CL_DEVICE_ERROR_CORRECTION_SUPPORT,
			    sizeof(cl_bool), &boolean, NULL);
			printf("\tGlobal Memory:\t\t%s%s\n",
			    human_format((unsigned long long) long_entries),
			    boolean == CL_TRUE ? " (ECC)" : "");
			clGetDeviceInfo(devices[d],
			    CL_DEVICE_GLOBAL_MEM_CACHE_SIZE, sizeof(cl_ulong),
			    &long_entries, NULL);
			printf("\tGlobal Memory Cache:\t%s\n",
			    human_format((unsigned long long) long_entries));
			clGetDeviceInfo(devices[d], CL_DEVICE_LOCAL_MEM_SIZE,
			    sizeof(cl_ulong), &long_entries, NULL);
			clGetDeviceInfo(devices[d], CL_DEVICE_LOCAL_MEM_TYPE,
			    sizeof(cl_device_local_mem_type), &memtype, NULL);
			printf("\tLocal Memory:\t\t%s (%s)\n",
			    human_format((unsigned long long) long_entries),
			    memtype == CL_LOCAL ? "Local" : "Global");
			clGetDeviceInfo(devices[d],
			    CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(cl_ulong),
			    &long_entries, NULL);
			printf("\tMax clock (MHz) :\t%llu\n",
			    (unsigned long long) long_entries);
			clGetDeviceInfo(devices[d],
			    CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(size_t),
			    &p_size, NULL);
			printf("\tMax Work Group Size:\t%d\n", (int) p_size);
			clGetDeviceInfo(devices[d],
			    CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cl_uint),
			    &entries, NULL);
			printf("\tParallel compute cores:\t%d\n", entries);

			opencl_get_dev_info(d);
			long_entries = get_processors_count(d);
			if (cores_per_MP[d])
				printf
				    ("\tStream processors:\t%llu  (%d x %d)\n",
				    (unsigned long long)long_entries, entries,
				     cores_per_MP[d]);

#ifdef CL_DEVICE_REGISTERS_PER_BLOCK_NV
			if (gpu_nvidia(device_info[d])) {
				unsigned int major = 0, minor = 0;

				clGetDeviceInfo(devices[d],
				    CL_DEVICE_WARP_SIZE_NV, sizeof(cl_uint),
				    &long_entries, NULL);
				printf("\tWarp size:\t\t%llu\n",
				       (unsigned long long)long_entries);

				clGetDeviceInfo(devices[d],
				    CL_DEVICE_REGISTERS_PER_BLOCK_NV,
				    sizeof(cl_uint), &long_entries, NULL);
				printf("\tMax. GPRs/work-group:\t%llu\n",
				    (unsigned long long)long_entries);

				get_compute_capability(d, &major, &minor);
				printf
				    ("\tCompute capability:\t%u.%u (sm_%u%u)\n",
				    major, minor, major, minor);

				clGetDeviceInfo(devices[d],
				    CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV,
				    sizeof(cl_bool), &boolean, NULL);
				printf("\tKernel exec. timeout:\t%s\n",
				    boolean ? "yes" : "no");
			}
#endif
			puts("");
		}
	}
	return;
}

#undef LOG_SIZE
#undef SRC_SIZE

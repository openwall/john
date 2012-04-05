/* Common OpenCL functions go in this file */

#include "common-opencl.h"
#include <assert.h>
#include <string.h>
#define LOG_SIZE 1024*16

static char opencl_log[LOG_SIZE];
static char *kernel_source;
static int kernel_loaded;

void advance_cursor() {
  static int pos=0;
  char cursor[4]={'/','-','\\','|'};
  fprintf(stderr, "%c\b", cursor[pos]);
  fflush(stdout);
  pos = (pos+1) % 4;
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
		HANDLE_CLERROR(!CL_SUCCESS, "Source kernel not found!");
	fseek(fp, 0, SEEK_END);
	source_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	kernel_source = mem_calloc_tiny(source_size, MEM_ALIGN_NONE);
	read_size = fread(kernel_source, sizeof(char), source_size, fp);
	if (read_size != source_size)
		fprintf(stderr, "Error reading source: expected %zu, got %zu bytes.\n", source_size, read_size);
	fclose(fp);
	kernel_loaded = 1;
}

static void dev_init(unsigned int dev_id, unsigned int platform_id)
{
	assert(dev_id < MAXGPUS);
	cl_platform_id platform[MAX_PLATFORMS];
	cl_uint num_platforms, device_num;

	///Find CPU's
	HANDLE_CLERROR(clGetPlatformIDs(MAX_PLATFORMS, platform, &num_platforms),
	    "No OpenCL platform found");
	HANDLE_CLERROR(clGetPlatformInfo(platform[platform_id], CL_PLATFORM_NAME,
		sizeof(opencl_log), opencl_log, NULL),
	    "Error querying PLATFORM_NAME");
	HANDLE_CLERROR(clGetDeviceIDs
	    (platform[platform_id], CL_DEVICE_TYPE_ALL, MAXGPUS, devices, &device_num),
	    "No OpenCL device of that type exist");
	fprintf(stderr, "OpenCL platform %d: %s, %d device(s).\n", platform_id, opencl_log, device_num);
	cl_context_properties properties[] = {
		CL_CONTEXT_PLATFORM, (cl_context_properties) platform[platform_id],
		0
	};
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

cl_device_type get_device_type(int dev_id)
{
	cl_device_type type;
	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id], CL_DEVICE_TYPE,
	                               sizeof(cl_device_type), &type, NULL),
	               "Error querying CL_DEVICE_TYPE");

	return type;
}

static char * include_source(char *pathname, int dev_id)
{
	static char include[PATH_BUFFER_SIZE];

	sprintf(include, "-I %s %s %s", path_expand(pathname),
	        get_device_type(dev_id) == CL_DEVICE_TYPE_CPU ?
	        "-DDEVICE_IS_CPU" : "",
	        "-cl-strict-aliasing -cl-mad-enable");

	//fprintf(stderr, "Options used: %s\n", include);
	return include;
}


static void build_kernel(int dev_id)
{
	assert(kernel_loaded);
	const char *srcptr[] = { kernel_source };
	program[dev_id] =
	    clCreateProgramWithSource(context[dev_id], 1, srcptr, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while creating program");

	cl_int build_code;
	build_code = clBuildProgram(program[dev_id], 0, NULL,
	                            include_source("$JOHN/", dev_id),
	                            NULL, NULL);

	HANDLE_CLERROR(clGetProgramBuildInfo(program[dev_id], devices[dev_id],
		CL_PROGRAM_BUILD_LOG, sizeof(opencl_log), (void *) opencl_log,
		NULL), "Error while getting build info");

	///Report build errors and warnings
	if (build_code != CL_SUCCESS)
		fprintf(stderr, "Compilation log: %s\n", opencl_log);
#ifdef REPORT_OPENCL_WARNINGS
	else if (strlen(opencl_log) > 1) // Nvidia may return a single '\n' which is not that interesting
		fprintf(stderr, "Compilation log: %s\n", opencl_log);
#endif
#if 0
	FILE *file;
	size_t source_size;
	char *source;

	HANDLE_CLERROR(clGetProgramInfo (program[dev_id],
	                                 CL_PROGRAM_BINARY_SIZES,
	                                 sizeof(size_t),
	                                 &source_size,
	                                 NULL), "error");
	fprintf(stderr, "source size %zu\n", source_size);
	source = malloc(source_size);

	HANDLE_CLERROR(clGetProgramInfo (program[dev_id],
	                                 CL_PROGRAM_BINARIES,
	                                 sizeof(char*),
	                                 &source,
	                                 NULL), "error");

	file = fopen("program.bin", "w");
	if(file == NULL)
		fprintf(stderr, "Error opening binary file\n");
	else
		if (fwrite(source, source_size, 1, file) != 1)
			fprintf(stderr, "error writing binary\n");
	fclose(file);
	free(source);
#endif
}

void opencl_init(char *kernel_filename, unsigned int dev_id,
                 unsigned int platform_id)
{
	//if (!kernel_loaded)
		read_kernel_source(kernel_filename);
		dev_init(dev_id, platform_id);
	build_kernel(dev_id);
}

cl_ulong get_local_memory_size(int dev_id)
{
        cl_ulong size;
        HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id], CL_DEVICE_LOCAL_MEM_SIZE,
                sizeof(cl_ulong), &size, NULL),
                "Error querying CL_DEVICE_LOCAL_MEM_SIZE");

        return size;
}

size_t get_max_work_group_size(int dev_id)
{
        size_t max_group_size;

        HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id], CL_DEVICE_MAX_WORK_GROUP_SIZE,
                       sizeof (max_group_size), &max_group_size, NULL),
                       "Error querying CL_DEVICE_MAX_WORK_GROUP_SIZE");

        return max_group_size;
}

cl_uint get_max_compute_units(int dev_id)
{
        cl_uint size;
        HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id], CL_DEVICE_MAX_COMPUTE_UNITS,
                sizeof(cl_uint), &size, NULL),
                "Error querying CL_DEVICE_LOCAL_MEM_SIZE");

        return size;
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

char *megastring(unsigned long long value)
{
	static char outbuf[16];

	if (value >= 10000000000ULL)
		sprintf(outbuf, "%llu GB", value>>30);
	else if (value >= 10000000ULL)
		sprintf(outbuf, "%llu MB", value>>20);
	else if (value >= 10000ULL)
		sprintf(outbuf, "%llu KB", value>>10);
	else
		sprintf(outbuf, "%llu bytes", value);

	return outbuf;
}

#define MAX_OCLINFO_STRING_LEN	64
void listOpenCLdevices(void) {
	char dname[MAX_OCLINFO_STRING_LEN];
	cl_uint num_platforms, num_devices, entries;
	cl_ulong long_entries;
	int i, d;
	cl_int err;
	size_t p_size;

	/* Obtain list of platforms available */
	err = clGetPlatformIDs(MAX_PLATFORMS, platform, &num_platforms);
	if (err != CL_SUCCESS)
	{
		fprintf(stderr, "Error: Failure in clGetPlatformIDs, error code=%d \n", err);
		return;
	}

	//printf("%d platforms found\n", num_platforms);

	for(i = 0; i < num_platforms; i++) {
		/* Obtain information about platform */
		clGetPlatformInfo(platform[i], CL_PLATFORM_NAME, MAX_OCLINFO_STRING_LEN, dname, NULL);
		printf("Platform #%d name: %s\n", i, dname);
		clGetPlatformInfo(platform[i], CL_PLATFORM_VERSION, MAX_OCLINFO_STRING_LEN, dname, NULL);
		printf("Platform version: %s\n", dname);

		/* Obtain list of devices available on platform */
		clGetDeviceIDs(platform[i], CL_DEVICE_TYPE_ALL, MAXGPUS, devices, &num_devices);
		if (!num_devices) printf("%d devices found\n", num_devices);

		/* Query devices for information */
		for (d = 0; d < num_devices; ++d) {
			cl_device_local_mem_type memtype;
			cl_bool bool;

			clGetDeviceInfo(devices[d], CL_DEVICE_NAME, MAX_OCLINFO_STRING_LEN, dname, NULL);
			printf("\tDevice #%d name:\t\t%s\n", d, dname);
			clGetDeviceInfo(devices[d], CL_DEVICE_VENDOR, MAX_OCLINFO_STRING_LEN, dname, NULL);
			printf("\tDevice vendor:\t\t%s\n", dname);
			clGetDeviceInfo(devices[d], CL_DEVICE_TYPE, sizeof(cl_ulong), &long_entries, NULL);
			printf("\tDevice type:\t\t");
			if (long_entries & CL_DEVICE_TYPE_CPU)
				printf("CPU ");
			if (long_entries & CL_DEVICE_TYPE_GPU)
				printf("GPU ");
			if (long_entries & CL_DEVICE_TYPE_ACCELERATOR)
				printf("Accelerator ");
			if (long_entries & CL_DEVICE_TYPE_DEFAULT)
				printf("Default ");
			if (long_entries & ~(CL_DEVICE_TYPE_DEFAULT|CL_DEVICE_TYPE_ACCELERATOR|CL_DEVICE_TYPE_GPU|CL_DEVICE_TYPE_CPU))
				printf("Unknown ");
			clGetDeviceInfo(devices[d], CL_DEVICE_ENDIAN_LITTLE, sizeof(cl_bool), &bool, NULL);
			printf("(%s)\n", bool == CL_TRUE ? "LE" : "BE");
			clGetDeviceInfo(devices[d], CL_DEVICE_VERSION, MAX_OCLINFO_STRING_LEN, dname, NULL);
			printf("\tDevice version:\t\t%s\n", dname);
			clGetDeviceInfo(devices[d], CL_DRIVER_VERSION, MAX_OCLINFO_STRING_LEN, dname, NULL);
			printf("\tDriver version:\t\t%s\n", dname);
			clGetDeviceInfo(devices[d], CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(cl_ulong), &long_entries, NULL);
			clGetDeviceInfo(devices[d], CL_DEVICE_ERROR_CORRECTION_SUPPORT, sizeof(cl_bool), &bool, NULL);
			printf("\tGlobal Memory:\t\t%s%s\n", megastring((unsigned long long)long_entries), bool == CL_TRUE ? " (ECC)" : "");
			clGetDeviceInfo(devices[d], CL_DEVICE_GLOBAL_MEM_CACHE_SIZE, sizeof(cl_ulong), &long_entries, NULL);
			printf("\tGlobal Memory Cache:\t%s\n", megastring((unsigned long long)long_entries));
			clGetDeviceInfo(devices[d], CL_DEVICE_LOCAL_MEM_SIZE, sizeof(cl_ulong), &long_entries, NULL);
			clGetDeviceInfo(devices[d], CL_DEVICE_LOCAL_MEM_TYPE, sizeof(cl_device_local_mem_type), &memtype, NULL);
			printf("\tLocal Memory:\t\t%s (%s)\n", megastring((unsigned long long)long_entries), memtype == CL_LOCAL ? "Local" : "Global");
			clGetDeviceInfo(devices[d], CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(cl_ulong), &long_entries, NULL);
			printf("\tMax clock (MHz) :\t%llu\n", (unsigned long long)long_entries);
			clGetDeviceInfo(devices[d], CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(size_t), &p_size, NULL);
			printf("\tMax Work Group Size:\t%d\n", (int)p_size);
			clGetDeviceInfo(devices[d], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cl_uint), &entries, NULL);
			printf("\tParallel compute cores:\t%d\n\n", entries);
		}
	}
	return;
}

#undef LOG_SIZE
#undef SRC_SIZE

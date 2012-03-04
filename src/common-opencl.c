/* Common OpenCL functions go in this file */

#include "common-opencl.h"
#include <assert.h>
#include <string.h>
#define LOG_SIZE 1024*16
#define SRC_SIZE 1024*16

static char opencl_log[LOG_SIZE];
static char kernel_source[SRC_SIZE];
static int kernel_loaded;

void advance_cursor() {
  static int pos=0;
  char cursor[4]={'/','-','\\','|'};
  printf("%c\b", cursor[pos]);
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
	if (!fp)
		HANDLE_CLERROR(!CL_SUCCESS, "Source kernel not found!");
	size_t source_size = fread(kernel_source, sizeof(char), SRC_SIZE, fp);
	kernel_source[source_size] = 0;
	fclose(fp);
	kernel_loaded = 1;
}

static void dev_init(unsigned int dev_id)
{				//dev is 0 or 1
	assert(dev_id < MAXGPUS);
	cl_platform_id platform;
	cl_uint platforms, device_num;

	///Find CPU's
	HANDLE_CLERROR(clGetPlatformIDs(1, &platform, &platforms),
	    "No OpenCL platform found");
	printf("OpenCL Platforms: %d", platforms);
	HANDLE_CLERROR(clGetPlatformInfo(platform, CL_PLATFORM_NAME,
		sizeof(opencl_log), opencl_log, NULL),
	    "Error querying PLATFORM_NAME");
	printf("\nOpenCL Platform: <<<%s>>>", opencl_log);

	HANDLE_CLERROR(clGetDeviceIDs
	    (platform, CL_DEVICE_TYPE_ALL, MAXGPUS, devices, &device_num),
	    "No OpenCL device of that type exist");

	printf(" %d device(s), ", device_num);
	cl_context_properties properties[] = {
		CL_CONTEXT_PLATFORM, (cl_context_properties) platform,
		0
	};
	HANDLE_CLERROR(clGetDeviceInfo(devices[dev_id], CL_DEVICE_NAME,
		sizeof(opencl_log), opencl_log, NULL),
	    "Error querying DEVICE_NAME");
	printf("using device: <<<%s>>>\n", opencl_log);
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


static void build_kernel(int dev_id)
{
	assert(kernel_loaded);
	const char *srcptr[] = { kernel_source };
	program[dev_id] =
	    clCreateProgramWithSource(context[dev_id], 1, srcptr, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while creating program");

	cl_int build_code;
	build_code = clBuildProgram(program[dev_id], 0, NULL, "", NULL, NULL);

	HANDLE_CLERROR(clGetProgramBuildInfo(program[dev_id], devices[dev_id],
		CL_PROGRAM_BUILD_LOG, sizeof(opencl_log), (void *) opencl_log,
		NULL), "Error while getting build info");

	///Report build errors and warnings
	if (build_code != CL_SUCCESS)
		printf("Compilation log: %s\n", opencl_log);
#ifdef REPORT_OPENCL_WARNINGS
	else if (strlen(opencl_log) > 0)
		printf("Compilation log: %s\n", opencl_log);
#endif
}

void opencl_init(char *kernel_filename, unsigned int dev_id)
{
	//if (!kernel_loaded)
		read_kernel_source(kernel_filename);
	dev_init(dev_id);
	build_kernel(dev_id);
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

#undef LOG_SIZE
#undef SRC_SIZE

/* Common OpenCL functions go in this file */

#include "common-opencl.h"

void if_error_log(cl_int ret_code, const char *message)
{
    if(ret_code != CL_SUCCESS) {
        printf("\nOpenCL: %s\n", message);
        exit(-1);
    }
}

/* TODO: make this function more generic */
void opencl_init(char *kernel_filename, cl_device_type device_type)
{
    // load kernel source
    char *source = (char*)mem_alloc(1024*16);
    char *kernel_path = path_expand(kernel_filename);
    printf("\nKernel path is : %s\n", kernel_path);
    FILE *fp = fopen(kernel_path,"r");
    if(!fp)
        if_error_log(!CL_SUCCESS, "Source kernel not found!");
    size_t source_size = fread(source, sizeof(char), 1024*16, fp);
    source[source_size] = 0;
    fclose(fp);

    // get a platform and its information
    char log[1024*64];
    ret_code = clGetPlatformIDs(1, &platform, NULL);
    if_error_log(ret_code, "No OpenCL platform exist");
    ret_code = clGetPlatformInfo(platform, CL_PLATFORM_NAME, sizeof(log), log, NULL);
    if_error_log(ret_code, "Error querying PLATFORM_NAME");
    printf("\nOpenCL Platform: <<<%s>>>", log);

    // find an OpenCL device
    ret_code = clGetDeviceIDs(platform, device_type, 1, &devices, NULL);
    if_error_log(ret_code, "No OpenCL device of that type exist");
    ret_code = clGetDeviceInfo(devices, CL_DEVICE_NAME, sizeof(log), log, NULL);
    if_error_log(ret_code, "Error querying DEVICE_NAME");
    printf(" and device: <<<%s>>>\n",log);
    ret_code = clGetDeviceInfo(devices, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(max_group_size), &max_group_size, NULL);
    if_error_log(ret_code, "Error querying MAX_WORK_GROUP_SIZE");

    // create a context and command queue on the device.
    context = clCreateContext(NULL, 1, &devices, NULL, NULL, &ret_code);
    if_error_log(ret_code, "Error creating context");
    queue = clCreateCommandQueue(context, devices, 0, &ret_code);
    if_error_log(ret_code, "Error creating command queue");

    // submit the kernel source for compilation
    program = clCreateProgramWithSource(context, 1, (const char **)&source, NULL, &ret_code);
    if_error_log(ret_code,"Error creating program");
    ret_code = clBuildProgram(program, 1, &devices, NULL, NULL, NULL);
    if(ret_code != CL_SUCCESS) {
        printf("failed in clBuildProgram with %d\n", ret_code);
        clGetProgramBuildInfo(program, devices, CL_PROGRAM_BUILD_LOG, sizeof(log), (void*)log, NULL);
        printf("compilation log: %s\n", log);
        exit(-1);
    }
}

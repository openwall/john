//-------------------------------------------------------------------------------------
// Dynamic OpenCL library loader. Automatically generated.
//
// This software is copyright (c) 2023, Alain Espinosa <alainesp at gmail.com> and it
// is hereby released to the general public under the following terms:
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted.
//-------------------------------------------------------------------------------------
#ifdef HAVE_OPENCL

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

// DLL handle
static void* opencl_dll = NULL;
static void load_opencl_dll();

/* clGetPlatformIDs */
static cl_int (*ptr_clGetPlatformIDs)(cl_uint num_entries, cl_platform_id * platforms, cl_uint * num_platforms) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetPlatformIDs(cl_uint num_entries, cl_platform_id * platforms, cl_uint * num_platforms)
{
	load_opencl_dll();

        if (!opencl_dll)
        {
                // Our implementation
                if ((num_entries == 0 && platforms) || (!num_platforms && !platforms))
                        return CL_INVALID_VALUE;

                if (num_platforms)
                        *num_platforms = 0;
                        
                return CL_SUCCESS;
        }
	return ptr_clGetPlatformIDs(num_entries, platforms, num_platforms);
}

/* clGetPlatformInfo */
static cl_int (*ptr_clGetPlatformInfo)(cl_platform_id platform, cl_platform_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetPlatformInfo(cl_platform_id platform, cl_platform_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetPlatformInfo(platform, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clGetDeviceIDs */
static cl_int (*ptr_clGetDeviceIDs)(cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id * devices, cl_uint * num_devices) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetDeviceIDs(cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id * devices, cl_uint * num_devices)
{
	return ptr_clGetDeviceIDs(platform, device_type, num_entries, devices, num_devices);
}

/* clGetDeviceInfo */
static cl_int (*ptr_clGetDeviceInfo)(cl_device_id device, cl_device_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetDeviceInfo(cl_device_id device, cl_device_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetDeviceInfo(device, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clCreateSubDevices */
static cl_int (*ptr_clCreateSubDevices)(cl_device_id in_device, const cl_device_partition_property * properties, cl_uint num_devices, cl_device_id * out_devices, cl_uint * num_devices_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clCreateSubDevices(cl_device_id in_device, const cl_device_partition_property * properties, cl_uint num_devices, cl_device_id * out_devices, cl_uint * num_devices_ret)
{
	return ptr_clCreateSubDevices(in_device, properties, num_devices, out_devices, num_devices_ret);
}

/* clRetainDevice */
static cl_int (*ptr_clRetainDevice)(cl_device_id device) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clRetainDevice(cl_device_id device)
{
	return ptr_clRetainDevice(device);
}

/* clReleaseDevice */
static cl_int (*ptr_clReleaseDevice)(cl_device_id device) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clReleaseDevice(cl_device_id device)
{
	return ptr_clReleaseDevice(device);
}

/* clCreateContext */
static cl_context (*ptr_clCreateContext)(const cl_context_properties * properties, cl_uint num_devices, const cl_device_id * devices, void (CL_CALLBACK * pfn_notify)(const char * errinfo, const void * private_info, size_t cb, void * user_data), void * user_data, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_context CL_API_CALL clCreateContext(const cl_context_properties * properties, cl_uint num_devices, const cl_device_id * devices, void (CL_CALLBACK * pfn_notify)(const char * errinfo, const void * private_info, size_t cb, void * user_data), void * user_data, cl_int * errcode_ret)
{
	return ptr_clCreateContext(properties, num_devices, devices, pfn_notify, user_data, errcode_ret);
}

/* clCreateContextFromType */
static cl_context (*ptr_clCreateContextFromType)(const cl_context_properties * properties, cl_device_type device_type, void (CL_CALLBACK * pfn_notify)(const char * errinfo, const void * private_info, size_t cb, void * user_data), void * user_data, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_context CL_API_CALL clCreateContextFromType(const cl_context_properties * properties, cl_device_type device_type, void (CL_CALLBACK * pfn_notify)(const char * errinfo, const void * private_info, size_t cb, void * user_data), void * user_data, cl_int * errcode_ret)
{
	return ptr_clCreateContextFromType(properties, device_type, pfn_notify, user_data, errcode_ret);
}

/* clRetainContext */
static cl_int (*ptr_clRetainContext)(cl_context context) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clRetainContext(cl_context context)
{
	return ptr_clRetainContext(context);
}

/* clReleaseContext */
static cl_int (*ptr_clReleaseContext)(cl_context context) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clReleaseContext(cl_context context)
{
	return ptr_clReleaseContext(context);
}

/* clGetContextInfo */
static cl_int (*ptr_clGetContextInfo)(cl_context context, cl_context_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetContextInfo(cl_context context, cl_context_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetContextInfo(context, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clRetainCommandQueue */
static cl_int (*ptr_clRetainCommandQueue)(cl_command_queue command_queue) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clRetainCommandQueue(cl_command_queue command_queue)
{
	return ptr_clRetainCommandQueue(command_queue);
}

/* clReleaseCommandQueue */
static cl_int (*ptr_clReleaseCommandQueue)(cl_command_queue command_queue) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clReleaseCommandQueue(cl_command_queue command_queue)
{
	return ptr_clReleaseCommandQueue(command_queue);
}

/* clGetCommandQueueInfo */
static cl_int (*ptr_clGetCommandQueueInfo)(cl_command_queue command_queue, cl_command_queue_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetCommandQueueInfo(cl_command_queue command_queue, cl_command_queue_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetCommandQueueInfo(command_queue, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clCreateBuffer */
static cl_mem (*ptr_clCreateBuffer)(cl_context context, cl_mem_flags flags, size_t size, void * host_ptr, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_mem CL_API_CALL clCreateBuffer(cl_context context, cl_mem_flags flags, size_t size, void * host_ptr, cl_int * errcode_ret)
{
	return ptr_clCreateBuffer(context, flags, size, host_ptr, errcode_ret);
}

/* clCreateSubBuffer */
static cl_mem (*ptr_clCreateSubBuffer)(cl_mem buffer, cl_mem_flags flags, cl_buffer_create_type buffer_create_type, const void * buffer_create_info, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_mem CL_API_CALL clCreateSubBuffer(cl_mem buffer, cl_mem_flags flags, cl_buffer_create_type buffer_create_type, const void * buffer_create_info, cl_int * errcode_ret)
{
	return ptr_clCreateSubBuffer(buffer, flags, buffer_create_type, buffer_create_info, errcode_ret);
}

/* clCreateImage */
static cl_mem (*ptr_clCreateImage)(cl_context context, cl_mem_flags flags, const cl_image_format * image_format, const cl_image_desc * image_desc, void * host_ptr, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_mem CL_API_CALL clCreateImage(cl_context context, cl_mem_flags flags, const cl_image_format * image_format, const cl_image_desc * image_desc, void * host_ptr, cl_int * errcode_ret)
{
	return ptr_clCreateImage(context, flags, image_format, image_desc, host_ptr, errcode_ret);
}

/* clRetainMemObject */
static cl_int (*ptr_clRetainMemObject)(cl_mem memobj) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clRetainMemObject(cl_mem memobj)
{
	return ptr_clRetainMemObject(memobj);
}

/* clReleaseMemObject */
static cl_int (*ptr_clReleaseMemObject)(cl_mem memobj) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clReleaseMemObject(cl_mem memobj)
{
	return ptr_clReleaseMemObject(memobj);
}

/* clGetSupportedImageFormats */
static cl_int (*ptr_clGetSupportedImageFormats)(cl_context context, cl_mem_flags flags, cl_mem_object_type image_type, cl_uint num_entries, cl_image_format * image_formats, cl_uint * num_image_formats) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetSupportedImageFormats(cl_context context, cl_mem_flags flags, cl_mem_object_type image_type, cl_uint num_entries, cl_image_format * image_formats, cl_uint * num_image_formats)
{
	return ptr_clGetSupportedImageFormats(context, flags, image_type, num_entries, image_formats, num_image_formats);
}

/* clGetMemObjectInfo */
static cl_int (*ptr_clGetMemObjectInfo)(cl_mem memobj, cl_mem_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetMemObjectInfo(cl_mem memobj, cl_mem_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetMemObjectInfo(memobj, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clGetImageInfo */
static cl_int (*ptr_clGetImageInfo)(cl_mem image, cl_image_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetImageInfo(cl_mem image, cl_image_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetImageInfo(image, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clSetMemObjectDestructorCallback */
static cl_int (*ptr_clSetMemObjectDestructorCallback)(cl_mem memobj, void (CL_CALLBACK * pfn_notify)(cl_mem memobj, void * user_data), void * user_data) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clSetMemObjectDestructorCallback(cl_mem memobj, void (CL_CALLBACK * pfn_notify)(cl_mem memobj, void * user_data), void * user_data)
{
	return ptr_clSetMemObjectDestructorCallback(memobj, pfn_notify, user_data);
}

/* clRetainSampler */
static cl_int (*ptr_clRetainSampler)(cl_sampler sampler) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clRetainSampler(cl_sampler sampler)
{
	return ptr_clRetainSampler(sampler);
}

/* clReleaseSampler */
static cl_int (*ptr_clReleaseSampler)(cl_sampler sampler) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clReleaseSampler(cl_sampler sampler)
{
	return ptr_clReleaseSampler(sampler);
}

/* clGetSamplerInfo */
static cl_int (*ptr_clGetSamplerInfo)(cl_sampler sampler, cl_sampler_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetSamplerInfo(cl_sampler sampler, cl_sampler_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetSamplerInfo(sampler, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clCreateProgramWithSource */
static cl_program (*ptr_clCreateProgramWithSource)(cl_context context, cl_uint count, const char ** strings, const size_t * lengths, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_program CL_API_CALL clCreateProgramWithSource(cl_context context, cl_uint count, const char ** strings, const size_t * lengths, cl_int * errcode_ret)
{
	return ptr_clCreateProgramWithSource(context, count, strings, lengths, errcode_ret);
}

/* clCreateProgramWithBinary */
static cl_program (*ptr_clCreateProgramWithBinary)(cl_context context, cl_uint num_devices, const cl_device_id * device_list, const size_t * lengths, const unsigned char ** binaries, cl_int * binary_status, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_program CL_API_CALL clCreateProgramWithBinary(cl_context context, cl_uint num_devices, const cl_device_id * device_list, const size_t * lengths, const unsigned char ** binaries, cl_int * binary_status, cl_int * errcode_ret)
{
	return ptr_clCreateProgramWithBinary(context, num_devices, device_list, lengths, binaries, binary_status, errcode_ret);
}

/* clCreateProgramWithBuiltInKernels */
static cl_program (*ptr_clCreateProgramWithBuiltInKernels)(cl_context context, cl_uint num_devices, const cl_device_id * device_list, const char * kernel_names, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_program CL_API_CALL clCreateProgramWithBuiltInKernels(cl_context context, cl_uint num_devices, const cl_device_id * device_list, const char * kernel_names, cl_int * errcode_ret)
{
	return ptr_clCreateProgramWithBuiltInKernels(context, num_devices, device_list, kernel_names, errcode_ret);
}

/* clRetainProgram */
static cl_int (*ptr_clRetainProgram)(cl_program program) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clRetainProgram(cl_program program)
{
	return ptr_clRetainProgram(program);
}

/* clReleaseProgram */
static cl_int (*ptr_clReleaseProgram)(cl_program program) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clReleaseProgram(cl_program program)
{
	return ptr_clReleaseProgram(program);
}

/* clBuildProgram */
static cl_int (*ptr_clBuildProgram)(cl_program program, cl_uint num_devices, const cl_device_id * device_list, const char * options, void (CL_CALLBACK * pfn_notify)(cl_program program, void * user_data), void * user_data) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clBuildProgram(cl_program program, cl_uint num_devices, const cl_device_id * device_list, const char * options, void (CL_CALLBACK * pfn_notify)(cl_program program, void * user_data), void * user_data)
{
	return ptr_clBuildProgram(program, num_devices, device_list, options, pfn_notify, user_data);
}

/* clCompileProgram */
static cl_int (*ptr_clCompileProgram)(cl_program program, cl_uint num_devices, const cl_device_id * device_list, const char * options, cl_uint num_input_headers, const cl_program * input_headers, const char ** header_include_names, void (CL_CALLBACK * pfn_notify)(cl_program program, void * user_data), void * user_data) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clCompileProgram(cl_program program, cl_uint num_devices, const cl_device_id * device_list, const char * options, cl_uint num_input_headers, const cl_program * input_headers, const char ** header_include_names, void (CL_CALLBACK * pfn_notify)(cl_program program, void * user_data), void * user_data)
{
	return ptr_clCompileProgram(program, num_devices, device_list, options, num_input_headers, input_headers, header_include_names, pfn_notify, user_data);
}

/* clLinkProgram */
static cl_program (*ptr_clLinkProgram)(cl_context context, cl_uint num_devices, const cl_device_id * device_list, const char * options, cl_uint num_input_programs, const cl_program * input_programs, void (CL_CALLBACK * pfn_notify)(cl_program program, void * user_data), void * user_data, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_program CL_API_CALL clLinkProgram(cl_context context, cl_uint num_devices, const cl_device_id * device_list, const char * options, cl_uint num_input_programs, const cl_program * input_programs, void (CL_CALLBACK * pfn_notify)(cl_program program, void * user_data), void * user_data, cl_int * errcode_ret)
{
	return ptr_clLinkProgram(context, num_devices, device_list, options, num_input_programs, input_programs, pfn_notify, user_data, errcode_ret);
}

/* clUnloadPlatformCompiler */
static cl_int (*ptr_clUnloadPlatformCompiler)(cl_platform_id platform) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clUnloadPlatformCompiler(cl_platform_id platform)
{
	return ptr_clUnloadPlatformCompiler(platform);
}

/* clGetProgramInfo */
static cl_int (*ptr_clGetProgramInfo)(cl_program program, cl_program_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetProgramInfo(cl_program program, cl_program_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetProgramInfo(program, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clGetProgramBuildInfo */
static cl_int (*ptr_clGetProgramBuildInfo)(cl_program program, cl_device_id device, cl_program_build_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetProgramBuildInfo(cl_program program, cl_device_id device, cl_program_build_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetProgramBuildInfo(program, device, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clCreateKernel */
static cl_kernel (*ptr_clCreateKernel)(cl_program program, const char * kernel_name, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_kernel CL_API_CALL clCreateKernel(cl_program program, const char * kernel_name, cl_int * errcode_ret)
{
	return ptr_clCreateKernel(program, kernel_name, errcode_ret);
}

/* clCreateKernelsInProgram */
static cl_int (*ptr_clCreateKernelsInProgram)(cl_program program, cl_uint num_kernels, cl_kernel * kernels, cl_uint * num_kernels_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clCreateKernelsInProgram(cl_program program, cl_uint num_kernels, cl_kernel * kernels, cl_uint * num_kernels_ret)
{
	return ptr_clCreateKernelsInProgram(program, num_kernels, kernels, num_kernels_ret);
}

/* clRetainKernel */
static cl_int (*ptr_clRetainKernel)(cl_kernel kernel) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clRetainKernel(cl_kernel kernel)
{
	return ptr_clRetainKernel(kernel);
}

/* clReleaseKernel */
static cl_int (*ptr_clReleaseKernel)(cl_kernel kernel) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clReleaseKernel(cl_kernel kernel)
{
	return ptr_clReleaseKernel(kernel);
}

/* clSetKernelArg */
static cl_int (*ptr_clSetKernelArg)(cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void * arg_value) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clSetKernelArg(cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void * arg_value)
{
	return ptr_clSetKernelArg(kernel, arg_index, arg_size, arg_value);
}

/* clGetKernelInfo */
static cl_int (*ptr_clGetKernelInfo)(cl_kernel kernel, cl_kernel_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetKernelInfo(cl_kernel kernel, cl_kernel_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetKernelInfo(kernel, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clGetKernelArgInfo */
static cl_int (*ptr_clGetKernelArgInfo)(cl_kernel kernel, cl_uint arg_indx, cl_kernel_arg_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetKernelArgInfo(cl_kernel kernel, cl_uint arg_indx, cl_kernel_arg_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetKernelArgInfo(kernel, arg_indx, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clGetKernelWorkGroupInfo */
static cl_int (*ptr_clGetKernelWorkGroupInfo)(cl_kernel kernel, cl_device_id device, cl_kernel_work_group_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetKernelWorkGroupInfo(cl_kernel kernel, cl_device_id device, cl_kernel_work_group_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetKernelWorkGroupInfo(kernel, device, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clWaitForEvents */
static cl_int (*ptr_clWaitForEvents)(cl_uint num_events, const cl_event * event_list) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clWaitForEvents(cl_uint num_events, const cl_event * event_list)
{
	return ptr_clWaitForEvents(num_events, event_list);
}

/* clGetEventInfo */
static cl_int (*ptr_clGetEventInfo)(cl_event event, cl_event_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetEventInfo(cl_event event, cl_event_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetEventInfo(event, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clCreateUserEvent */
static cl_event (*ptr_clCreateUserEvent)(cl_context context, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_event CL_API_CALL clCreateUserEvent(cl_context context, cl_int * errcode_ret)
{
	return ptr_clCreateUserEvent(context, errcode_ret);
}

/* clRetainEvent */
static cl_int (*ptr_clRetainEvent)(cl_event event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clRetainEvent(cl_event event)
{
	return ptr_clRetainEvent(event);
}

/* clReleaseEvent */
static cl_int (*ptr_clReleaseEvent)(cl_event event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clReleaseEvent(cl_event event)
{
	return ptr_clReleaseEvent(event);
}

/* clSetUserEventStatus */
static cl_int (*ptr_clSetUserEventStatus)(cl_event event, cl_int execution_status) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clSetUserEventStatus(cl_event event, cl_int execution_status)
{
	return ptr_clSetUserEventStatus(event, execution_status);
}

/* clSetEventCallback */
static cl_int (*ptr_clSetEventCallback)(cl_event event, cl_int command_exec_callback_type, void (CL_CALLBACK * pfn_notify)(cl_event event, cl_int event_command_status, void * user_data), void * user_data) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clSetEventCallback(cl_event event, cl_int command_exec_callback_type, void (CL_CALLBACK * pfn_notify)(cl_event event, cl_int event_command_status, void * user_data), void * user_data)
{
	return ptr_clSetEventCallback(event, command_exec_callback_type, pfn_notify, user_data);
}

/* clGetEventProfilingInfo */
static cl_int (*ptr_clGetEventProfilingInfo)(cl_event event, cl_profiling_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clGetEventProfilingInfo(cl_event event, cl_profiling_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetEventProfilingInfo(event, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clFlush */
static cl_int (*ptr_clFlush)(cl_command_queue command_queue) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clFlush(cl_command_queue command_queue)
{
	return ptr_clFlush(command_queue);
}

/* clFinish */
static cl_int (*ptr_clFinish)(cl_command_queue command_queue) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clFinish(cl_command_queue command_queue)
{
	return ptr_clFinish(command_queue);
}

/* clEnqueueReadBuffer */
static cl_int (*ptr_clEnqueueReadBuffer)(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t size, void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueReadBuffer(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t size, void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueReadBuffer(command_queue, buffer, blocking_read, offset, size, ptr, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueReadBufferRect */
static cl_int (*ptr_clEnqueueReadBufferRect)(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, const size_t * buffer_origin, const size_t * host_origin, const size_t * region, size_t buffer_row_pitch, size_t buffer_slice_pitch, size_t host_row_pitch, size_t host_slice_pitch, void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueReadBufferRect(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, const size_t * buffer_origin, const size_t * host_origin, const size_t * region, size_t buffer_row_pitch, size_t buffer_slice_pitch, size_t host_row_pitch, size_t host_slice_pitch, void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueReadBufferRect(command_queue, buffer, blocking_read, buffer_origin, host_origin, region, buffer_row_pitch, buffer_slice_pitch, host_row_pitch, host_slice_pitch, ptr, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueWriteBuffer */
static cl_int (*ptr_clEnqueueWriteBuffer)(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t size, const void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueWriteBuffer(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t size, const void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueWriteBuffer(command_queue, buffer, blocking_write, offset, size, ptr, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueWriteBufferRect */
static cl_int (*ptr_clEnqueueWriteBufferRect)(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, const size_t * buffer_origin, const size_t * host_origin, const size_t * region, size_t buffer_row_pitch, size_t buffer_slice_pitch, size_t host_row_pitch, size_t host_slice_pitch, const void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueWriteBufferRect(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, const size_t * buffer_origin, const size_t * host_origin, const size_t * region, size_t buffer_row_pitch, size_t buffer_slice_pitch, size_t host_row_pitch, size_t host_slice_pitch, const void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueWriteBufferRect(command_queue, buffer, blocking_write, buffer_origin, host_origin, region, buffer_row_pitch, buffer_slice_pitch, host_row_pitch, host_slice_pitch, ptr, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueFillBuffer */
static cl_int (*ptr_clEnqueueFillBuffer)(cl_command_queue command_queue, cl_mem buffer, const void * pattern, size_t pattern_size, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueFillBuffer(cl_command_queue command_queue, cl_mem buffer, const void * pattern, size_t pattern_size, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueFillBuffer(command_queue, buffer, pattern, pattern_size, offset, size, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueCopyBuffer */
static cl_int (*ptr_clEnqueueCopyBuffer)(cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueCopyBuffer(cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueCopyBuffer(command_queue, src_buffer, dst_buffer, src_offset, dst_offset, size, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueCopyBufferRect */
static cl_int (*ptr_clEnqueueCopyBufferRect)(cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, const size_t * src_origin, const size_t * dst_origin, const size_t * region, size_t src_row_pitch, size_t src_slice_pitch, size_t dst_row_pitch, size_t dst_slice_pitch, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueCopyBufferRect(cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, const size_t * src_origin, const size_t * dst_origin, const size_t * region, size_t src_row_pitch, size_t src_slice_pitch, size_t dst_row_pitch, size_t dst_slice_pitch, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueCopyBufferRect(command_queue, src_buffer, dst_buffer, src_origin, dst_origin, region, src_row_pitch, src_slice_pitch, dst_row_pitch, dst_slice_pitch, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueReadImage */
static cl_int (*ptr_clEnqueueReadImage)(cl_command_queue command_queue, cl_mem image, cl_bool blocking_read, const size_t * origin, const size_t * region, size_t row_pitch, size_t slice_pitch, void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueReadImage(cl_command_queue command_queue, cl_mem image, cl_bool blocking_read, const size_t * origin, const size_t * region, size_t row_pitch, size_t slice_pitch, void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueReadImage(command_queue, image, blocking_read, origin, region, row_pitch, slice_pitch, ptr, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueWriteImage */
static cl_int (*ptr_clEnqueueWriteImage)(cl_command_queue command_queue, cl_mem image, cl_bool blocking_write, const size_t * origin, const size_t * region, size_t input_row_pitch, size_t input_slice_pitch, const void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueWriteImage(cl_command_queue command_queue, cl_mem image, cl_bool blocking_write, const size_t * origin, const size_t * region, size_t input_row_pitch, size_t input_slice_pitch, const void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueWriteImage(command_queue, image, blocking_write, origin, region, input_row_pitch, input_slice_pitch, ptr, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueFillImage */
static cl_int (*ptr_clEnqueueFillImage)(cl_command_queue command_queue, cl_mem image, const void * fill_color, const size_t * origin, const size_t * region, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueFillImage(cl_command_queue command_queue, cl_mem image, const void * fill_color, const size_t * origin, const size_t * region, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueFillImage(command_queue, image, fill_color, origin, region, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueCopyImage */
static cl_int (*ptr_clEnqueueCopyImage)(cl_command_queue command_queue, cl_mem src_image, cl_mem dst_image, const size_t * src_origin, const size_t * dst_origin, const size_t * region, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueCopyImage(cl_command_queue command_queue, cl_mem src_image, cl_mem dst_image, const size_t * src_origin, const size_t * dst_origin, const size_t * region, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueCopyImage(command_queue, src_image, dst_image, src_origin, dst_origin, region, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueCopyImageToBuffer */
static cl_int (*ptr_clEnqueueCopyImageToBuffer)(cl_command_queue command_queue, cl_mem src_image, cl_mem dst_buffer, const size_t * src_origin, const size_t * region, size_t dst_offset, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueCopyImageToBuffer(cl_command_queue command_queue, cl_mem src_image, cl_mem dst_buffer, const size_t * src_origin, const size_t * region, size_t dst_offset, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueCopyImageToBuffer(command_queue, src_image, dst_buffer, src_origin, region, dst_offset, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueCopyBufferToImage */
static cl_int (*ptr_clEnqueueCopyBufferToImage)(cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_image, size_t src_offset, const size_t * dst_origin, const size_t * region, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueCopyBufferToImage(cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_image, size_t src_offset, const size_t * dst_origin, const size_t * region, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueCopyBufferToImage(command_queue, src_buffer, dst_image, src_offset, dst_origin, region, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueMapBuffer */
static void * (*ptr_clEnqueueMapBuffer)(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_map, cl_map_flags map_flags, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event, cl_int * errcode_ret) = NULL;
CL_API_ENTRY void * CL_API_CALL clEnqueueMapBuffer(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_map, cl_map_flags map_flags, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event, cl_int * errcode_ret)
{
	return ptr_clEnqueueMapBuffer(command_queue, buffer, blocking_map, map_flags, offset, size, num_events_in_wait_list, event_wait_list, event, errcode_ret);
}

/* clEnqueueMapImage */
static void * (*ptr_clEnqueueMapImage)(cl_command_queue command_queue, cl_mem image, cl_bool blocking_map, cl_map_flags map_flags, const size_t * origin, const size_t * region, size_t * image_row_pitch, size_t * image_slice_pitch, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event, cl_int * errcode_ret) = NULL;
CL_API_ENTRY void * CL_API_CALL clEnqueueMapImage(cl_command_queue command_queue, cl_mem image, cl_bool blocking_map, cl_map_flags map_flags, const size_t * origin, const size_t * region, size_t * image_row_pitch, size_t * image_slice_pitch, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event, cl_int * errcode_ret)
{
	return ptr_clEnqueueMapImage(command_queue, image, blocking_map, map_flags, origin, region, image_row_pitch, image_slice_pitch, num_events_in_wait_list, event_wait_list, event, errcode_ret);
}

/* clEnqueueUnmapMemObject */
static cl_int (*ptr_clEnqueueUnmapMemObject)(cl_command_queue command_queue, cl_mem memobj, void * mapped_ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueUnmapMemObject(cl_command_queue command_queue, cl_mem memobj, void * mapped_ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueUnmapMemObject(command_queue, memobj, mapped_ptr, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueMigrateMemObjects */
static cl_int (*ptr_clEnqueueMigrateMemObjects)(cl_command_queue command_queue, cl_uint num_mem_objects, const cl_mem * mem_objects, cl_mem_migration_flags flags, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueMigrateMemObjects(cl_command_queue command_queue, cl_uint num_mem_objects, const cl_mem * mem_objects, cl_mem_migration_flags flags, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueMigrateMemObjects(command_queue, num_mem_objects, mem_objects, flags, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueNDRangeKernel */
static cl_int (*ptr_clEnqueueNDRangeKernel)(cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t * global_work_offset, const size_t * global_work_size, const size_t * local_work_size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueNDRangeKernel(cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t * global_work_offset, const size_t * global_work_size, const size_t * local_work_size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueNDRangeKernel(command_queue, kernel, work_dim, global_work_offset, global_work_size, local_work_size, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueNativeKernel */
static cl_int (*ptr_clEnqueueNativeKernel)(cl_command_queue command_queue, void (CL_CALLBACK * user_func)(void *), void * args, size_t cb_args, cl_uint num_mem_objects, const cl_mem * mem_list, const void ** args_mem_loc, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueNativeKernel(cl_command_queue command_queue, void (CL_CALLBACK * user_func)(void *), void * args, size_t cb_args, cl_uint num_mem_objects, const cl_mem * mem_list, const void ** args_mem_loc, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueNativeKernel(command_queue, user_func, args, cb_args, num_mem_objects, mem_list, args_mem_loc, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueMarkerWithWaitList */
static cl_int (*ptr_clEnqueueMarkerWithWaitList)(cl_command_queue command_queue, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueMarkerWithWaitList(cl_command_queue command_queue, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueMarkerWithWaitList(command_queue, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueBarrierWithWaitList */
static cl_int (*ptr_clEnqueueBarrierWithWaitList)(cl_command_queue command_queue, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueBarrierWithWaitList(cl_command_queue command_queue, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueBarrierWithWaitList(command_queue, num_events_in_wait_list, event_wait_list, event);
}

/* clGetExtensionFunctionAddressForPlatform */
static void * (*ptr_clGetExtensionFunctionAddressForPlatform)(cl_platform_id platform, const char * func_name) = NULL;
CL_API_ENTRY void * CL_API_CALL clGetExtensionFunctionAddressForPlatform(cl_platform_id platform, const char * func_name)
{
	return ptr_clGetExtensionFunctionAddressForPlatform(platform, func_name);
}

/* clSetCommandQueueProperty */
static cl_int (*ptr_clSetCommandQueueProperty)(cl_command_queue command_queue, cl_command_queue_properties properties, cl_bool enable, cl_command_queue_properties * old_properties) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clSetCommandQueueProperty(cl_command_queue command_queue, cl_command_queue_properties properties, cl_bool enable, cl_command_queue_properties * old_properties)
{
	return ptr_clSetCommandQueueProperty(command_queue, properties, enable, old_properties);
}

/* clCreateImage2D */
static cl_mem (*ptr_clCreateImage2D)(cl_context context, cl_mem_flags flags, const cl_image_format * image_format, size_t image_width, size_t image_height, size_t image_row_pitch, void * host_ptr, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_mem CL_API_CALL clCreateImage2D(cl_context context, cl_mem_flags flags, const cl_image_format * image_format, size_t image_width, size_t image_height, size_t image_row_pitch, void * host_ptr, cl_int * errcode_ret)
{
	return ptr_clCreateImage2D(context, flags, image_format, image_width, image_height, image_row_pitch, host_ptr, errcode_ret);
}

/* clCreateImage3D */
static cl_mem (*ptr_clCreateImage3D)(cl_context context, cl_mem_flags flags, const cl_image_format * image_format, size_t image_width, size_t image_height, size_t image_depth, size_t image_row_pitch, size_t image_slice_pitch, void * host_ptr, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_mem CL_API_CALL clCreateImage3D(cl_context context, cl_mem_flags flags, const cl_image_format * image_format, size_t image_width, size_t image_height, size_t image_depth, size_t image_row_pitch, size_t image_slice_pitch, void * host_ptr, cl_int * errcode_ret)
{
	return ptr_clCreateImage3D(context, flags, image_format, image_width, image_height, image_depth, image_row_pitch, image_slice_pitch, host_ptr, errcode_ret);
}

/* clEnqueueMarker */
static cl_int (*ptr_clEnqueueMarker)(cl_command_queue command_queue, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueMarker(cl_command_queue command_queue, cl_event * event)
{
	return ptr_clEnqueueMarker(command_queue, event);
}

/* clEnqueueWaitForEvents */
static cl_int (*ptr_clEnqueueWaitForEvents)(cl_command_queue command_queue, cl_uint num_events, const cl_event * event_list) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueWaitForEvents(cl_command_queue command_queue, cl_uint num_events, const cl_event * event_list)
{
	return ptr_clEnqueueWaitForEvents(command_queue, num_events, event_list);
}

/* clEnqueueBarrier */
static cl_int (*ptr_clEnqueueBarrier)(cl_command_queue command_queue) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueBarrier(cl_command_queue command_queue)
{
	return ptr_clEnqueueBarrier(command_queue);
}

/* clUnloadCompiler */
static cl_int (*ptr_clUnloadCompiler)(void) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clUnloadCompiler(void)
{
	return ptr_clUnloadCompiler();
}

/* clGetExtensionFunctionAddress */
static void * (*ptr_clGetExtensionFunctionAddress)(const char * func_name) = NULL;
CL_API_ENTRY void * CL_API_CALL clGetExtensionFunctionAddress(const char * func_name)
{
	return ptr_clGetExtensionFunctionAddress(func_name);
}

/* clCreateCommandQueue */
static cl_command_queue (*ptr_clCreateCommandQueue)(cl_context context, cl_device_id device, cl_command_queue_properties properties, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_command_queue CL_API_CALL clCreateCommandQueue(cl_context context, cl_device_id device, cl_command_queue_properties properties, cl_int * errcode_ret)
{
	return ptr_clCreateCommandQueue(context, device, properties, errcode_ret);
}

/* clCreateSampler */
static cl_sampler (*ptr_clCreateSampler)(cl_context context, cl_bool normalized_coords, cl_addressing_mode addressing_mode, cl_filter_mode filter_mode, cl_int * errcode_ret) = NULL;
CL_API_ENTRY cl_sampler CL_API_CALL clCreateSampler(cl_context context, cl_bool normalized_coords, cl_addressing_mode addressing_mode, cl_filter_mode filter_mode, cl_int * errcode_ret)
{
	return ptr_clCreateSampler(context, normalized_coords, addressing_mode, filter_mode, errcode_ret);
}

/* clEnqueueTask */
static cl_int (*ptr_clEnqueueTask)(cl_command_queue command_queue, cl_kernel kernel, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event) = NULL;
CL_API_ENTRY cl_int CL_API_CALL clEnqueueTask(cl_command_queue command_queue, cl_kernel kernel, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueTask(command_queue, kernel, num_events_in_wait_list, event_wait_list, event);
}


#include <dlfcn.h>
#include <stdio.h>
static void load_opencl_dll()
{
        int i;
        if (opencl_dll)
            return;

        // Names to try to load
        const char* opencl_names[] = {
            "libOpenCL.so",      // Linux/others
            "OpenCL",            // _WIN
            "/System/Library/Frameworks/OpenCL.framework/OpenCL", // __APPLE__
            "opencl.dll",        // __CYGWIN__
            "cygOpenCL-1.dll",   // __CYGWIN__
            "libOpenCL.so.1"     // Linux/others
        };
        for (i = 0; i < sizeof(opencl_names)/sizeof(opencl_names[0]); i++)
        {
            opencl_dll = dlopen(opencl_names[i], RTLD_NOW);
            if (opencl_dll) break;
        }      
          
        // Load function pointers
        if (opencl_dll)
        {
                int all_functions_loaded = 1;

		ptr_clGetPlatformIDs = dlsym(opencl_dll, "clGetPlatformIDs");
		if (!ptr_clGetPlatformIDs)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetPlatformIDs function\n");
		}
		ptr_clGetPlatformInfo = dlsym(opencl_dll, "clGetPlatformInfo");
		if (!ptr_clGetPlatformInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetPlatformInfo function\n");
		}
		ptr_clGetDeviceIDs = dlsym(opencl_dll, "clGetDeviceIDs");
		if (!ptr_clGetDeviceIDs)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetDeviceIDs function\n");
		}
		ptr_clGetDeviceInfo = dlsym(opencl_dll, "clGetDeviceInfo");
		if (!ptr_clGetDeviceInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetDeviceInfo function\n");
		}
		ptr_clCreateSubDevices = dlsym(opencl_dll, "clCreateSubDevices");
		if (!ptr_clCreateSubDevices)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateSubDevices function\n");
		}
		ptr_clRetainDevice = dlsym(opencl_dll, "clRetainDevice");
		if (!ptr_clRetainDevice)
		{
			all_functions_loaded = 0;
			printf("Cannot load clRetainDevice function\n");
		}
		ptr_clReleaseDevice = dlsym(opencl_dll, "clReleaseDevice");
		if (!ptr_clReleaseDevice)
		{
			all_functions_loaded = 0;
			printf("Cannot load clReleaseDevice function\n");
		}
		ptr_clCreateContext = dlsym(opencl_dll, "clCreateContext");
		if (!ptr_clCreateContext)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateContext function\n");
		}
		ptr_clCreateContextFromType = dlsym(opencl_dll, "clCreateContextFromType");
		if (!ptr_clCreateContextFromType)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateContextFromType function\n");
		}
		ptr_clRetainContext = dlsym(opencl_dll, "clRetainContext");
		if (!ptr_clRetainContext)
		{
			all_functions_loaded = 0;
			printf("Cannot load clRetainContext function\n");
		}
		ptr_clReleaseContext = dlsym(opencl_dll, "clReleaseContext");
		if (!ptr_clReleaseContext)
		{
			all_functions_loaded = 0;
			printf("Cannot load clReleaseContext function\n");
		}
		ptr_clGetContextInfo = dlsym(opencl_dll, "clGetContextInfo");
		if (!ptr_clGetContextInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetContextInfo function\n");
		}
		ptr_clRetainCommandQueue = dlsym(opencl_dll, "clRetainCommandQueue");
		if (!ptr_clRetainCommandQueue)
		{
			all_functions_loaded = 0;
			printf("Cannot load clRetainCommandQueue function\n");
		}
		ptr_clReleaseCommandQueue = dlsym(opencl_dll, "clReleaseCommandQueue");
		if (!ptr_clReleaseCommandQueue)
		{
			all_functions_loaded = 0;
			printf("Cannot load clReleaseCommandQueue function\n");
		}
		ptr_clGetCommandQueueInfo = dlsym(opencl_dll, "clGetCommandQueueInfo");
		if (!ptr_clGetCommandQueueInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetCommandQueueInfo function\n");
		}
		ptr_clCreateBuffer = dlsym(opencl_dll, "clCreateBuffer");
		if (!ptr_clCreateBuffer)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateBuffer function\n");
		}
		ptr_clCreateSubBuffer = dlsym(opencl_dll, "clCreateSubBuffer");
		if (!ptr_clCreateSubBuffer)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateSubBuffer function\n");
		}
		ptr_clCreateImage = dlsym(opencl_dll, "clCreateImage");
		if (!ptr_clCreateImage)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateImage function\n");
		}
		ptr_clRetainMemObject = dlsym(opencl_dll, "clRetainMemObject");
		if (!ptr_clRetainMemObject)
		{
			all_functions_loaded = 0;
			printf("Cannot load clRetainMemObject function\n");
		}
		ptr_clReleaseMemObject = dlsym(opencl_dll, "clReleaseMemObject");
		if (!ptr_clReleaseMemObject)
		{
			all_functions_loaded = 0;
			printf("Cannot load clReleaseMemObject function\n");
		}
		ptr_clGetSupportedImageFormats = dlsym(opencl_dll, "clGetSupportedImageFormats");
		if (!ptr_clGetSupportedImageFormats)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetSupportedImageFormats function\n");
		}
		ptr_clGetMemObjectInfo = dlsym(opencl_dll, "clGetMemObjectInfo");
		if (!ptr_clGetMemObjectInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetMemObjectInfo function\n");
		}
		ptr_clGetImageInfo = dlsym(opencl_dll, "clGetImageInfo");
		if (!ptr_clGetImageInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetImageInfo function\n");
		}
		ptr_clSetMemObjectDestructorCallback = dlsym(opencl_dll, "clSetMemObjectDestructorCallback");
		if (!ptr_clSetMemObjectDestructorCallback)
		{
			all_functions_loaded = 0;
			printf("Cannot load clSetMemObjectDestructorCallback function\n");
		}
		ptr_clRetainSampler = dlsym(opencl_dll, "clRetainSampler");
		if (!ptr_clRetainSampler)
		{
			all_functions_loaded = 0;
			printf("Cannot load clRetainSampler function\n");
		}
		ptr_clReleaseSampler = dlsym(opencl_dll, "clReleaseSampler");
		if (!ptr_clReleaseSampler)
		{
			all_functions_loaded = 0;
			printf("Cannot load clReleaseSampler function\n");
		}
		ptr_clGetSamplerInfo = dlsym(opencl_dll, "clGetSamplerInfo");
		if (!ptr_clGetSamplerInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetSamplerInfo function\n");
		}
		ptr_clCreateProgramWithSource = dlsym(opencl_dll, "clCreateProgramWithSource");
		if (!ptr_clCreateProgramWithSource)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateProgramWithSource function\n");
		}
		ptr_clCreateProgramWithBinary = dlsym(opencl_dll, "clCreateProgramWithBinary");
		if (!ptr_clCreateProgramWithBinary)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateProgramWithBinary function\n");
		}
		ptr_clCreateProgramWithBuiltInKernels = dlsym(opencl_dll, "clCreateProgramWithBuiltInKernels");
		if (!ptr_clCreateProgramWithBuiltInKernels)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateProgramWithBuiltInKernels function\n");
		}
		ptr_clRetainProgram = dlsym(opencl_dll, "clRetainProgram");
		if (!ptr_clRetainProgram)
		{
			all_functions_loaded = 0;
			printf("Cannot load clRetainProgram function\n");
		}
		ptr_clReleaseProgram = dlsym(opencl_dll, "clReleaseProgram");
		if (!ptr_clReleaseProgram)
		{
			all_functions_loaded = 0;
			printf("Cannot load clReleaseProgram function\n");
		}
		ptr_clBuildProgram = dlsym(opencl_dll, "clBuildProgram");
		if (!ptr_clBuildProgram)
		{
			all_functions_loaded = 0;
			printf("Cannot load clBuildProgram function\n");
		}
		ptr_clCompileProgram = dlsym(opencl_dll, "clCompileProgram");
		if (!ptr_clCompileProgram)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCompileProgram function\n");
		}
		ptr_clLinkProgram = dlsym(opencl_dll, "clLinkProgram");
		if (!ptr_clLinkProgram)
		{
			all_functions_loaded = 0;
			printf("Cannot load clLinkProgram function\n");
		}
		ptr_clUnloadPlatformCompiler = dlsym(opencl_dll, "clUnloadPlatformCompiler");
		if (!ptr_clUnloadPlatformCompiler)
		{
			all_functions_loaded = 0;
			printf("Cannot load clUnloadPlatformCompiler function\n");
		}
		ptr_clGetProgramInfo = dlsym(opencl_dll, "clGetProgramInfo");
		if (!ptr_clGetProgramInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetProgramInfo function\n");
		}
		ptr_clGetProgramBuildInfo = dlsym(opencl_dll, "clGetProgramBuildInfo");
		if (!ptr_clGetProgramBuildInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetProgramBuildInfo function\n");
		}
		ptr_clCreateKernel = dlsym(opencl_dll, "clCreateKernel");
		if (!ptr_clCreateKernel)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateKernel function\n");
		}
		ptr_clCreateKernelsInProgram = dlsym(opencl_dll, "clCreateKernelsInProgram");
		if (!ptr_clCreateKernelsInProgram)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateKernelsInProgram function\n");
		}
		ptr_clRetainKernel = dlsym(opencl_dll, "clRetainKernel");
		if (!ptr_clRetainKernel)
		{
			all_functions_loaded = 0;
			printf("Cannot load clRetainKernel function\n");
		}
		ptr_clReleaseKernel = dlsym(opencl_dll, "clReleaseKernel");
		if (!ptr_clReleaseKernel)
		{
			all_functions_loaded = 0;
			printf("Cannot load clReleaseKernel function\n");
		}
		ptr_clSetKernelArg = dlsym(opencl_dll, "clSetKernelArg");
		if (!ptr_clSetKernelArg)
		{
			all_functions_loaded = 0;
			printf("Cannot load clSetKernelArg function\n");
		}
		ptr_clGetKernelInfo = dlsym(opencl_dll, "clGetKernelInfo");
		if (!ptr_clGetKernelInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetKernelInfo function\n");
		}
		ptr_clGetKernelArgInfo = dlsym(opencl_dll, "clGetKernelArgInfo");
		if (!ptr_clGetKernelArgInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetKernelArgInfo function\n");
		}
		ptr_clGetKernelWorkGroupInfo = dlsym(opencl_dll, "clGetKernelWorkGroupInfo");
		if (!ptr_clGetKernelWorkGroupInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetKernelWorkGroupInfo function\n");
		}
		ptr_clWaitForEvents = dlsym(opencl_dll, "clWaitForEvents");
		if (!ptr_clWaitForEvents)
		{
			all_functions_loaded = 0;
			printf("Cannot load clWaitForEvents function\n");
		}
		ptr_clGetEventInfo = dlsym(opencl_dll, "clGetEventInfo");
		if (!ptr_clGetEventInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetEventInfo function\n");
		}
		ptr_clCreateUserEvent = dlsym(opencl_dll, "clCreateUserEvent");
		if (!ptr_clCreateUserEvent)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateUserEvent function\n");
		}
		ptr_clRetainEvent = dlsym(opencl_dll, "clRetainEvent");
		if (!ptr_clRetainEvent)
		{
			all_functions_loaded = 0;
			printf("Cannot load clRetainEvent function\n");
		}
		ptr_clReleaseEvent = dlsym(opencl_dll, "clReleaseEvent");
		if (!ptr_clReleaseEvent)
		{
			all_functions_loaded = 0;
			printf("Cannot load clReleaseEvent function\n");
		}
		ptr_clSetUserEventStatus = dlsym(opencl_dll, "clSetUserEventStatus");
		if (!ptr_clSetUserEventStatus)
		{
			all_functions_loaded = 0;
			printf("Cannot load clSetUserEventStatus function\n");
		}
		ptr_clSetEventCallback = dlsym(opencl_dll, "clSetEventCallback");
		if (!ptr_clSetEventCallback)
		{
			all_functions_loaded = 0;
			printf("Cannot load clSetEventCallback function\n");
		}
		ptr_clGetEventProfilingInfo = dlsym(opencl_dll, "clGetEventProfilingInfo");
		if (!ptr_clGetEventProfilingInfo)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetEventProfilingInfo function\n");
		}
		ptr_clFlush = dlsym(opencl_dll, "clFlush");
		if (!ptr_clFlush)
		{
			all_functions_loaded = 0;
			printf("Cannot load clFlush function\n");
		}
		ptr_clFinish = dlsym(opencl_dll, "clFinish");
		if (!ptr_clFinish)
		{
			all_functions_loaded = 0;
			printf("Cannot load clFinish function\n");
		}
		ptr_clEnqueueReadBuffer = dlsym(opencl_dll, "clEnqueueReadBuffer");
		if (!ptr_clEnqueueReadBuffer)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueReadBuffer function\n");
		}
		ptr_clEnqueueReadBufferRect = dlsym(opencl_dll, "clEnqueueReadBufferRect");
		if (!ptr_clEnqueueReadBufferRect)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueReadBufferRect function\n");
		}
		ptr_clEnqueueWriteBuffer = dlsym(opencl_dll, "clEnqueueWriteBuffer");
		if (!ptr_clEnqueueWriteBuffer)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueWriteBuffer function\n");
		}
		ptr_clEnqueueWriteBufferRect = dlsym(opencl_dll, "clEnqueueWriteBufferRect");
		if (!ptr_clEnqueueWriteBufferRect)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueWriteBufferRect function\n");
		}
		ptr_clEnqueueFillBuffer = dlsym(opencl_dll, "clEnqueueFillBuffer");
		if (!ptr_clEnqueueFillBuffer)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueFillBuffer function\n");
		}
		ptr_clEnqueueCopyBuffer = dlsym(opencl_dll, "clEnqueueCopyBuffer");
		if (!ptr_clEnqueueCopyBuffer)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueCopyBuffer function\n");
		}
		ptr_clEnqueueCopyBufferRect = dlsym(opencl_dll, "clEnqueueCopyBufferRect");
		if (!ptr_clEnqueueCopyBufferRect)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueCopyBufferRect function\n");
		}
		ptr_clEnqueueReadImage = dlsym(opencl_dll, "clEnqueueReadImage");
		if (!ptr_clEnqueueReadImage)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueReadImage function\n");
		}
		ptr_clEnqueueWriteImage = dlsym(opencl_dll, "clEnqueueWriteImage");
		if (!ptr_clEnqueueWriteImage)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueWriteImage function\n");
		}
		ptr_clEnqueueFillImage = dlsym(opencl_dll, "clEnqueueFillImage");
		if (!ptr_clEnqueueFillImage)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueFillImage function\n");
		}
		ptr_clEnqueueCopyImage = dlsym(opencl_dll, "clEnqueueCopyImage");
		if (!ptr_clEnqueueCopyImage)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueCopyImage function\n");
		}
		ptr_clEnqueueCopyImageToBuffer = dlsym(opencl_dll, "clEnqueueCopyImageToBuffer");
		if (!ptr_clEnqueueCopyImageToBuffer)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueCopyImageToBuffer function\n");
		}
		ptr_clEnqueueCopyBufferToImage = dlsym(opencl_dll, "clEnqueueCopyBufferToImage");
		if (!ptr_clEnqueueCopyBufferToImage)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueCopyBufferToImage function\n");
		}
		ptr_clEnqueueMapBuffer = dlsym(opencl_dll, "clEnqueueMapBuffer");
		if (!ptr_clEnqueueMapBuffer)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueMapBuffer function\n");
		}
		ptr_clEnqueueMapImage = dlsym(opencl_dll, "clEnqueueMapImage");
		if (!ptr_clEnqueueMapImage)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueMapImage function\n");
		}
		ptr_clEnqueueUnmapMemObject = dlsym(opencl_dll, "clEnqueueUnmapMemObject");
		if (!ptr_clEnqueueUnmapMemObject)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueUnmapMemObject function\n");
		}
		ptr_clEnqueueMigrateMemObjects = dlsym(opencl_dll, "clEnqueueMigrateMemObjects");
		if (!ptr_clEnqueueMigrateMemObjects)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueMigrateMemObjects function\n");
		}
		ptr_clEnqueueNDRangeKernel = dlsym(opencl_dll, "clEnqueueNDRangeKernel");
		if (!ptr_clEnqueueNDRangeKernel)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueNDRangeKernel function\n");
		}
		ptr_clEnqueueNativeKernel = dlsym(opencl_dll, "clEnqueueNativeKernel");
		if (!ptr_clEnqueueNativeKernel)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueNativeKernel function\n");
		}
		ptr_clEnqueueMarkerWithWaitList = dlsym(opencl_dll, "clEnqueueMarkerWithWaitList");
		if (!ptr_clEnqueueMarkerWithWaitList)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueMarkerWithWaitList function\n");
		}
		ptr_clEnqueueBarrierWithWaitList = dlsym(opencl_dll, "clEnqueueBarrierWithWaitList");
		if (!ptr_clEnqueueBarrierWithWaitList)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueBarrierWithWaitList function\n");
		}
		ptr_clGetExtensionFunctionAddressForPlatform = dlsym(opencl_dll, "clGetExtensionFunctionAddressForPlatform");
		if (!ptr_clGetExtensionFunctionAddressForPlatform)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetExtensionFunctionAddressForPlatform function\n");
		}
		ptr_clSetCommandQueueProperty = dlsym(opencl_dll, "clSetCommandQueueProperty");
		if (!ptr_clSetCommandQueueProperty)
		{
			all_functions_loaded = 0;
			printf("Cannot load clSetCommandQueueProperty function\n");
		}
		ptr_clCreateImage2D = dlsym(opencl_dll, "clCreateImage2D");
		if (!ptr_clCreateImage2D)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateImage2D function\n");
		}
		ptr_clCreateImage3D = dlsym(opencl_dll, "clCreateImage3D");
		if (!ptr_clCreateImage3D)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateImage3D function\n");
		}
		ptr_clEnqueueMarker = dlsym(opencl_dll, "clEnqueueMarker");
		if (!ptr_clEnqueueMarker)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueMarker function\n");
		}
		ptr_clEnqueueWaitForEvents = dlsym(opencl_dll, "clEnqueueWaitForEvents");
		if (!ptr_clEnqueueWaitForEvents)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueWaitForEvents function\n");
		}
		ptr_clEnqueueBarrier = dlsym(opencl_dll, "clEnqueueBarrier");
		if (!ptr_clEnqueueBarrier)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueBarrier function\n");
		}
		ptr_clUnloadCompiler = dlsym(opencl_dll, "clUnloadCompiler");
		if (!ptr_clUnloadCompiler)
		{
			all_functions_loaded = 0;
			printf("Cannot load clUnloadCompiler function\n");
		}
		ptr_clGetExtensionFunctionAddress = dlsym(opencl_dll, "clGetExtensionFunctionAddress");
		if (!ptr_clGetExtensionFunctionAddress)
		{
			all_functions_loaded = 0;
			printf("Cannot load clGetExtensionFunctionAddress function\n");
		}
		ptr_clCreateCommandQueue = dlsym(opencl_dll, "clCreateCommandQueue");
		if (!ptr_clCreateCommandQueue)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateCommandQueue function\n");
		}
		ptr_clCreateSampler = dlsym(opencl_dll, "clCreateSampler");
		if (!ptr_clCreateSampler)
		{
			all_functions_loaded = 0;
			printf("Cannot load clCreateSampler function\n");
		}
		ptr_clEnqueueTask = dlsym(opencl_dll, "clEnqueueTask");
		if (!ptr_clEnqueueTask)
		{
			all_functions_loaded = 0;
			printf("Cannot load clEnqueueTask function\n");
		}

            if (!all_functions_loaded)
            {
                dlclose(opencl_dll);
                opencl_dll = NULL;
            }
        }
        else
            printf("Cannot load OpenCL library\n");
}

#endif

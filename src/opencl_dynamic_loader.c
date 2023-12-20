/*
 * Dynamic OpenCL library loader. Automatically generated.
 *
 * This software is copyright (c) 2023, Alain Espinosa <alainesp at gmail.com> and it
 * is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#ifndef CL_TARGET_OPENCL_VERSION
#define CL_TARGET_OPENCL_VERSION 120
#endif

#include "CL/cl.h"
#include "CL/cl_ext.h"

#include <dlfcn.h>
#include <stdio.h>

/* DLL handle */
static void *opencl_dll;
static void load_opencl_dll(void);

/* clGetPlatformIDs */
static cl_int (*ptr_clGetPlatformIDs)(cl_uint num_entries, cl_platform_id * platforms, cl_uint * num_platforms);
CL_API_ENTRY cl_int CL_API_CALL clGetPlatformIDs(cl_uint num_entries, cl_platform_id * platforms, cl_uint * num_platforms)
{
	load_opencl_dll();

	if (!opencl_dll) {
		/* Our implementation */
		if ((!num_entries && platforms) || (!num_platforms && !platforms))
			return CL_INVALID_VALUE;

		if (num_platforms)
			*num_platforms = 0;

		return CL_SUCCESS;
	}

	return ptr_clGetPlatformIDs(num_entries, platforms, num_platforms);
}

/* clGetPlatformInfo */
static cl_int (*ptr_clGetPlatformInfo)(cl_platform_id platform, cl_platform_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret);
CL_API_ENTRY cl_int CL_API_CALL clGetPlatformInfo(cl_platform_id platform, cl_platform_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetPlatformInfo(platform, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clGetDeviceIDs */
static cl_int (*ptr_clGetDeviceIDs)(cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id * devices, cl_uint * num_devices);
CL_API_ENTRY cl_int CL_API_CALL clGetDeviceIDs(cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id * devices, cl_uint * num_devices)
{
	return ptr_clGetDeviceIDs(platform, device_type, num_entries, devices, num_devices);
}

/* clGetDeviceInfo */
static cl_int (*ptr_clGetDeviceInfo)(cl_device_id device, cl_device_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret);
CL_API_ENTRY cl_int CL_API_CALL clGetDeviceInfo(cl_device_id device, cl_device_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetDeviceInfo(device, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clCreateSubDevices */
static cl_int (*ptr_clCreateSubDevices)(cl_device_id in_device, const cl_device_partition_property * properties, cl_uint num_devices, cl_device_id * out_devices, cl_uint * num_devices_ret);
CL_API_ENTRY cl_int CL_API_CALL clCreateSubDevices(cl_device_id in_device, const cl_device_partition_property * properties, cl_uint num_devices, cl_device_id * out_devices, cl_uint * num_devices_ret)
{
	return ptr_clCreateSubDevices(in_device, properties, num_devices, out_devices, num_devices_ret);
}

/* clRetainDevice */
static cl_int (*ptr_clRetainDevice)(cl_device_id device);
CL_API_ENTRY cl_int CL_API_CALL clRetainDevice(cl_device_id device)
{
	return ptr_clRetainDevice(device);
}

/* clReleaseDevice */
static cl_int (*ptr_clReleaseDevice)(cl_device_id device);
CL_API_ENTRY cl_int CL_API_CALL clReleaseDevice(cl_device_id device)
{
	return ptr_clReleaseDevice(device);
}

/* clCreateContext */
static cl_context (*ptr_clCreateContext)(const cl_context_properties * properties, cl_uint num_devices, const cl_device_id * devices, void (CL_CALLBACK * pfn_notify)(const char * errinfo, const void * private_info, size_t cb, void * user_data), void * user_data, cl_int * errcode_ret);
CL_API_ENTRY cl_context CL_API_CALL clCreateContext(const cl_context_properties * properties, cl_uint num_devices, const cl_device_id * devices, void (CL_CALLBACK * pfn_notify)(const char * errinfo, const void * private_info, size_t cb, void * user_data), void * user_data, cl_int * errcode_ret)
{
	return ptr_clCreateContext(properties, num_devices, devices, pfn_notify, user_data, errcode_ret);
}

/* clCreateContextFromType */
static cl_context (*ptr_clCreateContextFromType)(const cl_context_properties * properties, cl_device_type device_type, void (CL_CALLBACK * pfn_notify)(const char * errinfo, const void * private_info, size_t cb, void * user_data), void * user_data, cl_int * errcode_ret);
CL_API_ENTRY cl_context CL_API_CALL clCreateContextFromType(const cl_context_properties * properties, cl_device_type device_type, void (CL_CALLBACK * pfn_notify)(const char * errinfo, const void * private_info, size_t cb, void * user_data), void * user_data, cl_int * errcode_ret)
{
	return ptr_clCreateContextFromType(properties, device_type, pfn_notify, user_data, errcode_ret);
}

/* clRetainContext */
static cl_int (*ptr_clRetainContext)(cl_context context);
CL_API_ENTRY cl_int CL_API_CALL clRetainContext(cl_context context)
{
	return ptr_clRetainContext(context);
}

/* clReleaseContext */
static cl_int (*ptr_clReleaseContext)(cl_context context);
CL_API_ENTRY cl_int CL_API_CALL clReleaseContext(cl_context context)
{
	return ptr_clReleaseContext(context);
}

/* clGetContextInfo */
static cl_int (*ptr_clGetContextInfo)(cl_context context, cl_context_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret);
CL_API_ENTRY cl_int CL_API_CALL clGetContextInfo(cl_context context, cl_context_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetContextInfo(context, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clRetainCommandQueue */
static cl_int (*ptr_clRetainCommandQueue)(cl_command_queue command_queue);
CL_API_ENTRY cl_int CL_API_CALL clRetainCommandQueue(cl_command_queue command_queue)
{
	return ptr_clRetainCommandQueue(command_queue);
}

/* clReleaseCommandQueue */
static cl_int (*ptr_clReleaseCommandQueue)(cl_command_queue command_queue);
CL_API_ENTRY cl_int CL_API_CALL clReleaseCommandQueue(cl_command_queue command_queue)
{
	return ptr_clReleaseCommandQueue(command_queue);
}

/* clGetCommandQueueInfo */
static cl_int (*ptr_clGetCommandQueueInfo)(cl_command_queue command_queue, cl_command_queue_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret);
CL_API_ENTRY cl_int CL_API_CALL clGetCommandQueueInfo(cl_command_queue command_queue, cl_command_queue_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetCommandQueueInfo(command_queue, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clCreateBuffer */
static cl_mem (*ptr_clCreateBuffer)(cl_context context, cl_mem_flags flags, size_t size, void * host_ptr, cl_int * errcode_ret);
CL_API_ENTRY cl_mem CL_API_CALL clCreateBuffer(cl_context context, cl_mem_flags flags, size_t size, void * host_ptr, cl_int * errcode_ret)
{
	return ptr_clCreateBuffer(context, flags, size, host_ptr, errcode_ret);
}

/* clCreateSubBuffer */
static cl_mem (*ptr_clCreateSubBuffer)(cl_mem buffer, cl_mem_flags flags, cl_buffer_create_type buffer_create_type, const void * buffer_create_info, cl_int * errcode_ret);
CL_API_ENTRY cl_mem CL_API_CALL clCreateSubBuffer(cl_mem buffer, cl_mem_flags flags, cl_buffer_create_type buffer_create_type, const void * buffer_create_info, cl_int * errcode_ret)
{
	return ptr_clCreateSubBuffer(buffer, flags, buffer_create_type, buffer_create_info, errcode_ret);
}

/* clRetainMemObject */
static cl_int (*ptr_clRetainMemObject)(cl_mem memobj);
CL_API_ENTRY cl_int CL_API_CALL clRetainMemObject(cl_mem memobj)
{
	return ptr_clRetainMemObject(memobj);
}

/* clReleaseMemObject */
static cl_int (*ptr_clReleaseMemObject)(cl_mem memobj);
CL_API_ENTRY cl_int CL_API_CALL clReleaseMemObject(cl_mem memobj)
{
	return ptr_clReleaseMemObject(memobj);
}

/* clGetMemObjectInfo */
static cl_int (*ptr_clGetMemObjectInfo)(cl_mem memobj, cl_mem_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret);
CL_API_ENTRY cl_int CL_API_CALL clGetMemObjectInfo(cl_mem memobj, cl_mem_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetMemObjectInfo(memobj, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clSetMemObjectDestructorCallback */
static cl_int (*ptr_clSetMemObjectDestructorCallback)(cl_mem memobj, void (CL_CALLBACK * pfn_notify)(cl_mem memobj, void * user_data), void * user_data);
CL_API_ENTRY cl_int CL_API_CALL clSetMemObjectDestructorCallback(cl_mem memobj, void (CL_CALLBACK * pfn_notify)(cl_mem memobj, void * user_data), void * user_data)
{
	return ptr_clSetMemObjectDestructorCallback(memobj, pfn_notify, user_data);
}

/* clRetainSampler */
static cl_int (*ptr_clRetainSampler)(cl_sampler sampler);
CL_API_ENTRY cl_int CL_API_CALL clRetainSampler(cl_sampler sampler)
{
	return ptr_clRetainSampler(sampler);
}

/* clReleaseSampler */
static cl_int (*ptr_clReleaseSampler)(cl_sampler sampler);
CL_API_ENTRY cl_int CL_API_CALL clReleaseSampler(cl_sampler sampler)
{
	return ptr_clReleaseSampler(sampler);
}

/* clGetSamplerInfo */
static cl_int (*ptr_clGetSamplerInfo)(cl_sampler sampler, cl_sampler_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret);
CL_API_ENTRY cl_int CL_API_CALL clGetSamplerInfo(cl_sampler sampler, cl_sampler_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetSamplerInfo(sampler, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clCreateProgramWithSource */
static cl_program (*ptr_clCreateProgramWithSource)(cl_context context, cl_uint count, const char ** strings, const size_t * lengths, cl_int * errcode_ret);
CL_API_ENTRY cl_program CL_API_CALL clCreateProgramWithSource(cl_context context, cl_uint count, const char ** strings, const size_t * lengths, cl_int * errcode_ret)
{
	return ptr_clCreateProgramWithSource(context, count, strings, lengths, errcode_ret);
}

/* clCreateProgramWithBinary */
static cl_program (*ptr_clCreateProgramWithBinary)(cl_context context, cl_uint num_devices, const cl_device_id * device_list, const size_t * lengths, const unsigned char ** binaries, cl_int * binary_status, cl_int * errcode_ret);
CL_API_ENTRY cl_program CL_API_CALL clCreateProgramWithBinary(cl_context context, cl_uint num_devices, const cl_device_id * device_list, const size_t * lengths, const unsigned char ** binaries, cl_int * binary_status, cl_int * errcode_ret)
{
	return ptr_clCreateProgramWithBinary(context, num_devices, device_list, lengths, binaries, binary_status, errcode_ret);
}

/* clCreateProgramWithBuiltInKernels */
static cl_program (*ptr_clCreateProgramWithBuiltInKernels)(cl_context context, cl_uint num_devices, const cl_device_id * device_list, const char * kernel_names, cl_int * errcode_ret);
CL_API_ENTRY cl_program CL_API_CALL clCreateProgramWithBuiltInKernels(cl_context context, cl_uint num_devices, const cl_device_id * device_list, const char * kernel_names, cl_int * errcode_ret)
{
	return ptr_clCreateProgramWithBuiltInKernels(context, num_devices, device_list, kernel_names, errcode_ret);
}

/* clRetainProgram */
static cl_int (*ptr_clRetainProgram)(cl_program program);
CL_API_ENTRY cl_int CL_API_CALL clRetainProgram(cl_program program)
{
	return ptr_clRetainProgram(program);
}

/* clReleaseProgram */
static cl_int (*ptr_clReleaseProgram)(cl_program program);
CL_API_ENTRY cl_int CL_API_CALL clReleaseProgram(cl_program program)
{
	return ptr_clReleaseProgram(program);
}

/* clBuildProgram */
static cl_int (*ptr_clBuildProgram)(cl_program program, cl_uint num_devices, const cl_device_id * device_list, const char * options, void (CL_CALLBACK * pfn_notify)(cl_program program, void * user_data), void * user_data);
CL_API_ENTRY cl_int CL_API_CALL clBuildProgram(cl_program program, cl_uint num_devices, const cl_device_id * device_list, const char * options, void (CL_CALLBACK * pfn_notify)(cl_program program, void * user_data), void * user_data)
{
	return ptr_clBuildProgram(program, num_devices, device_list, options, pfn_notify, user_data);
}

/* clCompileProgram */
static cl_int (*ptr_clCompileProgram)(cl_program program, cl_uint num_devices, const cl_device_id * device_list, const char * options, cl_uint num_input_headers, const cl_program * input_headers, const char ** header_include_names, void (CL_CALLBACK * pfn_notify)(cl_program program, void * user_data), void * user_data);
CL_API_ENTRY cl_int CL_API_CALL clCompileProgram(cl_program program, cl_uint num_devices, const cl_device_id * device_list, const char * options, cl_uint num_input_headers, const cl_program * input_headers, const char ** header_include_names, void (CL_CALLBACK * pfn_notify)(cl_program program, void * user_data), void * user_data)
{
	return ptr_clCompileProgram(program, num_devices, device_list, options, num_input_headers, input_headers, header_include_names, pfn_notify, user_data);
}

/* clLinkProgram */
static cl_program (*ptr_clLinkProgram)(cl_context context, cl_uint num_devices, const cl_device_id * device_list, const char * options, cl_uint num_input_programs, const cl_program * input_programs, void (CL_CALLBACK * pfn_notify)(cl_program program, void * user_data), void * user_data, cl_int * errcode_ret);
CL_API_ENTRY cl_program CL_API_CALL clLinkProgram(cl_context context, cl_uint num_devices, const cl_device_id * device_list, const char * options, cl_uint num_input_programs, const cl_program * input_programs, void (CL_CALLBACK * pfn_notify)(cl_program program, void * user_data), void * user_data, cl_int * errcode_ret)
{
	return ptr_clLinkProgram(context, num_devices, device_list, options, num_input_programs, input_programs, pfn_notify, user_data, errcode_ret);
}

/* clUnloadPlatformCompiler */
static cl_int (*ptr_clUnloadPlatformCompiler)(cl_platform_id platform);
CL_API_ENTRY cl_int CL_API_CALL clUnloadPlatformCompiler(cl_platform_id platform)
{
	return ptr_clUnloadPlatformCompiler(platform);
}

/* clGetProgramInfo */
static cl_int (*ptr_clGetProgramInfo)(cl_program program, cl_program_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret);
CL_API_ENTRY cl_int CL_API_CALL clGetProgramInfo(cl_program program, cl_program_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetProgramInfo(program, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clGetProgramBuildInfo */
static cl_int (*ptr_clGetProgramBuildInfo)(cl_program program, cl_device_id device, cl_program_build_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret);
CL_API_ENTRY cl_int CL_API_CALL clGetProgramBuildInfo(cl_program program, cl_device_id device, cl_program_build_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetProgramBuildInfo(program, device, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clCreateKernel */
static cl_kernel (*ptr_clCreateKernel)(cl_program program, const char * kernel_name, cl_int * errcode_ret);
CL_API_ENTRY cl_kernel CL_API_CALL clCreateKernel(cl_program program, const char * kernel_name, cl_int * errcode_ret)
{
	return ptr_clCreateKernel(program, kernel_name, errcode_ret);
}

/* clCreateKernelsInProgram */
static cl_int (*ptr_clCreateKernelsInProgram)(cl_program program, cl_uint num_kernels, cl_kernel * kernels, cl_uint * num_kernels_ret);
CL_API_ENTRY cl_int CL_API_CALL clCreateKernelsInProgram(cl_program program, cl_uint num_kernels, cl_kernel * kernels, cl_uint * num_kernels_ret)
{
	return ptr_clCreateKernelsInProgram(program, num_kernels, kernels, num_kernels_ret);
}

/* clRetainKernel */
static cl_int (*ptr_clRetainKernel)(cl_kernel kernel);
CL_API_ENTRY cl_int CL_API_CALL clRetainKernel(cl_kernel kernel)
{
	return ptr_clRetainKernel(kernel);
}

/* clReleaseKernel */
static cl_int (*ptr_clReleaseKernel)(cl_kernel kernel);
CL_API_ENTRY cl_int CL_API_CALL clReleaseKernel(cl_kernel kernel)
{
	return ptr_clReleaseKernel(kernel);
}

/* clSetKernelArg */
static cl_int (*ptr_clSetKernelArg)(cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void * arg_value);
CL_API_ENTRY cl_int CL_API_CALL clSetKernelArg(cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void * arg_value)
{
	return ptr_clSetKernelArg(kernel, arg_index, arg_size, arg_value);
}

/* clGetKernelInfo */
static cl_int (*ptr_clGetKernelInfo)(cl_kernel kernel, cl_kernel_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret);
CL_API_ENTRY cl_int CL_API_CALL clGetKernelInfo(cl_kernel kernel, cl_kernel_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetKernelInfo(kernel, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clGetKernelArgInfo */
static cl_int (*ptr_clGetKernelArgInfo)(cl_kernel kernel, cl_uint arg_indx, cl_kernel_arg_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret);
CL_API_ENTRY cl_int CL_API_CALL clGetKernelArgInfo(cl_kernel kernel, cl_uint arg_indx, cl_kernel_arg_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetKernelArgInfo(kernel, arg_indx, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clGetKernelWorkGroupInfo */
static cl_int (*ptr_clGetKernelWorkGroupInfo)(cl_kernel kernel, cl_device_id device, cl_kernel_work_group_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret);
CL_API_ENTRY cl_int CL_API_CALL clGetKernelWorkGroupInfo(cl_kernel kernel, cl_device_id device, cl_kernel_work_group_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetKernelWorkGroupInfo(kernel, device, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clWaitForEvents */
static cl_int (*ptr_clWaitForEvents)(cl_uint num_events, const cl_event * event_list);
CL_API_ENTRY cl_int CL_API_CALL clWaitForEvents(cl_uint num_events, const cl_event * event_list)
{
	return ptr_clWaitForEvents(num_events, event_list);
}

/* clGetEventInfo */
static cl_int (*ptr_clGetEventInfo)(cl_event event, cl_event_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret);
CL_API_ENTRY cl_int CL_API_CALL clGetEventInfo(cl_event event, cl_event_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetEventInfo(event, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clCreateUserEvent */
static cl_event (*ptr_clCreateUserEvent)(cl_context context, cl_int * errcode_ret);
CL_API_ENTRY cl_event CL_API_CALL clCreateUserEvent(cl_context context, cl_int * errcode_ret)
{
	return ptr_clCreateUserEvent(context, errcode_ret);
}

/* clRetainEvent */
static cl_int (*ptr_clRetainEvent)(cl_event event);
CL_API_ENTRY cl_int CL_API_CALL clRetainEvent(cl_event event)
{
	return ptr_clRetainEvent(event);
}

/* clReleaseEvent */
static cl_int (*ptr_clReleaseEvent)(cl_event event);
CL_API_ENTRY cl_int CL_API_CALL clReleaseEvent(cl_event event)
{
	return ptr_clReleaseEvent(event);
}

/* clSetUserEventStatus */
static cl_int (*ptr_clSetUserEventStatus)(cl_event event, cl_int execution_status);
CL_API_ENTRY cl_int CL_API_CALL clSetUserEventStatus(cl_event event, cl_int execution_status)
{
	return ptr_clSetUserEventStatus(event, execution_status);
}

/* clSetEventCallback */
static cl_int (*ptr_clSetEventCallback)(cl_event event, cl_int command_exec_callback_type, void (CL_CALLBACK * pfn_notify)(cl_event event, cl_int event_command_status, void * user_data), void * user_data);
CL_API_ENTRY cl_int CL_API_CALL clSetEventCallback(cl_event event, cl_int command_exec_callback_type, void (CL_CALLBACK * pfn_notify)(cl_event event, cl_int event_command_status, void * user_data), void * user_data)
{
	return ptr_clSetEventCallback(event, command_exec_callback_type, pfn_notify, user_data);
}

/* clGetEventProfilingInfo */
static cl_int (*ptr_clGetEventProfilingInfo)(cl_event event, cl_profiling_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret);
CL_API_ENTRY cl_int CL_API_CALL clGetEventProfilingInfo(cl_event event, cl_profiling_info param_name, size_t param_value_size, void * param_value, size_t * param_value_size_ret)
{
	return ptr_clGetEventProfilingInfo(event, param_name, param_value_size, param_value, param_value_size_ret);
}

/* clFlush */
static cl_int (*ptr_clFlush)(cl_command_queue command_queue);
CL_API_ENTRY cl_int CL_API_CALL clFlush(cl_command_queue command_queue)
{
	return ptr_clFlush(command_queue);
}

/* clFinish */
static cl_int (*ptr_clFinish)(cl_command_queue command_queue);
CL_API_ENTRY cl_int CL_API_CALL clFinish(cl_command_queue command_queue)
{
	return ptr_clFinish(command_queue);
}

/* clEnqueueReadBuffer */
static cl_int (*ptr_clEnqueueReadBuffer)(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t size, void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueReadBuffer(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t size, void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueReadBuffer(command_queue, buffer, blocking_read, offset, size, ptr, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueReadBufferRect */
static cl_int (*ptr_clEnqueueReadBufferRect)(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, const size_t * buffer_origin, const size_t * host_origin, const size_t * region, size_t buffer_row_pitch, size_t buffer_slice_pitch, size_t host_row_pitch, size_t host_slice_pitch, void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueReadBufferRect(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, const size_t * buffer_origin, const size_t * host_origin, const size_t * region, size_t buffer_row_pitch, size_t buffer_slice_pitch, size_t host_row_pitch, size_t host_slice_pitch, void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueReadBufferRect(command_queue, buffer, blocking_read, buffer_origin, host_origin, region, buffer_row_pitch, buffer_slice_pitch, host_row_pitch, host_slice_pitch, ptr, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueWriteBuffer */
static cl_int (*ptr_clEnqueueWriteBuffer)(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t size, const void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueWriteBuffer(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t size, const void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueWriteBuffer(command_queue, buffer, blocking_write, offset, size, ptr, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueWriteBufferRect */
static cl_int (*ptr_clEnqueueWriteBufferRect)(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, const size_t * buffer_origin, const size_t * host_origin, const size_t * region, size_t buffer_row_pitch, size_t buffer_slice_pitch, size_t host_row_pitch, size_t host_slice_pitch, const void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueWriteBufferRect(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, const size_t * buffer_origin, const size_t * host_origin, const size_t * region, size_t buffer_row_pitch, size_t buffer_slice_pitch, size_t host_row_pitch, size_t host_slice_pitch, const void * ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueWriteBufferRect(command_queue, buffer, blocking_write, buffer_origin, host_origin, region, buffer_row_pitch, buffer_slice_pitch, host_row_pitch, host_slice_pitch, ptr, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueFillBuffer */
static cl_int (*ptr_clEnqueueFillBuffer)(cl_command_queue command_queue, cl_mem buffer, const void * pattern, size_t pattern_size, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueFillBuffer(cl_command_queue command_queue, cl_mem buffer, const void * pattern, size_t pattern_size, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueFillBuffer(command_queue, buffer, pattern, pattern_size, offset, size, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueCopyBuffer */
static cl_int (*ptr_clEnqueueCopyBuffer)(cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueCopyBuffer(cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueCopyBuffer(command_queue, src_buffer, dst_buffer, src_offset, dst_offset, size, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueCopyBufferRect */
static cl_int (*ptr_clEnqueueCopyBufferRect)(cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, const size_t * src_origin, const size_t * dst_origin, const size_t * region, size_t src_row_pitch, size_t src_slice_pitch, size_t dst_row_pitch, size_t dst_slice_pitch, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueCopyBufferRect(cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, const size_t * src_origin, const size_t * dst_origin, const size_t * region, size_t src_row_pitch, size_t src_slice_pitch, size_t dst_row_pitch, size_t dst_slice_pitch, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueCopyBufferRect(command_queue, src_buffer, dst_buffer, src_origin, dst_origin, region, src_row_pitch, src_slice_pitch, dst_row_pitch, dst_slice_pitch, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueMapBuffer */
static void * (*ptr_clEnqueueMapBuffer)(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_map, cl_map_flags map_flags, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event, cl_int * errcode_ret);
CL_API_ENTRY void * CL_API_CALL clEnqueueMapBuffer(cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_map, cl_map_flags map_flags, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event, cl_int * errcode_ret)
{
	return ptr_clEnqueueMapBuffer(command_queue, buffer, blocking_map, map_flags, offset, size, num_events_in_wait_list, event_wait_list, event, errcode_ret);
}

/* clEnqueueUnmapMemObject */
static cl_int (*ptr_clEnqueueUnmapMemObject)(cl_command_queue command_queue, cl_mem memobj, void * mapped_ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueUnmapMemObject(cl_command_queue command_queue, cl_mem memobj, void * mapped_ptr, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueUnmapMemObject(command_queue, memobj, mapped_ptr, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueMigrateMemObjects */
static cl_int (*ptr_clEnqueueMigrateMemObjects)(cl_command_queue command_queue, cl_uint num_mem_objects, const cl_mem * mem_objects, cl_mem_migration_flags flags, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueMigrateMemObjects(cl_command_queue command_queue, cl_uint num_mem_objects, const cl_mem * mem_objects, cl_mem_migration_flags flags, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueMigrateMemObjects(command_queue, num_mem_objects, mem_objects, flags, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueNDRangeKernel */
static cl_int (*ptr_clEnqueueNDRangeKernel)(cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t * global_work_offset, const size_t * global_work_size, const size_t * local_work_size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueNDRangeKernel(cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t * global_work_offset, const size_t * global_work_size, const size_t * local_work_size, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueNDRangeKernel(command_queue, kernel, work_dim, global_work_offset, global_work_size, local_work_size, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueNativeKernel */
static cl_int (*ptr_clEnqueueNativeKernel)(cl_command_queue command_queue, void (CL_CALLBACK * user_func)(void *), void * args, size_t cb_args, cl_uint num_mem_objects, const cl_mem * mem_list, const void ** args_mem_loc, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueNativeKernel(cl_command_queue command_queue, void (CL_CALLBACK * user_func)(void *), void * args, size_t cb_args, cl_uint num_mem_objects, const cl_mem * mem_list, const void ** args_mem_loc, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueNativeKernel(command_queue, user_func, args, cb_args, num_mem_objects, mem_list, args_mem_loc, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueMarkerWithWaitList */
static cl_int (*ptr_clEnqueueMarkerWithWaitList)(cl_command_queue command_queue, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueMarkerWithWaitList(cl_command_queue command_queue, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueMarkerWithWaitList(command_queue, num_events_in_wait_list, event_wait_list, event);
}

/* clEnqueueBarrierWithWaitList */
static cl_int (*ptr_clEnqueueBarrierWithWaitList)(cl_command_queue command_queue, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueBarrierWithWaitList(cl_command_queue command_queue, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueBarrierWithWaitList(command_queue, num_events_in_wait_list, event_wait_list, event);
}

/* clGetExtensionFunctionAddressForPlatform */
static void * (*ptr_clGetExtensionFunctionAddressForPlatform)(cl_platform_id platform, const char * func_name);
CL_API_ENTRY void * CL_API_CALL clGetExtensionFunctionAddressForPlatform(cl_platform_id platform, const char * func_name)
{
	return ptr_clGetExtensionFunctionAddressForPlatform(platform, func_name);
}

/* clSetCommandQueueProperty */
static cl_int (*ptr_clSetCommandQueueProperty)(cl_command_queue command_queue, cl_command_queue_properties properties, cl_bool enable, cl_command_queue_properties * old_properties);
CL_API_ENTRY cl_int CL_API_CALL clSetCommandQueueProperty(cl_command_queue command_queue, cl_command_queue_properties properties, cl_bool enable, cl_command_queue_properties * old_properties)
{
	return ptr_clSetCommandQueueProperty(command_queue, properties, enable, old_properties);
}

/* clEnqueueMarker */
static cl_int (*ptr_clEnqueueMarker)(cl_command_queue command_queue, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueMarker(cl_command_queue command_queue, cl_event * event)
{
	return ptr_clEnqueueMarker(command_queue, event);
}

/* clEnqueueWaitForEvents */
static cl_int (*ptr_clEnqueueWaitForEvents)(cl_command_queue command_queue, cl_uint num_events, const cl_event * event_list);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueWaitForEvents(cl_command_queue command_queue, cl_uint num_events, const cl_event * event_list)
{
	return ptr_clEnqueueWaitForEvents(command_queue, num_events, event_list);
}

/* clEnqueueBarrier */
static cl_int (*ptr_clEnqueueBarrier)(cl_command_queue command_queue);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueBarrier(cl_command_queue command_queue)
{
	return ptr_clEnqueueBarrier(command_queue);
}

/* clUnloadCompiler */
static cl_int (*ptr_clUnloadCompiler)(void);
CL_API_ENTRY cl_int CL_API_CALL clUnloadCompiler(void)
{
	return ptr_clUnloadCompiler();
}

/* clGetExtensionFunctionAddress */
static void * (*ptr_clGetExtensionFunctionAddress)(const char * func_name);
CL_API_ENTRY void * CL_API_CALL clGetExtensionFunctionAddress(const char * func_name)
{
	return ptr_clGetExtensionFunctionAddress(func_name);
}

/* clCreateCommandQueue */
static cl_command_queue (*ptr_clCreateCommandQueue)(cl_context context, cl_device_id device, cl_command_queue_properties properties, cl_int * errcode_ret);
CL_API_ENTRY cl_command_queue CL_API_CALL clCreateCommandQueue(cl_context context, cl_device_id device, cl_command_queue_properties properties, cl_int * errcode_ret)
{
	return ptr_clCreateCommandQueue(context, device, properties, errcode_ret);
}

/* clCreateSampler */
static cl_sampler (*ptr_clCreateSampler)(cl_context context, cl_bool normalized_coords, cl_addressing_mode addressing_mode, cl_filter_mode filter_mode, cl_int * errcode_ret);
CL_API_ENTRY cl_sampler CL_API_CALL clCreateSampler(cl_context context, cl_bool normalized_coords, cl_addressing_mode addressing_mode, cl_filter_mode filter_mode, cl_int * errcode_ret)
{
	return ptr_clCreateSampler(context, normalized_coords, addressing_mode, filter_mode, errcode_ret);
}

/* clEnqueueTask */
static cl_int (*ptr_clEnqueueTask)(cl_command_queue command_queue, cl_kernel kernel, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event);
CL_API_ENTRY cl_int CL_API_CALL clEnqueueTask(cl_command_queue command_queue, cl_kernel kernel, cl_uint num_events_in_wait_list, const cl_event * event_wait_list, cl_event * event)
{
	return ptr_clEnqueueTask(command_queue, kernel, num_events_in_wait_list, event_wait_list, event);
}


static cl_int unimplemented_function(void)
{
	return CL_INVALID_OPERATION;
}

static void load_opencl_dll(void)
{
	int i;

	if (opencl_dll)
		return;

	/* Names to try to load */
	const char * const opencl_names[] = {
		"libOpenCL.so",		/* Linux/others, hack via "development" sub-package's symlink */
		"OpenCL",		/* _WIN */
		"/System/Library/Frameworks/OpenCL.framework/OpenCL", /* __APPLE__ */
		"opencl.dll",		/* __CYGWIN__ */
		"cygOpenCL-1.dll",	/* __CYGWIN__ */
		"libOpenCL.so.1"	/* Linux/others, no "development" sub-package installed */
	};

	for (i = 0; i < sizeof(opencl_names)/sizeof(opencl_names[0]); i++) {
		opencl_dll = dlopen(opencl_names[i], RTLD_NOW);
		if (opencl_dll)
			break;
	}

	if (!opencl_dll) {
		puts("Cannot load OpenCL library");
		return;
	}

	/* Load function pointers */
	ptr_clGetPlatformIDs = dlsym(opencl_dll, "clGetPlatformIDs");
	if (!ptr_clGetPlatformIDs) {
		ptr_clGetPlatformIDs = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetPlatformIDs function\n");
	}
	ptr_clGetPlatformInfo = dlsym(opencl_dll, "clGetPlatformInfo");
	if (!ptr_clGetPlatformInfo) {
		ptr_clGetPlatformInfo = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetPlatformInfo function\n");
	}
	ptr_clGetDeviceIDs = dlsym(opencl_dll, "clGetDeviceIDs");
	if (!ptr_clGetDeviceIDs) {
		ptr_clGetDeviceIDs = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetDeviceIDs function\n");
	}
	ptr_clGetDeviceInfo = dlsym(opencl_dll, "clGetDeviceInfo");
	if (!ptr_clGetDeviceInfo) {
		ptr_clGetDeviceInfo = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetDeviceInfo function\n");
	}
	ptr_clCreateSubDevices = dlsym(opencl_dll, "clCreateSubDevices");
	if (!ptr_clCreateSubDevices) {
		ptr_clCreateSubDevices = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCreateSubDevices function\n");
	}
	ptr_clRetainDevice = dlsym(opencl_dll, "clRetainDevice");
	if (!ptr_clRetainDevice) {
		ptr_clRetainDevice = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clRetainDevice function\n");
	}
	ptr_clReleaseDevice = dlsym(opencl_dll, "clReleaseDevice");
	if (!ptr_clReleaseDevice) {
		ptr_clReleaseDevice = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clReleaseDevice function\n");
	}
	ptr_clCreateContext = dlsym(opencl_dll, "clCreateContext");
	if (!ptr_clCreateContext) {
		ptr_clCreateContext = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCreateContext function\n");
	}
	ptr_clCreateContextFromType = dlsym(opencl_dll, "clCreateContextFromType");
	if (!ptr_clCreateContextFromType) {
		ptr_clCreateContextFromType = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCreateContextFromType function\n");
	}
	ptr_clRetainContext = dlsym(opencl_dll, "clRetainContext");
	if (!ptr_clRetainContext) {
		ptr_clRetainContext = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clRetainContext function\n");
	}
	ptr_clReleaseContext = dlsym(opencl_dll, "clReleaseContext");
	if (!ptr_clReleaseContext) {
		ptr_clReleaseContext = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clReleaseContext function\n");
	}
	ptr_clGetContextInfo = dlsym(opencl_dll, "clGetContextInfo");
	if (!ptr_clGetContextInfo) {
		ptr_clGetContextInfo = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetContextInfo function\n");
	}
	ptr_clRetainCommandQueue = dlsym(opencl_dll, "clRetainCommandQueue");
	if (!ptr_clRetainCommandQueue) {
		ptr_clRetainCommandQueue = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clRetainCommandQueue function\n");
	}
	ptr_clReleaseCommandQueue = dlsym(opencl_dll, "clReleaseCommandQueue");
	if (!ptr_clReleaseCommandQueue) {
		ptr_clReleaseCommandQueue = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clReleaseCommandQueue function\n");
	}
	ptr_clGetCommandQueueInfo = dlsym(opencl_dll, "clGetCommandQueueInfo");
	if (!ptr_clGetCommandQueueInfo) {
		ptr_clGetCommandQueueInfo = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetCommandQueueInfo function\n");
	}
	ptr_clCreateBuffer = dlsym(opencl_dll, "clCreateBuffer");
	if (!ptr_clCreateBuffer) {
		ptr_clCreateBuffer = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCreateBuffer function\n");
	}
	ptr_clCreateSubBuffer = dlsym(opencl_dll, "clCreateSubBuffer");
	if (!ptr_clCreateSubBuffer) {
		ptr_clCreateSubBuffer = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCreateSubBuffer function\n");
	}
	ptr_clRetainMemObject = dlsym(opencl_dll, "clRetainMemObject");
	if (!ptr_clRetainMemObject) {
		ptr_clRetainMemObject = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clRetainMemObject function\n");
	}
	ptr_clReleaseMemObject = dlsym(opencl_dll, "clReleaseMemObject");
	if (!ptr_clReleaseMemObject) {
		ptr_clReleaseMemObject = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clReleaseMemObject function\n");
	}
	ptr_clGetMemObjectInfo = dlsym(opencl_dll, "clGetMemObjectInfo");
	if (!ptr_clGetMemObjectInfo) {
		ptr_clGetMemObjectInfo = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetMemObjectInfo function\n");
	}
	ptr_clSetMemObjectDestructorCallback = dlsym(opencl_dll, "clSetMemObjectDestructorCallback");
	if (!ptr_clSetMemObjectDestructorCallback) {
		ptr_clSetMemObjectDestructorCallback = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clSetMemObjectDestructorCallback function\n");
	}
	ptr_clRetainSampler = dlsym(opencl_dll, "clRetainSampler");
	if (!ptr_clRetainSampler) {
		ptr_clRetainSampler = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clRetainSampler function\n");
	}
	ptr_clReleaseSampler = dlsym(opencl_dll, "clReleaseSampler");
	if (!ptr_clReleaseSampler) {
		ptr_clReleaseSampler = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clReleaseSampler function\n");
	}
	ptr_clGetSamplerInfo = dlsym(opencl_dll, "clGetSamplerInfo");
	if (!ptr_clGetSamplerInfo) {
		ptr_clGetSamplerInfo = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetSamplerInfo function\n");
	}
	ptr_clCreateProgramWithSource = dlsym(opencl_dll, "clCreateProgramWithSource");
	if (!ptr_clCreateProgramWithSource) {
		ptr_clCreateProgramWithSource = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCreateProgramWithSource function\n");
	}
	ptr_clCreateProgramWithBinary = dlsym(opencl_dll, "clCreateProgramWithBinary");
	if (!ptr_clCreateProgramWithBinary) {
		ptr_clCreateProgramWithBinary = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCreateProgramWithBinary function\n");
	}
	ptr_clCreateProgramWithBuiltInKernels = dlsym(opencl_dll, "clCreateProgramWithBuiltInKernels");
	if (!ptr_clCreateProgramWithBuiltInKernels) {
		ptr_clCreateProgramWithBuiltInKernels = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCreateProgramWithBuiltInKernels function\n");
	}
	ptr_clRetainProgram = dlsym(opencl_dll, "clRetainProgram");
	if (!ptr_clRetainProgram) {
		ptr_clRetainProgram = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clRetainProgram function\n");
	}
	ptr_clReleaseProgram = dlsym(opencl_dll, "clReleaseProgram");
	if (!ptr_clReleaseProgram) {
		ptr_clReleaseProgram = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clReleaseProgram function\n");
	}
	ptr_clBuildProgram = dlsym(opencl_dll, "clBuildProgram");
	if (!ptr_clBuildProgram) {
		ptr_clBuildProgram = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clBuildProgram function\n");
	}
	ptr_clCompileProgram = dlsym(opencl_dll, "clCompileProgram");
	if (!ptr_clCompileProgram) {
		ptr_clCompileProgram = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCompileProgram function\n");
	}
	ptr_clLinkProgram = dlsym(opencl_dll, "clLinkProgram");
	if (!ptr_clLinkProgram) {
		ptr_clLinkProgram = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clLinkProgram function\n");
	}
	ptr_clUnloadPlatformCompiler = dlsym(opencl_dll, "clUnloadPlatformCompiler");
	if (!ptr_clUnloadPlatformCompiler) {
		ptr_clUnloadPlatformCompiler = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clUnloadPlatformCompiler function\n");
	}
	ptr_clGetProgramInfo = dlsym(opencl_dll, "clGetProgramInfo");
	if (!ptr_clGetProgramInfo) {
		ptr_clGetProgramInfo = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetProgramInfo function\n");
	}
	ptr_clGetProgramBuildInfo = dlsym(opencl_dll, "clGetProgramBuildInfo");
	if (!ptr_clGetProgramBuildInfo) {
		ptr_clGetProgramBuildInfo = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetProgramBuildInfo function\n");
	}
	ptr_clCreateKernel = dlsym(opencl_dll, "clCreateKernel");
	if (!ptr_clCreateKernel) {
		ptr_clCreateKernel = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCreateKernel function\n");
	}
	ptr_clCreateKernelsInProgram = dlsym(opencl_dll, "clCreateKernelsInProgram");
	if (!ptr_clCreateKernelsInProgram) {
		ptr_clCreateKernelsInProgram = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCreateKernelsInProgram function\n");
	}
	ptr_clRetainKernel = dlsym(opencl_dll, "clRetainKernel");
	if (!ptr_clRetainKernel) {
		ptr_clRetainKernel = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clRetainKernel function\n");
	}
	ptr_clReleaseKernel = dlsym(opencl_dll, "clReleaseKernel");
	if (!ptr_clReleaseKernel) {
		ptr_clReleaseKernel = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clReleaseKernel function\n");
	}
	ptr_clSetKernelArg = dlsym(opencl_dll, "clSetKernelArg");
	if (!ptr_clSetKernelArg) {
		ptr_clSetKernelArg = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clSetKernelArg function\n");
	}
	ptr_clGetKernelInfo = dlsym(opencl_dll, "clGetKernelInfo");
	if (!ptr_clGetKernelInfo) {
		ptr_clGetKernelInfo = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetKernelInfo function\n");
	}
	ptr_clGetKernelArgInfo = dlsym(opencl_dll, "clGetKernelArgInfo");
	if (!ptr_clGetKernelArgInfo) {
		ptr_clGetKernelArgInfo = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetKernelArgInfo function\n");
	}
	ptr_clGetKernelWorkGroupInfo = dlsym(opencl_dll, "clGetKernelWorkGroupInfo");
	if (!ptr_clGetKernelWorkGroupInfo) {
		ptr_clGetKernelWorkGroupInfo = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetKernelWorkGroupInfo function\n");
	}
	ptr_clWaitForEvents = dlsym(opencl_dll, "clWaitForEvents");
	if (!ptr_clWaitForEvents) {
		ptr_clWaitForEvents = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clWaitForEvents function\n");
	}
	ptr_clGetEventInfo = dlsym(opencl_dll, "clGetEventInfo");
	if (!ptr_clGetEventInfo) {
		ptr_clGetEventInfo = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetEventInfo function\n");
	}
	ptr_clCreateUserEvent = dlsym(opencl_dll, "clCreateUserEvent");
	if (!ptr_clCreateUserEvent) {
		ptr_clCreateUserEvent = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCreateUserEvent function\n");
	}
	ptr_clRetainEvent = dlsym(opencl_dll, "clRetainEvent");
	if (!ptr_clRetainEvent) {
		ptr_clRetainEvent = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clRetainEvent function\n");
	}
	ptr_clReleaseEvent = dlsym(opencl_dll, "clReleaseEvent");
	if (!ptr_clReleaseEvent) {
		ptr_clReleaseEvent = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clReleaseEvent function\n");
	}
	ptr_clSetUserEventStatus = dlsym(opencl_dll, "clSetUserEventStatus");
	if (!ptr_clSetUserEventStatus) {
		ptr_clSetUserEventStatus = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clSetUserEventStatus function\n");
	}
	ptr_clSetEventCallback = dlsym(opencl_dll, "clSetEventCallback");
	if (!ptr_clSetEventCallback) {
		ptr_clSetEventCallback = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clSetEventCallback function\n");
	}
	ptr_clGetEventProfilingInfo = dlsym(opencl_dll, "clGetEventProfilingInfo");
	if (!ptr_clGetEventProfilingInfo) {
		ptr_clGetEventProfilingInfo = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetEventProfilingInfo function\n");
	}
	ptr_clFlush = dlsym(opencl_dll, "clFlush");
	if (!ptr_clFlush) {
		ptr_clFlush = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clFlush function\n");
	}
	ptr_clFinish = dlsym(opencl_dll, "clFinish");
	if (!ptr_clFinish) {
		ptr_clFinish = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clFinish function\n");
	}
	ptr_clEnqueueReadBuffer = dlsym(opencl_dll, "clEnqueueReadBuffer");
	if (!ptr_clEnqueueReadBuffer) {
		ptr_clEnqueueReadBuffer = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueReadBuffer function\n");
	}
	ptr_clEnqueueReadBufferRect = dlsym(opencl_dll, "clEnqueueReadBufferRect");
	if (!ptr_clEnqueueReadBufferRect) {
		ptr_clEnqueueReadBufferRect = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueReadBufferRect function\n");
	}
	ptr_clEnqueueWriteBuffer = dlsym(opencl_dll, "clEnqueueWriteBuffer");
	if (!ptr_clEnqueueWriteBuffer) {
		ptr_clEnqueueWriteBuffer = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueWriteBuffer function\n");
	}
	ptr_clEnqueueWriteBufferRect = dlsym(opencl_dll, "clEnqueueWriteBufferRect");
	if (!ptr_clEnqueueWriteBufferRect) {
		ptr_clEnqueueWriteBufferRect = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueWriteBufferRect function\n");
	}
	ptr_clEnqueueFillBuffer = dlsym(opencl_dll, "clEnqueueFillBuffer");
	if (!ptr_clEnqueueFillBuffer) {
		ptr_clEnqueueFillBuffer = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueFillBuffer function\n");
	}
	ptr_clEnqueueCopyBuffer = dlsym(opencl_dll, "clEnqueueCopyBuffer");
	if (!ptr_clEnqueueCopyBuffer) {
		ptr_clEnqueueCopyBuffer = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueCopyBuffer function\n");
	}
	ptr_clEnqueueCopyBufferRect = dlsym(opencl_dll, "clEnqueueCopyBufferRect");
	if (!ptr_clEnqueueCopyBufferRect) {
		ptr_clEnqueueCopyBufferRect = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueCopyBufferRect function\n");
	}
	ptr_clEnqueueMapBuffer = dlsym(opencl_dll, "clEnqueueMapBuffer");
	if (!ptr_clEnqueueMapBuffer) {
		ptr_clEnqueueMapBuffer = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueMapBuffer function\n");
	}
	ptr_clEnqueueUnmapMemObject = dlsym(opencl_dll, "clEnqueueUnmapMemObject");
	if (!ptr_clEnqueueUnmapMemObject) {
		ptr_clEnqueueUnmapMemObject = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueUnmapMemObject function\n");
	}
	ptr_clEnqueueMigrateMemObjects = dlsym(opencl_dll, "clEnqueueMigrateMemObjects");
	if (!ptr_clEnqueueMigrateMemObjects) {
		ptr_clEnqueueMigrateMemObjects = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueMigrateMemObjects function\n");
	}
	ptr_clEnqueueNDRangeKernel = dlsym(opencl_dll, "clEnqueueNDRangeKernel");
	if (!ptr_clEnqueueNDRangeKernel) {
		ptr_clEnqueueNDRangeKernel = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueNDRangeKernel function\n");
	}
	ptr_clEnqueueNativeKernel = dlsym(opencl_dll, "clEnqueueNativeKernel");
	if (!ptr_clEnqueueNativeKernel) {
		ptr_clEnqueueNativeKernel = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueNativeKernel function\n");
	}
	ptr_clEnqueueMarkerWithWaitList = dlsym(opencl_dll, "clEnqueueMarkerWithWaitList");
	if (!ptr_clEnqueueMarkerWithWaitList) {
		ptr_clEnqueueMarkerWithWaitList = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueMarkerWithWaitList function\n");
	}
	ptr_clEnqueueBarrierWithWaitList = dlsym(opencl_dll, "clEnqueueBarrierWithWaitList");
	if (!ptr_clEnqueueBarrierWithWaitList) {
		ptr_clEnqueueBarrierWithWaitList = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueBarrierWithWaitList function\n");
	}
	ptr_clGetExtensionFunctionAddressForPlatform = dlsym(opencl_dll, "clGetExtensionFunctionAddressForPlatform");
	if (!ptr_clGetExtensionFunctionAddressForPlatform) {
		ptr_clGetExtensionFunctionAddressForPlatform = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetExtensionFunctionAddressForPlatform function\n");
	}
	ptr_clSetCommandQueueProperty = dlsym(opencl_dll, "clSetCommandQueueProperty");
	if (!ptr_clSetCommandQueueProperty) {
		ptr_clSetCommandQueueProperty = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clSetCommandQueueProperty function\n");
	}
	ptr_clEnqueueMarker = dlsym(opencl_dll, "clEnqueueMarker");
	if (!ptr_clEnqueueMarker) {
		ptr_clEnqueueMarker = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueMarker function\n");
	}
	ptr_clEnqueueWaitForEvents = dlsym(opencl_dll, "clEnqueueWaitForEvents");
	if (!ptr_clEnqueueWaitForEvents) {
		ptr_clEnqueueWaitForEvents = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueWaitForEvents function\n");
	}
	ptr_clEnqueueBarrier = dlsym(opencl_dll, "clEnqueueBarrier");
	if (!ptr_clEnqueueBarrier) {
		ptr_clEnqueueBarrier = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueBarrier function\n");
	}
	ptr_clUnloadCompiler = dlsym(opencl_dll, "clUnloadCompiler");
	if (!ptr_clUnloadCompiler) {
		ptr_clUnloadCompiler = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clUnloadCompiler function\n");
	}
	ptr_clGetExtensionFunctionAddress = dlsym(opencl_dll, "clGetExtensionFunctionAddress");
	if (!ptr_clGetExtensionFunctionAddress) {
		ptr_clGetExtensionFunctionAddress = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clGetExtensionFunctionAddress function\n");
	}
	ptr_clCreateCommandQueue = dlsym(opencl_dll, "clCreateCommandQueue");
	if (!ptr_clCreateCommandQueue) {
		ptr_clCreateCommandQueue = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCreateCommandQueue function\n");
	}
	ptr_clCreateSampler = dlsym(opencl_dll, "clCreateSampler");
	if (!ptr_clCreateSampler) {
		ptr_clCreateSampler = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clCreateSampler function\n");
	}
	ptr_clEnqueueTask = dlsym(opencl_dll, "clEnqueueTask");
	if (!ptr_clEnqueueTask) {
		ptr_clEnqueueTask = (void *)unimplemented_function;
		fprintf(stderr, "Warning: Cannot find the clEnqueueTask function\n");
	}
}

#endif

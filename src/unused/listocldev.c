/* gcc listocldev.c -o listocldev -lOpenCL
 *
 * List all OpenCL platforms, their devices and some info.
 *
 * This  software is Copyright © 2012 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 */

#include <stdio.h>
#include <CL/cl.h>

#define MAX_PLATFORMS	10
#define MAX_DEVICES	10
#define MAX_STRING_LEN	512

int main(int argc, char** argv) {
	char dname[MAX_STRING_LEN];
	cl_device_id devices[MAX_DEVICES];
	cl_uint num_platforms, num_devices, entries;
	cl_ulong long_entries;
	int i, d;
	cl_int err;
	cl_platform_id platform_id[MAX_PLATFORMS];
	size_t p_size;

	/* Obtain list of platforms available */
	err = clGetPlatformIDs(MAX_PLATFORMS, platform_id, &num_platforms);
	if (err != CL_SUCCESS)
	{
		printf("Error: Failure in clGetPlatformIDs, error code=%d \n", err);
		return 1;
	}

	//printf("%d platforms found\n", num_platforms);

	for(i = 0; i < num_platforms; i++) {
		/* Obtain information about platform */
		clGetPlatformInfo(platform_id[i], CL_PLATFORM_NAME, MAX_STRING_LEN, dname, NULL);
		printf("Platform #%d name: %s\n", i, dname);
		clGetPlatformInfo(platform_id[i], CL_PLATFORM_VERSION, MAX_STRING_LEN, dname, NULL);
		printf("Platform version: %s\n", dname);

		/* Obtain list of devices available on platform */
		clGetDeviceIDs(platform_id[i], CL_DEVICE_TYPE_ALL, MAX_DEVICES, devices, &num_devices);
		if (!num_devices) printf("%d devices found\n", num_devices);

		/* Query devices for information */
		for (d = 0; d < num_devices; ++d) {
			clGetDeviceInfo(devices[d], CL_DEVICE_NAME, MAX_STRING_LEN, dname, NULL);
			printf("\tDevice #%d name:\t\t%s\n", d, dname);
			clGetDeviceInfo(devices[d], CL_DEVICE_VENDOR, MAX_STRING_LEN, dname, NULL);
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
			printf("\n");
			clGetDeviceInfo(devices[d], CL_DEVICE_VERSION, MAX_STRING_LEN, dname, NULL);
			printf("\tDevice version:\t\t%s\n", dname);
			clGetDeviceInfo(devices[d], CL_DRIVER_VERSION, MAX_STRING_LEN, dname, NULL);
			printf("\tDriver version:\t\t%s\n", dname);
			clGetDeviceInfo(devices[d], CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(cl_ulong), &long_entries, NULL);
			printf("\tGlobal Memory:\t\t%llu MB\n", (long long unsigned)long_entries>>20);
			clGetDeviceInfo(devices[d], CL_DEVICE_GLOBAL_MEM_CACHE_SIZE, sizeof(cl_ulong), &long_entries, NULL);
			printf("\tGlobal Memory Cache:\t%llu MB\n", (long long unsigned)long_entries>>20);
			clGetDeviceInfo(devices[d], CL_DEVICE_LOCAL_MEM_SIZE, sizeof(cl_ulong), &long_entries, NULL);
			printf("\tLocal Memory:\t\t%llu KB\n", (long long unsigned)long_entries>>10);
			clGetDeviceInfo(devices[d], CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(cl_ulong), &long_entries, NULL);
			printf("\tMax clock (MHz) :\t%llu\n", (long long unsigned)long_entries);
			clGetDeviceInfo(devices[d], CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(size_t), &p_size, NULL);
			printf("\tMax Work Group Size:\t%d\n", (int)p_size);
			clGetDeviceInfo(devices[d], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cl_uint), &entries, NULL);
			printf("\tParallel compute cores:\t%d\n\n", entries);
		}
	}
	return 0;
}

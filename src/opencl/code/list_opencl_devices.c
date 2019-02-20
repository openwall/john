/*
 * This file is part of John the Ripper password cracker.
 *
 * Common OpenCL functions.
 * - the <base> source code is opencl_common.c;
 *   - <base> includes this file;
 * - copyright notes are inside the <base> source code file.
 *
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 */

/* Defined in the <base> source code file */
static char *opencl_driver_info(int sequential_id);
static int get_if_device_is_in_use(int sequential_id);
static int start_opencl_device(int sequential_id, int *err_type);

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
	cl_int ret;
	cl_platform_id platform_list[MAX_PLATFORMS];
	cl_uint entries;
	cl_uint num_platforms, num_devices;
	cl_ulong long_entries;
	int available_devices = 0;
	int i, j, sequence_nr = 0, err_type = 0, platform_in_use = -1;
	size_t p_size;
	size_t z_entries;

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
			        ", clGetDeviceIDs() = %s\n", i, get_error_name(ret));

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
			char *p;
			cl_bool boolean;
			cl_device_local_mem_type memtype;
			int fan, temp, util, cl, ml;
			int ret, cpu;

			if (!getenv("_SKIP_OCL_INITIALIZATION") &&
			        (!default_gpu_selected &&
			         !get_if_device_is_in_use(sequence_nr)))
				/* Nothing to do, skipping */
				continue;

			if (platform_in_use != i) {
				/* Now, dealing with different platform. */
				/* Obtain information about platform */
				clGetPlatformInfo(platforms[i].platform,
				                  CL_PLATFORM_NAME, sizeof(dname),
				                  dname, NULL);
				printf("Platform #%d name: %s, ", i, dname);
				clGetPlatformInfo(platforms[i].platform,
				                  CL_PLATFORM_VERSION, sizeof(dname),
				                  dname, NULL);
				printf("version: %s\n", dname);

				clGetPlatformInfo(platforms[i].platform,
				                  CL_PLATFORM_EXTENSIONS,
				                  sizeof(dname), dname, NULL);
				if (options.verbosity > VERB_LEGACY)
					printf("    Platform extensions:    %s\n",
					       dname);

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
					       "Context creation error",
					       get_error_name(ret_code));
				else
					printf("    Status:                 %s (%s)\n",
					       "Queue creation error",
					       get_error_name(ret_code));
			}

			ret = clGetDeviceInfo(devices[sequence_nr],
			                      CL_DEVICE_BOARD_NAME_AMD, sizeof(dname),
			                      dname, NULL);
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
			                CL_DEVICE_ENDIAN_LITTLE, sizeof(cl_bool),
			                &boolean, NULL);
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
			                      CL_DEVICE_MAX_CLOCK_FREQUENCY,
			                      sizeof(cl_int), &entries, NULL);
			if (ret == CL_SUCCESS && entries)
				printf("    Max clock (MHz):        %u\n", entries);
			ret = clGetDeviceInfo(devices[sequence_nr],
			                      CL_DEVICE_PROFILING_TIMER_RESOLUTION,
			                      sizeof(size_t), &z_entries, NULL);
			if (ret == CL_SUCCESS && z_entries)
				printf("    Profiling timer res.:   " Zu " ns\n", z_entries);
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(size_t),
			                &p_size, NULL);
			printf("    Max Work Group Size:    %d\n", (int)p_size);
			clGetDeviceInfo(devices[sequence_nr],
			                CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cl_uint),
			                &entries, NULL);
			printf("    Parallel compute cores: %d\n", entries);

			long_entries = get_processors_count(sequence_nr);
			if (!cpu && ocl_device_list[sequence_nr].cores_per_MP > 1)
				printf("    %s      "LLu" "
				       " (%d x %d)\n",
				       gpu_nvidia(device_info[sequence_nr]) ?
				       "CUDA cores:       " : "Stream processors:",
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
				printf
				("    ADL:                    Overdrive%d, device id %d\n",
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

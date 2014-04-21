/*
* This software is Copyright (c) 2011-2012 Lukas Odzioba <ukasz at openwall dot net>
* Copyright (c) 2011-2014 magnum
* Copyright (c) 2014 Muhammad Junaid Muzammil <mjunaidmuzammil at gmail dot com>,
*  and it is hereby released to the general public under the following terms:
*  Redistribution and use in source and binary forms, with or without
*  modification, are permitted.
*/
#include <ctype.h>

#include "cuda_common.h"
#include "options.h"
#include "john.h"
#include "memdbg.h"

void cuda_init()
{
	int devices;
	struct list_entry *current;
	cudaError_t ret;

	ret = cudaGetDeviceCount(&devices);
	if (ret == cudaErrorNoDevice) {
		puts("Error: No CUDA-capable devices were detected by the installed CUDA driver.\n");
		exit(1);
	}
	if (ret == cudaErrorInsufficientDriver) {
		puts("Error: The installed NVIDIA CUDA driver is older than the CUDA runtime library.\nThis is not a supported configuration. Update your display driver.\n");
		exit(1);
	}

	nvidia_probe();
	gpu_device_list[0] = gpu_device_list[1] = -1;
	if ((current = options.gpu_devices->head)) {
		int n = 0;
		if (!isdigit(current->data[0])) {
			fprintf(stderr, "Invalid CUDA device id \"%s\"\n",
			        current->data);
			exit(1);
		}
		gpu_id = atoi(current->data);
		dev_get_temp[gpu_id] = nvml_lib ? nvidia_get_temp : NULL;
		temp_dev_id[gpu_id] = gpu_id;
		do {
			int device_repeat = 0, i;
			int device_id = atoi(current->data);
			for(i = 0; i < n; i++) {
				if(gpu_device_list[i] == device_id) {
					fprintf(stderr, "Duplicate CUDA device id %d\n", device_id);
					device_repeat = 1;
				}
			}
			if((device_repeat == 0) && (isdigit(current->data[0]))) {
				gpu_device_list[n++] = device_id;
			}

		} while ((current = current->next) && (n < MAX_GPU_DEVICES));

		if(n < MAX_GPU_DEVICES) {
			gpu_device_list[n] = -1;
		} else {
/* GPU DEVICE LIMIT log as number of devices approach MAX_GPU_DEVICES */
			fprintf(stderr, "Maximum GPU Device Limit %d Reached\n", MAX_GPU_DEVICES);
		}
	} else {
		gpu_device_list[0] = gpu_id = 0;
		dev_get_temp[gpu_id] = nvml_lib ? nvidia_get_temp : NULL;
		temp_dev_id[gpu_id] = gpu_id;
	}

	HANDLE_ERROR(cudaGetDeviceCount(&devices));
	if (gpu_id < devices && devices > 0)
		cudaSetDevice(gpu_id);
	else {
		fprintf(stderr, "Invalid CUDA device id = %d\n", gpu_id);
		exit(1);
	}
}

void cuda_done(void)
{
	if (nvml_lib)
		nvmlShutdown();
}

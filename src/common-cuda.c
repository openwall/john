/*
 The software updates are Copyright (c) 2014 Muhammad Junaid Muzammil <mjunaidmuzammil at gmail dot com>,
 and it is hereby released to the general public under the following terms:
 Redistribution and use in source and binary forms, with or without
 modification, are permitted.
*/
#include <ctype.h>
#include "cuda_common.h"
#include "options.h"
#include "john.h"

int cuda_gpu_id;
int cuda_dev_list[MAX_CUDA_DEVICES];

#ifndef HAVE_OPENCL
/* If we have OpenCL as well, we use its exact same function */
void advance_cursor()
{
	static int pos = 0;
	char cursor[4] = { '/', '-', '\\', '|' };

	if (john_main_process) {
		fprintf(stderr, "%c\b", cursor[pos]);
		pos = (pos + 1) % 4;
	}
}
#endif

void cuda_init()
{
	int devices;
	struct list_entry *current;

	if ((current = options.gpu_devices->head)) {
                int n = 0;
                if (!isdigit(current->data[0])) {
                        fprintf(stderr, "Invalid CUDA device id \"%s\"\n",
                                current->data);
                        exit(1);
                }
                cuda_gpu_id = atoi(current->data);
                do {
                        int device_repeat = 0, i;
                        int device_id = atoi(current->data);
                        for(i = 0; i < n; i++) {
                                if(cuda_dev_list[i] == device_id) {
                                        fprintf(stderr, "Duplicate CUDA device id %d\n", device_id);
                                        device_repeat = 1;
                                }
                        }
                        if((device_repeat == 0) && (isdigit(current->data[0]))) {
                                cuda_dev_list[n++] = device_id;
                        }

                 } while ((current = current->next) && (n < MAX_CUDA_DEVICES));

                if(n < MAX_CUDA_DEVICES) {
                        cuda_dev_list[n] = -1;
                }
                
                else {
/* GPU DEVICE LIMIT log as number of devices approach MAX_CUDA_DEVICES */                	
                	fprintf(stderr, "Maximum GPU Device Limit %d Reached\n", MAX_CUDA_DEVICES);
                }

	} else
		cuda_gpu_id = 0;

	HANDLE_ERROR(cudaGetDeviceCount(&devices));
	if (cuda_gpu_id < devices && devices > 0)
		cudaSetDevice(cuda_gpu_id);
	else {
		fprintf(stderr, "Invalid CUDA device id = %d\n", cuda_gpu_id);
		exit(1);
	}
}

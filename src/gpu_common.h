/* ***
 * This file is part of John the Ripper password cracker.
 *
 * Functions common to OpenCL and other accelerators (eg. FPGA) go in this file.
 *
 *
 * Copyright (c) 2013-2015 Claudio André <claudioandre.br at gmail.com>,
 * Copyright (c) 2012-2013 magnum,
 * Others and
 * is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 *** */

#ifndef _COMMON_GPU_H
#define _COMMON_GPU_H

#if defined (HAVE_OPENCL)

#if (__cplusplus)
extern "C" {
#endif

#include "gpu_sensors.h"

#define SUBSECTION_GPU			":GPU"

extern void *nvml_lib;
extern void *adl_lib;

typedef struct {
	int  bus;
	int  device;
	int  function;
	char busId[100];
} hw_bus;

#define DEV_LIST_END             -1
#define NO_GPU                   -1

#define MAX_GPU_DEVICES         128
extern int gpu_id;
extern int engaged_devices[MAX_GPU_DEVICES + 1];
extern int requested_devices[MAX_GPU_DEVICES + 1];

extern hw_bus gpu_device_bus[MAX_GPU_DEVICES];

extern int gpu_temp_limit;
extern int cool_gpu_down;
#define DEGREE_SIGN L"\xb0" // Degree sign as wchar_t

extern char gpu_degree_sign[8];

/* Progress indicator "spinning wheel" */
void advance_cursor(void);

/* Load nvidia-ml.so and populate function pointers if available */
void nvidia_probe(void);

/* Load libatiadlxx.so and populate function pointers if available */
void amd_probe(void);

/*
 * nvidia temperature/fan monitoring
 * https://developer.nvidia.com/sites/default/files/akamai/cuda/files/CUDADownloads/NVML_cuda5/nvml.4.304.55.pdf
 */
extern void nvidia_get_temp(int gpu_id, int *temp, int *fanspeed, int *util,
                            int *cl, int *ml);

extern void amd_get_temp(int adl_gpu_id, int *temp, int *fanspeed, int *util,
                         int *cl, int *ml);

/* Function pointer to read temperature for device n */
extern void (*dev_get_temp[MAX_GPU_DEVICES]) (int id, int *temp, int *fanspeed,
                                              int *util, int *cl, int *ml);

/* Map OpenCL device number to ADL/NVML device number */
extern unsigned int temp_dev_id[MAX_GPU_DEVICES];

/* Map OpenCL device number to ADL/NVML device number using PCI info */
extern int id2nvml(const hw_bus busInfo);
extern int id2adl(const hw_bus busInfo);

/* Mapping between our device number and ADL id */
extern int amd2adl[MAX_GPU_DEVICES];
extern int adl2od[MAX_GPU_DEVICES];

/* Check temperature limit */
extern void gpu_check_temp(void);

/* Log GPU sensors */
extern void gpu_log_temp(void);

#if (__cplusplus)
}
#endif

#endif /* defined (HAVE_OPENCL) */

#endif /* _COMMON_GPU_H */

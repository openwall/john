/* ***
 * This file is part of John the Ripper password cracker.
 *
 * Functions common to CUDA and OpenCL go in this file.
 *
 *
 * Copyright (c) 2013 by Claudio André <claudio.andre at correios.net.br>,
 * Copyright (c) 2012-2013 magnum,
 * Others and
 * is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 *** */

#if defined (HAVE_CUDA) || defined (HAVE_OPENCL)
#ifndef _COMMON_GPU_H
#define _COMMON_GPU_H

extern void *nvml_lib;
extern void *adl_lib;

#ifdef __linux__
#include <wchar.h>
#include "adl_sdk.h"

#define ADL_WARNING_NO_DATA -100
typedef int (*ADL_MAIN_CONTROL_CREATE)(ADL_MAIN_MALLOC_CALLBACK, int);
typedef int (*ADL_MAIN_CONTROL_DESTROY)();
typedef int (*ADL_ADAPTER_NUMBEROFADAPTERS_GET) (int*);
typedef int (*ADL_ADAPTER_ADAPTERINFO_GET) (LPAdapterInfo, int);
typedef int (*ADL_ADAPTER_ACTIVE_GET) (int, int*);
typedef int (*ADL_OVERDRIVE_CAPS) (int iAdapterIndex, int *iSupported, int *iEnabled, int *iVersion);

typedef int (*ADL_OVERDRIVE5_THERMALDEVICES_ENUM) (int iAdapterIndex, int iThermalControllerIndex, ADLThermalControllerInfo *lpThermalControllerInfo);
typedef int (*ADL_OVERDRIVE5_TEMPERATURE_GET) (int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature);
typedef int (*ADL_OVERDRIVE5_FANSPEED_GET) (int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedValue *lpFanSpeedValue);
typedef int (*ADL_OVERDRIVE5_FANSPEEDINFO_GET) (int iAdapterIndex, int iThermalControllerIndex, ADLFanSpeedInfo *lpFanSpeedInfo);
typedef int (*ADL_OVERDRIVE5_ODPARAMETERS_GET) (int iAdapterIndex, ADLODParameters *lpOdParameters);
typedef int (*ADL_OVERDRIVE5_CURRENTACTIVITY_GET) (int iAdapterIndex, ADLPMActivity *lpActivity);

typedef int (*ADL_OVERDRIVE6_FANSPEED_GET)(int iAdapterIndex, ADLOD6FanSpeedInfo *lpFanSpeedInfo);
typedef int (*ADL_OVERDRIVE6_THERMALCONTROLLER_CAPS)(int iAdapterIndex, ADLOD6ThermalControllerCaps *lpThermalControllerCaps);
typedef int (*ADL_OVERDRIVE6_TEMPERATURE_GET)(int iAdapterIndex, int *lpTemperature);
typedef int (*ADL_OVERDRIVE6_CURRENTSTATUS_GET)(int iAdapterIndex, ADLOD6CurrentStatus *lpCurrentStatus);
typedef int (*ADL_OVERDRIVE6_POWERCONTROL_GET)(int iAdapterIndex, int *lpCurrentValue, int *lpDefaultValue);

#endif

/* These are shared between CUDA and OpenCL */
#define MAX_GPU_DEVICES         128
extern int gpu_id;
extern int gpu_device_list[MAX_GPU_DEVICES];

#define DEGC "\xc2\xb0" "C" // UTF-8 degree sign, Celsius

typedef struct nvmlDevice_st* nvmlDevice_t;

typedef struct nvmlUtilization_st
{
    unsigned int gpu;    // GPU kernel execution last second, percent
    unsigned int memory; // GPU memory read/write last second, percent
} nvmlUtilization_t;

typedef enum nvmlReturn_enum
{
    NVML_SUCCESS = 0,                   // The operation was successful
    NVML_ERROR_UNINITIALIZED = 1,       // NVML was not first initialized with nvmlInit()
    NVML_ERROR_INVALID_ARGUMENT = 2,    // A supplied argument is invalid
    NVML_ERROR_NOT_SUPPORTED = 3,       // The requested operation is not available on target device
    NVML_ERROR_NO_PERMISSION = 4,       // The current user does not have permission for operation
    NVML_ERROR_ALREADY_INITIALIZED = 5, // Deprecated: Multiple initializations are now allowed through ref counting
    NVML_ERROR_NOT_FOUND = 6,           // A query to find an object was unsuccessful
    NVML_ERROR_INSUFFICIENT_SIZE = 7,   // An input argument is not large enough
    NVML_ERROR_INSUFFICIENT_POWER = 8,  // A device's external power cables are not properly attached
    NVML_ERROR_DRIVER_NOT_LOADED = 9,   // NVIDIA driver is not loaded
    NVML_ERROR_TIMEOUT = 10,            // User provided timeout passed
    NVML_ERROR_UNKNOWN = 999            // An internal driver error occurred
} nvmlReturn_t;

typedef enum nvmlTemperatureSensors_enum
{
    NVML_TEMPERATURE_GPU = 0     // Temperature sensor for the GPU die
} nvmlTemperatureSensors_t;

typedef nvmlReturn_t ( *NVMLINIT ) ();
typedef nvmlReturn_t ( *NVMLSHUTDOWN ) ();
typedef nvmlReturn_t ( *NVMLDEVICEGETHANDLEBYINDEX ) (unsigned int, nvmlDevice_t*);
typedef nvmlReturn_t ( *NVMLDEVICEGETTEMPERATURE )( nvmlDevice_t, int, unsigned int *);
typedef nvmlReturn_t ( *NVMLDEVICEGETFANSPEED ) (nvmlDevice_t, unsigned int *);
typedef nvmlReturn_t ( *NVMLDEVICEGETUTILIZATIONRATES ) (nvmlDevice_t, nvmlUtilization_t *);
//typedef nvmlReturn_t ( *NVMLDEVICEGETNAME ) (nvmlDevice_t, char *, unsigned int);

/* Progress indicator "spinning wheel" */
void advance_cursor(void);

/* Load nvidia-ml.so and populate function pointers if available */
void nvidia_probe(void);

/* Load libatiadlxx.so and populate function pointers if available */
void amd_probe(void);

extern NVMLSHUTDOWN nvmlShutdown;

/*
 * nvidia temperature/fan monitoring
 * https://developer.nvidia.com/sites/default/files/akamai/cuda/files/CUDADownloads/NVML_cuda5/nvml.4.304.55.pdf
 */
extern void nvidia_get_temp(int gpu_id, int *temp, int *fanspeed, int *util);

extern void amd_get_temp(int adl_gpu_id, int *temp, int *fanspeed, int *util);

/* Function pointer to read temperature for device n */
extern void (*dev_get_temp[MAX_GPU_DEVICES]) (int, int *, int *, int *);

/* Map OpenCL device number to ADL/NVML device number */
extern unsigned int temp_dev_id[MAX_GPU_DEVICES];

#endif /* _COMMON_GPU_H */
#endif /* HAVE_ */

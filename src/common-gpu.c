/*
 * This file is part of John the Ripper password cracker.
 *
 * Functions common to CUDA and OpenCL go in this file.
 *
 * This software is
 * Copyright (c) 2010-2012 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2010-2013 Lukas Odzioba <ukasz@openwall.net>
 * Copyright (c) 2010-2013 magnum
 * Copyright (c) 2012-2013 Claudio André <claudio.andre at correios.net.br>
 * and is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 */

#if defined (HAVE_CUDA) || defined (HAVE_OPENCL)

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>

#include "common-gpu.h"
#include "john.h"

/* These are shared between OpenCL and CUDA */
int gpu_id;
int gpu_device_list[MAX_GPU_DEVICES];

void *nvml_lib;
NVMLINIT nvmlInit = NULL;
NVMLSHUTDOWN nvmlShutdown = NULL;
NVMLDEVICEGETHANDLEBYINDEX nvmlDeviceGetHandleByIndex = NULL;
NVMLDEVICEGETTEMPERATURE nvmlDeviceGetTemperature = NULL;
NVMLDEVICEGETFANSPEED nvmlDeviceGetFanSpeed = NULL;
NVMLDEVICEGETUTILIZATIONRATES nvmlDeviceGetUtilizationRates = NULL;
//NVMLDEVICEGETNAME nvmlDeviceGetName = NULL;

void *adl_lib;

#ifdef __linux__
static int amd2adl[MAX_GPU_DEVICES];
static int adl2od[MAX_GPU_DEVICES];

ADL_MAIN_CONTROL_CREATE ADL_Main_Control_Create;
ADL_MAIN_CONTROL_DESTROY ADL_Main_Control_Destroy;
ADL_ADAPTER_NUMBEROFADAPTERS_GET ADL_Adapter_NumberOfAdapters_Get;
ADL_ADAPTER_ADAPTERINFO_GET ADL_Adapter_AdapterInfo_Get;
ADL_ADAPTER_ACTIVE_GET ADL_Adapter_Active_Get;
ADL_OVERDRIVE_CAPS ADL_Overdrive_Caps;

ADL_OVERDRIVE5_THERMALDEVICES_ENUM ADL_Overdrive5_ThermalDevices_Enum = NULL;
ADL_OVERDRIVE5_ODPARAMETERS_GET ADL_Overdrive5_ODParameters_Get = NULL;
ADL_OVERDRIVE5_TEMPERATURE_GET ADL_Overdrive5_Temperature_Get = NULL;
ADL_OVERDRIVE5_FANSPEED_GET ADL_Overdrive5_FanSpeed_Get = NULL;
ADL_OVERDRIVE5_FANSPEEDINFO_GET ADL_Overdrive5_FanSpeedInfo_Get = NULL;
ADL_OVERDRIVE5_CURRENTACTIVITY_GET ADL_Overdrive5_CurrentActivity_Get = NULL;

ADL_OVERDRIVE6_FANSPEED_GET ADL_Overdrive6_FanSpeed_Get = NULL;
ADL_OVERDRIVE6_THERMALCONTROLLER_CAPS ADL_Overdrive6_ThermalController_Caps = NULL;
ADL_OVERDRIVE6_TEMPERATURE_GET ADL_Overdrive6_Temperature_Get = NULL;
ADL_OVERDRIVE6_CURRENTSTATUS_GET ADL_Overdrive6_CurrentStatus_Get = NULL;

// Memory allocation callback function
static void*ADL_Main_Memory_Alloc(int iSize)
{
	void*lpBuffer = malloc(iSize);
	return lpBuffer;
}

#endif /* __linux__ */

void advance_cursor()
{
	static int pos = 0;
	char cursor[4] = { '/', '-', '\\', '|' };

	if (john_main_process) {
		fprintf(stderr, "%c\b", cursor[pos]);
		pos = (pos + 1) % 4;
	}
}

/* Function pointer to read temperature for device n */
void (*dev_get_temp[MAX_GPU_DEVICES]) (int, int *, int *, int *);

/* Map OpenCL device number to ADL/NVML device number */
unsigned int temp_dev_id[MAX_GPU_DEVICES];

void nvidia_probe(void)
{
	if (nvml_lib)
		return;

	if (!(nvml_lib = dlopen("libnvidia-ml.so", RTLD_LAZY|RTLD_GLOBAL)))
		return;

	nvmlInit = (NVMLINIT) dlsym(nvml_lib, "nvmlInit");
	nvmlShutdown = (NVMLSHUTDOWN) dlsym(nvml_lib, "nvmlShutdown");
	nvmlDeviceGetHandleByIndex = (NVMLDEVICEGETHANDLEBYINDEX) dlsym(nvml_lib, "nvmlDeviceGetHandleByIndex");
	nvmlDeviceGetTemperature = (NVMLDEVICEGETTEMPERATURE) dlsym(nvml_lib, "nvmlDeviceGetTemperature");
	nvmlDeviceGetFanSpeed = (NVMLDEVICEGETFANSPEED) dlsym(nvml_lib, "nvmlDeviceGetFanSpeed");
	nvmlDeviceGetUtilizationRates = (NVMLDEVICEGETUTILIZATIONRATES) dlsym(nvml_lib, "nvmlDeviceGetUtilizationRates");
	//nvmlDeviceGetName = (NVMLDEVICEGETNAME) dlsym(nvml_lib, "nvmlDeviceGetName");

	nvmlInit();
}

void amd_probe(void)
{
#ifdef __linux__
	LPAdapterInfo lpAdapterInfo = NULL;
	int i, ret;
	int iNumberAdapters = 0;
	int iOverdriveSupported = 0;
	int iOverdriveEnabled = 0;
	int iOverdriveVersion = 0;
	char *env;
	int amd = 0;

	if (adl_lib)
		return;

	if (!(adl_lib = dlopen("libatiadlxx.so", RTLD_LAZY|RTLD_GLOBAL)))
		return;

	env = getenv("COMPUTE");
	if (env && *env)
		setenv("DISPLAY", env, 1);
	else {
		env = getenv("DISPLAY");
		if (!env || !*env) {
			//fprintf(stderr, "Warning: No DISPLAY nor COMPUTE variable set. Defaulting to :0\n");
			setenv("DISPLAY", ":0", 1);
		}
	}

	ADL_Main_Control_Create = (ADL_MAIN_CONTROL_CREATE) dlsym(adl_lib,"ADL_Main_Control_Create");
	ADL_Main_Control_Destroy = (ADL_MAIN_CONTROL_DESTROY) dlsym(adl_lib,"ADL_Main_Control_Destroy");
	ADL_Adapter_NumberOfAdapters_Get = (ADL_ADAPTER_NUMBEROFADAPTERS_GET) dlsym(adl_lib,"ADL_Adapter_NumberOfAdapters_Get");
	ADL_Adapter_AdapterInfo_Get = (ADL_ADAPTER_ADAPTERINFO_GET) dlsym(adl_lib,"ADL_Adapter_AdapterInfo_Get");
	ADL_Adapter_Active_Get = (ADL_ADAPTER_ACTIVE_GET)dlsym(adl_lib, "ADL_Adapter_Active_Get");
	ADL_Overdrive_Caps = (ADL_OVERDRIVE_CAPS)dlsym(adl_lib, "ADL_Overdrive_Caps");

	ADL_Overdrive5_ThermalDevices_Enum = (ADL_OVERDRIVE5_THERMALDEVICES_ENUM) dlsym(adl_lib, "ADL_Overdrive5_ThermalDevices_Enum");
	ADL_Overdrive5_Temperature_Get = (ADL_OVERDRIVE5_TEMPERATURE_GET) dlsym(adl_lib, "ADL_Overdrive5_Temperature_Get");
	ADL_Overdrive5_FanSpeed_Get = (ADL_OVERDRIVE5_FANSPEED_GET) dlsym(adl_lib, "ADL_Overdrive5_FanSpeed_Get");
	ADL_Overdrive5_FanSpeedInfo_Get = (ADL_OVERDRIVE5_FANSPEEDINFO_GET) dlsym(adl_lib, "ADL_Overdrive5_FanSpeedInfo_Get");
	ADL_Overdrive5_ODParameters_Get = (ADL_OVERDRIVE5_ODPARAMETERS_GET) dlsym(adl_lib, "ADL_Overdrive5_ODParameters_Get");
	ADL_Overdrive5_CurrentActivity_Get = (ADL_OVERDRIVE5_CURRENTACTIVITY_GET) dlsym(adl_lib, "ADL_Overdrive5_CurrentActivity_Get");

	ADL_Overdrive6_FanSpeed_Get = (ADL_OVERDRIVE6_FANSPEED_GET) dlsym(adl_lib,"ADL_Overdrive6_FanSpeed_Get");
	ADL_Overdrive6_ThermalController_Caps = (ADL_OVERDRIVE6_THERMALCONTROLLER_CAPS)dlsym(adl_lib, "ADL_Overdrive6_ThermalController_Caps");
	ADL_Overdrive6_Temperature_Get = (ADL_OVERDRIVE6_TEMPERATURE_GET)dlsym(adl_lib, "ADL_Overdrive6_Temperature_Get");
	ADL_Overdrive6_CurrentStatus_Get = (ADL_OVERDRIVE6_CURRENTSTATUS_GET)dlsym(adl_lib, "ADL_Overdrive6_CurrentStatus_Get");

	if ((ret = ADL_Main_Control_Create(ADL_Main_Memory_Alloc, 1)) != ADL_OK)
		return;

	// Obtain the number of adapters for the system
	if (ADL_Adapter_NumberOfAdapters_Get(&iNumberAdapters) != ADL_OK) {
		//printf("Cannot get the number of adapters!\n");
		return;
	}

	if (iNumberAdapters > 0) {
		lpAdapterInfo = (LPAdapterInfo)malloc(sizeof(AdapterInfo) * iNumberAdapters);
		memset(lpAdapterInfo,'\0', sizeof(AdapterInfo) * iNumberAdapters);

		ADL_Adapter_AdapterInfo_Get(lpAdapterInfo, sizeof(AdapterInfo) * iNumberAdapters);
	}

	for (i = 0; i < iNumberAdapters; i++) {
		int adapterActive = 0;
		AdapterInfo adapterInfo = lpAdapterInfo[i];

		ADL_Adapter_Active_Get(adapterInfo.iAdapterIndex , &adapterActive);
		if (adapterActive) {
			int adl_id = adapterInfo.iAdapterIndex;

			amd2adl[amd++] = adl_id;
			adl2od[adl_id] = 0;

			if (ADL_Overdrive_Caps(adl_id, &iOverdriveSupported, &iOverdriveEnabled, &iOverdriveVersion) != ADL_OK) {
				//printf("Can't get Overdrive capabilities\n");
				return;
			}

			if (!iOverdriveSupported) {
				//printf("Overdrive is not supported\n");
				return;
			}

			if (iOverdriveVersion == 5)
				adl2od[adl_id] = 5;
			else if (iOverdriveVersion == 6)
				adl2od[adl_id] = 6;
			else
				adl2od[adl_id] = 0;
		}
	}
#endif
}

void nvidia_get_temp(int gpu_id, int *temp, int *fanspeed, int *util)
{
	nvmlUtilization_t s_util;
	nvmlDevice_t dev;
	unsigned int value;
	//char name[80];

	if (nvmlDeviceGetHandleByIndex(gpu_id, &dev) != NVML_SUCCESS) {
		*temp = *fanspeed = *util = -1;
		return;
	}

	if (nvmlDeviceGetTemperature(dev, NVML_TEMPERATURE_GPU, &value) == NVML_SUCCESS)
		*temp = value;
	else
		*temp = -1;
	if (nvmlDeviceGetFanSpeed(dev, &value) == NVML_SUCCESS)
		*fanspeed = value;
	else
		*fanspeed = -1;
	if (nvmlDeviceGetUtilizationRates(dev, &s_util) == NVML_SUCCESS)
		*util = s_util.gpu;
	else
		*util = -1;

	//if (nvmlDeviceGetName(dev, name, sizeof(name)) == NVML_SUCCESS)
	//	printf("Querying %s\n", name);
}

#ifdef __linux__
static void get_temp_od5(int adl_id, int *temp, int *fanspeed, int *util)
{
	int ADL_Err = ADL_ERR;
	ADLFanSpeedInfo fanSpeedInfo = { 0 };
	int fanSpeedReportingMethod = 0;
	int iThermalControllerIndex;
	ADLThermalControllerInfo termalControllerInfo = { 0 };
	ADLODParameters overdriveParameters = { 0 };
	ADLPMActivity activity = { 0 };

	*temp = *fanspeed = *util = -1;

	if (!ADL_Overdrive5_ThermalDevices_Enum ||
	    !ADL_Overdrive5_Temperature_Get ||
	    !ADL_Overdrive5_FanSpeed_Get ||
	    !ADL_Overdrive5_FanSpeedInfo_Get ||
	    !ADL_Overdrive5_ODParameters_Get ||
	    !ADL_Overdrive5_CurrentActivity_Get)
		return;

	termalControllerInfo.iSize = sizeof(ADLThermalControllerInfo);

	for (iThermalControllerIndex = 0; iThermalControllerIndex < 10; iThermalControllerIndex++) {
		ADL_Err = ADL_Overdrive5_ThermalDevices_Enum(adl_id, iThermalControllerIndex, &termalControllerInfo);

		if (ADL_Err == ADL_WARNING_NO_DATA)
			break;

		if (termalControllerInfo.iThermalDomain == ADL_DL_THERMAL_DOMAIN_GPU) {
			ADLTemperature adlTemperature = { 0 };
			ADLFanSpeedValue fanSpeedValue = { 0 };

			adlTemperature.iSize = sizeof(ADLTemperature);
			if (ADL_Overdrive5_Temperature_Get(adl_id, iThermalControllerIndex, &adlTemperature) == ADL_OK)
				*temp = adlTemperature.iTemperature / 1000;

			fanSpeedInfo.iSize = sizeof(ADLFanSpeedInfo);
			if (ADL_Overdrive5_FanSpeedInfo_Get(adl_id, iThermalControllerIndex, &fanSpeedInfo) == ADL_OK)
			if ((fanSpeedReportingMethod = (fanSpeedInfo.iFlags & ADL_DL_FANCTRL_SUPPORTS_PERCENT_READ))) {
				fanSpeedValue.iSpeedType = fanSpeedReportingMethod;
				if (ADL_Overdrive5_FanSpeed_Get(adl_id, iThermalControllerIndex, &fanSpeedValue) == ADL_OK)
					*fanspeed = fanSpeedValue.iFanSpeed;
			}
		}
	}

	overdriveParameters.iSize = sizeof(ADLODParameters);
	if (ADL_Overdrive5_ODParameters_Get(adl_id, &overdriveParameters) == ADL_OK) {
		activity.iSize = sizeof(ADLPMActivity);
		if (ADL_Overdrive5_CurrentActivity_Get(adl_id, &activity) == ADL_OK)
		if (overdriveParameters.iActivityReportingSupported)
			*util = activity.iActivityPercent;
	}

	return;
}

static void get_temp_od6(int adl_id, int *temp, int *fanspeed, int *util)
{
	ADLOD6FanSpeedInfo fanSpeedInfo = { 0 };
	ADLOD6ThermalControllerCaps thermalControllerCaps = { 0 };
	ADLOD6Capabilities od6Capabilities = { 0 };
	int temperature = 0;
	ADLOD6CurrentStatus currentStatus = { 0 };

	*temp = *fanspeed = *util = -1;

	if (!ADL_Overdrive6_FanSpeed_Get ||
	    !ADL_Overdrive6_ThermalController_Caps ||
	    !ADL_Overdrive6_Temperature_Get ||
	    !ADL_Overdrive6_CurrentStatus_Get)
		return;

	if (ADL_Overdrive6_ThermalController_Caps(adl_id, &thermalControllerCaps) == ADL_OK) {
		if (thermalControllerCaps.iCapabilities & ADL_OD6_TCCAPS_FANSPEED_CONTROL)
		if (thermalControllerCaps.iCapabilities & ADL_OD6_TCCAPS_FANSPEED_PERCENT_READ)
		if (ADL_Overdrive6_FanSpeed_Get(adl_id, &fanSpeedInfo) == ADL_OK)
		if (fanSpeedInfo.iSpeedType & ADL_OD6_FANSPEED_TYPE_PERCENT)
			*fanspeed = fanSpeedInfo.iFanSpeedPercent;

		if (thermalControllerCaps.iCapabilities & ADL_OD6_TCCAPS_THERMAL_CONTROLLER)
		if (ADL_Overdrive6_Temperature_Get(adl_id, &temperature) == ADL_OK)
			*temp = temperature / 1000;

		if (ADL_Overdrive6_CurrentStatus_Get(adl_id, &currentStatus) == ADL_OK)
		if (od6Capabilities.iCapabilities & ADL_OD6_CAPABILITY_GPU_ACTIVITY_MONITOR)
			*util = currentStatus.iActivityPercent;
	}

	return;
}
#endif

void amd_get_temp(int amd_id, int *temp, int *fanspeed, int *util)
{
#ifdef __linux__
	int adl_id = amd2adl[amd_id];

	if (adl2od[adl_id] == 5) {
		get_temp_od5(adl_id, temp, fanspeed, util);
	} else if (adl2od[adl_id] == 6) {
		get_temp_od6(adl_id, temp, fanspeed, util);
	} else
#endif
		*temp = *fanspeed = *util = -1;
}

#endif /* HAVE_ */

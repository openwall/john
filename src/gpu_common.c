/*
 * This file is part of John the Ripper password cracker.
 *
 * Functions common to OpenCL and other accelerators (eg. FPGA) go in this file.
 *
 * This software is
 * Copyright (c) 2010-2012 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2010-2013 Lukas Odzioba <ukasz@openwall.net>
 * Copyright (c) 2010-2013 magnum
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * and is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 */

#if defined (HAVE_OPENCL)

#ifdef AC_BUILT
#include "autoconfig.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#if HAVE_LIBDL
#include <dlfcn.h>
#elif HAVE_WINDOWS_H
// For mingw/VC
#include "Win32-dlfcn-port.h"
#define HAVE_LIBDL 1
#endif

#include <string.h>

#include "gpu_common.h"
#include "john.h"
#include "memory.h"
#include "params.h"
#include "logger.h"
#include "signals.h"
#ifndef BENCH_BUILD
#include "options.h"
#endif

int gpu_id;
int engaged_devices[MAX_GPU_DEVICES + 1];
int requested_devices[MAX_GPU_DEVICES + 1];
hw_bus gpu_device_bus[MAX_GPU_DEVICES];

int gpu_temp_limit, cool_gpu_down;
char gpu_degree_sign[8] = "";

void *nvml_lib;
#if __linux__ && HAVE_LIBDL
NVMLINIT nvmlInit;
NVMLSHUTDOWN nvmlShutdown;
NVMLDEVICEGETHANDLEBYINDEX nvmlDeviceGetHandleByIndex;
NVMLDEVICEGETTEMPERATURE nvmlDeviceGetTemperature;
NVMLDEVICEGETFANSPEED nvmlDeviceGetFanSpeed;
NVMLDEVICEGETUTILIZATIONRATES nvmlDeviceGetUtilizationRates;
NVMLDEVICEGETPCIINFO nvmlDeviceGetPciInfo;
NVMLDEVICEGETNAME nvmlDeviceGetName;
NVMLDEVICEGETHANDLEBYPCIBUSID nvmlDeviceGetHandleByPciBusId;
NVMLDEVICEGETINDEX nvmlDeviceGetIndex;
NVMLDEVICEGETCURRPCIELINKWIDTH nvmlDeviceGetCurrPcieLinkWidth;
NVMLDEVICEGETMAXPCIELINKWIDTH nvmlDeviceGetMaxPcieLinkWidth;
#endif /* __linux__ && HAVE_LIBDL */

void *adl_lib;

#if HAVE_LIBDL
static int amd = 0;
int amd2adl[MAX_GPU_DEVICES];
int adl2od[MAX_GPU_DEVICES];

ADL_MAIN_CONTROL_CREATE ADL_Main_Control_Create;
ADL_MAIN_CONTROL_DESTROY ADL_Main_Control_Destroy;
ADL_ADAPTER_NUMBEROFADAPTERS_GET ADL_Adapter_NumberOfAdapters_Get;
ADL_ADAPTER_ADAPTERINFO_GET ADL_Adapter_AdapterInfo_Get;
ADL_ADAPTER_ACTIVE_GET ADL_Adapter_Active_Get;
ADL_OVERDRIVE_CAPS ADL_Overdrive_Caps;

ADL_OVERDRIVE5_THERMALDEVICES_ENUM ADL_Overdrive5_ThermalDevices_Enum;
ADL_OVERDRIVE5_ODPARAMETERS_GET ADL_Overdrive5_ODParameters_Get;
ADL_OVERDRIVE5_TEMPERATURE_GET ADL_Overdrive5_Temperature_Get;
ADL_OVERDRIVE5_FANSPEED_GET ADL_Overdrive5_FanSpeed_Get;
ADL_OVERDRIVE5_FANSPEEDINFO_GET ADL_Overdrive5_FanSpeedInfo_Get;
ADL_OVERDRIVE5_CURRENTACTIVITY_GET ADL_Overdrive5_CurrentActivity_Get;

ADL_OVERDRIVE6_FANSPEED_GET ADL_Overdrive6_FanSpeed_Get;
ADL_OVERDRIVE6_THERMALCONTROLLER_CAPS ADL_Overdrive6_ThermalController_Caps;
ADL_OVERDRIVE6_TEMPERATURE_GET ADL_Overdrive6_Temperature_Get;
ADL_OVERDRIVE6_CURRENTSTATUS_GET ADL_Overdrive6_CurrentStatus_Get;
ADL_OVERDRIVE6_CAPABILITIES_GET ADL_Overdrive6_Capabilities_Get;

// Memory allocation callback function
static void* ADL_Main_Memory_Alloc(int iSize)
{
	void*lpBuffer = malloc(iSize);
	return lpBuffer;
}

#endif /* HAVE_LIBDL */

void advance_cursor()
{
	static int pos = 0;
	char cursor[4] = { '/', '-', '\\', '|' };

	if (john_main_process && isatty(fileno(stderr))) {
		fprintf(stderr, "%c\b", cursor[pos]);
		pos = (pos + 1) % 4;
	}
}

/* Function pointer to read temperature for device n */
void (*dev_get_temp[MAX_GPU_DEVICES]) (int id, int *temp, int *fanspeed,
                                       int *util, int *cl, int *ml);

/* Map OpenCL device number to ADL/NVML device number */
unsigned int temp_dev_id[MAX_GPU_DEVICES];

void nvidia_probe(void)
{
#if __linux__ && HAVE_LIBDL
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
	nvmlDeviceGetPciInfo = (NVMLDEVICEGETPCIINFO) dlsym(nvml_lib, "nvmlDeviceGetPciInfo");
	nvmlDeviceGetName = (NVMLDEVICEGETNAME) dlsym(nvml_lib, "nvmlDeviceGetName");
	nvmlDeviceGetHandleByPciBusId = (NVMLDEVICEGETHANDLEBYPCIBUSID) dlsym(nvml_lib, "nvmlDeviceGetHandleByPciBusId");
	nvmlDeviceGetIndex = (NVMLDEVICEGETINDEX) dlsym(nvml_lib, "nvmlDeviceGetIndex");
	//nvmlUnitGetCount = (NVMLUNITGETCOUNT) dlsym(nvml_lib, "nvmlUnitGetCount");
	nvmlDeviceGetCurrPcieLinkWidth = (NVMLDEVICEGETCURRPCIELINKWIDTH) dlsym(nvml_lib, "nvmlDeviceGetCurrPcieLinkWidth");
	nvmlDeviceGetMaxPcieLinkWidth = (NVMLDEVICEGETMAXPCIELINKWIDTH) dlsym(nvml_lib, "nvmlDeviceGetMaxPcieLinkWidth");
	nvmlInit();
#endif
}

void amd_probe(void)
{
#if HAVE_LIBDL
	LPAdapterInfo lpAdapterInfo = NULL;
	int i, ret;
	int iNumberAdapters = 0;
	int iOverdriveSupported = 0;
	int iOverdriveEnabled = 0;
	int iOverdriveVersion = 0;
	char *env;

	if (adl_lib)
		return;

#if HAVE_WINDOWS_H
	if (!(adl_lib = dlopen("atiadlxx.dll", RTLD_LAZY|RTLD_GLOBAL)) &&
	    !(adl_lib = dlopen("atiadlxy.dll", RTLD_LAZY|RTLD_GLOBAL)))
		return;
#else
	if (!(adl_lib = dlopen("libatiadlxx.so", RTLD_LAZY|RTLD_GLOBAL)))
		return;
#endif

	env = getenv("COMPUTE");
	if (env && *env)
		setenv("DISPLAY", env, 1);
	else {
		env = getenv("DISPLAY");
		if (!env || !*env)
			setenv("DISPLAY", ":0", 1);
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
	ADL_Overdrive6_Capabilities_Get = (ADL_OVERDRIVE6_CAPABILITIES_GET)dlsym(adl_lib, "ADL_Overdrive6_Capabilities_Get");

	if ((ret = ADL_Main_Control_Create(ADL_Main_Memory_Alloc, 1)) != ADL_OK)
		return;

	// Obtain the number of adapters for the system
	if (ADL_Adapter_NumberOfAdapters_Get(&iNumberAdapters) != ADL_OK)
		return;

	if (iNumberAdapters > 0) {
		lpAdapterInfo = (LPAdapterInfo)mem_alloc(sizeof(AdapterInfo) * iNumberAdapters);
		memset(lpAdapterInfo,'\0', sizeof(AdapterInfo) * iNumberAdapters);

		ADL_Adapter_AdapterInfo_Get(lpAdapterInfo, sizeof(AdapterInfo) * iNumberAdapters);
	}

	for (i = 0; i < iNumberAdapters; i++) {
		int adapterActive = 0;
		AdapterInfo adapterInfo = lpAdapterInfo[i];

		ADL_Adapter_Active_Get(adapterInfo.iAdapterIndex , &adapterActive);
		if (adapterActive) {
			int adl_id = adapterInfo.iAdapterIndex;

			amd2adl[amd] = adl_id;
			adl2od[adl_id] = 0;
			gpu_device_bus[amd].bus = adapterInfo.iBusNumber;
			gpu_device_bus[amd].device = adapterInfo.iDeviceNumber;
			gpu_device_bus[amd].function = adapterInfo.iFunctionNumber;

#if OCL_DEBUG
			printf("amd %u adl %u hardware id %02x:%02x.%x\n", amd, adl_id, gpu_device_bus[amd].bus, gpu_device_bus[amd].device,gpu_device_bus[amd].function);
#endif
			memset(gpu_device_bus[amd].busId, '\0', sizeof(gpu_device_bus[amd].busId));
			sprintf(gpu_device_bus[amd].busId, "%02x:%02x.%x", gpu_device_bus[amd].bus,
				gpu_device_bus[amd].device,gpu_device_bus[amd].function);

			amd++;

			if (ADL_Overdrive_Caps(adl_id, &iOverdriveSupported, &iOverdriveEnabled, &iOverdriveVersion) != ADL_OK) {
				MEM_FREE(lpAdapterInfo);
				ADL_Main_Control_Destroy();
				return;
			}

			if (!iOverdriveSupported) {
				MEM_FREE(lpAdapterInfo);
				ADL_Main_Control_Destroy();
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
	MEM_FREE(lpAdapterInfo);
	ADL_Main_Control_Destroy();
#endif
}

void nvidia_get_temp(int nvml_id, int *temp, int *fanspeed, int *util,
                     int *cl, int *ml)
{
#if __linux__ && HAVE_LIBDL
	nvmlUtilization_t s_util;
	nvmlDevice_t dev;
	unsigned int value;

	if (nvmlDeviceGetHandleByIndex(nvml_id, &dev) != NVML_SUCCESS) {
		*temp = *fanspeed = *util = *cl = *ml = -1;
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
	if (nvmlDeviceGetMaxPcieLinkWidth(dev, &value) == NVML_SUCCESS)
		*ml = value;
	if (nvmlDeviceGetCurrPcieLinkWidth(dev, &value) == NVML_SUCCESS)
		*cl = value;
	else
		*cl = *ml;
	if (*ml < *cl)
		*ml = *cl;
#endif /* __linux__ && HAVE_LIBDL */
}

#if HAVE_LIBDL
static void get_temp_od5(int adl_id, int *temp, int *fanspeed, int *util,
                         int *cl, int *ml)
{
	int ADL_Err = ADL_ERR;
	ADLFanSpeedInfo fanSpeedInfo = { 0 };
	int fanSpeedReportingMethod = 0;
	int iThermalControllerIndex;
	ADLThermalControllerInfo termalControllerInfo = { 0 };
	ADLODParameters overdriveParameters = { 0 };
	ADLPMActivity activity = { 0 };

	if (ADL_Main_Control_Create(ADL_Main_Memory_Alloc, 1) != ADL_OK)
		return;

	*temp = *fanspeed = *util = *cl = *ml = -1;

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
		if (overdriveParameters.iActivityReportingSupported) {
			*util = activity.iActivityPercent;
			*cl = activity.iCurrentBusLanes;
			*ml = activity.iMaximumBusLanes;
		}
	}

	ADL_Main_Control_Destroy();
	return;
}

static void get_temp_od6(int adl_id, int *temp, int *fanspeed, int *util,
                         int *cl, int *ml)
{
	ADLOD6FanSpeedInfo fanSpeedInfo = { 0 };
	ADLOD6ThermalControllerCaps thermalControllerCaps = { 0 };
	ADLOD6Capabilities od6Capabilities = { 0 };
	int temperature = 0;
	ADLOD6CurrentStatus currentStatus = { 0 };

	if (ADL_Main_Control_Create(ADL_Main_Memory_Alloc, 1) != ADL_OK)
		return;

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

		if (ADL_Overdrive6_Capabilities_Get(adl_id, &od6Capabilities) == ADL_OK)
		if (od6Capabilities.iCapabilities & ADL_OD6_CAPABILITY_GPU_ACTIVITY_MONITOR)
		if (ADL_Overdrive6_CurrentStatus_Get(adl_id, &currentStatus) == ADL_OK)
		{
			*util = currentStatus.iActivityPercent;
			*cl = currentStatus.iCurrentBusLanes;
			*ml = currentStatus.iMaximumBusLanes;
		}
	}

	ADL_Main_Control_Destroy();
	return;
}
#endif

void amd_get_temp(int amd_id, int *temp, int *fanspeed, int *util, int *cl,
                  int *ml)
{
#if HAVE_LIBDL
	int adl_id = amd_id;

	if (adl2od[adl_id] == 5) {
		get_temp_od5(adl_id, temp, fanspeed, util, cl, ml);
	} else if (adl2od[adl_id] == 6) {
		get_temp_od6(adl_id, temp, fanspeed, util, cl, ml);
	} else
#endif
		*temp = *fanspeed = *util = *cl = *ml = -1;
}

int id2nvml(const hw_bus busInfo) {
#if __linux__ && HAVE_LIBDL
	nvmlDevice_t dev;

	if (nvmlDeviceGetHandleByPciBusId &&
	    nvmlDeviceGetHandleByPciBusId(busInfo.busId, &dev) == NVML_SUCCESS &&
	    nvmlDeviceGetIndex)
	{
		unsigned int id_NVML;

		if (nvmlDeviceGetIndex(dev, &id_NVML) == NVML_SUCCESS)
			return id_NVML;
	}
#endif
	return -1;
}

int id2adl(const hw_bus busInfo) {
#if HAVE_LIBDL
	int hardware_id = 0;

	while (hardware_id < amd) {

		if (gpu_device_bus[hardware_id].bus == busInfo.bus &&
		    gpu_device_bus[hardware_id].device == busInfo.device &&
		    gpu_device_bus[hardware_id].function == busInfo.function)
			return amd2adl[hardware_id];

		hardware_id++;
	}
#endif
	return -1;
}

void gpu_check_temp(void)
{
#if HAVE_LIBDL
	static int warned, warnedTemperature;
	int i, hot_gpu = 0, alerts = 0;

	if (gpu_temp_limit < 0)
		return;

	for (i = 0; i < MAX_GPU_DEVICES && engaged_devices[i] != DEV_LIST_END; i++)
	if (dev_get_temp[engaged_devices[i]]) {
		int fan, temp, util, cl, ml;
		int dev = engaged_devices[i];

		dev_get_temp[dev](temp_dev_id[dev], &temp, &fan, &util, &cl, &ml);

		if (temp > 125 || temp < 10) {
			if (!warned++) {
				log_event("Device %d probably invalid temp reading (%d%sC).",
				          dev + 1, temp, gpu_degree_sign);
				fprintf(stderr,
				        "Device %d probably invalid temp reading (%d%sC).\n",
				        dev + 1, temp, gpu_degree_sign);
			}
			return;
		}

		if (temp >= gpu_temp_limit) {

			if (!alerts++ && !event_abort && !warnedTemperature) {
				char s_fan[16] = "n/a";
				if (fan >= 0)
					sprintf(s_fan, "%u%%", fan);

				if (cool_gpu_down == 1)
					warnedTemperature++;

				log_event("Device %d overheat (%d%sC, fan %s), %s%s.",
				          dev + 1, temp, gpu_degree_sign, s_fan,
				          (cool_gpu_down > 0) ? "sleeping" : "aborting job",
				          (hot_gpu) ? " again" : "");
				fprintf(stderr,
				        "Device %d overheat (%d%sC, fan %s), %s%s.\n",
				        dev + 1, temp, gpu_degree_sign, s_fan,
				        (cool_gpu_down > 0) ? "sleeping" : "aborting job",
				        (hot_gpu) ? " again" : "");
			}
			hot_gpu = 1;
			/***
			 * Graceful handling of GPU overheating
			 * - sleep for a while before re-checking the temperature.
			 ***/
			if (cool_gpu_down > 0) {
				int t = cool_gpu_down;
				while ((t = sleep(t)) && !event_abort);

				// Warn again in case things don't calm down
				if (alerts > 5)
					alerts = 0;

				/***
				 * Re-check the temperature of the same GPU.
				 * And loop indefinidely:
				 * - if the GPU doesn't cool down enough during the sleep time
				 ***/
				i--;
				continue;
			} else
				event_abort++;
		} else {

			if (hot_gpu && options.verbosity > VERB_DEFAULT &&
			    !warnedTemperature) {
				char s_fan[16] = "n/a";
				if (fan >= 0)
					sprintf(s_fan, "%u%%", fan);

				log_event("Device %d is waking up (%d%sC, fan %s).",
				          dev + 1, temp, gpu_degree_sign, s_fan);
				fprintf(stderr,
				        "Device %d is waking up (%d%sC, fan %s).\n",
				        dev + 1, temp, gpu_degree_sign, s_fan);
			}
			hot_gpu = 0;
		}
	}
#endif
}

void gpu_log_temp(void)
{
#if HAVE_LIBDL
	int i;

	for (i = 0; i < MAX_GPU_DEVICES && engaged_devices[i] != DEV_LIST_END; i++)
	if (dev_get_temp[engaged_devices[i]]) {
		char s_gpu[256] = "";
		int n, fan, temp, util, cl, ml;
		int dev = engaged_devices[i];

		fan = temp = util = -1;
		dev_get_temp[dev](temp_dev_id[dev], &temp, &fan, &util, &cl, &ml);
		n = sprintf(s_gpu, "Device %d:", dev + 1);
		if (temp >= 0)
			n += sprintf(s_gpu + n, " temp: %u%sC", temp, gpu_degree_sign);
		if (util > 0)
			n += sprintf(s_gpu + n, " util: %u%%", util);
		if (fan >= 0)
			n += sprintf(s_gpu + n, " fan: %u%%", fan);
		if (temp >= 0 || util > 0 || fan > 0)
			log_event("- %s", s_gpu);
	}
#endif
}

#endif /* defined (HAVE_OPENCL) */

/*
 * Glue for NVIDIA and AMD hardware sensors' libs. This is a subset of
 * typedefs and defines for e.g. JtR and is distributed under the "fair use"
 * doctrine. For complete headers and documentation, see respective vendor's
 * SDK.
 *
 * This software is Copyright (c) 2016, magnum and is hereby released to
 * the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 */

#ifndef _GPU_SENSORS_H
#define _GPU_SENSORS_H

#if !defined(_WIN32) && !defined(_WIN64) && !defined (__CYGWIN__)
#define __stdcall
#endif

/********** AMD ADL stuff (see adl_sdk.h) **********/

#define ADL_OK                                  0
#define ADL_ERR                                 -1
#define ADL_ERR_NOT_SUPPORTED                   -8
#define ADL_WARNING_NO_DATA                     -100

#define ADL_MAX_PATH                            256

#define ADL_DL_THERMAL_DOMAIN_GPU               1

#define ADL_DL_FANCTRL_SUPPORTS_PERCENT_READ    1
#define ADL_DL_FANCTRL_SUPPORTS_PERCENT_WRITE   2
#define ADL_DL_FANCTRL_SPEED_TYPE_PERCENT       1
#define ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED  1

#define ADL_OD6_SETSTATE_PERFORMANCE            0x00000001

#define ADL_OD6_GETSTATEINFO_CUSTOM_PERFORMANCE 0x00000004

#define ADL_OD6_CAPABILITY_GPU_ACTIVITY_MONITOR 0x00000004

#define ADL_OD6_TCCAPS_THERMAL_CONTROLLER       0x00000001
#define ADL_OD6_TCCAPS_FANSPEED_CONTROL         0x00000002
#define ADL_OD6_TCCAPS_FANSPEED_PERCENT_READ    0x00000100

#define ADL_OD6_FANSPEED_TYPE_PERCENT           0x00000001

typedef struct AdapterInfo {
	int  iSize;
	int  iAdapterIndex;
	char strUDID[ADL_MAX_PATH];
	int  iBusNumber;
	int  iDeviceNumber;
	int  iFunctionNumber;
	int  iVendorID;
	char strAdapterName[ADL_MAX_PATH];
	char strDisplayName[ADL_MAX_PATH];
	int  iPresent;

#if defined (_WIN32) || defined (_WIN64)
	int  iExist;
	char strDriverPath[ADL_MAX_PATH];
	char strDriverPathExt[ADL_MAX_PATH];
	char strPNPString[ADL_MAX_PATH];
	int  iOSDisplayIndex;
#endif /* (_WIN32) || (_WIN64) */

#if defined (__linux__)
	int  iXScreenNum;
	int  iDrvIndex;
	char strXScreenConfigName[ADL_MAX_PATH];
#endif /* (__linux__) */
} AdapterInfo, *LPAdapterInfo;

typedef struct ADLThermalControllerInfo {
	int iSize;
	int iThermalDomain;
	int iDomainIndex;
	int iFlags;
} ADLThermalControllerInfo;

typedef struct ADLTemperature {
	int iSize;
	int iTemperature;
} ADLTemperature;

typedef struct ADLFanSpeedInfo {
	int iSize;
	int iFlags;
	int iMinPercent;
	int iMaxPercent;
	int iMinRPM;
	int iMaxRPM;
} ADLFanSpeedInfo;

typedef struct ADLFanSpeedValue {
	int iSize;
	int iSpeedType;
	int iFanSpeed;
	int iFlags;
} ADLFanSpeedValue;

typedef struct ADLDisplayID {
	int iDisplayLogicalIndex;
	int iDisplayPhysicalIndex;
	int iDisplayLogicalAdapterIndex;
	int iDisplayPhysicalAdapterIndex;
} ADLDisplayID, *LPADLDisplayID;

typedef struct ADLDisplayInfo {
	ADLDisplayID displayID;
	int  iDisplayControllerIndex;
	char strDisplayName[ADL_MAX_PATH];
	char strDisplayManufacturerName[ADL_MAX_PATH];
	int  iDisplayType;
	int  iDisplayOutputType;
	int  iDisplayConnector;
	int  iDisplayInfoMask;
	int  iDisplayInfoValue;
} ADLDisplayInfo, *LPADLDisplayInfo;

typedef struct ADLBiosInfo {
	char strPartNumber[ADL_MAX_PATH];
	char strVersion[ADL_MAX_PATH];
	char strDate[ADL_MAX_PATH];
} ADLBiosInfo, *LPADLBiosInfo;

typedef struct ADLPMActivity {
	int iSize;
	int iEngineClock;
	int iMemoryClock;
	int iVddc;
	int iActivityPercent;
	int iCurrentPerformanceLevel;
	int iCurrentBusSpeed;
	int iCurrentBusLanes;
	int iMaximumBusLanes;
	int iReserved;
} ADLPMActivity;

typedef struct ADLODParameterRange {
	int iMin;
	int iMax;
	int iStep;
} ADLODParameterRange;

typedef struct ADLODParameters {
	int iSize;
	int iNumberOfPerformanceLevels;
	int iActivityReportingSupported;
	int iDiscretePerformanceLevels;
	int iReserved;
	ADLODParameterRange sEngineClock;
	ADLODParameterRange sMemoryClock;
	ADLODParameterRange sVddc;
} ADLODParameters;

typedef struct ADLODPerformanceLevel {
	int iEngineClock;
	int iMemoryClock;
	int iVddc;
} ADLODPerformanceLevel;

typedef struct ADLODPerformanceLevels {
	int iSize;
	int iReserved;
	ADLODPerformanceLevel aLevels [1];
} ADLODPerformanceLevels;

typedef struct _ADLOD6ThermalControllerCaps {
	int iCapabilities;
	int iFanMinPercent;
	int iFanMaxPercent;
	int iFanMinRPM;
	int iFanMaxRPM;
	int iExtValue;
	int iExtMask;
} ADLOD6ThermalControllerCaps;

typedef struct _ADLOD6FanSpeedInfo {
	int iSpeedType;
	int iFanSpeedPercent;
	int iFanSpeedRPM;
	int iExtValue;
	int iExtMask;
} ADLOD6FanSpeedInfo;

typedef struct _ADLOD6FanSpeedValue {
	int iSpeedType;
	int iFanSpeed;
	int iExtValue;
	int iExtMask;
} ADLOD6FanSpeedValue;

typedef struct _ADLOD6CurrentStatus {
	int iEngineClock;
	int iMemoryClock;
	int iActivityPercent;
	int iCurrentPerformanceLevel;
	int iCurrentBusSpeed;
	int iCurrentBusLanes;
	int iMaximumBusLanes;
	int iExtValue;
	int iExtMask;
} ADLOD6CurrentStatus;

typedef struct _ADLOD6ParameterRange {
	int iMin;
	int iMax;
	int iStep;
} ADLOD6ParameterRange;

typedef struct _ADLOD6Capabilities {
	int iCapabilities;
	int iSupportedStates;
	int iNumberOfPerformanceLevels;
	ADLOD6ParameterRange sEngineClockRange;
	ADLOD6ParameterRange sMemoryClockRange;
	int iExtValue;
	int iExtMask;
} ADLOD6Capabilities;

typedef struct _ADLOD6PerformanceLevel {
	int iEngineClock;
	int iMemoryClock;
} ADLOD6PerformanceLevel;

typedef struct _ADLOD6StateInfo {
	int iNumberOfPerformanceLevels;
	int iExtValue;
	int iExtMask;
	ADLOD6PerformanceLevel aLevels [1];
} ADLOD6StateInfo;

typedef struct _ADLOD6PowerControlInfo {
	int iMinValue;
	int iMaxValue;
	int iStepValue;
	int iExtValue;
	int iExtMask;
} ADLOD6PowerControlInfo;

typedef void* (__stdcall *ADL_MAIN_MALLOC_CALLBACK)(int);

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
typedef int (*ADL_OVERDRIVE6_CAPABILITIES_GET)(int iAdapterIndex, ADLOD6Capabilities *lpODCapabilities);

/********** NVIDIA stuff (see nvml.h and nvapi.h) **********/

typedef struct nvmlDevice_st* nvmlDevice_t;

typedef struct nvmlUtilization_st {
	unsigned int gpu;    // GPU kernel execution last second, percent
	unsigned int memory; // GPU memory read/write last second, percent
} nvmlUtilization_t;

typedef struct nvmlPciInfo_st {
	char busId[16];
	unsigned int domain;
	unsigned int bus;
	unsigned int device;
	unsigned int pciDeviceId;
	unsigned int pciSubSystemId;
} nvmlPciInfo_t;

typedef enum nvmlReturn_enum {
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

typedef enum nvmlTemperatureSensors_enum {
	NVML_TEMPERATURE_GPU = 0     // Temperature sensor for the GPU die
} nvmlTemperatureSensors_t;

typedef nvmlReturn_t (*NVMLINIT) ();
typedef nvmlReturn_t (*NVMLSHUTDOWN) ();
typedef nvmlReturn_t (*NVMLDEVICEGETHANDLEBYINDEX) (unsigned int, nvmlDevice_t *);
typedef nvmlReturn_t (*NVMLDEVICEGETTEMPERATURE)(nvmlDevice_t, int, unsigned int *);
typedef nvmlReturn_t (*NVMLDEVICEGETFANSPEED) (nvmlDevice_t, unsigned int *);
typedef nvmlReturn_t (*NVMLDEVICEGETUTILIZATIONRATES) (nvmlDevice_t, nvmlUtilization_t *);
typedef nvmlReturn_t (*NVMLDEVICEGETPCIINFO) (nvmlDevice_t, nvmlPciInfo_t *);
typedef nvmlReturn_t (*NVMLDEVICEGETNAME) (nvmlDevice_t, char *, unsigned int);
typedef nvmlReturn_t (*NVMLDEVICEGETHANDLEBYPCIBUSID) (const char *, nvmlDevice_t *);
typedef nvmlReturn_t (*NVMLDEVICEGETINDEX) (nvmlDevice_t, unsigned int *);
typedef nvmlReturn_t (*NVMLDEVICEGETCURRPCIELINKWIDTH) (nvmlDevice_t, unsigned int *);
typedef nvmlReturn_t (*NVMLDEVICEGETMAXPCIELINKWIDTH) (nvmlDevice_t, unsigned int *);

extern NVMLSHUTDOWN nvmlShutdown;

#endif /* _GPU_SENSORS_H */

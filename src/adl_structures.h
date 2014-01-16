///
///  Copyright (c) 2008 - 2013 Advanced Micro Devices, Inc.

///  THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
///  EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
///  WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.

/// \file adl_structures.h
///\brief This file contains the structure declarations that are used by the public ADL interfaces for \ALL platforms.\n <b>Included in ADL SDK</b>
///
/// All data structures used in AMD Display Library (ADL) public interfaces should be defined in this header file.
///

#ifndef ADL_STRUCTURES_H_
#define ADL_STRUCTURES_H_

#include "adl_defines.h"

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the graphics adapter.
///
/// This structure is used to store various information about the graphics adapter.  This
/// information can be returned to the user. Alternatively, it can be used to access various driver calls to set
/// or fetch various settings upon the user's request.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct AdapterInfo
{
/// \ALL_STRUCT_MEM

/// Size of the structure.
    int iSize;
/// The ADL index handle. One GPU may be associated with one or two index handles
    int iAdapterIndex;
/// The unique device ID associated with this adapter.
    char strUDID[ADL_MAX_PATH];
/// The BUS number associated with this adapter.
    int iBusNumber;
/// The driver number associated with this adapter.
    int iDeviceNumber;
/// The function number.
    int iFunctionNumber;
/// The vendor ID associated with this adapter.
    int iVendorID;
/// Adapter name.
    char strAdapterName[ADL_MAX_PATH];
/// Display name. For example, "\\Display0" for Windows or ":0:0" for Linux.
    char strDisplayName[ADL_MAX_PATH];
/// Present or not; 1 if present and 0 if not present.It the logical adapter is present, the display name such as \\.\Display1 can be found from OS
	int iPresent;
// @}

#if defined (_WIN32) || defined (_WIN64)
/// \WIN_STRUCT_MEM

/// Exist or not; 1 is exist and 0 is not present.
    int iExist;
/// Driver registry path.
    char strDriverPath[ADL_MAX_PATH];
/// Driver registry path Ext for.
    char strDriverPathExt[ADL_MAX_PATH];
/// PNP string from Windows.
    char strPNPString[ADL_MAX_PATH];
/// It is generated from EnumDisplayDevices.
    int iOSDisplayIndex;
// @}
#endif /* (_WIN32) || (_WIN64) */

#if defined (__linux__)
/// \LNX_STRUCT_MEM

/// Internal X screen number from GPUMapInfo (DEPRICATED use XScreenInfo)
    int iXScreenNum;
/// Internal driver index from GPUMapInfo
    int iDrvIndex;
/// \deprecated Internal x config file screen identifier name. Use XScreenInfo instead.
    char strXScreenConfigName[ADL_MAX_PATH];

// @}
#endif /* (__linux__) */
} AdapterInfo, *LPAdapterInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the Linux X screen information.
///
/// This structure is used to store the current screen number and xorg.conf ID name assoicated with an adapter index.
/// This structure is updated during ADL_Main_Control_Refresh or ADL_ScreenInfo_Update.
/// Note:  This structure should be used in place of iXScreenNum and strXScreenConfigName in AdapterInfo as they will be
/// deprecated.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
#if defined (__linux__)
typedef struct XScreenInfo
{
/// Internal X screen number from GPUMapInfo.
	int iXScreenNum;
/// Internal x config file screen identifier name.
    char strXScreenConfigName[ADL_MAX_PATH];
} XScreenInfo, *LPXScreenInfo;
#endif /* (__linux__) */


/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the ASIC memory.
///
/// This structure is used to store various information about the ASIC memory.  This
/// information can be returned to the user.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLMemoryInfo
{
/// Memory size in bytes.
    long long iMemorySize;
/// Memory type in string.
    char strMemoryType[ADL_MAX_PATH];
/// Memory bandwidth in Mbytes/s.
    long long iMemoryBandwidth;
} ADLMemoryInfo, *LPADLMemoryInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about memory required by type
///
/// This structure is returned by ADL_Adapter_ConfigMemory_Get, which given a desktop and display configuration
/// will return the Memory used.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLMemoryRequired
{
	long long iMemoryReq;		/// Memory in bytes required
	int iType;					/// Type of Memory \ref define_adl_validmemoryrequiredfields
	int iDisplayFeatureValue;   /// Display features \ref define_adl_visiblememoryfeatures that are using this type of memory
} ADLMemoryRequired, *LPADLMemoryRequired;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the features associated with a display
///
/// This structure is a parameter to ADL_Adapter_ConfigMemory_Get, which given a desktop and display configuration
/// will return the Memory used.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLMemoryDisplayFeatures
{
	int iDisplayIndex;			/// ADL Display index
	int iDisplayFeatureValue;	/// features that the display is using \ref define_adl_visiblememoryfeatures
} ADLMemoryDisplayFeatures, *LPADLMemoryDisplayFeatures;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing DDC information.
///
/// This structure is used to store various DDC information that can be returned to the user.
/// Note that all fields of type int are actually defined as unsigned int types within the driver.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDDCInfo
{
/// Size of the structure
    int  ulSize;
/// Indicates whether the attached display supports DDC. If this field is zero on return, no other DDC information fields will be used.
    int  ulSupportsDDC;
/// Returns the manufacturer ID of the display device. Should be zeroed if this information is not available.
    int  ulManufacturerID;
/// Returns the product ID of the display device. Should be zeroed if this information is not available.
    int  ulProductID;
/// Returns the name of the display device. Should be zeroed if this information is not available.
    char cDisplayName[ADL_MAX_DISPLAY_NAME];
/// Returns the maximum Horizontal supported resolution. Should be zeroed if this information is not available.
    int  ulMaxHResolution;
/// Returns the maximum Vertical supported resolution. Should be zeroed if this information is not available.
    int  ulMaxVResolution;
/// Returns the maximum supported refresh rate. Should be zeroed if this information is not available.
    int  ulMaxRefresh;
/// Returns the display device preferred timing mode's horizontal resolution.
    int  ulPTMCx;
/// Returns the display device preferred timing mode's vertical resolution.
    int  ulPTMCy;
/// Returns the display device preferred timing mode's refresh rate.
    int  ulPTMRefreshRate;
/// Return EDID flags.
    int  ulDDCInfoFlag;
} ADLDDCInfo, *LPADLDDCInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing DDC information.
///
/// This structure is used to store various DDC information that can be returned to the user.
/// Note that all fields of type int are actually defined as unsigned int types within the driver.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDDCInfo2
{
/// Size of the structure
    int  ulSize;
/// Indicates whether the attached display supports DDC. If this field is zero on return, no other DDC
/// information fields will be used.
    int  ulSupportsDDC;
/// Returns the manufacturer ID of the display device. Should be zeroed if this information is not available.
    int  ulManufacturerID;
/// Returns the product ID of the display device. Should be zeroed if this information is not available.
    int  ulProductID;
/// Returns the name of the display device. Should be zeroed if this information is not available.
    char cDisplayName[ADL_MAX_DISPLAY_NAME];
/// Returns the maximum Horizontal supported resolution. Should be zeroed if this information is not available.
    int  ulMaxHResolution;
/// Returns the maximum Vertical supported resolution. Should be zeroed if this information is not available.
    int  ulMaxVResolution;
/// Returns the maximum supported refresh rate. Should be zeroed if this information is not available.
    int  ulMaxRefresh;
/// Returns the display device preferred timing mode's horizontal resolution.
    int  ulPTMCx;
/// Returns the display device preferred timing mode's vertical resolution.
    int  ulPTMCy;
/// Returns the display device preferred timing mode's refresh rate.
    int  ulPTMRefreshRate;
/// Return EDID flags.
    int  ulDDCInfoFlag;
// Returns 1 if the display supported packed pixel, 0 otherwise
    int bPackedPixelSupported;
// Returns the Pixel formats the display supports \ref define_ddcinfo_pixelformats
    int iPanelPixelFormat;
/// Return EDID serial ID.
    int  ulSerialID;
// Reserved for future use
    int iReserved[26];
} ADLDDCInfo2, *LPADLDDCInfo2;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information controller Gamma settings.
///
/// This structure is used to store the red, green and blue color channel information for the.
/// controller gamma setting. This information is returned by ADL, and it can also be used to
/// set the controller gamma setting.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLGamma
{
/// Red color channel gamma value.
	float fRed;
/// Green color channel gamma value.
	float fGreen;
/// Blue color channel gamma value.
	float fBlue;
} ADLGamma, *LPADLGamma;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about component video custom modes.
///
/// This structure is used to store the component video custom mode.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLCustomMode
{
/// Custom mode flags.  They are returned by the ADL driver.
	int iFlags;
/// Custom mode width.
	int iModeWidth;
/// Custom mode height.
	int iModeHeight;
/// Custom mode base width.
	int iBaseModeWidth;
/// Custom mode base height.
	int iBaseModeHeight;
/// Custom mode refresh rate.
	int iRefreshRate;
} ADLCustomMode, *LPADLCustomMode;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing Clock information for OD5 calls.
///
/// This structure is used to retrieve clock information for OD5 calls.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLGetClocksOUT
{
    long ulHighCoreClock;
    long ulHighMemoryClock;
    long ulHighVddc;
    long ulCoreMin;
    long ulCoreMax;
    long ulMemoryMin;
    long ulMemoryMax;
    long ulActivityPercent;
    long ulCurrentCoreClock;
    long ulCurrentMemoryClock;
    long ulReserved;
} ADLGetClocksOUT;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing HDTV information for display calls.
///
/// This structure is used to retrieve HDTV information information for display calls.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDisplayConfig
{
/// Size of the structure
  long ulSize;
/// HDTV connector type.
  long ulConnectorType;
/// HDTV capabilities.
  long ulDeviceData;
/// Overridden HDTV capabilities.
  long ulOverridedDeviceData;
/// Reserved field
  long ulReserved;
} ADLDisplayConfig;


/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the display device.
///
/// This structure is used to store display device information
/// such as display index, type, name, connection status, mapped adapter and controller indexes,
/// whether or not multiple VPUs are supported, local display connections or not (through Lasso), etc.
/// This information can be returned to the user. Alternatively, it can be used to access various driver calls to set
/// or fetch various display device related settings upon the user's request.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDisplayID
{
/// The logical display index belonging to this adapter.
	int iDisplayLogicalIndex;

///\brief The physical display index.
/// For example, display index 2 from adapter 2 can be used by current adapter 1.\n
/// So current adapter may enumerate this adapter as logical display 7 but the physical display
/// index is still 2.
	int iDisplayPhysicalIndex;

/// The persistent logical adapter index for the display.
	int iDisplayLogicalAdapterIndex;

///\brief The persistent physical adapter index for the display.
/// It can be the current adapter or a non-local adapter. \n
/// If this adapter index is different than the current adapter,
/// the Display Non Local flag is set inside DisplayInfoValue.
    int iDisplayPhysicalAdapterIndex;
} ADLDisplayID, *LPADLDisplayID;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the display device.
///
/// This structure is used to store various information about the display device.  This
/// information can be returned to the user, or used to access various driver calls to set
/// or fetch various display-device-related settings upon the user's request
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDisplayInfo
{
/// The DisplayID structure
	ADLDisplayID displayID;

///\deprecated The controller index to which the display is mapped.\n Will not be used in the future\n
	int  iDisplayControllerIndex;

/// The display's EDID name.
	char strDisplayName[ADL_MAX_PATH];

/// The display's manufacturer name.
	char strDisplayManufacturerName[ADL_MAX_PATH];

/// The Display type. For example: CRT, TV, CV, DFP.
	int  iDisplayType;

/// The display output type. For example: HDMI, SVIDEO, COMPONMNET VIDEO.
	int  iDisplayOutputType;

/// The connector type for the device.
	int  iDisplayConnector;

///\brief The bit mask identifies the number of bits ADLDisplayInfo is currently using. \n
/// It will be the sum all the bit definitions in ADL_DISPLAY_DISPLAYINFO_xxx.
	int  iDisplayInfoMask;

/// The bit mask identifies the display status. \ref define_displayinfomask
	int  iDisplayInfoValue;
} ADLDisplayInfo, *LPADLDisplayInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the display port MST device.
///
/// This structure is used to store various MST information about the display port device.  This
/// information can be returned to the user, or used to access various driver calls to
/// fetch various display-device-related settings upon the user's request
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDisplayDPMSTInfo
{
	/// The ADLDisplayID structure
	ADLDisplayID displayID;

	/// total bandwidth available on the DP connector
	int	iTotalAvailableBandwidthInMpbs;
	/// bandwidth allocated to this display
	int	iAllocatedBandwidthInMbps;

	// info from DAL DpMstSinkInfo
	/// string identifier for the display
	char	strGlobalUniqueIdentifier[ADL_MAX_PATH];

	/// The link count of relative address, rad[0] upto rad[linkCount] are valid
	int		radLinkCount;
	/// The physical connector ID, used to identify the physical DP port
	int		iPhysicalConnectorID;

	/// Relative address, address scheme starts from source side
	char	rad[ADL_MAX_RAD_LINK_COUNT];
} ADLDisplayDPMSTInfo, *LPADLDisplayDPMSTInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing the display mode definition used per controller.
///
/// This structure is used to store the display mode definition used per controller.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDisplayMode
{
/// Vertical resolution (in pixels).
   int  iPelsHeight;
/// Horizontal resolution (in pixels).
   int  iPelsWidth;
/// Color depth.
   int  iBitsPerPel;
/// Refresh rate.
   int  iDisplayFrequency;
} ADLDisplayMode;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing detailed timing parameters.
///
/// This structure is used to store the detailed timing parameters.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDetailedTiming
{
/// Size of the structure.
     int   iSize;
/// Timing flags. \ref define_detailed_timing_flags
     short sTimingFlags;
/// Total width (columns).
     short sHTotal;
/// Displayed width.
     short sHDisplay;
/// Horizontal sync signal offset.
     short sHSyncStart;
/// Horizontal sync signal width.
     short sHSyncWidth;
/// Total height (rows).
     short sVTotal;
/// Displayed height.
     short sVDisplay;
/// Vertical sync signal offset.
     short sVSyncStart;
/// Vertical sync signal width.
     short sVSyncWidth;
/// Pixel clock value.
     short sPixelClock;
/// Overscan right.
     short sHOverscanRight;
/// Overscan left.
     short sHOverscanLeft;
/// Overscan bottom.
     short sVOverscanBottom;
/// Overscan top.
     short sVOverscanTop;
     short sOverscan8B;
     short sOverscanGR;
} ADLDetailedTiming;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing display mode information.
///
/// This structure is used to store the display mode information.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDisplayModeInfo
{
/// Timing standard of the current mode. \ref define_modetiming_standard
  int  iTimingStandard;
/// Applicable timing standards for the current mode.
  int  iPossibleStandard;
/// Refresh rate factor.
  int  iRefreshRate;
/// Num of pixels in a row.
  int  iPelsWidth;
/// Num of pixels in a column.
  int  iPelsHeight;
/// Detailed timing parameters.
  ADLDetailedTiming  sDetailedTiming;
} ADLDisplayModeInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
/// \brief Structure containing information about display property.
///
/// This structure is used to store the display property for the current adapter.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDisplayProperty
{
/// Must be set to sizeof the structure
  int iSize;
/// Must be set to \ref ADL_DL_DISPLAYPROPERTY_TYPE_EXPANSIONMODE or \ref ADL_DL_DISPLAYPROPERTY_TYPE_USEUNDERSCANSCALING
  int iPropertyType;
/// Get or Set \ref ADL_DL_DISPLAYPROPERTY_EXPANSIONMODE_CENTER or \ref ADL_DL_DISPLAYPROPERTY_EXPANSIONMODE_FULLSCREEN or \ref ADL_DL_DISPLAYPROPERTY_EXPANSIONMODE_ASPECTRATIO or \ref ADL_DL_DISPLAYPROPERTY_TYPE_ITCFLAGENABLE
  int iExpansionMode;
/// Display Property supported? 1: Supported, 0: Not supported
  int iSupport;
/// Display Property current value
  int iCurrent;
/// Display Property Default value
  int iDefault;
} ADLDisplayProperty;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Clock.
///
/// This structure is used to store the clock information for the current adapter
/// such as core clock and memory clock info.
///\nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLClockInfo
{
/// Core clock in 10 KHz.
    int iCoreClock;
/// Memory clock in 10 KHz.
    int iMemoryClock;
} ADLClockInfo, *LPADLClockInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about I2C.
///
/// This structure is used to store the I2C information for the current adapter.
/// This structure is used by the ADL_Display_WriteAndReadI2C() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLI2C
{
/// Size of the structure
    int iSize;
/// Numerical value representing hardware I2C.
    int iLine;
/// The 7-bit I2C slave device address, shifted one bit to the left.
    int iAddress;
/// The offset of the data from the address.
    int iOffset;
/// Read from or write to slave device. \ref ADL_DL_I2C_ACTIONREAD or \ref ADL_DL_I2C_ACTIONWRITE or \ref ADL_DL_I2C_ACTIONREAD_REPEATEDSTART
    int iAction;
/// I2C clock speed in KHz.
    int iSpeed;
/// A numerical value representing the number of bytes to be sent or received on the I2C bus.
    int iDataSize;
/// Address of the characters which are to be sent or received on the I2C bus.
    char *pcData;
} ADLI2C;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about EDID data.
///
/// This structure is used to store the information about EDID data for the adapter.
/// This structure is used by the ADL_Display_EdidData_Get() and ADL_Display_EdidData_Set() functions.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDisplayEDIDData
{
/// Size of the structure
  int iSize;
/// Set to 0
  int iFlag;
  /// Size of cEDIDData. Set by ADL_Display_EdidData_Get() upon return
  int iEDIDSize;
/// 0, 1 or 2. If set to 3 or above an error ADL_ERR_INVALID_PARAM is generated
  int iBlockIndex;
/// EDID data
  char cEDIDData[ADL_MAX_EDIDDATA_SIZE];
/// Reserved
  int iReserved[4];
}ADLDisplayEDIDData;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about input of controller overlay adjustment.
///
/// This structure is used to store the information about input of controller overlay adjustment for the adapter.
/// This structure is used by the ADL_Display_ControllerOverlayAdjustmentCaps_Get, ADL_Display_ControllerOverlayAdjustmentData_Get, and
/// ADL_Display_ControllerOverlayAdjustmentData_Set() functions.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLControllerOverlayInput
{
/// Should be set to the sizeof the structure
  int  iSize;
///\ref ADL_DL_CONTROLLER_OVERLAY_ALPHA or \ref ADL_DL_CONTROLLER_OVERLAY_ALPHAPERPIX
  int  iOverlayAdjust;
/// Data.
  int  iValue;
/// Should be 0.
  int  iReserved;
} ADLControllerOverlayInput;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about overlay adjustment.
///
/// This structure is used to store the information about overlay adjustment for the adapter.
/// This structure is used by the ADLControllerOverlayInfo() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLAdjustmentinfo
{
/// Default value
  int iDefault;
/// Minimum value
  int iMin;
/// Maximum Value
  int iMax;
/// Step value
  int iStep;
} ADLAdjustmentinfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about controller overlay information.
///
/// This structure is used to store information about controller overlay info for the adapter.
/// This structure is used by the ADL_Display_ControllerOverlayAdjustmentCaps_Get() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLControllerOverlayInfo
{
/// Should be set to the sizeof the structure
  int					iSize;
/// Data.
  ADLAdjustmentinfo	    sOverlayInfo;
/// Should be 0.
  int					iReserved[3];
} ADLControllerOverlayInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing GL-Sync module information.
///
/// This structure is used to retrieve GL-Sync module information for
/// Workstation Framelock/Genlock.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLGLSyncModuleID
{
/// Unique GL-Sync module ID.
	int		iModuleID;
/// GL-Sync GPU port index (to be passed into ADLGLSyncGenlockConfig.lSignalSource and ADLGlSyncPortControl.lSignalSource).
	int		iGlSyncGPUPort;
/// GL-Sync module firmware version of Boot Sector.
	int		iFWBootSectorVersion;
/// GL-Sync module firmware version of User Sector.
	int		iFWUserSectorVersion;
} ADLGLSyncModuleID , *LPADLGLSyncModuleID;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing GL-Sync ports capabilities.
///
/// This structure is used to retrieve hardware capabilities for the ports of the GL-Sync module
/// for Workstation Framelock/Genlock (such as port type and number of associated LEDs).
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLGLSyncPortCaps
{
/// Port type. Bitfield of ADL_GLSYNC_PORTTYPE_*  \ref define_glsync
	int		iPortType;
/// Number of LEDs associated for this port.
	int		iNumOfLEDs;
}ADLGLSyncPortCaps, *LPADLGLSyncPortCaps;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing GL-Sync Genlock settings.
///
/// This structure is used to get and set genlock settings for the GPU ports of the GL-Sync module
/// for Workstation Framelock/Genlock.\n
/// \see define_glsync
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLGLSyncGenlockConfig
{
/// Specifies what fields in this structure are valid \ref define_glsync
	int		iValidMask;
/// Delay (ms) generating a sync signal.
	int		iSyncDelay;
/// Vector of framelock control bits. Bitfield of ADL_GLSYNC_FRAMELOCKCNTL_* \ref define_glsync
	int		iFramelockCntlVector;
/// Source of the sync signal. Either GL_Sync GPU Port index or ADL_GLSYNC_SIGNALSOURCE_* \ref define_glsync
	int		iSignalSource;
/// Use sampled sync signal. A value of 0 specifies no sampling.
	int		iSampleRate;
/// For interlaced sync signals, the value can be ADL_GLSYNC_SYNCFIELD_1 or *_BOTH \ref define_glsync
	int		iSyncField;
/// The signal edge that should trigger synchronization. ADL_GLSYNC_TRIGGEREDGE_* \ref define_glsync
	int		iTriggerEdge;
/// Scan rate multiplier applied to the sync signal. ADL_GLSYNC_SCANRATECOEFF_* \ref define_glsync
	int		iScanRateCoeff;
}ADLGLSyncGenlockConfig, *LPADLGLSyncGenlockConfig;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing GL-Sync port information.
///
/// This structure is used to get status of the GL-Sync ports (BNC or RJ45s)
/// for Workstation Framelock/Genlock.
/// \see define_glsync
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLGlSyncPortInfo
{
/// Type of GL-Sync port (ADL_GLSYNC_PORT_*).
	int		iPortType;
/// The number of LEDs for this port. It's also filled within ADLGLSyncPortCaps.
	int		iNumOfLEDs;
/// Port state ADL_GLSYNC_PORTSTATE_*  \ref define_glsync
	int		iPortState;
/// Scanned frequency for this port (vertical refresh rate in milliHz; 60000 means 60 Hz).
	int		iFrequency;
/// Used for ADL_GLSYNC_PORT_BNC. It is ADL_GLSYNC_SIGNALTYPE_*   \ref define_glsync
	int		iSignalType;
/// Used for ADL_GLSYNC_PORT_RJ45PORT*. It is GL_Sync GPU Port index or ADL_GLSYNC_SIGNALSOURCE_*.  \ref define_glsync
	int		iSignalSource;

} ADLGlSyncPortInfo, *LPADLGlSyncPortInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing GL-Sync port control settings.
///
/// This structure is used to configure the GL-Sync ports (RJ45s only)
/// for Workstation Framelock/Genlock.
/// \see define_glsync
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLGlSyncPortControl
{
/// Port to control ADL_GLSYNC_PORT_RJ45PORT1 or ADL_GLSYNC_PORT_RJ45PORT2   \ref define_glsync
	int		iPortType;
/// Port control data ADL_GLSYNC_PORTCNTL_*   \ref define_glsync
	int		iControlVector;
/// Source of the sync signal. Either GL_Sync GPU Port index or ADL_GLSYNC_SIGNALSOURCE_*   \ref define_glsync
	int		iSignalSource;
} ADLGlSyncPortControl;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing GL-Sync mode of a display.
///
/// This structure is used to get and set GL-Sync mode settings for a display connected to
/// an adapter attached to a GL-Sync module for Workstation Framelock/Genlock.
/// \see define_glsync
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLGlSyncMode
{
/// Mode control vector. Bitfield of ADL_GLSYNC_MODECNTL_*   \ref define_glsync
	int		iControlVector;
/// Mode status vector. Bitfield of ADL_GLSYNC_MODECNTL_STATUS_*   \ref define_glsync
	int		iStatusVector;
/// Index of GL-Sync connector used to genlock the display/controller.
	int		iGLSyncConnectorIndex;
} ADLGlSyncMode, *LPADLGlSyncMode;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing GL-Sync mode of a display.
///
/// This structure is used to get and set GL-Sync mode settings for a display connected to
/// an adapter attached to a GL-Sync module for Workstation Framelock/Genlock.
/// \see define_glsync
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLGlSyncMode2
{
/// Mode control vector. Bitfield of ADL_GLSYNC_MODECNTL_*   \ref define_glsync
	int		iControlVector;
/// Mode status vector. Bitfield of ADL_GLSYNC_MODECNTL_STATUS_*   \ref define_glsync
	int		iStatusVector;
/// Index of GL-Sync connector used to genlock the display/controller.
	int		iGLSyncConnectorIndex;
/// Index of the display to which this GLSync applies to.
	int		iDisplayIndex;
} ADLGlSyncMode2, *LPADLGlSyncMode2;


/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing the packet info of a display.
///
/// This structure is used to get and set the packet information of a display.
/// This structure is used by ADLDisplayDataPacket.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct  ADLInfoPacket
{
	char hb0;
	char hb1;
	char hb2;
/// sb0~sb27
	char sb[28];
}ADLInfoPacket;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing the AVI packet info of a display.
///
/// This structure is used to get and set AVI the packet info of a display.
/// This structure is used by ADLDisplayDataPacket.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLAVIInfoPacket  //Valid user defined data/
{
/// byte 3, bit 7
   char bPB3_ITC;
/// byte 5, bit [7:4].
   char bPB5;
}ADLAVIInfoPacket;

// Overdrive clock setting structure definition.

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing the Overdrive clock setting.
///
/// This structure is used to get the Overdrive clock setting.
/// This structure is used by ADLAdapterODClockInfo.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLODClockSetting
{
/// Deafult clock
	int iDefaultClock;
/// Current clock
	int iCurrentClock;
/// Maximum clcok
	int iMaxClock;
/// Minimum clock
	int iMinClock;
/// Requested clcock
	int iRequestedClock;
/// Step
	int iStepClock;
} ADLODClockSetting;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing the Overdrive clock information.
///
/// This structure is used to get the Overdrive clock information.
/// This structure is used by the ADL_Display_ODClockInfo_Get() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLAdapterODClockInfo
{
/// Size of the structure
	int iSize;
/// Flag \ref define_clockinfo_flags
	int iFlags;
/// Memory Clock
	ADLODClockSetting sMemoryClock;
/// Engine Clock
	ADLODClockSetting sEngineClock;
} ADLAdapterODClockInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing the Overdrive clock configuration.
///
/// This structure is used to set the Overdrive clock configuration.
/// This structure is used by the ADL_Display_ODClockConfig_Set() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLAdapterODClockConfig
{
/// Size of the structure
  int iSize;
/// Flag \ref define_clockinfo_flags
  int iFlags;
/// Memory Clock
  int iMemoryClock;
/// Engine Clock
  int iEngineClock;
} ADLAdapterODClockConfig;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about current power management related activity.
///
/// This structure is used to store information about current power management related activity.
/// This structure (Overdrive 5 interfaces) is used by the ADL_PM_CurrentActivity_Get() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLPMActivity
{
/// Must be set to the size of the structure
	int iSize;
/// Current engine clock.
	int iEngineClock;
/// Current memory clock.
	int iMemoryClock;
/// Current core voltage.
	int iVddc;
/// GPU utilization.
	int iActivityPercent;
/// Performance level index.
	int iCurrentPerformanceLevel;
/// Current PCIE bus speed.
	int iCurrentBusSpeed;
/// Number of PCIE bus lanes.
	int iCurrentBusLanes;
/// Maximum number of PCIE bus lanes.
	int iMaximumBusLanes;
/// Reserved for future purposes.
	int iReserved;
} ADLPMActivity;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about thermal controller.
///
/// This structure is used to store information about thermal controller.
/// This structure is used by ADL_PM_ThermalDevices_Enum.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLThermalControllerInfo
{
/// Must be set to the size of the structure
  int iSize;
/// Possible valies: \ref ADL_DL_THERMAL_DOMAIN_OTHER or \ref ADL_DL_THERMAL_DOMAIN_GPU.
  int iThermalDomain;
///	GPU 0, 1, etc.
  int iDomainIndex;
/// Possible valies: \ref ADL_DL_THERMAL_FLAG_INTERRUPT or \ref ADL_DL_THERMAL_FLAG_FANCONTROL
  int iFlags;
} ADLThermalControllerInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about thermal controller temperature.
///
/// This structure is used to store information about thermal controller temperature.
/// This structure is used by the ADL_PM_Temperature_Get() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLTemperature
{
/// Must be set to the size of the structure
  int iSize;
/// Temperature in millidegrees Celsius.
  int iTemperature;
} ADLTemperature;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about thermal controller fan speed.
///
/// This structure is used to store information about thermal controller fan speed.
/// This structure is used by the ADL_PM_FanSpeedInfo_Get() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLFanSpeedInfo
{
/// Must be set to the size of the structure
  int iSize;
/// \ref define_fanctrl
  int iFlags;
/// Minimum possible fan speed value in percents.
  int iMinPercent;
/// Maximum possible fan speed value in percents.
  int iMaxPercent;
/// Minimum possible fan speed value in RPM.
  int iMinRPM;
/// Maximum possible fan speed value in RPM.
  int iMaxRPM;
} ADLFanSpeedInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about fan speed reported by thermal controller.
///
/// This structure is used to store information about fan speed reported by thermal controller.
/// This structure is used by the ADL_Overdrive5_FanSpeed_Get() and ADL_Overdrive5_FanSpeed_Set() functions.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLFanSpeedValue
{
/// Must be set to the size of the structure
  int iSize;
/// Possible valies: \ref ADL_DL_FANCTRL_SPEED_TYPE_PERCENT or \ref ADL_DL_FANCTRL_SPEED_TYPE_RPM
  int iSpeedType;
/// Fan speed value
  int iFanSpeed;
/// The only flag for now is: \ref ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED
  int iFlags;
} ADLFanSpeedValue;

////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing the range of Overdrive parameter.
///
/// This structure is used to store information about the range of Overdrive parameter.
/// This structure is used by ADLODParameters.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLODParameterRange
{
/// Minimum parameter value.
  int iMin;
/// Maximum parameter value.
  int iMax;
/// Parameter step value.
  int iStep;
} ADLODParameterRange;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive parameters.
///
/// This structure is used to store information about Overdrive parameters.
/// This structure is used by the ADL_Overdrive5_ODParameters_Get() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLODParameters
{
/// Must be set to the size of the structure
  int iSize;
/// Number of standard performance states.
  int iNumberOfPerformanceLevels;
/// Indicates whether the GPU is capable to measure its activity.
  int iActivityReportingSupported;
/// Indicates whether the GPU supports discrete performance levels or performance range.
  int iDiscretePerformanceLevels;
/// Reserved for future use.
  int iReserved;
/// Engine clock range.
  ADLODParameterRange sEngineClock;
/// Memory clock range.
  ADLODParameterRange sMemoryClock;
/// Core voltage range.
  ADLODParameterRange sVddc;
} ADLODParameters;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive level.
///
/// This structure is used to store information about Overdrive level.
/// This structure is used by ADLODPerformanceLevels.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLODPerformanceLevel
{
/// Engine clock.
  int iEngineClock;
/// Memory clock.
  int iMemoryClock;
/// Core voltage.
  int iVddc;
} ADLODPerformanceLevel;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive performance levels.
///
/// This structure is used to store information about Overdrive performance levels.
/// This structure is used by the ADL_Overdrive5_ODPerformanceLevels_Get() and ADL_Overdrive5_ODPerformanceLevels_Set() functions.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLODPerformanceLevels
{
/// Must be set to sizeof( \ref ADLODPerformanceLevels ) + sizeof( \ref ADLODPerformanceLevel ) * (ADLODParameters.iNumberOfPerformanceLevels - 1)
  int iSize;
  int iReserved;
/// Array of performance state descriptors. Must have ADLODParameters.iNumberOfPerformanceLevels elements.
  ADLODPerformanceLevel aLevels [1];
} ADLODPerformanceLevels;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the proper CrossfireX chains combinations.
///
/// This structure is used to store information about the CrossfireX chains combination for a particular adapter.
/// This structure is used by the ADL_Adapter_Crossfire_Caps(), ADL_Adapter_Crossfire_Get(), and ADL_Adapter_Crossfire_Set() functions.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLCrossfireComb
{
/// Number of adapters in this combination.
  int iNumLinkAdapter;
/// A list of ADL indexes of the linked adapters in this combination.
  int iAdaptLink[3];
} ADLCrossfireComb;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing CrossfireX state and error information.
///
/// This structure is used to store state and error information about a particular adapter CrossfireX combination.
/// This structure is used by the ADL_Adapter_Crossfire_Get() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLCrossfireInfo
{
/// Current error code of this CrossfireX combination.
  int iErrorCode;
/// Current \ref define_crossfirestate
  int iState;
/// If CrossfireX is supported by this combination. The value is either \ref ADL_TRUE or \ref ADL_FALSE.
  int iSupported;
} ADLCrossfireInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
/// \brief Structure containing information about the BIOS.
///
/// This structure is used to store various information about the Chipset.  This
/// information can be returned to the user.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLBiosInfo
{
	char strPartNumber[ADL_MAX_PATH];	///< Part number.
	char strVersion[ADL_MAX_PATH];		///< Version number.
	char strDate[ADL_MAX_PATH];		///< BIOS date in yyyy/mm/dd hh:mm format.
} ADLBiosInfo, *LPADLBiosInfo;


/////////////////////////////////////////////////////////////////////////////////////////////
/// \brief Structure containing information about adapter location.
///
/// This structure is used to store information about adapter location.
/// This structure is used by ADLMVPUStatus.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLAdapterLocation
{
/// PCI Bus number : 8 bits
	int iBus;
/// Device number : 5 bits
	int iDevice;
/// Function number : 3 bits
	int iFunction;
} ADLAdapterLocation,ADLBdf;


/////////////////////////////////////////////////////////////////////////////////////////////
/// \brief Structure containing information about MultiVPU capabilities.
///
/// This structure is used to store information about MultiVPU capabilities.
/// This structure is used by the ADL_Display_MVPUCaps_Get() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLMVPUCaps
{
/// Must be set to sizeof( ADLMVPUCaps ).
  int iSize;
/// Number of adapters.
  int iAdapterCount;
/// Bits set for all possible MVPU masters. \ref MVPU_ADAPTER_0 .. \ref MVPU_ADAPTER_3
  int iPossibleMVPUMasters;
/// Bits set for all possible MVPU slaves. \ref MVPU_ADAPTER_0 .. \ref MVPU_ADAPTER_3
  int iPossibleMVPUSlaves;
/// Registry path for each adapter.
  char cAdapterPath[ADL_DL_MAX_MVPU_ADAPTERS][ADL_DL_MAX_REGISTRY_PATH];
} ADLMVPUCaps;

/////////////////////////////////////////////////////////////////////////////////////////////
/// \brief Structure containing information about MultiVPU status.
///
/// This structure is used to store information about MultiVPU status.
/// Ths structure is used by the ADL_Display_MVPUStatus_Get() function.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLMVPUStatus
{
/// Must be set to sizeof( ADLMVPUStatus ).
  int iSize;
/// Number of active adapters.
  int iActiveAdapterCount;
/// MVPU status.
  int iStatus;
/// PCI Bus/Device/Function for each active adapter participating in MVPU.
  ADLAdapterLocation aAdapterLocation[ADL_DL_MAX_MVPU_ADAPTERS];
} ADLMVPUStatus;

// Displays Manager structures

///////////////////////////////////////////////////////////////////////////
/// \brief Structure containing information about the activatable source.
///
/// This structure is used to store activatable source information
/// This information can be returned to the user.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLActivatableSource
{
	/// The Persistent logical Adapter Index.
    int iAdapterIndex;
	/// The number of Activatable Sources.
    int iNumActivatableSources;
	/// The bit mask identifies the number of bits ActivatableSourceValue is using. (Not currnetly used)
	int iActivatableSourceMask;
	/// The bit mask identifies the status.  (Not currnetly used)
	int iActivatableSourceValue;
} ADLActivatableSource, *LPADLActivatableSource;

/////////////////////////////////////////////////////////////////////////////////////////////
/// \brief Structure containing information about display mode.
///
/// This structure is used to store the display mode for the current adapter
/// such as X, Y positions, screen resolutions, orientation,
/// color depth, refresh rate, progressive or interlace mode, etc.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////

typedef struct ADLMode
{
/// Adapter index.
    int iAdapterIndex;
/// Display IDs.
    ADLDisplayID displayID;
/// Screen position X coordinate.
    int iXPos;
/// Screen position Y coordinate.
    int iYPos;
/// Screen resolution Width.
    int iXRes;
/// Screen resolution Height.
    int iYRes;
/// Screen Color Depth. E.g., 16, 32.
    int iColourDepth;
/// Screen refresh rate. Could be fractional E.g. 59.97
    float fRefreshRate;
/// Screen orientation. E.g., 0, 90, 180, 270.
    int iOrientation;
/// Vista mode flag indicating Progressive or Interlaced mode.
    int iModeFlag;
/// The bit mask identifying the number of bits this Mode is currently using. It is the sum of all the bit definitions defined in \ref define_displaymode
    int iModeMask;
/// The bit mask identifying the display status. The detailed definition is in  \ref define_displaymode
    int iModeValue;
} ADLMode, *LPADLMode;


/////////////////////////////////////////////////////////////////////////////////////////////
/// \brief Structure containing information about display target information.
///
/// This structure is used to store the display target information.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDisplayTarget
{
	/// The Display ID.
	ADLDisplayID displayID;

	/// The display map index identify this manner and the desktop surface.
	int iDisplayMapIndex;

	/// The bit mask identifies the number of bits DisplayTarget is currently using. It is the sum of all the bit definitions defined in \ref ADL_DISPLAY_DISPLAYTARGET_PREFERRED.
	int  iDisplayTargetMask;

	/// The bit mask identifies the display status. The detailed definition is in \ref ADL_DISPLAY_DISPLAYTARGET_PREFERRED.
    int  iDisplayTargetValue;

} ADLDisplayTarget, *LPADLDisplayTarget;


/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the display SLS bezel Mode information.
///
/// This structure is used to store the display SLS bezel Mode information.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct tagADLBezelTransientMode
{
	/// Adapter Index
    int iAdapterIndex;

	/// SLS Map Index
    int iSLSMapIndex;

	/// The mode index
    int iSLSModeIndex;

	/// The mode
	ADLMode displayMode;

	/// The number of bezel offsets belongs to this map
    int  iNumBezelOffset;

	/// The first bezel offset array index in the native mode array
    int  iFirstBezelOffsetArrayIndex;

    /// The bit mask identifies the bits this structure is currently using. It will be the total OR of all the bit definitions.
    int  iSLSBezelTransientModeMask;

    /// The bit mask identifies the display status. The detail definition is defined below.
	int  iSLSBezelTransientModeValue;

} ADLBezelTransientMode, *LPADLBezelTransientMode;


/////////////////////////////////////////////////////////////////////////////////////////////
/// \brief Structure containing information about the adapter display manner.
///
/// This structure is used to store adapter display manner information
/// This information can be returned to the user. Alternatively, it can be used to access various driver calls to
/// fetch various display device related display manner settings upon the user's request.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLAdapterDisplayCap
{
	/// The Persistent logical Adapter Index.
    int iAdapterIndex;
	/// The bit mask identifies the number of bits AdapterDisplayCap is currently using. Sum all the bits defined in ADL_ADAPTER_DISPLAYCAP_XXX
    int  iAdapterDisplayCapMask;
	/// The bit mask identifies the status. Refer to ADL_ADAPTER_DISPLAYCAP_XXX
    int  iAdapterDisplayCapValue;
} ADLAdapterDisplayCap, *LPADLAdapterDisplayCap;


/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about display mapping.
///
/// This structure is used to store the display mapping data such as display manner.
/// For displays with horizontal or vertical stretch manner,
/// this structure also stores the display order, display row, and column data.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDisplayMap
{
/// The current display map index. It is the OS desktop index. For example, if the OS index 1 is showing clone mode, the display map will be 1.
	int iDisplayMapIndex;

/// The Display Mode for the current map
	ADLMode displayMode;

/// The number of display targets belongs to this map\n
	int iNumDisplayTarget;

/// The first target array index in the Target array\n
	int iFirstDisplayTargetArrayIndex;

/// The bit mask identifies the number of bits DisplayMap is currently using. It is the sum of all the bit definitions defined in ADL_DISPLAY_DISPLAYMAP_MANNER_xxx.
	int  iDisplayMapMask;

///The bit mask identifies the display status. The detailed definition is in ADL_DISPLAY_DISPLAYMAP_MANNER_xxx.
	int  iDisplayMapValue;

} ADLDisplayMap, *LPADLDisplayMap;


/////////////////////////////////////////////////////////////////////////////////////////////
/// \brief Structure containing information about the display device possible map for one GPU
///
/// This structure is used to store the display device possible map
/// This information can be returned to the user.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLPossibleMap
{
	/// The current PossibleMap index. Each PossibleMap is assigned an index
    int iIndex;
	/// The adapter index identifying the GPU for which to validate these Maps & Targets
	int iAdapterIndex;
	/// Number of display Maps for this GPU to be validated
    int iNumDisplayMap;
	/// The display Maps list to validate
    ADLDisplayMap* displayMap;
	/// the number of display Targets for these display Maps
    int iNumDisplayTarget;
	/// The display Targets list for these display Maps to be validated.
    ADLDisplayTarget* displayTarget;
} ADLPossibleMap, *LPADLPossibleMap;


/////////////////////////////////////////////////////////////////////////////////////////////
/// \brief Structure containing information about display possible mapping.
///
/// This structure is used to store the display possible mapping's controller index for the current display.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLPossibleMapping
{
    int iDisplayIndex;				///< The display index. Each display is assigned an index.
	int iDisplayControllerIndex;	///< The controller index to which display is mapped.
	int iDisplayMannerSupported;	///< The supported display manner.
} ADLPossibleMapping, *LPADLPossibleMapping;

/////////////////////////////////////////////////////////////////////////////////////////////
/// \brief Structure containing information about the validated display device possible map result.
///
/// This structure is used to store the validated display device possible map result
/// This information can be returned to the user.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLPossibleMapResult
{
	/// The current display map index. It is the OS Desktop index. For example, OS Index 1 showing clone mode. The Display Map will be 1.
    int iIndex;
	// The bit mask identifies the number of bits   PossibleMapResult is currently using. It will be the sum all the bit definitions defined in ADL_DISPLAY_POSSIBLEMAPRESULT_VALID.
	int iPossibleMapResultMask;
	/// The bit mask identifies the possible map result. The detail definition is defined in ADL_DISPLAY_POSSIBLEMAPRESULT_XXX.
	int iPossibleMapResultValue;
} ADLPossibleMapResult, *LPADLPossibleMapResult;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the display SLS Grid information.
///
/// This structure is used to store the display SLS Grid information.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLSLSGrid
{
/// The Adapter index.
	int iAdapterIndex;

/// The grid index.
	int  iSLSGridIndex;

/// The grid row.
	int  iSLSGridRow;

/// The grid column.
	int  iSLSGridColumn;

/// The grid bit mask identifies the number of bits DisplayMap is currently using. Sum of all bits defined in ADL_DISPLAY_SLSGRID_ORIENTATION_XXX
	int  iSLSGridMask;

/// The grid bit value identifies the display status. Refer to ADL_DISPLAY_SLSGRID_ORIENTATION_XXX
	int  iSLSGridValue;

} ADLSLSGrid, *LPADLSLSGrid;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the display SLS Map information.
///
/// This structure is used to store the display SLS Map information.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct	ADLSLSMap
{
	/// The Adapter Index
	int iAdapterIndex;

	/// The current display map index. It is the OS Desktop index. For example, OS Index 1 showing clone mode. The Display Map will be 1.
    int iSLSMapIndex;

	/// Indicate the current grid
    ADLSLSGrid grid;

	/// OS surface index
	int  iSurfaceMapIndex;

	 ///  Screen orientation. E.g., 0, 90, 180, 270
     int iOrientation;

	/// The number of display targets belongs to this map
    int  iNumSLSTarget;

	/// The first target array index in the Target array
    int  iFirstSLSTargetArrayIndex;

	/// The number of native modes belongs to this map
	int  iNumNativeMode;

	/// The first native mode array index in the native mode array
    int  iFirstNativeModeArrayIndex;

	/// The number of bezel modes belongs to this map
	int  iNumBezelMode;

	/// The first bezel mode array index in the native mode array
    int  iFirstBezelModeArrayIndex;

	/// The number of bezel offsets belongs to this map
	int  iNumBezelOffset;

	/// The first bezel offset array index in the
    int  iFirstBezelOffsetArrayIndex;

	/// The bit mask identifies the number of bits DisplayMap is currently using. Sum all the bit definitions defined in ADL_DISPLAY_SLSMAP_XXX.
    int  iSLSMapMask;

	/// The bit mask identifies the display map status. Refer to ADL_DISPLAY_SLSMAP_XXX
    int  iSLSMapValue;


} ADLSLSMap, *LPADLSLSMap;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the display SLS Offset information.
///
/// This structure is used to store the display SLS Offset information.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLSLSOffset
{
	/// The Adapter Index
	int iAdapterIndex;

	/// The current display map index. It is the OS Desktop index. For example, OS Index 1 showing clone mode. The Display Map will be 1.
    int iSLSMapIndex;

	/// The Display ID.
	ADLDisplayID displayID;

	/// SLS Bezel Mode Index
	int iBezelModeIndex;

	/// SLS Bezel Offset X
	int iBezelOffsetX;

	/// SLS Bezel Offset Y
	int iBezelOffsetY;

	/// SLS Display Width
	int iDisplayWidth;

	/// SLS Display Height
	int iDisplayHeight;

	/// The bit mask identifies the number of bits Offset is currently using.
	int iBezelOffsetMask;

	/// The bit mask identifies the display status.
	int  iBezelffsetValue;
} ADLSLSOffset, *LPADLSLSOffset;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the display SLS Mode information.
///
/// This structure is used to store the display SLS Mode information.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLSLSMode
{
	/// The Adapter Index
	int iAdapterIndex;

	/// The current display map index. It is the OS Desktop index. For example, OS Index 1 showing clone mode. The Display Map will be 1.
    int iSLSMapIndex;

	/// The mode index
	int iSLSModeIndex;

	/// The mode for this map.
    ADLMode displayMode;

	/// The bit mask identifies the number of bits Mode is currently using.
    int iSLSNativeModeMask;

	/// The bit mask identifies the display status.
	int iSLSNativeModeValue;
} ADLSLSMode, *LPADLSLSMode;




/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the display Possible SLS Map information.
///
/// This structure is used to store the display Possible SLS Map information.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLPossibleSLSMap
{
	/// The current display map index. It is the OS Desktop index.
	/// For example, OS Index 1 showing clone mode. The Display Map will be 1.
    int iSLSMapIndex;

	/// Number of display map to be validated.
    int iNumSLSMap;

	/// The display map list for validation
    ADLSLSMap* lpSLSMap;

	/// the number of display map config to be validated.
    int iNumSLSTarget;

	/// The display target list for validation.
    ADLDisplayTarget* lpDisplayTarget;
} ADLPossibleSLSMap, *LPADLPossibleSLSMap;


/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the SLS targets.
///
/// This structure is used to store the SLS targets information.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLSLSTarget
{
	/// the logic adapter index
    int iAdapterIndex;

	/// The SLS map index
    int iSLSMapIndex;

	/// The target ID
    ADLDisplayTarget displayTarget;

	/// Target postion X in SLS grid
	int iSLSGridPositionX;

	/// Target postion Y in SLS grid
    int iSLSGridPositionY;

	/// The view size width, height and rotation angle per SLS Target
	ADLMode viewSize;

	/// The bit mask identifies the bits in iSLSTargetValue are currently used
    int iSLSTargetMask;

	/// The bit mask identifies status info. It is for function extension purpose
    int iSLSTargetValue;

} ADLSLSTarget, *LPADLSLSTarget;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about the Adapter offset stepping size.
///
/// This structure is used to store the Adapter offset stepping size information.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLBezelOffsetSteppingSize
{
	/// the logic adapter index
    int iAdapterIndex;

	/// The SLS map index
    int iSLSMapIndex;

	/// Bezel X stepping size offset
	int iBezelOffsetSteppingSizeX;

	/// Bezel Y stepping size offset
	int iBezelOffsetSteppingSizeY;

	/// Identifies the bits this structure is currently using. It will be the total OR of all the bit definitions.
	int iBezelOffsetSteppingSizeMask;

	/// Bit mask identifies the display status.
	int iBezelOffsetSteppingSizeValue;

} ADLBezelOffsetSteppingSize, *LPADLBezelOffsetSteppingSize;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about driver supported PowerExpress Config Caps
///
/// This structure is used to store the driver supported PowerExpress Config Caps
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLPXConfigCaps
{
    /// The Persistent logical Adapter Index.
    int iAdapterIndex;

    /// The bit mask identifies the number of bits PowerExpress Config Caps is currently using. It is the sum of all the bit definitions defined in \ref ADL_PX_CONFIGCAPS_XXXX.
    int  iPXConfigCapMask;

    /// The bit mask identifies the PowerExpress Config Caps value. The detailed definition is in \ref ADL_PX_CONFIGCAPS_XXXX.
    int  iPXConfigCapValue;

} ADLPXConfigCaps, *LPADLPXConfigCaps;


/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about an application
///
/// This structure is used to store basic information of an application
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLApplicationData
{
	/// Path Name
	char strPathName[ADL_MAX_PATH];
	/// File Name
	char strFileName[ADL_APP_PROFILE_FILENAME_LENGTH];
	/// Creation timestamp
	char strTimeStamp[ADL_APP_PROFILE_TIMESTAMP_LENGTH];
	/// Version
	char strVersion[ADL_APP_PROFILE_VERSION_LENGTH];
}ADLApplicationData;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about an application
///
/// This structure is used to store basic information of an application
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLApplicationDataX2
{
	/// Path Name
	wchar_t strPathName[ADL_MAX_PATH];
	/// File Name
	wchar_t strFileName[ADL_APP_PROFILE_FILENAME_LENGTH];
	/// Creation timestamp
	wchar_t strTimeStamp[ADL_APP_PROFILE_TIMESTAMP_LENGTH];
	/// Version
	wchar_t strVersion[ADL_APP_PROFILE_VERSION_LENGTH];
}ADLApplicationDataX2;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information of a property of an application profile
///
/// This structure is used to store property information of an application profile
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _PropertyRecord
{
	/// Property Name
	char strName [ADL_APP_PROFILE_PROPERTY_LENGTH];
	/// Property Type
	ADLProfilePropertyType eType;
	/// Data Size in bytes
	int iDataSize;
	/// Property Value, can be any data type
	unsigned char uData[1];
}PropertyRecord;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about an application profile
///
/// This structure is used to store information of an application profile
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLApplicationProfile
{
	/// Number of properties
	int iCount;
	/// Buffer to store all property records
	PropertyRecord record[1];
}ADLApplicationProfile;

// @}

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about an OD5 Power Control feature
///
/// This structure is used to store information of an Power Control feature
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLPowerControlInfo
{
/// Minimum value.
int iMinValue;
/// Maximum value.
int iMaxValue;
/// The minimum change in between minValue and maxValue.
int iStepValue;
 } ADLPowerControlInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about an controller mode
///
/// This structure is used to store information of an controller mode
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLControllerMode
{
    /// This falg indicates actions that will be applied by set viewport
    /// The value can be a combination of ADL_CONTROLLERMODE_CM_MODIFIER_VIEW_POSITION,
    /// ADL_CONTROLLERMODE_CM_MODIFIER_VIEW_PANLOCK and ADL_CONTROLLERMODE_CM_MODIFIER_VIEW_SIZE
    int iModifiers;

    /// Horizontal view starting position
    int iViewPositionCx;

    /// Vertical view starting position
    int iViewPositionCy;

    /// Horizontal left panlock position
    int iViewPanLockLeft;

    /// Horizontal right panlock position
    int iViewPanLockRight;

    /// Vertical top panlock position
    int iViewPanLockTop;

    /// Vertical bottom panlock position
    int iViewPanLockBottom;

    /// View resolution in pixels (width)
    int iViewResolutionCx;

    /// View resolution in pixels (hight)
    int iViewResolutionCy;
}ADLControllerMode;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about a display
///
/// This structure is used to store information about a display
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDisplayIdentifier
{
    /// ADL display index
    long ulDisplayIndex;

    /// manufacturer ID of the display
    long ulManufacturerId;

    /// product ID of the display
    long ulProductId;

    /// serial number of the display
    long ulSerialNo;

} ADLDisplayIdentifier;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 clock range
///
/// This structure is used to store information about Overdrive 6 clock range
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLOD6ParameterRange
{
    /// The starting value of the clock range
    int 	iMin;
    /// The ending value of the clock range
    int 	iMax;
    /// The minimum increment between clock values
    int 	iStep;

} ADLOD6ParameterRange;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 capabilities
///
/// This structure is used to store information about Overdrive 6 capabilities
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLOD6Capabilities
{
    /// Contains a bitmap of the OD6 capability flags.  Possible values: \ref ADL_OD6_CAPABILITY_SCLK_CUSTOMIZATION,
    /// \ref ADL_OD6_CAPABILITY_MCLK_CUSTOMIZATION, \ref ADL_OD6_CAPABILITY_GPU_ACTIVITY_MONITOR
    int 	iCapabilities;
    /// Contains a bitmap indicating the power states
    /// supported by OD6.  Currently only the performance state
    /// is supported. Possible Values: \ref ADL_OD6_SUPPORTEDSTATE_PERFORMANCE
    int 	iSupportedStates;
    /// Number of levels. OD6 will always use 2 levels, which describe
    /// the minimum to maximum clock ranges.
    /// The 1st level indicates the minimum clocks, and the 2nd level
    /// indicates the maximum clocks.
    int     iNumberOfPerformanceLevels;
    /// Contains the hard limits of the sclk range.  Overdrive
    /// clocks cannot be set outside this range.
    ADLOD6ParameterRange 	sEngineClockRange;
    /// Contains the hard limits of the mclk range.  Overdrive
    /// clocks cannot be set outside this range.
    ADLOD6ParameterRange 	sMemoryClockRange;

    /// Value for future extension
    int     iExtValue;
    /// Mask for future extension
    int     iExtMask;

} ADLOD6Capabilities;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 clock values.
///
/// This structure is used to store information about Overdrive 6 clock values.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLOD6PerformanceLevel
{
    /// Engine (core) clock.
    int iEngineClock;
    /// Memory clock.
    int iMemoryClock;

} ADLOD6PerformanceLevel;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 clocks.
///
/// This structure is used to store information about Overdrive 6 clocks.  This is a
/// variable-sized structure.  iNumberOfPerformanceLevels indicate how many elements
/// are contained in the aLevels array.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLOD6StateInfo
{
    /// Number of levels.  OD6 uses clock ranges instead of discrete performance levels.
    /// iNumberOfPerformanceLevels is always 2.  The 1st level indicates the minimum clocks
    /// in the range.  The 2nd level indicates the maximum clocks in the range.
    int     iNumberOfPerformanceLevels;

    /// Value for future extension
    int     iExtValue;
    /// Mask for future extension
    int     iExtMask;

    /// Variable-sized array of levels.
    /// The number of elements in the array is specified by iNumberofPerformanceLevels.
    ADLOD6PerformanceLevel aLevels [1];

} ADLOD6StateInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about current Overdrive 6 performance status.
///
/// This structure is used to store information about current Overdrive 6 performance status.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLOD6CurrentStatus
{
    /// Current engine clock
    int 	iEngineClock;
    /// Current memory clock
    int 	iMemoryClock;
    /// Current GPU activity in percent.  This
    /// indicates how "busy" the GPU is.
    int 	iActivityPercent;
    /// Not used.  Reserved for future use.
    int 	iCurrentPerformanceLevel;
    /// Current PCI-E bus speed
    int 	iCurrentBusSpeed;
    /// Current PCI-E bus # of lanes
    int 	iCurrentBusLanes;
    /// Maximum possible PCI-E bus # of lanes
    int 	iMaximumBusLanes;

    /// Value for future extension
    int     iExtValue;
    /// Mask for future extension
    int     iExtMask;

} ADLOD6CurrentStatus;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 thermal contoller capabilities
///
/// This structure is used to store information about Overdrive 6 thermal controller capabilities
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLOD6ThermalControllerCaps
{
    /// Contains a bitmap of thermal controller capability flags. Possible values: \ref ADL_OD6_TCCAPS_THERMAL_CONTROLLER, \ref ADL_OD6_TCCAPS_FANSPEED_CONTROL,
    /// \ref ADL_OD6_TCCAPS_FANSPEED_PERCENT_READ, \ref ADL_OD6_TCCAPS_FANSPEED_PERCENT_WRITE, \ref ADL_OD6_TCCAPS_FANSPEED_RPM_READ, \ref ADL_OD6_TCCAPS_FANSPEED_RPM_WRITE
    int 	iCapabilities;
    /// Minimum fan speed expressed as a percentage
    int 	iFanMinPercent;
    /// Maximum fan speed expressed as a percentage
    int 	iFanMaxPercent;
    /// Minimum fan speed expressed in revolutions-per-minute
    int 	iFanMinRPM;
    /// Maximum fan speed expressed in revolutions-per-minute
    int 	iFanMaxRPM;

    /// Value for future extension
    int     iExtValue;
    /// Mask for future extension
    int     iExtMask;

} ADLOD6ThermalControllerCaps;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 fan speed information
///
/// This structure is used to store information about Overdrive 6 fan speed information
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLOD6FanSpeedInfo
{
    /// Contains a bitmap of the valid fan speed type flags.  Possible values: \ref ADL_OD6_FANSPEED_TYPE_PERCENT, \ref ADL_OD6_FANSPEED_TYPE_RPM, \ref ADL_OD6_FANSPEED_USER_DEFINED
    int 	iSpeedType;
    /// Contains current fan speed in percent (if valid flag exists in iSpeedType)
    int 	iFanSpeedPercent;
    /// Contains current fan speed in RPM (if valid flag exists in iSpeedType)
    int	    iFanSpeedRPM;

    /// Value for future extension
    int     iExtValue;
    /// Mask for future extension
    int     iExtMask;

} ADLOD6FanSpeedInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 fan speed value
///
/// This structure is used to store information about Overdrive 6 fan speed value
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLOD6FanSpeedValue
{
    /// Indicates the units of the fan speed.  Possible values: \ref ADL_OD6_FANSPEED_TYPE_PERCENT, \ref ADL_OD6_FANSPEED_TYPE_RPM
    int 	iSpeedType;
    /// Fan speed value (units as indicated above)
    int 	iFanSpeed;

    /// Value for future extension
    int     iExtValue;
    /// Mask for future extension
    int     iExtMask;

} ADLOD6FanSpeedValue;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 PowerControl settings.
///
/// This structure is used to store information about Overdrive 6 PowerControl settings.
/// PowerControl is the feature which allows the performance characteristics of the GPU
/// to be adjusted by changing the PowerTune power limits.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLOD6PowerControlInfo
{
    /// The minimum PowerControl adjustment value
    int 	iMinValue;
    /// The maximum PowerControl adjustment value
    int 	iMaxValue;
    /// The minimum difference between PowerControl adjustment values
    int 	iStepValue;

    /// Value for future extension
    int     iExtValue;
    /// Mask for future extension
    int     iExtMask;

} ADLOD6PowerControlInfo;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 PowerControl settings.
///
/// This structure is used to store information about Overdrive 6 PowerControl settings.
/// PowerControl is the feature which allows the performance characteristics of the GPU
/// to be adjusted by changing the PowerTune power limits.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLOD6VoltageControlInfo
{
    /// The minimum VoltageControl adjustment value
    int 	iMinValue;
    /// The maximum VoltageControl adjustment value
    int 	iMaxValue;
    /// The minimum difference between VoltageControl adjustment values
    int 	iStepValue;

    /// Value for future extension
    int     iExtValue;
    /// Mask for future extension
    int     iExtMask;

} ADLOD6VoltageControlInfo;

////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing ECC statistics namely SEC counts and DED counts
/// Single error count - count of errors that can be corrected
/// Doubt Error Detect -  count of errors that cannot be corrected
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLECCData
{
	// Single error count - count of errors that can be corrected
	int iSec;
	// Double error detect - count of errors that cannot be corrected
	int iDed;

} ADLECCData;


/// \brief Handle to ADL client context.
///
///  ADL clients obtain context handle from initial call to \ref ADL2_Main_Control_Create.
///  Clients have to pass the handle to each subsequent ADL call and finally destroy
///  the context with call to \ref ADL2_Main_Control_Destroy
/// \nosubgrouping
typedef void *ADL_CONTEXT_HANDLE;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing the display mode definition used per controller.
///
/// This structure is used to store the display mode definition used per controller.
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct ADLDisplayModeX2
{
/// Horizontal resolution (in pixels).
   int  iWidth;
/// Vertical resolution (in lines).
   int  iHeight;
/// Interlaced/Progressive. The value will be set for Interlaced as ADL_DL_TIMINGFLAG_INTERLACED. If not set it is progressive. Refer define_detailed_timing_flags.
   int  iScanType;
/// Refresh rate.
   int  iRefreshRate;
/// Timing Standard. Refer define_modetiming_standard.
   int  iTimingStandard;
} ADLDisplayModeX2;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 extension capabilities
///
/// This structure is used to store information about Overdrive 6 extension capabilities
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLOD6CapabilitiesEx
{
    /// Contains a bitmap of the OD6 extension capability flags.  Possible values: \ref ADL_OD6_CAPABILITY_SCLK_CUSTOMIZATION,
    /// \ref ADL_OD6_CAPABILITY_MCLK_CUSTOMIZATION, \ref ADL_OD6_CAPABILITY_GPU_ACTIVITY_MONITOR,
    /// \ref ADL_OD6_CAPABILITY_POWER_CONTROL, \ref ADL_OD6_CAPABILITY_VOLTAGE_CONTROL, \ref ADL_OD6_CAPABILITY_PERCENT_ADJUSTMENT,
    //// \ref ADL_OD6_CAPABILITY_THERMAL_LIMIT_UNLOCK
    int iCapabilities;
    /// The Power states that support clock and power customization.  Only performance state is currently supported.
    /// Possible Values: \ref ADL_OD6_SUPPORTEDSTATE_PERFORMANCE
    int iSupportedStates;
    /// Returns the hard limits of the SCLK overdrive adjustment range.  Overdrive clocks should not be adjusted outside of this range.  The values are specified as +/- percentages.
    ADLOD6ParameterRange sEngineClockPercent;
    /// Returns the hard limits of the MCLK overdrive adjustment range.  Overdrive clocks should not be adjusted outside of this range.  The values are specified as +/- percentages.
    ADLOD6ParameterRange sMemoryClockPercent;
    /// Returns the hard limits of the Power Limit adjustment range.  Power limit should not be adjusted outside this range.  The values are specified as +/- percentages.
    ADLOD6ParameterRange sPowerControlPercent;
    /// Reserved for future expansion of the structure.
    int iExtValue;
    /// Reserved for future expansion of the structure.
    int iExtMask;
} ADLOD6CapabilitiesEx;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 extension state information
///
/// This structure is used to store information about Overdrive 6 extension state information
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLOD6StateEx
{
    /// The current engine clock adjustment value, specified as a +/- percent.
    int iEngineClockPercent;
    /// The current memory clock adjustment value, specified as a +/- percent.
    int iMemoryClockPercent;
    /// The current power control adjustment value, specified as a +/- percent.
    int iPowerControlPercent;
    /// Reserved for future expansion of the structure.
    int iExtValue;
    /// Reserved for future expansion of the structure.
    int iExtMask;
} ADLOD6StateEx;

/////////////////////////////////////////////////////////////////////////////////////////////
///\brief Structure containing information about Overdrive 6 extension recommended maximum clock adjustment values
///
/// This structure is used to store information about Overdrive 6 extension recommended maximum clock adjustment values
/// \nosubgrouping
////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _ADLOD6MaxClockAdjust
{
    /// The recommended maximum engine clock adjustment in percent, for the specified power limit value.
    int iEngineClockMax;
    /// The recommended maximum memory clock adjustment in percent, for the specified power limit value.
    /// Currently the memory is independent of the Power Limit setting, so iMemoryClockMax will always return the maximum
    /// possible adjustment value.  This field is here for future enhancement in case we add a dependency between Memory Clock
    /// adjustment and Power Limit setting.
    int iMemoryClockMax;
    /// Reserved for future expansion of the structure.
    int iExtValue;
    /// Reserved for future expansion of the structure.
    int iExtMask;
} ADLOD6MaxClockAdjust;

#endif /* ADL_STRUCTURES_H_ */

//
//  Copyright (c) 2008 - 2013 Advanced Micro Devices, Inc.

//  THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
//  EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.

/// \file adl_defines.h
/// \brief Contains all definitions exposed by ADL for \ALL platforms.\n <b>Included in ADL SDK</b>
///
/// This file contains all definitions used by ADL.
/// The ADL definitions include the following:
/// \li ADL error codes
/// \li Enumerations for the ADLDisplayInfo structure
/// \li Maximum limits
///

#ifndef ADL_DEFINES_H_
#define ADL_DEFINES_H_

/// \defgroup DEFINES Constants and Definitions
// @{

/// \defgroup define_misc Miscellaneous Constant Definitions
// @{

/// \name General Definitions
// @{

/// Defines ADL_TRUE
#define ADL_TRUE	1
/// Defines ADL_FALSE
#define ADL_FALSE		0

/// Defines the maximum string length
#define ADL_MAX_CHAR                                    4096
/// Defines the maximum string length
#define ADL_MAX_PATH                                    256
/// Defines the maximum number of supported adapters
#define ADL_MAX_ADAPTERS                               250
/// Defines the maxumum number of supported displays
#define ADL_MAX_DISPLAYS                                150
/// Defines the maxumum string length for device name
#define ADL_MAX_DEVICENAME								32
/// Defines for all adapters
#define ADL_ADAPTER_INDEX_ALL							-1
///	Defines APIs with iOption none
#define ADL_MAIN_API_OPTION_NONE						0
// @}

/// \name Definitions for iOption parameter used by
/// ADL_Display_DDCBlockAccess_Get()
// @{

/// Switch to DDC line 2 before sending the command to the display.
#define ADL_DDC_OPTION_SWITCHDDC2              0x00000001
/// Save command in the registry under a unique key, corresponding to parameter \b iCommandIndex
#define ADL_DDC_OPTION_RESTORECOMMAND 0x00000002
/// Combine write-read DDC block access command.
#define ADL_DDC_OPTION_COMBOWRITEREAD 0x00000010
/// Direct DDC access to the immediate device connected to graphics card.
/// MST with this option set: DDC command is sent to first branch.
/// MST with this option not set: DDC command is sent to the end node sink device.
#define ADL_DDC_OPTION_SENDTOIMMEDIATEDEVICE 0x00000020
// @}

/// \name Values for
/// ADLI2C.iAction used with ADL_Display_WriteAndReadI2C()
// @{

#define ADL_DL_I2C_ACTIONREAD									0x00000001
#define ADL_DL_I2C_ACTIONWRITE								0x00000002
#define ADL_DL_I2C_ACTIONREAD_REPEATEDSTART    0x00000003
// @}


// @}		//Misc

/// \defgroup define_adl_results Result Codes
/// This group of definitions are the various results returned by all ADL functions \n
// @{
/// All OK, but need to wait
#define ADL_OK_WAIT				4
/// All OK, but need restart
#define ADL_OK_RESTART				3
/// All OK but need mode change
#define ADL_OK_MODE_CHANGE			2
/// All OK, but with warning
#define ADL_OK_WARNING				1
/// ADL function completed successfully
#define ADL_OK					0
/// Generic Error. Most likely one or more of the Escape calls to the driver failed!
#define ADL_ERR					-1
/// ADL not initialized
#define ADL_ERR_NOT_INIT			-2
/// One of the parameter passed is invalid
#define ADL_ERR_INVALID_PARAM			-3
/// One of the parameter size is invalid
#define ADL_ERR_INVALID_PARAM_SIZE		-4
/// Invalid ADL index passed
#define ADL_ERR_INVALID_ADL_IDX			-5
/// Invalid controller index passed
#define ADL_ERR_INVALID_CONTROLLER_IDX		-6
/// Invalid display index passed
#define ADL_ERR_INVALID_DIPLAY_IDX		-7
/// Function  not supported by the driver
#define ADL_ERR_NOT_SUPPORTED			-8
/// Null Pointer error
#define ADL_ERR_NULL_POINTER			-9
/// Call can't be made due to disabled adapter
#define ADL_ERR_DISABLED_ADAPTER		-10
/// Invalid Callback
#define ADL_ERR_INVALID_CALLBACK        	-11
/// Display Resource conflict
#define ADL_ERR_RESOURCE_CONFLICT				-12
//Failed to update some of the values. Can be returned by set request that include multiple values if not all values were successfully committed.
#define ADL_ERR_SET_INCOMPLETE 				-20
/// There's no Linux XDisplay in Linux Console environment
#define ADL_ERR_NO_XDISPLAY					-21

// @}
/// </A>

/// \defgroup define_display_type Display Type
/// Define Monitor/CRT display type
// @{
/// Define Monitor display type
#define ADL_DT_MONITOR          		0
/// Define TV display type
#define ADL_DT_TELEVISION                	1
/// Define LCD display type
#define ADL_DT_LCD_PANEL               		2
/// Define DFP display type
#define ADL_DT_DIGITAL_FLAT_PANEL		3
/// Define Componment Video display type
#define ADL_DT_COMPONENT_VIDEO           	4
/// Define Projector display type
#define ADL_DT_PROJECTOR           	        5
// @}

/// \defgroup define_display_connection_type Display Connection Type
// @{
/// Define unknown display output type
#define ADL_DOT_UNKNOWN				0
/// Define composite display output type
#define ADL_DOT_COMPOSITE			1
/// Define SVideo display output type
#define ADL_DOT_SVIDEO				2
/// Define analog display output type
#define ADL_DOT_ANALOG				3
/// Define digital display output type
#define ADL_DOT_DIGITAL				4
// @}

/// \defgroup define_color_type Display Color Type and Source
/// Define  Display Color Type and Source
// @{
#define ADL_DISPLAY_COLOR_BRIGHTNESS	(1 << 0)
#define ADL_DISPLAY_COLOR_CONTRAST	(1 << 1)
#define ADL_DISPLAY_COLOR_SATURATION	(1 << 2)
#define ADL_DISPLAY_COLOR_HUE		(1 << 3)
#define ADL_DISPLAY_COLOR_TEMPERATURE	(1 << 4)

/// Color Temperature Source is EDID
#define ADL_DISPLAY_COLOR_TEMPERATURE_SOURCE_EDID	(1 << 5)
/// Color Temperature Source is User
#define ADL_DISPLAY_COLOR_TEMPERATURE_SOURCE_USER	(1 << 6)
// @}

/// \defgroup define_adjustment_capabilities Display Adjustment Capabilities
/// Display adjustment capabilities values.  Returned by ADL_Display_AdjustCaps_Get
// @{
#define ADL_DISPLAY_ADJUST_OVERSCAN		(1 << 0)
#define ADL_DISPLAY_ADJUST_VERT_POS		(1 << 1)
#define ADL_DISPLAY_ADJUST_HOR_POS		(1 << 2)
#define ADL_DISPLAY_ADJUST_VERT_SIZE		(1 << 3)
#define ADL_DISPLAY_ADJUST_HOR_SIZE		(1 << 4)
#define ADL_DISPLAY_ADJUST_SIZEPOS		(ADL_DISPLAY_ADJUST_VERT_POS | ADL_DISPLAY_ADJUST_HOR_POS | ADL_DISPLAY_ADJUST_VERT_SIZE | ADL_DISPLAY_ADJUST_HOR_SIZE)
#define ADL_DISPLAY_CUSTOMMODES			(1<<5)
#define ADL_DISPLAY_ADJUST_UNDERSCAN		(1<<6)
// @}


/// \defgroup define_desktop_config Desktop Configuration Flags
/// These flags are used by ADL_DesktopConfig_xxx
/// \deprecated This API has been deprecated because it was only used for RandR 1.1 (Red Hat 5.x) distributions which is now not supported.
// @{
#define ADL_DESKTOPCONFIG_UNKNOWN    0    	  /* UNKNOWN desktop config   */
#define ADL_DESKTOPCONFIG_SINGLE     (1 <<  0)    /* Single                   */
#define ADL_DESKTOPCONFIG_CLONE      (1 <<  2)    /* Clone                    */
#define ADL_DESKTOPCONFIG_BIGDESK_H  (1 <<  4)    /* Big Desktop Horizontal   */
#define ADL_DESKTOPCONFIG_BIGDESK_V  (1 <<  5)    /* Big Desktop Vertical     */
#define ADL_DESKTOPCONFIG_BIGDESK_HR (1 <<  6)    /* Big Desktop Reverse Horz */
#define ADL_DESKTOPCONFIG_BIGDESK_VR (1 <<  7)    /* Big Desktop Reverse Vert */
#define ADL_DESKTOPCONFIG_RANDR12    (1 <<  8)    /* RandR 1.2 Multi-display */
// @}

/// needed for ADLDDCInfo structure
#define ADL_MAX_DISPLAY_NAME                                256

/// \defgroup define_edid_flags Values for ulDDCInfoFlag
/// defines for ulDDCInfoFlag EDID flag
// @{
#define ADL_DISPLAYDDCINFOEX_FLAG_PROJECTORDEVICE       (1 << 0)
#define ADL_DISPLAYDDCINFOEX_FLAG_EDIDEXTENSION         (1 << 1)
#define ADL_DISPLAYDDCINFOEX_FLAG_DIGITALDEVICE         (1 << 2)
#define ADL_DISPLAYDDCINFOEX_FLAG_HDMIAUDIODEVICE       (1 << 3)
#define ADL_DISPLAYDDCINFOEX_FLAG_SUPPORTS_AI           (1 << 4)
#define ADL_DISPLAYDDCINFOEX_FLAG_SUPPORT_xvYCC601      (1 << 5)
#define ADL_DISPLAYDDCINFOEX_FLAG_SUPPORT_xvYCC709      (1 << 6)
// @}

/// \defgroup define_displayinfo_connector Display Connector Type
/// defines for ADLDisplayInfo.iDisplayConnector
// @{
#define ADL_DISPLAY_CONTYPE_UNKNOWN                 0
#define ADL_DISPLAY_CONTYPE_VGA                     1
#define ADL_DISPLAY_CONTYPE_DVI_D                   2
#define ADL_DISPLAY_CONTYPE_DVI_I                   3
#define ADL_DISPLAY_CONTYPE_ATICVDONGLE_NTSC        4
#define ADL_DISPLAY_CONTYPE_ATICVDONGLE_JPN         5
#define ADL_DISPLAY_CONTYPE_ATICVDONGLE_NONI2C_JPN  6
#define ADL_DISPLAY_CONTYPE_ATICVDONGLE_NONI2C_NTSC 7
#define ADL_DISPLAY_CONTYPE_PROPRIETARY				8
#define ADL_DISPLAY_CONTYPE_HDMI_TYPE_A             10
#define ADL_DISPLAY_CONTYPE_HDMI_TYPE_B             11
#define ADL_DISPLAY_CONTYPE_SVIDEO               	12
#define ADL_DISPLAY_CONTYPE_COMPOSITE               13
#define ADL_DISPLAY_CONTYPE_RCA_3COMPONENT          14
#define ADL_DISPLAY_CONTYPE_DISPLAYPORT             15
#define ADL_DISPLAY_CONTYPE_EDP                     16
#define ADL_DISPLAY_CONTYPE_WIRELESSDISPLAY         17
// @}

/// TV Capabilities and Standards
/// \defgroup define_tv_caps TV Capabilities and Standards
/// \deprecated Dropping support for TV displays
// @{
#define ADL_TV_STANDARDS			(1 << 0)
#define ADL_TV_SCART				(1 << 1)

/// TV Standards Definitions
#define ADL_STANDARD_NTSC_M		(1 << 0)
#define ADL_STANDARD_NTSC_JPN		(1 << 1)
#define ADL_STANDARD_NTSC_N		(1 << 2)
#define ADL_STANDARD_PAL_B		(1 << 3)
#define ADL_STANDARD_PAL_COMB_N		(1 << 4)
#define ADL_STANDARD_PAL_D		(1 << 5)
#define ADL_STANDARD_PAL_G		(1 << 6)
#define ADL_STANDARD_PAL_H		(1 << 7)
#define ADL_STANDARD_PAL_I		(1 << 8)
#define ADL_STANDARD_PAL_K		(1 << 9)
#define ADL_STANDARD_PAL_K1		(1 << 10)
#define ADL_STANDARD_PAL_L		(1 << 11)
#define ADL_STANDARD_PAL_M		(1 << 12)
#define ADL_STANDARD_PAL_N		(1 << 13)
#define ADL_STANDARD_PAL_SECAM_D	(1 << 14)
#define ADL_STANDARD_PAL_SECAM_K	(1 << 15)
#define ADL_STANDARD_PAL_SECAM_K1	(1 << 16)
#define ADL_STANDARD_PAL_SECAM_L	(1 << 17)
// @}


/// \defgroup define_video_custom_mode Video Custom Mode flags
/// Component Video Custom Mode flags.  This is used by the iFlags parameter in ADLCustomMode
// @{
#define ADL_CUSTOMIZEDMODEFLAG_MODESUPPORTED	(1 << 0)
#define ADL_CUSTOMIZEDMODEFLAG_NOTDELETETABLE	(1 << 1)
#define ADL_CUSTOMIZEDMODEFLAG_INSERTBYDRIVER	(1 << 2)
#define ADL_CUSTOMIZEDMODEFLAG_INTERLACED	(1 << 3)
#define ADL_CUSTOMIZEDMODEFLAG_BASEMODE		(1 << 4)
// @}

/// \defgroup define_ddcinfoflag Values used for DDCInfoFlag
/// ulDDCInfoFlag field values used by the ADLDDCInfo structure
// @{
#define ADL_DISPLAYDDCINFOEX_FLAG_PROJECTORDEVICE	(1 << 0)
#define ADL_DISPLAYDDCINFOEX_FLAG_EDIDEXTENSION		(1 << 1)
#define ADL_DISPLAYDDCINFOEX_FLAG_DIGITALDEVICE		(1 << 2)
#define ADL_DISPLAYDDCINFOEX_FLAG_HDMIAUDIODEVICE	(1 << 3)
#define ADL_DISPLAYDDCINFOEX_FLAG_SUPPORTS_AI		(1 << 4)
#define ADL_DISPLAYDDCINFOEX_FLAG_SUPPORT_xvYCC601	(1 << 5)
#define ADL_DISPLAYDDCINFOEX_FLAG_SUPPORT_xvYCC709	(1 << 6)
// @}

/// \defgroup define_cv_dongle Values used by ADL_CV_DongleSettings_xxx
/// The following is applicable to ADL_DISPLAY_CONTYPE_ATICVDONGLE_JP and ADL_DISPLAY_CONTYPE_ATICVDONGLE_NONI2C_D only
/// \deprecated Dropping support for Component Video displays
// @{
#define ADL_DISPLAY_CV_DONGLE_D1          (1 << 0)
#define ADL_DISPLAY_CV_DONGLE_D2          (1 << 1)
#define ADL_DISPLAY_CV_DONGLE_D3          (1 << 2)
#define ADL_DISPLAY_CV_DONGLE_D4          (1 << 3)
#define ADL_DISPLAY_CV_DONGLE_D5          (1 << 4)

/// The following is applicable to ADL_DISPLAY_CONTYPE_ATICVDONGLE_NA and ADL_DISPLAY_CONTYPE_ATICVDONGLE_NONI2C only

#define ADL_DISPLAY_CV_DONGLE_480I        (1 << 0)
#define ADL_DISPLAY_CV_DONGLE_480P        (1 << 1)
#define ADL_DISPLAY_CV_DONGLE_540P        (1 << 2)
#define ADL_DISPLAY_CV_DONGLE_720P        (1 << 3)
#define ADL_DISPLAY_CV_DONGLE_1080I       (1 << 4)
#define ADL_DISPLAY_CV_DONGLE_1080P       (1 << 5)
#define ADL_DISPLAY_CV_DONGLE_16_9        (1 << 6)
#define ADL_DISPLAY_CV_DONGLE_720P50      (1 << 7)
#define ADL_DISPLAY_CV_DONGLE_1080I25     (1 << 8)
#define ADL_DISPLAY_CV_DONGLE_576I25      (1 << 9)
#define ADL_DISPLAY_CV_DONGLE_576P50      (1 << 10)
#define ADL_DISPLAY_CV_DONGLE_1080P24      (1 << 11)
#define ADL_DISPLAY_CV_DONGLE_1080P25      (1 << 12)
#define ADL_DISPLAY_CV_DONGLE_1080P30      (1 << 13)
#define ADL_DISPLAY_CV_DONGLE_1080P50      (1 << 14)
// @}

/// \defgroup define_formats_ovr	Formats Override Settings
/// Display force modes flags
// @{
///
#define ADL_DISPLAY_FORMAT_FORCE_720P		0x00000001
#define ADL_DISPLAY_FORMAT_FORCE_1080I		0x00000002
#define ADL_DISPLAY_FORMAT_FORCE_1080P		0x00000004
#define ADL_DISPLAY_FORMAT_FORCE_720P50		0x00000008
#define ADL_DISPLAY_FORMAT_FORCE_1080I25	0x00000010
#define ADL_DISPLAY_FORMAT_FORCE_576I25		0x00000020
#define ADL_DISPLAY_FORMAT_FORCE_576P50		0x00000040
#define ADL_DISPLAY_FORMAT_FORCE_1080P24	0x00000080
#define ADL_DISPLAY_FORMAT_FORCE_1080P25	0x00000100
#define ADL_DISPLAY_FORMAT_FORCE_1080P30	0x00000200
#define ADL_DISPLAY_FORMAT_FORCE_1080P50	0x00000400

///< Below are \b EXTENDED display mode flags

#define ADL_DISPLAY_FORMAT_CVDONGLEOVERIDE  0x00000001
#define ADL_DISPLAY_FORMAT_CVMODEUNDERSCAN  0x00000002
#define ADL_DISPLAY_FORMAT_FORCECONNECT_SUPPORTED  0x00000004
#define ADL_DISPLAY_FORMAT_RESTRICT_FORMAT_SELECTION 0x00000008
#define ADL_DISPLAY_FORMAT_SETASPECRATIO 0x00000010
#define ADL_DISPLAY_FORMAT_FORCEMODES    0x00000020
#define ADL_DISPLAY_FORMAT_LCDRTCCOEFF   0x00000040
// @}

/// Defines used by OD5
#define ADL_PM_PARAM_DONT_CHANGE    0

/// The following defines Bus types
// @{
#define ADL_BUSTYPE_PCI           0       /* PCI bus                          */
#define ADL_BUSTYPE_AGP           1       /* AGP bus                          */
#define ADL_BUSTYPE_PCIE          2       /* PCI Express bus                  */
#define ADL_BUSTYPE_PCIE_GEN2     3       /* PCI Express 2nd generation bus   */
#define ADL_BUSTYPE_PCIE_GEN3     4       /* PCI Express 3rd generation bus   */
// @}

/// \defgroup define_ws_caps	Workstation Capabilities
/// Workstation values
// @{

/// This value indicates that the workstation card supports active stereo though stereo output connector
#define ADL_STEREO_SUPPORTED		(1 << 2)
/// This value indicates that the workstation card supports active stereo via "blue-line"
#define ADL_STEREO_BLUE_LINE		(1 << 3)
/// This value is used to turn off stereo mode.
#define ADL_STEREO_OFF				0
/// This value indicates that the workstation card supports active stereo.  This is also used to set the stereo mode to active though the stereo output connector
#define ADL_STEREO_ACTIVE	 		(1 << 1)
/// This value indicates that the workstation card supports auto-stereo monitors with horizontal interleave. This is also used to set the stereo mode to use the auto-stereo monitor with horizontal interleave
#define ADL_STEREO_AUTO_HORIZONTAL	(1 << 30)
/// This value indicates that the workstation card supports auto-stereo monitors with vertical interleave. This is also used to set the stereo mode to use the auto-stereo monitor with vertical interleave
#define ADL_STEREO_AUTO_VERTICAL	(1 << 31)
/// This value indicates that the workstation card supports passive stereo, ie. non stereo sync
#define ADL_STEREO_PASSIVE              (1 << 6)
/// This value indicates that the workstation card supports auto-stereo monitors with vertical interleave. This is also used to set the stereo mode to use the auto-stereo monitor with vertical interleave
#define ADL_STEREO_PASSIVE_HORIZ        (1 << 7)
/// This value indicates that the workstation card supports auto-stereo monitors with vertical interleave. This is also used to set the stereo mode to use the auto-stereo monitor with vertical interleave
#define ADL_STEREO_PASSIVE_VERT         (1 << 8)
/// This value indicates that the workstation card supports auto-stereo monitors with Samsung.
#define ADL_STEREO_AUTO_SAMSUNG        (1 << 11)
/// This value indicates that the workstation card supports auto-stereo monitors with Tridility.
#define ADL_STEREO_AUTO_TSL         (1 << 12)
/// This value indicates that the workstation card supports DeepBitDepth (10 bpp)
#define ADL_DEEPBITDEPTH_10BPP_SUPPORTED   (1 << 5)

/// This value indicates that the workstation supports 8-Bit Grayscale
#define ADL_8BIT_GREYSCALE_SUPPORTED   (1 << 9)
/// This value indicates that the workstation supports CUSTOM TIMING
#define ADL_CUSTOM_TIMING_SUPPORTED   (1 << 10)

/// Load balancing is supported.
#define ADL_WORKSTATION_LOADBALANCING_SUPPORTED         0x00000001
/// Load balancing is available.
#define ADL_WORKSTATION_LOADBALANCING_AVAILABLE         0x00000002

/// Load balancing is disabled.
#define ADL_WORKSTATION_LOADBALANCING_DISABLED          0x00000000
/// Load balancing is Enabled.
#define ADL_WORKSTATION_LOADBALANCING_ENABLED           0x00000001



// @}

/// \defgroup define_adapterspeed speed setting from the adapter
// @{
#define ADL_CONTEXT_SPEED_UNFORCED		0		/* default asic running speed */
#define ADL_CONTEXT_SPEED_FORCEHIGH		1		/* asic running speed is forced to high */
#define ADL_CONTEXT_SPEED_FORCELOW		2		/* asic running speed is forced to low */

#define ADL_ADAPTER_SPEEDCAPS_SUPPORTED		(1 << 0)	/* change asic running speed setting is supported */
// @}

/// \defgroup define_glsync Genlock related values
/// GL-Sync port types (unique values)
// @{
/// Unknown port of GL-Sync module
#define ADL_GLSYNC_PORT_UNKNOWN		0
/// BNC port of of GL-Sync module
#define ADL_GLSYNC_PORT_BNC			1
/// RJ45(1) port of of GL-Sync module
#define ADL_GLSYNC_PORT_RJ45PORT1	2
/// RJ45(2) port of of GL-Sync module
#define ADL_GLSYNC_PORT_RJ45PORT2	3

// GL-Sync Genlock settings mask (bit-vector)

/// None of the ADLGLSyncGenlockConfig members are valid
#define ADL_GLSYNC_CONFIGMASK_NONE				0
/// The ADLGLSyncGenlockConfig.lSignalSource member is valid
#define ADL_GLSYNC_CONFIGMASK_SIGNALSOURCE		(1 << 0)
/// The ADLGLSyncGenlockConfig.iSyncField member is valid
#define ADL_GLSYNC_CONFIGMASK_SYNCFIELD			(1 << 1)
/// The ADLGLSyncGenlockConfig.iSampleRate member is valid
#define ADL_GLSYNC_CONFIGMASK_SAMPLERATE		(1 << 2)
/// The ADLGLSyncGenlockConfig.lSyncDelay member is valid
#define ADL_GLSYNC_CONFIGMASK_SYNCDELAY			(1 << 3)
/// The ADLGLSyncGenlockConfig.iTriggerEdge member is valid
#define ADL_GLSYNC_CONFIGMASK_TRIGGEREDGE		(1 << 4)
/// The ADLGLSyncGenlockConfig.iScanRateCoeff member is valid
#define ADL_GLSYNC_CONFIGMASK_SCANRATECOEFF		(1 << 5)
/// The ADLGLSyncGenlockConfig.lFramelockCntlVector member is valid
#define ADL_GLSYNC_CONFIGMASK_FRAMELOCKCNTL		(1 << 6)


// GL-Sync Framelock control mask (bit-vector)

/// Framelock is disabled
#define ADL_GLSYNC_FRAMELOCKCNTL_NONE			0
/// Framelock is enabled
#define ADL_GLSYNC_FRAMELOCKCNTL_ENABLE			( 1 << 0)

#define ADL_GLSYNC_FRAMELOCKCNTL_DISABLE		( 1 << 1)
#define ADL_GLSYNC_FRAMELOCKCNTL_SWAP_COUNTER_RESET	( 1 << 2)
#define ADL_GLSYNC_FRAMELOCKCNTL_SWAP_COUNTER_ACK	( 1 << 3)
#define ADL_GLSYNC_FRAMELOCKCNTL_VERSION_KMD	(1 << 4)

#define ADL_GLSYNC_FRAMELOCKCNTL_STATE_ENABLE		( 1 << 0)
#define ADL_GLSYNC_FRAMELOCKCNTL_STATE_KMD		(1 << 4)

// GL-Sync Framelock counters mask (bit-vector)
#define ADL_GLSYNC_COUNTER_SWAP				( 1 << 0 )

// GL-Sync Signal Sources (unique values)

/// GL-Sync signal source is undefined
#define ADL_GLSYNC_SIGNALSOURCE_UNDEFINED    0x00000100
/// GL-Sync signal source is Free Run
#define ADL_GLSYNC_SIGNALSOURCE_FREERUN      0x00000101
/// GL-Sync signal source is the BNC GL-Sync port
#define ADL_GLSYNC_SIGNALSOURCE_BNCPORT      0x00000102
/// GL-Sync signal source is the RJ45(1) GL-Sync port
#define ADL_GLSYNC_SIGNALSOURCE_RJ45PORT1    0x00000103
/// GL-Sync signal source is the RJ45(2) GL-Sync port
#define ADL_GLSYNC_SIGNALSOURCE_RJ45PORT2    0x00000104


// GL-Sync Signal Types (unique values)

/// GL-Sync signal type is unknown
#define ADL_GLSYNC_SIGNALTYPE_UNDEFINED      0
/// GL-Sync signal type is 480I
#define ADL_GLSYNC_SIGNALTYPE_480I           1
/// GL-Sync signal type is 576I
#define ADL_GLSYNC_SIGNALTYPE_576I           2
/// GL-Sync signal type is 480P
#define ADL_GLSYNC_SIGNALTYPE_480P           3
/// GL-Sync signal type is 576P
#define ADL_GLSYNC_SIGNALTYPE_576P           4
/// GL-Sync signal type is 720P
#define ADL_GLSYNC_SIGNALTYPE_720P           5
/// GL-Sync signal type is 1080P
#define ADL_GLSYNC_SIGNALTYPE_1080P          6
/// GL-Sync signal type is 1080I
#define ADL_GLSYNC_SIGNALTYPE_1080I          7
/// GL-Sync signal type is SDI
#define ADL_GLSYNC_SIGNALTYPE_SDI            8
/// GL-Sync signal type is TTL
#define ADL_GLSYNC_SIGNALTYPE_TTL            9
/// GL_Sync signal type is Analog
#define ADL_GLSYNC_SIGNALTYPE_ANALOG		10

// GL-Sync Sync Field options (unique values)

///GL-Sync sync field option is undefined
#define ADL_GLSYNC_SYNCFIELD_UNDEFINED		0
///GL-Sync sync field option is Sync to Field 1 (used for Interlaced signal types)
#define ADL_GLSYNC_SYNCFIELD_BOTH			1
///GL-Sync sync field option is Sync to Both fields (used for Interlaced signal types)
#define ADL_GLSYNC_SYNCFIELD_1				2


// GL-Sync trigger edge options (unique values)

/// GL-Sync trigger edge is undefined
#define ADL_GLSYNC_TRIGGEREDGE_UNDEFINED     0
/// GL-Sync trigger edge is the rising edge
#define ADL_GLSYNC_TRIGGEREDGE_RISING        1
/// GL-Sync trigger edge is the falling edge
#define ADL_GLSYNC_TRIGGEREDGE_FALLING       2
/// GL-Sync trigger edge is both the rising and the falling edge
#define ADL_GLSYNC_TRIGGEREDGE_BOTH          3


// GL-Sync scan rate coefficient/multiplier options (unique values)

/// GL-Sync scan rate coefficient/multiplier is undefined
#define ADL_GLSYNC_SCANRATECOEFF_UNDEFINED   0
/// GL-Sync scan rate coefficient/multiplier is 5
#define ADL_GLSYNC_SCANRATECOEFF_x5          1
/// GL-Sync scan rate coefficient/multiplier is 4
#define ADL_GLSYNC_SCANRATECOEFF_x4          2
/// GL-Sync scan rate coefficient/multiplier is 3
#define ADL_GLSYNC_SCANRATECOEFF_x3          3
/// GL-Sync scan rate coefficient/multiplier is 5:2 (SMPTE)
#define ADL_GLSYNC_SCANRATECOEFF_x5_DIV_2    4
/// GL-Sync scan rate coefficient/multiplier is 2
#define ADL_GLSYNC_SCANRATECOEFF_x2          5
/// GL-Sync scan rate coefficient/multiplier is 3 : 2
#define ADL_GLSYNC_SCANRATECOEFF_x3_DIV_2    6
/// GL-Sync scan rate coefficient/multiplier is 5 : 4
#define ADL_GLSYNC_SCANRATECOEFF_x5_DIV_4    7
/// GL-Sync scan rate coefficient/multiplier is 1 (default)
#define ADL_GLSYNC_SCANRATECOEFF_x1          8
/// GL-Sync scan rate coefficient/multiplier is 4 : 5
#define ADL_GLSYNC_SCANRATECOEFF_x4_DIV_5    9
/// GL-Sync scan rate coefficient/multiplier is 2 : 3
#define ADL_GLSYNC_SCANRATECOEFF_x2_DIV_3    10
/// GL-Sync scan rate coefficient/multiplier is 1 : 2
#define ADL_GLSYNC_SCANRATECOEFF_x1_DIV_2    11
/// GL-Sync scan rate coefficient/multiplier is 2 : 5 (SMPTE)
#define ADL_GLSYNC_SCANRATECOEFF_x2_DIV_5    12
/// GL-Sync scan rate coefficient/multiplier is 1 : 3
#define ADL_GLSYNC_SCANRATECOEFF_x1_DIV_3    13
/// GL-Sync scan rate coefficient/multiplier is 1 : 4
#define ADL_GLSYNC_SCANRATECOEFF_x1_DIV_4    14
/// GL-Sync scan rate coefficient/multiplier is 1 : 5
#define ADL_GLSYNC_SCANRATECOEFF_x1_DIV_5    15


// GL-Sync port (signal presence) states (unique values)

/// GL-Sync port state is undefined
#define ADL_GLSYNC_PORTSTATE_UNDEFINED       0
/// GL-Sync port is not connected
#define ADL_GLSYNC_PORTSTATE_NOCABLE         1
/// GL-Sync port is Idle
#define ADL_GLSYNC_PORTSTATE_IDLE            2
/// GL-Sync port has an Input signal
#define ADL_GLSYNC_PORTSTATE_INPUT           3
/// GL-Sync port is Output
#define ADL_GLSYNC_PORTSTATE_OUTPUT          4


// GL-Sync LED types (used index within ADL_Workstation_GLSyncPortState_Get returned ppGlSyncLEDs array) (unique values)

/// Index into the ADL_Workstation_GLSyncPortState_Get returned ppGlSyncLEDs array for the one LED of the BNC port
#define ADL_GLSYNC_LEDTYPE_BNC               0
/// Index into the ADL_Workstation_GLSyncPortState_Get returned ppGlSyncLEDs array for the Left LED of the RJ45(1) or RJ45(2) port
#define ADL_GLSYNC_LEDTYPE_RJ45_LEFT         0
/// Index into the ADL_Workstation_GLSyncPortState_Get returned ppGlSyncLEDs array for the Right LED of the RJ45(1) or RJ45(2) port
#define ADL_GLSYNC_LEDTYPE_RJ45_RIGHT        1


// GL-Sync LED colors (unique values)

/// GL-Sync LED undefined color
#define ADL_GLSYNC_LEDCOLOR_UNDEFINED        0
/// GL-Sync LED is unlit
#define ADL_GLSYNC_LEDCOLOR_NOLIGHT          1
/// GL-Sync LED is yellow
#define ADL_GLSYNC_LEDCOLOR_YELLOW           2
/// GL-Sync LED is red
#define ADL_GLSYNC_LEDCOLOR_RED              3
/// GL-Sync LED is green
#define ADL_GLSYNC_LEDCOLOR_GREEN            4
/// GL-Sync LED is flashing green
#define ADL_GLSYNC_LEDCOLOR_FLASH_GREEN      5


// GL-Sync Port Control (refers one GL-Sync Port) (unique values)

/// Used to configure the RJ54(1) or RJ42(2) port of GL-Sync is as Idle
#define ADL_GLSYNC_PORTCNTL_NONE             0x00000000
/// Used to configure the RJ54(1) or RJ42(2) port of GL-Sync is as Output
#define ADL_GLSYNC_PORTCNTL_OUTPUT           0x00000001


// GL-Sync Mode Control (refers one Display/Controller) (bitfields)

/// Used to configure the display to use internal timing (not genlocked)
#define ADL_GLSYNC_MODECNTL_NONE             0x00000000
/// Bitfield used to configure the display as genlocked (either as Timing Client or as Timing Server)
#define ADL_GLSYNC_MODECNTL_GENLOCK          0x00000001
/// Bitfield used to configure the display as Timing Server
#define ADL_GLSYNC_MODECNTL_TIMINGSERVER     0x00000002

// GL-Sync Mode Status
/// Display is currently not genlocked
#define ADL_GLSYNC_MODECNTL_STATUS_NONE		 0x00000000
/// Display is currently genlocked
#define ADL_GLSYNC_MODECNTL_STATUS_GENLOCK   0x00000001
/// Display requires a mode switch
#define ADL_GLSYNC_MODECNTL_STATUS_SETMODE_REQUIRED 0x00000002
/// Display is capable of being genlocked
#define ADL_GLSYNC_MODECNTL_STATUS_GENLOCK_ALLOWED 0x00000004

#define ADL_MAX_GLSYNC_PORTS							8
#define ADL_MAX_GLSYNC_PORT_LEDS						8

// @}

/// \defgroup define_crossfirestate CrossfireX state of a particular adapter CrossfireX combination
// @{
#define ADL_XFIREX_STATE_NOINTERCONNECT			( 1 << 0 )	/* Dongle / cable is missing */
#define ADL_XFIREX_STATE_DOWNGRADEPIPES			( 1 << 1 )	/* CrossfireX can be enabled if pipes are downgraded */
#define ADL_XFIREX_STATE_DOWNGRADEMEM			( 1 << 2 )	/* CrossfireX cannot be enabled unless mem downgraded */
#define ADL_XFIREX_STATE_REVERSERECOMMENDED		( 1 << 3 )	/* Card reversal recommended, CrossfireX cannot be enabled. */
#define ADL_XFIREX_STATE_3DACTIVE			( 1 << 4 )	/* 3D client is active - CrossfireX cannot be safely enabled */
#define ADL_XFIREX_STATE_MASTERONSLAVE			( 1 << 5 )	/* Dongle is OK but master is on slave */
#define ADL_XFIREX_STATE_NODISPLAYCONNECT		( 1 << 6 )	/* No (valid) display connected to master card. */
#define ADL_XFIREX_STATE_NOPRIMARYVIEW			( 1 << 7 )	/* CrossfireX is enabled but master is not current primary device */
#define ADL_XFIREX_STATE_DOWNGRADEVISMEM		( 1 << 8 )	/* CrossfireX cannot be enabled unless visible mem downgraded */
#define ADL_XFIREX_STATE_LESSTHAN8LANE_MASTER		( 1 << 9 ) 	/* CrossfireX can be enabled however performance not optimal due to <8 lanes */
#define ADL_XFIREX_STATE_LESSTHAN8LANE_SLAVE		( 1 << 10 )	/* CrossfireX can be enabled however performance not optimal due to <8 lanes */
#define ADL_XFIREX_STATE_PEERTOPEERFAILED		( 1 << 11 )	/* CrossfireX cannot be enabled due to failed peer to peer test */
#define ADL_XFIREX_STATE_MEMISDOWNGRADED		( 1 << 16 )	/* Notification that memory is currently downgraded */
#define ADL_XFIREX_STATE_PIPESDOWNGRADED		( 1 << 17 )	/* Notification that pipes are currently downgraded */
#define ADL_XFIREX_STATE_XFIREXACTIVE			( 1 << 18 )	/* CrossfireX is enabled on current device */
#define ADL_XFIREX_STATE_VISMEMISDOWNGRADED		( 1 << 19 )	/* Notification that visible FB memory is currently downgraded */
#define ADL_XFIREX_STATE_INVALIDINTERCONNECTION		( 1 << 20 )	/* Cannot support current inter-connection configuration */
#define ADL_XFIREX_STATE_NONP2PMODE			( 1 << 21 )	/* CrossfireX will only work with clients supporting non P2P mode */
#define ADL_XFIREX_STATE_DOWNGRADEMEMBANKS		( 1 << 22 )	/* CrossfireX cannot be enabled unless memory banks downgraded */
#define ADL_XFIREX_STATE_MEMBANKSDOWNGRADED		( 1 << 23 )	/* Notification that memory banks are currently downgraded */
#define ADL_XFIREX_STATE_DUALDISPLAYSALLOWED		( 1 << 24 )	/* Extended desktop or clone mode is allowed. */
#define ADL_XFIREX_STATE_P2P_APERTURE_MAPPING		( 1 << 25 )	/* P2P mapping was through peer aperture */
#define ADL_XFIREX_STATE_P2PFLUSH_REQUIRED		ADL_XFIREX_STATE_P2P_APERTURE_MAPPING	/* For back compatible */
#define ADL_XFIREX_STATE_XSP_CONNECTED			( 1 << 26 )	/* There is CrossfireX side port connection between GPUs */
#define ADL_XFIREX_STATE_ENABLE_CF_REBOOT_REQUIRED	( 1 << 27 )	/* System needs a reboot bofore enable CrossfireX */
#define ADL_XFIREX_STATE_DISABLE_CF_REBOOT_REQUIRED	( 1 << 28 )	/* System needs a reboot after disable CrossfireX */
#define ADL_XFIREX_STATE_DRV_HANDLE_DOWNGRADE_KEY	( 1 << 29 )	/* Indicate base driver handles the downgrade key updating */
#define ADL_XFIREX_STATE_CF_RECONFIG_REQUIRED		( 1 << 30 )	/* CrossfireX need to be reconfigured by CCC because of a LDA chain broken */
#define ADL_XFIREX_STATE_ERRORGETTINGSTATUS		( 1 << 31 )	/* Could not obtain current status */
// @}

///////////////////////////////////////////////////////////////////////////
// ADL_DISPLAY_ADJUSTMENT_PIXELFORMAT adjustment values
// (bit-vector)
///////////////////////////////////////////////////////////////////////////
/// \defgroup define_pixel_formats Pixel Formats values
/// This group defines the various Pixel Formats that a particular digital display can support. \n
/// Since a display can support multiple formats, these values can be bit-or'ed to indicate the various formats \n
// @{
#define ADL_DISPLAY_PIXELFORMAT_UNKNOWN             0
#define ADL_DISPLAY_PIXELFORMAT_RGB                       (1 << 0)
#define ADL_DISPLAY_PIXELFORMAT_YCRCB444                  (1 << 1)    //Limited range
#define ADL_DISPLAY_PIXELFORMAT_YCRCB422                 (1 << 2)    //Limited range
#define ADL_DISPLAY_PIXELFORMAT_RGB_LIMITED_RANGE      (1 << 3)
#define ADL_DISPLAY_PIXELFORMAT_RGB_FULL_RANGE    ADL_DISPLAY_PIXELFORMAT_RGB  //Full range
// @}

/// \defgroup define_contype Connector Type Values
/// ADLDisplayConfig.ulConnectorType defines
// @{
#define ADL_DL_DISPLAYCONFIG_CONTYPE_UNKNOWN      0
#define ADL_DL_DISPLAYCONFIG_CONTYPE_CV_NONI2C_JP 1
#define ADL_DL_DISPLAYCONFIG_CONTYPE_CV_JPN       2
#define ADL_DL_DISPLAYCONFIG_CONTYPE_CV_NA        3
#define ADL_DL_DISPLAYCONFIG_CONTYPE_CV_NONI2C_NA 4
#define ADL_DL_DISPLAYCONFIG_CONTYPE_VGA          5
#define ADL_DL_DISPLAYCONFIG_CONTYPE_DVI_D        6
#define ADL_DL_DISPLAYCONFIG_CONTYPE_DVI_I        7
#define ADL_DL_DISPLAYCONFIG_CONTYPE_HDMI_TYPE_A  8
#define ADL_DL_DISPLAYCONFIG_CONTYPE_HDMI_TYPE_B  9
#define ADL_DL_DISPLAYCONFIG_CONTYPE_DISPLAYPORT  10
// @}

///////////////////////////////////////////////////////////////////////////
// ADL_DISPLAY_DISPLAYINFO_ Definitions
// for ADLDisplayInfo.iDisplayInfoMask and ADLDisplayInfo.iDisplayInfoValue
// (bit-vector)
///////////////////////////////////////////////////////////////////////////
/// \defgroup define_displayinfomask Display Info Mask Values
// @{
#define ADL_DISPLAY_DISPLAYINFO_DISPLAYCONNECTED			0x00000001
#define ADL_DISPLAY_DISPLAYINFO_DISPLAYMAPPED				0x00000002
#define ADL_DISPLAY_DISPLAYINFO_NONLOCAL					0x00000004
#define ADL_DISPLAY_DISPLAYINFO_FORCIBLESUPPORTED			0x00000008
#define ADL_DISPLAY_DISPLAYINFO_GENLOCKSUPPORTED			0x00000010
#define ADL_DISPLAY_DISPLAYINFO_MULTIVPU_SUPPORTED			0x00000020
#define ADL_DISPLAY_DISPLAYINFO_LDA_DISPLAY					0x00000040
#define ADL_DISPLAY_DISPLAYINFO_MODETIMING_OVERRIDESSUPPORTED			0x00000080

#define ADL_DISPLAY_DISPLAYINFO_MANNER_SUPPORTED_SINGLE			0x00000100
#define ADL_DISPLAY_DISPLAYINFO_MANNER_SUPPORTED_CLONE			0x00000200

/// Legacy support for XP
#define ADL_DISPLAY_DISPLAYINFO_MANNER_SUPPORTED_2VSTRETCH		0x00000400
#define ADL_DISPLAY_DISPLAYINFO_MANNER_SUPPORTED_2HSTRETCH		0x00000800
#define ADL_DISPLAY_DISPLAYINFO_MANNER_SUPPORTED_EXTENDED		0x00001000

/// More support manners
#define ADL_DISPLAY_DISPLAYINFO_MANNER_SUPPORTED_NSTRETCH1GPU	0x00010000
#define ADL_DISPLAY_DISPLAYINFO_MANNER_SUPPORTED_NSTRETCHNGPU	0x00020000
#define ADL_DISPLAY_DISPLAYINFO_MANNER_SUPPORTED_RESERVED2		0x00040000
#define ADL_DISPLAY_DISPLAYINFO_MANNER_SUPPORTED_RESERVED3		0x00080000

/// Projector display type
#define ADL_DISPLAY_DISPLAYINFO_SHOWTYPE_PROJECTOR				0x00100000

// @}


///////////////////////////////////////////////////////////////////////////
// ADL_ADAPTER_DISPLAY_MANNER_SUPPORTED_ Definitions
// for ADLAdapterDisplayCap of ADL_Adapter_Display_Cap()
// (bit-vector)
///////////////////////////////////////////////////////////////////////////
/// \defgroup define_adaptermanner Adapter Manner Support Values
// @{
#define ADL_ADAPTER_DISPLAYCAP_MANNER_SUPPORTED_NOTACTIVE		0x00000001
#define ADL_ADAPTER_DISPLAYCAP_MANNER_SUPPORTED_SINGLE			0x00000002
#define ADL_ADAPTER_DISPLAYCAP_MANNER_SUPPORTED_CLONE			0x00000004
#define ADL_ADAPTER_DISPLAYCAP_MANNER_SUPPORTED_NSTRETCH1GPU	0x00000008
#define ADL_ADAPTER_DISPLAYCAP_MANNER_SUPPORTED_NSTRETCHNGPU	0x00000010

/// Legacy support for XP
#define ADL_ADAPTER_DISPLAYCAP_MANNER_SUPPORTED_2VSTRETCH		0x00000020
#define ADL_ADAPTER_DISPLAYCAP_MANNER_SUPPORTED_2HSTRETCH		0x00000040
#define ADL_ADAPTER_DISPLAYCAP_MANNER_SUPPORTED_EXTENDED		0x00000080

#define ADL_ADAPTER_DISPLAYCAP_PREFERDISPLAY_SUPPORTED			0x00000100
#define ADL_ADAPTER_DISPLAYCAP_BEZEL_SUPPORTED					0x00000200


///////////////////////////////////////////////////////////////////////////
// ADL_DISPLAY_DISPLAYMAP_MANNER_ Definitions
// for ADLDisplayMap.iDisplayMapMask and ADLDisplayMap.iDisplayMapValue
// (bit-vector)
///////////////////////////////////////////////////////////////////////////
#define ADL_DISPLAY_DISPLAYMAP_MANNER_RESERVED			0x00000001
#define ADL_DISPLAY_DISPLAYMAP_MANNER_NOTACTIVE			0x00000002
#define ADL_DISPLAY_DISPLAYMAP_MANNER_SINGLE			0x00000004
#define ADL_DISPLAY_DISPLAYMAP_MANNER_CLONE				0x00000008
#define ADL_DISPLAY_DISPLAYMAP_MANNER_RESERVED1			0x00000010  // Removed NSTRETCH
#define ADL_DISPLAY_DISPLAYMAP_MANNER_HSTRETCH			0x00000020
#define ADL_DISPLAY_DISPLAYMAP_MANNER_VSTRETCH			0x00000040
#define ADL_DISPLAY_DISPLAYMAP_MANNER_VLD				0x00000080

// @}

///////////////////////////////////////////////////////////////////////////
// ADL_DISPLAY_DISPLAYMAP_OPTION_ Definitions
// for iOption in function ADL_Display_DisplayMapConfig_Get
// (bit-vector)
///////////////////////////////////////////////////////////////////////////
#define ADL_DISPLAY_DISPLAYMAP_OPTION_GPUINFO			0x00000001

///////////////////////////////////////////////////////////////////////////
// ADL_DISPLAY_DISPLAYTARGET_ Definitions
// for ADLDisplayTarget.iDisplayTargetMask and ADLDisplayTarget.iDisplayTargetValue
// (bit-vector)
///////////////////////////////////////////////////////////////////////////
#define ADL_DISPLAY_DISPLAYTARGET_PREFERRED			0x00000001

///////////////////////////////////////////////////////////////////////////
// ADL_DISPLAY_POSSIBLEMAPRESULT_VALID Definitions
// for ADLPossibleMapResult.iPossibleMapResultMask and ADLPossibleMapResult.iPossibleMapResultValue
// (bit-vector)
///////////////////////////////////////////////////////////////////////////
#define ADL_DISPLAY_POSSIBLEMAPRESULT_VALID				0x00000001
#define ADL_DISPLAY_POSSIBLEMAPRESULT_BEZELSUPPORTED	0x00000002
#define ADL_DISPLAY_POSSIBLEMAPRESULT_OVERLAPSUPPORTED	0x00000004

///////////////////////////////////////////////////////////////////////////
// ADL_DISPLAY_MODE_ Definitions
// for ADLMode.iModeMask, ADLMode.iModeValue, and ADLMode.iModeFlag
// (bit-vector)
///////////////////////////////////////////////////////////////////////////
/// \defgroup define_displaymode Display Mode Values
// @{
#define ADL_DISPLAY_MODE_COLOURFORMAT_565				0x00000001
#define ADL_DISPLAY_MODE_COLOURFORMAT_8888				0x00000002
#define ADL_DISPLAY_MODE_ORIENTATION_SUPPORTED_000		0x00000004
#define ADL_DISPLAY_MODE_ORIENTATION_SUPPORTED_090		0x00000008
#define ADL_DISPLAY_MODE_ORIENTATION_SUPPORTED_180		0x00000010
#define ADL_DISPLAY_MODE_ORIENTATION_SUPPORTED_270		0x00000020
#define ADL_DISPLAY_MODE_REFRESHRATE_ROUNDED			0x00000040
#define ADL_DISPLAY_MODE_REFRESHRATE_ONLY				0x00000080

#define ADL_DISPLAY_MODE_PROGRESSIVE_FLAG	0
#define ADL_DISPLAY_MODE_INTERLACED_FLAG	2
// @}

///////////////////////////////////////////////////////////////////////////
// ADL_OSMODEINFO Definitions
///////////////////////////////////////////////////////////////////////////
/// \defgroup define_osmode OS Mode Values
// @{
#define ADL_OSMODEINFOXPOS_DEFAULT				-640
#define ADL_OSMODEINFOYPOS_DEFAULT				0
#define ADL_OSMODEINFOXRES_DEFAULT				640
#define ADL_OSMODEINFOYRES_DEFAULT				480
#define ADL_OSMODEINFOXRES_DEFAULT800			800
#define ADL_OSMODEINFOYRES_DEFAULT600			600
#define ADL_OSMODEINFOREFRESHRATE_DEFAULT		60
#define ADL_OSMODEINFOCOLOURDEPTH_DEFAULT		8
#define ADL_OSMODEINFOCOLOURDEPTH_DEFAULT16		16
#define ADL_OSMODEINFOCOLOURDEPTH_DEFAULT24		24
#define ADL_OSMODEINFOCOLOURDEPTH_DEFAULT32		32
#define ADL_OSMODEINFOORIENTATION_DEFAULT		0
#define ADL_OSMODEINFOORIENTATION_DEFAULT_WIN7	DISPLAYCONFIG_ROTATION_FORCE_UINT32
#define ADL_OSMODEFLAG_DEFAULT					0
// @}


///////////////////////////////////////////////////////////////////////////
// ADLThreadingModel Enumeration
///////////////////////////////////////////////////////////////////////////
/// \defgroup thread_model
/// Used with \ref ADL_Main_ControlX2_Create and \ref ADL2_Main_ControlX2_Create to specify how ADL handles API calls when executed by multiple threads concurrently.
/// \brief Declares ADL threading behavior.
// @{
typedef enum ADLThreadingModel
{
    ADL_THREADING_UNLOCKED    = 0, /*!< Default behavior. ADL will not enforce serialization of ADL API executions by multiple threads.  Multiple threads will be allowed to enter to ADL at the same time. Note that ADL library is not guaranteed to be thread-safe. Client that calls ADL_Main_Control_Create have to provide its own mechanism for ADL calls serialization. */
    ADL_THREADING_LOCKED     /*!< ADL will enforce serialization of ADL API when called by multiple threads.  Only single thread will be allowed to enter ADL API at the time. This option makes ADL calls thread-safe. You shouldn't use this option if ADL calls will be executed on Linux on x-server rendering thread. It can cause the application to hung.  */
}ADLThreadingModel;

// @}
///////////////////////////////////////////////////////////////////////////
// ADLPurposeCode Enumeration
///////////////////////////////////////////////////////////////////////////
enum ADLPurposeCode
{
	ADL_PURPOSECODE_NORMAL	= 0,
	ADL_PURPOSECODE_HIDE_MODE_SWITCH,
	ADL_PURPOSECODE_MODE_SWITCH,
	ADL_PURPOSECODE_ATTATCH_DEVICE,
	ADL_PURPOSECODE_DETACH_DEVICE,
	ADL_PURPOSECODE_SETPRIMARY_DEVICE,
	ADL_PURPOSECODE_GDI_ROTATION,
	ADL_PURPOSECODE_ATI_ROTATION
};
///////////////////////////////////////////////////////////////////////////
// ADLAngle Enumeration
///////////////////////////////////////////////////////////////////////////
enum ADLAngle
{
    ADL_ANGLE_LANDSCAPE = 0,
    ADL_ANGLE_ROTATERIGHT = 90,
    ADL_ANGLE_ROTATE180 = 180,
    ADL_ANGLE_ROTATELEFT = 270,
};

///////////////////////////////////////////////////////////////////////////
// ADLOrientationDataType Enumeration
///////////////////////////////////////////////////////////////////////////
enum ADLOrientationDataType
{
	ADL_ORIENTATIONTYPE_OSDATATYPE,
	ADL_ORIENTATIONTYPE_NONOSDATATYPE
};

///////////////////////////////////////////////////////////////////////////
// ADLPanningMode Enumeration
///////////////////////////////////////////////////////////////////////////
enum ADLPanningMode
{
	ADL_PANNINGMODE_NO_PANNING = 0,
	ADL_PANNINGMODE_AT_LEAST_ONE_NO_PANNING = 1,
	ADL_PANNINGMODE_ALLOW_PANNING = 2,
};

///////////////////////////////////////////////////////////////////////////
// ADLLARGEDESKTOPTYPE Enumeration
///////////////////////////////////////////////////////////////////////////
enum ADLLARGEDESKTOPTYPE
{
	ADL_LARGEDESKTOPTYPE_NORMALDESKTOP = 0,
    ADL_LARGEDESKTOPTYPE_PSEUDOLARGEDESKTOP = 1,
    ADL_LARGEDESKTOPTYPE_VERYLARGEDESKTOP = 2
};

///////////////////////////////////////////////////////////////////////////
// ADLPlatform Enumeration
///////////////////////////////////////////////////////////////////////////
enum ADLPlatForm
{
    GRAPHICS_PLATFORM_DESKTOP  = 0,
    GRAPHICS_PLATFORM_MOBILE   = 1
};
// Other Definitions for internal use

// Values for ADL_Display_WriteAndReadI2CRev_Get()

#define ADL_I2C_MAJOR_API_REV           0x00000001
#define ADL_I2C_MINOR_DEFAULT_API_REV   0x00000000
#define ADL_I2C_MINOR_OEM_API_REV       0x00000001

// Values for ADL_Display_WriteAndReadI2C()
#define ADL_DL_I2C_LINE_OEM                0x00000001
#define ADL_DL_I2C_LINE_OD_CONTROL         0x00000002
#define ADL_DL_I2C_LINE_OEM2               0x00000003
#define ADL_DL_I2C_LINE_OEM3               0x00000004
#define ADL_DL_I2C_LINE_OEM4               0x00000005
#define ADL_DL_I2C_LINE_OEM5               0x00000006
#define ADL_DL_I2C_LINE_OEM6               0x00000007

// Max size of I2C data buffer
#define ADL_DL_I2C_MAXDATASIZE             0x00000040
#define ADL_DL_I2C_MAXWRITEDATASIZE        0x0000000C
#define ADL_DL_I2C_MAXADDRESSLENGTH        0x00000006
#define ADL_DL_I2C_MAXOFFSETLENGTH         0x00000004


/// Values for ADLDisplayProperty.iPropertyType
#define ADL_DL_DISPLAYPROPERTY_TYPE_UNKNOWN              0
#define ADL_DL_DISPLAYPROPERTY_TYPE_EXPANSIONMODE        1
#define ADL_DL_DISPLAYPROPERTY_TYPE_USEUNDERSCANSCALING	 2
/// Enables ITC processing for HDMI panels that are capable of the feature
#define ADL_DL_DISPLAYPROPERTY_TYPE_ITCFLAGENABLE        9


/// Values for ADLDisplayContent.iContentType
/// Certain HDMI panels that support ITC have support for a feature such that, the display on the panel
/// can be adjusted to optimize the view of the content being displayed, depending on the type of content.
#define ADL_DL_DISPLAYCONTENT_TYPE_GRAPHICS		1
#define ADL_DL_DISPLAYCONTENT_TYPE_PHOTO		2
#define ADL_DL_DISPLAYCONTENT_TYPE_CINEMA		4
#define ADL_DL_DISPLAYCONTENT_TYPE_GAME			8





//values for ADLDisplayProperty.iExpansionMode
#define ADL_DL_DISPLAYPROPERTY_EXPANSIONMODE_CENTER        0
#define ADL_DL_DISPLAYPROPERTY_EXPANSIONMODE_FULLSCREEN    1
#define ADL_DL_DISPLAYPROPERTY_EXPANSIONMODE_ASPECTRATIO   2

//values for ADL_Display_DitherState_Get
#define ADL_DL_DISPLAY_DITHER_UNKNOWN    0
#define ADL_DL_DISPLAY_DITHER_DISABLED   1
#define ADL_DL_DISPLAY_DITHER_ENABLED    2

/// Display Get Cached EDID flag
#define ADL_MAX_EDIDDATA_SIZE              256 // number of UCHAR
#define ADL_MAX_OVERRIDEEDID_SIZE          512 // number of UCHAR
#define ADL_MAX_EDID_EXTENSION_BLOCKS      3

#define ADL_DL_CONTROLLER_OVERLAY_ALPHA         0
#define ADL_DL_CONTROLLER_OVERLAY_ALPHAPERPIX   1

#define ADL_DL_DISPLAY_DATA_PACKET__INFO_PACKET_RESET      0x00000000
#define ADL_DL_DISPLAY_DATA_PACKET__INFO_PACKET_SET        0x00000001
#define ADL_DL_DISPLAY_DATA_PACKET__INFO_PACKET_SCAN       0x00000002

///\defgroup define_display_packet Display Data Packet Types
// @{
#define ADL_DL_DISPLAY_DATA_PACKET__TYPE__AVI              0x00000001
#define ADL_DL_DISPLAY_DATA_PACKET__TYPE__RESERVED         0x00000002
#define ADL_DL_DISPLAY_DATA_PACKET__TYPE__VENDORINFO       0x00000004
// @}

// matrix types
#define ADL_GAMUT_MATRIX_SD         1   // SD matrix i.e. BT601
#define ADL_GAMUT_MATRIX_HD         2   // HD matrix i.e. BT709

///\defgroup define_clockinfo_flags Clock flags
/// Used by ADLAdapterODClockInfo.iFlag
// @{
#define ADL_DL_CLOCKINFO_FLAG_FULLSCREEN3DONLY         0x00000001
#define ADL_DL_CLOCKINFO_FLAG_ALWAYSFULLSCREEN3D       0x00000002
#define ADL_DL_CLOCKINFO_FLAG_VPURECOVERYREDUCED       0x00000004
#define ADL_DL_CLOCKINFO_FLAG_THERMALPROTECTION        0x00000008
// @}

// Supported GPUs
// ADL_Display_PowerXpressActiveGPU_Get()
#define ADL_DL_POWERXPRESS_GPU_INTEGRATED		1
#define ADL_DL_POWERXPRESS_GPU_DISCRETE			2

// Possible values for lpOperationResult
// ADL_Display_PowerXpressActiveGPU_Get()
#define ADL_DL_POWERXPRESS_SWITCH_RESULT_STARTED         1 // Switch procedure has been started - Windows platform only
#define ADL_DL_POWERXPRESS_SWITCH_RESULT_DECLINED        2 // Switch procedure cannot be started - All platforms
#define ADL_DL_POWERXPRESS_SWITCH_RESULT_ALREADY         3 // System already has required status  - All platforms
#define ADL_DL_POWERXPRESS_SWITCH_RESULT_DEFERRED        5  // Switch was deferred and requires an X restart - Linux platform only

// PowerXpress support version
// ADL_Display_PowerXpressVersion_Get()
#define ADL_DL_POWERXPRESS_VERSION_MAJOR			2	// Current PowerXpress support version 2.0
#define ADL_DL_POWERXPRESS_VERSION_MINOR			0

#define ADL_DL_POWERXPRESS_VERSION	(((ADL_DL_POWERXPRESS_VERSION_MAJOR) << 16) | ADL_DL_POWERXPRESS_VERSION_MINOR)

//values for ADLThermalControllerInfo.iThermalControllerDomain
#define ADL_DL_THERMAL_DOMAIN_OTHER      0
#define ADL_DL_THERMAL_DOMAIN_GPU        1

//values for ADLThermalControllerInfo.iFlags
#define ADL_DL_THERMAL_FLAG_INTERRUPT    1
#define ADL_DL_THERMAL_FLAG_FANCONTROL   2

///\defgroup define_fanctrl Fan speed cotrol
/// Values for ADLFanSpeedInfo.iFlags
// @{
#define ADL_DL_FANCTRL_SUPPORTS_PERCENT_READ     1
#define ADL_DL_FANCTRL_SUPPORTS_PERCENT_WRITE    2
#define ADL_DL_FANCTRL_SUPPORTS_RPM_READ         4
#define ADL_DL_FANCTRL_SUPPORTS_RPM_WRITE        8
// @}

//values for ADLFanSpeedValue.iSpeedType
#define ADL_DL_FANCTRL_SPEED_TYPE_PERCENT    1
#define ADL_DL_FANCTRL_SPEED_TYPE_RPM        2

//values for ADLFanSpeedValue.iFlags
#define ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED   1

// MVPU interfaces
#define ADL_DL_MAX_MVPU_ADAPTERS   4
#define MVPU_ADAPTER_0	      0x00000001
#define MVPU_ADAPTER_1		  0x00000002
#define MVPU_ADAPTER_2		  0x00000004
#define MVPU_ADAPTER_3		  0x00000008
#define ADL_DL_MAX_REGISTRY_PATH   256

//values for ADLMVPUStatus.iStatus
#define ADL_DL_MVPU_STATUS_OFF   0
#define ADL_DL_MVPU_STATUS_ON    1

// values for ASIC family
///\defgroup define_Asic_type Detailed asic types
/// Defines for Adapter ASIC family type
// @{
#define ADL_ASIC_UNDEFINED	0
#define ADL_ASIC_DISCRETE	(1 << 0)
#define ADL_ASIC_INTEGRATED	(1 << 1)
#define ADL_ASIC_FIREGL		(1 << 2)
#define ADL_ASIC_FIREMV		(1 << 3)
#define ADL_ASIC_XGP		(1 << 4)
#define ADL_ASIC_FUSION		(1 << 5)
#define ADL_ASIC_FIRESTREAM (1 << 6)
// @}

///\defgroup define_detailed_timing_flags Detailed Timimg Flags
/// Defines for ADLDetailedTiming.sTimingFlags field
// @{
#define ADL_DL_TIMINGFLAG_DOUBLE_SCAN              0x0001
//sTimingFlags is set when the mode is INTERLACED, if not PROGRESSIVE
#define ADL_DL_TIMINGFLAG_INTERLACED               0x0002
//sTimingFlags is set when the Horizontal Sync is POSITIVE, if not NEGATIVE
#define ADL_DL_TIMINGFLAG_H_SYNC_POLARITY          0x0004
//sTimingFlags is set when the Vertical Sync is POSITIVE, if not NEGATIVE
#define ADL_DL_TIMINGFLAG_V_SYNC_POLARITY          0x0008
// @}

///\defgroup define_modetiming_standard Timing Standards
/// Defines for ADLDisplayModeInfo.iTimingStandard field
// @{
#define ADL_DL_MODETIMING_STANDARD_CVT             0x00000001 // CVT Standard
#define ADL_DL_MODETIMING_STANDARD_GTF             0x00000002 // GFT Standard
#define ADL_DL_MODETIMING_STANDARD_DMT             0x00000004 // DMT Standard
#define ADL_DL_MODETIMING_STANDARD_CUSTOM          0x00000008 // User-defined standard
#define ADL_DL_MODETIMING_STANDARD_DRIVER_DEFAULT  0x00000010 // Remove Mode from overriden list
#define ADL_DL_MODETIMING_STANDARD_CVT_RB		   0x00000020 // CVT-RB Standard
// @}

// \defgroup define_xserverinfo driver x-server info
/// These flags are used by ADL_XServerInfo_Get()
// @

/// Xinerama is active in the x-server, Xinerama extension may report it to be active but it
/// may not be active in x-server
#define ADL_XSERVERINFO_XINERAMAACTIVE            (1<<0)

/// RandR 1.2 is supported by driver, RandR extension may report version 1.2
/// but driver may not support it
#define ADL_XSERVERINFO_RANDR12SUPPORTED          (1<<1)
// @


///\defgroup define_eyefinity_constants Eyefinity Definitions
// @{

#define ADL_CONTROLLERVECTOR_0		1	// ADL_CONTROLLERINDEX_0 = 0, (1 << ADL_CONTROLLERINDEX_0)
#define ADL_CONTROLLERVECTOR_1		2	// ADL_CONTROLLERINDEX_1 = 1, (1 << ADL_CONTROLLERINDEX_1)

#define ADL_DISPLAY_SLSGRID_ORIENTATION_000		0x00000001
#define ADL_DISPLAY_SLSGRID_ORIENTATION_090		0x00000002
#define ADL_DISPLAY_SLSGRID_ORIENTATION_180		0x00000004
#define ADL_DISPLAY_SLSGRID_ORIENTATION_270		0x00000008
#define ADL_DISPLAY_SLSGRID_CAP_OPTION_RELATIVETO_LANDSCAPE 	0x00000001
#define ADL_DISPLAY_SLSGRID_CAP_OPTION_RELATIVETO_CURRENTANGLE 	0x00000002
#define ADL_DISPLAY_SLSGRID_PORTAIT_MODE 						0x00000004


#define ADL_DISPLAY_SLSMAPCONFIG_GET_OPTION_RELATIVETO_LANDSCAPE 		0x00000001
#define ADL_DISPLAY_SLSMAPCONFIG_GET_OPTION_RELATIVETO_CURRENTANGLE 	0x00000002

#define ADL_DISPLAY_SLSMAPCONFIG_CREATE_OPTION_RELATIVETO_LANDSCAPE 		0x00000001
#define ADL_DISPLAY_SLSMAPCONFIG_CREATE_OPTION_RELATIVETO_CURRENTANGLE 	0x00000002

#define ADL_DISPLAY_SLSMAPCONFIG_REARRANGE_OPTION_RELATIVETO_LANDSCAPE 	0x00000001
#define ADL_DISPLAY_SLSMAPCONFIG_REARRANGE_OPTION_RELATIVETO_CURRENTANGLE 	0x00000002


#define ADL_DISPLAY_SLSGRID_RELATIVETO_LANDSCAPE 		0x00000010
#define ADL_DISPLAY_SLSGRID_RELATIVETO_CURRENTANGLE 	0x00000020


/// The bit mask identifies displays is currently in bezel mode.
#define ADL_DISPLAY_SLSMAP_BEZELMODE			0x00000010
/// The bit mask identifies displays from this map is arranged.
#define ADL_DISPLAY_SLSMAP_DISPLAYARRANGED		0x00000002
/// The bit mask identifies this map is currently in used for the current adapter.
#define ADL_DISPLAY_SLSMAP_CURRENTCONFIG		0x00000004

 ///For onlay active SLS  map info
#define ADL_DISPLAY_SLSMAPINDEXLIST_OPTION_ACTIVE		0x00000001

///For Bezel
#define ADL_DISPLAY_BEZELOFFSET_STEPBYSTEPSET			0x00000004
#define ADL_DISPLAY_BEZELOFFSET_COMMIT					0x00000008

// @}

///\defgroup define_powerxpress_constants PowerXpress Definitions
// @{

/// The bit mask identifies PX caps for ADLPXConfigCaps.iPXConfigCapMask and ADLPXConfigCaps.iPXConfigCapValue
#define	ADL_PX_CONFIGCAPS_SPLASHSCREEN_SUPPORT		0x0001
#define	ADL_PX_CONFIGCAPS_CF_SUPPORT				0x0002
#define	ADL_PX_CONFIGCAPS_MUXLESS					0x0004
#define	ADL_PX_CONFIGCAPS_PROFILE_COMPLIANT			0x0008
#define	ADL_PX_CONFIGCAPS_NON_AMD_DRIVEN_DISPLAYS	0x0010
#define ADL_PX_CONFIGCAPS_FIXED_SUPPORT             0x0020
#define ADL_PX_CONFIGCAPS_DYNAMIC_SUPPORT           0x0040
#define ADL_PX_CONFIGCAPS_HIDE_AUTO_SWITCH			0x0080

/// The bit mask identifies PX schemes for ADLPXSchemeRange
#define ADL_PX_SCHEMEMASK_FIXED						0x0001
#define ADL_PX_SCHEMEMASK_DYNAMIC					0x0002

/// PX Schemes
typedef enum _ADLPXScheme
{
    ADL_PX_SCHEME_INVALID   = 0,
    ADL_PX_SCHEME_FIXED     = ADL_PX_SCHEMEMASK_FIXED,
    ADL_PX_SCHEME_DYNAMIC   = ADL_PX_SCHEMEMASK_DYNAMIC
}ADLPXScheme;

/// Just keep the old definitions for compatibility, need to be removed later
typedef enum PXScheme
{
	PX_SCHEME_INVALID   = 0,
	PX_SCHEME_FIXED     = 1,
	PX_SCHEME_DYNAMIC   = 2
} PXScheme;


// @}

///\defgroup define_appprofiles For Application Profiles
// @{

#define ADL_APP_PROFILE_FILENAME_LENGTH		64
#define ADL_APP_PROFILE_TIMESTAMP_LENGTH	32
#define ADL_APP_PROFILE_VERSION_LENGTH		32
#define ADL_APP_PROFILE_PROPERTY_LENGTH		64

enum ApplicationListType
{
	ADL_PX40_MRU,
	ADL_PX40_MISSED,
	ADL_PX40_DISCRETE,
	ADL_PX40_INTEGRATED,

	ADL_PX40_TOTAL
};

typedef enum _ADLProfilePropertyType
{
	ADL_PROFILEPROPERTY_TYPE_BINARY		= 0,
	ADL_PROFILEPROPERTY_TYPE_BOOLEAN,
	ADL_PROFILEPROPERTY_TYPE_DWORD,
	ADL_PROFILEPROPERTY_TYPE_QWORD,
	ADL_PROFILEPROPERTY_TYPE_ENUMERATED,
	ADL_PROFILEPROPERTY_TYPE_STRING
}ADLProfilePropertyType;


// @}

///\defgroup define_dp12 For Display Port 1.2
// @{

/// Maximum Relative Address Link
#define ADL_MAX_RAD_LINK_COUNT	15

// @}

///\defgroup defines_gamutspace Driver Supported Gamut Space
// @{

/// The flags desribes that gamut is related to source or to destination and to overlay or to graphics
#define ADL_GAMUT_REFERENCE_SOURCE       (1 << 0)
#define ADL_GAMUT_GAMUT_VIDEO_CONTENT    (1 << 1)

/// The flags are used to describe the source of gamut and how read information from struct ADLGamutData
#define ADL_CUSTOM_WHITE_POINT           (1 << 0)
#define ADL_CUSTOM_GAMUT                 (1 << 1)

/// The define means the predefined gamut values  .
///Driver uses to find entry in the table and apply appropriate gamut space.
#define ADL_GAMUT_SPACE_CCIR_709     (1 << 0)
#define ADL_GAMUT_SPACE_CCIR_601     (1 << 1)
#define ADL_GAMUT_SPACE_ADOBE_RGB    (1 << 2)
#define ADL_GAMUT_SPACE_CIE_RGB      (1 << 3)
#define ADL_GAMUT_SPACE_CUSTOM       (1 << 4)

/// Predefine white point values are structed similar to gamut .
#define ADL_WHITE_POINT_5000K       (1 << 0)
#define ADL_WHITE_POINT_6500K       (1 << 1)
#define ADL_WHITE_POINT_7500K       (1 << 2)
#define ADL_WHITE_POINT_9300K       (1 << 3)
#define ADL_WHITE_POINT_CUSTOM      (1 << 4)

///gamut and white point coordinates are from 0.0 -1.0 and divider is used to find the real value .
/// X float = X int /divider
#define ADL_GAMUT_WHITEPOINT_DIVIDER           10000

///gamma a0 coefficient uses the following divider:
#define ADL_REGAMMA_COEFFICIENT_A0_DIVIDER       10000000
///gamma a1 ,a2,a3 coefficients use the following divider:
#define ADL_REGAMMA_COEFFICIENT_A1A2A3_DIVIDER   1000

///describes whether the coefficients are from EDID or custom user values.
#define ADL_EDID_REGAMMA_COEFFICIENTS          (1 << 0)
///Used for struct ADLRegamma. Feature if set use gamma ramp, if missing use regamma coefficents
#define ADL_USE_GAMMA_RAMP                     (1 << 4)
///Used for struct ADLRegamma. If the gamma ramp flag is used then the driver could apply de gamma corretion to the supplied curve and this depends on this flag
#define ADL_APPLY_DEGAMMA                      (1 << 5)

// @}

/// \defgroup define_ddcinfo_pixelformats DDCInfo Pixel Formats
// @{
/// defines for iPanelPixelFormat  in struct ADLDDCInfo2
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_RGB656                       0x00000001L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_RGB666                       0x00000002L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_RGB888                       0x00000004L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_RGB101010                    0x00000008L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_RGB161616                    0x00000010L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_RGB_RESERVED1                0x00000020L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_RGB_RESERVED2                0x00000040L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_RGB_RESERVED3                0x00000080L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_XRGB_BIAS101010              0x00000100L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_YCBCR444_8BPCC               0x00000200L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_YCBCR444_10BPCC              0x00000400L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_YCBCR444_12BPCC              0x00000800L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_YCBCR422_8BPCC               0x00001000L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_YCBCR422_10BPCC              0x00002000L
#define ADL_DISPLAY_DDCINFO_PIXEL_FORMAT_YCBCR422_12BPCC              0x00004000L
// @}



/// \defgroup define_dbd_state Deep Bit Depth
// @{

/// defines for ADL_Workstation_DeepBitDepth_Get and  ADL_Workstation_DeepBitDepth_Set functions
// This value indicates that the deep bit depth state is forced off
#define ADL_DEEPBITDEPTH_FORCEOFF 	0
/// This value indicates that the deep bit depth state  is set to auto, the driver will automatically enable the
/// appropriate deep bit depth state depending on what connected display supports.
#define ADL_DEEPBITDEPTH_10BPP_AUTO 	1
/// This value indicates that the deep bit depth state  is forced on to 10 bits per pixel, this is regardless if the display
/// supports 10 bpp.
#define ADL_DEEPBITDEPTH_10BPP_FORCEON 	2

/// defines for ADLAdapterConfigMemory of ADL_Adapter_ConfigMemory_Get
/// If this bit is set, it indicates that the Deep Bit Depth pixel is set on the display
#define ADL_ADAPTER_CONFIGMEMORY_DBD			(1 << 0)
/// If this bit is set, it indicates that the display is rotated (90, 180 or 270)
#define ADL_ADAPTER_CONFIGMEMORY_ROTATE			(1 << 1)
/// If this bit is set, it indicates that passive stereo is set on the display
#define ADL_ADAPTER_CONFIGMEMORY_STEREO_PASSIVE	(1 << 2)
/// If this bit is set, it indicates that the active stereo is set on the display
#define ADL_ADAPTER_CONFIGMEMORY_STEREO_ACTIVE	(1 << 3)
/// If this bit is set, it indicates that the tear free vsync is set on the display
#define ADL_ADAPTER_CONFIGMEMORY_ENHANCEDVSYNC	(1 << 4)
#define ADL_ADAPTER_CONFIGMEMORY_TEARFREEVSYNC	(1 << 4)
/// @}

/// \defgroup define_adl_validmemoryrequiredfields Memory Type
/// @{

///  This group defines memory types in ADLMemoryRequired struct \n
/// Indicates that this is the visible memory
#define ADL_MEMORYREQTYPE_VISIBLE				(1 << 0)
/// Indicates that this is the invisible memory.
#define ADL_MEMORYREQTYPE_INVISIBLE				(1 << 1)
/// Indicates that this is amount of visible memory per GPU that should be reserved for all other allocations.
#define ADL_MEMORYREQTYPE_GPURESERVEDVISIBLE	(1 << 2)
/// @}

/// \defgroup define_adapter_tear_free_status
/// Used in ADL_Adapter_TEAR_FREE_Set and ADL_Adapter_TFD_Get functions to indicate the tear free
/// desktop status.
/// @{
/// Tear free desktop is enabled.
#define ADL_ADAPTER_TEAR_FREE_ON				1
/// Tear free desktop can't be enabled due to a lack of graphic adapter memory.
#define ADL_ADAPTER_TEAR_FREE_NOTENOUGHMEM		-1
/// Tear free desktop can't be enabled due to quad buffer stereo being enabled.
#define ADL_ADAPTER_TEAR_FREE_OFF_ERR_QUADBUFFERSTEREO	-2
/// Tear free desktop can't be enabled due to MGPU-SLS being enabled.
#define ADL_ADAPTER_TEAR_FREE_OFF_ERR_MGPUSLD	-3
/// Tear free desktop is disabled.
#define ADL_ADAPTER_TEAR_FREE_OFF				0
/// @}

/// \defgroup define_adapter_crossdisplay_platforminfo
/// Used in ADL_Adapter_CrossDisplayPlatformInfo_Get function to indicate the Crossdisplay platform info.
/// @{
/// CROSSDISPLAY platform.
#define ADL_CROSSDISPLAY_PLATFORM					(1 << 0)
/// CROSSDISPLAY platform for Lasso station.
#define ADL_CROSSDISPLAY_PLATFORM_LASSO				(1 << 1)
/// CROSSDISPLAY platform for docking station.
#define ADL_CROSSDISPLAY_PLATFORM_DOCKSTATION		(1 << 2)
/// @}

/// \defgroup define_adapter_crossdisplay_option
/// Used in ADL_Adapter_CrossdisplayInfoX2_Set function to indicate cross display options.
/// @{
/// Checking if 3D application is runnning. If yes, not to do switch, return ADL_OK_WAIT; otherwise do switch.
#define ADL_CROSSDISPLAY_OPTION_NONE			0
/// Force switching without checking for running 3D applications
#define ADL_CROSSDISPLAY_OPTION_FORCESWITCH		(1 << 0)
/// @}

/// \defgroup define_adapter_states Adapter Capabilities
/// These defines the capabilities supported by an adapter. It is used by \ref ADL_Adapter_ConfigureState_Get
/// @{
/// Indicates that the adapter is headless (i.e. no displays can be connected to it)
#define ADL_ADAPTERCONFIGSTATE_HEADLESS ( 1 << 2 )
/// Indicates that the adapter is configured to define the main rendering capabilities. For example, adapters
/// in Crossfire(TM) configuration, this bit would only be set on the adapter driving the display(s).
#define ADL_ADAPTERCONFIGSTATE_REQUISITE_RENDER ( 1 << 0 )
/// Indicates that the adapter is configured to be used to unload some of the rendering work for a particular
/// requisite rendering adapter. For eample, for adapters in a Crossfire configuration, this bit would be set
/// on all adapters that are currently not driving the display(s)
#define ADL_ADAPTERCONFIGSTATE_ANCILLARY_RENDER ( 1 << 1 )
/// @}

/// \defgroup define_controllermode_ulModifiers
/// These defines the detailed actions supported by set viewport. It is used by \ref ADL_Display_ViewPort_Set
/// @{
/// Indicate that the viewport set will change the view position
#define ADL_CONTROLLERMODE_CM_MODIFIER_VIEW_POSITION       0x00000001
/// Indicate that the viewport set will change the view PanLock
#define ADL_CONTROLLERMODE_CM_MODIFIER_VIEW_PANLOCK        0x00000002
/// Indicate that the viewport set will change the view size
#define ADL_CONTROLLERMODE_CM_MODIFIER_VIEW_SIZE           0x00000008
/// @}

/// \defgroup defines for Mirabilis
/// These defines are used for the Mirabilis feature
/// @{
///
/// Indicates the maximum number of audio sample rates
#define ADL_MAX_AUDIO_SAMPLE_RATE_COUNT                    16
/// @}

///////////////////////////////////////////////////////////////////////////
// ADLMultiChannelSplitStateFlag Enumeration
///////////////////////////////////////////////////////////////////////////
enum ADLMultiChannelSplitStateFlag
{
    ADLMultiChannelSplit_Unitialized = 0,
    ADLMultiChannelSplit_Disabled    = 1,
    ADLMultiChannelSplit_Enabled     = 2,
    ADLMultiChannelSplit_SaveProfile = 3
};

///////////////////////////////////////////////////////////////////////////
// ADLSampleRate Enumeration
///////////////////////////////////////////////////////////////////////////
enum ADLSampleRate
{
    ADLSampleRate_32KHz =0,
    ADLSampleRate_44P1KHz,
    ADLSampleRate_48KHz,
    ADLSampleRate_88P2KHz,
    ADLSampleRate_96KHz,
    ADLSampleRate_176P4KHz,
    ADLSampleRate_192KHz,
    ADLSampleRate_384KHz, //DP1.2
    ADLSampleRate_768KHz, //DP1.2
    ADLSampleRate_Undefined
};

/// \defgroup define_overdrive6_capabilities
/// These defines the capabilities supported by Overdrive 6. It is used by \ref ADL_Overdrive6_Capabilities_Get
// @{
/// Indicate that core (engine) clock can be changed.
#define ADL_OD6_CAPABILITY_SCLK_CUSTOMIZATION               0x00000001
/// Indicate that memory clock can be changed.
#define ADL_OD6_CAPABILITY_MCLK_CUSTOMIZATION               0x00000002
/// Indicate that graphics activity reporting is supported.
#define ADL_OD6_CAPABILITY_GPU_ACTIVITY_MONITOR             0x00000004
/// Indicate that power limit can be customized.
#define ADL_OD6_CAPABILITY_POWER_CONTROL                    0x00000008
/// Indicate that SVI2 Voltage Control is supported.
#define ADL_OD6_CAPABILITY_VOLTAGE_CONTROL                  0x00000010
/// Indicate that OD6+ percentage adjustment is supported.
#define ADL_OD6_CAPABILITY_PERCENT_ADJUSTMENT               0x00000020
/// Indicate that Thermal Limit Unlock is supported.
#define ADL_OD6_CAPABILITY_THERMAL_LIMIT_UNLOCK             0x00000040
// @}

/// \defgroup define_overdrive6_supported_states
/// These defines the power states supported by Overdrive 6. It is used by \ref ADL_Overdrive6_Capabilities_Get
// @{
/// Indicate that overdrive is supported in the performance state.  This is currently the only state supported.
#define ADL_OD6_SUPPORTEDSTATE_PERFORMANCE                  0x00000001
/// Do not use.  Reserved for future use.
#define ADL_OD6_SUPPORTEDSTATE_POWER_SAVING                 0x00000002
// @}

/// \defgroup define_overdrive6_getstateinfo
/// These defines the power states to get information about. It is used by \ref ADL_Overdrive6_StateInfo_Get
// @{
/// Get default clocks for the performance state.
#define ADL_OD6_GETSTATEINFO_DEFAULT_PERFORMANCE            0x00000001
/// Do not use.  Reserved for future use.
#define ADL_OD6_GETSTATEINFO_DEFAULT_POWER_SAVING           0x00000002
/// Get clocks for current state.  Currently this is the same as \ref ADL_OD6_GETSTATEINFO_CUSTOM_PERFORMANCE
/// since only performance state is supported.
#define ADL_OD6_GETSTATEINFO_CURRENT                        0x00000003
/// Get the modified clocks (if any) for the performance state.  If clocks were not modified
/// through Overdrive 6, then this will return the same clocks as \ref ADL_OD6_GETSTATEINFO_DEFAULT_PERFORMANCE.
#define ADL_OD6_GETSTATEINFO_CUSTOM_PERFORMANCE             0x00000004
/// Do not use.  Reserved for future use.
#define ADL_OD6_GETSTATEINFO_CUSTOM_POWER_SAVING            0x00000005
// @}

/// \defgroup define_overdrive6_getstate and define_overdrive6_getmaxclockadjust
/// These defines the power states to get information about. It is used by \ref ADL_Overdrive6_StateEx_Get and \ref ADL_Overdrive6_MaxClockAdjust_Get
// @{
/// Get default clocks for the performance state.  Only performance state is currently supported.
#define ADL_OD6_STATE_PERFORMANCE            0x00000001
// @}

/// \defgroup define_overdrive6_setstate
/// These define which power state to set customized clocks on. It is used by \ref ADL_Overdrive6_State_Set
// @{
/// Set customized clocks for the performance state.
#define ADL_OD6_SETSTATE_PERFORMANCE                        0x00000001
/// Do not use.  Reserved for future use.
#define ADL_OD6_SETSTATE_POWER_SAVING                       0x00000002
// @}

/// \defgroup define_overdrive6_thermalcontroller_caps
/// These defines the capabilities of the GPU thermal controller. It is used by \ref ADL_Overdrive6_ThermalController_Caps
// @{
/// GPU thermal controller is supported.
#define ADL_OD6_TCCAPS_THERMAL_CONTROLLER                   0x00000001
/// GPU fan speed control is supported.
#define ADL_OD6_TCCAPS_FANSPEED_CONTROL                     0x00000002
/// Fan speed percentage can be read.
#define ADL_OD6_TCCAPS_FANSPEED_PERCENT_READ                0x00000100
/// Fan speed can be set by specifying a percentage value.
#define ADL_OD6_TCCAPS_FANSPEED_PERCENT_WRITE               0x00000200
/// Fan speed RPM (revolutions-per-minute) can be read.
#define ADL_OD6_TCCAPS_FANSPEED_RPM_READ                    0x00000400
/// Fan speed can be set by specifying an RPM value.
#define ADL_OD6_TCCAPS_FANSPEED_RPM_WRITE                   0x00000800
// @}

/// \defgroup define_overdrive6_fanspeed_type
/// These defines the fan speed type being reported. It is used by \ref ADL_Overdrive6_FanSpeed_Get
// @{
/// Fan speed reported in percentage.
#define ADL_OD6_FANSPEED_TYPE_PERCENT                       0x00000001
/// Fan speed reported in RPM.
#define ADL_OD6_FANSPEED_TYPE_RPM                           0x00000002
/// Fan speed has been customized by the user, and fan is not running in automatic mode.
#define ADL_OD6_FANSPEED_USER_DEFINED                       0x00000100
// @}

/// \defgroup define_ecc_mode_states
/// These defines the ECC(Error Correction Code) state. It is used by \ref ADL_Workstation_ECC_Get,ADL_Workstation_ECC_Set
// @{
/// Error Correction is disabled.
#define ECC_MODE_OFF 0
/// Error Correction is enabled.
#define ECC_MODE_ON 2
// @}

// End Bracket for Constants and Definitions. Add new groups ABOVE this line!

// @}

#endif /* ADL_DEFINES_H_ */

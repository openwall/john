/*
 * This software is Copyright (c) 2016,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//===============================================================
//
// Contains functions for operating Ztex USB-FPGA modules.
// Based on original Ztex SDK written in java.
//
//===============================================================
#ifndef _ZTEX_H_
#define _ZTEX_H_

#include "../list.h"
#include "ztex_sn.h"

#define USB_CMD_TIMEOUT 150
#define USB_RW_TIMEOUT 500

#define ZTEX_OPEN_NUM_RETRIES 3
#define ZTEX_OPEN_RETRY_WAIT 150

// includes '\0' terminator
#define ZTEX_PRODUCT_STRING_LEN 32

#define ZTEX_IDVENDOR 0x221A
#define ZTEX_IDPRODUCT 0x0100

#define ZTEX_ENDPOINT_HS 6

// Capability index for EEPROM support.
#define CAPABILITY_EEPROM 0,0
// Capability index for FPGA configuration support.
#define CAPABILITY_FPGA 0,1
// Capability index for FLASH memory support.
#define CAPABILITY_FLASH 0,2
// Capability index for DEBUG helper support.
#define CAPABILITY_DEBUG 0,3
// Capability index for AVR XMEGA support.
#define CAPABILITY_XMEGA 0,4
// Capability index for AVR XMEGA support.
#define CAPABILITY_HS_FPGA 0,5
// Capability index for AVR XMEGA support.
#define CAPABILITY_MAC_EEPROM 0,6
// Capability index for multi FPGA support.
#define CAPABILITY_MULTI_FPGA 0,7
// Unsure if this works (not tested), looks like the right version
// would be CAPABILITY_TEMP_SENSOR 1,0 (bit 0 in byte 1)
// Capability index for Temperature sensor support
#define CAPABILITY_TEMP_SENSOR 0,8
// Capability index for 2nd FLASH memory support
#define CAPABILITY_FLASH2 0,9


extern int ZTEX_DEBUG;


int vendor_command(struct libusb_device_handle *handle, int cmd, int value, int index, unsigned char *buf, int length);

int vendor_request(struct libusb_device_handle *handle, int cmd, int value, int index, unsigned char *buf, int length);


// used by ZTEX SDK VR 0x30: getFpgaState
// for debug purposes only
// inouttraffic doesn't use that
struct ztex_fpga_state {
	int fpgaConfigured;
	int fpgaChecksum;
	int fpgaBytes;
	int fpgaInitB;
	//int fpgaFlashResult; // present but not used in ZTEX
	//int fpgaFlashBitSwap;
};

struct ztex_device {
	struct libusb_device_handle *handle;
	libusb_device *usb_device;
	int busnum;
	int devnum;
	int num_of_fpgas;
	int selected_fpga;
	int valid;
	int iface_claimed;
	struct ztex_device *next;
	char snString[ZTEX_SNSTRING_LEN];
	// ZTEX specific stuff from device
	char snString_orig[ZTEX_SNSTRING_LEN];
	unsigned char productId[4];
	unsigned char fwVersion;
	unsigned char interfaceVersion;
	unsigned char interfaceCapabilities[6];
	unsigned char moduleReserved[12];
	char product_string[ZTEX_PRODUCT_STRING_LEN];
};

struct ztex_dev_list {
	struct ztex_device *dev;
};

int ztex_device_new(libusb_device *usb_dev, struct ztex_device **ztex_dev);

void ztex_device_delete(struct ztex_device *dev);

void ztex_device_invalidate(struct ztex_device *dev);

int ztex_device_valid(struct ztex_device *dev);


struct ztex_dev_list *ztex_dev_list_new();

void ztex_dev_list_add(struct ztex_dev_list *dev_list, struct ztex_device *dev);

// Moves valid devices from 'added_list' to 'dev_list'. Returns number of moved devices. 'added_list' emptied.
int ztex_dev_list_merge(struct ztex_dev_list *dev_list, struct ztex_dev_list *added_list);

// Device removed from list and deleted
void ztex_dev_list_remove(struct ztex_dev_list *dev_list, struct ztex_device *dev_remove);

// Deletes all devices and the list itself
void ztex_dev_list_delete(struct ztex_dev_list *dev_list);

int ztex_dev_list_count(struct ztex_dev_list *dev_list);

void ztex_dev_list_print(struct ztex_dev_list *dev_list);

struct ztex_device *ztex_find_by_sn(struct ztex_dev_list *dev_list, char *sn);


// equal to reset_fpga() from ZTEX SDK (VR 0x31)
// FPGA reset, removes bitstream
int ztex_reset_fpga(struct ztex_device *dev);

// equal to select_fpga() from ZTEX SDK (VR 0x51)
int ztex_select_fpga(struct ztex_device *dev, int num);

// Gets ZTEX-specific data from device (VR 0x22), including
// device type and capabilities
// Used in ztex_device_new()
int ztex_get_descriptor(struct ztex_device *dev);

// ZTEX Capabilities. Capabilities are pre-fetched and stored in 'struct ztex_device'
int ztex_check_capability(struct ztex_device *dev, int i, int j);

int ztex_firmware_is_ok(struct ztex_device *dev);

// Scans for devices that aren't already in dev_list, adds to new_dev_list
// - Performs all checks & closes file descriptor ASAP
// Returns:
// >= 0 number of devices added
// <0 error
int ztex_scan_new_devices(struct ztex_dev_list *new_dev_list,
		struct ztex_dev_list *dev_list, int warn_open,
		struct list_main *dev_allow);

// upload bitstream on FPGA
int ztex_configureFpgaHS(struct ztex_device *dev, FILE *fp, int interfaceHS);

// uploads bitsteam on every FPGA in the device
int ztex_upload_bitstream(struct ztex_device *dev, FILE *fp);

// reset_cpu used by firmware upload
int ztex_reset_cpu(struct ztex_device *dev, int r);

// firmware image loaded from an ihx (Intel Hex format) file.
struct ihx_data {
	short *data;
};

// Uploads firmware from .ihx file, device resets.
// < 0 on error.
int ztex_firmware_upload(struct ztex_device *dev, char *filename);

// resets device. firmware is lost.
void ztex_device_reset(struct ztex_device *dev);

#endif

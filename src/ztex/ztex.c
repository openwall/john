/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libusb-1.0/libusb.h>

#include "ztex.h"

#include "../path.h"

//===============================================================
//
// Contains functions for operating Ztex USB-FPGA modules.
// Based on original Ztex SDK written in java.
//
//===============================================================

int ZTEX_DEBUG = 0;

void ztex_error(const char *s, ...) {
	va_list ap;
	va_start(ap, s);
	vfprintf(stderr, s, ap);
	va_end(ap);
}

// Sends Vendor Command
// cmd - command number
// value (16 bit) - bytes 2 and 3 of setup data
// index (16 bit) - bytes 4 and 5 of setup data
// buf - payload data buffer
// length (16 bit) - size of the payload data (bytes 6 and 7 of setup data)
// returns number of bytes sent
//
int vendor_command(struct libusb_device_handle *handle, int cmd, int value, int index, unsigned char *buf, int length)
{
	return libusb_control_transfer(handle, 0x40, cmd, value, index, buf, length, USB_CMD_TIMEOUT);
}

// Vendor Request
// cmd - command number
// value (16 bit) - bytes 2 and 3 of setup data
// index (16 bit) - bytes 4 and 5 of setup data
// buf - payload data buffer
// length - size of requested payload data (bytes 6 and 7 of setup data)
// returns number of bytes received
//
// Original Ztex1.java VendorRequest method has following features:
// * 1 ms delay before execution
// * in case of error, continues until the timeout is reached
//
int vendor_request(struct libusb_device_handle *handle, int cmd, int value, int index, unsigned char *buf, int length)
{
	return libusb_control_transfer(handle, 0xc0, cmd, value, index, buf, length, USB_CMD_TIMEOUT);
}


////////////////////////////////////////////////////////////////////////////////
//
// Following functions use 'struct ztex_device' and 'struct ztex_dev_list'
//
////////////////////////////////////////////////////////////////////////////////

// checks if given string is a valid Serial Number
int ztex_sn_is_valid(char *sn)
{
	int i;
	for (i = 0; i < ZTEX_SNSTRING_LEN; i++) {
		if (!sn[i])
			return i < ZTEX_SNSTRING_MIN_LEN ? 0 : 1;
		if ( !( (sn[i] >= '0' && sn[i] <= '9') || (sn[i] >= 'A' && sn[i] <= 'F')
				|| (sn[i] >= 'a' && sn[i] <= 'f')) )
			return 0;
	}
	if (sn[i])
		return 0;

	return 1;
}

// Creates 'struct ztex_device' out of 'libusb_device *'
// gets data from the device
int ztex_device_new(libusb_device *usb_dev, struct ztex_device **ztex_dev)
{
	int result;

	*ztex_dev = NULL;
	struct ztex_device *dev = malloc(sizeof(struct ztex_device));
	if (!dev) {
		ztex_error("malloc: unable to allocate %d bytes\n", sizeof(struct ztex_device));
		return -1;
	}

	dev->handle = NULL;
	dev->usb_device = usb_dev;
	dev->busnum = libusb_get_bus_number(usb_dev);
	dev->devnum = libusb_get_device_address(usb_dev);

	result = libusb_open(usb_dev, &dev->handle);
	if (result < 0) {
		// e.g. on Windows no driver for device
		// or device already opened
		if (result != LIBUSB_ERROR_ACCESS)
			ztex_error("ztex_device_new: libusb_open returns %d (%s)\n",
					result, libusb_error_name(result));
		ztex_device_delete(dev);
		return result;
	}
	dev->valid = 1;

	struct libusb_device_descriptor desc;
	result = libusb_get_device_descriptor(usb_dev, &desc);
	if (result < 0) {
		ztex_error("ztex_device_new: libusb_get_device_descriptor returns %d (%s)\n",
				result, libusb_error_name(result));
		ztex_device_delete(dev);
		return result;
	}

	if (!desc.iSerialNumber || !desc.iProduct) {
		ztex_error("ztex_device_new: invalid iSerialNumber or iProduct\n");
		ztex_device_delete(dev);
		return -1;
	}

	result = libusb_get_string_descriptor_ascii(dev->handle, desc.iSerialNumber,
			(unsigned char *)dev->snString, ZTEX_SNSTRING_LEN);
	if (result < 0) {
		ztex_error("ztex_device_new: libusb_get_string_descriptor_ascii(iSerialNumber): %s\n",
				result, libusb_error_name(result));
		ztex_device_delete(dev);
		return result;
	}

	if (!ztex_sn_is_valid(dev->snString)) {
		ztex_error("ztex_device_new: bad Serial Number (%s)\n", dev->snString);
		ztex_device_delete(dev);
		return -1;
	}

	result = libusb_get_string_descriptor_ascii(dev->handle, desc.iProduct,
			(unsigned char *)dev->product_string, ZTEX_PRODUCT_STRING_LEN);
	if (result < 0) {
		ztex_error("ztex_device_new: libusb_get_string_descriptor_ascii(iProduct): %s\n",
				result, libusb_error_name(result));
		ztex_device_delete(dev);
		return result;
	}

	// Ztex specific descriptor. Contains device type
	result = ztex_get_descriptor(dev);
	if (result < 0) {
		ztex_device_delete(dev);
		return result;
	}

	if (ztex_check_capability(dev, CAPABILITY_MULTI_FPGA)) {
		unsigned char buf[3];
		// VR 0x50: getMultiFpgaInfo
		result = vendor_request(dev->handle, 0x50, 0, 0, buf, 3);
		if (result < 0) {
			ztex_error("SN %s: getMultiFpgaInfo returns %d (%s)\n",
					dev->snString, result, libusb_error_name(result));
			return result;
		}
		dev->num_of_fpgas = buf[0] + 1;
		dev->selected_fpga = buf[1];
		if (dev->num_of_fpgas <= 0 || dev->selected_fpga > dev->num_of_fpgas) {
			ztex_error("SN %s: getMultiFpgaInfo: invalid MultiFpga information\n",
				dev->snString);
			return -1;
		}
	}
	else
		dev->num_of_fpgas = 1;

	*ztex_dev = dev;
	return 0;
}

void ztex_device_delete(struct ztex_device *dev)
{
	if (!dev) {
		ztex_error("ztex_device_delete(NULL)\n");
		return;
	}
	ztex_device_invalidate(dev);
	free(dev);
}

void ztex_device_invalidate(struct ztex_device *dev)
{
	if (!dev || !dev->valid)
		return;
	dev->valid = 0;
	if (dev->handle)
		libusb_close(dev->handle);
}

int ztex_device_valid(struct ztex_device *dev)
{
	return dev && dev->valid;
}


struct ztex_dev_list *ztex_dev_list_new()
{
	struct ztex_dev_list *dev_list = malloc(sizeof(struct ztex_dev_list));
	if (!dev_list)
		return NULL;
	dev_list->dev = NULL;
	return dev_list;
}

void ztex_dev_list_add(struct ztex_dev_list *dev_list, struct ztex_device *dev)
{
	if (!dev_list) {
		ztex_error("ztex_dev_list_add(NULL)\n");
		return;
	}
	dev->next = dev_list->dev;
	dev_list->dev = dev;
}

int ztex_dev_list_merge(struct ztex_dev_list *dev_list, struct ztex_dev_list *added_list)
{
	if (!dev_list || !added_list) {
		ztex_error("ztex_dev_list_merge: invalid arguments\n");
		return 0;
	}
	int count = 0;
	struct ztex_device *dev, *dev_next;
	for (dev = added_list->dev; dev; dev = dev_next) {
		dev_next = dev->next;
		//printf("ztex_dev_list_merge: SN %s, valid %d\n",dev->snString, dev->valid);
		if (!ztex_device_valid(dev)) {
			ztex_device_delete(dev);
			continue;
		}
		ztex_dev_list_add(dev_list, dev);
		count++;
	}
	//added_list->dev = NULL;
	free(added_list);
	return count;
}

// Device removed from list and deleted
void ztex_dev_list_remove(struct ztex_dev_list *dev_list, struct ztex_device *dev_remove)
{
	if (!dev_list || !dev_list->dev || !dev_remove) {
		ztex_error("ztex_dev_list_remove: invalid arguuments\n");
		return;
	}
	if (dev_list->dev == dev_remove) {
		dev_list->dev = dev_remove->next;
		ztex_device_delete(dev_remove);
		return;
	}

	struct ztex_device *dev;
	for (dev = dev_list->dev; dev->next; dev = dev->next)
		if (dev->next == dev_remove) {
			dev->next = dev_remove->next;
			ztex_device_delete(dev_remove);
			return;
		}
}
/*
// not used, not tested
void ztex_dev_list_remove_invalid(struct ztex_dev_list *dev_list)
{
	struct ztex_device *dev;
	for (dev = dev_list->dev; dev; dev = dev->next) {
	}
}*/

// count only valid devices
int ztex_dev_list_count(struct ztex_dev_list *dev_list)
{
	int count = 0;
	struct ztex_device *dev;
	if (!dev_list)
		return 0;
	for (dev = dev_list->dev; dev; dev = dev->next)
		if (ztex_device_valid(dev))
			count++;
	return count;
}

void ztex_dev_list_print(struct ztex_dev_list *dev_list)
{
	struct ztex_device *dev;
	if (!dev_list || !dev_list->dev) {
		printf("Empty ztex_dev_list\n");
		return;
	}
	for (dev = dev_list->dev; dev; dev = dev->next) {
		if (!ztex_device_valid(dev))
			continue;
		printf("SN: %s ",dev->snString);
		printf("productId: %d.%d.%d.%d \"%s\" ", dev->productId[0], dev->productId[1],
			dev->productId[2], dev->productId[3], dev->product_string);
		printf("busnum:%d devnum:%d ", dev->busnum, dev->devnum);
		if (ZTEX_DEBUG) printf("valid:%d ", ztex_device_valid(dev));
		printf("\n");
	}
}


// Finds valid device with given Serial Number in ztex_dev_list
struct ztex_device *ztex_find_by_sn(struct ztex_dev_list *dev_list, char *sn)
{
	if (!dev_list)
		return NULL;

	struct ztex_device *dev;
	for (dev = dev_list->dev; dev; dev = dev->next) {
		if (!ztex_device_valid(dev))
			continue;
		if (!strncmp(dev->snString, sn, ZTEX_SNSTRING_LEN))
			return dev;
	}
	return NULL;
}

// Finds valid device by libusb_device *
struct ztex_device *ztex_find_by_usb_dev(struct ztex_dev_list *dev_list, libusb_device *usb_dev)
{
	if (!dev_list)
		return NULL;

	struct ztex_device *dev;
	for (dev = dev_list->dev; dev; dev = dev->next) {
		if (!ztex_device_valid(dev))
			continue;
		if (dev->usb_device == usb_dev)
			return dev;
	}
	return NULL;
}

// Resets bitstream
int ztex_reset_fpga(struct ztex_device *dev)
{
	int result = vendor_command(dev->handle, 0x31, 0, 0, NULL, 0);
	if (result < 0) {
		ztex_error("SN %s: ztex_reset_fpga() returns %d (%s)\n",
				dev->snString, result, libusb_error_name(result));
		return result;
	}
	return 0;
}

int ztex_select_fpga(struct ztex_device *dev, int num)
{
	if (dev->num_of_fpgas == 1 || num == dev->selected_fpga)
		return 0;
	if (num < 0 || num >= dev->num_of_fpgas) {
		ztex_error ("SN %s: ztex_select_fpga(): invalid argument %d\n",
				dev->snString, num);
		return -1;
	}
	int result = vendor_command(dev->handle, 0x51, num, 0, NULL, 0);
	if (result < 0) {
		ztex_error("SN %s: ztex_select_fpga() returns %d (%s)\n",
				dev->snString, result, libusb_error_name(result));
		return result;
	}
	dev->selected_fpga = num;
	return result;
}


// get ZTEX-specific descriptor (VR 0x22)
// store in 'struct ztex_device'
int ztex_get_descriptor(struct ztex_device *dev)
{
	unsigned char buf[40];
	int result = vendor_request(dev->handle, 0x22, 0, 0, buf, 40);
	if (result < 0) {
		ztex_error("SN %s: ztex_get_descriptor() returns %d (%s)\n",
				dev->snString, result, libusb_error_name(result));
		return result;
	}
	//printf("result VR 0x22: %d %d %d %d\n", result, buf[6], buf[7], buf[8]);
	if (buf[0] != 40 || buf[1] != 1 || buf[2] != 'Z' || buf[3] != 'T'
			|| buf[4] != 'E' || buf[5] != 'X') {
		ztex_error("SN %s: ztex_get_descriptor: invalid ztex-specific descriptor\n",
				dev->snString);
		return -1;
	}

	int i;
	for (i = 0; i < 4; i++)
		dev->productId[i] = buf[i+6];
	dev->fwVersion = buf[10];
	dev->interfaceVersion = buf[11];
	for (i = 0; i < 6; i++)
		dev->interfaceCapabilities[i] = buf[i+12];
	for (i = 0; i < 12; i++)
		dev->moduleReserved[i] = buf[i+18];
	return 0;
}

// ZTEX Capabilities. Capabilities are pre-fetched and stored in 'struct ztex_device'
int ztex_check_capability(struct ztex_device *dev, int i, int j)
{
	if (i >= 0 && i <= 5 && j >= 0 && j < 8 && (dev->interfaceCapabilities[i] & 0xFF) & (1 << j) ) {
		return 1;
	}
	return 0;
}


// Scans for devices that aren't already in dev_list, adds them to new_dev_list
// Devices in question:
// 1. Got ZTEX Vendor & Product ID, also SN
// 2. Have ZTEX-specific descriptor
// If some devices are already opened (e.g. by other process) -
// skips them, warns if warn_open is set (it can't distinguish device
// is already opened or other error condition such as permissions).
// Returns:
// >= 0 number of devices added
// <0 error
int ztex_scan_new_devices(struct ztex_dev_list *new_dev_list,
		struct ztex_dev_list *dev_list, int warn_open)
{
	libusb_device **usb_devs;
	int result;
	int count = 0;
	ssize_t cnt;

	cnt = libusb_get_device_list(NULL, &usb_devs);
	if (cnt < 0) {
		ztex_error("libusb_get_device_list: %s\n", libusb_error_name((int)cnt));
		return (int)cnt;
	}

	int num_fail_open = 0;
	int i;
	for (i = 0; usb_devs[i]; i++) {
		libusb_device *usb_dev = usb_devs[i];

		struct libusb_device_descriptor desc;
		result = libusb_get_device_descriptor(usb_dev, &desc);
		if (result < 0) {
			ztex_error("libusb_get_device_descriptor: %s\n", libusb_error_name(result));
			continue;
		}

		if (ZTEX_DEBUG) printf("ztex_scan_new_devices: USB %04x %04x\n",
				desc.idVendor, desc.idProduct);
		if (desc.idVendor != ZTEX_IDVENDOR || desc.idProduct != ZTEX_IDPRODUCT)
			continue;

		if (ztex_find_by_usb_dev(dev_list, usb_dev)) {
			continue;
		}

		struct ztex_device *ztex_dev;
		result = ztex_device_new(usb_dev, &ztex_dev);
		if (result < 0) {
			if (result == LIBUSB_ERROR_ACCESS)
				num_fail_open ++;
			continue;
		}

		// found new device
		if (ZTEX_DEBUG) printf("ztex_scan_new_devices: SN %s productId: %d.%d\n",
				ztex_dev->snString, ztex_dev->productId[0], ztex_dev->productId[1]);
/* Check if device is supported by application - moved to application

		// only 1.15y devices supported for now
		if (ztex_dev->productId[0] == 10 && ztex_dev->productId[1] == 15) {
			ztex_dev_list_add(new_dev_list, ztex_dev);
			count++;
		}
		else {
			if (ZTEX_DEBUG) printf("SN %s: unsupported type: %d.%d, skipping\n",
				ztex_dev->productId[0], ztex_dev->productId[1], ztex_dev->snString);
			ztex_device_delete(ztex_dev);
		}*/
		ztex_dev_list_add(new_dev_list, ztex_dev);
		count++;
	}

	libusb_free_device_list(usb_devs, 1);

	if (warn_open && num_fail_open) {
		fprintf(stderr, "Warning: unable to access %d board(s), could be "
			"insufficient permissions or\n"
			"another instance of john running.\n",
			num_fail_open);
	}
	return count;
}


// function is used by Ztex SDK to check if bitstream is uploaded.
// inouttraffic uses other approach: queries FPGA with VR 0x88 ( fpga_test_get_id() )
int ztex_getFpgaState(struct ztex_device *dev, struct ztex_fpga_state *fpga_state)
{
	unsigned char buf[9];
	int result;

	// VR 0x30: getFpgaState
	result = vendor_request(dev->handle, 0x30, 0, 0, buf, 9);
	if (result < 0) {
		ztex_error("SN %s: getFpgaState returns %d (%s)\n",
				dev->snString, result, libusb_error_name(result));
		return result;
	}
	if (result != 9) {
		ztex_error("SN %s: getFpgaState reads %d, must be 9\n",
				dev->snString, result);
		return -1;
	}
	fpga_state->fpgaConfigured = buf[0] == 0;
	fpga_state->fpgaChecksum = buf[1];
	fpga_state->fpgaBytes = (buf[5] << 24) | (buf[4] << 16) | (buf[3] << 8) | buf[2];
	fpga_state->fpgaInitB = buf[6];
	return 0;
}

void ztex_printFpgaState(struct ztex_fpga_state *fpga_state)
{
	printf("Configured:%d, Checksum:%d, Bytes:%d, InitB:%d\n",
		fpga_state->fpgaConfigured, fpga_state->fpgaChecksum, fpga_state->fpgaBytes, fpga_state->fpgaInitB);
}

void ztex_swap_bits(unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		unsigned char b = buf[i];
		buf[i] = ((b & 128) >> 7) | ((b & 1) << 7)
			| ((b & 64) >> 5) | ((b & 2) << 5)
			| ((b & 32) >> 3) | ((b & 4) << 3)
			| ((b & 16) >> 1) | ((b & 8) << 1);
	}
}

int ztex_configureFpgaHS(struct ztex_device *dev, FILE *fp, int endpointHS)
{
	int result;
	struct ztex_fpga_state fpga_state;
	if (ZTEX_DEBUG) {
		result = ztex_getFpgaState(dev, &fpga_state);
		printf("%s Start HS config: ", dev->snString);
		ztex_printFpgaState(&fpga_state);
	}

	const int transactionBytes = 65536;
	unsigned char buf[transactionBytes];
	int transferred;

	result = ztex_reset_fpga(dev);
	if (result < 0)
		return result;

	// VC 0x34: initHSFPGAConfiguration
	result = vendor_command(dev->handle, 0x34, 0, 0, NULL, 0);
	if (result < 0) {
		ztex_error("SN %s: initHSFPGAConfiguration returns %d (%s)\n",
				dev->snString, result, libusb_error_name(result));
		return result;
	}

	rewind(fp);
	do {
		int length = fread(buf, 1, transactionBytes, fp);
		if (ferror(fp)) {
			ztex_error("configureFpgaHS: fread: %s\n", strerror(errno));
			return -1;
		}
		ztex_swap_bits(buf, length);
		result = libusb_bulk_transfer(dev->handle, endpointHS, buf, length, &transferred, USB_RW_TIMEOUT);
		if (result < 0) {
			ztex_error("SN %s: usb_bulk_write returns %d (%s)\n",
					dev->snString, result, libusb_error_name(result));
			return result;
		}
		if (transferred != length) {
			ztex_error("SN %s: usb_bulk_write: length %d, transferred %d\n",
					dev->snString, length,transferred);
			return -1;
		}
	} while ( !feof(fp) );

	// VC 0x35: finishHSFPGAConfiguration
	result = vendor_command(dev->handle, 0x35, 0, 0, NULL, 0);
	if (result < 0) {
		ztex_error("SN %s: finishHSFPGAConfiguration returns %d (%s)\n",
				dev->snString, result, libusb_error_name(result));
		return result;
	}

	if (ZTEX_DEBUG) {
		result = ztex_getFpgaState(dev, &fpga_state);
		printf("%s End HS config: ", dev->snString);
		ztex_printFpgaState(&fpga_state);
		if (!fpga_state.fpgaConfigured) {
			printf("UNCONFIGURED!\n");
			return -1;
		}
	}

	return 0;
}

// upload bitstream (High-Speed) on every FPGA in the device
int ztex_upload_bitstream(struct ztex_device *dev, FILE *fp)
{
	unsigned char settings[2];
	int result;

	// VR 0x33: getHSFpgaSettings
	result = vendor_request(dev->handle, 0x33, 0, 0, settings, 2);
	if (result < 0) {
		ztex_error("SN %s: getHSFpgaSettings returns %d (%s)\n",
				dev->snString, result, libusb_error_name(result));
		return result;
	}
	int endpointHS = settings[0];
	int interfaceHS = settings[1];
	if (endpointHS <= 0 || interfaceHS < 0) {
		ztex_error("SN %s: invalid HS Fpga Settings\n",
				dev->snString, result, libusb_error_name(result));
		return -1;
	}

	// device_new() from inouttraffic performs claim_interface()
	int i;
	for (i = 0; i < dev->num_of_fpgas; i++) {
		result = ztex_select_fpga(dev,i);
		if (result < 0)
			return result;
		result = ztex_configureFpgaHS(dev, fp, endpointHS);
		if (result < 0)
			return result;
	}

	return 1;
}

// firmware image loaded from an ihx (Intel Hex format) file.
char hex_digit(char ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	else
		return -1;
}

short hex_byte(char *str)
{
	char digit0 = hex_digit(str[0]);
	char digit1 = hex_digit(str[1]);
	if (digit0 == -1 || digit1 == -1)
		return -1;
	short result = (digit0 << 4) | digit1;
	return result & 0xff;
}

const int IHX_SIZE_MAX = 65536;

int ihx_load_data(struct ihx_data *ihx_data, FILE *fp)
{
	ihx_data->data = malloc(2*IHX_SIZE_MAX);
	if (!ihx_data->data) {
		ztex_error("ihx_load_data: malloc(%d) failed\n", 2*IHX_SIZE_MAX);
		return -1;
	}
	int i;
	for (i = 0; i < IHX_SIZE_MAX; i++)
		ihx_data->data[i] = -1;

	fseek(fp, 0L, SEEK_END);
	long file_size = ftell(fp);
	if (!file_size) {
		ztex_error("ihx_load_data: empty ihx file\n");
		return -1;
	}

	rewind(fp);
	char *file_data = malloc(file_size);
	if (!file_data) {
		ztex_error("ihx_load_data: malloc(%d) failed\n", file_size);
		return -1;
	}

	int offset = 0;
	do {
		int length = fread(file_data + offset, 1, file_size, fp);
		if (ferror(fp)) {
			ztex_error("ihx_load_data: fread: %s\n", strerror(errno));
			return -1;
		}
		offset += length;
	} while ( !feof(fp) );

	int b, len, cs, addr, type;
	int line = 0;
	unsigned char buf[256];
	int eof_ok = 0;
	for (i = 0; i < file_size; ) {
		while (file_data[i] != ':') {
			i++;
			continue;
		}
		i++;
		line++;

		len = hex_byte(file_data + i); // length field
		if (len == -1) {
			ztex_error("ihx_load_data: line %d: invalid len\n", line);
			return -1;
		}
		cs = len;

		b = hex_byte(file_data + i + 2); // address field
		if (b == -1) {
			ztex_error("ihx_load_data: line %d: invalid address byte 0\n", line);
			return -1;
		}
		cs += b;
		addr = b << 8;
		b = hex_byte(file_data + i + 4);
		if (b == -1) {
			ztex_error("ihx_load_data: line %d: invalid address byte 1\n", line);
			return -1;
		}
		cs += b;
		addr |= b;

		type = hex_byte(file_data + i + 6); // type field
		if (type == -1) {
			ztex_error("ihx_load_data: line %d: invalid type\n", line);
			return -1;
		}
		cs += type;

		int j;
		for (j = 0; j < len; j++) { // data
			buf[j] = hex_byte(file_data + i + j*2 + 8);
			cs += buf[j];
		}

		cs += hex_byte(file_data + i + j*2 + 8); // checksum
		if ( (cs & 0xff) != 0 ) {
			ztex_error("ihx_load_data: line %d: wrong checksum %d\n", line, cs);
			return -1;
		}
		i += j*2 + 10;

		if (type == 0) { // common data
			int k;
			for (k = 0; k < len; k++) {
				if (addr + k >= IHX_SIZE_MAX) {
					ztex_error("ihx_load_data: line %d: addr(%d) >= IHX_SIZE_MAX(%d)\n",
						line, addr, IHX_SIZE_MAX);
					return -1;
				}
				if (ihx_data->data[addr+k] != -1) {
					ztex_error("ihx_load_data: line %d: intersection, addr %d+%d\n", line, addr, k);
					return -1;
				}
				ihx_data->data[addr+k] = (short)buf[k];
			}
		}
		else if (type == 1) { // special record at end-of-file
			eof_ok = 1;
			break;
		}
	}
	if (!eof_ok) {
		ztex_error("ihx_load_data: no special record at end-of-file\n");
		return -1;
	}
	return 0;
}

int ztex_reset_cpu(struct ztex_device *dev, int r)
{
	unsigned char buf[1] = { r };
	int result = vendor_command(dev->handle, 0xA0, 0xE600, 0, buf, 1);
	// Don't return error on r==0 && LIBUSB_ERROR_NO_DEVICE
	if (result < 0 && !(result == LIBUSB_ERROR_NO_DEVICE && !r) ) {
		ztex_error("SN %s: ztex_reset_cpu(%d) returns %d (%s)\n",
				dev->snString, r, result, libusb_error_name(result));
		return result;
	}
	if (result != 1) {
		ztex_error("SN %s: ztex_reset_cpu(): read %d, must be 1\n",
				dev->snString, result);
		return -1;
	}
	return 1;
}

int ztex_firmware_upload_ihx(struct ztex_device *dev, struct ihx_data *ihx_data)
{
	const int transactionBytes = 4096;
	unsigned char buf[transactionBytes];
	int result;

	result = ztex_reset_cpu(dev, 1);
	if (result < 0)
		return -1;

	int uploaded = 0;
	int i, j;
	for (i = 0; i < IHX_SIZE_MAX; ) {
		// firmware upload start address must be aligned to 2-byte word
		// unaligned byte must be 0
		if (ihx_data->data[i] == -1 && ihx_data->data[i+1] == -1) {
			i += 2;
			continue;
		}

		int write_len = 0;
		for (j = 0; j < transactionBytes && j < IHX_SIZE_MAX - i; j += 2) {
			if (ihx_data->data[i+j] == -1) {
				if (ihx_data->data[i+j+1] == -1)
					break;
				else {
					buf[j] = 0;
					buf[j+1] = ihx_data->data[i+j+1];
					write_len += 2;
				}
			}
			else {
				buf[j] = ihx_data->data[i+j];
				write_len ++;
				if (ihx_data->data[i+j+1] == -1) {
					j += 2;
					break;
				}
				buf[j+1] = ihx_data->data[i+j+1];
				write_len ++;
			}
		}

		result = vendor_command(dev->handle, 0xA0, i, 0, buf, write_len);
		//printf("ztex_upload_firmware: offset %d, send %d data %d result %d\n", i, write_len, buf[0], result);
		if (result < 0) {
			ztex_error("SN %s: ztex_upload_firmware() returns %d (%s)\n",
					dev->snString, result, libusb_error_name(result));
			return result;
		}
		if (result != write_len) {
			ztex_error("SN %s: ztex_upload_firmware: write %d, transferred %d\n",
					dev->snString, write_len, result);
			return -1;
		}
		uploaded += j;
		i += j;
	} // for ( i < IHX_SIZE_MAX; )

	if (ZTEX_DEBUG) printf("SN %s uploaded %d bytes\n",
			dev->snString, uploaded);

	result = ztex_reset_cpu(dev, 0);
	// On some systems it returns -4 LIBUSB_ERR_NO_DEVICE
	// (indeed device goes into reset, disappears)
	//
	//if (result < 0)
	//	return -1;
	return 0;
}

int ztex_firmware_upload(struct ztex_device *dev, char *filename)
{
	int result;
	FILE *fp;
	if ( !(fp = fopen(path_expand(filename), "r")) ) {
		printf("fopen(%s): %s\n", path_expand(filename), strerror(errno));
		return -1;
	}
	if (ZTEX_DEBUG) {
		printf("SN %s: uploading firmware (%s).. ", dev->snString, filename);
		fflush(stdout);
	}
	struct ihx_data ihx_data;
	result = ihx_load_data(&ihx_data, fp);
	fclose(fp);
	if (result < 0) {
		return -1;
	}

	result = ztex_firmware_upload_ihx(dev, &ihx_data);
	return result;
}

void ztex_device_reset(struct ztex_device *dev)
{
	if (!dev->handle)
		return;

	if (ztex_reset_cpu(dev, 1) < 0)
		return;
	ztex_reset_cpu(dev, 0);
}

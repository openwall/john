/*
 * This software is Copyright (c) 2016,2018-2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <libusb-1.0/libusb.h>

#include "../options.h"
#include "../list.h"

#include "../ztex_common.h"
#include "ztex.h"
#include "inouttraffic.h"
#include "ztex_scan.h"

///////////////////////////////////////////////////////////////////
//
// Find Ztex devices (of supported type)
// Upload firmware (device resets) if necessary
// Returns number of newly found devices (excluding those that were reset)
//
///////////////////////////////////////////////////////////////////

// Find Ztex USB devices (of supported type)
// Check "--devices" command-line option
// Upload firmware (device resets) if necessary
// Return number of newly found devices (excluding those that were reset)
static int ztex_scan(struct ztex_dev_list *new_dev_list, struct ztex_dev_list *dev_list,
		int *fw_upload_count, int warn_open, struct list_main *dev_allow)
{
	static int fw_3rd_party_warning = 0;
	int fw_3rd_party_count = 0;
	int count = 0;
	(*fw_upload_count) = 0;

	int result = ztex_scan_new_devices(new_dev_list, dev_list,
		warn_open, dev_allow);
	if (result <= 0)
		return 0;

	struct ztex_device *dev, *dev_next;
	for (dev = new_dev_list->dev; dev; dev = dev_next) {
		dev_next = dev->next;

		// Check firmware
		if (ztex_firmware_is_ok(dev)) {
			count++;
			continue;
		}
		// 3rd party firmware
		else if (ZTEX_FW_3RD_PARTY_OVERWRITE
			// dummy firmware, do upload/override
			|| !strncmp("USB-FPGA Module 1.15y (default)", dev->product_string, 31)
			// inouttraffic firmware of other version
			|| !strncmp("inouttraffic", dev->product_string, 12) ) {
			// upload firmware
			result = ztex_firmware_upload(dev, ZTEX_FW_IHX_PATH);
			if (result >= 0) {
				printf("SN %s: firmware uploaded\n", dev->snString);
				(*fw_upload_count)++;
			}
			// ztex_firmware_upload() resets the device
			ztex_dev_list_remove(new_dev_list, dev);
		}
		// device with some 3rd party firmware - skip it
		else {
			if (!fw_3rd_party_warning) {
				printf("SN %s: 3rd party firmware \"%s\", skipping\n",
						dev->snString, dev->product_string);
				fw_3rd_party_count ++;
			}
			ztex_dev_list_remove(new_dev_list, dev);
		}
	}

	if (!fw_3rd_party_warning && fw_3rd_party_count) {
		printf("Total %d boards with 3rd party firmware skipped.\n",
				fw_3rd_party_count);
		fw_3rd_party_warning = 1;
	}
	return count;
}

// Scan interval in seconds.
int ztex_scan_interval = ZTEX_SCAN_INTERVAL_DEFAULT;

struct timeval ztex_scan_prev_time = { 0, 0 };

int ztex_scan_fw_upload_count = 0;


///////////////////////////////////////////////////////////////////
//
// ztex_timely_scan()
// Function to be invoked timely to scan for new devices.
// Upload firmware if necessary. After upload device resets.
// Immediately returns number of newly found devices.
//
///////////////////////////////////////////////////////////////////

int ztex_timely_scan(struct ztex_dev_list *new_dev_list,
		struct ztex_dev_list *dev_list, struct list_main *dev_allow)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	int time_diff = tv.tv_sec - ztex_scan_prev_time.tv_sec
			+ (tv.tv_usec - ztex_scan_prev_time.tv_usec > 0 ? 0 : -1);
	if ( !( (ztex_scan_fw_upload_count && time_diff >= ZTEX_FW_UPLOAD_DELAY)
			|| time_diff >= ztex_scan_interval) )
		return 0;

	int count, fw_upload_count;
	count = ztex_scan(new_dev_list, dev_list, &fw_upload_count, 0,
		dev_allow);
	if (ztex_scan_fw_upload_count > count) {
		// Not exact; better record SNs of devices for fw upload
		fprintf(stderr, "%d device(s) lost after firmware upload\n",
				ztex_scan_fw_upload_count - count);
	}

	ztex_scan_fw_upload_count = fw_upload_count;
	gettimeofday(&ztex_scan_prev_time, NULL);
	return count;
}


///////////////////////////////////////////////////////////////////
//
// ztex_init_scan()
// Function to be invoked at program initialization.
// Skip valid devices from 'dev_list'.
// If no devices immediately ready and it was firmware upload - waits and rescans.
// Returns number of ready devices with uploaded firmware.
//
///////////////////////////////////////////////////////////////////

int ztex_init_scan(struct ztex_dev_list *new_dev_list,
		struct list_main *dev_allow)
{
	int count1, count2;

	count1 = ztex_scan(new_dev_list, NULL, &ztex_scan_fw_upload_count,
		1, dev_allow);

	if (ztex_scan_fw_upload_count) {
		// Some devices are in reset state after firmware upload
		usleep(ZTEX_FW_UPLOAD_DELAY* 1000*1000);

		int fw_upload_count_stage2;
		count2 = ztex_scan(new_dev_list, new_dev_list, &fw_upload_count_stage2,
			0, dev_allow);
		//if (fw_upload_count_stage2) { // device just plugged in. wait for timely_scan
		if (ztex_scan_fw_upload_count > count2) {
			// Not exact; better record SNs of devices for fw upload
			fprintf(stderr, "%d device(s) lost after firmware upload\n",
					ztex_scan_fw_upload_count - count2);
		}
	} else {
		count2 = 0;
	}

	gettimeofday(&ztex_scan_prev_time, NULL);
	return count1 + count2;
}

void ztex_detect(struct list_main *dev_allow,
		struct list_main **ztex_detected_list)
{
	struct ztex_dev_list *ztex_dev_list = ztex_dev_list_new();
	struct ztex_device *dev;

	int result = libusb_init(NULL);
	if (result < 0) {
		fprintf(stderr, "libusb_init() returns %d: %s\n",
				result, libusb_error_name(result));
		error();
	}

	if (!ztex_init_scan(ztex_dev_list, dev_allow)) {
		fprintf(stderr, "No ZTEX devices found.\n");
		error();
	}

	ztex_dev_list_print(ztex_dev_list);

	int num_detected = ztex_dev_list_count(ztex_dev_list);
	if (num_detected > 1)
		fprintf(stderr, "Detected %d ZTEX devices.\n", num_detected);

	list_init(ztex_detected_list);
	for (dev = ztex_dev_list->dev; dev; dev = dev->next)
		list_add((*ztex_detected_list), dev->snString);
	ztex_dev_list_delete(ztex_dev_list);
	libusb_exit(NULL);
}

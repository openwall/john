/*
 * This software is Copyright (c) 2016,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#ifndef _ZTEX_SCAN_H_
#define _ZTEX_SCAN_H_

#include "../list.h"

struct ztex_dev_list;

// Scan interval in seconds. Consider following:
// If some board is buggy it might timely upload bitstream then fail.
// bitstream upload takes ~1s and other boards don't perform I/O during that time.
extern int ztex_scan_interval;
#define ZTEX_SCAN_INTERVAL_DEFAULT	15

extern struct timeval ztex_scan_prev_time;

// If set to 1, overwrite any 3rd party firmware
#define ZTEX_FW_3RD_PARTY_OVERWRITE 1

// firmware image file (*.ihx)
#define ZTEX_FW_IHX_PATH	"$JOHN/ztex/inouttraffic.ihx"

// if firmware was uploaded, perform rescan after that many sec
#define ZTEX_FW_UPLOAD_DELAY	2

// Function to be invoked timely to scan for new devices.
// Skip valid devices from 'dev_list'.
// Upload firmware if necessary. After upload device resets.
// Immediately returns number of ready devices (excluding those that were reset).
int ztex_timely_scan(struct ztex_dev_list *new_dev_list,
		struct ztex_dev_list *dev_list, struct list_main *dev_allow);

// Function to be invoked at program initialization.
// If there was firmware upload - waits and rescans.
// Returns number of ready devices with uploaded firmware.
int ztex_init_scan(struct ztex_dev_list *new_dev_list,
		struct list_main *dev_allow);

// Same as above, doesn't return until all boards ready.
// Fills-in ztex_detected_list, closes opened I/O descriptiors.
// Exits from the application with error() if no boards found.
void ztex_detect(struct list_main *dev_allow,
		struct list_main **ztex_detected_list);

#endif

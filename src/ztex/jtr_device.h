/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#ifndef _JTR_DEVICE_H_
#define _JTR_DEVICE_H_
/*
 * jtr_device.h
 */
#include "task.h"

extern struct fmt_params *jtr_fmt_params;

extern struct device_bitstream *jtr_bitstream;

// Global physical device_list
extern struct device_list *device_list;

// Global jtr_device_list
extern struct jtr_device_list *jtr_device_list;

/*
 * JtR device.
 * - jtr_device is some remote computing device (part of the device)
 * independent from other such devices from the point of view from JtR.
 * - jtr_device doesn't contain anything specific to underlying
 * physical device or link layer.
 * - Implemented on top of 'inouttraffic' device.
 */
struct jtr_device {
	struct jtr_device *next;
	// physical device
	struct device *device;
	int fpga_num;
	// channel for high-speed packet communication (pkt_comm)
	struct pkt_comm *comm;

	// TODO: there might be several cores in the design
	// that share same communication channel
	//int core_id;

	// using db_salt->sequential_id's that start from 0.
	// on jtr_device with unconfigured comparator cmp_config_id is -1.
	int cmp_config_id;
	// each task is assigned an ID, unique within jtr_device
	// this ID (16-bit) is used as pkt_id of outgoing packets
	int task_id_next;
};

struct jtr_device_list {
	struct jtr_device *device;
};

// create JtR device, add to the list
struct jtr_device *jtr_device_new(
		struct jtr_device_list *jtr_device_list,
		struct device *device, int fpga_num,
		struct pkt_comm *comm);

// Remove device from the list, delete the device
void jtr_device_delete(
		struct jtr_device_list *jtr_device_list,
		struct jtr_device *jtr_device);

// create list of JtR devices out of inouttraffic devices
struct jtr_device_list *jtr_device_list_new(struct device_list *device_list);

// return human-readable identifier
char *jtr_device_id(struct jtr_device *dev);

// Returns number of devices in global jtr_device_list
int jtr_device_list_count();

// Get 1st jtr_device in a list by physical device
struct jtr_device *jtr_device_by_device(
		struct jtr_device_list *jtr_device_list,
		struct device *device);

// This is what is used by JtR's "format" init() function.
// (re-)initialize underlying physical devices, create jtr_device_list.
// Uses global device_list
struct jtr_device_list *jtr_device_list_init();

// Print a line for every connected board
void jtr_device_list_print();

// Print a line with total number of boards
void jtr_device_list_print_count();

// Devices from the 2nd list go to the 1st list. jtr_device_list_1 deleted.
void jtr_device_list_merge(
		struct jtr_device_list *jtr_device_list,
		struct jtr_device_list *jtr_device_list_1);

// Performs timely scan for new devices, merges into global device list
// Returns number of devices found
int jtr_device_list_check();

int jtr_device_list_set_app_mode(unsigned char mode);

// Perform I/O operations on underlying physical devices
// Uses global jtr_device_list
// Return values:
// > 0 - OK, there was some transfer on some devices
// 0 - OK, no data transfer
// < 0 - no valid devices left
int jtr_device_list_rw(struct task_list *task_list);

// Fetch input packets from pkt_comm_queue
// Match input packets to assigned tasks, create task_result's
// Uses global jtr_device_list
// Return values:
// NULL - everything processed (if anything)
// (struct jtr_device *) - bad input from the device
struct jtr_device *jtr_device_list_process_inpkt(struct task_list *task_list);

// Stop physical device
// - deassign tasks
// - remove jtr_devices for failed physical device
int device_stop(
		struct device *device,
		struct task_list *task_list,
		char *error_msg);

#endif

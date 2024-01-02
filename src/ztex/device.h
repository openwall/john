/*
 *
 * Top Level Hardware Operating Functions for Ztex Multi-FPGA board.
 *
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#include "device_bitstream.h"


// device_list_init() takes list of devices with uploaded firmware
// 1. uploads specified bitstreams
// 2. initializes FPGAs
void device_list_init(struct device_list *device_list, struct device_bitstream *bitstream);

// - Scans for devices at program initialization
// - Uploads specified bitstream
// - Initializes devices
// - Returns list of newly found and initialized devices.
// The function waits until device initialization and it takes some time.
struct device_list *device_init_scan(struct device_bitstream *bitstream);

// - Scans for new devices when program is running
// - *device_list argument points at devices already operated (to skip them)
// - Invoked timely, actual scan occurs as often as defined in ztex_scan.h
// - Initializes devices
// - Uploads specified bitstream
// - Returns list of newly found and initialized devices.
// Device initialization takes time; the function returns ASAP
// and continue initialization sequence at next invocations.
struct device_list *device_timely_scan(struct device_list *device_list, struct device_bitstream *bitstream);

void device_list_print(struct device_list *device_list);

// Performs read/write operations on the device
// using high-speed packet communication interface (pkt_comm)
// Return values:
// < 0 - error (expecting caller to invalidate or reset the device)
// 0 - OK, no data was actually send or received (because of either host or remote reasons)
// > 0 - OK, some data was sent or received
int device_pkt_rw(struct device *device);

// Returns ASCII string containing human-readable error description.
// ! not implemented yet
char *device_strerror(int error_code);

// ! Obsolete function (still works, a little buggy)
// Performs r/w operation on device
// using high-speed packet communication interface (pkt_comm)
// Return values:
// < 0 - error
// >= 0 - OK, including the case when no data was actually transmitted
int device_fpgas_pkt_rw(struct device *device);

/*
 * Functions for operating ZTEX 1.15y Multi-FPGA board at High-Speed
 * Require basic ZTEX functions (ztex.c)
 * Assuming device has 'inouttraffic' firmware (inouttraffic.ihx)
 *
 * This software is Copyright (c) 2016-2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#ifndef _INOUTTRAFFIC_H_
#define _INOUTTRAFFIC_H_

#include "device_bitstream.h"

#define ERR_IO_STATE_TIMEOUT -3001
#define ERR_IO_STATE_OVERFLOW -3002
#define ERR_IO_STATE_LIMIT_NOT_DONE -3003
#define ERR_IO_STATE_SFIFO_NOT_EMPTY -3004

#define ERR_WR_PARTIAL -3101

#define ERR_RD_ZEROREAD -3201

#define DEVICE_FPGAS_MAX 4

#define OUTPUT_WORD_WIDTH 2

#define NUM_PROGCLK_MAX	4

// DEBUG=1: print all function calls to stderr
// DEBUG=2: also print I/O data
extern int DEBUG;

// VR 0x84
// Returned by fpga_get_io_state(), fpga_select_setup_io()
// the most important thing here is io_state.IO_STATE_INPUT_PROG_FULL
// When not asserted FPGA's input buffer has space for data
struct fpga_io_state {
	unsigned char io_state;
	unsigned char timeout;
	unsigned char app_status;
	unsigned char pkt_comm_status;
	unsigned char debug2;
	unsigned char debug3;
};

// fpga_io_state.io_state
#define IO_STATE_INPUT_PROG_FULL 0x01
#define IO_STATE_LIMIT_NOT_DONE 0x02
#define IO_STATE_OUTPUT_ERR_OVERFLOW 0x04
#define IO_STATE_SFIFO_NOT_EMPTY 0x08

// used by VR 0x88, fpga_test_get_id()
struct fpga_echo_request {
	unsigned short out[2];
	struct {
		unsigned short data[2];
		unsigned char fpga_id;
		unsigned char reserved;
		unsigned short bitstream_type;
	} reply;
};

// soft reset (VC 0x8B)
// It resets FPGA to its post-configuration state with Global Set Reset (GSR).
// Inouttraffic bitstreams have High-Speed interface disabled by default.
// After reset, fpga_reset() enables High-Speed interface.
// consider device_fpga_reset() to reset all FPGA's on device
int fpga_reset(struct libusb_device_handle *handle);

// used by VR 0x8C, fpga_select_setup_io()
struct fpga_status {
	struct fpga_io_state io_state;
	unsigned short read_limit;
};

struct fpga_wr {
	struct fpga_io_state io_state;
	int io_state_valid; // io_state was taken from other source
	//struct timeval io_state_tv;
	int io_state_timeout_count;
	int wr_done;
	uint64_t wr_count;
	unsigned char *buf; // used only by test.c
	int len;
};

struct fpga_rd {
	unsigned short read_limit;
	int read_limit_valid; // read_limit previously set
	int rd_done;
	uint64_t read_count;
	uint64_t partial_read_count;
	unsigned char *buf; // used only by test.c
	int len;
};

struct fpga {
	struct device *device;
	//struct fpga_id fpga_id;
	unsigned short bitstream_type;
	int num;
	int valid; // actually not used; on a valid device all FPGA's are OK
	struct fpga_wr wr;
	struct fpga_rd rd;
	uint64_t cmd_count;
	uint64_t data_out,data_in; // specific for advanced_test.c

	struct pkt_comm *comm;
	int freq[NUM_PROGCLK_MAX]; // current frequencies
};

struct device {
	struct ztex_device *ztex_device;
	struct device *next;
	int valid;
	struct libusb_device_handle *handle;
	struct fpga fpga[DEVICE_FPGAS_MAX];
	int num_of_valid_fpgas; // actually not used; on a valid device all FPGA's are OK
	int num_of_fpgas;
	int selected_fpga;
};

struct device_list {
	struct device *device;
	struct ztex_dev_list *ztex_dev_list;
};

// Creates 'struct device' on top of 'struct ztex_device'
// claims USB interface 1
struct device *device_new(struct ztex_device *ztex_device);

void device_delete(struct device *device);

// device usually invalidated if there's some error
// underlying ztex_device also invalidated
void device_invalidate(struct device *device);

// check if device has valid state
int device_valid(struct device *device);


struct device_list *device_list_new(struct ztex_dev_list *ztex_dev_list);

void device_list_add(struct device_list *device_list, struct device *device);

void device_list_delete(struct device_list *device_list);

int device_list_count(struct device_list *device_list);

// After merge, added device list deleted.
// Underlying ztex_dev_list's also merged.
int device_list_merge(struct device_list *device_list, struct device_list *added_list);

// Performs fpga_reset() on all FPGA's
// It resets FPGAs to its post-configuration state with Global Set Reset (GSR).
//
// Return values:
// < 0 error; would require heavier reset
//
// Issue. What if only 1 of onboard FPGAs has error.
// Currently following approarch used (heavy_test.c):
// Initialization functions (soft_reset, check_bitstream) initialize all onboard FPGAs.
// On any error, entire device is put into invalid state.
int device_fpga_reset(struct device *device);

// Bitstream type is hardcoded into bitstream (vcr.v/BITSTREAM_TYPE)
// Return value:
// > 0 all FPGA's has bitstream of specified type
// 0 at least 1 FPGA has no bitstream or bitstream of other type
// < 0 error
int device_check_bitstream_type(struct device *device, unsigned short bitstream_type);

// Checks if bitstreams on devices are loaded and of specified type.
// if (filename != NULL) performs upload in case of wrong or no bitstream
// Returns: number of devices with bitstreams uploaded
int device_list_check_bitstreams(struct device_list *device_list, unsigned short BITSTREAM_TYPE, char *filename);

// tests if bitstream from currently selected FPGA is operational and gets bitstream_type
// Returns:
// < 0 on I/O error
// 0 bitstream isn't operational or unable to get bitstream_type
// > 0 bitstream OK
// consider use of device_check_bitstream_type()
int fpga_test_get_id(struct fpga *fpga);

// some application mode, does not directly affect I/O
int fpga_set_app_mode(struct fpga *fpga, int app_mode);

// set app_mode on every FPGA on every device in the list
// Returns number of affected devices
// On error, invalidates device and continues
int device_list_set_app_mode(struct device_list *device_list, int app_mode);

// Performs device_fpga_reset() on each device in the list
int device_list_fpga_reset(struct device_list *device_list);

// unlike ztex_select_fpga(), it waits for I/O timeout
int fpga_select(struct fpga *fpga);

// combines fpga_select(), fpga_get_io_state(), fpga_setup_output() in 1 USB request
int fpga_select_setup_io(struct fpga *fpga);

// Sets Programmable clock in MHz. Rounds down given frequency
// to the nearest value in the table. Return values:
// <0 Error
// >0 New frequency (MHz)
int fpga_progclk(struct fpga *fpga, int clk_num, int freq);

// ***************************************************************
//
// Functions below are used by tests or obsolete.
// For operating the board, use top-level functions from device.c
//
// ***************************************************************

// Requests 'struct fpga_io_state' fro currently selected FPGA
int fpga_get_io_state(struct libusb_device_handle *handle, struct fpga_io_state *io_state);

// FPGA would not send data until fpga_setup_output().
// Returns number of bytes FPGA is going to transmit.
int fpga_setup_output(struct libusb_device_handle *handle);

// enable/disable high-speed output.
// FPGA comes with High-Speed I/O (hs_io) disabled.
// Application usually would not need this:
// hs_io status changes internally by e.g. fpga_select() and fpga_reset().
int fpga_hs_io_enable(struct libusb_device_handle *handle, int enable);

// enabled by default; disable for raw I/O tests
int fpga_output_limit_enable(struct libusb_device_handle *handle, int enable);

// checks io_state (unless previously checked with fpga_select_setup_io)
// if input buffer isn't full - performs write
// used by simple_test.c, test.c
int fpga_write(struct fpga *fpga);

// requests read_limit (unless previously requested with fpga_select_setup_io) and performs read
// used by simple_test.c, test.c
int fpga_read(struct fpga *fpga);

// ! Synchronous write with pkt_comm - obsolete
int fpga_pkt_write(struct fpga *fpga);

// ! Synchronous read with pkt_comm - obsolete
int fpga_pkt_read(struct fpga *fpga);

#endif

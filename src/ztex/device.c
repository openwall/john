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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libusb-1.0/libusb.h>

#include "ztex.h"
#include "inouttraffic.h"
#include "ztex_scan.h"
#include "pkt_comm/pkt_comm.h"
#include "device.h"


int device_init_fpgas(struct device *device, struct device_bitstream *bitstream)
{
	int i;
	for (i = 0; i < device->num_of_fpgas; i++) {
		struct fpga *fpga = &device->fpga[i];

		int result = fpga_select(fpga);
		if (result < 0) {
			device_invalidate(device);
			return result;
		}

		//
		// Attn: on GSR, clocks remain at programmed frequency
		// Set FPGAs to default frequency before GSR
		//
		int clk_num;
		for (clk_num = 0; clk_num < bitstream->num_progclk; clk_num++)
			if (bitstream->freq[clk_num] > 0) {
				result = fpga_progclk(fpga, clk_num,
						bitstream->freq[clk_num]);
				if (result < 0)
					return result;
			}

		// Resets FPGA application with Global Set Reset (GSR)
		result = fpga_reset(device->handle);
		if (result < 0) {
			printf("SN %s #%d: device_fpga_reset: %d (%s)\n",
				device->ztex_device->snString,
				i, result, libusb_error_name(result));
			device_invalidate(device);
			return result;
		}

		fpga->comm = pkt_comm_new(&bitstream->pkt_comm_params);

	} // for
	return 0;
}

int device_list_init_fpgas(struct device_list *device_list, struct device_bitstream *bitstream)
{
	int ok_count = 0;
	struct device *device;
	for (device = device_list->device; device; device = device->next) {
		if (!device_valid(device))
			continue;

		int result = device_init_fpgas(device, bitstream);
		if (result < 0) {
			fprintf(stderr, "SN %s error %d initializing FPGAs.\n",
					device->ztex_device->snString, result);
			device_invalidate(device);
		}
		else
			ok_count ++;
	}
	return ok_count;
}


///////////////////////////////////////////////////////////////////
//
// Hardware Handling
//
// device_list_init() takes list of devices with uploaded firmware
// 1. upload bitstreams
// 2. initialize FPGAs
//
///////////////////////////////////////////////////////////////////

void device_list_init(struct device_list *device_list, struct device_bitstream *bitstream)
{
	// bitstream->type is hardcoded into bitstream (vcr.v/BITSTREAM_TYPE)
	if (!bitstream || !bitstream->type || !bitstream->path) {
		fprintf(stderr, "device_list_init(): invalid bitstream information\n");
		exit(-1);
	}

	int result = device_list_check_bitstreams(device_list, bitstream->type, bitstream->path);
	if (result < 0) {
		// fatal error
		exit(-1);
	}
	if (result > 0) {
		//usleep(3000);
		result = device_list_check_bitstreams(device_list, bitstream->type, NULL);
		if (result < 0) {
			exit(-1);
		}
	}

	device_list_init_fpgas(device_list, bitstream);

	// Application mode 2: use high-speed packet communication (pkt_comm)
	// that's the primary mode of operation as opposed to test modes 0 & 1.
	device_list_set_app_mode(device_list, 2);
}


///////////////////////////////////////////////////////////////////
//
// Top Level Hardware Initialization Function.
//
// device_timely_scan() takes the list of devices currently in use
//
// 1. Performs ztex_timely_scan()
// 2. Initialize devices
// 3. Returns list of newly found and initialized devices.
//
///////////////////////////////////////////////////////////////////

struct device_list *device_timely_scan(struct device_list *device_list, struct device_bitstream *bitstream)
{
	struct ztex_dev_list *ztex_dev_list_1 = ztex_dev_list_new();
	ztex_timely_scan(ztex_dev_list_1, device_list->ztex_dev_list);

	struct device_list *device_list_1 = device_list_new(ztex_dev_list_1);
	device_list_init(device_list_1, bitstream);

	return device_list_1;
}

struct device_list *device_init_scan(struct device_bitstream *bitstream)
{
	struct ztex_dev_list *ztex_dev_list = ztex_dev_list_new();
	ztex_init_scan(ztex_dev_list);

	struct device_list *device_list = device_list_new(ztex_dev_list);
	device_list_init(device_list, bitstream);

	return device_list;
}


void device_list_print(struct device_list *device_list)
{
	struct device *dev;
	for (dev = device_list->device; dev; dev = dev->next) {
		int num, j;
		int has_progclk = 0;

		printf("ZTEX %s bus:%d dev:%d",
				dev->ztex_device->snString, dev->ztex_device->busnum,
				dev->ztex_device->devnum);
		for (num = 0; num < dev->num_of_fpgas; num++) {
			for (j = 0; j < NUM_PROGCLK_MAX; j++) {
				if (!dev->fpga[num].freq[j])
					break;
				if (!has_progclk) {
					printf(" Frequency:");
					has_progclk = 1;
				}
				if (j > 0)
					printf(",");
				printf("%d", dev->fpga[num].freq[j]);
			}
			if (has_progclk)
				printf(" ");
		}
		printf("\n");
	}
}


///////////////////////////////////////////////////////////////////
//
// Perform read/write operations on the device
// using high-speed packet communication interface (pkt_comm).
//
// Return values:
// <0 - error (expecting caller to invalidate / reset the device)
// 0 - no data was actually send or received (because of either host or remote reasons)
// >0 - success, some data was sent or received
//
///////////////////////////////////////////////////////////////////

int device_pkt_rw(struct device *device)
{
	int data_transferred = 0;
	int result;
	int num;
	for (num = 0; num < device->num_of_fpgas; num++) {
		struct fpga *fpga = &device->fpga[num];

		// Get input buffer
		unsigned char *input_buf = pkt_comm_input_get_buf(fpga->comm);
		if (fpga->comm->error)
			return -1;
		// Input buffer is full - skip r/w operation
		if (!input_buf) {
			if (DEBUG) printf("fpga_pkt_rw(): input buffer is full\n");
			continue;
		}

		// fpga_select(), fpga_get_io_state(), fpga_setup_output() in 1 USB request
		result = fpga_select_setup_io(fpga);
		if (result < 0) {
			fprintf(stderr, "SN %s FPGA #%d fpga_select_setup_io() error: %d\n",
				device->ztex_device->snString, num, result);
			return result;
		}

		// TODO: human readable error description
		if (fpga->wr.io_state.pkt_comm_status) {
			fprintf(stderr, "SN %s FPGA #%d error: pkt_comm_status=0x%02x\n",
				device->ztex_device->snString, num, fpga->wr.io_state.pkt_comm_status);
			return -1;
		}

		if (fpga->wr.io_state.app_status) {
			fprintf(stderr, "SN %s FPGA #%d error: app_status=0x%02x\n",
				device->ztex_device->snString, num, fpga->wr.io_state.app_status);
			return -1;
		}

		if (fpga->wr.io_state.io_state & ~IO_STATE_INPUT_PROG_FULL) {
			fprintf(stderr, "SN %s FPGA #%d error: io_state=0x%02x\n",
				device->ztex_device->snString, num, fpga->wr.io_state.io_state);
			return -1;
		}

		int input_full = fpga->wr.io_state.io_state & IO_STATE_INPUT_PROG_FULL;
		if (input_full) {

			// FPGA input is full - no write
			if (DEBUG) printf("#%d write: Input full\n", num);

		} else {

			// Get output buffer
			int output_data_len = 0;
			unsigned char *output_data = pkt_comm_get_output_data(fpga->comm,
					&output_data_len);

			if (!output_data) {

				// No data for output - no write
				if (DEBUG) printf("fpga_pkt_write(): no data for output\n");

			} else {

				if (DEBUG >= 2) {
					int i;
					for (i=0; i < output_data_len; i++) {
						if (i && !(i%32)) printf("\n");
						printf("%02x ", output_data[i]);
					}
					printf("\n");
				}

				// Performing write
				int transferred = 0;
				result = libusb_bulk_transfer(fpga->device->handle, 0x06,
						output_data, output_data_len, &transferred, USB_RW_TIMEOUT);
				if (DEBUG) printf("#%d write: result=%d tx=%d/%d\n",
						fpga->num, result, transferred, output_data_len);
				if (result < 0) {
					return result;
				}
				if (transferred != output_data_len) {
					return ERR_WR_PARTIAL;
				}

				// Let pkt_comm register data transmit (clear buffers etc)
				pkt_comm_output_completed(fpga->comm, output_data_len, 0);
				data_transferred = 1;
			}
		} // output issues end


		// No data to read from FPGA - continue with next one
		int read_limit = fpga->rd.read_limit;
		if (!read_limit)
			continue;

		// Performing read
		int current_read_limit = read_limit;
		for ( ; ; ) {
			int transferred = 0;
			result = libusb_bulk_transfer(fpga->device->handle, 0x82, input_buf,
					current_read_limit, &transferred, USB_RW_TIMEOUT);
			if (DEBUG) printf("#%d read: result=%d, rx=%d/%d\n",
					fpga->num, result, transferred, current_read_limit);
			if (result < 0) {
				return result;
			}
			else if (transferred == 0) {
				return ERR_RD_ZEROREAD;
			}
			else if (transferred != current_read_limit) { // partial read
				if (DEBUG) printf("#%d PARTIAL READ: %d of %d\n",
						fpga->num, transferred, current_read_limit);
				current_read_limit -= transferred;
				fpga->rd.partial_read_count++;
				continue;
			}
			else
				break;
		} // for (;;)

		// Read completed.
		if (DEBUG >= 2) {
			int i;
			for (i=0; i < read_limit; i++) {
				if (i && !(i%32)) printf("\n");
				printf("%02x ", input_buf[i]);
			}
			printf("\n");
		}

		// Let pkt_comm handle data (process packets, place into input queue)
		result = pkt_comm_input_completed(fpga->comm, read_limit, 0);
		if (result < 0)
			return result;
		data_transferred = 1;
	}

	return data_transferred;
}


char *device_strerror(int error_code)
{
	static char buf[256];
	sprintf(buf, "%d unknown error", error_code);
	return buf;
}


/////////////////////////////////////////////////////////////////////////////////////

//unsigned long long wr_byte_count = 0, rd_byte_count = 0;

// - The function is obsolete
// - There's a glitch: when input buffer / queue is full,
// it still attempts to read resulting in FPGA error OUTPUT_LIMIT_NOT_DONE
// (FPGA started output operation and did not complete).
// Suggest usage of device_pkt_rw(struct device *device)
//
int device_fpgas_pkt_rw(struct device *device)
{
	int result;
	int num;
	for (num = 0; num < device->num_of_fpgas; num++) {

		struct fpga *fpga = &device->fpga[num];
		//if (!fpga->valid) // currently if r/w error on some FPGA, the entire device invalidated
		//	continue;

		//fpga_select(fpga); // unlike select_fpga() from Ztex SDK, it waits for i/o timeout
		result = fpga_select_setup_io(fpga); // combines fpga_select(), fpga_get_io_state() and fpga_setup_output() in 1 USB request
		if (result < 0) {
			fprintf(stderr, "SN %s FPGA #%d fpga_select_setup_io() error: %d\n",
				device->ztex_device->snString, num, result);
			return result;
		}

		if (fpga->wr.io_state.pkt_comm_status) {
			fprintf(stderr, "SN %s FPGA #%d error: pkt_comm_status=0x%02x\n",
				device->ztex_device->snString, num, fpga->wr.io_state.pkt_comm_status);
			return -1;
		}

		if (fpga->wr.io_state.app_status) {
			fprintf(stderr, "SN %s FPGA #%d error: app_status=0x%02x\n",
				device->ztex_device->snString, num, fpga->wr.io_state.app_status);
			return -1;
		}

		result = fpga_pkt_write(fpga);
		if (result < 0) {
			fprintf(stderr, "SN %s FPGA #%d write error: %d (%s)\n",
				device->ztex_device->snString, num, result, libusb_error_name(result));
			return result; // on such a result, device will be invalidated
		}
		//if (result > 0) {
			//wr_byte_count += result;
			//if ( wr_byte_count/1024/1024 != (wr_byte_count - result)/1024/1024 ) {
				//printf(".");
				//fflush(stdout);
		//	}
		//}

		// read
		result = fpga_pkt_read(fpga);
		if (result < 0) {
			fprintf(stderr, "SN %s FPGA #%d read error: %d (%s)\n",
				device->ztex_device->snString, num, result, libusb_error_name(result));
			return result; // on such a result, device will be invalidated
		}
		//if (result > 0)
		//	rd_byte_count += result;

	} // for ( ;num_of_fpgas ;)
	return 1;
}



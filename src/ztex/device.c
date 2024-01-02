/*
 *
 * Top Level Hardware Operating Functions for Ztex Multi-FPGA board.
 *
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
#include <libusb-1.0/libusb.h>

#include "../config.h"
#include "../misc.h"

#include "../ztex_common.h"
#include "ztex.h"
#include "inouttraffic.h"
#include "ztex_scan.h"
#include "pkt_comm/pkt_comm.h"
#include "pkt_comm/init_data.h"
#include "device.h"


#define CONFIG_MAX_LEN	256

// boards are in "no comparison" mode
int device_nocompar_mode = 0;

static int hex_digit2bin(char digit)
{
	if (digit >= '0' && digit <= '9')
		return digit - '0';
	if (digit >= 'a' && digit <= 'f')
		return digit - 'a' + 10;
	if (digit >= 'A' && digit <= 'F')
		return digit - 'A' + 10;
	return -1;
}

// Convert hexadecimal ascii string e.g. \x0c\x00 into binary string
// TODO: consider moving into src/config.c
static char *hex_string2bin(const char *src, int *len)
{
	static char dst[CONFIG_MAX_LEN];

	if (!src) {
		fprintf(stderr, "NULL pointer in device.c:hex_string2bin()\n");
		error();
	}
	*len = 0;

	int i;
	for (i = 0; ; i = i + 4) {
		if (!src[i])
			break;
		if (src[i] != '\\' || !src[i+1] || src[i+1] != 'x'
				|| !src[i+2] || !src[i+3]) {
			fprintf(stderr, "Invalid hex string in john.conf: %s\n", src);
			error();
		}

		int upper = hex_digit2bin(src[i+2]);
		int lower = hex_digit2bin(src[i+3]);
		if (upper == -1 || lower == -1) {
			fprintf(stderr, "Invalid hex digit in john.conf: %s\n", src);
			error();
		}

		dst[(*len)++] = upper << 4 | lower;
		if (*len == CONFIG_MAX_LEN) {
			fprintf(stderr, "Hex string in john.conf of exceeds %d hex "
				"chars: %s\n", CONFIG_MAX_LEN, src);
			error();
		}
	}

	if (!*len) {
		fprintf(stderr, "Empty hex string in john.conf\n");
		error();
	}
	return dst;
}


static int device_init_fpgas(struct device *device,
		struct device_bitstream *bitstream)
{
	// Read config for given bitstream, device
	char *CFG_SECTION = "ZTEX:";
	// conf_name_board_freq must be shorter than conf_name_freq to avoid a
	// gcc-9 compiler warning. But at least 21 bytes to make the string fit.
	char conf_name_board_freq[128], conf_name_freq[256];
	int default_freq[NUM_PROGCLK_MAX], board_freq[NUM_PROGCLK_MAX],
		fpga_freq[NUM_PROGCLK_MAX];

	// Frequency
	if (bitstream->num_progclk) {
		// Default frequency (for every device for given bitstream)
		cfg_get_int_array(CFG_SECTION, bitstream->label, "Frequency",
				default_freq, NUM_PROGCLK_MAX);

		// Frequency specific to given board
		snprintf(conf_name_board_freq, sizeof(conf_name_board_freq),
				"Frequency_%s", device->ztex_device->snString);
		cfg_get_int_array(CFG_SECTION, bitstream->label,
				conf_name_board_freq, board_freq, NUM_PROGCLK_MAX);

		if (board_freq[0] == -1 && default_freq[0] != -1)
			memcpy(board_freq, default_freq, sizeof(board_freq));
	}

	// TODO: rewrite
	//  (if more subtypes of a configuration packet appear).
	//
	// Runtime configuration packet.
	// Only subtype 1 is currently supported.
	// Length is specific to bitstream.
	// If configuration packet is of incorrect length then
	// the FPGA would raise an error (app_status=0x08)
	char conf_name_board_config1[128], conf_name_config1[256];
	char default_config1[CONFIG_MAX_LEN], board_config1[CONFIG_MAX_LEN];
	int len_default, len_board, len;

	const char *ptr;
	ptr = cfg_get_param(CFG_SECTION, bitstream->label, "Config1");
	if (ptr) {
		char *hex_str = hex_string2bin(ptr, &len_default);
		strncpy(default_config1, hex_str, len_default);
	} else
		len_default = 0;

	snprintf(conf_name_board_config1, sizeof(conf_name_board_config1),
			"Config1_%s", device->ztex_device->snString);
	ptr = cfg_get_param(CFG_SECTION, bitstream->label,
			conf_name_board_config1);
	if (ptr) {
		char *hex_str = hex_string2bin(ptr, &len_board);
		strncpy(board_config1, hex_str, len_board);
	} else {
		len_board = len_default;
		strncpy(board_config1, default_config1, len_default);
	}

	int fpga_num;
	for (fpga_num = 0; fpga_num < device->num_of_fpgas; fpga_num++) {
		struct fpga *fpga = &device->fpga[fpga_num];

		int result = fpga_select(fpga);
		if (result < 0) {
			device_invalidate(device);
			return result;
		}

		// Attn: on GSR, clocks remain at programmed frequency
		// Set FPGAs to given frequency before GSR
		if (bitstream->num_progclk) {

			// Check for frequency for given fpga in the config
			snprintf(conf_name_freq, sizeof(conf_name_freq), "%s_%d", conf_name_board_freq, fpga_num + 1);
			cfg_get_int_array(CFG_SECTION, bitstream->label, conf_name_freq,
					fpga_freq, NUM_PROGCLK_MAX);

			int clk_num;
			for (clk_num = 0; clk_num < bitstream->num_progclk; clk_num++) {
				int freq =
					fpga_freq[clk_num] != -1 ? fpga_freq[clk_num] :
					board_freq[clk_num] != -1 ? board_freq[clk_num] :
					bitstream->freq[clk_num];

				int result = fpga_progclk(fpga, clk_num, freq);
				if (result < 0)
					return result;
			}

			for ( ; clk_num < NUM_PROGCLK_MAX; clk_num++)
				fpga->freq[clk_num] = 0;
		}


		// Reset FPGA application with Global Set Reset (GSR)
		// Affected is FPGA previously selected with fpga_select()
		result = fpga_reset(device->handle);
		if (result < 0) {
			fprintf(stderr, "SN %s #%d: device_fpga_reset: %d (%s)\n",
				device->ztex_device->snString,
				fpga_num + 1, result, libusb_error_name(result));
			device_invalidate(device);
			return result;
		}


		fpga->comm = pkt_comm_new(&bitstream->pkt_comm_params);

		// Initialization packet (must be the 1st packet after GSR)
		if (bitstream->init_len > 1 || bitstream->init_len < 0) {
			fprintf(stderr, "Bad or unsupported bitstream->"
				"init_len=%d\n", bitstream->init_len);
			error();
		}
		else if (bitstream->init_len == 1) {
			struct pkt *pkt_init
				= pkt_init_data_1b_new(bitstream->init_data[0]);
			pkt_queue_push(fpga->comm->output_queue, pkt_init);
		}

		// Runtime configuration packet
		struct pkt *pkt_config1 = NULL;

		snprintf(conf_name_config1, sizeof(conf_name_config1),
				"%s_%d", conf_name_board_config1,
				fpga_num + 1);
		ptr = cfg_get_param(CFG_SECTION, bitstream->label,
				conf_name_config1);
		if (ptr) {
			char *hex_str = hex_string2bin(ptr, &len);
			pkt_config1 = pkt_config_new(1, hex_str, len);
		} else if (len_board)
			pkt_config1 = pkt_config_new(1, board_config1, len_board);

		if (pkt_config1)
			pkt_queue_push(fpga->comm->output_queue, pkt_config1);


	} // for fpga
	return 0;
}


static int device_list_init_fpgas(struct device_list *device_list,
		struct device_bitstream *bitstream)
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

void device_list_init(struct device_list *device_list,
		struct device_bitstream *bitstream)
{
	// bitstream->type is hardcoded into bitstream (vcr.v/BITSTREAM_TYPE)
	if (!bitstream || !bitstream->type || !bitstream->path) {
		fprintf(stderr, "device_list_init(): invalid bitstream information\n");
		error();
	}

	int result = device_list_check_bitstreams(device_list, bitstream->type, bitstream->path);
	if (result < 0) {
		// fatal error
		error();
	}
	if (result > 0) {
		//usleep(3000);
		result = device_list_check_bitstreams(device_list, bitstream->type, NULL);
		if (result < 0) {
			error();
		}
	}

	device_list_init_fpgas(device_list, bitstream);

	if (device_nocompar_mode)
		device_list_set_app_mode(device_list, 0x40);
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
	ztex_timely_scan(ztex_dev_list_1, device_list->ztex_dev_list,
		ztex_use_list);

	struct device_list *device_list_1 = device_list_new(ztex_dev_list_1);
	device_list_init(device_list_1, bitstream);

	return device_list_1;
}

struct device_list *device_init_scan(struct device_bitstream *bitstream)
{
	struct ztex_dev_list *ztex_dev_list = ztex_dev_list_new();
	ztex_init_scan(ztex_dev_list, ztex_use_list);

	struct device_list *device_list = device_list_new(ztex_dev_list);
	device_list_init(device_list, bitstream);

	return device_list;
}


void device_list_print(struct device_list *device_list)
{
	struct device *dev;
	for (dev = device_list->device; dev; dev = dev->next) {
		if (!device_valid(dev))
			continue;

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
				device->ztex_device->snString, num + 1, result);
			return result;
		}

		// TODO: human readable error description
		if (fpga->wr.io_state.pkt_comm_status) {
			fprintf(stderr, "SN %s FPGA #%d error: pkt_comm_status=0x%02x,"
				" debug=0x%04x\n", device->ztex_device->snString, num + 1,
				fpga->wr.io_state.pkt_comm_status,
				fpga->wr.io_state.debug3 << 8 | fpga->wr.io_state.debug2);
			return -1;
		}

		if (fpga->wr.io_state.app_status) {
			fprintf(stderr, "SN %s FPGA #%d error: app_status=0x%02x,"
				" debug=0x%04x\n", device->ztex_device->snString, num + 1,
				fpga->wr.io_state.app_status,
				fpga->wr.io_state.debug3 << 8 | fpga->wr.io_state.debug2);
			return -1;
		}

		if (fpga->wr.io_state.io_state & ~IO_STATE_INPUT_PROG_FULL) {
			fprintf(stderr, "SN %s FPGA #%d error: io_state=0x%02x\n",
				device->ztex_device->snString, num + 1,
				fpga->wr.io_state.io_state);
			return -1;
		}

		int input_full = fpga->wr.io_state.io_state & IO_STATE_INPUT_PROG_FULL;
		if (input_full) {

			// FPGA input is full - no write
			if (DEBUG) printf("#%d write: Input full\n", num + 1);

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
						fpga->num + 1, result, transferred, output_data_len);
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
					fpga->num + 1, result, transferred, current_read_limit);
			if (result < 0) {
				return result;
			}
			else if (transferred == 0) {
				return ERR_RD_ZEROREAD;
			}
			else if (transferred != current_read_limit) { // partial read
				if (DEBUG) printf("#%d PARTIAL READ: %d of %d\n",
						fpga->num + 1, transferred, current_read_limit);
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
	snprintf(buf, sizeof(buf), "%d unknown error", error_code);
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
				device->ztex_device->snString, num + 1, result);
			return result;
		}

		if (fpga->wr.io_state.pkt_comm_status) {
			fprintf(stderr, "SN %s FPGA #%d error: pkt_comm_status=0x%02x\n",
				device->ztex_device->snString, num + 1, fpga->wr.io_state.pkt_comm_status);
			return -1;
		}

		if (fpga->wr.io_state.app_status) {
			fprintf(stderr, "SN %s FPGA #%d error: app_status=0x%02x\n",
				device->ztex_device->snString, num + 1, fpga->wr.io_state.app_status);
			return -1;
		}

		result = fpga_pkt_write(fpga);
		if (result < 0) {
			fprintf(stderr, "SN %s FPGA #%d write error: %d (%s)\n",
				device->ztex_device->snString, num + 1, result, libusb_error_name(result));
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
				device->ztex_device->snString, num + 1, result, libusb_error_name(result));
			return result; // on such a result, device will be invalidated
		}
		//if (result > 0)
		//	rd_byte_count += result;

	} // for ( ;num_of_fpgas ;)
	return 1;
}

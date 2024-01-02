/*
 * This software is Copyright (c) 2016-2017 Denis Burykin
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
#include <errno.h>
#include <libusb-1.0/libusb.h>

#include "ztex.h"
#include "inouttraffic.h"
#include "pkt_comm/pkt_comm.h"

#include "../path.h"

int DEBUG = 0;

int fpga_get_io_state(struct libusb_device_handle *handle, struct fpga_io_state *io_state)
{
	int result = vendor_request(handle, 0x84, 0, 0, (unsigned char *)io_state, sizeof(io_state));
	if (DEBUG) printf("get_io_state: %x %x %x pkt: 0x%x debug: 0x%x 0x%x\n",
		io_state->io_state, io_state->timeout, io_state->app_status,
		io_state->pkt_comm_status, io_state->debug2, io_state->debug3);
	return result;
}

// with output limit enabled, FPGA would not send data
// until fpga_setup_output()
// enabled by default
int fpga_output_limit_enable(struct libusb_device_handle *handle, int enable)
{
	int result = vendor_command(handle, 0x86, enable, 0, NULL, 0);
	return result;
}

// 1. returns number of bytes in FPGA's output FIFO
// 2. FPGA starts output of that many
int fpga_setup_output(struct libusb_device_handle *handle)
{
	unsigned char output_limit[2] = {0,0};
	// vendor_request returns in output FIFO words (OUTPUT_WORD_WIDTH bytes)
	int result = vendor_request(handle, 0x85, 0, 0, output_limit, 2);
	if (DEBUG) printf("output limit: %d\n", OUTPUT_WORD_WIDTH * ((output_limit[1] << 8) + output_limit[0]) );
	if (result < 0)
		return result;
	else
		return OUTPUT_WORD_WIDTH* (unsigned int)( (output_limit[1] << 8) + output_limit[0]);
}

// Inouttraffic bitstreams have High-Speed interface disabled by default.
// fpga_reset() enables High-Speed interface.
// consider device_fpga_reset() to reset all FPGA's on device
int fpga_reset(struct libusb_device_handle *handle)
{
	int result = vendor_command(handle, 0x8B, 0, 0, NULL, 0);
	return result;
}

// enable/disable high-speed output.
// FPGA comes with High-Speed I/O (hs_io) disabled.
// Application usually would not need this:
// hs_io status changes internally by e.g. fpga_select() and fpga_reset().
int fpga_hs_io_enable(struct libusb_device_handle *handle, int enable)
{
	int result = vendor_command(handle, 0x80, enable, 0, NULL, 0);
	return result;
}


// =======================================================================
//
// Following functions all use 'struct device' and 'struct fpga'
//
// =======================================================================

// Creates 'struct device' on top of 'struct ztex_device'
struct device *device_new(struct ztex_device *ztex_device)
{
	struct device *device = malloc(sizeof(struct device));
	if (!device)
		return NULL;
	device->ztex_device = ztex_device;
	device->handle = ztex_device->handle;
	device->num_of_fpgas = ztex_device->num_of_fpgas;
	device->selected_fpga = ztex_device->selected_fpga;
	device->num_of_valid_fpgas = 0;

	int i;
	for (i = 0; i < device->num_of_fpgas; i++) {
		device->fpga[i].device = device;
		device->fpga[i].num = i;
		device->fpga[i].valid = 0;
		device->fpga[i].wr.io_state_valid = 0;
		device->fpga[i].wr.io_state_timeout_count = 0;
		device->fpga[i].wr.wr_count = 0;
		device->fpga[i].rd.read_limit_valid = 0;
		device->fpga[i].rd.read_count = 0;
		device->fpga[i].rd.partial_read_count = 0;
		device->fpga[i].cmd_count = 0;
		// packet-based communication
		device->fpga[i].comm = NULL;

		int j;
		for (j = 0; j < NUM_PROGCLK_MAX; j ++)
			device->fpga[i].freq[j] = 0;
	}

	device->valid = 1;
	return device;
}

void device_delete(struct device *device)
{
	device_invalidate(device);
	free(device);
}

// device usually invalidated if there's some error
// underlying ztex_device also invalidated
void device_invalidate(struct device *device)
{
	if (!device || !device->valid)
		return;
	device->valid = 0;

	int i;
	for (i = 0; i < device->num_of_fpgas; i++) {
		if (device->fpga[i].comm)
			pkt_comm_delete(device->fpga[i].comm);
	}

	ztex_device_invalidate(device->ztex_device);
}

int device_valid(struct device *device)
{
	return device && device->valid;
}

// Performs fpga_reset() on all FPGA's
// It resets FPGAs to its post-configuration state with Global Set Reset (GSR).
//
// Return values:
// < 0 error; would require heavier reset
//
// Issue. What if only 1 of onboard FPGAs has error.
// Currently following approarch used:
// Initialization functions (soft_reset, check_bitstream) initialize all onboard FPGAs.
// On any error, entire device is put into invalid state.
int device_fpga_reset(struct device *device)
{
	if (DEBUG) printf("SN %s: device_fpga_reset()\n", device->ztex_device->snString);

	int result;
	int i;
	for (i = 0; i < device->num_of_fpgas; i++) {
		struct fpga *fpga = &device->fpga[i];

		result = fpga_select(fpga);
		if (result < 0)
			return result;

		result = fpga_reset(device->handle);
		if (result < 0) {
			printf("SN %s #%d: device_fpga_reset: %d (%s)\n", device->ztex_device->snString,
					i + 1, result, libusb_error_name(result));
			return result;
		}
		fpga->wr.wr_count = 0;
	}
	return 0;
}

struct device_list *device_list_new(struct ztex_dev_list *ztex_dev_list)
{
	struct device_list *device_list = malloc(sizeof(struct device_list));
	if (!device_list)
		return NULL;
	device_list->device = NULL;
	device_list->ztex_dev_list = ztex_dev_list;
	if (!ztex_dev_list)
		return device_list;

	struct ztex_device *ztex_dev;
	struct device *device;
	for (ztex_dev = ztex_dev_list->dev; ztex_dev; ztex_dev = ztex_dev->next) {
		if (!ztex_device_valid(ztex_dev))
			continue;
		device = device_new(ztex_dev);
		if (!device)
			continue;
		device_list_add(device_list, device);
	}
	return device_list;
}

void device_list_add(struct device_list *device_list, struct device *device)
{
	device->next = device_list->device;
	device_list->device = device;
}

int device_list_merge(struct device_list *device_list, struct device_list *added_list)
{
	if (!device_list || !added_list) {
		printf("device_list_merge: invalid arguments\n");
		return 0;
	}
	int count = 0;
	struct device *dev, *dev_next;
	for (dev = added_list->device; dev; dev = dev_next) {
		dev_next = dev->next;
		if (DEBUG) printf("device_list_merge: SN %s, valid %d, next: %d\n",
				dev->ztex_device->snString, dev->valid, !!dev_next);
		if (!device_valid(dev)) {
			device_delete(dev);
			continue;
		}
		device_list_add(device_list, dev);
		count++;
	}

	int ztex_dev_count = ztex_dev_list_merge(device_list->ztex_dev_list,
			added_list->ztex_dev_list);
	if (ztex_dev_count != count) {
		printf("device_list_merge: ztex count %d, device count %d\n",
				ztex_dev_count, count);
	}

	//added_list->dev = NULL;
	free(added_list);
	return count;
}

void device_list_delete(struct device_list *device_list)
{
	if (!device_list)
		return;

	struct device *dev, *dev_next;
	for (dev = device_list->device; dev; dev = dev_next) {
		dev_next = dev->next;
		device_delete(dev);
	}
	free(device_list);
}

int device_list_count(struct device_list *device_list)
{
	int count = 0;
	struct device *device;
	if (!device_list)
		return 0;
	for (device = device_list->device; device; device = device->next)
		if (device_valid(device))
			count++;
	return count;
}

int fpga_test_get_id(struct fpga *fpga)
{
	const int MAGIC_W = 0x5A5A;
	struct fpga_echo_request echo;
	echo.out[0] = random();
	echo.out[1] = random();
	int result = vendor_request(fpga->device->handle, 0x88, echo.out[0], echo.out[1],
		(unsigned char *)&echo.reply, sizeof(echo.reply));
	int test_ok =
		(echo.reply.data[0] ^ MAGIC_W) == echo.out[0]
		&& (echo.reply.data[1] ^ MAGIC_W) == echo.out[1];
	if (test_ok)
		fpga->bitstream_type = echo.reply.bitstream_type;
	else
		fpga->bitstream_type = 0;

	if (DEBUG) {
		printf("fpga_test_get_id(%d): request 0x%04X 0x%04X, reply 0x%04X 0x%04X",
			fpga->num + 1, echo.out[0], echo.out[1], echo.reply.data[0], echo.reply.data[1]);
		if (!test_ok) printf(" (must be 0x%04X 0x%04X)", echo.out[0] ^ MAGIC_W, echo.out[1] ^ MAGIC_W);
		else printf("(ok)");
		printf(", fpga_id %d, bitstream_type 0x%04X\n",
			echo.reply.fpga_id, echo.reply.bitstream_type);
	}
	if (result < 0)
		return result;
	else
		return test_ok && fpga->num == echo.reply.fpga_id;
}


// Return value:
// > 0 all FPGA's has bitstream of specified type
// 0 at least 1 FPGA has no bitstream or bitstream of other type
// < 0 error
int device_check_bitstream_type(struct device *device, unsigned short bitstream_type)
{
	if (!device)
		return -1;

	int i;
	for (i = 0; i < device->num_of_fpgas; i++) {
		int result;
		result = ztex_select_fpga(device->ztex_device, i);//fpga_select(&device->fpga[i]);
		if (result < 0)
			return result;
		result = fpga_test_get_id(&device->fpga[i]);
		//if (DEBUG)
		//printf("device_check_bitstream_type: id=%d, result=%d\n",i,result);
		if (result < 0)
			return result;
		if (result > 0) {
			if (device->fpga[i].bitstream_type != bitstream_type)
				return 0;
			//device->fpga[i].valid = 1;
			//device->num_of_valid_fpgas ++;
		}
		else {
			return 0;
			//device->fpga[i].valid = 0; // no bitstream
		}
	}
	return 1;
}

////////////////////////////////////////////////////////////////////////////////////////
//
// Checks if bitstreams on devices are loaded and of specified type.
// if (filename != NULL) performs upload in case of wrong or no bitstream
//
// If bitstream doesn't function properly - device invalidated
//
// Returns: number of devices with bitstreams uploaded
// < 0 on fatal error
int device_list_check_bitstreams(struct device_list *device_list, unsigned short BITSTREAM_TYPE, char *filename)
{
	int ok_count = 0;
	int uploaded_count = 0;
	int do_upload = filename != NULL;
	FILE *fp = NULL;
	struct device *device;

	for (device = device_list->device; device; device = device->next) {
		if (!device->valid)
			continue;

		int result;
		result = device_check_bitstream_type(device, BITSTREAM_TYPE);
		if (result > 0) {
			ok_count ++;
			continue;
		}
		else if (result < 0) {
			printf("SN %s: device_list_check_bitstreams() failed: %d\n",
				device->ztex_device->snString, result);
			device_invalidate(device);
			continue;
		}

		if (!do_upload) {
			printf("SN %s: device_list_check_bitstreams(): no bitstream or wrong type\n",
				device->ztex_device->snString);
			device_invalidate(device);
			continue;
		}

		if (!fp)
			if ( !(fp = fopen(path_expand(filename), "r")) ) {
				printf("fopen(%s): %s\n", path_expand(filename), strerror(errno));
				return -1;
			}
		printf("SN %s: uploading bitstreams.. ", device->ztex_device->snString);
		fflush(stdout);

		result = ztex_upload_bitstream(device->ztex_device, fp);
		if (result < 0) {
			printf("failed\n");
			device_invalidate(device);
		}
		else {
			printf("ok\n");
			ok_count ++;
			uploaded_count ++;
		}
	}
	if (fp)
		fclose(fp);
	return ok_count;
}

int fpga_set_app_mode(struct fpga *fpga, int app_mode)
{
	int result = vendor_command(fpga->device->handle, 0x82, app_mode, 0, NULL, 0);
	fpga->cmd_count++;
	if (DEBUG) printf("fpga_set_app_mode(%d): %d\n", fpga->num + 1, app_mode);
	return result;
}

int device_list_set_app_mode(struct device_list *device_list, int app_mode)
{
	int count = 0;
	struct device *device;
	for (device = device_list->device; device; device = device->next) {
		if (!device_valid(device))
			continue;

		int result;
		int i;
		for (i = 0; i < device->num_of_fpgas; i++) {
			struct fpga *fpga = &device->fpga[i];
			result = fpga_select(fpga);
			if (result < 0) {
				device_invalidate(device);
				break;
			}
			result = fpga_set_app_mode(fpga, app_mode);
			if (result < 0) {
				printf("SN %s set_app_mode %d: error %d (%s).\n", device->ztex_device->snString,
					app_mode, result, libusb_error_name(result));
				device_invalidate(device);
				break;
			}
		} // for (fpga)
		count ++;

	} // for (device)
	return count;
}

int device_list_fpga_reset(struct device_list *device_list)
{
	int count = 0;
	struct device *device;
	for (device = device_list->device; device; device = device->next) {
		if (!device_valid(device))
			continue;

		int result = device_fpga_reset(device);
		if (result < 0) {
			device_invalidate(device);
			continue;
		}
		count++;
	}
	return count;
}

// unlike ztex_select_fpga(), it waits for I/O timeout
int fpga_select(struct fpga *fpga)
{
	int result = vendor_command(fpga->device->handle, 0x8E, fpga->num,
			0, NULL, 0);
	fpga->cmd_count++;
	if (DEBUG) printf("fpga_select(%d): %d\n", fpga->num + 1, result);
	if (result < 0) {
		printf("fpga_select(%d): %s\n", fpga->num + 1, libusb_error_name(result));
	}
	return result;
}

// combines fpga_select(), fpga_get_io_state(), fpga_setup_output() in 1 USB request
int fpga_select_setup_io(struct fpga *fpga)
{
	struct fpga_status fpga_status;
	int result = vendor_request(fpga->device->handle, 0x8C, fpga->num, 0,
		(unsigned char *)&fpga_status, sizeof(fpga_status));
	fpga->cmd_count++;
	if (result < 0)
		return result;
	fpga_status.read_limit *= OUTPUT_WORD_WIDTH;
	if (DEBUG) {
		struct fpga_io_state *io_state = &fpga_status.io_state;
		printf("fpga_select_setup_io(%d): state 0x%02x 0x%02x 0x%02x "
				"- 0x%02x 0x%02x 0x%02x, limit %u\n",
			fpga->num + 1,
			io_state->io_state, io_state->timeout, io_state->app_status,
			io_state->pkt_comm_status, io_state->debug2, io_state->debug3,
			fpga_status.read_limit);
	}
	fpga->wr.io_state = fpga_status.io_state;
	fpga->wr.io_state_valid = 1;
	fpga->rd.read_limit = fpga_status.read_limit;
	fpga->rd.read_limit_valid = 1;
	return result;
}


int fpga_progclk_raw(struct fpga *fpga, int clk_num,
		int d_value, int m_value)
{
	int result = vendor_command(fpga->device->handle, 0x93,
			fpga->num | clk_num << 8, d_value | m_value << 8, NULL, 0);
	if (result < 0)
		fprintf(stderr, "fpga_progclk_raw(%d): %s\n", fpga->num + 1,
			libusb_error_name(result));
	return result;
}


int fpga_progclk(struct fpga *fpga, int clk_num, int freq)
{
	if (DEBUG)
		fprintf(stderr, "fpga_progclk(%d,%d,%d)\n", fpga->num + 1,
				clk_num, freq);

	const struct {
		int freq, m, d;
	} freq_values[] = {
		{135,36,81},// {,,}, {,,}, {,,}, {,,},
		{140,35,76}, {141,38,82}, {142,35,75}, {143,32,68}, {144,37,78},
		{145,31,65}, {146,37,77}, {147,29,60}, {148,37,76}, {149,24,49},
		{150,31,63}, {151,39,79}, {152,39,78}, {153,39,77}, {154,32,63},
		{155,25,49}, {156,39,76}, {157,31,60}, {158,39,75}, {159,34,65},
		{160,30,57}, {161,36,68}, {162,32,60}, {163,37,69}, {164,34,63},
		{165,38,70}, {166,36,66}, {167,39,71}, {168,37,67}, {169,35,63},
		{170,33,59}, {171,36,64}, {172,39,69}, {173,37,65}, {174,36,63},
		{175,38,66}, {176,33,57}, {177,39,67}, {178,31,53}, {179,30,51},
		{180,29,49}, {181,31,52}, {182,39,65}, {183,38,63}, {184,23,38},
		{185,31,51},  {187,32,52},
		{190,35,56},  {192,36,57},
		{195,25,39},  {197,35,54},
		{200,27,41},  {202,38,57},
		{205,33,49},  {207,32,47},
		{210,38,55},  {212,39,56},
		{215,29,41},  {217,35,49},
		{220,21,29}, {221,32,44}, {222,27,37}, {223,33,45}, {224,28,38},
		{225,20,27}, {226,32,43}, {227,38,51}, {228,39,52}, {229,37,49},
		{230,31,41}, {231,38,50}, {232,29,38}, {233,23,30}, {234,37,48},
		{235,34,44}, {236,35,45}, {237,39,50}, {238,29,37}, {239,37,47},
		{240,30,38}, {241,23,29}, {242,39,49}, {243,36,45}, {244,37,46},
		{245,25,31}, {246,34,42}, {247,39,48}, {248,31,38}, {249,32,39},
		{250,37,45}, {251,33,40}, {252,34,41}, {253,35,42}, {254,36,43},
		{255,21,25},  {257,33,39},
		{260,35,41},  {262,31,36},
		{265,34,39},  {267,37,42},
		{270,32,36},  {272,34,38},
		{275,38,42},  {277,31,34},
		{280,35,38},  {282,39,42},
		{285,30,32},
		{290,21,22},
		{295,33,34},
		{310,39,38},
		{330,25,23},
		{350,23,20},
		{0}
	};

	if (freq < freq_values[0].freq) {
		fprintf(stderr, "fpga_progclk(%d, %d, %d): Min. allowed frequency"
			" is %d MHz\n", fpga->num + 1, clk_num, freq, freq_values[0].freq);
		return -1;
	}

	int i;
	for (i = 1; freq_values[i].freq; i++) {
		if (freq < freq_values[i].freq)
			break;
	}

	if (!freq_values[i].freq && freq > 1.5 * freq_values[i-1].freq) {
		fprintf(stderr, "fpga_progclk(%d, %d, %d): Max. possible frequency"
			" is %d MHz\n", fpga->num + 1, clk_num, freq, freq_values[i-1].freq);
		return -1;
	}

	int result = fpga_progclk_raw(fpga, clk_num, freq_values[i-1].d,
			freq_values[i-1].m);

	if (result < 0)
		return result;
	else {
		fpga->freq[clk_num] = freq_values[i-1].freq;
		return freq_values[i-1].freq;
	}
}


// ***************************************************************
//
// Functions below are used by tests or obsolete.
// For operating the board, use top-level functions from device.c
//
// ***************************************************************

// in OUTPUT_WORD_WIDTH-byte words, default 0. It doesn't register output limit if amount is below output_limit_min
// if output_limit_min happens to be greater than buffer size, limit_min equal to buffer size is used.
// * This works but looks like not useful, it's commented out in FPGA application
//int fpga_set_output_limit_min(struct fpga *fpga, unsigned short limit_min)
//{
//	int result = vendor_command(fpga->device->handle, 0x83, limit_min, 0, NULL, 0);
//	fpga->cmd_count++;
//	if (DEBUG) printf("fpga_set_output_limit_min: %d\n", limit_min);
//	return result;
//}

// checks io_state (if necessary) and performs write
int fpga_write(struct fpga *fpga)
{
	struct fpga_wr *wr = &fpga->wr;
	wr->wr_done = 0;
	struct fpga_io_state *io_state = &wr->io_state;
	int result;

	if (!wr->io_state_valid) {
		result = fpga_get_io_state(fpga->device->handle, io_state);
		fpga->cmd_count++;
		if (result < 0) {
			return result;
		}
		if (io_state->timeout < 1) {
			if (++wr->io_state_timeout_count >= 2) // timeout value in ~usecs
				return ERR_IO_STATE_TIMEOUT;
			else
				return 0; // write not performed
			if (DEBUG) printf("#%d io_state.timeout = %d, skipping write\n",
				fpga->num + 1, io_state->timeout);
		}
		// fpga_get_io_state() OK
		wr->io_state_timeout_count = 0;
	}
	wr->io_state_valid = 0; // io_state is used

	//if (io_state->io_state & IO_STATE_OUTPUT_ERR_OVERFLOW) {
	//	return ERR_IO_STATE_OVERFLOW;
	//}
	if (io_state->io_state & IO_STATE_LIMIT_NOT_DONE) {
		return ERR_IO_STATE_LIMIT_NOT_DONE;
	}
	if (io_state->io_state & IO_STATE_SFIFO_NOT_EMPTY) {
		return ERR_IO_STATE_SFIFO_NOT_EMPTY;
	}
	if (io_state->io_state & ~IO_STATE_INPUT_PROG_FULL) {
		printf("Unknown error: io_state=0x%02X\n", io_state->io_state);
		return -1;
	}
	if (io_state->io_state & IO_STATE_INPUT_PROG_FULL) {
		if (DEBUG) printf("#%d fpga_write_do(): Input full\n", fpga->num + 1);
		return 0; // Input full, no write
	}

	int transferred = 0;
	result = libusb_bulk_transfer(fpga->device->handle, 0x06, wr->buf, wr->len, &transferred, USB_RW_TIMEOUT);
	if (DEBUG) printf("#%d fpga_write(): %d %d\n", fpga->num + 1, result, transferred);
	if (result < 0) {
		return result;
	}
	if (transferred != wr->len) {
		return ERR_WR_PARTIAL;
	}
	wr->wr_count++;
	wr->wr_done = 1;
	return transferred;
}

// requests read_limit (if necessary) and performs read
int fpga_read(struct fpga *fpga)
{
	struct fpga_rd *rd = &fpga->rd;
	rd->rd_done = 0;
	int result;
	int current_read_limit;

	if (!rd->read_limit_valid) {
		result = fpga_setup_output(fpga->device->handle);
		fpga->cmd_count++;
		if (result < 0) {
			//fprintf(stderr, "fpga_setup_output() returned %d\n", result);
			return result;
		}
		else if (result == 0) { // Nothing to read
			if (DEBUG) printf("#%d read_limit==0\n", fpga->num + 1);
			return 0;
		}
		rd->read_limit = result;
	}
	rd->read_limit_valid = 0;
	if (!rd->read_limit)
		return 0;

	current_read_limit = rd->read_limit;
	int offset = 0;
	for ( ; ; ) {
		int transferred = 0;
		result = libusb_bulk_transfer(fpga->device->handle, 0x82, rd->buf + offset,
				current_read_limit, &transferred, USB_RW_TIMEOUT);
		if (DEBUG) printf("#%d usb_bulk_read(): result=%d, transferred=%d, current_read_limit=%d\n",
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
			offset += transferred;
			rd->partial_read_count++;
			continue;
		}
		else {
			break;
		}
	} // for (;;)
	rd->read_count++;
	rd->rd_done = 1;
	rd->len = rd->read_limit;
	return rd->read_limit;
}


// Synchronous write with pkt_comm (packet communication)
int fpga_pkt_write(struct fpga *fpga)
{
	struct fpga_wr *wr = &fpga->wr;
	wr->wr_done = 0;
	struct fpga_io_state *io_state = &wr->io_state;
	int result;

	if (!wr->io_state_valid) {
		result = fpga_get_io_state(fpga->device->handle, io_state);
		fpga->cmd_count++;
		if (result < 0) {
			return result;
		}
		if (io_state->timeout < 1) {
			if (++wr->io_state_timeout_count >= 2) // timeout value in ~usecs
				return ERR_IO_STATE_TIMEOUT;
			else
				return 0; // write not performed
			if (DEBUG) printf("#%d io_state.timeout = %d, skipping write\n",
				fpga->num + 1, io_state->timeout);
		}
		// fpga_get_io_state() OK
		wr->io_state_timeout_count = 0;
	}
	wr->io_state_valid = 0; // io_state is used

	//if (io_state->io_state & IO_STATE_OUTPUT_ERR_OVERFLOW) {
	//	return ERR_IO_STATE_OVERFLOW;
	//}
	if (io_state->io_state & IO_STATE_LIMIT_NOT_DONE) {
		return ERR_IO_STATE_LIMIT_NOT_DONE;
	}
	if (io_state->io_state & IO_STATE_SFIFO_NOT_EMPTY) {
		return ERR_IO_STATE_SFIFO_NOT_EMPTY;
	}
	if (io_state->io_state & ~IO_STATE_INPUT_PROG_FULL) {
		printf("Unknown error: io_state=0x%02X\n", io_state->io_state);
		return -1;
	}
	if (io_state->io_state & IO_STATE_INPUT_PROG_FULL) {
		if (DEBUG) printf("#%d fpga_write_do(): Input full\n", fpga->num + 1);
		return 0; // Input full, no write
	}

	// get data for transmission
	int data_len = 0;
	unsigned char *data = pkt_comm_get_output_data(fpga->comm, &data_len);
	if (!data) {
		if (DEBUG) printf("fpga_pkt_write(): no data for transmission\n");
		return 0;
	}

	if (DEBUG >= 2) {
		int i;
		for (i=0; i < data_len; i++) {
			printf("%02x ", data[i]);
		}
		printf("\n");
	}

	int transferred = 0;
	result = libusb_bulk_transfer(fpga->device->handle, 0x06, data,
			data_len, &transferred, USB_RW_TIMEOUT);
	if (DEBUG) printf("#%d fpga_write(): %d %d/%d\n",
			fpga->num + 1, result, transferred, data_len);
	if (result < 0) {
		return result;
	}
	if (transferred != data_len) {
		return ERR_WR_PARTIAL;
	}

	pkt_comm_output_completed(fpga->comm, data_len, 0);

	wr->wr_count++;
	wr->wr_done = 1;
	return transferred;
}

// Synchronous read with pkt_comm (packet communication)
int fpga_pkt_read(struct fpga *fpga)
{
	struct fpga_rd *rd = &fpga->rd;
	rd->rd_done = 0;
	int result;
	int current_read_limit;

	if (!rd->read_limit_valid) {
		result = fpga_setup_output(fpga->device->handle);
		fpga->cmd_count++;
		if (result < 0) {
			//fprintf(stderr, "fpga_setup_output() returned %d\n", result);
			return result;
		}
		else if (result == 0) { // Nothing to read
			if (DEBUG) printf("#%d read_limit==0\n", fpga->num + 1);
			return 0;
		}
		rd->read_limit = result;
	}
	rd->read_limit_valid = 0;
	if (!rd->read_limit)
		return 0;

	// get input buffer
	unsigned char *input_buf = pkt_comm_input_get_buf(fpga->comm);
	if (fpga->comm->error)
		return -1;
	if (!input_buf)
		return 0;

	current_read_limit = rd->read_limit;
	for ( ; ; ) {
		int transferred = 0;
		//result = libusb_bulk_transfer(fpga->device->handle, 0x82, rd->buf,
		//		current_read_limit, &transferred, USB_RW_TIMEOUT);
		result = libusb_bulk_transfer(fpga->device->handle, 0x82, input_buf,
				current_read_limit, &transferred, USB_RW_TIMEOUT);
		if (DEBUG) printf("#%d usb_bulk_read(): result=%d, transferred=%d, current_read_limit=%d\n",
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
			rd->partial_read_count++;
			continue;
		}
		else {
			break;
		}
	} // for (;;)
	rd->read_count++;
	rd->rd_done = 1;
	rd->len = rd->read_limit;
/*
	// did read into buffer.
	int i, j;
	for (i=0; i < rd->read_limit; i++) {
		//if (!input_buf[i])
		//	printf(" ");
		//else
		if (i && !(i%8)) printf("\n");
			printf("%d ", input_buf[i]);
	}
	printf("\n");
*/
	result = pkt_comm_input_completed(fpga->comm, rd->read_limit, 0);

	if (result < 0)
		return result;
	return rd->read_limit;
}

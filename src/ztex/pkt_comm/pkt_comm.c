/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>

#include "pkt_comm.h"


void pkt_error(const char *s, ...) {
	va_list ap;
	va_start(ap, s);
	vfprintf(stderr, s, ap);
	va_end(ap);
}

int total_pkt_count=0;
int get_pkt_count(void)
{
	return total_pkt_count;
}

struct pkt *pkt_new(int type, char *data, int data_len)
{
	if (data_len > PKT_MAX_DATA_LEN) {
		pkt_error("pkt_new(type %d): data_len(%d) exceeds %d bytes\n",
				type, data_len, PKT_MAX_DATA_LEN);
		exit(-1);
		return NULL;
	}

	struct pkt *pkt = malloc(sizeof(struct pkt));
	if (!pkt) {
		pkt_error("pkt_new(type %d): unable to allocate %d bytes\n",
				type, sizeof(struct pkt));
		return NULL;
	}

	pkt->version = PKT_COMM_VERSION;
	pkt->type = type;
	pkt->data_len = data_len;
	pkt->id = 0;

	pkt->data = data;
	pkt->header_ok = 0;
	pkt->partial_header_len = 0;
	pkt->partial_data_len = 0;
	pkt->header = NULL;

	total_pkt_count++;
	return pkt;
}

unsigned int pkt_get_id(struct pkt *pkt)
{
	return pkt->id;
}

void pkt_delete(struct pkt *pkt)
{
	if (pkt->data)
		free(pkt->data);
	if (pkt->partial_header_len && pkt->header)
		free(pkt->header);
	free(pkt);
	total_pkt_count--;
}

//
// Create binary packet header in the area pointed to by *header
//
void pkt_create_header(struct pkt *pkt, unsigned char *header)
{
	pkt->header = header;

	pkt->header[0] = pkt->version;
	pkt->header[1] = pkt->type;
	//pkt->header[2] = 0;
	//pkt->header[3] = 0;
	pkt->header[4] = pkt->data_len;
	pkt->header[5] = pkt->data_len >> 8;
	pkt->header[6] = pkt->data_len >> 16;
	//pkt->header[7] = 0;
	pkt->header[8] = pkt->id;
	pkt->header[9] = pkt->id >> 8;
}

// Read checksum pointed to by 'src' and convert to integer type
//
PKT_CHECKSUM_TYPE pkt_checksum_read(unsigned char *src)
{
	return src[0] | (src[1] << 8) | (src[2] << 16) | (src[3] << 24);
}

//
// Calculate checksum of 'data' of length 'len'
// If 'dst' is not NULL, place checksum there
//
PKT_CHECKSUM_TYPE pkt_checksum(unsigned char *dst, unsigned char *data, int len)
{
	PKT_CHECKSUM_TYPE checksum = 0;

	PKT_CHECKSUM_TYPE checksum_tmp = 0;
	int checksum_byte_count = 0;

	int i;
	for (i = 0; i < len; i++) {
		checksum_tmp |= data[i] << 8 * checksum_byte_count;
		if (++checksum_byte_count == PKT_CHECKSUM_LEN) {
			checksum += checksum_tmp;
			checksum_tmp = 0;
			checksum_byte_count = 0;
		}
	}
	checksum += checksum_tmp;

	checksum = ~checksum;

	for (i = 0; i < PKT_CHECKSUM_LEN; i++) {
		if (dst)
			dst[i] = checksum >> 8 * i;
	}
	return checksum;
}

//
// Convert binary packet header into human-readable string
// (for debug purposes)
//
void pkt_header2str(struct pkt *pkt, unsigned char *header, char *str)
{
	char tmp_str[16];
	int i;
	strcpy(str, "[ ");
	for (i=0; i < PKT_HEADER_LEN; i++) {
		if (i && !(i % 4))
			strcat(str, ". ");
		sprintf(tmp_str, "%d ", header[i]);
		strcat(str, tmp_str);
	}
	strcat(str, "]");
}

//
// Process input packet header in the area pointed to by *header
// including checksum
// Return < 0 on error
//
int pkt_process_header(struct pkt *pkt, unsigned char *header)
{
	char str[256];

	PKT_CHECKSUM_TYPE checksum = pkt_checksum(NULL, header, PKT_HEADER_LEN);
	PKT_CHECKSUM_TYPE checksum_got = pkt_checksum_read(header + PKT_HEADER_LEN);
	if (checksum_got != checksum) {
		pkt_error("pkt_process_header: bad checksum: got 0x%x, must be 0x%x\n",
			checksum_got, checksum);
		return -1;
	}

	pkt->version = header[0];
	if (pkt->version != PKT_COMM_VERSION) {
		pkt_header2str(pkt, header, str);
		pkt_error("pkt_process_header: wrong version %d, must be %d, header: %s\n",
				pkt->version, PKT_COMM_VERSION, str);
		return -1;
	}
	pkt->type = header[1];
	if (!pkt->type) {
		pkt_header2str(pkt, header, str);
		pkt_error("pkt_process_header: empty packet type, header: %s\n", str);
		return -1;
	}

	pkt->data_len = (unsigned)(header[4] | (header[5] << 8) | (header[6] << 16));
	if (!pkt->data_len || pkt->data_len > PKT_MAX_DATA_LEN) {
		pkt_header2str(pkt, header, str);
		pkt_error("pkt_process_header: bad data_len %d, header: %s\n",
				pkt->data_len, str);
		return -1;
	}
	pkt->id = header[8] | (header[9] << 8);

	pkt->partial_header_len = 0;
	pkt->header_ok = 1;
	return 0;
}

// ****************************************************************

struct pkt_queue *pkt_queue_new()
{
	struct pkt_queue *queue = malloc(sizeof(struct pkt_queue));
	if (!queue) {
		pkt_error("pkt_queue_new(): unable to allocate %d bytes\n",
				sizeof(struct pkt_queue));
		return NULL;
	}
	queue->count = 0;
	queue->empty_slot_idx = 0;
	queue->first_pkt_idx = 0;

	int i;
	for (i = 0; i < PKT_QUEUE_MAX; i++)
		queue->pkt[i] = NULL;

	return queue;
}

void pkt_queue_delete(struct pkt_queue *queue)
{
	if (!queue) {
		pkt_error("pkt_queue_delete(): NULL argument\n");
		return;
	}

	int i;
	for (i = 0; i < PKT_QUEUE_MAX; i++) {
		if (queue->pkt[i])
			pkt_delete(queue->pkt[i]);
	}
	free(queue);
}

int pkt_queue_push(struct pkt_queue *queue, struct pkt *pkt)
{
	if (queue->count == PKT_QUEUE_MAX)
		return -1;

	queue->pkt[queue->empty_slot_idx] = pkt;
	if (++queue->empty_slot_idx == PKT_QUEUE_MAX)
		queue->empty_slot_idx = 0;

	queue->count++;
	return 0;
}

int pkt_queue_full(struct pkt_queue *queue, int num)
{
	return queue->count + num > PKT_QUEUE_MAX ? 1 : 0;
}

struct pkt *pkt_queue_fetch(struct pkt_queue *queue)
{
	if (!queue->count)
		return NULL;

	struct pkt *pkt = queue->pkt[queue->first_pkt_idx];
	queue->pkt[queue->first_pkt_idx] = NULL;
	queue->count--;

	if (++queue->first_pkt_idx == PKT_QUEUE_MAX)
		queue->first_pkt_idx = 0;

	return pkt;
}

// Get total size (including headers and checksums) of all packets in queue
int pkt_queue_get_total_size(struct pkt_queue *queue)
{
	int total_size = 0;

	int i;
	for (i = 0; i < PKT_QUEUE_MAX; i++)
		if (queue->pkt[i]) {
			total_size += queue->pkt[i]->data_len + PKT_HEADER_LEN;
			total_size += 2 * PKT_CHECKSUM_LEN;
		}

	return total_size;
}

// ****************************************************************

struct pkt_comm *pkt_comm_new(struct pkt_comm_params *params)
{
	if (params->output_max_len <= 0 || params->input_max_len <= 0
			|| params->alignment < 0 || params->alignment > 256) {
		pkt_error("pkt_comm_new(): wrong pkt_comm_params\n");
		return NULL;
	}

	struct pkt_comm *comm = malloc(sizeof(struct pkt_comm));
	if (!comm) {
		pkt_error("pkt_comm_new(): unable to allocate %d bytes\n",
				sizeof(struct pkt_comm));
		return NULL;
	}
	comm->params = params;

	comm->output_queue = pkt_queue_new();
	if (!comm->output_queue) {
		free(comm);
		return NULL;
	}
	comm->output_buf = NULL;

	comm->input_queue = pkt_queue_new();
	if (!comm->input_queue) {
		free(comm);
		return NULL;
	}
	comm->input_buf = malloc(params->input_max_len);
	if (!comm->input_buf) {
		pkt_error("pkt_comm_new(): unable to allocate %d bytes\n",
				params->input_max_len);
		free(comm);
		return NULL;
	}
	comm->input_buf_len = 0;
	comm->input_pkt = NULL;

	comm->error = 0;
	return comm;
}

void pkt_comm_delete(struct pkt_comm *comm)
{
	if (!comm) {
		pkt_error("pkt_comm_delete(): NULL argument\n");
		return;
	}

	pkt_queue_delete(comm->input_queue);
	pkt_queue_delete(comm->output_queue);
	free(comm->input_buf);
	if (comm->output_buf)
		free(comm->output_buf);
	if (comm->input_pkt)
		pkt_delete(comm->input_pkt);
}


// ******************************************************************
//
// pkt_comm output over link layer
//
// ******************************************************************

// allocates output buffer
// fetches all packets from output queue and puts them into output buffer
// calculates checksums
// deals with alignment issues
//
int pkt_comm_create_output_buf(struct pkt_comm *comm)
{
	// there's already output buffer
	if (comm->output_buf) {
		pkt_error("pkt_comm_create_output_buf(): buffer already created\n");
		return -1;
	}

	// output queue empty, output buffer not created
	if (!comm->output_queue->count)
		return 0;

	int size = pkt_queue_get_total_size(comm->output_queue);
	if (!size)
		return 0;

	// alignment issue; pad with 0's
	int align = comm->params->alignment;
	int extra_zeroes = align && size % align ? align - size % align : 0;
	size += extra_zeroes;

	comm->output_buf = malloc(size);
	if (!comm->output_buf) {
		pkt_error("pkt_comm_create_output_buf(): unable to allocate %d bytes\n", size);
		return 0;
	}
	comm->output_buf_size = size;
	comm->output_buf_offset = 0;

	int i;
	for (i = 0; i < extra_zeroes; i++)
		comm->output_buf[size - i - 1] = 0;

	// fetch all packets from output queue and put them into output buffer
	int offset = 0;
	struct pkt *pkt;
	while ( (pkt = pkt_queue_fetch(comm->output_queue)) ) {

		pkt_create_header(pkt, comm->output_buf + offset);
		pkt_checksum(comm->output_buf + offset + PKT_HEADER_LEN,
				comm->output_buf + offset, PKT_HEADER_LEN);
		offset += PKT_HEADER_LEN + PKT_CHECKSUM_LEN;

		memcpy(comm->output_buf + offset, pkt->data, pkt->data_len);
		pkt_checksum(comm->output_buf + offset + pkt->data_len,
				comm->output_buf + offset, pkt->data_len);
		offset += pkt->data_len + PKT_CHECKSUM_LEN;

		pkt_delete(pkt);
	}

	return size;
}

/*
// Not tested
int pkt_comm_has_output_data(struct pkt_comm *comm)
{
	// There's data in output buffer
	if (comm->output_buf) {
		if (comm->output_buf_offset >= comm->output_buf_size
				|| !comm->output_buf_size) {
			// Looks like internal error
			pkt_error("pkt_comm_has_output_data: %d, %d\n",
				comm->output_buf_offset, comm->output_buf_size);
			return 0;
		}
		return 1;
	}

	// There's data in output queue
	if (!comm->output_queue->count)
		return 1;

	return 0;
}
*/

unsigned char *pkt_comm_get_output_data(struct pkt_comm *comm, int *len)
{
	if (!comm->output_buf) {
		if (!pkt_comm_create_output_buf(comm)) {
			// No output data
			*len = 0;
			return NULL;
		}
	}

	int size = comm->output_buf_size;
	int offset = comm->output_buf_offset;
	//printf("pkt: size %d off %d\n",size,offset);
	if (size - offset <= comm->params->output_max_len) {
		// TODO: check if there's data in output queue, add-up to buffer
		// if remeining size is less than max.transfer size over link layer
		*len = size - offset;
	} else {
		*len = comm->params->output_max_len;
	}

	return comm->output_buf + offset;
}


void pkt_comm_output_completed(struct pkt_comm *comm, int len, int error)
{
	comm->error = error;
	if (error)
		return;

	comm->output_buf_offset += len;
	if (comm->output_buf_offset >= comm->output_buf_size) {
		free(comm->output_buf);
		comm->output_buf = NULL;
	}
}

// ******************************************************************
//
// pkt_comm input over link layer
//
// ******************************************************************

int pkt_comm_input_process_zeroes(struct pkt_comm *comm)
{
	int count = 0;
	while (comm->input_buf[comm->input_buf_offset] == 0) {
		if (++comm->input_buf_offset >= comm->input_buf_len) {
			comm->input_buf_len = 0;
			return 0;
		}
		if (++count > 256) {
			pkt_error("pkt_comm_process_input_buf: too many padding 0's\n");
			return -1;
		}
	}
	return 0;
}

// process packet header from input buffer
// including checksum after the header
//
int pkt_comm_process_input_header(struct pkt_comm *comm)
{
	struct pkt *pkt = comm->input_pkt;
	unsigned char *buf = comm->input_buf;
	int offset = comm->input_buf_offset;
	//printf("process input header: off %d, input_pkt(y/n): %d\n", offset, !!pkt);

	// nothing in input buffer
	if (!comm->input_buf_len)
		return 0;

	// There's already input packet with partial header
	if (pkt && pkt->partial_header_len) {
		//printf("process input header: partial header len %d\n",pkt->partial_header_len);

		// packet header is split over 3+ link layer transfers - should not happen
		if (offset + PKT_HEADER_LEN + PKT_CHECKSUM_LEN - pkt->partial_header_len
				> comm->input_buf_len) {
			pkt_error("pkt_comm_process_input_buf: splitted partial header, buf_len %d, off %d\n",
					comm->input_buf_len, offset);
			return -1;
		}

		memcpy(pkt->header + pkt->partial_header_len, buf + offset,
				PKT_HEADER_LEN + PKT_CHECKSUM_LEN - pkt->partial_header_len);
		comm->input_buf_offset += PKT_HEADER_LEN + PKT_CHECKSUM_LEN - pkt->partial_header_len;

		if (pkt_process_header(pkt, pkt->header) < 0)
			return -1;
		free(pkt->header);
		pkt->header = NULL;
		return 0;
	}

	// Partial header of a new input packet
	if (offset + PKT_HEADER_LEN + PKT_CHECKSUM_LEN > comm->input_buf_len) {
		pkt->header = malloc(PKT_HEADER_LEN + PKT_CHECKSUM_LEN);
		if (!pkt->header) {
			pkt_error("pkt_comm_process_input_header: unable to allocate %d bytes\n",
				PKT_HEADER_LEN + PKT_CHECKSUM_LEN);
			return -1;
		}
		pkt->partial_header_len = comm->input_buf_len - offset;
		memcpy(pkt->header, buf + offset, pkt->partial_header_len);
		comm->input_buf_len = 0;
		//printf("partial header: off %d len %d\n", offset, pkt->partial_header_len);
		return 0;
	}
	// Full header of a new input packet
	else {
		if (pkt_process_header(pkt, buf + offset) < 0)
			return -1;
		comm->input_buf_offset += PKT_HEADER_LEN + PKT_CHECKSUM_LEN;
		if (comm->input_buf_offset == comm->input_buf_len)
			comm->input_buf_len = 0;
	}

	return 0;
}

// process packet data from input buffer
// including checksum
//
int pkt_comm_process_input_packet_data(struct pkt_comm *comm)
{
	struct pkt *pkt = comm->input_pkt;
	if (!pkt || !pkt->data_len) {
		pkt_error("pkt_comm_process_input_packet_data: bad input packet\n");
		return -1;
	}

	// nothing in input buffer
	if (!comm->input_buf_len)
		return 0;

	// no data in packet
	if (!pkt->data) {
		// allocate memory for packet data
		pkt->data = malloc(pkt->data_len + PKT_CHECKSUM_LEN);
		if (!pkt->data) {
			pkt_error("pkt_comm_process_input_packet_data: unable to allocate %d bytes\n",
				pkt->data_len + PKT_CHECKSUM_LEN);
			return -1;
		}
	}
	// ok, packet already has partial data
	else if (pkt->data && pkt->partial_data_len
			&& pkt->partial_data_len < pkt->data_len + PKT_CHECKSUM_LEN) {
		//printf("PARTIAL DATA: %d\n", pkt->partial_data_len);
	}
	else {
		pkt_error("pkt_comm_process_input_packet_data: bad partial packet\n");
		return -1;
	}

	int offset = comm->input_buf_offset;
	int remains = pkt->data_len + PKT_CHECKSUM_LEN - pkt->partial_data_len ;

	// packet completed
	if (remains <= comm->input_buf_len - offset) {
		memcpy(pkt->data + pkt->partial_data_len, comm->input_buf + offset, remains);
		pkt->partial_data_len = 0;

		PKT_CHECKSUM_TYPE checksum = pkt_checksum(NULL, (unsigned char *)pkt->data, pkt->data_len);
		PKT_CHECKSUM_TYPE checksum_got = pkt_checksum_read((unsigned char *)pkt->data + pkt->data_len);
		if (checksum_got != checksum) {
			pkt_error("pkt_comm_process_input_packet_data: bad checksum: got 0x%x, must be 0x%x\n",
				checksum_got, checksum);
			return -1;
		}

		// input buffer is empty
		if (remains == comm->input_buf_len - offset) {
			comm->input_buf_len = 0;
		}
		// input buffer is not empty
		else {
			comm->input_buf_offset += remains;
		}
	}
	// partial packet data, input buffer is empty
	else {
		memcpy(pkt->data + pkt->partial_data_len, comm->input_buf + offset,
				comm->input_buf_len - offset);
		pkt->partial_data_len += comm->input_buf_len - offset;
		comm->input_buf_len = 0;
	}

	return 0;
}

// Process input buffer, store full packets in input queue
// store partially received packet in comm->input_pkt
// return < 0 on error
//
int pkt_comm_process_input_buf(struct pkt_comm *comm)
{
	//printf("pkt_comm_process_input_buf: off %d\n", comm->input_buf_offset);
	struct pkt *pkt = comm->input_pkt;

	//if (pkt) printf("process_input_buf: h_ok %d part_head %d data %d part_data %d\n",
	//	pkt->header_ok, pkt->partial_header_len, !!pkt->data, pkt->partial_data_len);
	//else printf("process_input_buf: no input_pkt\n");
	while(1) {
		// there's input packet with no header or partial header
		if (pkt && !pkt->header_ok) {
			if (pkt_comm_process_input_header(comm) < 0)
				return -1;
		}

		// there's full header and no data or partial data
		if (pkt && pkt->header_ok && (!pkt->data || pkt->partial_data_len)) {
			if (pkt_comm_process_input_packet_data(comm) < 0)
				return -1;
		}

		// there's already a complete input packet
		if (pkt && pkt->header_ok && pkt->data && !pkt->partial_data_len) {
			//printf("pkt_comm_process_input_buf: header_ok:%d data:%d partial_data_len:%d\n",
			//	!!pkt->header_ok, !!pkt->data, pkt->partial_data_len);
			if (pkt_queue_full(comm->input_queue, 1))
				return 0;
			// push packet into input queue
			pkt_queue_push(comm->input_queue, pkt);
			comm->input_pkt = NULL;
		}

		// input buffer is empty - finish processing
		if (!comm->input_buf_len)
			return 0;

		// skip padding zeroes
		/*
		 * OK - the device creates aligned packets only
		 *
		if (pkt_comm_input_process_zeroes(comm) < 0)
			return -1;
		if (!comm->input_buf_len)
			return 0;
		*/

		// expecting new input packet
		pkt = pkt_new(0, NULL, 0);
		comm->input_pkt = pkt;

	} // while(1) - process incoming packets
}

unsigned char *pkt_comm_input_get_buf(struct pkt_comm *comm)
{
	// input queue full
	if (pkt_queue_full(comm->input_queue, 1))
		return NULL;

	// input buffer not empty
	// that's probably because input queue was full
	// at time of processing
	if (comm->input_buf_len) {
		// try to process and empty it
		if (pkt_comm_process_input_buf(comm) < 0) {
			comm->error = 1;
			return NULL;
		}

		// still not empty
		if (comm->input_buf_len)
			return NULL;
	}

	comm->input_buf_offset = 0;
	return comm->input_buf;
}

int pkt_comm_input_completed(struct pkt_comm *comm, int len, int error)
{
	//printf("input_completed %d %d\n", len, error);
	comm->error = error;
	if (error)
		return -1;

	if (!len)
		return -1;
	if (len > comm->params->input_max_len) {
		pkt_error("pkt_comm_input_completed: len %d exceeds input_max_len(%d)\n",
				len, comm->params->input_max_len);
		return -1;
	}
	comm->input_buf_len = len;

	if (pkt_comm_process_input_buf(comm) < 0) {
		comm->error = 1;
		return -1;
	}
	return 0;
}

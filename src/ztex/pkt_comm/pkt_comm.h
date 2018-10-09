/*
 * Some generic communication to a remote device
 *
 * - communication goes in sequential packets
 * - API is independent from hardware and link layer
 *
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#ifndef _PKT_COMM_H_

#include <stdint.h>

// *****************************************************************
//
// That's the packet when transmitted over link layer
//
//	struct pkt {
//		unsigned char version; // version
//		unsigned char type;
//		unsigned short reserved0;
//		unsigned char data_len0;
//		unsigned char data_len1;
//		unsigned char data_len2; // doesn't count header and checksum
//		unsigned char reserved1;
//		unsigned short id;
//		unsigned char data[pkt_data_len];
//	};
//
// Checksum is PKT_CHECKSUM_LEN bytes long. Words added and inverted.
// Checksum is not included in data length.
// - inserted after packet header
// - after the end of packet
//
// *****************************************************************

#define PKT_COMM_VERSION	2

#define PKT_HEADER_LEN		10

// packet can be split when transmitted over link layer
#define PKT_MAX_LEN			(16 * 65536)

#define PKT_CHECKSUM_LEN	4
// PKT_CHECKSUM_TYPE must be unsigned type
#define PKT_CHECKSUM_TYPE	uint32_t

#define PKT_MAX_DATA_LEN	(PKT_MAX_LEN - PKT_HEADER_LEN - 2 * PKT_CHECKSUM_LEN)

struct pkt {
	unsigned char version;
	unsigned char type; // type must be > 0
	int data_len;	// data length
	unsigned short id;
	char *data;
	// fields below are used by library;
	// application developer usually would not need them
	int header_ok;
	// partially received packet
	int partial_header_len;
	int partial_data_len;
	// variable usage for output and input
	unsigned char *header;
};

// Currently error messages are printed to stderr
void pkt_error(const char *s, ...);

// Creates new packet. Does not allocate memory for data
struct pkt *pkt_new(int type, char *data, int data_len);

unsigned int pkt_get_id(struct pkt *pkt);

// Deletes packet, also frees pkt->data
void pkt_delete(struct pkt *pkt);

// Total number of packets created with pkt_new() and not yet deleted
int get_pkt_count(void);


// *****************************************************************
//
// packet queue
//
// *****************************************************************

#define PKT_QUEUE_MAX	100

struct pkt_queue {
	int count;			// number of packets currently in queue
	int empty_slot_idx;	// index of 1st empty slot
	int first_pkt_idx;	// index of first packet
	struct pkt *pkt[PKT_QUEUE_MAX];
};

struct pkt_queue *pkt_queue_new();

void pkt_queue_delete(struct pkt_queue *queue);

// Returns false if queue has space for 'num' more packets
int pkt_queue_full(struct pkt_queue *queue, int num);

// Packet goes into the queue. It deletes the packet when
// it sends the packet to device or deletes the queue.
// Returns -1 if queue is full.
int pkt_queue_push(struct pkt_queue *queue, struct pkt *pkt);

// returns NULL if queue is empty
struct pkt *pkt_queue_fetch(struct pkt_queue *queue);


// *****************************************************************
//
// struct pkt_comm
//
// Represents a communication to some independently communicating
// device (part of device)
// * Queue for output packets
// * Output buffer
// * Queue for input packets
// * Input buffer
//
// *****************************************************************

// Parameters for link layer
struct pkt_comm_params {
	int alignment;
	int output_max_len;	// link layer max. transmit length
	int input_max_len;	// link layer max. receive length
};

struct pkt_comm {
	struct pkt_comm_params *params;

	struct pkt_queue *output_queue;
	unsigned char *output_buf;
	int output_buf_size;
	int output_buf_offset;

	struct pkt_queue *input_queue;
	unsigned char *input_buf;
	int input_buf_len;
	int input_buf_offset;
	struct pkt *input_pkt;

	int error;
};

struct pkt_comm *pkt_comm_new(struct pkt_comm_params *params);

void pkt_comm_delete(struct pkt_comm *comm);


// *****************************************************************
//
// Following functions are for I/O over link layer
//
// *****************************************************************

// Returns true if there's data for output
//int pkt_comm_has_output_data(struct pkt_comm *comm);

// Get data for output over link layer. Can be used to check
// if there's data for output. If all or part of the data was actually sent,
// then the caller must call pkt_comm_output_completed().
// Returns a pointer to data buffer or NULL if there's no data for output.
// 'len' is updated with data length.
unsigned char *pkt_comm_get_output_data(struct pkt_comm *comm, int *len);

// Called after the transmission of data requested with pkt_comm_output_get_data()
// 'len' is length of actually transmitted data
// < 0 on error
void pkt_comm_output_completed(struct pkt_comm *comm, int len, int error);

// Get buffer for link layer input
// Return NULL if input is full
unsigned char *pkt_comm_input_get_buf(struct pkt_comm *comm);

// Called after data was received into buffer requested with pkt_comm_input_get_buf()
// 'len' is length of actually received data
// < 0 on error
int pkt_comm_input_completed(struct pkt_comm *comm, int len, int error);


#define _PKT_COMM_H_
#endif

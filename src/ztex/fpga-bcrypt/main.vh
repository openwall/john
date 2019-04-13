/*
 * This software is Copyright (c) 2016,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// ************************************************************
//
// ISE Version: 14.5
//
// Include as Global File in Compile List: main.vh log2.vh
// Set as Top Module: ztex_inouttraffic
//
// ************************************************************


// Parameters for ztex_inouttraffic
`define	MAIN_MODULE_INST	bcrypt_v2
`define	BITSTREAM_TYPE		16'hbc01
`define	INPUT_FIFO_INST	fifo_16_sync_8kb
// prog_full asserts when input fifo has <=6kb free

// must be power of 2; actual size for output fifo is 2 bytes less
`define	OUTPUT_FIFO_SIZE	8192

// Parameters for pkt_comm
`define	PKT_COMM_VERSION	2
`define	RANGES_MAX			4
`define	CHAR_BITS			8
`define	PLAINTEXT_LEN		72
// outpkt_v3
`define	OUTPKT_TYPE_MSB	2
`define	OUTPKT_TYPE_CMP_EQUAL	'b01
`define	OUTPKT_TYPE_PACKET_DONE	'b10
`define	OUTPKT_TYPE_RESULT		'b11
`define	OUTPKT_TYPE_CMP_RESULT	'b100

`define	RESULT_LEN			24
`define	OUTPKT_DATA_MAX_LEN	(8 + `RESULT_LEN)

// comparator
`define	NUM_HASHES		512
`define	HASH_NUM_MSB	`MSB(`NUM_HASHES-1)
`define	HASH_COUNT_MSB	`MSB(`NUM_HASHES)


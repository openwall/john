/*
 * This software is Copyright (c) 2016-2018 Denis Burykin
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
`define	BITSTREAM_TYPE		16'hd5c0

// must be power of 2; actual size for output fifo is 2 bytes less
`define	OUTPUT_FIFO_SIZE	4096

// Parameters for pkt_comm
`define	PKT_COMM_VERSION	2
`define	RANGES_MAX			4
`define	CHAR_BITS			8
`define	PLAINTEXT_LEN		64

// outpkt
`define	OUTPKT_TYPE_MSB	2
`define	OUTPKT_TYPE_CMP_EQUAL	'b01
`define	OUTPKT_TYPE_PACKET_DONE	'b10
`define	OUTPKT_TYPE_RESULT		'b11
`define	OUTPKT_TYPE_CMP_RESULT	'b100

`define	RESULT_LEN			16
//`define	OUTPKT_DATA_MAX_LEN	(8 + `RESULT_LEN)

// comparator
`define	NUM_HASHES		512
`define	HASH_NUM_MSB	`MSB(`NUM_HASHES-1)
`define	HASH_COUNT_MSB	`MSB(`NUM_HASHES)


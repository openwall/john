/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// ************************************************************
//
// ISE Project: jtr_ztex
// ISE Version: 14.5
//
// Include as Global File in Compile List: main.vh log2.vh
// Set as Top Module: ztex_inouttraffic
//
// ************************************************************

// ************************************************************
//
// Using to build several projects in same workspace
//
// ************************************************************

//`define	PROJECT_PKT_TEST

`define	PROJECT_DESCRYPT

//`define	PROJECT_


// Parameters for every project
`define	RANGES_MAX			4
`define	PKT_COMM_VERSION	2


// ****************************************************
//
// packet communication test (pkt_test.c)
// Takes input packets, generates plaintext candidates
// and outputs them (1 candidate with IDs per packet).
//
// ****************************************************
`ifdef	PROJECT_PKT_TEST
// remove descrypt.ucf from project

// Main parameters
`define	MAIN_MODULE_INST	pkt_test
`define	TEST_MODES_01

// Parameters for ztex_inouttraffic
`define	BITSTREAM_TYPE		16'h0002
`define	INPUT_FIFO_INST	fifo_16in_8out_64k
`define	OUTPUT_FIFO_CLK	PKT_COMM_CLK
// actual size is 2 bytes less
`define	OUTPUT_FIFO_SIZE	32768

// Parameters for pkt_comm
`define	CHAR_BITS			7
`define	PLAINTEXT_LEN		8
// RESULT_LEN must be even number
`define	RESULT_LEN			8
// outpkt_v2: define used packet types
//`define	OUTPKT_TYPE_CMP_EQUAL
//`define	OUTPKT_TYPE_PACKET_DONE
`define	OUTPKT_TYPE_RESULT1


// ****************************************************
//
// ****************************************************
`elsif	PROJECT_DESCRYPT
// add files:
// descrypt/descrypt.ucf
//

// Main parameters
`define	MAIN_MODULE_INST	descrypt
`define	TEST_MODES_01

// Parameters for ztex_inouttraffic
`define	BITSTREAM_TYPE		16'h0101
`define	INPUT_FIFO_INST	fifo_16in_8out_64k
`define	OUTPUT_FIFO_CLK	CMP_CLK
// actual size is 2 bytes less
`define	OUTPUT_FIFO_SIZE	2048

// Parameters for pkt_comm
`define	CHAR_BITS			7
`define	PLAINTEXT_LEN		8
// must define RESULT_LEN even if OUTPKT_TYPE_RESULT1 isn't used
`define	RESULT_LEN			8
// outpkt_v2: define used packet types
`define	OUTPKT_TYPE_CMP_EQUAL
`define	OUTPKT_TYPE_PACKET_DONE
//`define	OUTPKT_TYPE_RESULT1


// ****************************************************
//
// ****************************************************
`elsif	PROJECT_


`endif

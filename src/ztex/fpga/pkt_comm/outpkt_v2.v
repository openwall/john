`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// ******************************************************
//
// * Read units of various data (all the packet data in parallel)
// * Create output application packets (pkt_comm.h)
// * Expect read from 16-bit output FIFO
//
// ******************************************************

`ifdef OUTPKT_TYPE_CMP_EQUAL
	`define OUTPKT_USE_IDS
	`define OUTPKT_USE_HASH_NUM
`endif

`ifdef OUTPKT_TYPE_RESULT1
	`define OUTPKT_USE_IDS
	`define OUTPKT_USE_RESULT
`endif


module outpkt_v2 #(
	parameter [7:0] VERSION = `PKT_COMM_VERSION,
	parameter PKT_TYPE_MSB = 2,
	parameter RESULT_LEN = `RESULT_LEN,
	parameter HASH_NUM_MSB = 15
	)(
	input CLK,
	
	output full,
	input wr_en,
	input [PKT_TYPE_MSB:0] pkt_type,
	input [15:0] pkt_id,

	// data depends on packet type
`ifdef OUTPKT_USE_IDS
	input [15:0] word_id,
	input [31:0] gen_id,
`endif
`ifdef OUTPKT_USE_HASH_NUM
	input [HASH_NUM_MSB:0] hash_num,
`endif
`ifdef OUTPKT_TYPE_PACKET_DONE
	input [31:0] num_processed,
`endif
`ifdef OUTPKT_USE_RESULT
	input [8*RESULT_LEN-1:0] result,
`endif
	
	output [15:0] dout,
	input rd_en,
	output empty
	);

	reg full_r = 0;
	assign full = full_r;


	localparam OUTPKT_TYPE_CMP_EQUAL		= 8'hD1;
	localparam OUTPKT_TYPE_PACKET_DONE	= 8'hD2;
	localparam OUTPKT_TYPE_RESULT1		= 8'hD3; // result with IDs (w/o hash_num)

	reg [PKT_TYPE_MSB:0] outpkt_type_r;
	
	wire [7:0] outpkt_type =
		outpkt_type_r == 'b001 ? OUTPKT_TYPE_CMP_EQUAL : 
		outpkt_type_r == 'b010 ? OUTPKT_TYPE_PACKET_DONE :
		outpkt_type_r == 'b100 ? OUTPKT_TYPE_RESULT1 :
	0;

	wire [15:0] outpkt_len = // in bytes, must be even number
		outpkt_type == OUTPKT_TYPE_CMP_EQUAL	? 8 :
		outpkt_type == OUTPKT_TYPE_PACKET_DONE	? 4 :
		outpkt_type == OUTPKT_TYPE_RESULT1		? 6 + RESULT_LEN :
	0;

	// ! RESULT_LEN might be inappropriate if OUTPKT_TYPE_RESULT1 not used
	localparam DATA_MAX_LEN = 6 + RESULT_LEN; // in bytes
	
	localparam HEADER_LEN = 10; // in bytes

	localparam COUNT_MSB = `MSB((DATA_MAX_LEN + HEADER_LEN)/2 - 1);
	
	
	// Register everything then go.
	reg [15:0] pkt_id_r;
	reg [15:0] word_id_r;
	reg [31:0] gen_id_r;
	reg [HASH_NUM_MSB:0] hash_num_r;
	reg [31:0] num_processed_r;
	reg [8*RESULT_LEN-1:0] result_r;

	reg [COUNT_MSB:0] count = 0;
	
	always @(posedge CLK) begin
		if (~full & wr_en) begin
			pkt_id_r <= pkt_id;
			outpkt_type_r <= pkt_type;
			full_r <= 1;

		`ifdef OUTPKT_USE_IDS
			gen_id_r <= gen_id;
			word_id_r <= word_id;
		`endif
		`ifdef OUTPKT_USE_HASH_NUM
			hash_num_r <= hash_num;
		`endif
		`ifdef OUTPKT_TYPE_PACKET_DONE
			num_processed_r <= num_processed;
		`endif
		`ifdef OUTPKT_USE_RESULT
			result_r <= result;
		`endif
		end

		if (full_r & rd_en_pkt) begin
			if (pkt_end) begin
				count <= 0;
				full_r <= 0;
			end
			else
				count <= count + 1'b1;
		end
	end

	wire pkt_new = count == 0;
	
	wire pkt_end = count == outpkt_len[15:1] + HEADER_LEN/2 - 1;
	
	wire [15:0] pkt_dout =
		// version, type
		count == 0 ? { outpkt_type, VERSION } :
		// reserved
		count == 1 ? 16'h0 :
		// data length
		count == 2 ? outpkt_len :
		count == 3 ? 16'h0 :
		// packet id
		count == 4 ? pkt_id_r :
		// packet header ends

	`ifdef OUTPKT_TYPE_RESULT1
		count == 5 && outpkt_type == OUTPKT_TYPE_RESULT1 ? word_id_r :
		count == 6 && outpkt_type == OUTPKT_TYPE_RESULT1 ? gen_id_r[15:0] :
		count == 7 && outpkt_type == OUTPKT_TYPE_RESULT1 ? gen_id_r[31:16] :
		count >= 8 && outpkt_type == OUTPKT_TYPE_RESULT1 ? result_r[16*(count-7)-1 -:16] :
	`endif

	`ifdef OUTPKT_TYPE_CMP_EQUAL
		count == 5 && outpkt_type == OUTPKT_TYPE_CMP_EQUAL ? word_id_r :
		count == 6 && outpkt_type == OUTPKT_TYPE_CMP_EQUAL ? gen_id_r[15:0] :
		count == 7 && outpkt_type == OUTPKT_TYPE_CMP_EQUAL ? gen_id_r[31:16] :
		count == 8 && outpkt_type == OUTPKT_TYPE_CMP_EQUAL ? { {15-HASH_NUM_MSB{1'b0}}, hash_num_r[HASH_NUM_MSB:0] } :
	`endif
	
	`ifdef OUTPKT_TYPE_PACKET_DONE
		count == 5 && outpkt_type == OUTPKT_TYPE_PACKET_DONE ? num_processed_r[15:0] :
		count == 6 && outpkt_type == OUTPKT_TYPE_PACKET_DONE ? num_processed_r[31:16] :
	`endif
	
	{16{1'b0}};
	// pkt_dout assigment ends
	
	
	assign rd_en_pkt = full_r & ~full_checksum;
	assign wr_en_checksum = rd_en_pkt;

	outpkt_checksum outpkt_checksum(
		.CLK(CLK), .din(pkt_dout), .pkt_new(pkt_new), .pkt_end(pkt_end),
		.wr_en(wr_en_checksum), .full(full_checksum),
		
		.dout(dout), .rd_en(rd_en), .empty(empty)
	);
	
endmodule

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
// * Read units of various data (all the packet data in parallel, in 1 shot)
// * Create output application packets (pkt_comm.h) w/o checksum
// * Pass-by packets through outpkt_checksum
// * TODO: more advanced checksumming algorithm
// * Expect read from 16-bit output FIFO
//
// ******************************************************

`ifdef USE_OUTPKT_CMP_EQUAL
	`define OUTPKT_USE_IDS
	`define OUTPKT_USE_HASH_NUM
`endif

`ifdef USE_OUTPKT_RESULT
	`define OUTPKT_USE_IDS
	`define OUTPKT_USE_RESULT
`endif

`ifdef USE_OUTPKT_CMP_RESULT
	`define OUTPKT_USE_IDS
	`define OUTPKT_USE_RESULT
	`define OUTPKT_USE_HASH_NUM
`endif


module outpkt_v3 #(
	parameter [7:0] VERSION = `PKT_COMM_VERSION,
	parameter PKT_TYPE_MSB = `OUTPKT_TYPE_MSB,
	parameter HASH_NUM_MSB = 15,
	parameter SIMULATION = 0
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
`ifdef USE_OUTPKT_PACKET_DONE
	input [31:0] num_processed,
`endif
`ifdef OUTPKT_USE_RESULT
	input [8*`RESULT_LEN-1:0] result,
`endif
	
	output [15:0] dout,
	output pkt_end_out,
	input rd_en,
	output empty
	);

	reg full_r = 0;
	assign full = full_r;

	// Type ID appears on host in 'type' field
	localparam OUTPKT_TYPE_ID_CMP_EQUAL		= 8'hD1;
	localparam OUTPKT_TYPE_ID_PACKET_DONE	= 8'hD2;
	localparam OUTPKT_TYPE_ID_RESULT			= 8'hD3; // result with IDs (w/o hash_num)
	localparam OUTPKT_TYPE_ID_CMP_RESULT	= 8'hD4; // result with IDs & hash_num

	reg [PKT_TYPE_MSB:0] pkt_type_r;

	wire [7:0] pkt_type_id =
		pkt_type_r == `OUTPKT_TYPE_CMP_EQUAL ? OUTPKT_TYPE_ID_CMP_EQUAL : 
		pkt_type_r == `OUTPKT_TYPE_PACKET_DONE ? OUTPKT_TYPE_ID_PACKET_DONE :
		pkt_type_r == `OUTPKT_TYPE_RESULT ? OUTPKT_TYPE_ID_RESULT :
		pkt_type_r == `OUTPKT_TYPE_CMP_RESULT ? OUTPKT_TYPE_ID_CMP_RESULT :
	0;

	wire [15:0] pkt_len = // data length in bytes, must be even number
		pkt_type_r == `OUTPKT_TYPE_CMP_EQUAL ? 8 :
		pkt_type_r == `OUTPKT_TYPE_PACKET_DONE ? 4 :
		pkt_type_r == `OUTPKT_TYPE_RESULT ? 6 + `RESULT_LEN :
		pkt_type_r == `OUTPKT_TYPE_CMP_RESULT ? 8 + `RESULT_LEN :
	0;
	

	localparam HEADER_LEN = 10; // in bytes
	localparam COUNT_MSB = `MSB((`OUTPKT_DATA_MAX_LEN + HEADER_LEN)/2 - 1);
	
	// Register everything then go.
	// All *_r1* declared as TIG
	reg [15:0] pkt_id_r1;
	reg [15:0] word_id_r1;
	reg [31:0] gen_id_r1;
	reg [HASH_NUM_MSB:0] hash_num_r1;
	reg [31:0] num_processed_r1;
	reg [8*`RESULT_LEN-1:0] result_r1;

	reg [COUNT_MSB:0] count = 0;
	
	always @(posedge CLK) begin
		// All the packet data is written in one shot
		if (~full & wr_en) begin
			pkt_type_r <= pkt_type;
			full_r <= 1;
			pkt_id_r1 <= pkt_id;

		`ifdef OUTPKT_USE_IDS
			gen_id_r1 <= gen_id;
			word_id_r1 <= word_id;
		`endif
		`ifdef OUTPKT_USE_HASH_NUM
			hash_num_r1 <= hash_num;
		`endif
		`ifdef USE_OUTPKT_PACKET_DONE
			num_processed_r1 <= num_processed;
		`endif
		`ifdef OUTPKT_USE_RESULT
			result_r1 <= result;
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
	
	wire pkt_end = count == pkt_len[15:1] + HEADER_LEN/2 - 1;
	
	wire [15:0] pkt_dout =
		// version, type
		count == 0 ? { pkt_type_id, VERSION } :
		// reserved
		count == 1 ? 16'h35b9 : // some arbitrary value for better checksumming
		// data length
		count == 2 ? pkt_len :
		count == 3 ? 16'h0 :
		// packet id
		count == 4 ? pkt_id_r1 :
		// packet header ends

	`ifdef USE_OUTPKT_RESULT
		count == 5 && pkt_type_r == `OUTPKT_TYPE_RESULT ? word_id_r1 :
		count == 6 && pkt_type_r == `OUTPKT_TYPE_RESULT ? gen_id_r1[15:0] :
		count == 7 && pkt_type_r == `OUTPKT_TYPE_RESULT ? gen_id_r1[31:16] :
		count >= 8 && pkt_type_r == `OUTPKT_TYPE_RESULT ? result_r1[16*(count-7)-1 -:16] :
	`endif

	`ifdef USE_OUTPKT_CMP_RESULT
		count == 5 && pkt_type_r == `OUTPKT_TYPE_CMP_RESULT ? word_id_r1 :
		count == 6 && pkt_type_r == `OUTPKT_TYPE_CMP_RESULT ? gen_id_r1[15:0] :
		count == 7 && pkt_type_r == `OUTPKT_TYPE_CMP_RESULT ? gen_id_r1[31:16] :
		count == 8 && pkt_type_r == `OUTPKT_TYPE_CMP_RESULT ? { {15-HASH_NUM_MSB{1'b0}}, hash_num_r1[HASH_NUM_MSB:0] } :
		count >= 9 && pkt_type_r == `OUTPKT_TYPE_CMP_RESULT ? result_r1[16*(count-8)-1 -:16] :
	`endif

	`ifdef USE_OUTPKT_CMP_EQUAL
		count == 5 && pkt_type_r == `OUTPKT_TYPE_CMP_EQUAL ? word_id_r1 :
		count == 6 && pkt_type_r == `OUTPKT_TYPE_CMP_EQUAL ? gen_id_r1[15:0] :
		count == 7 && pkt_type_r == `OUTPKT_TYPE_CMP_EQUAL ? gen_id_r1[31:16] :
		count == 8 && pkt_type_r == `OUTPKT_TYPE_CMP_EQUAL ? { {15-HASH_NUM_MSB{1'b0}}, hash_num_r1[HASH_NUM_MSB:0] } :
	`endif
	
	`ifdef USE_OUTPKT_PACKET_DONE
		count == 5 && pkt_type_r == `OUTPKT_TYPE_PACKET_DONE ? num_processed_r1[15:0] :
		count == 6 && pkt_type_r == `OUTPKT_TYPE_PACKET_DONE ? num_processed_r1[31:16] :
	`endif
	
	{16{1'b0}};
	// pkt_dout assigment ends
	
	if (SIMULATION) begin
		reg [15:0] PKT_count_cmp_eq = 0;
		reg [15:0] PKT_count_done = 0;
		reg [15:0] PKT_count_result = 0;
		reg [15:0] PKT_count_other = 0;
		always @(posedge CLK)
			if (~full & wr_en) begin
				if (pkt_type == `OUTPKT_TYPE_CMP_EQUAL)
					PKT_count_cmp_eq <= PKT_count_cmp_eq + 1'b1;
				else if (pkt_type == `OUTPKT_TYPE_PACKET_DONE)
					PKT_count_done <= PKT_count_done + 1'b1;
				else if (pkt_type == `OUTPKT_TYPE_RESULT)
					PKT_count_result <= PKT_count_result + 1'b1;
				else
					PKT_count_other <= PKT_count_other + 1'b1;
			end
	end
	
	assign rd_en_pkt = full_r & ~checksum_full;
	assign checksum_wr_en = rd_en_pkt;
/*
	assign rd_en_pkt = ~checksum_fifo_full & full_r;
	wire [15:0] pkt_dout_2;
	wire pkt_new_2, pkt_end_2;
	
	fifo_122x32 checksum_fifo (
		.wr_clk(CLK),
		.din({pkt_dout, pkt_new, pkt_end}),
		.wr_en(rd_en_pkt),
		.full(checksum_fifo_full),
		.almost_full(),//almost_full),

		.rd_clk(CLK),
		.dout({pkt_dout_2, pkt_new_2, pkt_end_2}),
		.rd_en(checksum_wr_en),
		.empty(checksum_fifo_empty)
	);
	
	assign checksum_wr_en = ~checksum_fifo_empty & ~checksum_full;
*/	
	outpkt_checksum outpkt_checksum(
		.CLK(CLK),
		.din(pkt_dout), .pkt_new(pkt_new), .pkt_end(pkt_end),
		//.din(pkt_dout_2), .pkt_new(pkt_new_2), .pkt_end(pkt_end_2),
		.wr_en(checksum_wr_en), .full(checksum_full),
		
		.dout(dout), .pkt_end_out(pkt_end_out), .rd_en(rd_en), .empty(empty)
	);
	
endmodule

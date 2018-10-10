`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016-2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//
// Based on outpkt_bcrypt
//
module outpkt #(
	parameter [7:0] VERSION = `PKT_COMM_VERSION,
	parameter PKT_TYPE_MSB = `OUTPKT_TYPE_MSB,
	parameter HASH_NUM_MSB = 15,
	parameter SIMULATION = 0
	)(
	input CLK,

	output reg full = 1,
	input source_not_empty,
	// Read from 16-bit wide memory
	input [15:0] din,
	output reg [`MSB(4 +`RESULT_LEN/2 -1):0] rd_addr = 0,

	input wr_en,
	input [PKT_TYPE_MSB:0] pkt_type,
	input [15:0] pkt_id,
	input [HASH_NUM_MSB:0] hash_num,
	input [31:0] num_processed,

	output [15:0] dout,
	output pkt_end_out,
	input rd_en,
	output empty
	);


	// Type ID appears on host in 'type' field
	//localparam [7:0] OUTPKT_TYPE_ID_CMP_EQUAL		= 8'hD1;
	localparam [7:0] OUTPKT_TYPE_ID_PACKET_DONE	= 8'hD2;
	localparam [7:0] OUTPKT_TYPE_ID_RESULT			= 8'hD3; // result with IDs (w/o hash_num)
	localparam [7:0] OUTPKT_TYPE_ID_CMP_RESULT	= 8'hD4; // result with IDs & hash_num

	wire [7:0] pkt_type_id =
		//pkt_type == `OUTPKT_TYPE_CMP_EQUAL ? OUTPKT_TYPE_ID_CMP_EQUAL :
		pkt_type == `OUTPKT_TYPE_PACKET_DONE ? OUTPKT_TYPE_ID_PACKET_DONE :
		pkt_type == `OUTPKT_TYPE_RESULT ? OUTPKT_TYPE_ID_RESULT :
		pkt_type == `OUTPKT_TYPE_CMP_RESULT ? OUTPKT_TYPE_ID_CMP_RESULT :
	0;

	wire [7:0] pkt_len = // data length in bytes, must be even number
		//pkt_type == `OUTPKT_TYPE_CMP_EQUAL ? 8 :
		pkt_type == `OUTPKT_TYPE_PACKET_DONE ? 4 :
		pkt_type == `OUTPKT_TYPE_RESULT ? 6 + `RESULT_LEN :
		pkt_type == `OUTPKT_TYPE_CMP_RESULT ? 8 + `RESULT_LEN :
	0;


	reg pkt_empty = 1;
	reg [15:0] pkt_dout = 0;
	reg [2:0] count = 0;
	reg pkt_new = 1, pkt_end = 0;

	localparam [3:0] STATE_NONE = 0,
				STATE_HEADER = 1,
				STATE_NUM_PROC0 = 2,
				STATE_NUM_PROC1 = 3,
				STATE_WORD_ID = 4,
				STATE_GEN_ID0 = 5,
				STATE_GEN_ID1 = 6,
				STATE_HASH_NUM = 7,
				STATE_RESULT = 8,
				STATE_RD_PREPARE = 9,
				STATE_RD = 10,
				STATE_RD_WAIT = 11;

	(* FSM_EXTRACT="true" *)
	reg [3:0] state = STATE_NONE;

	always @(posedge CLK) begin
		if (~pkt_empty) begin
			if (checksum_wr_en) begin
				pkt_empty <= 1;
				pkt_end <= 0;
			end
		end

		else // internal register (pkt_dout) is empty
		case(state)
		STATE_NONE: if (source_not_empty)
			state <= STATE_HEADER;

		// Read from Fall-Through type source
		STATE_HEADER: begin
			pkt_dout <=
				// version, type
				count == 0 ? { pkt_type_id, VERSION } :
				// reserved
				count == 1 ? 16'h35b9 : // some arbitrary value for better checksumming
				// data length
				count == 2 ? { 8'b0, pkt_len } :
				count == 3 ? 16'h0 :
				// packet id
				count == 4 ? pkt_id :
				16'h0;

			pkt_new <= count == 0 ? 1'b1 : 1'b0;

			pkt_empty <= 0;
			if (count == 4) begin
				count <= 0;
				state <= pkt_type == `OUTPKT_TYPE_PACKET_DONE
					? STATE_NUM_PROC0 : STATE_WORD_ID;
			end
			else
				count <= count + 1'b1;

			// 0 - word_id
			// 1 - pkt_id
			// 2-3 - gen_id
			// 4-(4+RESULT_LEN/2) - result
			rd_addr <= 0;
		end

		STATE_NUM_PROC0: begin
			pkt_dout <= num_processed[15:0];
			pkt_empty <= 0;
			state <= STATE_NUM_PROC1;
		end

		STATE_NUM_PROC1: begin
			pkt_dout <= num_processed[31:16];
			pkt_empty <= 0;
			pkt_end <= 1;
			state <= STATE_RD_PREPARE;
		end

		STATE_WORD_ID: begin
			pkt_dout <= din;
			pkt_empty <= 0;
			rd_addr <= 2;
			state <= STATE_GEN_ID0;
		end

		STATE_GEN_ID0: begin
			pkt_dout <= din;
			pkt_empty <= 0;
			rd_addr <= rd_addr + 1'b1;
			state <= STATE_GEN_ID1;
		end

		STATE_GEN_ID1: begin
			pkt_dout <= din;
			pkt_empty <= 0;
			rd_addr <= rd_addr + 1'b1;
			state <= pkt_type == `OUTPKT_TYPE_CMP_RESULT
				? STATE_HASH_NUM : STATE_RESULT;
		end

		STATE_HASH_NUM: begin
			pkt_dout <= { {15-HASH_NUM_MSB{1'b0}}, hash_num };
			pkt_empty <= 0;
			state <= STATE_RESULT;
		end

		STATE_RESULT: begin
			pkt_dout <= din;
			pkt_empty <= 0;
			rd_addr <= rd_addr + 1'b1;
			if (rd_addr == 4 +`RESULT_LEN/2 -1) begin
				pkt_end <= 1;
				state <= STATE_RD_PREPARE;
			end
		end

		STATE_RD_PREPARE: begin
			full <= 0;
			state <= STATE_RD;
		end

		STATE_RD: if (wr_en) begin
			full <= 1;
			state <= STATE_RD_WAIT;
		end

		STATE_RD_WAIT:
			state <= STATE_NONE;

		endcase
	end


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


	assign checksum_wr_en = ~pkt_empty & ~checksum_full;

	outpkt_checksum outpkt_checksum(
		.CLK(CLK),
		.din(pkt_dout), .pkt_new(pkt_new), .pkt_end(pkt_end),
		.wr_en(checksum_wr_en), .full(checksum_full),

		.dout(dout), .pkt_end_out(pkt_end_out), .rd_en(rd_en), .empty(empty)
	);

endmodule

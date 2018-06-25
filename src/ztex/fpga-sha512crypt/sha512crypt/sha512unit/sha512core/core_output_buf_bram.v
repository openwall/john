`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017-2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../sha512.vh"


module core_output_buf_bram(
	input CLK,

	input [63:0] din,
	input wr_en,
	input [3:0] wr_addr,
	input wr_seq,
	
	// ==============================================================
	//
	//   OUTPUT OPERATION
	//
	// 1. At some stage, 'core_out_ready' asserts.
	//    core_out_ctx_num, core_out_seq_num are set accordingly.
	// 2. Wait for input rd_en, then transmit 16 x 32-bit
	//
	// ==============================================================
	output reg [31:0] dout,
	output reg core_out_ready = 0, core_out_start = 0,
	output reg core_out_ctx_num, core_out_seq_num,
	input rd_en
	);

	(* RAM_STYLE="BLOCK" *)
	reg [63:0] mem [31:0];
	
	reg full0 = 0, full1 = 0;
	wire rst_full0, rst_full1;
	reg seq0, seq1;
	reg [15:0] X_INPUT_ERRORS = 0;


	// *****************************************************
	//
	// Input
	//
	// *****************************************************
	always @(posedge CLK) begin
		if (wr_en)
			mem [wr_addr] <= din;
		
		if (wr_en & wr_addr == 0) begin
			full0 <= 1;
			seq0 <= wr_seq;
		end
		if (rst_full0)
			full0 <= 0;
		
		if (wr_en & wr_addr == 8) begin
			full1 <= 1;
			seq1 <= wr_seq;
		end
		if (rst_full1)
			full1 <= 0;
		
`ifdef SIMULATION
		// Output has enough bandwith, there should be no errors
		if (wr_en & wr_addr == 0 & full0
				| wr_en & wr_addr == 8 & full1)
			X_INPUT_ERRORS <= X_INPUT_ERRORS + 1'b1;
`endif
	end
		

	// *****************************************************
	//
	// Output
	//
	// *****************************************************
	reg [3:0] output_cnt = 0; // output are 16 words X 32 bit

	reg [63:0] mem_r;

	localparam STATE_OUTPUT_NONE = 0,
					STATE_OUTPUT_READY = 1,
					STATE_OUTPUT_START = 2,
					STATE_OUTPUT_READ_MEM = 3;

	(* FSM_EXTRACT="true", FSM_ENCODING="one-hot" *)
	reg [1:0] state_output = STATE_OUTPUT_NONE;

	always @(posedge CLK) begin

		case(state_output)
		STATE_OUTPUT_NONE: if (full0 | full1) begin
			core_out_ready <= 1;
			core_out_ctx_num <= full0 ? 1'b0 : 1'b1;
			core_out_seq_num <= full0 ? seq0 : seq1;
			state_output <= STATE_OUTPUT_READY;
		end
		
		STATE_OUTPUT_READY: if (rd_en) begin
			state_output <= STATE_OUTPUT_START;
		end
		
		STATE_OUTPUT_START: begin
			core_out_ready <= 0;
			state_output <= STATE_OUTPUT_READ_MEM;
		end
		
		STATE_OUTPUT_READ_MEM: begin
			core_out_start <= output_cnt == 0;
			mem_r <= mem [{ core_out_ctx_num, output_cnt[3:1] }];
			
			output_cnt <= output_cnt + 1'b1;
			if (output_cnt == 15)
				state_output <= STATE_OUTPUT_NONE;
		end
		endcase
	end
	
	reg dout_en = 0;
	
	always @(posedge CLK) begin
		dout_en <= state_output == STATE_OUTPUT_READ_MEM;
		if (dout_en)
			dout <= output_cnt[0] ? mem_r[63:32] : mem_r[31:0];
	end
	
	assign rst_full0 = ~core_out_ctx_num & state_output == STATE_OUTPUT_START;
	assign rst_full1 = core_out_ctx_num & state_output == STATE_OUTPUT_START;


endmodule

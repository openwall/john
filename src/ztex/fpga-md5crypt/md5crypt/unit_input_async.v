`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "md5.vh"

//
// Data arrives from different clock domain.
//
// Input is divided into packets.
// Each packet consists of:
// - Packet type (1 input word).
// - Data. Data is stored at the beginning of thread's memory.
// Data size must be divisible by 4 bytes.
// - The start and the end word of the packet is determined
// by 'ctrl' signal.
//
module unit_input_async #(
	parameter N_CORES = -1,
	parameter N_THREADS = 4 * N_CORES,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1),
	parameter INPUT_WIDTH = `UNIT_INPUT_WIDTH,
	parameter RATIO = 32 / INPUT_WIDTH,
	parameter RATIO_MSB = `MSB(RATIO),
	parameter INPUT_N_WORDS = 128
	)(
	input WR_CLK,
	input [INPUT_WIDTH-1:0] in,
	input ctrl,
	input wr_en,
	output reg afull = 0, ready = 1,

	input RD_CLK,
	output reg [31:0] out,
	output [`MEM_TOTAL_MSB :0] mem_addr,
	input rd_en,
	output reg empty = 1,

	// thread_state (ts)
	//output reg [N_THREADS_MSB :0] ts_num = 0, // Thread #
	output [N_THREADS_MSB :0] ts_num,
	output reg ts_wr_en = 0,
	output [`THREAD_STATE_MSB :0] ts_wr,
	input [`THREAD_STATE_MSB :0] ts_rd,

	output reg [`ENTRY_PT_MSB:0] entry_pt_curr = 0
	);
/*
	reg ts_wr_en_r = 0;
	(* SHREG_EXTRACT="no" *) reg [`THREAD_STATE_MSB :0] ts_rd_r;
	always @(posedge RD_CLK) begin
		ts_wr_en <= ts_wr_en_r;
		ts_num <= thread_num;
		ts_rd_r <= ts_rd;
	end
*/
	assign ts_wr = `THREAD_STATE_WR_RDY;


	(* RAM_STYLE="DISTRIBUTED" *)
	reg [INPUT_WIDTH-1 :0] input_buf [INPUT_N_WORDS-1 :0];
	
	reg [`MSB(INPUT_N_WORDS-1) :0] input_addr = 0, output_addr = 0;
	reg [RATIO_MSB-1:0] output_cnt = 0;

	reg [N_THREADS_MSB :0] thread_num = 0;
	assign ts_num = thread_num;
	reg [`MEM_ADDR_MSB :0] thread_mem_addr = 0;
	assign mem_addr = { thread_num, thread_mem_addr };

	wire [`MSB(N_THREADS-1) :0] thread_num_next;
	next_thread_num #( .N_CORES(N_CORES)
	) next_thread_num( .in(thread_num), .out(thread_num_next) );


	localparam STATE_IN_NONE = 0,
				STATE_IN_GOING = 1,
				STATE_IN_WAIT_PKT_END = 2,
				STATE_IN_WAIT_SYNC = 3;

	(* FSM_EXTRACT="true", FSM_ENCODING="auto" *)
	reg [3:0] state_in = STATE_IN_NONE;

	always @(posedge WR_CLK) begin
		case(state_in)
		// Wait for the start of input packet.
		STATE_IN_NONE: begin
			if (wr_en & ctrl & in[2:0] == 0)
				state_in <= STATE_IN_GOING;
			else if (wr_en & ctrl & in[2:0] == 1) begin
				entry_pt_curr <= in [`ENTRY_PT_MSB+3 :3];
				state_in <= STATE_IN_WAIT_PKT_END;
			end
		end

		STATE_IN_WAIT_PKT_END: if (wr_en & ctrl)
			state_in <= STATE_IN_NONE;

		STATE_IN_GOING: begin
			ready <= 0;

			if (wr_en) begin
				input_buf [input_addr] <= in;
				input_addr <= input_addr + 1'b1;
				if (ctrl)
					state_in <= STATE_IN_WAIT_SYNC;
				//if (input_addr == INPUT_N_WORDS - 1)
			end
		end

		STATE_IN_WAIT_SYNC:
			if (output_complete_sync) begin
				ready <= 1;
				input_addr <= 0;
				state_in <= STATE_IN_NONE;
			end
		endcase
	end

	sync_pulse sync_input_complete( .wr_clk(WR_CLK),
		.sig(state_in == STATE_IN_GOING & wr_en & ctrl), .busy(),
		.rd_clk(RD_CLK), .out(input_complete_sync) );


	localparam STATE_OUT_NONE = 0,
				STATE_OUT_NEXT_WORD = 1,
				STATE_OUT_SEARCH1 = 2,
				STATE_OUT_SEARCH2 = 3,
				STATE_OUT_SEARCH3 = 4,
				STATE_OUT_COMPLETED = 5;

	(* FSM_EXTRACT="true", FSM_ENCODING="auto" *)
	reg [2:0] state_out = STATE_OUT_NONE;

	always @(posedge RD_CLK) begin
		if (ts_wr_en)
			ts_wr_en <= 0;
			
		case(state_out)
		STATE_OUT_NONE: if (input_complete_sync)
			state_out <= STATE_OUT_NEXT_WORD;
		
		STATE_OUT_NEXT_WORD: begin
			if (empty & output_addr != input_addr) begin
				output_addr <= output_addr + 1'b1;
				output_cnt <= output_cnt + 1'b1;

				out [output_cnt*INPUT_WIDTH +:INPUT_WIDTH]
					<= input_buf [output_addr];

				if (output_cnt == RATIO - 1)
					empty <= 0;
			end
			if (~empty & rd_en) begin
				thread_mem_addr <= thread_mem_addr + 1'b1;
				empty <= 1;
			end
			if (empty & output_addr == input_addr) begin
				output_addr <= 0;
				output_cnt <= 0;
				ts_wr_en <= 1;
				state_out <= STATE_OUT_SEARCH1;
			end
		end
		
		STATE_OUT_SEARCH1: begin
			thread_num <= thread_num_next;
			state_out <= STATE_OUT_SEARCH2;
		end
		
		STATE_OUT_SEARCH2:
			state_out <= STATE_OUT_SEARCH3;
		
		STATE_OUT_SEARCH3:
			if (ts_rd == `THREAD_STATE_NONE)
				state_out <= STATE_OUT_COMPLETED;
			else
				state_out <= STATE_OUT_SEARCH1;
		
		STATE_OUT_COMPLETED: begin
			thread_mem_addr <= 0;
			state_out <= STATE_OUT_NONE;
		end
		endcase
	end

	sync_pulse sync_output_complete( .wr_clk(RD_CLK),
		.sig(state_out == STATE_OUT_COMPLETED), .busy(),
		.rd_clk(WR_CLK), .out(output_complete_sync) );


`ifdef SIMULATION
	reg [15:0] X_PKTS_RECV = 0;
	always @(posedge RD_CLK)
		if (state_out == STATE_OUT_COMPLETED)
			X_PKTS_RECV <= X_PKTS_RECV + 1'b1;
`endif

/*	reg [9:0] X_BYTES_RECEIVED = 0;
	always @(posedge CLK)
		if (state_in == STATE_IN_NONE)
			X_BYTES_RECEIVED <= 0;
		else if (wr_en)
			X_BYTES_RECEIVED <= X_BYTES_RECEIVED + 1'b1;
`endif
*/
endmodule

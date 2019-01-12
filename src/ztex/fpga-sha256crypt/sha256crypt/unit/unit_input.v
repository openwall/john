`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../sha256.vh"

// Unit input is designed to minimize unit space,
// at possible expense in arbiter
// Input is over UNIT_INPUT_WIDTH -bit bus into main memory.
//
// Input is divided into packets.
// Each packet consists of:
// - Packet type (1 input word).
// - Data. Data is stored at the beginning of thread's memory.
// Data size must be divisible by 4 bytes.
// - The start and the end word of the packet is determined
// by 'ctrl' signal.
//

module unit_input #(
	parameter N_CORES = `N_CORES,
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1),
	parameter INPUT_WIDTH = `UNIT_INPUT_WIDTH,
	parameter RATIO = 32 / INPUT_WIDTH,
	parameter RATIO_MSB = `MSB(RATIO),
	parameter AFULL_SIZE = 13
	)(
	input CLK,

	input [INPUT_WIDTH-1:0] in,
	input wr_en, ctrl,
	output reg afull = 0, ready = 1,

	output reg [31:0] out,
	output [`MEM_TOTAL_MSB :0] mem_addr,
	input rd_en,
	output reg empty = 1,

	// thread_state (ts)
	output [N_THREADS_MSB :0] ts_num, // Thread #
	output reg ts_wr_en = 0,
	output [`THREAD_STATE_MSB :0] ts_wr,
	input [`THREAD_STATE_MSB :0] ts_rd,

	output reg [`ENTRY_PT_MSB:0] entry_pt_curr = 0
	);

	assign ts_wr = `THREAD_STATE_WR_RDY;


	(* RAM_STYLE="DISTRIBUTED" *)
	reg [INPUT_WIDTH-1:0] input_buf [31:0];
	reg [4:0] input_addr = 0, output_addr = 0;
	reg [RATIO_MSB-1:0] output_cnt = 0;

	reg [N_THREADS_MSB :0] thread_num = 0;
	assign ts_num = thread_num;
	reg [`MEM_ADDR_MSB :0] thread_mem_addr = 0;
	assign mem_addr = { thread_num, thread_mem_addr };

	wire [`MSB(N_THREADS-1) :0] thread_num_next;
	next_thread_num #( .N_CORES(N_CORES), .N_THREADS(N_THREADS)
	) next_thread_num( .in(thread_num), .out(thread_num_next) );

	wire [4:0] size = input_addr - output_addr;


	localparam STATE_IN_NONE = 0,
				STATE_IN_GOING = 1,
				STATE_IN_WAIT_WRITE_MEM = 2,
				STATE_IN_SEARCH1 = 3,
				STATE_IN_SEARCH2 = 4,
				STATE_IN_SEARCH3 = 5,
				STATE_IN_WAIT_PKT_END = 6;

	(* FSM_EXTRACT="true" *)
	reg [2:0] state_in = STATE_IN_NONE;

	always @(posedge CLK) begin
		if (ts_wr_en)
			ts_wr_en <= 0;

		case(state_in)
		// Wait for the start of input packet.
		STATE_IN_NONE: begin
			afull <= 0;
			if (wr_en & ctrl & in[2:0] == 0)
				state_in <= STATE_IN_GOING;
`ifdef ENTRY_PTS_EN
			else if (wr_en & ctrl & in[2:0] == 1) begin
				entry_pt_curr <= in [`ENTRY_PT_MSB+3 :3];
				state_in <= STATE_IN_WAIT_PKT_END;
			end
`endif
		end

`ifdef ENTRY_PTS_EN
		STATE_IN_WAIT_PKT_END: if (wr_en & ctrl)
			state_in <= STATE_IN_NONE;
`endif

		STATE_IN_GOING: begin
			ready <= 0;

			if (wr_en) begin
				input_buf [input_addr] <= in;
				input_addr <= input_addr + 1'b1;
			end

			afull <= size >= 32 - AFULL_SIZE;

			if (wr_en & ctrl)
				state_in <= STATE_IN_WAIT_WRITE_MEM;
		end

		STATE_IN_WAIT_WRITE_MEM: begin
			if (empty & output_addr == input_addr) begin
				ts_wr_en <= 1;
				state_in <= STATE_IN_SEARCH1;
			end
		end

		STATE_IN_SEARCH1: begin // Search for idle thread
			thread_num <= thread_num_next;
			state_in <= STATE_IN_SEARCH2;
		end

		STATE_IN_SEARCH2:
			state_in <= STATE_IN_SEARCH3;

		STATE_IN_SEARCH3: begin
			if (ts_rd == `THREAD_STATE_NONE) begin
				ready <= 1;
				state_in <= STATE_IN_NONE;
			end
			else
				state_in <= STATE_IN_SEARCH1;
		end
		endcase
	end


	localparam STATE_OUT_NONE = 0,
				STATE_OUT_NEXT_WORD = 1;

	(* FSM_EXTRACT="true" *)
	reg [1:0] state_out = STATE_OUT_NONE;

	always @(posedge CLK)
	case(state_out)
	STATE_OUT_NONE: if (state_in == STATE_IN_GOING) begin
		thread_mem_addr <= 0;
		output_cnt <= 0;
		state_out <= STATE_OUT_NEXT_WORD;
	end

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
		if (empty & output_addr == input_addr
				& state_in == STATE_IN_WAIT_WRITE_MEM)
			state_out <= STATE_OUT_NONE;
	end
	endcase

/*
`ifdef SIMULATION
	reg [9:0] X_BYTES_RECEIVED = 0;
	always @(posedge CLK)
		if (state_in == STATE_IN_NONE)
			X_BYTES_RECEIVED <= 0;
		else if (wr_en)
			X_BYTES_RECEIVED <= X_BYTES_RECEIVED + 1'b1;
`endif
*/

endmodule

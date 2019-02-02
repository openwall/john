`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018-2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../sha512.vh"

// Unit input is designed to minimize unit space,
// at possible expense in arbiter
// Input is over UNIT_INPUT_WIDTH -bit bus into main memory.
//
// Input is divided into packets.
// Each packet consists of:
// - Packet type (1 input word).
// - Data. Data is stored at the beginning of thread's memory.
// Data size must be divisible by MEM_WIDTH bits.
// - The start and the end word of the packet is determined
// by 'ctrl' signal.
//

module unit_input #(
	parameter N_CORES = `N_CORES,
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1),
	parameter INPUT_WIDTH = `UNIT_INPUT_WIDTH,
	parameter MEM_WIDTH = `MEM_WIDTH,
	parameter RATIO = MEM_WIDTH / INPUT_WIDTH,
	parameter RATIO_MSB = `MSB(RATIO),
	parameter AFULL_SIZE = 13
	)(
	input CLK,

	input [INPUT_WIDTH-1:0] in,
	input wr_en, ctrl,
	output afull,
	output reg ready = 1,

	output [MEM_WIDTH-1 :0] out,
	output [`MEM_TOTAL_MSB :0] mem_addr,
	input rd_en,
	output empty,

	// thread_state (ts)
	output [N_THREADS_MSB :0] ts_wr_num, ts_rd_num, // Thread #
	output reg ts_wr_en = 0,
	output [`THREAD_STATE_MSB :0] ts_wr,
	input [`THREAD_STATE_MSB :0] ts_rd,

	output reg [`ENTRY_PT_MSB:0] entry_pt_curr = 0
	);

	assign ts_wr = `THREAD_STATE_WR_RDY;

	reg [INPUT_WIDTH-1:0] in_r;
	reg ctrl_r = 0, wr_en_r = 0;
	always @(posedge CLK) begin
		wr_en_r <= wr_en;
		if (wr_en) begin
			in_r <= in;
			ctrl_r <= ctrl;
		end
	end
	

	reg [N_THREADS_MSB :0] thread_num = 0;
	assign ts_wr_num = thread_num;
	assign ts_rd_num = thread_num;
	reg [`MEM_ADDR_MSB :0] thread_mem_addr = 0;
	assign mem_addr = { thread_num, thread_mem_addr };

	wire [`MSB(N_THREADS-1) :0] thread_num_next;
	next_thread_num #( .N_CORES(N_CORES), .N_THREADS(N_THREADS)
	) next_thread_num( .in(thread_num), .out(thread_num_next) );


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
			if (wr_en_r & ctrl_r & in_r[2:0] == 0)
				state_in <= STATE_IN_GOING;
`ifdef ENTRY_PTS_EN
			else if (wr_en_r & ctrl_r & in_r[2:0] == 1) begin
				entry_pt_curr <= in [`ENTRY_PT_MSB+3 :3];
				state_in <= STATE_IN_WAIT_PKT_END;
			end
`endif
		end

`ifdef ENTRY_PTS_EN
		STATE_IN_WAIT_PKT_END: if (wr_en_r & ctrl_r)
			state_in <= STATE_IN_NONE;
`endif

		STATE_IN_GOING: begin
			ready <= 0;
			if (wr_en_r & ctrl_r)
				state_in <= STATE_IN_WAIT_WRITE_MEM;
		end

		STATE_IN_WAIT_WRITE_MEM:
			if (empty & fifo_empty) begin
				ts_wr_en <= 1;
				state_in <= STATE_IN_SEARCH1;
			end

		STATE_IN_SEARCH1: begin // Search for idle thread
			thread_num <= thread_num_next;
			state_in <= STATE_IN_SEARCH2;
		end

		STATE_IN_SEARCH2:
			state_in <= STATE_IN_SEARCH3;

		STATE_IN_SEARCH3:
			if (ts_rd == `THREAD_STATE_NONE) begin
				ready <= 1;
				state_in <= STATE_IN_NONE;
			end
			else
				state_in <= STATE_IN_SEARCH1;

		endcase
	end


	wire [INPUT_WIDTH-1 :0] fifo_dout;
	unit_input_fifo #( .WIDTH(INPUT_WIDTH), .AFULL_SIZE(AFULL_SIZE)
	) unit_input_fifo(
		.CLK(CLK), .din(in_r), .wr_en(wr_en_r & state_in == STATE_IN_GOING),
		.afull(afull),
		.rd_en(fifo_rd_en), .empty(fifo_empty), .dout(fifo_dout)
	);


	// *********************************************
	//
	//   OUTPUT
	//
	// *********************************************

	localparam STATE_OUT_NONE = 0,
				STATE_OUT_NEXT_WORD = 1;

	(* FSM_EXTRACT="true" *)
	reg [1:0] state_out = STATE_OUT_NONE;

	regNxW #( .N(RATIO), .WIDTH(INPUT_WIDTH)
	) regNxW(
		.CLK(CLK), .din(fifo_dout), .wr_en(fifo_rd_en),
		// Possible TODO: write incomplete MEM_WIDTH-bit word,
		// reset register (currently hangs)
		.rst(1'b0),
		.rd_en(rd_en), .empty(empty), .dout(out)
	);

	always @(posedge CLK)
	case(state_out)
	STATE_OUT_NONE: if (state_in == STATE_IN_GOING) begin
		thread_mem_addr <= 0;
		state_out <= STATE_OUT_NEXT_WORD;
	end

	STATE_OUT_NEXT_WORD: begin
		if (~empty & rd_en)
			thread_mem_addr <= thread_mem_addr + 1'b1;

		if (empty & fifo_empty & state_in == STATE_IN_WAIT_WRITE_MEM)
			state_out <= STATE_OUT_NONE;
	end
	endcase

	assign fifo_rd_en = (empty | ~empty & rd_en) & ~fifo_empty;

/*
`ifdef SIMULATION
	reg [9:0] X_BYTES_RECEIVED = 0;
	always @(posedge CLK)
		if (state_in == STATE_IN_NONE)
			X_BYTES_RECEIVED <= 0;
		else if (wr_en_r)
			X_BYTES_RECEIVED <= X_BYTES_RECEIVED + 1'b1;
`endif
*/
endmodule


module unit_input_fifo #(
	parameter WIDTH = -1,
	parameter AFULL_SIZE = 13
	)(
	input CLK,
	input [WIDTH-1:0] din,
	input wr_en,
	output reg afull = 0,

	input rd_en,
	output reg empty = 1,
	output [WIDTH-1:0] dout
	);

	(* RAM_STYLE="DISTRIBUTED" *)
	reg [WIDTH-1:0] ram [31:0];
	reg [4:0] input_addr = 0, output_addr = 0;

	assign dout = ram [output_addr];

	reg [4:0] size = 0;

	wire do_write = ~afull & wr_en;
	wire do_read = ~empty & rd_en;

	always @(posedge CLK) begin
		if (do_write) begin
			ram [input_addr] <= din;
			input_addr <= input_addr + 1'b1;
		end

		if (do_read)
			output_addr <= output_addr + 1'b1;

		if (do_write & do_read) begin
		end
		else if (do_write) begin
			size <= size + 1'b1;
			empty <= 0;
		end
		else if (do_read) begin
			size <= size - 1'b1;
			empty <= size == 1;
		end

		afull <= size >= 32 - AFULL_SIZE;
	end

endmodule


module regNxW #(
	parameter N = -1,
	parameter WIDTH = 8
	)(
	input CLK,
	input [WIDTH-1 :0] din,
	input wr_en, rd_en, rst,
	output reg empty = 1,
	output [N*WIDTH-1 :0] dout
	);

	reg [`MSB(N-1) :0] cnt = 0;
	always @(posedge CLK) begin
		if (rst)
			cnt <= 0;
		else if (wr_en)
			cnt <= cnt + 1'b1;

		if (wr_en & cnt == N-1)
			empty <= 0;
		if (rd_en)
			empty <= 1;
	end

	genvar i;
	generate
	for (i=0; i < N; i=i+1) begin:regs

		(* KEEP_HIERARCHY="true" *)
		regW #( .WIDTH(WIDTH)
		) regW( .CLK(CLK), .din(din), .ce(cnt == i & wr_en),
			.dout(dout[i*WIDTH +:WIDTH]) );

	end
	endgenerate

endmodule


module regW #(
	parameter WIDTH = -1
	)(
	input CLK,
	input [WIDTH-1:0] din,
	input ce,
	output reg [WIDTH-1:0] dout = 0
	);

	always @(posedge CLK)
		if (ce)
			dout <= din;

endmodule


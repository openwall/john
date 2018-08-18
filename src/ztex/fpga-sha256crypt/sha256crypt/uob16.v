`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "sha256.vh"

//
//   Unit's Output Buffer (UOB)
//
//
// Input (into the buffer) operation.
//
// 1. Multi-threaded environment. At any given time UOB may
//    contain data for 1 given thread.
// 2. Using 16-bit output from the CPU.
// 3. CPU memorizes which thread it writes.
//
//
// Output (from the buffer) operation.
//
// 1. After 'rd_en' assertion, it starts output its content,
//    'rd_en' no longer controls the data flow.
// 2. Output are header (1 word) and (OUT_N_WORDS * OUT_WIDTH) bits.
//
module uob16 #(
	parameter N_THREADS = 6,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1),
	parameter OUT_WIDTH = 2,
	parameter OUT_N_WORDS = 128 + 32,
	parameter RATIO = 16 / OUT_WIDTH
	)(
	input clk_wr,

	input [15:0] din,
	input wr_en, set_input_complete,
	input [`UOB_ADDR_MSB :0] wr_addr,
	output reg ready = 1, // buffer is empty, ready for write
	output reg full = 0, // buffer can't accept data
	// Briefly:
	// ready=1: any thread can start write
	// full=0: thread that started can continue writing

	input clk_rd,
	output reg [`UNIT_OUTPUT_WIDTH-1 :0] dout = 0,
	input rd_en,
	output reg empty = 1
	);


	// ***********************************
	//
	// Input
	//
	// ***********************************
	always @(posedge clk_wr) begin
		if (wr_en)
			ready <= 0;

		if (set_input_complete)
			full <= 1;
		else if (read_complete_sync) begin
			full <= 0;
			ready <= 1;
		end
	end

	sync_pulse sync_input_complete( .wr_clk(clk_wr),
		.sig(set_input_complete), .busy(),
		.rd_clk(clk_rd), .out(input_complete_sync) );


	// ******************************************************
	//
	// Memory (BRAM)
	// 32 words X 16 bits from the point of view from the CPU
	// Output is 2-bit wide
	//
	// ******************************************************
	reg [`MSB(OUT_N_WORDS-1) :0] output_addr = 0;
	wire [`UNIT_OUTPUT_WIDTH-1 :0] doutb;

	asymm_bram_min_rd #(
		.minWIDTH(2), .RATIO(8), .maxDEPTH(2**(`UOB_ADDR_MSB+1))
	) mem(
		.wr_clk(clk_wr), .wr_en(wr_en),
		.wr_addr(wr_addr), .din(din),
		// 2-cycle write
		//.wr_clk(clk_wr), .wr_en(wr_en_r | wr_en_r2),
		//.wr_addr(wr_addr_r), .din(din_r),

		.rd_clk(clk_rd), .rd_en(enb),
		.rd_addr(output_addr), .dout(doutb)
	);


	// ***********************************
	//
	// Output
	//
	// ***********************************

	localparam STATE_NONE = 0,
				STATE_RD_READY = 1,
				STATE_RD = 2,
				STATE_RD_END = 3;

	(* FSM_EXTRACT="true" *)
	reg [2:0] state_rd = STATE_NONE;

	always @(posedge clk_rd)
		case (state_rd)
		STATE_NONE: if (input_complete_sync) begin
			empty <= 0;
			state_rd <= STATE_RD_READY;
		end

		STATE_RD_READY: if (rd_en) begin
			dout <= 2'b11;
			output_addr <= output_addr + 1'b1;
			empty <= 1;
			state_rd <= STATE_RD;
		end

		STATE_RD: begin
			dout <= doutb;
			output_addr <= output_addr + 1'b1;
			if (output_addr == OUT_N_WORDS)
				state_rd <= STATE_RD_END;
		end

		STATE_RD_END: begin
			dout <= 0;
			output_addr <= 0;
			state_rd <= STATE_NONE;
		end
		endcase

	assign enb = state_rd != STATE_NONE;

	sync_pulse sync_read_complete( .wr_clk(clk_rd),
		.sig(state_rd == STATE_RD_END), .busy(),
		.rd_clk(clk_wr), .out(read_complete_sync) );

endmodule


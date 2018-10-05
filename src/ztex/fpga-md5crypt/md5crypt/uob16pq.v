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
//   Unit's Output Buffer (UOB) with Packet Queue
//
//
// Input (into the buffer) operation.
//
// 1. Multi-threaded environment. At any given time UOB may
//    accept data for 1 given thread.
// 2. Using 16-bit output from the CPU.
// 3. CPU memorizes which thread it writes.
// 4. After 'set_input_complete' asserts, the packet goes into output
//    queue, making UOB available for write immediately.
//
// Output (from the buffer) operation.
//
// 1. After 'rd_en' assertion, it starts output its content,
//    'rd_en' no longer controls the data flow.
// 2. Output are header (1 word) and (OUT_N_WORDS * OUT_WIDTH) bits.
//
module uob16pq #(
	parameter N_THREADS = 6,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1),
	parameter IN_WIDTH = 16,
	parameter PKT_LEN = 12, // in input words
	parameter PKT_QUEUE_MSB = 3, // 16 packets
	parameter OUT_WIDTH = `UNIT_OUTPUT_WIDTH,
	parameter RATIO = IN_WIDTH / OUT_WIDTH,
	parameter OUT_N_WORDS = PKT_LEN * RATIO //128 + 32
	)(
	input clk_wr,

	input [IN_WIDTH-1:0] din,
	input wr_en, set_input_complete,
	input [`UOB_ADDR_MSB :0] wr_addr,
	output reg ready = 1, // buffer is empty, ready for write
	output reg full = 0, // buffer can't accept data
	// Briefly:
	// ready=1: any thread can start write
	// full=0: thread that started can continue writing

	input clk_rd,
	output reg [OUT_WIDTH-1 :0] dout = 0,
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

	// sync'd after packet is enqueued
	sync_pulse3 sync_input_complete( .wr_clk(clk_wr),
		.sig(set_input_complete), .busy(),
		.rd_clk(clk_rd), .out(input_complete_sync) );

	reg [PKT_QUEUE_MSB:0] base_addr_wr = 0; // sync'd with clk_rd
	reg [PKT_QUEUE_MSB:0] base_addr_rd = 0;


	// ******************************************************
	//
	// Memory (BRAM)
	//
	// ******************************************************
	reg [`MSB(OUT_N_WORDS-1) :0] output_addr = 0;
	wire [`UNIT_OUTPUT_WIDTH-1 :0] doutb;

	asymm_bram_min_rd #(
		.minWIDTH(OUT_WIDTH), .RATIO(RATIO),
		.maxDEPTH( 2**(PKT_QUEUE_MSB+1 + `UOB_ADDR_MSB+1) )
	) mem(
		.wr_clk(clk_wr), .wr_en(wr_en),
		.wr_addr({base_addr_wr, wr_addr}), .din(din),

		.rd_clk(clk_rd), .rd_en(enb),
		.rd_addr({base_addr_rd, output_addr}), .dout(doutb)
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

	wire queue_empty = base_addr_wr == base_addr_rd;
	wire queue_full = base_addr_wr + 1'b1 == base_addr_rd;
	reg enqueued = 0;

	always @(posedge clk_rd) begin
		if (input_complete_sync) begin
			base_addr_wr <= base_addr_wr + 1'b1;
			enqueued <= 1;
		end

		if (state_rd == STATE_RD_END) begin
			base_addr_rd <= base_addr_rd + 1'b1;
		end

		if (enqueued & ~queue_full)
			enqueued <= 0;

		// Read from UOB. 'empty' deasserts after 'rd_en'.
		case (state_rd)
		STATE_NONE: if (~queue_empty) begin
			empty <= 0;
			state_rd <= STATE_RD_READY;
		end

		STATE_RD_READY: if (rd_en) begin
			dout <= {OUT_WIDTH{1'b1}};
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
	end

	assign enb = state_rd != STATE_NONE;

	sync_pulse3 sync_read_complete( .wr_clk(clk_rd),
		.sig(enqueued & ~queue_full), .busy(),
		.rd_clk(clk_wr), .out(read_complete_sync) );

endmodule


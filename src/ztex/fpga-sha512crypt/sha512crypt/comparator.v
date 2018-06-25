`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module comparator(
	input CLK,

	// Input from cmp_config
	input [7:0] din,
	input wr_en,
	input [`HASH_NUM_MSB+2:0] wr_addr,
	input [`HASH_COUNT_MSB:0] hash_count,

	// Iteraction with arbiter_rx (comparsion)
	input [31:0] cmp_data,
	input start,
	output reg found = 0, finished = 0,
	output reg [`HASH_NUM_MSB:0] hash_num = 0
	);


	// **************************************************
	//
	// Comparator's memory.
	// Input is 8-bit, output is 32-bit.
	//
	// **************************************************
	localparam DEPTH = 512;

	reg [`MSB(DEPTH):0] rd_addr = 0;
	wire [31:0] mem_dout;

	asymm_bram_min_wr #( .minWIDTH(), .RATIO(4), .maxDEPTH(DEPTH)
	) mem(
		.wr_clk(CLK), .din(din), .wr_en(wr_en), .wr_addr(wr_addr),
		.rd_clk(CLK), .dout(mem_dout), .rd_en(rd_en),
		.rd_addr(rd_addr[`MSB(DEPTH-1):0])
	);


	// **************************************************
	//
	// Comparator's function.
	// It iterates the list linearily.
	//
	// **************************************************
	localparam STATE_IDLE = 0,
				STATE_START = 1,
				STATE_COMPARE = 2;

	(* FSM_EXTRACT="true" *)
	reg [1:0] state = STATE_IDLE;

	always @(posedge CLK) begin
		case (state)
		STATE_IDLE: if (start) begin
			found <= 0;
			finished <= 0;
			rd_addr <= 0;
			state <= STATE_START;
		end

		STATE_START: begin
			hash_num <= 0;
			state <= STATE_COMPARE;
		end

		STATE_COMPARE: begin
			rd_addr <= rd_addr + 1'b1;
			if (rd_addr == hash_count) begin
				finished <= 1;
				state <= STATE_IDLE;
			end

			if (mem_dout == cmp_data) begin
				found <= 1;
				state <= STATE_IDLE;
			end
			else
				hash_num <= rd_addr[`HASH_NUM_MSB:0];
		end
		endcase
	end

	assign rd_en = state != STATE_IDLE;


endmodule

`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// ********************************************************************
//
// ********************************************************************

module word_storage #(
	parameter WORD_MAX_LEN = -1
	)(
	input CLK,
	
	input [7:0] din,
	input [`MSB(WORD_MAX_LEN-1):0] wr_addr,
	input wr_en,
	input set_full,
	output reg full = 0,

	// Asynchronous read
	output [7:0] dout,
	input [`MSB(WORD_MAX_LEN-1):0] rd_addr,
	//input rd_en,
	input set_empty,
	output empty
	);

	assign empty = ~full;
	
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [7:0] storage [WORD_MAX_LEN-1:0];
	assign dout = storage [rd_addr];

	localparam	STATE_WR = 0,
					STATE_RD = 1;

	(* FSM_EXTRACT="true" *)
	reg [1:0] state = STATE_WR;
	
	always @(posedge CLK) begin
		case (state)
		STATE_WR: begin
			if (wr_en)
				storage [wr_addr] <= din;
			if (set_full) begin
				full <= 1;
				state <= STATE_RD;
			end
		end
		
		STATE_RD: if (set_empty) begin
			full <= 0;
			state <= STATE_WR;
		end
		endcase
	end
	
endmodule

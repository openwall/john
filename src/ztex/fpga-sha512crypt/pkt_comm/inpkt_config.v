`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

module inpkt_config(
	input CLK,
	input [7:0] din,
	input wr_en,
	output full,

	output reg [15:0] dout1 = 0,
	output reg err = 0
	);

	assign full = 0;

	localparam STATE_SUBTYPE = 0,
				STATE_DATA0 = 1,
				STATE_DATA1 = 2,
				STATE_RESERVED = 3;

	(* FSM_EXTRACT="true" *)
	reg [2:0] state = STATE_SUBTYPE;

	always @(posedge CLK) if (~err & wr_en)
		case(state)
		STATE_SUBTYPE: begin
			if (din != 1)
				err <= 1;
			state <= STATE_DATA0;
		end
		
		// Subtype 1: 16-bit value
		STATE_DATA0: begin
			dout1 [7:0] <= din;
			state <= STATE_DATA1;
		end
		
		STATE_DATA1: begin
			dout1 [15:8] <= din;
			state <= STATE_RESERVED;
		end
		
		STATE_RESERVED:
			state <= STATE_SUBTYPE;
		endcase

endmodule

`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module regs2d #( // 2-direction
	parameter IN_WIDTH = -1,
	parameter OUT_WIDTH = -1,
	parameter STAGES = 0 // 0 stages - no registers
	)(
	input CLK,
	input [IN_WIDTH-1:0] enter_in,
	output [OUT_WIDTH-1:0] enter_out,
	output [IN_WIDTH-1:0] exit_in,
	input [OUT_WIDTH-1:0] exit_out
	);


	wire [IN_WIDTH-1:0] stage_in [STAGES:0];
	assign stage_in[0] = enter_in;
	assign exit_in = stage_in [STAGES];

	wire [OUT_WIDTH-1:0] stage_out [STAGES:0];
	assign enter_out = stage_out[0];
	assign stage_out [STAGES] = exit_out;


	genvar k;
	generate
	for (k=0; k < STAGES; k=k+1) begin:stage

		(* SHREG_EXTRACT="no" *)
		reg [IN_WIDTH-1:0] r_in = 0;
		always @(posedge CLK)
			r_in <= stage_in[k];

		assign stage_in[k+1] = r_in;
		
		(* SHREG_EXTRACT="no" *)
		reg [OUT_WIDTH-1:0] r_out = 0;
		always @(posedge CLK)
			r_out <= stage_out[k+1];
		
		assign stage_out[k] = r_out;

	end
	endgenerate

endmodule

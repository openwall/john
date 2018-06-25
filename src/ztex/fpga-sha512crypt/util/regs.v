`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module regs #(
	parameter N = -1,
	parameter STAGES = 0 // 0 stages - no registers
	)(
	input CLK,
	input [N-1:0] in,
	output [N-1:0] out
	);


	wire [N-1:0] stage_output [STAGES:0];

	assign stage_output[0] = in;
	assign out = stage_output [STAGES];


	genvar k;
	generate
	for (k=0; k < STAGES; k=k+1) begin:stage
	
		(* SHREG_EXTRACT="no" *)
		reg [N-1:0] r = 0;
		always @(posedge CLK)
			r <= stage_output[k];

		assign stage_output[k+1] = r;

	end
	endgenerate

endmodule

`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

module shreg #(
	parameter WIDTH = 32,
	parameter DEPTH = 1 // 1+
	)(
	input CLK,
	input [WIDTH-1:0] i,
	input en,
	output [WIDTH-1:0] o
	);

	genvar j;

	wire [3:0] A = DEPTH - 1;

	generate
	for (j=0; j < WIDTH; j=j+1) begin:shreg

		SRL16E #(
			.INIT(16'h0000) // Initial Value of Shift Register
		) SRL16E_inst (
			.Q(o[j]),       // SRL data output
			.A0(A[0]),     // Select[0] input
			.A1(A[1]),     // Select[1] input
			.A2(A[2]),     // Select[2] input
			.A3(A[3]),     // Select[3] input
			.CE(en),     // Clock enable input
			.CLK(CLK),   // Clock input
			.D(i[j])        // SRL data input
		);

	end
	endgenerate

endmodule

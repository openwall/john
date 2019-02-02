`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "../sha512.vh"

//
// Synthesis: Optimization: Area
//
`ifndef SIMULATION

module add3 #(
	parameter WIDTH = 64,
	parameter [WIDTH-1:0] IV = 0
	)(
	input CLK,
	input [WIDTH-1:0] a, b, c,
	input en, rst,
	output reg [WIDTH-1:0] o = IV
	);

endmodule

`else

module add3 #(
	parameter WIDTH = 64,
	parameter [WIDTH-1:0] IV = 0
	)(
	input CLK,
	input [WIDTH-1:0] a, b, c,
	input en, rst,
	output reg [WIDTH-1:0] o = IV
	);

	always @(posedge CLK)
		if (rst)
			o <= IV;
		else if (en)
			o <= a + b + c;

endmodule

`endif


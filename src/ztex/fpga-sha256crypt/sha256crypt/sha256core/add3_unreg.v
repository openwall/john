`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "../sha256.vh"

//
// Synthesis: Optimization: Area
//
`ifndef SIMULATION

module add3_unreg #(
	parameter WIDTH = 32
	)(
	input [WIDTH-1:0] a, b, c,
	output [WIDTH-1:0] o
	);

endmodule

`else

module add3_unreg #(
	parameter WIDTH = 32
	)(
	input [WIDTH-1:0] a, b, c,
	output [WIDTH-1:0] o
	);

	assign o = a + b + c;

endmodule

`endif

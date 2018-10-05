`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "../md5.vh"

`ifndef SIMULATION

module ff32 #(
	parameter N = 32
	)(
	input CLK,
	input en, rst,
	input [N-1:0] i,
	output reg [N-1:0] o = 0
	);

endmodule

`else

module ff32 #(
	parameter N = 32
	)(
	input CLK,
	input en, rst,
	input [N-1:0] i,
	output reg [N-1:0] o = 0
	);

	always @(posedge CLK)
		if (rst)
			o <= 0;
		else if (en)
			o <= i;

endmodule

`endif

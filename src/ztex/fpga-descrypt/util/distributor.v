`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//
// Distributes WIDTH-bit data items among N entities.
//
module distributor #(
	parameter WIDTH = -1,
	parameter N = 1
	)(
	input CLK,
	input [WIDTH-1:0] din,
	input bcast,
	input wr_en,
	output full,

	output [WIDTH*N-1:0] dout,
	input [N-1:0] rd_en,
	output reg [N-1:0] empty = {N{1'b1}}
	);

	genvar i;

	wire all_empty = &empty;

	reg [`MSB(N-1):0] next_r = 0;
	assign full = ~((~bcast & empty[next_r]) | (bcast & all_empty));

	always @(posedge CLK) begin
		if (~empty[next_r])
			if (next_r == N-1)
				next_r <= 0;
			else
				next_r <= next_r + 1'b1;
	end

	generate
	for (i=0; i < N; i=i+1) begin:distrib

		reg [WIDTH-1:0] dout_r;
		assign dout[WIDTH*(i+1)-1 : WIDTH*i] = dout_r;

		always @(posedge CLK) begin
			if (~empty[i]) begin
				if (rd_en[i])
					empty[i] <= 1;
			end
			if (wr_en & ((empty[i] & next_r == i) | (bcast & all_empty)) ) begin
				dout_r <= din;
				empty[i] <= 0;
			end
		end

	end
	endgenerate

endmodule


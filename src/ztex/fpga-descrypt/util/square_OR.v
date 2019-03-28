`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

module square_OR #(
	parameter WIDTH = -1,
	parameter N = 1
	)(
	input [N*WIDTH-1:0] din,
	output [WIDTH-1:0] dout
	);

	genvar i, j;

	generate
	for (i=0; i < WIDTH; i=i+1) begin:outer

		wire [N-1:0] bit_i;
		assign dout[i] = |bit_i;

		for (j=0; j < N; j=j+1) begin:inner
			assign bit_i[j] = din[WIDTH*j+i];
		end

	end
	endgenerate

endmodule


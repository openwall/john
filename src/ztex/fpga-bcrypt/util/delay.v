`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//
// After 'in' is asserted for about 2**NBITS cycles,
// 'out' gets asserted.
// Deassertion of 'in' resets the counter and
// deasserts 'out' in 1 cycle.
//
module delay #(
	parameter [0:0] INIT = 0,
	parameter NBITS = 4,
	parameter CMP_NUM_MSBITS = 4
	)(
	input CLK,
	input in,
	output reg out = INIT
	);

	localparam CMP_NUM_BITS = NBITS > CMP_NUM_MSBITS ? CMP_NUM_MSBITS : NBITS;

	reg [NBITS-1:0] counter = 0;

	always @(posedge CLK)
		if (~in) begin
			counter <= 0;
			out <= 0;
		end
		else if (&counter[NBITS-1 -:CMP_NUM_BITS])
			out <= 1;
		else
			counter <= counter + 1'b1;

endmodule


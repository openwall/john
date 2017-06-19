`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

/*
WARNING:Place:913 - Local congestion has been detected at location
	SLICE_X19Y154. There is a limitation that at most 2 global signals can drive
	non-clock pins per CLB. The placer has detected SLICE_X19Y154 is present in a
	CLB that has3 global signals driving non-clock pins. This may result in an
	unroutable situation.

	- Actually it can get 3rd global signal from an adjacent CLB,
	- or it can fail (resulting in signal gets unrouted)
*/

module global_wires #(
	parameter N = -1
	)(
	input [N-1:0] in,
	output [N-1:0] out
	);

	genvar i;
	
	generate
	for (i=0; i < N; i=i+1) begin:global_wires
	
		BUFG BUFG_0(
			.I(in[i]),
			.O(out[i])
		);
	
	end
	endgenerate

endmodule


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


module core_input_buf(
	input CLK,

	input [31:0] din,
	input [3:0] wr_addr,
	input wr_en,
	
	output reg [31:0] dout = 0,
	input rd_en,
	input [3:0] rd_addr
	);

	// Data block 512-bit (2x)
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [31:0] input_buf [0:15];

	always @(posedge CLK) begin
		if (rd_en)
			dout <= input_buf [rd_addr];
		if (wr_en)
			input_buf [wr_addr] <= `SWAP(din);
	end

endmodule

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
// 4x 1K S-blocks for bcrypt core
//
module S #(
	parameter MSB = 31,
	parameter ADDR_NBITS = 8
	)(
	input CLK,
	input [MSB:0] din,
	input wr_en,
	input [9:0] addr_wr,

	input rd_en,
	input rst_rd,
	input [MSB:0] addr_rd,
	output [MSB:0] out
	);

	reg [MSB:0] S0 [255:0];
	reg [MSB:0] S1 [255:0];
	reg [MSB:0] S2 [255:0];
	reg [MSB:0] S3 [255:0];

	reg [MSB:0] S0_out = 0, S1_out = 0, S2_out = 0, S3_out = 0;

	always @(posedge CLK) begin
		// Write channel
		if (wr_en && addr_wr[9:8] == 2'b00)
			S0 [addr_wr[7:0]] <= din;
		if (wr_en && addr_wr[9:8] == 2'b01)
			S1 [addr_wr[7:0]] <= din;
		if (wr_en && addr_wr[9:8] == 2'b10)
			S2 [addr_wr[7:0]] <= din;
		if (wr_en && addr_wr[9:8] == 2'b11)
			S3 [addr_wr[7:0]] <= din;

		// Read channel
		if (rst_rd) begin
			S0_out <= 0;
			S1_out <= 0;
			S2_out <= 0;
			S3_out <= 0;
		end
		else if (rd_en) begin
			S0_out <= S0 [ addr_rd[4*ADDR_NBITS-1 : 3*ADDR_NBITS] ];
			S1_out <= S1 [ addr_rd[3*ADDR_NBITS-1 : 2*ADDR_NBITS] ];
			S2_out <= S2 [ addr_rd[2*ADDR_NBITS-1 : ADDR_NBITS] ];
			S3_out <= S3 [ addr_rd[ADDR_NBITS-1 : 0] ];
		end
	end


	assign out = S3_out + (S2_out ^ (S1_out + S0_out));


endmodule

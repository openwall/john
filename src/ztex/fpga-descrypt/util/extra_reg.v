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
//
module extra_reg_afull #(
	parameter WIDTH = -1
	)(
	input CLK,
	input [WIDTH-1:0] din,
	input wr_en,
	(* SHREG_EXTRACT="false" *) output reg full = 1,

	(* SHREG_EXTRACT="false" *) output reg [WIDTH-1:0] dout,
	input afull,
	input rd_en,
	(* SHREG_EXTRACT="false" *) output reg empty = 1
	);

	always @(posedge CLK) begin
		full <= afull;

		if (wr_en) begin
			empty <= 0;
			dout <= din;
		end
		else if (rd_en)
			empty <= 1;
	end

endmodule


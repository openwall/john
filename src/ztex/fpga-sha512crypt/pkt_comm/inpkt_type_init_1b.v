`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//
// PKT_TYPE_INIT (0x05) typically contain runtime
// initialization data.
// Length of 1 byte is currently supported.
//
module inpkt_type_init_1b(
	input CLK,
	input [7:0] din,
	input wr_en,
	output full,

	output reg [7:0] dout = 0,
	input rd_en,
	output reg empty = 1
	//output reg err = 0
	);

	assign full = 0;

	always @(posedge CLK) begin
		if (wr_en & empty) begin
			dout <= din;
			empty <= 0;
		end
		if (rd_en & ~empty)
			empty <= 1;
	end

endmodule

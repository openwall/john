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
// Synchronous FIFO (DRAM)
// 1st Word Fall-Through
// Area Optimized
//
module fifo_sync_small #(
	parameter D_WIDTH = -1,
	parameter A_WIDTH = 5
	)(
	input CLK,
	input [D_WIDTH-1:0] din,
	input wr_en,
	output full,

	output [D_WIDTH-1:0] dout,
	input rd_en,
	output empty
	);

	(* RAM_STYLE="DISTRIBUTED" *)
	reg [D_WIDTH-1:0] ram [2**A_WIDTH-1:0];
	reg [A_WIDTH-1:0] inptr = 0, outptr = 0;

	assign empty = inptr == outptr;
	assign full = inptr + 1'b1 == outptr;
	assign dout = ram[outptr];

	always @(posedge CLK) begin
		if (~full & wr_en) begin
			ram[inptr] <= din;
			inptr <= inptr + 1'b1;
		end
		if (~empty & rd_en)
			outptr <= outptr + 1'b1;
	end

endmodule


module fifo_sync_fast #(
	parameter D_WIDTH = -1,
	parameter A_WIDTH = 5
	)(
	input CLK,
	input [D_WIDTH-1:0] din,
	input wr_en,
	output reg full = 0,

	output [D_WIDTH-1:0] dout,
	input rd_en,
	output reg empty = 1
	);

	(* RAM_STYLE="DISTRIBUTED" *)
	reg [D_WIDTH-1:0] ram [2**A_WIDTH-1:0];
	reg [A_WIDTH-1:0] inptr = 0, outptr = 0;

	assign dout = ram[outptr];

	wire do_write = ~full & wr_en;
	wire do_read = ~empty & rd_en;

	always @(posedge CLK) begin
		if (do_write) begin
			ram[inptr] <= din;
			inptr <= inptr + 1'b1;
		end

		if (do_read)
			outptr <= outptr + 1'b1;

		full <= ~do_read & (inptr + 1'b1 == outptr
				|| inptr + 2'b10 == outptr & do_write);

		empty <= ~do_write & (inptr == outptr
				|| inptr == outptr + 1'b1 & do_read);
	end

endmodule


module fifo_sync_fast_af_ae #(
	parameter D_WIDTH = -1,
	parameter A_WIDTH = 5
	)(
	input CLK,
	input [D_WIDTH-1:0] din,
	input wr_en,
	output reg full = 0,
	output reg almost_full = 0,

	output [D_WIDTH-1:0] dout,
	input rd_en,
	output reg empty = 1,
	output reg almost_empty = 1
	);

	(* RAM_STYLE="DISTRIBUTED" *)
	reg [D_WIDTH-1:0] ram [2**A_WIDTH-1:0];
	reg [A_WIDTH-1:0] inptr = 0, outptr = 0;

	assign dout = ram[outptr];

	wire do_write = ~full & wr_en;
	wire do_read = ~empty & rd_en;

	always @(posedge CLK) begin
		if (do_write) begin
			ram[inptr] <= din;
			inptr <= inptr + 1'b1;
		end

		if (do_read)
			outptr <= outptr + 1'b1;

		full <= ~do_read & (inptr + 1'b1 == outptr
				|| inptr + 2'b10 == outptr & do_write);

		almost_full <= full
				|| ~do_read & (inptr + 2'b10 == outptr
				|| inptr + 2'b11 == outptr & do_write);

		empty <= ~do_write & (inptr == outptr
				|| inptr == outptr + 1'b1 & do_read);

		almost_empty <= empty
				|| ~do_write & (inptr == outptr + 1'b1
				|| inptr == outptr + 2'b10 & do_read);
	end

endmodule


//
// Like fifo_sync_fast, output is equpped with extra register
//
module fifo_sync_very_fast #(
	parameter D_WIDTH = -1,
	parameter A_WIDTH = 5
	)(
	input CLK,
	input [D_WIDTH-1:0] din,
	input wr_en,
	output full,

	output reg [D_WIDTH-1:0] dout,
	input rd_en,
	output reg empty = 1
	);

	wire [D_WIDTH-1:0] fifo_dout;

	fifo_sync_fast #( .A_WIDTH(A_WIDTH), .D_WIDTH(D_WIDTH)
	) fifo_sync_fast(
		.CLK(CLK),
		.din(din),
		.wr_en(wr_en), .full(full),

		.dout(fifo_dout),
		.rd_en(fifo_rd_en), .empty(fifo_empty)
	);

	assign fifo_rd_en = empty & ~fifo_empty
		|| ~empty & ~fifo_empty & rd_en;

	always @(posedge CLK)
		if (fifo_rd_en) begin
			dout <= fifo_dout;
			empty <= 0;
		end
		else if (rd_en)
			empty <= 1;

endmodule


module fifo_sync_very_fast_af #(
	parameter D_WIDTH = -1,
	parameter A_WIDTH = 5
	)(
	input CLK,
	input [D_WIDTH-1:0] din,
	input wr_en,
	output full, almost_full,

	output reg [D_WIDTH-1:0] dout,
	input rd_en,
	output reg empty = 1
	);

	wire [D_WIDTH-1:0] fifo_dout;

	fifo_sync_fast_af_ae #( .A_WIDTH(A_WIDTH), .D_WIDTH(D_WIDTH)
	) fifo_sync_fast(
		.CLK(CLK),
		.din(din),
		.wr_en(wr_en),
		.full(full), .almost_full(almost_full),

		.dout(fifo_dout),
		.rd_en(fifo_rd_en),
		.empty(fifo_empty), .almost_empty(fifo_almost_empty)
	);

	assign fifo_rd_en = empty & ~fifo_empty
		|| ~empty & ~fifo_empty & rd_en;

	always @(posedge CLK)
		if (fifo_rd_en) begin
			dout <= fifo_dout;
			empty <= 0;
		end
		else if (rd_en)
			empty <= 1;

endmodule

`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 *
 * Output Limit FIFO (high-speed output).
 *
 * Features:
 *
 * - Configurable width and depth
 * - 1st word Fall-Through
 * - Does not output on its own (reports EMPTY) when mode_limit == 1.
 *
 * - When reg_output_limit asserted:
 * -- Reports amount ready for output (output_limit) in WIDTH-bit words
 * -- Starts output of that amount, asserts output_limit_not_done
 * -- Deasserts output_limit_not_done when finished
 *
 * - Does not require extra components from IP Coregen
 * - The design is unable for asynchronous operation
 * - Size equals to RAM size minus 1 word.
 *
 */

module output_limit_fifo #(
	// ADDR_MSB==11 : 8 Kbytes
	parameter ADDR_MSB = 11,
	parameter WIDTH = 16
	)(
	input rst,
	input CLK,

	input [WIDTH-1:0] din,
	input wr_en,
	output full,

	output [WIDTH-1:0] dout,
	input rd_en,
	output empty,

	input mode_limit, // turn on output limit
	input reg_output_limit,
	output [15:0] output_limit,
	output reg output_limit_not_done
	);

	reg [ADDR_MSB:0] addra = 0;
	reg [ADDR_MSB:0] output_limit_addr = 0;
	reg [ADDR_MSB:0] output_limit_r = 0;
	reg [ADDR_MSB:0] addrb = 0;

	// 1st Word Fall-Through
	reg wft = 0;
	assign empty = rst || ~wft;

	assign output_limit = { {15-ADDR_MSB{1'b0}}, output_limit_r };

	assign full = rst || (addra + 1'b1 == addrb);
	wire ena = wr_en && !full;

	always @(posedge CLK) begin
		if (rst) begin
			addra <= 0;
			output_limit_addr <= 0;
			output_limit_r <= 0;
		end
		else begin
			if (ena) begin
				addra <= addra + 1'b1;
			end

			if (!mode_limit || reg_output_limit) begin
				output_limit_addr <= addra;
				output_limit_r <= addra - output_limit_addr;
			end
		end // ~rst
	end

	wire ram_empty_or_limit = (output_limit_addr == addrb);

	wire enb = (!ram_empty_or_limit && (empty || rd_en));
	reg enb_r = 0;

	wire [15:0] ram_out;
	reg [15:0] dout_r;
	assign dout = dout_r;

	always @(posedge CLK) begin
		if (rst) begin
			addrb <= 0;
			wft <= 0;
			enb_r <= 0;
		end
		else begin
			if (empty || rd_en)
				enb_r <= enb;

			if (enb) begin
				addrb <= addrb + 1'b1;
			end

			if (enb_r) begin
				if (!wft || rd_en) begin
					wft <= 1;
					dout_r <= ram_out;
				end
			end // enb_r
			else if (rd_en)
				wft <= 0;
		end // ~rst

		output_limit_not_done <= ~ram_empty_or_limit;
	end


	(* RAM_STYLE = "BLOCK" *)
	reg [WIDTH-1:0] ram [2**(ADDR_MSB+1)-1:0];
	reg [WIDTH-1:0] ram_out_r;
	assign ram_out = ram_out_r;

	always @(posedge CLK) begin
		if (ena)
			ram[addra] <= din;
		if (enb)
			ram_out_r <= ram[addrb];
	end

endmodule

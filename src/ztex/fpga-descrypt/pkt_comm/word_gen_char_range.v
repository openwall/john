`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016-2017,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

module word_gen_char_range #(
	parameter CHAR_BITS = 7, // valid values: 7 8
	parameter CHARS_NUMBER_MAX = CHAR_BITS == 7 ? 128 : 256,
	parameter NUM_CHARS_MSB = `MSB(CHARS_NUMBER_MAX-1)
	)(
	input CONF_CLK, // configuration clock
	input [CHAR_BITS-1:0] din,

	input conf_en_num_chars,
	input num_chars_eq0,	// number of chars in the range equals to 0
	input num_chars_lt2,	// less than 2 chars in the range

	input conf_en_chars,
	input [NUM_CHARS_MSB:0] conf_char_addr,
	input pre_end_char, // asserted on char before last char in the range (conf_en_chars)

	input OP_CLK, // generation clock
	input op_en,
	input [2:0] op_state,
	input op_done_sync,

	input carry_in,
	output carry,
	output [CHAR_BITS-1:0] dout
	);

	`include "word_gen.vh"

	reg num_chars_eq0_r = 1;
	reg num_chars_lt2_r = 1;
	reg [NUM_CHARS_MSB:0] current_idx = 0;

	wire do_next;

	wire [1+ CHAR_BITS-1:0] dina = { pre_end_char, din[NUM_CHARS_MSB:0]};
	wire pre_end_char_out;
	wire [CHAR_BITS-1:0] char_out;

	word_gen_range_ram #( .ADDR_MSB(CHAR_BITS-1), .WIDTH(1+ CHAR_BITS)
	) ram(
		.wr_clk(CONF_CLK), .addra(conf_char_addr), .ena(conf_en_chars),
		.dina(dina),

		.rd_clk(OP_CLK),
		.addrb(current_idx), .enb(do_next), .rstb(num_chars_eq0_r),
		.doutb({pre_end_char_out, char_out})
	);

	always @(posedge OP_CLK) begin
		if (op_state == OP_STATE_READY | num_chars_lt2_r
				| do_next & pre_end_char_out)
			current_idx <= 0;

		else if (do_next)
			current_idx <= current_idx + 1'b1;

	end

	reg carry_r;
	always @(posedge OP_CLK)
		if (do_next)
			carry_r <= pre_end_char_out | num_chars_lt2_r;


	// Extra register stage
	if (EXTRA_REGISTER_STAGE) begin

		assign do_next =
			op_state == OP_STATE_START | op_state == OP_STATE_EXTRA_STAGE
			| op_state == OP_STATE_NEXT_CHAR & op_en & carry_in;

		(* SHREG_EXTRACT="no" *) reg carry_r2;
		(* SHREG_EXTRACT="no" *) reg [CHAR_BITS-1:0] dout_r2;
		always @(posedge OP_CLK)
			if (do_next) begin
				carry_r2 <= carry_r;
				dout_r2 <= char_out;
			end

		assign carry = carry_r2;
		assign dout = dout_r2;

	end else begin

		assign do_next =
			op_state == OP_STATE_START
			| op_state == OP_STATE_NEXT_CHAR & op_en & carry_in;

		assign carry = carry_r;
		assign dout = char_out;

	end // EXTRA_REGISTER_STAGE


	// Range configuration
	always @(posedge CONF_CLK) begin
		if (op_done_sync) begin
			num_chars_eq0_r <= 1;
			num_chars_lt2_r <= 1;
		end
		else if (conf_en_num_chars) begin
			num_chars_eq0_r <= num_chars_eq0;
			num_chars_lt2_r <= num_chars_lt2;
		end
	end

endmodule


module word_gen_range_ram #(
	parameter ADDR_MSB = 0,
	parameter WIDTH = 18
	)(
	input wr_clk,
	input [ADDR_MSB:0] addra,
	input [WIDTH-1:0] dina,
	input ena,

	input rd_clk,
	input [ADDR_MSB:0] addrb,
	input rstb, enb,
	output [WIDTH-1:0] doutb
	);

	(* RAM_STYLE = "BLOCK" *)
	reg [WIDTH-1:0] ram [2**(ADDR_MSB+1)-1:0];
	reg [WIDTH-1:0] ram_out_r;
	assign doutb = ram_out_r;

	always @(posedge wr_clk)
		// Port A write
		if (ena)
			ram[addra] <= dina;

	always @(posedge rd_clk) begin
		//
		// UG383 Spartan-6 Block RAM User Guide pg.21
		// "... the set/reset function is active only
		// when the enable pin of the port is active."
		//
		// Port B reset (RSTBRST)
		if (rstb)
			ram_out_r <= 0;

		// Port B read enable (ENBRDEN)
		else if (enb)
			ram_out_r <= ram[addrb];
	end

endmodule

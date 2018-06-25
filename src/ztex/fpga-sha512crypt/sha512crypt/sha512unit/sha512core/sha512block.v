`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "../sha512.vh"

`define	SHA512_R0(x)	(`CYCLIC (x, 1) ^ `CYCLIC (x, 8) ^ (x >> 7))
`define	SHA512_R1(x)	(`CYCLIC (x, 19) ^ `CYCLIC (x, 61) ^ (x >> 6))


module sha512block(
	input CLK,
	
	input external_input_en, // select external input
	input ctx_save_en, // select save into memory from context
	input [63:0] in, ctx_in,

	// memory ops
	input mem_wr_en,
	input [7:0] wr_addr, rd_addr0, rd_addr1,

	// register ops
	input W16_R1_rst, R0_rst, Wt_rst,

	output [63:0] block2ctx, // loading context from mem1
	output reg [63:0] Wt = 0
	);

	reg [63:0] save_r = 0;
	
	wire [63:0] mem0_out, mem1_out;

	w_mem w_mem(
		.CLK(CLK),
		.in(save_r),
		.wr_en(mem_wr_en),
		.wr_addr(wr_addr),

		.rd_addr0(rd_addr0), .rd_addr1(rd_addr1),
		.out0(mem0_out), .out1(mem1_out) // right out from BRAM
	);

	wire [63:0] mem0, mem1;
	// Prevent usage of BRAM output registers
	ff_reg ff_reg0(
		.CLK(CLK), .en(1'b1), .rst(1'b0),
		.i(mem0_out), .o(mem0)
	);

	reg [63:0] R0 = 0;
	always @(posedge CLK)
		R0 <= R0_rst ? 0 : `SHA512_R0(mem1_out);

	ff_reg ff_reg1(
		.CLK(CLK), .en(1'b1), .rst(1'b0),
		.i(mem1_out), .o(mem1)
	);
	assign block2ctx = mem1;


	reg [63:0] Wtmp;
	reg [63:0] W16 = 0;
	reg [63:0] W16_2, W16_3;
	reg [63:0] R1 = 0;
	reg [63:0] R1_2;
	reg [63:0] Wt_r;

	always @(posedge CLK) begin
		save_r <= ctx_save_en ? ctx_in : R1_2;
		
		//Wtmp <= external_input_en ? in : mem0 + R0; // wastes LUTs
		Wtmp <= R0 + (external_input_en ? in : mem0);
		Wt_r <= Wtmp + W16 + R1;
		Wt <= Wt_rst ? 0 : Wt_r;

		W16 <= W16_R1_rst ? 0 : W16_2;
		W16_2 <= W16_3;
		W16_3 <= mem1;
		
		R1 <= W16_R1_rst ? 0 : `SHA512_R1(R1_2);
		R1_2 <= Wt;
	end


endmodule


// Memory for W[t], IVs and saved contexts.
// 1 write channel, 2 read channels.
// Expecting 4 BRAM x 1 Kbyte.
//
// outputs:
// mem0 - W[t-7], values for post-block additions
// mem1 - W[t-15], IVs & saved contexts (via block2ctx)
//
// content
// 0..15 - current block, ctx0
// 24..31 - IVs in reverse order (H..A)
// 32..63 - context save slots (0..3) for ctx0, seq0
// 96..127 - context save slots (0..3) for ctx0, seq1
//
// 128..143 - current block, ctx1
// 160..191 - context save slots (0..3) for ctx1, seq0
// 224..255 - context save slots (0..3) for ctx1, seq1
//
module w_mem(
	input CLK,
	
	input [63:0] in,
	input wr_en,
	input [7:0] wr_addr,
	
	input [7:0] rd_addr0, rd_addr1,
	output [63:0] out0, out1
	);

	localparam [511:0] SHA512_IV = `SHA512_IV;

	integer k;
	
	(* RAM_STYLE="BLOCK" *)
	reg [63:0] mem0 [255:0], mem1 [255:0];
	initial
		for (k=24; k <= 31; k=k+1) begin
			mem0[k] = SHA512_IV[(31-k)*64 +:64];
			mem1[k] = SHA512_IV[(31-k)*64 +:64];
		end

	reg [63:0] mem0_r = 0, mem1_r = 0;

	always @(posedge CLK) begin
		if (wr_en) begin
			mem0 [wr_addr] <= in;
			mem1 [wr_addr] <= in;
		end
		
		if (1'b1) begin
			mem0_r <= mem0 [rd_addr0];
			mem1_r <= mem1 [rd_addr1];
		end
	end

	assign out0 = mem0_r;
	assign out1 = mem1_r;

endmodule

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

`define SHA256_R0(x) (`CYCLIC (x, 7) ^ `CYCLIC (x, 18) ^ (x >> 3))
`define SHA256_R1(x) (`CYCLIC (x, 17) ^ `CYCLIC (x, 19) ^ (x >> 10))


module sha256block(
	input CLK,

	input external_input_en, // select external input
	input ctx_save_en, // select save into memory from context
	//input save_en,
	input [31:0] in,

	// memory ops
	input mem_wr_en,
	input mem_rd_en0, mem_rd_en1,
	input [6:0] wr_addr, rd_addr0, rd_addr1,

	//input R0_en, R1_rst, R1_en, W16_rst, W16_en,
	input R0_en, R1_en, W16_rst, W16_en, Wt_2_en,

	// Kt unit
	input Kt_en,
	input [6:0] K_round_num,

	// Context unit
	input S1_CH_I_rst, S1_CH_I_en,
	input S0_en, MAJ_en, block2ctx_en,
	input ctx_en,

	input output_en,
	output [31:0] o
	);

	//reg [31:0] save_r = 0;
	wire [31:0] mem_input;

	wire [31:0] mem0_out, mem1_out;

	w_mem w_mem(
		.CLK(CLK),
		//.in(save_r),
		.in(mem_input),
		.wr_en(mem_wr_en), .wr_addr(wr_addr),

		.rd_addr0(rd_addr0), .rd_addr1(rd_addr1),
		.rd_en0(mem_rd_en0), .rd_en1(mem_rd_en1),
		.out0(mem0_out), .out1(mem1_out) // right out from BRAM
	);

	//
	// Prevent usage of BRAM output registers
	//
	reg mem_rd_en0_r = 0, mem_rd_en1_r = 0;
	always @(posedge CLK) begin
		mem_rd_en0_r <= mem_rd_en0;
		mem_rd_en1_r <= mem_rd_en1;
	end
	
	wire [31:0] mem0, mem1;

	ff32 ff_reg0(
		.CLK(CLK), .en(mem_rd_en0_r), .rst(1'b0),
		.i(mem0_out), .o(mem0)
	);

	ff32 ff_reg1(
		.CLK(CLK), .en(mem_rd_en1_r), .rst(1'b0),
		.i(mem1_out), .o(mem1)
	);


	wire [31:0] Wtmp =
		external_input_en ? in :
		R0_en ? `SHA256_R0(mem1) + mem0 :
		mem0;

	reg [31:0] W16 = 0;
	always @(posedge CLK)
		if (W16_rst)
			W16 <= 0;
		else if (W16_en)
			W16 <= mem1;
/*	
	reg [31:0] R1 = 0;
	always @(posedge CLK)
		if (R1_rst)
			R1 <= 0;
		else if (R1_en)
			R1 <= `SHA256_R1(Wt);
*/
	wire [31:0] R1;

	wire [31:0] Wt;
	add3 Wt_inst (.CLK(CLK), .en(1'b1), .rst(1'b0),
		.a(Wtmp), .b(W16), .c(R1), .o(Wt) );

	reg [31:0] Wt_2;
	always @(posedge CLK)
		if (Wt_2_en)
			Wt_2 <= Wt;

	assign R1 = R1_en ? `SHA256_R1(Wt_2) : 0;

	wire [31:0] ctx2block;
	assign mem_input = ctx_save_en ? ctx2block : Wt_2;//Wt;
	//always @(posedge CLK)
	//	if (save_en)
	//		save_r <= ctx_save_en ? ctx2block : Wt;


	wire [31:0] Kt;
	sha256_Kt_bram sha256_Kt(
		.CLK(CLK),
		.en(Kt_en), .t(K_round_num), .Kt(Kt),
		.wr_en(1'b0), .wr_addr(1'b0)
	);


	sha256ctx sha256ctx(
		.CLK(CLK),
		.S1_CH_I_rst(S1_CH_I_rst), .S1_CH_I_en(S1_CH_I_en),
		.S0_en(S0_en), .MAJ_en(MAJ_en), .block2ctx_en(block2ctx_en),
		.en(ctx_en),// .D2E_en(1'b0),
		.block2ctx(mem1), .Wt(Wt), .Kt(Kt),
		.output_en(output_en), .o(ctx2block)
	);

	assign o = ctx2block;

endmodule


// Memory for W[t], IVs and saved contexts.
// 1 write channel, 2 read channels.
// Expecting 2 BRAM x 1 Kbyte.
//
// outputs:
// mem0 - W[t-7], values for post-block additions
// mem1 - W[t-15], IVs & saved contexts (via block2ctx)
//
// content
// 0..15 - current block
// 24..31 - IVs in reverse order (H..A)
// 32..63 - context save slots (0..3) for seq0
// 96..127 - context save slots (0..3) for seq1
//
module w_mem(
	input CLK,

	input [31:0] in,
	input wr_en,
	input [6:0] wr_addr,

	input [6:0] rd_addr0, rd_addr1,
	input rd_en0, rd_en1,
	output [31:0] out0, out1
	);

	localparam [255:0] SHA256_IV = `SHA256_IV;

	integer k;

	(* RAM_STYLE="BLOCK" *)
	reg [31:0] mem0 [127:0], mem1 [127:0];
	initial
		for (k=24; k <= 31; k=k+1) begin
			mem0[k] = SHA256_IV[(31-k)*32 +:32];
			mem1[k] = SHA256_IV[(31-k)*32 +:32];
		end

	reg [31:0] mem0_r = 0, mem1_r = 0;

	always @(posedge CLK) begin
		if (wr_en) begin
			mem0 [wr_addr] <= in;
			mem1 [wr_addr] <= in;
		end

		if (rd_en0)
			mem0_r <= mem0 [rd_addr0];
		if (rd_en1)
			mem1_r <= mem1 [rd_addr1];
	end

	assign out0 = mem0_r;
	assign out1 = mem1_r;

endmodule

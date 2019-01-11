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

	// input buffer
	input wr_en,
	input [31:0] din,
	input [5:0] input_buf_wr_addr,
	input input_buf_rd_en,
	input [5:0] input_buf_rd_addr,

	input glbl_en,
	input input_buf_en, // select input from the input buffer
	input ctx_save_en, // select save into memory from context
	input save_r_en,

	// memory ops
	input mem_wr_en,
	input mem_rd_en0, mem_rd_en1,
	input [6:0] wr_addr, rd_addr0, rd_addr1,

	input R0_en, R1_rst, R1_en, W16_rst, W16_en, R1_2_en,

	// Kt unit
	input Kt_en,
	input [6:0] K_round_num,

	// Context unit
	input S1_CH_rst,
	input S0_rst,
	input D2E_en,
	input block2ctx_en, T1_rst,

	output [31:0] o
	);

	(* RAM_STYLE="block" *)
	reg [31:0] input_buf [0:63];
	reg [31:0] input_buf_out;
	always @(posedge CLK) begin
		if (wr_en)
			input_buf [input_buf_wr_addr] <= din;
		if (input_buf_rd_en)
			input_buf_out <= input_buf [input_buf_rd_addr];

	end

	reg [31:0] save_r = 0;

	wire [31:0] mem0_out, mem1_out;
	w_mem w_mem(
		.CLK(CLK),
		.in(save_r),
		.wr_en(mem_wr_en), .wr_addr(wr_addr),

		.rd_addr0(rd_addr0), .rd_addr1(rd_addr1),
		.rd_en0(mem_rd_en0), .rd_en1(mem_rd_en1),
		.out0(mem0_out), .out1(mem1_out) // right out from BRAM
	);

	reg [31:0] input_r;
	always @(posedge CLK)
		if (glbl_en)
			input_r <= input_buf_en ? input_buf_out : mem0_out;

	//
	// Prevent usage of BRAM output registers
	//
	reg mem_rd_en1_r = 0;
	always @(posedge CLK)
		mem_rd_en1_r <= mem_rd_en1;

	wire [31:0] mem1_r;
	ff32 ff_reg1(
		.CLK(CLK), .en(mem_rd_en1_r), .rst(1'b0),
		.i(mem1_out), .o(mem1_r)
	);

	reg [31:0] Wtmp;
	always @(posedge CLK)
		if (glbl_en)
			Wtmp <= (R0_en ? `SHA256_R0(mem1_r) : 0) + input_r;

	reg [31:0] W16 = 0, W16_2 = 0, W16_3 = 0;
	always @(posedge CLK) begin
		if (W16_rst)
			W16 <= 0;
		else if (W16_en) begin
			W16 <= W16_2;
		end
		if (W16_en) begin
			W16_2 <= W16_3;
			W16_3 <= mem1_r;
		end
	end

	reg [31:0] Wt = 0;
	reg [31:0] R1 = 0, R1_2 = 0;
	always @(posedge CLK) begin
		if (R1_rst)
			R1 <= 0;
		else if (R1_en)
			R1 <= `SHA256_R1(R1_2);

		if (R1_2_en)
			R1_2 <= Wt;
	end

	wire [31:0] Wt_r;
	add3 Wt_inst (.CLK(CLK), .en(1'b1), .rst(1'b0),
		.a(Wtmp), .b(W16), .c(R1), .o(Wt_r) );

	always @(posedge CLK)
		if (glbl_en)
			Wt <= Wt_r;


	wire [31:0] ctx2block;
	always @(posedge CLK)
		if (save_r_en)
			save_r <= ctx_save_en ? ctx2block : R1_2;


	wire [31:0] Kt;
	sha256_Kt_bram sha256_Kt(
		.CLK(CLK),
		.en(Kt_en), .t(K_round_num), .Kt(Kt),
		.wr_en(1'b0), .wr_addr(1'b0)
	);


	sha256ctx sha256ctx(
		.CLK(CLK),
		.S1_CH_rst(S1_CH_rst),
		.S0_rst(S0_rst),
		.D2E_en(D2E_en),
		.block2ctx_en(block2ctx_en), .T1_rst(T1_rst),
		.glbl_en(glbl_en),

		.block2ctx(mem1_r),
		.Wt(Wt), .Kt(Kt),
		.o(ctx2block)
	);

	assign o = save_r;

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
// 16..23 - saved context
// 24..31 - IVs in reverse order (H..A)
//
module w_mem(
	input CLK,

	input [31:0] in,
	input wr_en,
	input [6:0] wr_addr,

	input [6:0] rd_addr0, rd_addr1,
	input rd_en0, rd_en1,
	output reg [31:0] out0 = 0, out1 = 0
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

	always @(posedge CLK) begin
		if (wr_en) begin
			mem0 [wr_addr] <= in;
			mem1 [wr_addr] <= in;
		end

		if (rd_en0)
			out0 <= mem0 [rd_addr0];
		if (rd_en1)
			out1 <= mem1 [rd_addr1];
	end

endmodule

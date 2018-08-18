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

`define SHA256_CH(x, y, z) ((x & y) ^ (~x & z))
`define SHA256_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
`define SHA256_S0(x) (`CYCLIC (x, 2) ^ `CYCLIC (x, 13) ^ `CYCLIC (x, 22))
`define SHA256_S1(x) (`CYCLIC (x, 6) ^ `CYCLIC (x, 11) ^ `CYCLIC (x, 25))


// Notes.
//
// - At the same time 2 contexts are running, in 2 clock cycles
//   each one performs one round.
// - Both contexts are independent one from another.
//
// - Performs SHA256 block (64 rounds) in 64 + 8 cycles
// - It performs operations other than 64 rounds, such as post-addition
//   and output of computed result for save. To accomplish that,
//   it has ability to set passby I->A and D->E via adders
//   (other inputs of adders are set to 0 at that time).
// - For 8 cycles after 64 rounds, it performs addition with values
//   from the previous block (input via Wt) and output of computed
//   result for save. Also the result remains in registers and is
//   used for subsequent block.
//
// Synthesis option: "Optimization Goal: Area"
// Map option: "LUT Combining: Auto"
//
//`ifdef SIMULATION

module sha256ctx(
	input CLK,

	input S1_CH_I_rst, S1_CH_I_en,
	input S0_en, MAJ_en, block2ctx_en,
	//input D2E_en, // enable D2->E pass-by
	input en,

	input [31:0] block2ctx, // loading context from mem1
	input [31:0] Wt, Kt,
	
	input output_en,
	output reg [31:0] o
	//output [31:0] o
	);

	reg [31:0] B = 0, C = 0, D = 0, E = 0, F = 0, G = 0;

	wire [31:0] I;
	//add3 I_inst ( .CLK(CLK), .en(1'b1), .rst(1'b0),
	//	.a(G), .b(Wt), .c(Kt), .o(I) );
	add3_unreg I_inst( .a(G), .b(Wt), .c(Kt), .o(I) );
	
	reg [31:0] S1 = 0, CH = 0, I_r = 0;
	always @(posedge CLK)
		if (S1_CH_I_rst) begin
			S1 <= 0;
			CH <= 0;
			I_r <= 0;
		end
		else if (S1_CH_I_en) begin
			S1 <= `SHA256_S1(E_input);
			CH <= `SHA256_CH(E_input, E, F);
			I_r <= I;
		end

	wire [31:0] T1;
	add3_unreg T1_inst( .a(I_r), .b(S1), .c(CH), .o(T1) );

	//wire [31:0] E_input = D + (D2E_en ? 0 : T1); // 1 LUT/bit
	wire [31:0] E_input = D + T1;

	wire [31:0] S0 = ~S0_en ? 0 : `SHA256_S0(A);
	
	wire [31:0] MAJ = block2ctx_en ? block2ctx :
		MAJ_en ? `SHA256_MAJ(A, B, C) : 0;

	wire [31:0] A;
	add3 A_inst (.CLK(CLK), .en(1'b1), .rst(1'b0),
		.a(T1), .b(S0), .c(MAJ), .o(A) );

	always @(posedge CLK) if (en) begin
		B <= A;
		C <= B;
		D <= C;
		E <= E_input;
		F <= E;
		G <= F;
	end

	//assign o = I;
	always @(posedge CLK)
		if (output_en)
			o <= I;


endmodule
/*
`else

module sha256ctx(
	input CLK,

	input S1_CH_rst, S0_rst, MAJ_rst,
	input D2E_en,
	input block2ctx_en, T1_rst,

	input [31:0] block2ctx,
	input [31:0] Wt, Kt,
	output [31:0] o
	);

endmodule

`endif
*/

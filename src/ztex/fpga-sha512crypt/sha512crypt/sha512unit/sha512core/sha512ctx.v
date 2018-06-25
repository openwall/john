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

`define	CH(x,y,z) ((x & y) ^ (~x & z))
`define	MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
`define	S0(x) (`CYCLIC (x, 28) ^ `CYCLIC (x, 34) ^ `CYCLIC (x, 39))
`define	S1(x) (`CYCLIC (x, 14) ^ `CYCLIC (x, 18) ^ `CYCLIC (x, 41))


// Notes.
//
// - At the same time 2 contexts are running, in 2 clock cycles
//   each one performs one round.
// - Both contexts are independent one from another.
//
// - Performs SHA512 block (80 rounds) in 80 + 8 cycles
// - It performs operations other than 80 rounds, such as post-addition
//   and output of computed result for save. To accomplish that,
//   it has ability to set passby I->A and D->E via adders
//   (other inputs of adders are set to 0 at that time).
// - For 8 cycles after 80 rounds, it performs addition with values
//   from the previous block (input via Wt) and output of computed
//   result for save. Also the result remains in registers and is
//   used for subsequent block.
//
// Synthesis option: "Optimization Goal: Speed"
// Map option: "LUT Combining: Auto"
//
`ifdef SIMULATION

module sha512ctx(
	input CLK,

	input S1_CH_rst, S0_rst, MAJ_rst,
	input D2E_en, // enable D2->E pass-by
	input block2ctx_en, T1_rst,

	input [63:0] block2ctx, // loading context from mem1
	input [63:0] Wt, Kt,
	output [63:0] o
	);

	reg [63:0] B, C, D, E, F, G;
	reg [63:0] A2, B2, C2, D2, E2, F2;
	reg [63:0] G2 = 0;

	reg [63:0] S1_r = 0;
	reg [63:0] CH = 0;
	reg [63:0] S0 = 0;
	reg [63:0] MAJ = 0;


	wire [63:0] I_output;
	add3 I (.CLK(CLK), .en(1'b1), .rst(1'b0),
		.a(G2), .b(Wt), .c(Kt), .o(I_output) );

	wire [63:0] T1_output;
	add3 T1 (.CLK(CLK), .en(1'b1), .rst(T1_rst),
		.a(I_output), .b(S1_r), .c(CH), .o(T1_output) );

	wire [63:0] E_input = D2 + (D2E_en ? 0 : T1_output); // 1 LUT/bit

	wire [63:0] A_output;
	add3// #( .IV(SHA512_IV[383:320])
	A (.CLK(CLK), .en(1'b1), .rst(1'b0),
		.a(T1_output), .b(S0), .c(MAJ), .o(A_output) );


	//wire [63:0] S1_output;
	//S1 S1_inst( .i(E_input), .o(S1_output) );


	always @(posedge CLK) begin
		S1_r <= S1_CH_rst ? 0 : `S1(E_input);//S1_output;
		CH <= S1_CH_rst ? 0 : `CH(E_input, E2, F2);
		
		S0 <= S0_rst ? 0 : `S0(A_output);
		MAJ <= MAJ_rst ? 0 : block2ctx_en ? block2ctx : `MAJ(A_output, B, C);
		
		A2 <= A_output;
		B <= A2;
		B2 <= B;
		C <= B2;
		C2 <= C;
		D <= C2;
		D2 <= D;
		E <= E_input;
		E2 <= E;
		F <= E2;
		F2 <= F;
		G <= F2;
		G2 <= G;
	end

	assign o = I_output;

endmodule

`else

module sha512ctx(
	input CLK,

	input S1_CH_rst, S0_rst, MAJ_rst,
	input D2E_en,
	input block2ctx_en, T1_rst,

	input [63:0] block2ctx,
	input [63:0] Wt, Kt,
	output [63:0] o
	);

endmodule

`endif

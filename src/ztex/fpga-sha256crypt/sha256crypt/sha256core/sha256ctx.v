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

`define CH(x, y, z) ((x & y) ^ (~x & z))
`define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
`define S0(x) (`CYCLIC (x, 2) ^ `CYCLIC (x, 13) ^ `CYCLIC (x, 22))
`define S1(x) (`CYCLIC (x, 6) ^ `CYCLIC (x, 11) ^ `CYCLIC (x, 25))


// Notes.
//
// - At the same time 2 contexts are running, in 2 clock cycles
//   each one performs one round.
// - Both contexts are independent one from another.
//
// - Performs 2x SHA256 blocks (64 rounds) in 2x (64 + 8) cycles
//
// Synthesis option: "Optimization Goal: Area"
// Map option: "LUT Combining: Auto"
//
module sha256ctx(
	input CLK,

	input S1_CH_rst, S0_rst,
	input D2E_en, // enable D2->E pass-by
	input block2ctx_en, T1_rst,
	input glbl_en,

	input [31:0] block2ctx, // loading context from mem1
	input [31:0] Wt, Kt,
	output [31:0] o
	);

	wire [31:0] I_output, T1_output, A_output, E_input;
	wire [31:0] B, C, D2, E2, F2, G2;

	shreg #(.DEPTH(2)) B_inst( .CLK(CLK), .en(glbl_en), .i(A_output), .o(B) );
	shreg #(.DEPTH(2)) C_inst( .CLK(CLK), .en(glbl_en), .i(B), .o(C) );
	shreg #(.DEPTH(3)) D2_inst( .CLK(CLK), .en(glbl_en), .i(C), .o(D2) );
	shreg #(.DEPTH(2)) E2_inst( .CLK(CLK), .en(glbl_en), .i(E_input), .o(E2) );
	shreg #(.DEPTH(2)) F2_inst( .CLK(CLK), .en(glbl_en), .i(E2), .o(F2) );
	shreg #(.DEPTH(2)) G2_inst( .CLK(CLK), .en(glbl_en), .i(F2), .o(G2) );

	reg [31:0] S1 = 0;
	reg [31:0] CH = 0;
	reg [31:0] S0 = 0;
	reg [31:0] MAJ = 0;


	add3 I (.CLK(CLK), .en(glbl_en), .rst(1'b0),
		.a(G2), .b(Wt), .c(Kt), .o(I_output) );

	add3 T1 (.CLK(CLK), .en(glbl_en), .rst(T1_rst),
		.a(I_output), .b(S1), .c(CH), .o(T1_output) );

	assign E_input = D2 + (D2E_en ? 0 : T1_output);

	add3 A (.CLK(CLK), .en(glbl_en), .rst(1'b0),
		.a(T1_output), .b(S0), .c(MAJ), .o(A_output) );

	always @(posedge CLK) begin
		if (S1_CH_rst) begin
			S1 <= 0;
			CH <= 0;
		end
		else if (glbl_en) begin
			S1 <= `S1(E_input);
			CH <= `CH(E_input, E2, F2);
		end

		if (S0_rst)
			S0 <= 0;
		else if (glbl_en)
			S0 <= `S0(A_output);

		if (glbl_en)
			MAJ <= block2ctx_en ? block2ctx : `MAJ(A_output, B, C);
	end


	assign o = I_output;

endmodule

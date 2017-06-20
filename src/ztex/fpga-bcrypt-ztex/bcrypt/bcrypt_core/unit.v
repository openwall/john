`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "../bcrypt.vh"

module unit #(
	parameter MSB = 31,
	parameter ADDR_NBITS = 8
	)(
	input CLK,
	input [MSB:0] din,

	input [9:0] S_wr_addr, // S - write
	input S_wr_en,
	input S_rd_en, // S - read
	input S_rst,

	input [4:0] PD_addr, // PD
	input PD_wr_en,

	input [4:0] PN_wr_addr, // P - write
	input [4:0] PN_addr, // P - read
	input PS_input_select, decr, // P input mux
	input PN_wr_en,
	input ZF_wr_en,
	output ZF, B31,

	input L_input_select,
	input Ltmp_wr_en,
	input L_wr_en,
	input R_wr_en,
	input LR_zero,

	input [4:0] output_cnt, // 1-bit output
	output out
	);


	//
	// L, R registers
	//
	reg [MSB:0] L = 0, R = 0, Ltmp = 0;
	wire [MSB:0] L_in;

	always @(posedge CLK)
		if (Ltmp_wr_en)
			Ltmp <= L_in;

	always @(posedge CLK)
		if (LR_zero)
			L <= 0;
		else if (L_wr_en)
			L <= L_in;

	always @(posedge CLK)
		if (LR_zero)
			R <= 0;
		else if (R_wr_en)
			R <= L;


	//
	// "P" unit: 2 x 32
	//
	wire [MSB:0] PD, PN, S_input;

	P_2x32 #( .MSB(MSB)
	) P(
		.CLK(CLK),
		.PD_addr(PD_addr), .PD_wr_en(PD_wr_en), .PD_out(PD),
		.din(din), .Ltmp_in(Ltmp),
		.PS_input_select(PS_input_select), .decr(decr),
		.S_input(S_input),
		.PN_wr_addr(PN_wr_addr), .PN_wr_en(PN_wr_en),
		.PN_addr(PN_addr), .PN_out(PN),
		.ZF_wr_en(ZF_wr_en), .ZF(ZF), .B31(B31)
	);


	//
	// "S" unit: 32x1024, 1 write port, 1 read port
	//
	wire [MSB:0] S_dout;

	S #( .MSB(MSB), .ADDR_NBITS(ADDR_NBITS)
	) S(
		.CLK(CLK),
		.din(S_input),
		//.din(PS_input_select ? din : L_in),
		.addr_wr(S_wr_addr), .wr_en(S_wr_en),
		.addr_rd(L_in), .out(S_dout), .rd_en(S_rd_en), .rst_rd(S_rst)
	);


	//
	// Big XOR unit where the round starts
	//
	assign L_in = (L_input_select ? L : R ^ S_dout) ^ PD ^ PN;


	//
	// 1-bit output
	//
	assign out = Ltmp [output_cnt];

endmodule



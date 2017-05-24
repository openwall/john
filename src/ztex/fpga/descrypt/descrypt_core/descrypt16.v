`timescale 1ns / 1ns
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "descrypt.vh"


module descrypt16(
	input CLK,

	input [`SALT_MSB:0] salt_in,
	input [55:0] key56_in,
	input valid_in,
	
	input ENABLE_CRYPT,
	input START_CRYPT,

	output [`HASH_MSB:0] hash_out,
	output valid_out
	);

	genvar i;
	
	wire [55:0] CiDi [15:0];
	wire [63:0] Ti [15:0];
	wire [15:0] valid;

	wire [63:0] Ti_out = Ti[15];
	wire [63:0] Ti_in = {Ti_out[31:0], Ti_out[63:32]};

	wire [55:0] CiDi_in = START_CRYPT ? key56_in : CiDi[15];
	wire valid0_in = START_CRYPT ? valid_in : valid[15];
	
	//(* KEEP_HIERARCHY="true" *)
	descrypt_round0 descrypt_round0(
		.CLK(CLK), .ENABLE_CRYPT(ENABLE_CRYPT), .START_CRYPT(START_CRYPT), .salt_in(salt_in),
		.CiDi_in(CiDi_in), .Ti_in(Ti_in), .valid_in(valid0_in),
		.CiDi_out(CiDi[0]), .Ti_out(Ti[0]), .valid_out(valid[0])
	);

	generate
	for (i=1; i < 16; i=i+1) begin: rounds

		localparam ROTATE2 = i==1 || i==8 || i==15 ? 1'b0 : 1'b1;

		//(* KEEP_HIERARCHY="true" *)
		descrypt_round #(.ROTATE2(ROTATE2)) descrypt_round(
			.CLK(CLK), .salt_in(salt_in),
			.CiDi_in(CiDi[i-1]), .Ti_in(Ti[i-1]), .valid_in(valid[i-1]),
			.CiDi_out(CiDi[i]), .Ti_out(Ti[i]), .valid_out(valid[i])
		);

	end
	endgenerate

	wire [63:0] IP1_out;
	IP1 IP1_instance(Ti_out, IP1_out);

	assign hash_out = IP1_out[`HASH_MSB:0];
	assign valid_out = valid[15];
	
endmodule

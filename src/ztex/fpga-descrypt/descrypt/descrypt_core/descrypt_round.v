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

// rounds 1-15 don't have ENABLE_CRYPT
module descrypt_round #(
	parameter [0:0] ROTATE2 = 1
	)(
	input CLK,
	
	input [`SALT_MSB:0] salt_in,
	input [55:0] CiDi_in,
	input [63:0] Ti_in,
	input valid_in,
	
	output [55:0] CiDi_out,
	output [63:0] Ti_out,
	output reg valid_out = 0
	);

	//(* SHREG_EXTRACT="NO" *) 
	reg [55:0] CiDi;
	wire [47:0] Ki;
	rotate_1or2_pc2 rotate_1or2_pc2_instance(ROTATE2[0], CiDi, CiDi_out, Ki);

	always @(posedge CLK)
		CiDi <= CiDi_in;


	reg [63:0] Ti = 0;
	
	des_loop des_loop_instance(
		.Ti_in(Ti),
		.Ki(Ki),
		.salt_in(salt_in),
		.Ti_out(Ti_out)
	);

	always @(posedge CLK)
		Ti <= Ti_in;

	always @(posedge CLK)
		valid_out <= valid_in;

endmodule


module descrypt_round0(
	input CLK,
	input ENABLE_CRYPT,
	input START_CRYPT,

	input [`SALT_MSB:0] salt_in,
	input [55:0] CiDi_in,
	input [63:0] Ti_in,
	input valid_in,
	
	output [55:0] CiDi_out,
	output [63:0] Ti_out,
	reg valid_out = 0
	);

	//(* SHREG_EXTRACT="NO" *) 
	reg [55:0] CiDi;
	wire [47:0] Ki;
	rotate_1or2_pc2 rotate_1or2_pc2_instance(1'b0, CiDi, CiDi_out, Ki);

	always @(posedge CLK)
		if (ENABLE_CRYPT)
			CiDi <= CiDi_in;


	reg [63:0] Ti = 0;
	
	des_loop des_loop_instance(
		.Ti_in(Ti),
		.Ki(Ki),
		.salt_in(salt_in),
		.Ti_out(Ti_out)
	);

	always @(posedge CLK)
		if (START_CRYPT)
			Ti <= 0;
		else if (ENABLE_CRYPT)
			Ti <= Ti_in;

	always @(posedge CLK)
		if (ENABLE_CRYPT)
			valid_out <= valid_in;

endmodule


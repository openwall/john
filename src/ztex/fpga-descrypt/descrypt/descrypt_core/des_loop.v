/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "descrypt.vh"


////////////////////////////////////////////////////////////////////////
//
// body of inner loop (1 of 16)
//

module des_loop (
	input [63:0] Ti_in,
	input [47:0] Ki,
	input [`SALT_MSB:0] salt_in,
	output [63:0] Ti_out
	);

	wire [31:0] Li = Ti_in[63:32];
	wire [31:0] Ri = Ti_in[31:0];

	// E,xor,S,P
	wire [47:0] E_result;
	Eblock Eblock_instance( salt_in, Ri, E_result );

	wire [47:0] xor_result;
	assign xor_result = E_result ^ Ki;

	wire [31:0] P_result;
	//des_SP des_SP_instance(xor_result, P_result);
	SP_v2 SP(xor_result, P_result);

	assign Ti_out [31:0] = Li ^ P_result;
	assign Ti_out [63:32] = Ri;

endmodule

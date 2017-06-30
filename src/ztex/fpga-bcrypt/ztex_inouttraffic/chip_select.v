`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// **********************************************
//
// Proper handling of Chip Select (CS) input
// on a multi-FPGA board.
//
// On CS assertion:
// * cycle 1. CS input gets registered (CS)
// * cycle 2. Some outputs go T-state (out_z)
// * cycle 3. Some outputs go T-state (out_z_wait1)
//
// **********************************************

module chip_select(
	// Asynchronous CS input
	input CS_IN,
	input CLK,
	// Synchronous output
	output CS,
	//output out_z,
	output out_z_wait1
	);

	(* IOB="true" *) reg cs_in_r = 0;
	always @(posedge CLK)
		cs_in_r <= CS_IN;
	assign CS = cs_in_r;

	//(* IOB="true" *) reg cs_out_inv_r = 0;
	(* IOB="true" *) reg cs_out_inv_wait1_r = 0;
	reg deselect_delay = 0;

	always @(posedge CLK)
		if (~cs_in_r) begin
			//cs_out_inv_r <= 1;
			deselect_delay <= 1;
			if (deselect_delay)
				cs_out_inv_wait1_r <= 1;
		end
		else begin
			//cs_out_inv_r <= 0;
			deselect_delay <= 0;
			cs_out_inv_wait1_r <= 0;
		end

	//assign out_z = cs_out_inv_r;
	assign out_z_wait1 = cs_out_inv_wait1_r;
	
endmodule

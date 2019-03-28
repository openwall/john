`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "descrypt_core/descrypt.vh"

module cmp_config_distrib #(
	parameter N = 1
	) (
	input CLK,
	input new_cmp_config, // arrives, waits
	input [N-1:0] cmp_config_applied,
	output reg all_cmp_config_applied = 0,

	input [`GLOBAL_SALT_MSB:`GLOBAL_SALT_LSB] global_salt_in,
	output [`GLOBAL_SALT_MSB:`GLOBAL_SALT_LSB] global_salt_out
/*
	input [`SEGMENT_MSB:0] num_hashes_in,
	input [`LVL1_NBITS-1:0] num_hashes_remain_in,
	output reg [`SEGMENT_MSB:0] num_hashes = 0, // Min. number of hashes in each segment
	output reg [`LVL1_NBITS-1:0] num_hashes_remain = 0 // Extra hashes (1-0/segment)
*/
	);

	genvar i;

	reg [`GLOBAL_SALT_MSB:`GLOBAL_SALT_LSB] global_salt_r = 0;
	(* KEEP_HIERARCHY="true" *)
	global_wires #(
		.N(`GLOBAL_SALT_MSB - `GLOBAL_SALT_LSB +1)
	) global_wires_salt (
		.in(global_salt_r),
		.out(global_salt_out)
	);

	reg [N-1:0] applied = 0;

	localparam STATE_IDLE = 0,
				STATE_NEW_CONFIG = 1,
				STATE_ALL_APPLIED = 2,
				STATE_RESET = 3;

	reg [1:0] state = STATE_IDLE;

	always @(posedge CLK) begin
		case (state)
		STATE_IDLE: if (new_cmp_config)
			state <= STATE_NEW_CONFIG;

		STATE_NEW_CONFIG: if (&applied) begin
			state <= STATE_ALL_APPLIED;
		end

		STATE_ALL_APPLIED: begin
			global_salt_r <= global_salt_in;

			//num_hashes_remain <= num_hashes_remain_in;
			//num_hashes <= num_hashes_in;

			all_cmp_config_applied <= 1;
			state <= STATE_RESET;
		end

		STATE_RESET: begin
			all_cmp_config_applied <= 0;
			state <= STATE_IDLE;
		end
		endcase
	end


	generate
	for (i=0; i < N; i=i+1) begin:applied_gen

		always @(posedge CLK)
			if (state == STATE_NEW_CONFIG & cmp_config_applied[i])
				applied[i] <= 1;
			else if (state == STATE_ALL_APPLIED)
				applied[i] <= 0;

	end
	endgenerate

endmodule

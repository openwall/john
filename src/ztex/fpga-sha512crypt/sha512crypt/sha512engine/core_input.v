`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../sha512.vh"

//
// Extracted from realign:
// everything dependent on N_CORES
//
module core_input #(
	parameter N_CORES = `N_CORES,
	parameter N_CORES_MSB = `MSB(N_CORES-1),
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,

	// from realign
	input realign_wr_en_r, realign_valid_eqn, realign_valid,

	input [N_THREADS_MSB :0] thread_num,
	input [`BLK_OP_MSB:0] blk_op,

	output reg [N_CORES-1:0] core_wr_en = 0,
	output reg [3:0] core_wr_addr = 0,
	output reg [`BLK_OP_MSB:0] core_blk_op,
	output reg core_input_ctx, core_input_seq,
	output reg set_input_ready = 0
	);

	genvar i;

	reg [N_THREADS_MSB :0] thread_num1;
	reg [`BLK_OP_MSB:0] blk_op1;
	always @(posedge CLK) begin
		thread_num1 <= thread_num;
		blk_op1 <= blk_op;
	end

	wire [N_CORES_MSB :0] core_num;
	assign { core_num, ctx_num, seq_num } = thread_num1;

	generate
	for (i=0; i < N_CORES; i=i+1) begin:cores_wr_en
		always @(posedge CLK)
			core_wr_en[i] <= i == core_num & realign_valid_eqn;
	end
	endgenerate


	always @(posedge CLK) if (realign_wr_en_r) begin
		core_input_seq <= seq_num;
		core_input_ctx <= ctx_num;
		core_blk_op <= blk_op1;
	end


	always @(posedge CLK) if (realign_valid) begin
		core_wr_addr <= core_wr_addr + 1'b1;

		set_input_ready <= core_wr_addr == 14;
	end


endmodule

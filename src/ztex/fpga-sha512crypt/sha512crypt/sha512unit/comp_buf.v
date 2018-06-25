`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "sha512.vh"

//
// Each thread performs at most 1 computation at given time.
// comp_buf contains computation data. That's divided into:
// - data1: read by procb (block transmission)
// - data2: read by memory_input_mgr (save into memory)
//
module comp_buf #(
	parameter N_THREADS = 16, // min.4
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,

	input [N_THREADS_MSB :0] wr_thread_num,
	input wr_en,
	input [`COMP_DATA1_MSB :0] wr_data1,
	input [`COMP_DATA2_MSB :0] wr_data2,

	input [N_THREADS_MSB :0] rd_thread_num1,
	output reg [`COMP_DATA1_MSB :0] dout1 = 0,

	input [N_THREADS_MSB :0] rd_thread_num2,
	output reg [`COMP_DATA2_MSB :0] dout2 = 0
	);

	(* RAM_STYLE="DISTRIBUTED" *)
	reg [`COMP_DATA1_MSB :0] mem1 [0: N_THREADS-1];
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [`COMP_DATA2_MSB :0] mem2 [0: N_THREADS-1];

	always @(posedge CLK) begin
		if (wr_en) begin
			mem1 [wr_thread_num] <= wr_data1;
			mem2 [wr_thread_num] <= wr_data2;
		end

		dout1 <= mem1 [rd_thread_num1];
		dout2 <= mem2 [rd_thread_num2];
	end


endmodule

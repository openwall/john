`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017-2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "sha512.vh"

//
// Keep state for each thread in between blocks.
// - bytes_total of unfinished SHA512 computation;
// - data for unfinished process_bytes record (including padding)
//
module procb_saved_state #(
	//parameter N_CORES = 4,
	//parameter N_CORES_MSB = `MSB(N_CORES-1),
	parameter N_THREADS = 16,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,

	input [N_THREADS_MSB :0] wr_thread_num,
	input wr_en,
	input [`PROCB_SAVE_MSB :0] din,

	input [N_THREADS_MSB :0] rd_thread_num,
	//input rd_en,
	//output reg [`PROCB_SAVE_MSB :0] dout = 0
	output [`PROCB_SAVE_MSB :0] dout
	);

	
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [`PROCB_SAVE_MSB :0] mem [0: N_THREADS-1];

	always @(posedge CLK)
		if (wr_en)
			mem [wr_thread_num] <= din;

	//always @(posedge CLK)
	//	if (rd_en)
	//		dout <= mem [rd_thread_num];
	assign dout = mem [rd_thread_num];

endmodule

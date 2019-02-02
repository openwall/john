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
// Keep state for each thread in between blocks.
// - bytes_total of unfinished computation;
// - data for unfinished process_bytes record (including padding)
//
module procb_saved_state #(
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,

	input [N_THREADS_MSB :0] wr_thread_num,
	input wr_en,
	input [`PROCB_SAVE_WIDTH-1 :0] din,

	input [N_THREADS_MSB :0] rd_thread_num,
	input rd_en,
	output reg [`PROCB_SAVE_WIDTH-1 :0] dout
	);


	(* RAM_STYLE="DISTRIBUTED" *)
	reg [`PROCB_SAVE_WIDTH-1 :0] mem [0: N_THREADS-1];

	always @(posedge CLK)
		if (wr_en)
			mem [wr_thread_num] <= din;

	//assign dout = mem [rd_thread_num];

	always @(posedge CLK)
		if (rd_en)
			dout <= mem [rd_thread_num];

endmodule

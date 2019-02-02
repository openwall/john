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

module registers_bram #(
	parameter WIDTH = 16,
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,
	// input into register file from the memory
	input [WIDTH-1:0] mem_din,
	input [WIDTH-1:0] din1, din2, din3,
	input [1:0] reg_din_select,
	input mem_wr_en, wr_en,
	input [`REG_ADDR_MSB:0] wr_addr, rd_addr,
	input [N_THREADS_MSB :0] wr_thread_num, rd_thread_num,
	input rd_en0, rd_en1,
	output [WIDTH-1:0] dout
	);

	(* RAM_STYLE="BLOCK" *)
	reg [WIDTH-1:0] reg_mem [0: 16*N_THREADS-1];
	reg [WIDTH-1:0] reg_mem_r;

	// Prevent inference of BRAM output register
	ff16 ff_reg( .CLK(CLK), .en(rd_en1),
		.rst(1'b0), .i(reg_mem_r), .o(dout) );

	wire [WIDTH-1:0] reg_input =
		reg_din_select == 2'd1 ? din1 :
		reg_din_select == 2'd2 ? din2 :
		reg_din_select == 2'd3 ? din3 :
		mem_din;

	always @(posedge CLK) begin
		if (mem_wr_en | wr_en)
			reg_mem [{ wr_thread_num, wr_addr }] <= reg_input;

		if (rd_en0)
			reg_mem_r <= reg_mem [{ rd_thread_num, rd_addr }];
	end

endmodule


`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`define	Kt_N_CYCLES		64

`define	Kt(x) (K[32*(`Kt_N_CYCLES-(x))-1 -:32])

module md5_Kt_dram(
	input CLK,
	input [6:0] t,
	input en, rst,
	output reg [31:0] Kt = 0
	);

	localparam [32*`Kt_N_CYCLES-1 :0] K = {
		32'hd76aa478, 32'he8c7b756, 32'h242070db, 32'hc1bdceee,
		32'hf57c0faf, 32'h4787c62a, 32'ha8304613, 32'hfd469501,
		32'h698098d8, 32'h8b44f7af, 32'hffff5bb1, 32'h895cd7be,
		32'h6b901122, 32'hfd987193, 32'ha679438e, 32'h49b40821,

		32'hf61e2562, 32'hc040b340, 32'h265e5a51, 32'he9b6c7aa,
		32'hd62f105d, 32'h02441453, 32'hd8a1e681, 32'he7d3fbc8,
		32'h21e1cde6, 32'hc33707d6, 32'hf4d50d87, 32'h455a14ed,
		32'ha9e3e905, 32'hfcefa3f8, 32'h676f02d9, 32'h8d2a4c8a,

		32'hfffa3942, 32'h8771f681, 32'h6d9d6122, 32'hfde5380c,
		32'ha4beea44, 32'h4bdecfa9, 32'hf6bb4b60, 32'hbebfbc70,
		32'h289b7ec6, 32'heaa127fa, 32'hd4ef3085, 32'h04881d05,
		32'hd9d4d039, 32'he6db99e5, 32'h1fa27cf8, 32'hc4ac5665,

		32'hf4292244, 32'h432aff97, 32'hab9423a7, 32'hfc93a039,
		32'h655b59c3, 32'h8f0ccc92, 32'hffeff47d, 32'h85845dd1,
		32'h6fa87e4f, 32'hfe2ce6e0, 32'ha3014314, 32'h4e0811a1,
		32'hf7537e82, 32'hbd3af235, 32'h2ad7d2bb, 32'heb86d391
	};

	integer i;

	(* RAM_STYLE="distributed" *)
	reg [31:0] mem [0:`Kt_N_CYCLES-1];
	initial
		for (i = 0; i < `Kt_N_CYCLES; i = i+1)
			mem[i] = `Kt(i);


	reg [5:0] rd_addr;
	always @(posedge CLK) begin
		if (en)
			rd_addr <= t - 4;
		
		if (rst)
			Kt <= 0;
		else if (en)
			Kt <= mem[rd_addr];
	end


endmodule

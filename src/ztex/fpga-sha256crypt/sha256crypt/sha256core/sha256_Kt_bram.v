`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`define	Kt_N_CYCLES		72

`define	Kt(x) (K[32*(`Kt_N_CYCLES-(x))-1 -:32])


module sha256_Kt_bram(
	input CLK,
	input en,
	input [6:0] t,
	output [31:0] Kt,

	// "dummy" 2nd write-only port
	input wr_en,
	input wr_addr
	);

	localparam [32*`Kt_N_CYCLES-1 :0] K = {
		32'h0, 32'h0, 32'h0, 32'h0,
		32'h0, 32'h0, 32'h0,
		32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5,
		32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
		32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3,
		32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
		32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc,
		32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
		32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7,
		32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
		32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13,
		32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
		32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3,
		32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
		32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5,
		32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
		32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208,
		32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2,
		32'h0
	};

	integer i;

	(* RAM_STYLE="block" *)
	reg [31:0] mem [127:0];
	initial
		for (i = 0; i < 72; i = i+1)
			mem[i] = `Kt(i);

	reg [31:0] mem_r;
	always @(posedge CLK)
		if (en)
			mem_r <= mem[t];


	reg en_r = 0;
	always @(posedge CLK)
		en_r <= en;
	
	// Prevent inference of BRAM output regs
	ff32 ff_reg(
		.CLK(CLK), .en(en_r), .rst(~en_r),
		.i(mem_r), .o(Kt)
	);



	//
	// Declaring "dummy" 2nd write-only port
	//
	(* KEEP="true" *) wire wr_en_keep = wr_en;
	(* KEEP="true" *) wire wr_addr_keep = wr_addr;
	always @(posedge CLK)
		if (wr_en_keep)
			mem[wr_addr_keep] <= 1'b0;

endmodule

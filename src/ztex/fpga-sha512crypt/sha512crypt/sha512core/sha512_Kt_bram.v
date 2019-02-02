`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018-2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`define	Kt_N_CYCLES		88

`define	Kt(x) (K[64*(`Kt_N_CYCLES-(x))-1 -:64])


module sha512_Kt_bram(
	input CLK,
	input en,
	input [6:0] t,
	output [63:0] Kt,

	// "dummy" 2nd write-only port
	input wr_en,
	input wr_addr
	);

	localparam [64*`Kt_N_CYCLES-1 :0] K = {
		64'h0, 64'h0, 64'h0, 64'h0,
		64'h0, 64'h0, 64'h0,
		64'h428a2f98d728ae22, 64'h7137449123ef65cd, 64'hb5c0fbcfec4d3b2f,
		64'he9b5dba58189dbbc, 64'h3956c25bf348b538, 64'h59f111f1b605d019,
		64'h923f82a4af194f9b, 64'hab1c5ed5da6d8118, 64'hd807aa98a3030242,
		64'h12835b0145706fbe, 64'h243185be4ee4b28c, 64'h550c7dc3d5ffb4e2,
		64'h72be5d74f27b896f, 64'h80deb1fe3b1696b1, 64'h9bdc06a725c71235,
		64'hc19bf174cf692694, 64'he49b69c19ef14ad2, 64'hefbe4786384f25e3,
		64'h0fc19dc68b8cd5b5, 64'h240ca1cc77ac9c65, 64'h2de92c6f592b0275,
		64'h4a7484aa6ea6e483, 64'h5cb0a9dcbd41fbd4, 64'h76f988da831153b5,
		64'h983e5152ee66dfab, 64'ha831c66d2db43210, 64'hb00327c898fb213f,
		64'hbf597fc7beef0ee4, 64'hc6e00bf33da88fc2, 64'hd5a79147930aa725,
		64'h06ca6351e003826f, 64'h142929670a0e6e70, 64'h27b70a8546d22ffc,
		64'h2e1b21385c26c926, 64'h4d2c6dfc5ac42aed, 64'h53380d139d95b3df,
		64'h650a73548baf63de, 64'h766a0abb3c77b2a8, 64'h81c2c92e47edaee6,
		64'h92722c851482353b, 64'ha2bfe8a14cf10364, 64'ha81a664bbc423001,
		64'hc24b8b70d0f89791, 64'hc76c51a30654be30, 64'hd192e819d6ef5218,
		64'hd69906245565a910, 64'hf40e35855771202a, 64'h106aa07032bbd1b8,
		64'h19a4c116b8d2d0c8, 64'h1e376c085141ab53, 64'h2748774cdf8eeb99,
		64'h34b0bcb5e19b48a8, 64'h391c0cb3c5c95a63, 64'h4ed8aa4ae3418acb,
		64'h5b9cca4f7763e373, 64'h682e6ff3d6b2b8a3, 64'h748f82ee5defb2fc,
		64'h78a5636f43172f60, 64'h84c87814a1f0ab72, 64'h8cc702081a6439ec,
		64'h90befffa23631e28, 64'ha4506cebde82bde9, 64'hbef9a3f7b2c67915,
		64'hc67178f2e372532b, 64'hca273eceea26619c, 64'hd186b8c721c0c207,
		64'heada7dd6cde0eb1e, 64'hf57d4f7fee6ed178, 64'h06f067aa72176fba,
		64'h0a637dc5a2c898a6, 64'h113f9804bef90dae, 64'h1b710b35131c471b,
		64'h28db77f523047d84, 64'h32caab7b40c72493, 64'h3c9ebe0a15c9bebc,
		64'h431d67c49c100d4c, 64'h4cc5d4becb3e42b6, 64'h597f299cfc657e2a,
		64'h5fcb6fab3ad6faec, 64'h6c44198c4a475817,
		64'h0
	};

	integer i;

	(* RAM_STYLE="block" *)
	reg [63:0] mem [127:0];
	initial
		for (i = 0; i < `Kt_N_CYCLES; i = i+1)
			mem[i] = `Kt(i);

	reg [63:0] mem_r;
	always @(posedge CLK)
		if (en)
			mem_r <= mem[t];


	reg en_r = 0, rst_r = 0;
	always @(posedge CLK) begin
		en_r <= en;
		rst_r <= ~en;
	end

	// Prevent inference of BRAM output regs
	ff64 ff_reg(
		.CLK(CLK), .en(en_r), .rst(rst_r),
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

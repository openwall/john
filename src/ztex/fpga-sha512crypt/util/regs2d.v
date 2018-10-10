`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module regs2d #( // 2-direction
	parameter IN_WIDTH = -1,
	parameter OUT_WIDTH = -1,
	parameter STAGES = 0 // 0 stages - no registers
	)(
	input CLK,
	//input en,
	input [IN_WIDTH-1:0] enter_in,
	output [OUT_WIDTH-1:0] enter_out,
	output [IN_WIDTH-1:0] exit_in,
	input [OUT_WIDTH-1:0] exit_out
	);


	wire [IN_WIDTH-1:0] stage_in [STAGES:0];
	assign stage_in[0] = enter_in;
	assign exit_in = stage_in [STAGES];

	//wire [STAGES-1:0] stage_en;
	//assign stage_en[0] = en;
	
	wire [OUT_WIDTH-1:0] stage_out [STAGES:0];
	assign enter_out = stage_out[0];
	assign stage_out [STAGES] = exit_out;


	genvar k;
	generate
	// Stages are numbered 1..STAGES
	for (k=1; k <= STAGES; k=k+1) begin:stage

		(* SHREG_EXTRACT="no" *)
		//reg [1 + OUT_WIDTH + IN_WIDTH-1 :0] r = 0;
		reg [OUT_WIDTH + IN_WIDTH-1 :0] r = 0;

		always @(posedge CLK) begin
			//r[OUT_WIDTH + IN_WIDTH] <= stage_en[k-1];
			//if (stage_en[k-1]) begin
				r[IN_WIDTH-1:0] <= stage_in[k-1];
				r[OUT_WIDTH + IN_WIDTH-1 :IN_WIDTH] <= stage_out[k];
			//end
		end

		assign stage_in[k] = r[IN_WIDTH-1:0];
		//assign stage_en[k] = r[OUT_WIDTH + IN_WIDTH];
		assign stage_out[k-1] = r[OUT_WIDTH + IN_WIDTH-1 :IN_WIDTH];
	end
	endgenerate

endmodule

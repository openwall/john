`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
 

// 2-stage FF synchronizer
module sync_sig #(
	parameter INIT = 0,
	// if input signal is 1-2 clk cycles
	// and CLK1 is set, result would be 1 cycle long
	// * if input is longer than 2 cycles, it would produce extra result
	// * if less than 1 cycle, there might be no result (consider usage of sync_short_sig)
	parameter CLK1 = 0
	)(
	input sig,
	input clk,
	//input en,
	output out
	);

	(* SHREG_EXTRACT="NO" *)
	reg [1:0] ff = {2{INIT[0]}};
	assign out = ff[1];
	
	if (CLK1) begin
	
		always @(posedge clk)
			if (ff[1] ^ INIT[0])
				ff[1:0] <= {2{INIT[0]}};
			else
				ff[1:0] <= { ff[0], sig };

	end else begin // ! CLK1
	
		always @(posedge clk)
			ff[1:0] <= { ff[0], sig };

	end

endmodule


// Any frequency relation between wr_clk and rd_clk
// 'out' duration is 1 clock cycle (repeats after 'busy' deasserts)
module sync_pulse (
	input wr_clk,
	input sig,
	output busy,
	
	input rd_clk,
	// 'out' must be OK in terms of metastability
	output out
	);

	reg flag_wr = 0;
	always @(posedge wr_clk) flag_wr <= flag_wr ^ (sig & ~busy);

	(* SHREG_EXTRACT="NO" *)
	reg [2:0] sync_rd = 3'b000;
	always @(posedge rd_clk) sync_rd <= {sync_rd[1:0], flag_wr};

	(* SHREG_EXTRACT="NO" *)
	reg [1:0] sync_wr = 2'b00;
	always @(posedge wr_clk) sync_wr <= {sync_wr[0], sync_rd[2]};

	assign busy = flag_wr ^ sync_wr[1];
	assign out = sync_rd[2] ^ sync_rd[1];

endmodule


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


// 3-stage FF synchronizer
module sync_sig3(
	input sig,
	input clk,
	output out
	);

	(* SHREG_EXTRACT="NO" *)
	reg [2:0] ff = 0;
	assign out = ff[2];

	always @(posedge clk)
		ff[2:0] <= { ff[1:0], sig };

endmodule

/*
// For synchronizing short-duration signals (less than clk cycle),
// 2-stage FF synchronizer is prepended with async register
module sync_short_sig #(
	parameter INIT = 0,
	parameter CLK1 = 0
	)(
	input sig,
	input clk,
	output out
	);

	// There's no such registers in Spartan 6 architecture,
	// with a warning tools produce an equvalent item from 3 parts
	reg async_r = INIT[0];
	
	always @(posedge clk or posedge sig)
		if (sig)
			async_r <= ~INIT[0];
		else
			if (out)
				async_r <= INIT[0];
	
	sync_sig #(.INIT(INIT), .CLK1(CLK1)) sync(.sig(async_r), .clk(clk), .out(out));

endmodule
*/

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


// Any frequency relation between wr_clk and rd_clk
// 'out' duration is 1 clock cycle (repeats after 'busy' deasserts)
// 3 FFs
module sync_pulse3 (
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
	reg [3:0] sync_rd = 4'b0000;
	always @(posedge rd_clk) sync_rd <= {sync_rd[2:0], flag_wr};

	(* SHREG_EXTRACT="NO" *)
	reg [2:0] sync_wr = 3'b000;
	always @(posedge wr_clk) sync_wr <= {sync_wr[1:0], sync_rd[3]};

	assign busy = flag_wr ^ sync_wr[2];
	assign out = sync_rd[3] ^ sync_rd[2];

endmodule

/*
// Any frequency relation between wr_clk and rd_clk
module sync_ack(
	input wr_clk,
	input sig,
	output busy, // asserts on the next cycle
	
	input rd_clk,
	output out,
	input done
	);

	reg flag_wr = 0;
	always @(posedge wr_clk) flag_wr <= flag_wr ^ (sig & ~busy);

	(* SHREG_EXTRACT="NO" *)
	reg [2:0] sync_rd = 3'b0;
	always @(posedge rd_clk) 
		if (~out | done)
			sync_rd <= {sync_rd[1:0], flag_wr};

	(* SHREG_EXTRACT="NO" *)
	reg [1:0] sync_wr = 2'b0;
	always @(posedge wr_clk)
		if (out | done | done_r)
			sync_wr <= {sync_wr[0], sync_rd[2]};

	assign out = sync_rd[2] ^ sync_rd[1];
	assign busy = flag_wr ^ sync_wr[1];

	reg done_r = 0;
	always @(posedge rd_clk)
		if (out & done)
			done_r <= 1;
		else if (done_r)
			done_r <= 0;

endmodule
*/
/*
// sig is active for no more than 1 cycle
module pulse1(
	input CLK,
	input sig,
	output out
	);
	
	reg done = 0;
	always @(posedge CLK)
		done <= sig;
	
	assign out = sig & ~done;
	
endmodule
*/


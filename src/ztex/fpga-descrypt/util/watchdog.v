`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

module watchdog #(
	parameter NBITS = -1 // Number of bits in delay counter
	)(
	input START_CLK,
	input start,

	input RESET_CLK,
	input reset,

	input CLK,
	output reg timeout = 0
	);

	sync_pulse sync_start(.wr_clk(START_CLK), .sig(start), .busy(),
		.rd_clk(CLK), .out(start_sync) );

	sync_pulse sync_reset(.wr_clk(RESET_CLK), .sig(reset), .busy(),
		.rd_clk(CLK), .out(reset_sync) );


	localparam WD_STATE_NONE = 0,
				WD_STATE_WAIT = 1;

	(* FSM_EXTRACT="true" *)
	reg wd_state = WD_STATE_NONE;

	always @(posedge CLK) begin
		case (wd_state)
		WD_STATE_NONE: if (start_sync)
			wd_state <= WD_STATE_WAIT;

		WD_STATE_WAIT: if (reset_sync) begin
			timeout <= 0;
			wd_state <= WD_STATE_NONE;
		end
		else if (timeout_in)
			timeout <= 1;
		endcase
	end

	delay #( .NBITS(NBITS) ) delay_inst(.CLK(CLK),
		.in(wd_state == WD_STATE_WAIT), .out(timeout_in) );

endmodule

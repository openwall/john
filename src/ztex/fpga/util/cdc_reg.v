`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// *********************************************************
//
// Clock Domain Crossing Register
//
// * assumes frequency relation: wr_clk <= rd_clk <= wr_clk X 2
//   (write frequency is less or equal)
//
// *********************************************************

module cdc_reg #(
	parameter WIDTH = -1
	)(
	input wr_clk,
	input [WIDTH-1:0] din,
	input wr_en,
	output reg full = 0,
	
	input rd_clk,
	output reg [WIDTH-1:0] dout = {WIDTH{1'b0}},
	input rd_en,
	output empty
	);

	always @(posedge wr_clk) begin
		if (~full) begin
			if (wr_en) begin
				dout <= din;
				full <= 1;
			end
		end
		else if (rd_en_sync)
			full <= 0;
	end

	sync_sig sync_full(.sig(full), .clk(rd_clk), .out(full_sync));

	sync_short_sig #(.CLK1(1)) sync_rd_en(.sig(rd_en), .clk(wr_clk), .out(rd_en_sync));
	
	// EMPTY considerations.
	// must react on rd_en in 1 cycle - requires to run on rd_clk clock
	// after read, consider FULL flag synchronization
	localparam	EMPTY_STATE_INIT = 0,
					EMPTY_STATE_CAN_READ = 1,
					EMPTY_STATE_READ_COMPLETE = 2;

	(* FSM_EXTRACT="true" *)
	reg [1:0] empty_state = EMPTY_STATE_INIT;
	
	always @(posedge rd_clk)
		case (empty_state)
		EMPTY_STATE_INIT:
			if (full_sync)
				empty_state <= EMPTY_STATE_CAN_READ;
			
		EMPTY_STATE_CAN_READ:
			if (rd_en)
				empty_state <= EMPTY_STATE_READ_COMPLETE;
				
		EMPTY_STATE_READ_COMPLETE:
			if (~full_sync)
				empty_state <= EMPTY_STATE_INIT;

		endcase

	assign empty = empty_state == EMPTY_STATE_CAN_READ ? 1'b0 : 1'b1;
	

endmodule


// *********************************************************
//
// Clock Domain Crossing Register - Improved version
//
// * Any frequency relation
// * For good throughput, use a FIFO
//
// *********************************************************

module xdc_reg #(
	parameter WIDTH = -1
	)(
	input wr_clk,
	input [WIDTH-1:0] din,
	input wr_en,
	output reg full = 0,
	
	input rd_clk,
	output reg [WIDTH-1:0] dout = {WIDTH{1'b0}},
	input rd_en,
	output empty
	);

	always @(posedge wr_clk) begin
		if (~full) begin
			if (wr_en) begin
				dout <= din;
				full <= 1;
			end
		end
		else if (rd_en_sync)
			full <= 0;
	end

	sync_pulse sync_full(.wr_clk(wr_clk), .sig(full), .busy(), .rd_clk(rd_clk), .out(full_sync));

	sync_pulse sync_rd_en(.wr_clk(rd_clk), .sig(rd_en), .busy(), .rd_clk(wr_clk), .out(rd_en_sync));
	
	localparam	EMPTY_STATE_CAN_READ = 0,
					EMPTY_STATE_READ_COMPLETE = 1;

	//(* FSM_EXTRACT="true" *)
	reg empty_state = EMPTY_STATE_CAN_READ;
	
	always @(posedge rd_clk)
		case (empty_state)
		EMPTY_STATE_CAN_READ:
			if (rd_en & full_sync)
				empty_state <= EMPTY_STATE_READ_COMPLETE;
				
		EMPTY_STATE_READ_COMPLETE:
			if (~full_sync)
				empty_state <= EMPTY_STATE_CAN_READ;

		endcase

	assign empty = empty_state == EMPTY_STATE_CAN_READ & full_sync ? 1'b0 : 1'b1;

endmodule

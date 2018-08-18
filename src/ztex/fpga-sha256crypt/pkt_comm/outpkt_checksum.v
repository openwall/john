`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

module outpkt_checksum(
	input CLK,
	input [15:0] din,
	input pkt_new, // asserted on 1st word of packet header
	input pkt_end, // asserted on last word of packet data
	input wr_en,
	output full,
	output [15:0] dout,
	output reg pkt_end_out = 0,
	input rd_en,
	output empty
	);

	localparam PKT_HEADER_LEN = 10;

	// 4-byte checksum:
	//
	// after packet header
	// after each PKT_CHECKSUM_INTERVAL bytes <-- not implemented
	// after the end of packet
	localparam PKT_CHECKSUM_INTERVAL = 448;

	// Input register.
	reg [15:0] input_r;
	reg full_r = 0, pkt_new_r = 0, pkt_end_r = 0;
	assign full = full_r;
	
	always @(posedge CLK) begin
		if (wr_en & (~full_r | input_rd_en)) begin
			input_r <= din;
			pkt_new_r <= pkt_new;
			pkt_end_r <= pkt_end;
			full_r <= 1;
		end
		else if (input_rd_en)
			full_r <= 0;
	end

	// Output register.
	reg [15:0] output_r;
	assign dout = output_r;
	reg empty_r = 1;
	assign empty = empty_r;

	always @(posedge CLK)
		if (rd_en & ~output_wr_en)
			empty_r <= 1;
		else if (output_wr_en & ~rd_en)
			empty_r <= 0;
	

	//(* USE_DSP48="true" *)
	reg [31:0] checksum = 0;
	reg [15:0] checksum_tmp = 0;
	reg checksum_counter = 0;
	//reg [`MSB(PKT_CHECKSUM_INTERVAL/2):0] word_counter = 0;
	reg [`MSB(PKT_HEADER_LEN/2):0] word_counter = 0;
	
	localparam	STATE_PKT_INPUT = 0,
					STATE_CHECKSUM0 = 1,
					STATE_CHECKSUM1 = 2,
					STATE_CHECKSUM2 = 3;
	
	(* FSM_EXTRACT="true" *)
	reg [1:0] state = STATE_PKT_INPUT;

	reg pkt_state = 0; // 0: packet header, 1: packet data
	
	// Read from input register.
	assign input_rd_en =
		full_r & (state == STATE_PKT_INPUT)
		& (empty_r | ~empty_r & rd_en);
		
	// Write into output register.
	assign output_wr_en =
		(full_r & (state == STATE_PKT_INPUT)
		| (state == STATE_CHECKSUM1 | state == STATE_CHECKSUM2))
		& (empty_r | ~empty_r & rd_en);
		
	always @(posedge CLK) begin
		if (state == STATE_PKT_INPUT) begin
			if (output_wr_en) begin

				output_r <= input_r;
				pkt_end_out <= 0;
				
				if (pkt_new_r | ~checksum_counter) begin
					checksum_tmp <= input_r;
					checksum_counter <= 1;
				end
				else if (checksum_counter) begin
					checksum <= checksum + {input_r, checksum_tmp};
					checksum_counter <= 0;
				end
			
				if (~pkt_state & word_counter == PKT_HEADER_LEN/2 - 1
					//| word_counter == PKT_CHECKSUM_INTERVAL/2 - 1
					| pkt_end_r
				) begin
					if (~checksum_counter)
						state <= STATE_CHECKSUM0;
					else
						state <= STATE_CHECKSUM1;
				end
				else
					word_counter <= word_counter + 1'b1;
			end // input_rd_en
		end
		
		else if (state == STATE_CHECKSUM0) begin
			checksum <= checksum + checksum_tmp;
			state <= STATE_CHECKSUM1;
		end

		else if (state == STATE_CHECKSUM1) begin
			if (output_wr_en) begin
				output_r <= ~checksum[15:0];
				state <= STATE_CHECKSUM2;
			end
		end
		
		else if (state == STATE_CHECKSUM2) begin
			if (output_wr_en) begin
				output_r <= ~checksum[31:16];
				if (pkt_state)
					pkt_end_out <= 1;
				checksum_counter <= 0;
				checksum <= 0;
				
				pkt_state <= ~pkt_state;
				word_counter <= 0;
				state <= STATE_PKT_INPUT;
			end
		end
	end


endmodule

`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// ********************************************************************
//
// template_list_b: stores the word into 8-bit wide memory.
//
// template_list is going to replace word_list.
//
// * Designed for usage with word_gen_b
//
// * Accepts both PKT_TYPE_WORD_LIST and PKT_TYPE_TEMPLATE_LIST
//
// * If word length is WORD_MAX_LEN, then it isn't followed by '\0';
//   shorter words are '\0' terminated.
//
// * In PKT_TYPE_TEMPLATE_LIST, each word is followed by
//   RANGE_INFO records: RANGES_MAX records 1 byte each.
//   If some RANGE_INFO record is zero, then it was the last range_info
//   for the template key.
//
// * Last word is followed by a dummy word with word_list_end asserted
//
// ********************************************************************

module template_list_b #(
	parameter WORD_MAX_LEN = -1,
	parameter RANGES_MAX = -1,
	parameter RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1)
	)(
	input CLK,

	input [7:0] din,
	input wr_en,
	output reg full = 1,
	input inpkt_end,
	input is_template_list,

	output reg [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info = 0,
	output reg [15:0] word_id = 0,
	// It produces a dummy word after the end of the list, with word_list_end set
	output word_list_end,

	// Output from 8-bit wide word_storage
	output [7:0] dout,
	input [`MSB(WORD_MAX_LEN-1):0] rd_addr,
	input set_empty,
	output empty,

	output reg err_template = 0, err_word_list_count = 0
	);

	// Storage for output generated word
	reg [`MSB(WORD_MAX_LEN-1):0] storage_wr_addr = 0;
	reg storage_set_full = 0;

	reg [`MSB(RANGES_MAX-1):0] range_info_count = 0;
	reg word_list_end_r = 0;

	localparam [2:0] STATE_INIT = 0,
					STATE_WR_WORD = 1,
					STATE_PAD_ZEROES = 2,
					STATE_WR_RANGE_INFO = 3,
					STATE_RD_START = 4,
					STATE_RD_WAIT = 5,
					STATE_RD_LIST_END_START = 6,
					STATE_RD_LIST_END_WAIT = 7;

	(* FSM_EXTRACT="true" *)
	reg [2:0] state = STATE_INIT;

	always @(posedge CLK) begin
		case (state)
		STATE_INIT: begin
			range_info <= 0;
			range_info_count <= 0;
			word_list_end_r <= 0;
			storage_wr_addr <= 0;
			full <= 0;
			state <= STATE_WR_WORD;
		end

		STATE_WR_WORD:	if (wr_en) begin
			storage_wr_addr <= storage_wr_addr + 1'b1;

			if (storage_wr_addr == WORD_MAX_LEN - 1) begin
				// word is at max.length - word ends
				if (~is_template_list) begin
					full <= 1;
					storage_set_full <= 1;
					state <= STATE_RD_START;
				end
				else
					state <= STATE_WR_RANGE_INFO;
			end
			else if (din == 0) begin
				full <= 1;
				// word ends; word of zero length - OK, permitted
				state <= STATE_PAD_ZEROES;
			end

			if (inpkt_end) begin
				word_list_end_r <= 1;
				if (is_template_list || (din != 0 && storage_wr_addr != WORD_MAX_LEN - 1) )
					// inexpected pkt_end
					err_template <= 1;
			end
		end

		STATE_PAD_ZEROES: begin
			storage_wr_addr <= storage_wr_addr + 1'b1;
			if (storage_wr_addr == WORD_MAX_LEN - 1) begin
				if (is_template_list) begin
					full <= 0;
					state <= STATE_WR_RANGE_INFO;
				end
				else begin
					storage_set_full <= 1;
					state <= STATE_RD_START;
				end
			end
		end

		STATE_WR_RANGE_INFO: if (wr_en) begin
			range_info_count <= range_info_count + 1'b1;

			if (din == 0) begin
				// range_info ends
				full <= 1;
				storage_set_full <= 1;
				state <= STATE_RD_START;
			end
			else begin
				// next item of range_info going
				range_info[(range_info_count + 1'b1)*(RANGE_INFO_MSB+1)-1 -:RANGE_INFO_MSB+1]
						<= { din[7], din[RANGE_INFO_MSB-1:0] };

				if (WORD_MAX_LEN < 64 && din[6 : RANGE_INFO_MSB >= 6 ? 6 : RANGE_INFO_MSB+1] != 0)
					// unexpected content in range_info
					err_template <= 1;

				if (range_info_count == RANGES_MAX - 1) begin
					full <= 1;
					storage_set_full <= 1;
					state <= STATE_RD_START;
				end
			end

			if (inpkt_end) begin
				word_list_end_r <= 1;
				if (din != 0 && range_info_count != RANGES_MAX - 1)
					// inexpected pkt_end
					err_template <= 1;
			end
		end

		STATE_RD_START: begin
			storage_set_full <= 0;
			state <= STATE_RD_WAIT;
		end

		// Wait until the reader reads it
		STATE_RD_WAIT: if (~storage_full) begin
			if (word_list_end_r) begin
				storage_set_full <= 1;
				word_id <= 0;
				state <= STATE_RD_LIST_END_START;
			end
			else begin
				word_id <= word_id + 1'b1;
				state <= STATE_INIT;
			end

			if ( ~|(word_id + 1'b1) )
				// word_id_r overflows
				err_word_list_count <= 1;
		end

		// Write dummy word after the end of the list, with word_list_end set
		STATE_RD_LIST_END_START: begin
			storage_set_full <= 0;
			state <= STATE_RD_LIST_END_WAIT;
		end

		STATE_RD_LIST_END_WAIT: if (~storage_full)
			state <= STATE_INIT;

		endcase
	end

	assign storage_wr_en = wr_en && state == STATE_WR_WORD || state == STATE_PAD_ZEROES;

	assign word_list_end = state == STATE_RD_LIST_END_WAIT;

	word_storage #( .WORD_MAX_LEN(WORD_MAX_LEN)
	) word_storage(
		.CLK(CLK),
		.din(state == STATE_PAD_ZEROES ? 8'd0 : din), .wr_addr(storage_wr_addr),
		.wr_en(storage_wr_en), .set_full(storage_set_full), .full(storage_full),

		.dout(dout), .rd_addr(rd_addr), .set_empty(set_empty), .empty(empty)
	);


endmodule

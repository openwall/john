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
// template_list is going to replace word_list.
//
// * Designed for usage with word_gen_v2
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

module template_list #(
	parameter CHAR_BITS = -1, // valid values: 7 8
	parameter WORD_MAX_LEN = -1,
	parameter RANGES_MAX = -1,
	parameter RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1)
	)(
	input wr_clk,
	input [7:0] din,
	input wr_en,
	output full,
	input inpkt_end,
	input is_template_list,

	input rd_clk,
	output [WORD_MAX_LEN * CHAR_BITS - 1 :0] dout,
	output [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info,
	(* USE_DSP48="true" *)
	output [15:0] word_id,
	output word_list_end,
	input rd_en,
	output empty,
	
	output reg err_template = 0, err_word_list_count = 0
	);

	reg full_r = 0;
	assign full = full_r;

	reg [WORD_MAX_LEN * CHAR_BITS - 1 :0] dout_r = 0;
	reg [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info_r = 0;
	reg [15:0] word_id_r = 0;
	reg word_list_end_r = 0;
	
	reg [`MSB(WORD_MAX_LEN-1):0] char_count = 0;
	reg [`MSB(RANGES_MAX-1):0] range_info_count = 0;
	

	localparam [1:0] STATE_WR_WORD = 0,
					STATE_WR_RANGE_INFO = 1,
					STATE_RD = 2,
					STATE_RD_LIST_END = 3;

	(* FSM_EXTRACT="true" *)
	reg [1:0] state = STATE_WR_WORD;
	
	always @(posedge wr_clk) begin
		case (state)
		STATE_WR_WORD:	if (wr_en) begin
			if (din == 0) begin
				// word ends; word of zero length - OK, permitted
				if (~is_template_list)
					full_r <= 1;
				state <= is_template_list ? STATE_WR_RANGE_INFO : STATE_RD;
			end
			else begin
				// next char is going
				dout_r[(char_count + 1'b1)*CHAR_BITS-1 -:CHAR_BITS] <= din[CHAR_BITS-1:0];
				
				if (char_count == WORD_MAX_LEN - 1) begin
					// word is at max.length - word ends
					if (~is_template_list)
						full_r <= 1;
					state <= is_template_list ? STATE_WR_RANGE_INFO : STATE_RD;
				end
				else
					char_count <= char_count + 1'b1;
			end
			
			if (inpkt_end) begin
				word_list_end_r <= 1;
				if (is_template_list || (din && char_count != WORD_MAX_LEN - 1) )
					// inexpected pkt_end
					err_template <= 1;
			end
		end
		
		STATE_WR_RANGE_INFO: if (wr_en) begin
			if (din == 0) begin
				// range_info ends
				full_r <= 1;
				state <= STATE_RD;
			end
			else begin
				// next item of range_info going
				range_info_r[(range_info_count + 1'b1)*(RANGE_INFO_MSB+1)-1 -:RANGE_INFO_MSB+1]
						<= { din[7], din[RANGE_INFO_MSB-1:0] };
				//if (WORD_MAX_LEN < 64)
				if (din[6:RANGE_INFO_MSB] != 0)
					// unexpected content in range_info
					err_template <= 1;
						
				if (range_info_count == RANGES_MAX - 1) begin
					full_r <= 1;
					state <= STATE_RD;
				end
				else
					range_info_count <= range_info_count + 1'b1;
			end

			if (inpkt_end) begin
				word_list_end_r <= 1;
				if ( din && range_info_count != RANGES_MAX - 1)
					// inexpected pkt_end
					err_template <= 1;
			end
		end
		
		STATE_RD: if (rd_en_internal) begin
			dout_r <= 0;
			range_info_r <= 0;
			char_count <= 0;
			range_info_count <= 0;
			
			word_list_end_r <= 0;
			if (word_list_end_r) begin
				word_id_r <= 0;
				state <= STATE_RD_LIST_END;
			end
			else begin
				full_r <= 0;
				word_id_r <= word_id_r + 1'b1;
				state <= STATE_WR_WORD;
			end

			if (&word_id_r)
				// word_id_r overflows
				err_word_list_count <= 1;
		end
		
		// Write dummy word after the end of the list, with word_list_end set
		STATE_RD_LIST_END: if (rd_en_internal) begin
			full_r <= 0;
			state <= STATE_WR_WORD;
		end
		
		endcase
	end
	
	assign rd_en_internal = ~output_reg_full
			& (state == STATE_RD || state == STATE_RD_LIST_END);

	cdc_reg #( 
		.WIDTH(WORD_MAX_LEN*CHAR_BITS + RANGES_MAX*(RANGE_INFO_MSB+1) + 16 + 1)
	) output_reg (
		.wr_clk(wr_clk),
		.din({ dout_r, range_info_r, word_id_r, state == STATE_RD_LIST_END }),
		.wr_en(rd_en_internal), .full(output_reg_full),
		
		.rd_clk(rd_clk),
		.dout({ dout, range_info, word_id, word_list_end }),
		.rd_en(rd_en), .empty(empty)
	);

endmodule

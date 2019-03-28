`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016-2017,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//**********************************************************************
//
// 2017:
// - removed start_idx,num_generate (accept and ignore)
// - input word_list ends with a dummy word with word_list_end set
// - after the last candidate, generates a dummy one with gen_end set
//
// Version 2 of word generator.
//
// * Designed to work with template_list.
// * Interface difference is that word_len input is removed,
//		range_info input is added.
// * Items removed from configuration: num_words, word_insert_pos
// * Removed mode of operation not based on supplied words.
//
//
// Word Generator
//
// * Words are produced every cycle (as long as reader is not full).
// * Delay when getting a new word from word_list:
//		1 cycle if start_idx's not used, 3 if used.
// * There's a delay when it loads a new configuration for word generator,
// 	equal to number of bytes in configuration at CLK frequency
// 	plus few more cycles.
//
//**********************************************************************

module word_gen_v2 #(
	parameter CHAR_BITS = -1, // valid values: 7 8
	parameter RANGES_MAX = -1,
	parameter WORD_MAX_LEN = -1,
	parameter RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1)
	)(
	input CLK, // configuration clock
	// Word generator configuration.
	input [7:0] din,
	input [15:0] inpkt_id,
	input wr_conf_en,
	output conf_full,

	input WORD_GEN_CLK, // clock for running word_list input, generation and output
	// Accepts 1 packet of type word_list then finishes.
	input [WORD_MAX_LEN * CHAR_BITS - 1 :0] word_in,
	input [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info,
	input [15:0] word_id,
	input word_list_end,
	input word_wr_en,
	output reg word_full = 0,

	input rd_en,
	output empty,
	output [WORD_MAX_LEN * CHAR_BITS - 1 :0] dout,
	output reg [15:0] pkt_id,
	output reg [15:0] word_id_out,
	// Number of generated word (resets on each inserted word)
	output reg [31:0] gen_id = 0,
	output gen_end, // asserts on last generated word
	output word_end,

	output reg err_word_gen_conf = 0
	);


	reg conf_done = 0;
	assign conf_full = state == CONF_ERROR | state == CONF_DONE;

	// Max. number of chars in range
	localparam CHARS_NUMBER_MAX = CHAR_BITS == 7 ? 128 : 256;

	localparam NUM_RANGES_MSB = `MSB(RANGES_MAX);
	localparam NUM_CHARS_MSB = `MSB(CHARS_NUMBER_MAX-1);

	// Number of the last range (num_ranges - 1)
	reg [NUM_RANGES_MSB:0] last_range_num;
	reg [NUM_RANGES_MSB:0] conf_range_count;

	// Number of the last character in the range (num_chars - 1)
	reg [NUM_CHARS_MSB:0] conf_last_char_num;
	reg [NUM_CHARS_MSB:0] conf_chars_count;

	assign conf_en_num_chars = state == CONF_RANGE_NUM_CHARS;
	assign conf_en_chars = state == CONF_RANGE_CHARS;

	wire [RANGES_MAX * CHAR_BITS - 1:0] range_dout;

	wire range_rd_en;
	wire carry_in [RANGES_MAX-1:0];
	wire carry [RANGES_MAX-1:0];
	wire carry_out [RANGES_MAX-1:0];
	reg op_done = 0;

	sync_short_sig #(.CLK1(1)) sync_op_done (.sig(op_done), .clk(CLK), .out(op_done_sync) );


	`include "word_gen.vh"

	(* FSM_EXTRACT = "true", FSM_ENCODING = "speed1" *)
	reg [2:0] op_state = OP_STATE_DONE;

	genvar i;
	generate
	for (i=0; i < RANGES_MAX; i=i+1)
	begin:char_ranges

		assign range_conf_en = i == conf_range_count;
		assign carry_in[i] = i == RANGES_MAX-1 ? 1'b1 : carry_out[(i==RANGES_MAX-1) ? 0 : i+1];
		assign carry_out[i] = carry_in[i] & carry[i];

		word_gen_char_range #(
			.CHAR_BITS(CHAR_BITS), .CHARS_NUMBER_MAX(CHARS_NUMBER_MAX)
		) word_gen_char_range(
			.CONF_CLK(CLK),
			.din(din[CHAR_BITS-1:0]),
			.conf_en_num_chars(range_conf_en & conf_en_num_chars),
			.num_chars_eq0(1'b0), .num_chars_lt2(din[NUM_CHARS_MSB:0] < 2),

			.conf_en_chars(range_conf_en & conf_en_chars), .conf_char_addr(conf_chars_count),
			.pre_end_char(conf_chars_count + 1'b1 == conf_last_char_num),

			.OP_CLK(WORD_GEN_CLK),
			.op_en(range_rd_en), .op_state(op_state), .op_done_sync(op_done_sync),
			.carry_in(carry_in[i]), .carry(carry[i]),
			.dout(range_dout[(i+1)*CHAR_BITS-1 -:CHAR_BITS])
		);

	end
	endgenerate


	// *******************************************************************
	//
	// Operation
	//
	// *******************************************************************

	// Generator v2 always inserts words.
	//wire word_insert_mode = 1'b1;//num_words != 0;

	// input from word_list.
	//
	//reg [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info_r;
	// input range_info is converted to easy to use form
	wire [WORD_MAX_LEN-1:0] if_range;
	wire [WORD_MAX_LEN*(RANGE_INFO_MSB)-1:0] range_shift_val;

	// Attn.: confising identifiers.
	// range_info contains new positions for placeholders.
	// (previously contained shift for placeholders).
	range_info_process #(
		.RANGES_MAX(RANGES_MAX), .WORD_MAX_LEN(WORD_MAX_LEN)
	) range_info_process(
		.range_info(range_info),
		.if_range(if_range),
		.range_shift_val(range_shift_val)
	);

	reg [WORD_MAX_LEN * CHAR_BITS - 1 :0] word_in_r;
	reg word_list_end_r = 0;
	reg [WORD_MAX_LEN-1:0] if_range_r;
	reg [WORD_MAX_LEN*(RANGE_INFO_MSB)-1:0] range_shift_val_r;

	range_insert #(
		.CHAR_BITS(CHAR_BITS), .RANGES_MAX(RANGES_MAX), .WORD_MAX_LEN(WORD_MAX_LEN)
	) range_insert(
		.word(word_in_r),
		.ranges(range_dout),
		//.range_info(range_info_r),
		.if_range(if_range_r),
		.range_shift_val(range_shift_val_r),
		.dout(dout)		// Output from the generator
	);

	always @(posedge WORD_GEN_CLK) begin

		if (~word_full & word_wr_en) begin
			word_full <= 1;

			// word_list ends with dummy word with word_list_end set.
			// generator produces 1 dummy candidate with gen_end set
			word_list_end_r <= word_list_end;

			word_in_r <= word_in;
			//range_info_r <= range_info;
			if_range_r <= if_range;
			range_shift_val_r <= range_shift_val;
			word_id_out <= word_id;
		end

		case (op_state)
		OP_STATE_READY: begin
			// Ranges configured, ready for operation
			if (conf_done_sync) begin
				op_state <= OP_STATE_START;
			end
		end

		OP_STATE_START: begin
			if (EXTRA_REGISTER_STAGE)
				op_state <= OP_STATE_EXTRA_STAGE;
			else
				op_state <= OP_STATE_NEXT_CHAR;
		end

		OP_STATE_EXTRA_STAGE: begin
			op_state <= OP_STATE_NEXT_CHAR;
		end

		OP_STATE_NEXT_CHAR: if (range_rd_en) begin
			if (carry_out[0] | word_list_end_r) begin

				// Generation for current word ends.
				word_full <= 0;
				if (word_list_end_r) begin
					// Generation for current word_list ends.
					op_done <= 1;
					op_state <= OP_STATE_DONE;
				end

				// continue with next word
			end
		end

		OP_STATE_DONE: begin // reset configuration
			op_done <= 0;
			op_state <= OP_STATE_READY;
		end
		endcase

	end

	assign range_rd_en = rd_en & ~empty;

	assign empty = ~(
		op_state == OP_STATE_NEXT_CHAR & word_full
	);

	assign gen_end = op_state == OP_STATE_NEXT_CHAR & word_list_end_r;

	assign word_end = op_state == OP_STATE_NEXT_CHAR & carry_out[0];

	always @(posedge WORD_GEN_CLK)
		if (range_rd_en & op_state == OP_STATE_NEXT_CHAR)
			if (carry_out[0] | word_list_end_r)
				gen_id <= 0;
			else
				gen_id <= gen_id + 1'b1;


	// *******************************************************************
	//
	// Configuration (word_gen.h)
	//
	// struct word_gen_char_range {
	//		unsigned char num_chars;		// number of chars in range
	//		unsigned char start_idx;		// UNUSED
	//		unsigned char chars[CHAR_BITS==7 ? 128 : 256]; // only chars_number transmitted
	//	};
	// range must have at least 1 char
	//
	// struct word_gen {
	//		unsigned char num_ranges;
	//		struct word_gen_char_range ranges[RANGES_MAX]; // only num_ranges transmitted
	//		unsigned long num_generate; // UNUSED
	//		unsigned char magic;	// 0xBB
	//	};
	//
	// example word generator (words pass-by):
	// {
	// 0,		// num_ranges
	// 0,		// UNUSED
	// 0xBB
	// };
	//
	// *******************************************************************

	localparam	CONF_NUM_RANGES = 1,
					CONF_RANGE_NUM_CHARS = 2,
					CONF_RANGE_START_IDX = 3,
					CONF_RANGE_CHARS = 4,
					//CONF_NUM_WORDS = 5,
					//CONF_WORD_INSERT_POS = 6,
					CONF_NUM_GENERATE0 = 7,
					CONF_NUM_GENERATE1 = 8,
					CONF_NUM_GENERATE2 = 9,
					CONF_NUM_GENERATE3 = 10,
					CONF_MAGIC = 11,
					CONF_DONE = 12,
					CONF_ERROR = 13;

	(* FSM_EXTRACT = "true" *)
	reg [3:0] state = CONF_NUM_RANGES;

	always @(posedge CLK) begin
		if (state == CONF_DONE) begin
			conf_done <= 0;

			// Generation done. Ready for a new configuration.
			if (op_done_sync) begin
				state <= CONF_NUM_RANGES;
			end
		end

		else if (state == CONF_ERROR)
			err_word_gen_conf <= 1;

		else if (wr_conf_en) begin
			case (state)
			CONF_NUM_RANGES: begin
				pkt_id <= inpkt_id;
				last_range_num <= din[NUM_RANGES_MSB:0] - 1'b1;
				conf_range_count <= 0;
				// Num. of ranges exceeds RANGES_MAX
				if (din > RANGES_MAX)
					state <= CONF_ERROR;
				else if ( din[NUM_RANGES_MSB:0] )
					state <= CONF_RANGE_NUM_CHARS;
				else
					state <= CONF_NUM_GENERATE0;
			end

			CONF_RANGE_NUM_CHARS: begin
				conf_last_char_num <= din[NUM_CHARS_MSB:0] - 1'b1;
				conf_chars_count <= 0;
				// Wrong number of chars in range
				if (din == 0 || din > CHARS_NUMBER_MAX)
					state <= CONF_ERROR;
				else
					state <= CONF_RANGE_START_IDX;
			end

			CONF_RANGE_START_IDX: begin
				if (din != 0)
					state <= CONF_ERROR;
				else
					state <= CONF_RANGE_CHARS;
			end

			CONF_RANGE_CHARS: begin
				conf_chars_count <= conf_chars_count + 1'b1;
				if (conf_chars_count == conf_last_char_num) begin
					conf_range_count <= conf_range_count + 1'b1;
					if (conf_range_count == last_range_num)
						state <= CONF_NUM_GENERATE0;
					else
						state <= CONF_RANGE_NUM_CHARS;
				end
			end

			CONF_NUM_GENERATE0: begin
				state <= CONF_NUM_GENERATE1;
			end

			CONF_NUM_GENERATE1: begin
				state <= CONF_NUM_GENERATE2;
			end

			CONF_NUM_GENERATE2: begin
				state <= CONF_NUM_GENERATE3;
			end

			CONF_NUM_GENERATE3: begin
				state <= CONF_MAGIC;
			end

			CONF_MAGIC: begin
				if (din == 8'hBB) begin
					conf_done <= 1;
					state <= CONF_DONE;
				end
				else
					state <= CONF_ERROR;
			end

			endcase
		end

	end

	sync_sig sync_conf_done(.sig(conf_done), .clk(WORD_GEN_CLK), .out(conf_done_sync));

endmodule

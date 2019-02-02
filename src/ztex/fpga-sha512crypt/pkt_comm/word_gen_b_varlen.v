`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//**********************************************************************
//
// word_gen_b_varlen: inputs and outputs using 8-bit wide memory. Area optimized.
// Variable word length: not padded with zeroes, length is supplied/output,
// words don't end with '\0'.
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

module word_gen_b_varlen #(
	parameter RANGES_MAX = `RANGES_MAX,
	parameter WORD_MAX_LEN = `PLAINTEXT_LEN,
	parameter RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1)
	)(
	input CLK,
	
	// Word generator configuration.
	input [7:0] din,
	input [15:0] inpkt_id,
	input conf_wr_en,
	output reg conf_full = 0,

	// Words are read from byte-wide memory.
	input [7:0] word_in,
	output reg [`MSB(WORD_MAX_LEN-1):0] word_rd_addr = 0,
	input word_empty,
	output word_set_empty,
	// Each word is supplied with extra data.
	input [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info,
	input [15:0] word_id,
	input [`MSB(WORD_MAX_LEN):0] word_len,
	input word_list_end,

	// Output from 8-bit wide word_storage
	output [7:0] dout,
	input [`MSB(WORD_MAX_LEN-1):0] rd_addr,
	input set_empty,
	output empty,

	output reg [15:0] pkt_id,
	output reg [15:0] word_id_out,
	output reg [`MSB(WORD_MAX_LEN):0] word_len_out,
	// Number of generated word (resets on each inserted word)
	//(* USE_DSP48="true" *) 
	output reg [31:0] gen_id = 0,
	output reg gen_end = 0, // after last candidate from last word in word_list,
					// it generates extra dummy candidate with gen_end set
	//output word_end, // asserts on last candidate from each word
	output reg totally_empty = 1,
	
	output err
	);

	integer k;

	// *******************************************************************
	//
	// Configuration (word_gen.h)
	//
	// struct word_gen_char_range {
	//		unsigned char num_chars;	// number of chars in range
	//		unsigned char start_idx;	// unused
	//		unsigned char chars[256];	// only num_chars transmitted
	//	};
	// range must have at least 1 char
	//
	// struct word_gen {
	//		unsigned char num_ranges;
	//		struct word_gen_char_range ranges[RANGES_MAX]; // only num_ranges transmitted
	//		uint32_t num_generate;	// unused
	//		unsigned char magic;		// 0xBB
	//	};
	//
	// example word generator (words pass-by):
	// {
	// 0,		// num_ranges
	// 0,		// num_generate (unused)
	// 0xBB
	// };
	//
	// *******************************************************************

	localparam NUM_RANGES_MSB = `MSB(RANGES_MAX-1);
	
	// Number of the last range (num_ranges - 1)
	reg [NUM_RANGES_MSB:0] last_range_num;
	reg zero_ranges_active = 1;

	// *******************************************************************

	(* RAM_STYLE="DISTRIBUTED" *)
	reg [7:0] range_counter [RANGES_MAX-1 :0]; // Points at the next char in the range
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [7:0] range_count_max [RANGES_MAX-1 :0]; // Contains max. value for range_counter
	
	reg [7:0] cur_range_count = 0, cur_range_count_max = 0;
	reg [`MSB(RANGES_MAX-1):0] cur_range = 0;
	reg range_carry = 1;
		
	wire [7:0] range_char;
	
	// Upper bit indicates range is active
	reg [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info_r;
	
	wire cur_range_active = range_info_r [(cur_range+1)*(RANGE_INFO_MSB+1)-1];
	wire [RANGE_INFO_MSB-1:0] cur_range_pos
			= range_info_r [(cur_range+1)*(RANGE_INFO_MSB+1)-2 -:RANGE_INFO_MSB];

	reg [1:0] conf_num_generate = 0;
	
	wire [7:0] din_minus_1 = din - 1'b1;

	reg [`MSB(WORD_MAX_LEN-1):0] word_len_minus_1;
	wire [`MSB(WORD_MAX_LEN-1)+1:0] word_len_minus_1_eqn = word_len - 1'b1;

	localparam	CONF_NUM_RANGES = 0,
					CONF_RANGE_NUM_CHARS = 1,
					CONF_RANGE_START_IDX = 2,
					CONF_RANGE_CHARS = 3,
					CONF_RANGE_NEXT = 4,
					CONF_NUM_GENERATE = 5,
					CONF_MAGIC = 6,
					CONF_ERROR = 7,
					OP_RESET = 8,
					OP_COPY_NEXT_WORD = 9,
					OP_NEXT_RANGE_1 = 10,
					OP_NEXT_RANGE_2 = 11,
					OP_NEXT_RANGE_WR = 12,
					OP_WAIT_READ = 13;
	
	(* FSM_EXTRACT = "true" *)//, FSM_ENCODING="one-hot" *)
	reg [3:0] state = CONF_NUM_RANGES;
	
	always @(posedge CLK) begin
		case (state)
		//
		// Generator configuration.
		//
		CONF_NUM_RANGES: if (conf_wr_en) begin
			totally_empty <= 0;
			zero_ranges_active <= 1;
			pkt_id <= inpkt_id;
			last_range_num <= din_minus_1[NUM_RANGES_MSB:0];
			cur_range <= 0;
			// Num. of ranges exceeds RANGES_MAX
			if (din > RANGES_MAX)
				state <= CONF_ERROR;
			else if (din[`MSB(RANGES_MAX):0] != 0)
				state <= CONF_RANGE_NUM_CHARS;
			else
				state <= CONF_NUM_GENERATE;
		end
		
		CONF_RANGE_NUM_CHARS: if (conf_wr_en) begin
			zero_ranges_active <= 0;
			//range_count_max[cur_range] <= din_minus_1;
			cur_range_count_max <= din_minus_1;
			cur_range_count <= 0;
			// Wrong number of chars in range
			//if (din == 0)	// <-- allow 256 chars
			//	state <= CONF_ERROR;
			//else
				state <= CONF_RANGE_START_IDX;
		end

		CONF_RANGE_START_IDX: if (conf_wr_en) begin
			range_count_max[cur_range] <= cur_range_count_max;
			state <= CONF_RANGE_CHARS;
		end
			
		CONF_RANGE_CHARS: if (conf_wr_en) begin
			//ranges [{cur_range, cur_range_count}] <= din;
			cur_range_count <= cur_range_count + 1'b1;
			
			//if (cur_range_count == range_count_max[cur_range]) begin
			if (cur_range_count == cur_range_count_max) begin
				conf_full <= 1;
				state <= CONF_RANGE_NEXT;
			end
		end

		CONF_RANGE_NEXT: begin
			conf_full <= 0;
			cur_range <= cur_range + 1'b1;
			if (cur_range == last_range_num)
				state <= CONF_NUM_GENERATE;
			else
				state <= CONF_RANGE_NUM_CHARS;
		end
		
		CONF_NUM_GENERATE: if (conf_wr_en) begin
			conf_num_generate <= conf_num_generate + 1'b1;
			if (conf_num_generate == 3)
				state <= CONF_MAGIC;
		end

		CONF_MAGIC: if (conf_wr_en) begin
			conf_full <= 1;
			cur_range <= 0;
			if (din != 8'hBB)
				state <= CONF_ERROR;
			else
				state <= OP_RESET;
		end
		
		CONF_ERROR:
			conf_full <= 1;

		//
		// Generator operation.
		//
		OP_RESET: begin // Prepare to process next input word
			word_rd_addr <= 0;
			storage_wr_addr <= 0;

			//range_counter[cur_range] <= 0;
			cur_range <= cur_range + 1'b1;
			if (cur_range == RANGES_MAX - 1 & ~word_empty) begin
				word_len_minus_1// <= word_len - 1'b1;
					<= word_len_minus_1_eqn[`MSB(WORD_MAX_LEN-1):0];
				state <= OP_COPY_NEXT_WORD;
			end
		end

		// Start processing new input word - copy into output word_storage
		OP_COPY_NEXT_WORD: begin//if (~word_empty) begin
			word_rd_addr <= word_rd_addr + 1'b1;
			storage_wr_addr <= storage_wr_addr + 1'b1;
			cur_range <= last_range_num;
			range_carry <= 1;
			
			if (word_list_end)
				state <= OP_WAIT_READ;
			else if (storage_wr_addr == word_len_minus_1
					| word_len == 0) begin
				if (~zero_ranges_active)
					state <= OP_NEXT_RANGE_1;
				else
					state <= OP_WAIT_READ;
			end
			
			range_info_r <= range_info;

			// Also copy IDs
			word_id_out <= word_id;
			word_len_out <= word_len;
			gen_end <= word_list_end;
			gen_id <= 0;
		end

		OP_NEXT_RANGE_1: begin
			cur_range_count <= range_counter[cur_range];
			cur_range_count_max <= range_count_max[cur_range];
			state <= OP_NEXT_RANGE_2;
		end
			
		OP_NEXT_RANGE_2: begin
			if (range_carry) begin // Advance to the next char in the range
				//if (cur_range_count == range_count_max[cur_range]) begin
				if (cur_range_count == cur_range_count_max) begin
					//range_counter[cur_range] <= 0;
					range_carry <= 1;
				end
				else begin
					//range_counter[cur_range] <= cur_range_count + 1'b1;
					range_carry <= 0;
				end
			end
			storage_wr_addr <= cur_range_pos;
			// Get the char from ranges
			//range_char <= ranges [{cur_range, cur_range_count}];
			state <= OP_NEXT_RANGE_WR;
		end
		
		OP_NEXT_RANGE_WR: begin // Write word_storage
			// Advance pointer to the next range
			cur_range <= cur_range - 1'b1;
			if (cur_range == 0)
				state <= OP_WAIT_READ;
			else
				state <= OP_NEXT_RANGE_1;
		end
		
		// Wait until the reader reads generated word from the storage
		OP_WAIT_READ: if (~storage_full) begin
			range_carry <= 1;
			gen_id <= gen_id + 1'b1;

			if (gen_end) begin
				cur_range <= 0;
				conf_full <= 0;
				totally_empty <= 1;
				state <= CONF_NUM_RANGES;
			end
			else if (range_carry) begin // Generation for this input word is over
				cur_range <= 0;
				state <= OP_RESET;
			end
			else begin
				cur_range <= last_range_num;
				state <= OP_NEXT_RANGE_1;
			end
		end
		endcase
	end

	always @(posedge CLK)
		if (state == OP_RESET | state == OP_NEXT_RANGE_2 & range_carry)
			range_counter[cur_range] <= state == OP_NEXT_RANGE_2
				//& cur_range_count != range_count_max[cur_range]
				& cur_range_count != cur_range_count_max
					? cur_range_count + 1'b1 : 8'd0;
	
	assign err = state == CONF_ERROR;
	
	assign storage_wr_en = state == OP_COPY_NEXT_WORD
		| state == OP_NEXT_RANGE_WR;
	
	assign storage_set_full = (state == OP_NEXT_RANGE_WR & cur_range == 0)
		| state == OP_COPY_NEXT_WORD// & ~word_empty
			//& ( (storage_wr_addr + 1'b1 == word_len | word_len == 0)
			& ( (storage_wr_addr == word_len_minus_1 | word_len == 0)
				& zero_ranges_active | word_list_end);

	// set-empty-after-copy
	assign word_set_empty = state == OP_COPY_NEXT_WORD// & ~word_empty
		//& (storage_wr_addr + 1'b1 == word_len | word_len == 0
		& ( (storage_wr_addr == word_len_minus_1 | word_len == 0)
			| word_list_end);
	
	
	// Storage for range characters
	wire ram_wr_en = state == CONF_RANGE_CHARS && conf_wr_en;
	
	word_gen_ram #( .RANGES_MAX(RANGES_MAX)
	) word_gen_ram(
		.CLK(CLK), .din(din), .addr({cur_range, cur_range_count}),
		.en(ram_wr_en || state == OP_NEXT_RANGE_2), .wr_en(ram_wr_en),
		.dout(range_char)
	);

	
	// Storage for output generated word
	reg [`MSB(WORD_MAX_LEN-1):0] storage_wr_addr = 0;
	
	word_storage #( .WORD_MAX_LEN(WORD_MAX_LEN)
	) word_storage(
		.CLK(CLK),
		.din(state == OP_COPY_NEXT_WORD ? word_in : range_char),
		.wr_addr(storage_wr_addr), .wr_en(storage_wr_en),
		.set_full(storage_set_full), .full(storage_full),
		
		.dout(dout), .rd_addr(rd_addr), .set_empty(set_empty), .empty(empty)
	);

endmodule


module word_gen_ram #(
	parameter RANGES_MAX = -1
	)(
	input CLK,
	input [7:0] din,
	input [`MSB(RANGES_MAX-1)+1 +7:0] addr,
	input en,
	input wr_en,
	output reg [7:0] dout = 0
	);
	
	(* RAM_STYLE="BLOCK" *)
	//(* RAM_STYLE="DISTRIBUTED" *)
	reg [7:0] ranges [256*RANGES_MAX-1 :0];

	always @(posedge CLK) if (en)
		if (wr_en)
			ranges [addr] <= din;
		else
			dout <= ranges [addr];
	
endmodule


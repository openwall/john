`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "descrypt.vh"

//
// Do define CORE_INCLUDE_SRC when NGC file for "blackbox" module 
// is being built.
//
//`define CORE_INCLUDE_SRC

`ifdef CORE_INCLUDE_SRC

// Features:
// * Input register
// * CiDi circles over pipeline
//
module descrypt_core #(
	parameter READY_DELAY = 5, // =5: 1 extra reg. in wrapper
	parameter NUM_KEYS = 16,
	parameter ASYNC = 0 // ASYNC: CORE_CLK != CMP_CLK
	)(
	input CORE_CLK,
	input [`DIN_MSB:0] din,
	// addr_in:
	// ***1 - write hash into RAM
	// ***010 - write salt, read_addr_start, addr_diff_start
	// ***100 - write 56-bit key
	// ***110 - start computation, write batch_num & pkt_num
	input [2:0] addr_in,
	input wr_en,
	input [`GLOBAL_SALT_MSB:`GLOBAL_SALT_LSB] global_salt,
	
	output crypt_ready, // asserted when it's ready for new data
	output core_idle,
	output reg core_error = 0,
	
	input CMP_CLK,
	input dout_ready,
	output reg [3:0] dout = 0,
	output reg cmp_error = 0
	);

	genvar i;
	integer k;

	//
	// Input register.
	//
	reg [`DIN_MSB:0] din_r;
	reg [2:0] addr_r;
	reg wr_en_r = 0;
	
	always @(posedge CORE_CLK) begin
		if (wr_en) begin
			din_r <= din;
			addr_r <= addr_in;
		end
		wr_en_r <= wr_en;
	end
	
	reg [`GLOBAL_SALT_LSB-1:0] salt_r = 0;
	wire [`SALT_MSB:0] salt = { global_salt, salt_r };
	
	always @(posedge CORE_CLK)
		if (wr_en_r) begin
			if (addr_r[2:0] == 3'b010)
				{ addr_diff_start,
					read_addr_start,
					salt_r
				} <= din_r[`RAM_ADDR_MSB + `RAM_ADDR_MSB + `GLOBAL_SALT_LSB-1:0];
		end

	wire [55:0] key56_in = din_r[55:0];
	wire valid_in = din_r[56];
	
	reg write_key_r = 0;
	always @(posedge CORE_CLK)
		write_key_r <= wr_en & addr_in[2:0] == 3'b100;

	wire [`HASH_MSB:0] hash_out;

	// Only round0 affected by ENABLE
	reg ENABLE_CRYPT = 0;
	always @(posedge CORE_CLK)
		ENABLE_CRYPT <= wr_en & addr_in[2:0] == 3'b100 | state == STATE_GOING;

	descrypt16 descrypt16(
		.CLK(CORE_CLK), .salt_in(salt), .key56_in(key56_in), .valid_in(valid_in),
		.ENABLE_CRYPT(ENABLE_CRYPT),
		.START_CRYPT(write_key_r),
		
		.hash_out(hash_out), .valid_out(valid_out)
	);

	reg [3:0] loop_counter = 0;
	reg [`CRYPT_COUNTER_NBITS-1:0] crypt_counter = 0;
	reg crypt_cnt24 = 0; 
	reg loop14_crypt24 = 0;
	
	reg crypt_ready_r = 1; // it goes 400 cycles when crypt_ready_r deasserted
	// `crypt_ready' can assert before 'cmp_start/wait', waits for comparator
	reg crypt_ready_cmp_wait = 0; 
	assign crypt_ready = crypt_ready_r & ~crypt_ready_cmp_wait;
	wire cmp_ready_sync;
	assign core_idle = crypt_ready_r & cmp_ready_sync;

	localparam	STATE_IDLE = 0,
				STATE_GOING = 1;
				
	(* FSM_EXTRACT="true" *)
	reg [0:0] state = STATE_IDLE;
	
	always @(posedge CORE_CLK) begin
		if (write_key_r & (state == STATE_IDLE & ~crypt_ready_r
				| state == STATE_GOING & crypt_ready_r
				| state == STATE_GOING & crypt_counter != 0) )
			core_error <= 1;

		if (cmp_ready_sync)
			crypt_ready_cmp_wait <= 0;

		case (state)
		STATE_IDLE: begin
			if (write_key_r) begin
				crypt_ready_r <= 0;
				// Writer writes a batch of NUM_KEYS in sequence
				state <= STATE_GOING;
			end
			loop_counter <= 0;
			crypt_counter <= 0;
			crypt_cnt24 <= 0;
			loop14_crypt24 <= 0;
		end

		STATE_GOING: begin
			loop_counter <= loop_counter + 1'b1;
			loop14_crypt24 <= loop_counter == 13 & crypt_cnt24;

			if (crypt_cnt24 & loop_counter == 13 - READY_DELAY) begin
				crypt_ready_r <= 1;
				if (~cmp_ready_sync)
					crypt_ready_cmp_wait <= 1;
			end

			if (loop_counter == 15) begin
				crypt_counter <= crypt_counter + 1'b1;
				crypt_cnt24 <= crypt_counter == `CRYPT_COUNT - 2;
				if (crypt_cnt24)
					state <= STATE_IDLE;
			end
		end
		endcase
	end


	// Issue. Pipeline rounds mostly don't have clock enable.
	// Destination memory bank must be empty
	// when it starts to deploy keys onto the pipeline.
	// (== when crypt_ready output is asserted)
	//
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [1+`HASH_MSB:0] result [2 * NUM_KEYS - 1 :0]; 
	reg [3:0] result_cnt = 0;
	reg result_bank_wr = 0, result_bank_rd = 0;
	reg write_result = 0; // results are being written from the end of the pipeline into memory

	// intermediate reg at the end of the pipeline before write to DRAM.
	reg [1+`HASH_MSB:0] result_r;
	reg [3:0] result_cnt_r;
	reg write_result_r = 0;
	reg result_bank_wr_r;

	always @(posedge CORE_CLK)
		if (write_result) begin
			result_r <= { valid_out, hash_out };
			result_cnt_r <= result_cnt;
			result_bank_wr_r <= result_bank_wr;
			write_result_r <= 1;
		end
		else
			write_result_r <= 0;
		
	always @(posedge CORE_CLK)
		if (write_result_r)
			result [ {result_bank_wr_r, result_cnt_r} ] <= result_r;

	always @(posedge CORE_CLK)
		if (write_result) begin
			result_cnt <= result_cnt + 1'b1;
			if (result_cnt == NUM_KEYS-1) begin
				write_result <= 0;
				result_bank_wr <= ~result_bank_wr;
			end
		end
		else if (loop14_crypt24)
			write_result <= 1;

	reg cmp_start = 0; // flag for comparator
	reg cmp_wait = 0; // asserted when waiting for comparator to finish
	
	always @(posedge CORE_CLK)
		if (cmp_start)
			cmp_start <= 0;

		else if (loop14_crypt24)
			if (cmp_ready_sync)
				cmp_start <= 1;
			else
				cmp_wait <= 1;

		else if (cmp_wait & cmp_ready_sync) begin
			cmp_wait <= 0;
			cmp_start <= 1;
		end

	
	// batch_num & pkt_num written on the next cycle after keys
	reg [`NUM_BATCHES_MSB:0] batch_num [1:0];
	reg [`NUM_PKTS_MSB:0] pkt_num [1:0];

	always @(posedge CORE_CLK) begin
		if (wr_en_r & addr_r[2:0] == 3'b110) begin
			batch_num[result_bank_wr] <= din_r[`NUM_BATCHES_MSB:0];
			pkt_num[result_bank_wr] <= din_r[`NUM_PKTS_MSB + `NUM_BATCHES_MSB+1 : `NUM_BATCHES_MSB+1];
		end
	end

	(* KEEP="true" *)
	wire [`NUM_BATCHES_MSB:0] cmp_batch_num = batch_num [result_bank_rd];
	(* KEEP="true" *)
	wire [`NUM_PKTS_MSB:0] cmp_pkt_num = pkt_num [result_bank_rd];

	// *********************************************************
	//
	// Comparator
	//
	// *********************************************************

	reg cmp_ready = 1; // asserted when it's ready for comparsion
	wire cmp_start_sync; // signal starts the comparsion

	if (ASYNC) begin
		sync_sig sync_cmp_ready(.sig(cmp_ready), .clk(CORE_CLK), .out(cmp_ready_sync));
		// Assuming CMP_CLK frequency is less than CORE_CLK
		sync_short_sig sync_cmp_start(.sig(cmp_start), .clk(CMP_CLK), .out(cmp_start_sync));
	end
	else begin
		assign cmp_ready_sync = cmp_ready;
		assign cmp_start_sync = cmp_start;
	end


	// Comparator configuration.
	localparam [`RAM_ADDR_MSB-1:0] READ_ADDR_INIT = {`RAM_ADDR_MSB{1'b1}};
	reg [`RAM_ADDR_MSB-1:0] read_addr_start = READ_ADDR_INIT;
	localparam [`RAM_ADDR_MSB-1:0] ADDR_DIFF_INIT = { 1'b1, {`RAM_ADDR_MSB-1{1'b0}} };
	reg [`RAM_ADDR_MSB-1:0] addr_diff_start = ADDR_DIFF_INIT;

	
	reg [`MSB(NUM_KEYS-1):0] cmp_instance = 0;
	reg current_key_valid = 0;
	wire [`HASH_MSB:0] cmp_hash_out;
	wire current_key_valid_out;
	assign {current_key_valid_out, cmp_hash_out}
		= result [ {result_bank_rd, cmp_instance} ];

	wire [`RAM_ADDR_MSB:0] ram_read_addr;
	reg [`RAM_ADDR_MSB:0] ram_read_addr_r;
	reg [`RAM_ADDR_MSB-1:0] read_addr_diff;
	reg cur_hash_cmp_over = 0;
	
	
	// MSB in RAM indicates hash is valid
	// upper table row is unused (hash_valid always 0)
	(* RAM_STYLE = "BLOCK" *)
	reg [1+`HASH_MSB:0] ram [2**(`RAM_ADDR_MSB+1)-1:0];
	initial
		for (k=0; k < 2**(`RAM_ADDR_MSB+1); k=k+1)
			ram[k] = {1+`HASH_MSB+1{1'b0}};
			
	
	reg [`HASH_MSB:0] ram_out = 0;
	reg hash_valid = 0, hash_valid_r = 0;
	
	always @(posedge CORE_CLK)
		if (wr_en_r & addr_r[0])
			ram[ din_r[`RAM_ADDR_MSB+2+`HASH_MSB : 2+`HASH_MSB] ] <= din_r[1+`HASH_MSB:0];

	always @(posedge CMP_CLK)
		if (cmp_state == CMP_STATE_START | cmp_state == CMP_STATE_COMPARE)
			{hash_valid, ram_out} <= ram[ram_read_addr];


	// On the read from BRAM, compare some bits immediately (cycle 0).
	// Issue: it must place 'borrow' FF immediately after carry_out.
	localparam CMP0_NBITS = 34;

	reg [`HASH_MSB:CMP0_NBITS] cmp_hash, ram_out_r;

	reg borrow = 0, equal = 0;
	wire [1+CMP0_NBITS-1 :0] sub_result
		= cmp_hash_out[CMP0_NBITS-1:0] - ram_out[CMP0_NBITS-1:0];

	always @(posedge CMP_CLK) begin
		borrow <= sub_result[CMP0_NBITS];
		equal <= cmp_hash_out[CMP0_NBITS-1:0] == ram_out[CMP0_NBITS-1:0];
	end

	wire EQUAL = current_key_valid & hash_valid_r & equal
		& cmp_hash == ram_out_r;

	wire BATCH_COMPLETE = cmp_instance == NUM_KEYS - 1;
	
	reg equal_r = 0, batch_complete_r = 0;

	// Bsearch-type comparator. Expecting hashes in RAM are in ascending order.
	// On the 1st read from memory on a new search, 'ram_read_start' is asserted.
	(* KEEP="true" *)
	wire ram_read_start =
		cmp_state == CMP_STATE_START | cur_hash_cmp_over | ~current_key_valid;

	reg [`RAM_ADDR_MSB:0] ram_read_addr_sub, ram_read_addr_add;

	wire [1+`HASH_MSB:CMP0_NBITS] sub_result2 = cmp_hash - ram_out_r - borrow;
	(* KEEP="true" *)
	wire less_than = sub_result2[1+`HASH_MSB] | ~hash_valid_r;

	assign ram_read_addr =
		ram_read_start ? { 1'b0, read_addr_start } :
		less_than ? ram_read_addr_sub :
		ram_read_addr_add;
	
	reg dout_ready_r = 0;
	always @(posedge CMP_CLK)
		dout_ready_r <= dout_ready;
	
	
	localparam	CMP_STATE_IDLE = 0,
					CMP_STATE_START = 1,
					CMP_STATE_READ = 2,
					CMP_STATE_COMPARE = 3,
					CMP_STATE_CHECK = 4,
					CMP_STATE_BATCH_COMPLETE = 5;
					
	(* FSM_EXTRACT="true", FSM_ENCODING="one-hot" *)
	reg [2:0] cmp_state = CMP_STATE_IDLE;

	// A number of wires from distant cores pass-by other cores,
	// occupying routing resources and affecting timing. Reduce number of wires.
	// Output data is sent in a batch over 4-bit bus (2 or 6 writes)
	localparam OUTPUT_STATE_NONE = 0,
				OUTPUT_STATE_SEND1 = 2,
				OUTPUT_STATE_SEND2 = 3,
				OUTPUT_STATE_SEND3 = 4,
				OUTPUT_STATE_SEND4 = 5,
				OUTPUT_STATE_SEND5 = 6,
				OUTPUT_STATE_COMPLETE = 7;
				
				
	(* FSM_EXTRACT="true" *)
	reg [2:0] output_state = OUTPUT_STATE_NONE;
	
	always @(posedge CMP_CLK) begin
		case (cmp_state)
		CMP_STATE_IDLE: begin
			cmp_instance <= 0;
			dout <= 0;

			if (cmp_start_sync) begin
				if (!cmp_ready)
					cmp_error <= 1;
				cmp_ready <= 0;

				ram_read_addr_r <= { 1'b0, read_addr_start };
				read_addr_diff <= addr_diff_start;
				cur_hash_cmp_over <= addr_diff_start == 0;
				cmp_state <= CMP_STATE_START;
			end
		end

		CMP_STATE_START: begin // 1st read from ram
			cmp_state <= CMP_STATE_READ;
		end

		CMP_STATE_READ: begin // hash_valid, ram_out signals valid
			hash_valid_r <= hash_valid;
			ram_out_r <= ram_out[`HASH_MSB:CMP0_NBITS];		
			current_key_valid <= current_key_valid_out;
			cmp_hash <= cmp_hash_out[`HASH_MSB:CMP0_NBITS];

			ram_read_addr_sub <= ram_read_addr_r - read_addr_diff;
			ram_read_addr_add <= ram_read_addr_r + read_addr_diff;

			cmp_state <= CMP_STATE_COMPARE;
		end
		
		CMP_STATE_COMPARE: begin
			equal_r <= EQUAL;
			batch_complete_r <= BATCH_COMPLETE;
				
			if (EQUAL | cur_hash_cmp_over | ~current_key_valid) begin // search for current hash ends
				
				// Output equality or(and) batch_complete
				if (EQUAL | BATCH_COMPLETE) begin
					cmp_state <= CMP_STATE_CHECK;
				end
				else begin // comparsion of next hash
					ram_read_addr_r <= { 1'b0, read_addr_start };
					read_addr_diff <= addr_diff_start;
					cur_hash_cmp_over <= addr_diff_start == 0;
					cmp_instance <= cmp_instance + 1'b1;
					cmp_state <= CMP_STATE_READ;
				end
			end	

			else begin // next comparison stage
				ram_read_addr_r <= ram_read_addr;
				read_addr_diff <= read_addr_diff >> 1;
				cur_hash_cmp_over <= read_addr_diff[0];
				cmp_state <= CMP_STATE_READ;
			end
		end

		CMP_STATE_CHECK:
			if (output_state == OUTPUT_STATE_NONE & dout_ready_r) begin
				dout <= { cmp_batch_num, cmp_pkt_num, 1'b1 };
				output_state <= OUTPUT_STATE_SEND1;
			end
		endcase

		case (output_state)
		OUTPUT_STATE_NONE: begin
		end

		OUTPUT_STATE_SEND1: begin
			dout <= { current_key_valid, equal_r, batch_complete_r };
			if (equal_r)
				output_state <= OUTPUT_STATE_SEND2;

			else begin // only batch_complete was sent
				result_bank_rd <= ~result_bank_rd;
				cmp_ready <= 1;
				cmp_state <= CMP_STATE_IDLE;
				output_state <= OUTPUT_STATE_NONE;
			end
		end
		
		OUTPUT_STATE_SEND2: begin
			dout <= cmp_instance;
			output_state <= OUTPUT_STATE_SEND3;
		end
		
		OUTPUT_STATE_SEND3: begin
			dout <= ram_read_addr_r[3:0];
			output_state <= OUTPUT_STATE_SEND4;
		end

		OUTPUT_STATE_SEND4: begin
			dout <= ram_read_addr_r[7:4];
			output_state <= OUTPUT_STATE_SEND5;
		end

		OUTPUT_STATE_SEND5: begin
			dout <= { {11-`RAM_ADDR_MSB{1'b0}}, ram_read_addr_r[`RAM_ADDR_MSB:8] };
			output_state <= OUTPUT_STATE_COMPLETE;
		end
		
		OUTPUT_STATE_COMPLETE: begin
			dout <= 0;
			ram_read_addr_r <= { 1'b0, read_addr_start };
			read_addr_diff <= addr_diff_start;
			cur_hash_cmp_over <= addr_diff_start == 0;
			cmp_instance <= cmp_instance + 1'b1;

			if (batch_complete_r) begin
				result_bank_rd <= ~result_bank_rd;
				cmp_ready <= 1;
				cmp_state <= CMP_STATE_IDLE;
			end
			else begin
				cmp_state <= CMP_STATE_START;
			end
			output_state <= OUTPUT_STATE_NONE;
		end
		endcase
	end

endmodule

`else

module descrypt_core #(
	parameter READY_DELAY = 5, // =5: 1 extra reg. in wrapper
	parameter NUM_KEYS = 16
	)(
	input CORE_CLK,
	input [`DIN_MSB:0] din,
	// addr_in:
	// ***1 - write hash into RAM
	// ***010 - write salt, read_addr_start, addr_diff_start
	// ***100 - write 56-bit key
	// ***110 - start computation, write batch_num & pkt_num
	input [2:0] addr_in,
	input wr_en,
	input [`GLOBAL_SALT_MSB:`GLOBAL_SALT_LSB] global_salt,
	
	output crypt_ready, // asserted when it's ready for new data
	output core_idle,
	output reg core_error = 0,
	
	input CMP_CLK,
	input dout_ready,
	output reg [3:0] dout = 0,
	output reg cmp_error = 0
	);

endmodule

`endif

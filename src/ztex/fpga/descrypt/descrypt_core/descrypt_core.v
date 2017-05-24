`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "descrypt.vh"

// Features:
// * Input register
// * CiDi circles over pipeline
//
module descrypt_core #(
	parameter INPUT_R = 1,
	parameter NUM_CRYPT_INSTANCES = 16
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
	
	wire write_key_r = wr_en_r & addr_r[2:0] == 3'b100;

	wire [`HASH_MSB:0] hash_out;

	reg enable_crypt_r = 0;
	always @(posedge CORE_CLK)
		enable_crypt_r <= wr_en & addr_in[2:0] == 3'b100 | ~crypt_ready_r;

	// Only round0 affected by ENABLE
	wire ENABLE_CRYPT = enable_crypt_r;

	//(* KEEP_HIERARCHY="true" *)
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
	assign crypt_ready = crypt_ready_r & ~cmp_wait;
	assign core_idle = crypt_ready_r & cmp_ready_sync;

	// Writer writes a batch of 16 keys in sequence
	always @(posedge CORE_CLK) begin
		if (write_key_r & crypt_ready_r) begin
			if (~crypt_ready)
				core_error <= 1;
			crypt_ready_r <= 0;
			loop_counter <= 0; //?
			crypt_counter <= 0;
			crypt_cnt24 <= 0;
			loop14_crypt24 <= 0;
		end
		else if (~crypt_ready_r) begin
			loop_counter <= loop_counter + 1'b1;
			loop14_crypt24 <= loop_counter == 13 & crypt_cnt24;
			
			if (loop_counter == 15) begin
				if (crypt_cnt24)
					crypt_ready_r <= 1; // assuming no extra register stages between arbiter and core
				else begin
					crypt_counter <= crypt_counter + 1'b1;
					crypt_cnt24 <= crypt_counter == `CRYPT_COUNT - 2;
				end
			end
		end
	end


	// Issue. Pipeline rounds except for round0 don't have clock enable.
	// Destination memory bank must be empty at the start of the crypt.
	//
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [1+`HASH_MSB:0] result [2 * NUM_CRYPT_INSTANCES - 1 :0]; 
	reg [3:0] result_cnt = 0;
	reg result_bank_wr = 0, result_bank_rd = 0;
	reg write_result = 0; // results are being written from the end of the pipeline into memory

	// extra register stage at the end of the pipeline before write to DRAM.
	// not required at 216 MHz.
	
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
	/*
	always @(posedge CORE_CLK)
		if (write_result)
			result [ {result_bank_wr, result_cnt} ] <= { valid_out, hash_out[`HASH_MSB:0] };
	*/
	always @(posedge CORE_CLK)
		if (write_result) begin
			result_cnt <= result_cnt + 1'b1;
			if (result_cnt == 15) begin
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


	// *********************************************************
	//
	// Comparator
	//
	// *********************************************************

	reg cmp_ready = 1; // asserted when it's ready for comparsion

	sync_sig sync_cmp_ready(.sig(cmp_ready), .clk(CORE_CLK), .out(cmp_ready_sync));

	// Assuming CMP_CLK frequency is less than CORE_CLK
	sync_short_sig sync_cmp_start(.sig(cmp_start), .clk(CMP_CLK), .out(cmp_start_sync));
	
	// Comparator configuration.
	localparam [`RAM_ADDR_MSB-1:0] READ_ADDR_INIT = {`RAM_ADDR_MSB{1'b1}};
	reg [`RAM_ADDR_MSB-1:0] read_addr_start = READ_ADDR_INIT;
	localparam [`RAM_ADDR_MSB-1:0] ADDR_DIFF_INIT = { 1'b1, {`RAM_ADDR_MSB-1{1'b0}} };
	reg [`RAM_ADDR_MSB-1:0] addr_diff_start = ADDR_DIFF_INIT;

	
	reg [`MSB(NUM_CRYPT_INSTANCES-1):0] cmp_instance = 0;
	reg [`HASH_MSB:0] cmp_hash;
	reg current_key_valid = 0;

	wire [`RAM_ADDR_MSB:0] ram_read_addr;
	reg [`RAM_ADDR_MSB:0] ram_read_addr_r;
	reg [`RAM_ADDR_MSB-1:0] read_addr_diff;
	
	
	// MSB in RAM indicates hash is valid
	// upper table row is unused (hash_valid always 0)
	(* RAM_STYLE = "BLOCK" *)
	reg [1+`HASH_MSB:0] ram [2**(`RAM_ADDR_MSB+1)-1:0];
	initial
		for (k=0; k < 2**(`RAM_ADDR_MSB+1); k=k+1)
			ram[k] = {1+`HASH_MSB+1{1'b0}};
			
	
	reg [`HASH_MSB:0] ram_out = 0, ram_out_r = 0;
	reg hash_valid = 0, hash_valid_r = 0;
	reg ram_rd_en = 0;
	
	always @(posedge CORE_CLK)
		if (wr_en_r & addr_r[0])
			ram[ din_r[`RAM_ADDR_MSB+2+`HASH_MSB : 2+`HASH_MSB] ] <= din_r[1+`HASH_MSB:0];

	always @(posedge CMP_CLK)
		if (ram_rd_en)
			{hash_valid, ram_out} <= ram[ram_read_addr];

	wire EQUAL = current_key_valid & hash_valid_r & cmp_hash == ram_out_r;
	
	wire BATCH_COMPLETE = cmp_instance == NUM_CRYPT_INSTANCES - 1;
	
	// Bsearch-type comparator. Expecting hashes in RAM are in ascending order.
	// On the 1st read from memory on a new search, 'ram_read_start' is asserted.
	wire ram_read_start =
		cmp_state == CMP_STATE_START || EQUAL || !read_addr_diff || ~current_key_valid;
	
	assign ram_read_addr =
		ram_read_start ? { 1'b0, read_addr_start } :
		!hash_valid_r || cmp_hash < ram_out_r ? ram_read_addr_r - read_addr_diff :
		ram_read_addr_r + read_addr_diff;
	
	reg dout_ready_r = 0;
	always @(posedge CMP_CLK)
		dout_ready_r <= dout_ready;
	
	
	localparam	CMP_STATE_IDLE = 0,
					CMP_STATE_START = 1,
					CMP_STATE_READ = 2,
					CMP_STATE_COMPARE = 3;
					
	(* FSM_EXTRACT="true", FSM_ENCODING="one-hot" *)
	reg [1:0] cmp_state = CMP_STATE_IDLE;

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
			ram_read_addr_r <= { 1'b0, read_addr_start };
			read_addr_diff <= addr_diff_start;
			dout <= 0;

			if (cmp_start_sync) begin
				if (!cmp_ready)
					cmp_error <= 1;
				cmp_ready <= 0;

				ram_rd_en <= 1;
				cmp_state <= CMP_STATE_START;
			end
		end

		CMP_STATE_START: begin // 1st read from ram
			ram_rd_en <= 0;	
			cmp_state <= CMP_STATE_READ;
		end

		CMP_STATE_READ: begin // hash_valid, ram_out signals valid
			hash_valid_r <= hash_valid;
			ram_out_r <= ram_out;		
			{current_key_valid, cmp_hash} <= result [ {result_bank_rd, cmp_instance} ];
			
			ram_rd_en <= 1;
			cmp_state <= CMP_STATE_COMPARE;
		end
		
		CMP_STATE_COMPARE: begin
			ram_rd_en <= 0;
			
			if (EQUAL || !read_addr_diff || ~current_key_valid) begin // search for current hash ends
				
				// Output equality or(and) batch_complete
				if (EQUAL || BATCH_COMPLETE) begin
					if (output_state == OUTPUT_STATE_NONE & dout_ready_r) begin
						dout <= { batch_num[result_bank_rd], pkt_num[result_bank_rd], 1'b1 };
						output_state <= OUTPUT_STATE_SEND1;
					end
					// if ~dout_ready_r: wait here
				end
				else begin // comparsion of next hash
					ram_read_addr_r <= { 1'b0, read_addr_start };
					read_addr_diff <= addr_diff_start;
					cmp_instance <= cmp_instance + 1'b1;
					cmp_state <= CMP_STATE_READ;
				end
			end	

			else begin // next comparison stage
				ram_read_addr_r <= ram_read_addr;
				read_addr_diff <= read_addr_diff >> 1;
				cmp_state <= CMP_STATE_READ;
			end
		end
		endcase

		case (output_state)
		OUTPUT_STATE_NONE: begin
		end

		OUTPUT_STATE_SEND1: begin
			dout <= { current_key_valid, EQUAL, BATCH_COMPLETE };
			if (EQUAL)
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
			if (BATCH_COMPLETE) begin
				result_bank_rd <= ~result_bank_rd;
				cmp_ready <= 1;
				cmp_state <= CMP_STATE_IDLE;
			end
			else begin
				ram_read_addr_r <= { 1'b0, read_addr_start };
				read_addr_diff <= addr_diff_start;
				cmp_instance <= cmp_instance + 1'b1;
				cmp_state <= CMP_STATE_READ;
			end
			output_state <= OUTPUT_STATE_NONE;
		end
		endcase
	end

endmodule



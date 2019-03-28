`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "descrypt_core/descrypt.vh"

// ************************************************************
//
// Comparator configuration data is as follows:
//
// - salt (2 bytes) //salt (4 bytes) (*)
// - //iteration count (4 bytes) (*)
// - num_hashes (2 bytes)
// - hashes (N bytes each)
// - magic byte (0xCC)
//
// (*) - used only 12-bit salt. Iteration count hardcoded into cores (25)
//
// ************************************************************

module cmp_config #(
	parameter BYTE_COUNT_INT = ((`HASH_MSB + 1) / 8),
	parameter BYTE_COUNT_MAX = BYTE_COUNT_INT + |(`HASH_MSB + 1 - BYTE_COUNT_INT * 8)
	)(
	input wr_clk,
	input [7:0] din,
	input wr_en,
	output full,
	output reg idle = 1,

	// Assumes frequency of rd_clk is greater than or equal to wr_clk
	input rd_clk,
	output reg [`SALT_MSB:0] salt_out,
	output reg [`RAM_ADDR_MSB-1:0] read_addr_start = {`RAM_ADDR_MSB{1'b1}},
	output reg [`RAM_ADDR_MSB-1:0] addr_diff_start = { 1'b1, {`RAM_ADDR_MSB-1{1'b0}} },
	output hash_valid, hash_end,
	output [`HASH_MSB:0] hash_out,
	output [`RAM_ADDR_MSB:0] hash_addr_out,
	input rd_en,
	output empty,
	output new_cmp_config,	// asserts when incoming comparator config is going
	input config_applied,	// configuration is taken into processing,
									// let pkt_comm handle next packet
	output error
	);

	assign full = full_r | state == STATE_ERROR | state == STATE_EMPTY_HASHES;

	reg full_r = 0;
	reg [`HASH_MSB:0] hash_r;
	reg hash_valid_r, hash_end_r;
	reg new_cmp_config_r = 0;
	reg [`RAM_ADDR_MSB:0] num_hashes = 0, prev_num_hashes = 0, hash_addr_r = 0, hash_count = 0;
	reg [`MSB(BYTE_COUNT_MAX-1):0] byte_count = 0;
	
	sync_short_sig sync_config_applied(.sig(config_applied), .clk(wr_clk), .out(config_applied_sync));
	reg config_applied_r = 0;
	
	reg cmp_configured = 0;

	localparam	STATE_SALT0 = 0,
					STATE_SALT1 = 1,
					STATE_NUM_HASHES0 = 2,
					STATE_NUM_HASHES1 = 3,
					STATE_HASH = 4,
					STATE_EMPTY_HASHES = 5,
					STATE_MAGIC = 6,
					STATE_ERROR = 7;

	(* FSM_EXTRACT="true", FSM_ENCODING="one-hot" *)
	reg [2:0] state = STATE_SALT0;
	
	always @(posedge wr_clk) begin
		if (config_applied_sync) begin
			config_applied_r <= 1;
			new_cmp_config_r <= 0;
		end
			
		if (state == STATE_ERROR) begin
		end
		
		// Comparator's hash table has 2**(`RAM_ADDR_MSB+1)-1 rows (uppermost row is unused).
		// Hashes must be sorted in ascending order.
		// MSB of each row in table is hash_valid bit. 
		// It requires to fill all empty rows with hash_valid=0.
		//
		// On startup all rows are 0. After reset, 1st configuration fills all rows.
		// If a new configuration has less rows than previous one, remaining rows filled with 0.
		//
		else if (~full_r & state == STATE_EMPTY_HASHES) begin
			// write at least 1 hash with hash_valid=0
			// to satisfy a requirement to produce an output with hash_end_r=1.
			if (~hash_end_r) begin
				hash_valid_r <= 0;
				full_r <= 1;
				hash_addr_r <= hash_count;
				hash_count <= hash_count + 1'b1;
			end
			if (cmp_configured & hash_count >= prev_num_hashes
					|| ~cmp_configured & &hash_count) begin
				hash_end_r <= 1;
				// if config_applied is not set - wait here
				if (config_applied_r) begin
					config_applied_r <= 0;
					state <= STATE_MAGIC;
				end
			end
		end

		else if (~full_r & wr_en) begin
			case(state)
			STATE_SALT0: begin
				salt_out[7:0] <= din;
				prev_num_hashes <= num_hashes;
				hash_count <= 0;
				state <= STATE_SALT1;
			end
			
			STATE_SALT1: begin
				salt_out[`SALT_MSB:8] <= din[`SALT_MSB-8:0];
				if (din[7:`SALT_MSB-7])
					// salt must be (`SALT_MSB+1) bits.
					state <= STATE_ERROR;
				else
					state <= STATE_NUM_HASHES0;
			end

			STATE_NUM_HASHES0: begin
				num_hashes[7:0] <= din;
				state <= STATE_NUM_HASHES1;
			end
			
			STATE_NUM_HASHES1: begin
				new_cmp_config_r <= 1;
				read_addr_start <= read_addr_start_out;
				addr_diff_start <= addr_diff_start_out;
				
				num_hashes[`RAM_ADDR_MSB:8] <= din[`RAM_ADDR_MSB-8:0];
				if (din[7:`RAM_ADDR_MSB-7] || !din[`RAM_ADDR_MSB-8:0] & !num_hashes[7:0])
					// num_hashes exceeds maximum value or zero num_hashes
					state <= STATE_ERROR;
				else
					state <= STATE_HASH;
			end
			
			STATE_HASH: begin
				hash_r[(byte_count + 1)*8-1 -:8] <= din;
				hash_valid_r <= 1;
				hash_end_r <= 0;
				if (byte_count == BYTE_COUNT_MAX - 1) begin
					byte_count <= 0;
					full_r <= 1;
					hash_addr_r <= hash_count;
					hash_count <= hash_count + 1'b1;
					if (hash_count + 1'b1 == num_hashes) begin
						idle <= 0;
						state <= STATE_EMPTY_HASHES;
					end
				end
				else
					byte_count <= byte_count + 1'b1;
			end

			// It doesn't read last byte ("magic") of comparator configuration
			// until configuration is applied. That blocks pkt_comm from
			// reading further packets.
			//
			// Well, the application might need some common mechanism for
			// arranging input packet flow.
			STATE_MAGIC: begin
				idle <= 1;
				if (din != 8'hCC)
					state <= STATE_ERROR;
				else begin
					state <= STATE_SALT0;
					cmp_configured <= 1;
				end
			end
			endcase
		end // ~full_r & wr_en
		
		else if (output_reg_wr_en)
			full_r <= 0;
	end

	wire [`RAM_ADDR_MSB-1:0] read_addr_start_out, addr_diff_start_out;
	
	// STATE_NUM_HASHES1
	get_read_addr_start get_read_addr_start(
		.in({ din[`RAM_ADDR_MSB-8:0], num_hashes[7:0] }),
		.read_addr_start(read_addr_start_out),
		.addr_diff_start(addr_diff_start_out)
	);
	
	sync_sig sync_new_cmp_config(.sig(new_cmp_config_r), .clk(rd_clk), .out(new_cmp_config));
	
	assign error = state == STATE_ERROR;

	assign output_reg_wr_en = ~output_reg_full & full_r;

	cdc_reg #(.WIDTH(2 + `HASH_MSB+1 + `RAM_ADDR_MSB+1)) output_reg (
		.wr_clk(wr_clk),
		.din({ hash_end_r, hash_valid_r, hash_r, hash_addr_r }),
		.wr_en(output_reg_wr_en), .full(output_reg_full),
		
		.rd_clk(rd_clk),
		.dout({ hash_end, hash_valid, hash_out, hash_addr_out }),
		.rd_en(rd_en), .empty(empty)
	);
	
endmodule


module get_read_addr_start #(
	parameter MSB = `RAM_ADDR_MSB
	)(
	input [MSB:0] in, // total number of hashes (>0)
	output [MSB-1:0] read_addr_start,
	output [MSB-1:0] addr_diff_start
	);
	
	wire [MSB-1:0] in_shr = in[MSB:1];
	
	genvar i;
	generate
	for (i=0; i < MSB; i=i+1)
	begin: gen_read_addr

		assign read_addr_start[i] = (i == MSB-1) ? in_shr[i]
				// remove out-of-bound warning when i+1==MSB
				: in_shr[i] | read_addr_start[(i == MSB-1) ? 0 : i+1];

	end
	endgenerate

	wire [MSB-2:0] read_addr_shr = read_addr_start[MSB-1:1];

	assign addr_diff_start = read_addr_start ^ { 1'b0, read_addr_shr };

endmodule

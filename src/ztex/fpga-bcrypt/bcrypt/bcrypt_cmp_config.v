`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "bcrypt.vh"

//
// CMP_CONFIG packet for bcrypt:
//
// * 17 bytes salt: 16 bytes + 1 byte subtype (ASCII 'a','b','x' or 'y')
// * 4 bytes: "tunable cost" (iteration count)
// * 2 bytes: hash count for comparator (up to `NUM_HASHES)
// * 4*(hash count) bytes: comparator data (bits 0-30 of hash).
//	Bit 31 indicates hash is valid, it's set by bcrypt_cmp_config.
// * ends with 0xCC
//
// BUG! Only 3 hashes per salt actually supported
//
module bcrypt_cmp_config(
	input CLK,

	input [7:0] din,
	input wr_en,
	output reg full = 0,
	output error,

	// When asserted, it accepts packets without comparator data.
	input no_cmp_data,

	// Iteraction with other subsystems.
	output reg new_cmp_config = 0, // asserted when new cmp_config incoming
	// do not finish processing, block processing next packets by pkt_comm
	// until cmp_config_applied asserted
	input cmp_config_applied,

	// Output
	input [3:0] addr,
	output [31:0] dout,
	output reg sign_extension_bug = 0
	);

	integer k;

	reg [31:0] tmp = 0;
	reg sign_extension_bug_tmp;

	// Data for output is stored in 16 x32-bit distributed RAM.
	// 0 - iter_count(1)
	// 1-4 - salt(4)
	// 5-9 - cmp_data(5)
	//
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [31:0] data [15:0];
	initial
		for (k=6; k <= 10; k=k+1)
			data[k] = 0;

	assign dout = data [addr];
	reg [3:0] wr_addr = 1;

	reg [1:0] byte_count = 0;
	reg [1:0] salt_word_count = 0;
	reg [`HASH_NUM_MSB:0] hash_count = 0, hash_num = 0;

	localparam STATE_SALT = 0,
					STATE_SALT_SUBTYPE = 1,
					STATE_ITER_COUNT = 2,
					STATE_HASH_COUNT0 = 3,
					STATE_HASH_COUNT1 = 4,
					STATE_CMP_DATA = 5,
					STATE_SAVE_CMP_DATA = 6,
					STATE_EMPTY_CMP_DATA_SET = 7,
					STATE_EMPTY_CMP_DATA_SAVE = 8,
					STATE_WAIT_CMP_CONFIG_APPLIED = 9,
					STATE_MAGIC = 10,
					STATE_ERROR = 11;

	(* FSM_EXTRACT="true" *)
	reg [3:0] state = STATE_SALT;

	always @(posedge CLK) begin
		if (state == STATE_ERROR) begin
		end

		else if (state == STATE_WAIT_CMP_CONFIG_APPLIED) begin
			if (cmp_config_applied) begin
				new_cmp_config <= 0;
				sign_extension_bug <= sign_extension_bug_tmp;
				full <= 0;
				state <= STATE_MAGIC;
			end
		end

		else if (state == STATE_SAVE_CMP_DATA) begin
			wr_addr <= wr_addr + 1'b1;
			hash_num <= hash_num + 1'b1;
			if (hash_num + 1'b1 == hash_count) begin
				if (hash_count == `NUM_HASHES) begin
					new_cmp_config <= 1;
					state <= STATE_WAIT_CMP_CONFIG_APPLIED;
				end
				else
					state <= STATE_EMPTY_CMP_DATA_SET;
			end
			else begin
				full <= 0;
				state <= STATE_CMP_DATA;
			end
		end

		else if (state == STATE_EMPTY_CMP_DATA_SET) begin
			tmp <= 0;
			state <= STATE_EMPTY_CMP_DATA_SAVE;
		end

		else if (state == STATE_EMPTY_CMP_DATA_SAVE) begin
			wr_addr <= wr_addr + 1'b1;
			hash_num <= hash_num + 1'b1;
			if (hash_num + 1'b1 == `NUM_HASHES) begin
				new_cmp_config <= 1;
				state <= STATE_WAIT_CMP_CONFIG_APPLIED;
			end
			else
				state <= STATE_EMPTY_CMP_DATA_SET;
		end

		else if (wr_en) begin
		case (state)
		STATE_SALT: begin
			if (byte_count == 3) begin
				if (salt_word_count == 3)
					state <= STATE_SALT_SUBTYPE;
				salt_word_count <= salt_word_count + 1'b1;
			end
			tmp[8*(byte_count+1)-1 -:8] <= din;
			byte_count <= byte_count + 1'b1;
			if (byte_count == 0 && salt_word_count > 0) begin
				wr_addr <= wr_addr + 1'b1;
			end
		end

		STATE_SALT_SUBTYPE: begin
			if (din == "x") begin
				sign_extension_bug_tmp <= 1;
				state <= STATE_ITER_COUNT;
			end
			else if (din == "a" || din == "b" || din == "y") begin
				sign_extension_bug_tmp <= 0;
				state <= STATE_ITER_COUNT;
			end
			else
				state <= STATE_ERROR;
		end

		STATE_ITER_COUNT: begin
			if (byte_count == 3)
				state <= STATE_HASH_COUNT0;
			tmp[8*(byte_count+1)-1 -:8] <= din;
			byte_count <= byte_count + 1'b1;
			wr_addr <= 0;
		end

		STATE_HASH_COUNT0: begin
			hash_count <= din[`HASH_NUM_MSB:0];
			if (|tmp[31:`SETTING_MAX+1] || din > `NUM_HASHES)
				state <= STATE_ERROR;
			else
				state <= STATE_HASH_COUNT1;
		end

		STATE_HASH_COUNT1: begin
			if (din != 0 || no_cmp_data && hash_count != 0
					|| ~no_cmp_data && hash_count == 0)
				state <= STATE_ERROR;
			else if (no_cmp_data && hash_count == 0) begin
				full <= 1;
				new_cmp_config <= 1;
				state <= STATE_WAIT_CMP_CONFIG_APPLIED;
			end
			else begin
				wr_addr <= 5;
				hash_num <= 0;
				state <= STATE_CMP_DATA;
			end
		end

		STATE_CMP_DATA: begin
			if (byte_count == 3) begin
				tmp[31] <= 1;
				tmp[30:24] <= din[6:0];
				full <= 1;
				state <= STATE_SAVE_CMP_DATA;
			end
			else
				tmp[8*(byte_count+1)-1 -:8] <= din;
			byte_count <= byte_count + 1'b1;
		end

		STATE_MAGIC: begin
			wr_addr <= 1;
			if (din == 8'hCC)
				state <= STATE_SALT;
			else
				state <= STATE_ERROR;
		end

		endcase
		end
	end

	assign error = state == STATE_ERROR;

	always @(posedge CLK)
		if (state == STATE_SALT & (byte_count == 0 && salt_word_count > 0)
				| state == STATE_SALT_SUBTYPE // saves last 32-bit of salt
				| state == STATE_HASH_COUNT0 // saves iter_count
				| state == STATE_SAVE_CMP_DATA | state == STATE_EMPTY_CMP_DATA_SAVE)
			data[wr_addr] <= tmp;

endmodule

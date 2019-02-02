`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018-2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module xcrypt_cmp_config(
	//
	// unified xcrypt_cmp_config for various *crypt functions.
	//
	// CMP_CONFIG packet:
	//
	// * 18 bytes salt: 1 byte unused, 1 salt_len, 16 bytes salt itself
	//   (if actual salt_len is less than 16 then it's padded)
	// * 4 bytes: "tunable cost 0" (iteration count)
	// * 2 bytes: hash count for comparator (up to `NUM_HASHES)
	// * 4*(hash count) bytes: comparator data (bits 0-31 of hash).
	// * ends with 0xCC
	//
	input CLK,
	// When asserted, it accepts packets without comparator data.
	input mode_cmp,

	input [7:0] din,
	input wr_en,
	output reg full = 0,
	output err,

	// Iteraction with other subsystems.
	output reg new_cmp_config = 0, // asserted on a new cmp_config packet.

	// do not finish processing, block processing next packets by pkt_comm
	// until cmp_config_applied asserts (requires mode_cmp=1).
	input cmp_config_applied,

	// Output into comparator
	output reg [`HASH_COUNT_MSB:0] hash_count,
	output reg [`HASH_NUM_MSB+2:0] cmp_wr_addr = {`HASH_NUM_MSB+3{1'b1}},
	output reg cmp_wr_en = 0,
	output reg [7:0] cmp_din,

	// Output
	input [4:0] addr,
	output [7:0] dout
	);

	integer k;

	//
	// CMP_CONFIG data, except for hashes, is stored in distributed RAM.
	// DRAM is accessible asynchronously with addr,dout
	// Content:
	// 0..3 - iter_cnt
	// 4..7 - salt_len
	// 8..23 - salt
	//
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [7:0] data [0:31];
	initial
		for (k=0; k <= 31; k=k+1)
			data[k] = 0;

	assign dout = data [addr];
	wire [4:0] data_wr_addr;

	always @(posedge CLK)
		if (data_wr_en)
			data [data_wr_addr] <= din;


	reg [4:0] salt_addr = 8;
	reg [1:0] iter_cnt = 0;
	reg [`HASH_NUM_MSB+2:0] cmp_wr_addr_max;
	wire [`HASH_NUM_MSB+3:0] cmp_wr_addr_max_eqn
		= { din[`HASH_COUNT_MSB-8:0], hash_count[7:0], 2'b00 } - 2'b10;


	localparam STATE_NONE = 0,
					STATE_SALT_LEN = 1,
					STATE_SALT = 2,
					STATE_ITER_COUNT = 3,
					STATE_HASH_COUNT0 = 4,
					STATE_HASH_COUNT1 = 5,
					STATE_CMP_DATA = 6,
					STATE_WAIT_CMP_CONFIG_APPLIED = 7,
					STATE_MAGIC = 8,
					STATE_ERROR = 9,
					STATE_WAIT1 = 10;

	(* FSM_EXTRACT="true" *)//, FSM_ENCODING="one-hot" *)
	reg [3:0] state = STATE_NONE;

	always @(posedge CLK) begin
		if (state == STATE_WAIT_CMP_CONFIG_APPLIED) begin
			if (cmp_config_applied) begin
				new_cmp_config <= 0;
				full <= 0;
				state <= STATE_SALT_LEN;
			end
		end

		else if (~wr_en)
			cmp_wr_en <= 0;

		else if (wr_en)
		case (state)
		STATE_NONE:
			if (din != 0)
				state <= STATE_ERROR;
			else begin
				new_cmp_config <= 1;
				full <= 1;
				state <= STATE_WAIT_CMP_CONFIG_APPLIED;
			end

		STATE_SALT_LEN: begin
			if (din > 16 | din == 0)
				state <= STATE_ERROR;
			else
				state <= STATE_SALT;
			salt_addr <= 8;
		end

		STATE_SALT: begin
			salt_addr <= salt_addr + 1'b1;
			if (salt_addr == 23)
				state <= STATE_ITER_COUNT;
		end

		STATE_ITER_COUNT: begin
			// TODO: raise error on rounds=0
			iter_cnt <= iter_cnt + 1'b1;
			if (iter_cnt == 3)
				state <= STATE_HASH_COUNT0;
		end

		STATE_HASH_COUNT0: begin
			hash_count[7:0] <= din;
			if (~mode_cmp & din != 0)
				state <= STATE_ERROR;
			else
				state <= STATE_HASH_COUNT1;
		end

		STATE_HASH_COUNT1: begin
			hash_count[`HASH_COUNT_MSB:8] <= din[`HASH_COUNT_MSB-8:0];
			cmp_wr_addr <= {`HASH_NUM_MSB+3{1'b1}};
			cmp_wr_addr_max <= cmp_wr_addr_max_eqn[`HASH_NUM_MSB+2:0];

			if (mode_cmp) begin
				state <= STATE_CMP_DATA;
			end
			else begin
				if (din != 0)
					state <= STATE_ERROR;
				else
					state <= STATE_MAGIC;
			end
		end

		STATE_CMP_DATA: begin
			cmp_wr_en <= 1;
			cmp_din <= din;
			cmp_wr_addr <= cmp_wr_addr + 1'b1;
			//if (cmp_wr_addr + 2'b10 == { hash_count, 2'b00 } )
			if (cmp_wr_addr == cmp_wr_addr_max)
				state <= STATE_MAGIC;
		end

		STATE_MAGIC: begin
			cmp_wr_en <= 0;
			if (din == 8'hCC)
				state <= STATE_NONE;
			else
				state <= STATE_ERROR;
		end

		STATE_ERROR:
			full <= 1;
		endcase
	end

	assign err = state == STATE_ERROR;

	assign data_wr_en = wr_en & (state == STATE_SALT_LEN
		| state == STATE_SALT | state == STATE_ITER_COUNT);

	assign data_wr_addr =
		state == STATE_SALT_LEN ? 5'd4 :
		state == STATE_SALT ? salt_addr :
		iter_cnt;

endmodule

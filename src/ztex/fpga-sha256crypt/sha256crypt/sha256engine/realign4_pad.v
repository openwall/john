`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../sha256.vh"

//
// Task:
//
// - With the help from an upper level wrapper, send a number
// of bytes from 32-bit memory in 32-bit words. Starting address
// may not be aligned to 4 bytes.
// - Add padding and total length when required
// - Allow input ~1 word/cycle
//
// Limitations:
// - only the 1st word in the block may be unaligned.
// (typically becuse of resumed process_bytes).
// - it doesn't handle correctly len=0 (just don't send)
//

module realign4_pad (
	input CLK,

	input wr_en,
	input [2:0] len, // 1..4
	input [1:0] off, // can be used only on the 1st word
	input [31:0] din,

	// Following controls don't require wr_en
	input add0x80pad, // ignore 'in'; set in0 to 0x80; used with add0pad
	input add0pad,  // add 8x 0x0
	input add_total,
	input [`PROCB_TOTAL_MSB:0] in_total,

	output valid_eqn,
	output reg valid = 0, // r1_len == 4
	output reg wr_en_r = 0,
	output [31:0] out, // always transmit

	output reg err = 0
	);

	genvar i;

	wire [31:0] total =
		`SWAP({ {28-`PROCB_TOTAL_MSB{1'b0}}, in_total, 3'b0 });

	// 'in' register.
	//reg wr_en_r = 0;
	reg [7:0] in0 = 8'h80, in1 = 0, in2 = 0, in3 = 0;

	always @(posedge CLK) begin
		wr_en_r <= wr_en | add0pad | add_total;

		if (add0x80pad)
			in0 <= 8'h80;
		else if (add0pad)
			in0 <= 0;
		else if (add_total) // in0
			in0 <= total[7:0];
		else if (wr_en)
			in0 <= din[7:0];

		if (add0pad) begin // in1..3
			in1 <= 0; in2 <= 0; in3 <= 0;
		end
		else if (add_total) begin
			in1 <= total[15:8]; in2 <= total[23:16]; in3 <= total[31:24];
		end
		else if (wr_en) begin
			in1 <= din[15:8]; in2 <= din[23:16]; in3 <= din[31:24];
		end
	end


	reg [2:0] in_len = 0;
	reg [1:0] in_off = 0;
	reg off_eq0 = 1;
	always @(posedge CLK) begin
		in_len <= len;
		in_off <= off;
		off_eq0 <= off == 0;
	end


	// =================================================================
	// 'r1', 'r2' registers
	//
	reg [7:0] r10 = 0, r11 = 0, r12 = 0, r13 = 0;
	reg [7:0] r20, r21, r22;

	assign out = { r13, r12, r11, r10 };

	reg [2:0] r1_len = 0; // 0..4
	//reg r1_len_eq0_or8 = 1;
	reg [1:0] r2_len = 0; // 0..3
	//reg r2_len_eq0 = 1;

	wire [2:0] r1_plus_in_len = r1_len + in_len;
	wire [2:0] r2_plus_in_len = r2_len + in_len;

	always @(posedge CLK) begin
		if (wr_en_r & in_len == 0)
			err <= 1;

		if (r2_len != 0) begin
			if (~wr_en_r) begin
				r2_len <= 0;
				r1_len <= r2_len;
			end
			else if (wr_en_r & ~off_eq0)
				// The previous block was not aligned to 4-byte
				err <= 1;

			// wr_en; r2 written
			else if (wr_en_r & r2_plus_in_len[2]) begin//(r2_len + in_len > 4)) begin
				r2_len <= r2_plus_in_len[1:0];//r2_len + in_len - 4;
				//r2_len_eq0 <= r2_plus_in_len[2:0] == 0;
				r1_len <= 4;
				//r1_len_eq0_or8 <= 1;
			end

			else begin // wr_en; r2 not written
				r2_len <= 0;
				//r2_len_eq0 <= 1;
				r1_len <= r2_plus_in_len;//r2_len + in_len;
				//r1_len_eq0_or8 <= r2_plus_in_len[3];//r2_len + in_len == 8;
			end
		end

		else begin // r2_len == 0
			if (wr_en_r) begin
				if (~off_eq0) begin
					if (in_len[2]) // off > 0, in_len >= 4
						err <= 1;
					r2_len <= in_len[1:0];
					//r2_len_eq0 <= 0;
					// Starting new data block; ensure the previous block
					// was aligned to 32-bit
					//if (~r1_len_eq0_or8)
					if (~(r1_len == 0 | r1_len == 4))
						err <= 1;
					r1_len <= 0;
					//r1_len_eq0_or8 <= 1;
				end
				else if (r1_len == 0 | r1_len == 4) begin
					r1_len <= in_len;
					//r1_len_eq0_or8 <= in_len == 0 | in_len == 8;
				end
				else begin // r2_len=0, r1_len!=0 & r1_len!=8
					r2_len <= r1_plus_in_len[2] ? r1_plus_in_len[1:0] : 2'b0;
					//r2_len_eq0 <= r1_plus_in_len <= 8;

					r1_len <= r1_plus_in_len[2] ? 3'd4 : r1_plus_in_len[1:0];
					//r1_len_eq0_or8 <= r1_plus_in_len[3];
				end
			end
			else if (~wr_en_r & valid) begin
				r1_len <= 0;
				//r1_len_eq0_or8 <= 1;
			end

		end

	end


	assign valid_eqn = r2_len != 0 ? (//~r2_len_eq0 ? (
		~wr_en_r ? 1'b0 :
		//wr_en_r & r2_plus_in_len[2] ? 1'b1 :
		r2_plus_in_len[2]
		) : (
		wr_en_r & ~off_eq0 ? 1'b0 :
		//wr_en_r & r1_len_eq0_or8 ? (in_len == 0 | in_len == 8) :
		wr_en_r & (r1_len == 0 | r1_len == 4) ? in_len[2] :
		wr_en_r ? r1_plus_in_len[2] :
		1'b0
		);

	always @(posedge CLK)
		valid <= valid_eqn;


	wire [1:0] wr_off =
		~off_eq0 ? 3'd4 - in_off :
		(r1_len == 0 | r1_len == 4) ? r2_len :
		r1_len[1:0];


	always @(posedge CLK) begin
		if (r2_len != 0)
			r10 <= r20;
		else if (wr_en_r & (r1_len == 0 | r1_len == 4))
			r10 <= in0;

		if (r2_len > 1)
			r11 <= r21;
		else if (wr_en_r & (r1_len <= 1 | r1_len == 4))
			r11 <= wr_off == 0 ? in1 : in0;

		if (r2_len > 2)
			r12 <= r22;
		else if (wr_en_r & (r1_len <= 2 | r1_len == 4))
			r12 <=
				wr_off == 0 ? in2 :
				wr_off == 1 ? in1 :
				in0;

		if (wr_en_r)
			r13 <=
				wr_off == 0 ? in3 :
				wr_off == 1 ? in2 :
				wr_off == 2 ? in1 :
				in0;
	end


	always @(posedge CLK) if (wr_en_r) begin
		r20 <=
			wr_off == 1 ? in3 :
			wr_off == 2 ? in2 :
			in1;
		r21 <= wr_off == 2 ? in3 : in2;
		r22 <= in3;
	end

endmodule


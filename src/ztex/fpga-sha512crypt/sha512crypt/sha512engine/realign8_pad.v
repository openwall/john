`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../sha512.vh"

//
// Task:
//
// - With the help from an upper level wrapper, send a number
// of bytes from 64-bit memory in 64-bit words. Starting address
// may not be aligned to 8 bytes.
// - Add SHA512 padding and total length when required
// - Allow input 1 word/cycle
//
// Limitations:
// - only the 1st word in the block may be unaligned.
// (typically becuse of resumed process_bytes).
// - it doesn't handle correctly len=0 (just don't send)
//
// Performance: N output words take N + M cycles if the 1st word is
// aligned to 8 bytes; N + M + 1 cycles if the 1st word is not aligned,
// where M is the number of input words with length not divisible by 8.
//
// Synthesis options:
// Optimization: Area (-50 LUTs; still OK for 250 MHz)
// LUT combining: Auto
//
//`ifdef SIMULATION

module realign8_pad (
	input CLK,

	input wr_en,
	input [3:0] len, // 1..8
	input [2:0] off, // can be used only on the 1st word
	input [63:0] din,

	// Following controls don't require wr_en
	input add0x80pad, // ignore 'in'; set in0 to 0x80; used with add0pad
	input add0pad,  // add 8x 0x0
	// "Put the 128-bit file length in *bits* at the end of the buffer"
	input add_total,
	input [`PROCB_TOTAL_MSB:0] total_bytes,

	output valid_eqn,
	output reg valid = 0, // r1_len == 8
	output reg wr_en_r = 0,
	output reg err = 0,
	output [63:0] out // always transmit
	);

	genvar i;
	
	wire [63:0] total
		= `SWAP({ {60-`PROCB_TOTAL_MSB{1'b0}}, total_bytes, 3'b0 });

	// 'in' register.
	//reg wr_en_r = 0;
	reg [7:0] in0 = 8'h80, in1 = 0, in2 = 0, in3 = 0,
			in4 = 0, in5 = 0, in6 = 0, in7 = 0;

	always @(posedge CLK) begin
		wr_en_r <= wr_en | add0pad | add_total;

		if (add0x80pad)
			in0 <= 8'h80;
		else if (add0pad | add_total) // in0
			in0 <= 0;
		else if (wr_en)
			in0 <= din[7:0];

		if (add0pad | add_total) begin // in1..4
			in1 <= 0; in2 <= 0;
			in3 <= 0; in4 <= 0;
		end
		else if (wr_en) begin
			in1 <= din[15:8]; in2 <= din[23:16];
			in3 <= din[31:24]; in4 <= din[39:32];
		end

		if (add0pad) begin // in5..7
			in5 <= 0; in6 <= 0; in7 <= 0;
		end
		else if (add_total) begin
			in5 <= total[47:40];
			in6 <= total[55:48]; in7 <= total[63:56];
		end
		else if (wr_en) begin
			in5 <= din[47:40];
			in6 <= din[55:48]; in7 <= din[63:56];
		end
	end


	reg [3:0] in_len = 0;
	reg [2:0] in_off = 0;
	reg off_eq0 = 1;
	always @(posedge CLK) begin
		in_len <= len;
		in_off <= off;
		off_eq0 <= off == 0;
	end


	// =================================================================
	// 'r1', 'r2' registers
	//
	reg [7:0] r10 = 0, r11 = 0, r12 = 0, r13 = 0,
			r14 = 0, r15 = 0, r16 = 0, r17 = 0;
	reg [7:0] r20, r21, r22, r23, r24, r25, r26;
	assign out = { r17, r16, r15, r14, r13, r12, r11, r10 };


	reg [3:0] r1_len = 0; // 0..8
	reg r1_len_eq0_or8 = 1;
	reg [2:0] r2_len = 0; // 0..7
	reg r2_len_eq0 = 1;

	wire [3:0] r1_plus_in_len = r1_len + in_len;
	wire [3:0] r2_plus_in_len = r2_len + in_len;

	always @(posedge CLK) begin
		if (wr_en_r & in_len == 0)
			err <= 1;
			
		if (~r2_len_eq0) begin//r2_len != 0) begin
			if (~wr_en_r) begin
				r2_len <= 0;
				r2_len_eq0 <= 1;
				r1_len <= r2_len;
				r1_len_eq0_or8 <= 0;
				//valid <= 0;
			end

			else if (wr_en_r & ~off_eq0) begin
				// The previous block was not aligned to 8-byte
				err <= 1;
			end

			// wr_en; r2 written
			else if (wr_en_r & r2_plus_in_len[3]) begin//(r2_len + in_len > 8)) begin
				r2_len <= r2_plus_in_len[2:0];//r2_len + in_len - 8;
				r2_len_eq0 <= r2_plus_in_len[2:0] == 0;
				r1_len <= 8;
				r1_len_eq0_or8 <= 1;
				//valid <= 1;
			end

			else begin // wr_en; r2 not written
				r2_len <= 0;
				r2_len_eq0 <= 1;
				r1_len <= r2_plus_in_len;//r2_len + in_len;
				r1_len_eq0_or8 <= r2_plus_in_len[3];//r2_len + in_len == 8;
				//valid <= r2_plus_in_len[3];//r2_len + in_len == 8;
			end
		end

		else begin // r2_len == 0
			if (wr_en_r) begin
				if (~off_eq0) begin
					if (in_len[3]) // off > 0, in_len == 8
						err <= 1;
					r2_len <= in_len[2:0];
					r2_len_eq0 <= 0;
					// Starting new data block; ensure the previous block
					// was aligned to 64-bit
					if (~r1_len_eq0_or8)
						err <= 1;
					r1_len <= 0;
					r1_len_eq0_or8 <= 1;
					//valid <= 0;
				end
				else if (r1_len_eq0_or8) begin
					r1_len <= in_len;
					r1_len_eq0_or8 <= in_len == 0 | in_len == 8;
					//valid <= in_len == 0 | in_len == 8;
				end
				else begin // r2_len=0, r1_len!=0 & !=8
					// Construct is unsupported by ISIM; no warning in XST
					//r2_len <= r1_len + in_len >= 8 ? {r1_len + in_len - 8}[2:0] : 3'b0;

					//r2_len <= r1_len + in_len >= 8 ? r1_len + in_len - 8 : 3'b0;
					//r1_len <= r1_len + in_len >= 8 ? 4'd8 : r1_len + in_len;
					
					r2_len <= r1_plus_in_len[3] ? r1_plus_in_len[2:0] : 3'b0;
					r2_len_eq0 <= r1_plus_in_len <= 8;

					r1_len <= r1_plus_in_len[3] ? 4'd8 : r1_plus_in_len[2:0];

					r1_len_eq0_or8 <= r1_plus_in_len[3];
					//valid <= r1_plus_in_len[3];
				end
			end
			else if (~wr_en_r & valid) begin
				r1_len <= 0;
				r1_len_eq0_or8 <= 1;
				//valid <= 0;
			end
		end

	end


	assign valid_eqn = ~r2_len_eq0 ? (
		~wr_en_r ? 1'b0 :
		wr_en_r & r2_plus_in_len[3] ? 1'b1 :
		r2_plus_in_len[3]
		) : (
		wr_en_r & ~off_eq0 ? 1'b0 :
		wr_en_r & r1_len_eq0_or8 ? (in_len == 0 | in_len == 8) :
		wr_en_r ? r1_plus_in_len[3] :
		1'b0
		);
		
	always @(posedge CLK)
		valid <= valid_eqn;


	wire [2:0] wr_off =
		~off_eq0 ? 4'd8 - in_off :
		r1_len_eq0_or8 ? r2_len :
		r1_len[2:0];

	always @(posedge CLK) begin
		if (~r2_len_eq0)//r2_len != 0)
			r10 <= r20;
		else if (wr_en_r & r1_len_eq0_or8)
			r10 <= in0;

		if (r2_len > 1)
			r11 <= r21;
		else if (wr_en_r & (r1_len <= 1 | r1_len == 8))
			r11 <= wr_off == 0 ? in1 : in0;

		if (r2_len > 2)
			r12 <= r22;
		else if (wr_en_r & (r1_len <= 2 | r1_len == 8))
			r12 <=
				wr_off == 0 ? in2 :
				wr_off == 1 ? in1 :
				in0;

		if (r2_len > 3)
			r13 <= r23;
		else if (wr_en_r & (r1_len <= 3 | r1_len == 8))
			r13 <=
				wr_off == 0 ? in3 :
				wr_off == 1 ? in2 :
				wr_off == 2 ? in1 :
				in0;

		if (r2_len > 4)
			r14 <= r24;
		else if (wr_en_r & (r1_len <= 4 | r1_len == 8))
			r14 <=
				wr_off == 0 ? in4 :
				wr_off == 1 ? in3 :
				wr_off == 2 ? in2 :
				wr_off == 3 ? in1 :
				in0;

		if (r2_len > 5)
			r15 <= r25;
		else if (wr_en_r & (r1_len <= 5 | r1_len == 8))
			r15 <=
				wr_off == 0 ? in5 :
				wr_off == 1 ? in4 :
				wr_off == 2 ? in3 :
				wr_off == 3 ? in2 :
				wr_off == 4 ? in1 :
				in0;

		if (r2_len > 6)
			r16 <= r26;
		else if (wr_en_r & (r1_len <= 6 | r1_len == 8))
			r16 <=
				wr_off == 0 ? in6 :
				wr_off == 1 ? in5 :
				wr_off == 2 ? in4 :
				wr_off == 3 ? in3 :
				wr_off == 4 ? in2 :
				wr_off == 5 ? in1 :
				in0;

		if (wr_en_r)
			r17 <=
				wr_off == 0 ? in7 :
				wr_off == 1 ? in6 :
				wr_off == 2 ? in5 :
				wr_off == 3 ? in4 :
				wr_off == 4 ? in3 :
				wr_off == 5 ? in2 :
				wr_off == 6 ? in1 :
				in0;
	end


	always @(posedge CLK) begin
		if (wr_en_r) begin
			r20 <=
				wr_off == 1 ? in7 :
				wr_off == 2 ? in6 :
				wr_off == 3 ? in5 :
				wr_off == 4 ? in4 :
				wr_off == 5 ? in3 :
				wr_off == 6 ? in2 :
				in1;
			r21 <=
				wr_off == 2 ? in7 :
				wr_off == 3 ? in6 :
				wr_off == 4 ? in5 :
				wr_off == 5 ? in4 :
				wr_off == 6 ? in3 :
				in2;
			r22 <=
				wr_off == 3 ? in7 :
				wr_off == 4 ? in6 :
				wr_off == 5 ? in5 :
				wr_off == 6 ? in4 :
				in3;
			r23 <=
				wr_off == 4 ? in7 :
				wr_off == 5 ? in6 :
				wr_off == 6 ? in5 :
				in4;
			r24 <=
				wr_off == 5 ? in7 :
				wr_off == 6 ? in6 :
				in5;
			r25 <= wr_off == 6 ? in7 : in6;
			r26 <= in7;
		end
	end


endmodule
/*
`else

module realign8_pad (
	input CLK,

	input wr_en,
	input [3:0] len, // 1..8
	input [2:0] off, // can be used only on the 1st word
	input [63:0] din,

	// Following controls don't require wr_en
	input add0x80pad, // ignore 'in'; set in0 to 0x80; used with add0pad
	input add0pad,  // add 8x 0x0
	// "Put the 128-bit file length in *bits* at the end of the buffer"
	input add_total,
	input [`PROCB_TOTAL_MSB:0] total_bytes,

	output valid_eqn,
	output reg valid = 0, // r1_len == 8
	output reg wr_en_r = 0,
	output reg err = 0,
	output [63:0] out // always transmit
	);

endmodule

`endif
*/

`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// Creates expanded key (EK) out of key.
//
// Read from word_gen_b
//
// Outputs in 32-bit words.
//
module bcrypt_expand_key_b #(
	parameter KEY_LEN = 72
	)(
	input CLK,
	// Read from word_storage
	input [7:0] din,
	output reg [`MSB(KEY_LEN-1):0] rd_addr = 0,
	output word_set_empty,
	input word_empty,

	input sign_extension_bug,

	output reg [31:0] dout = 0,
	input rd_en,
	output empty
	);

	reg [1:0] output_byte_count = 0;
	reg [`MSB(KEY_LEN)-2:0] output_word_count = 0;

	localparam	STATE_IDLE = 0,
					STATE_INPUT = 1,
					STATE_OUTPUT = 2,
					STATE_READ_SRC = 3;

	(* FSM_EXTRACT="true" *)
	reg [1:0] state = STATE_IDLE;

	always @(posedge CLK) begin
		case (state)
		STATE_IDLE: if (~word_empty)
			state <= STATE_INPUT;

		STATE_INPUT: begin
			if (sign_extension_bug)
				dout <= (dout << 8) | { {25{din[7]}}, din[6:0] };
			else
				dout <= { dout[23:0], din };

			if (din == 0)
				rd_addr <= 0;
			else
				rd_addr <= rd_addr + 1'b1;

			if (output_byte_count == 3)
				state <= STATE_OUTPUT;

			output_byte_count <= output_byte_count + 1'b1;
		end

		STATE_OUTPUT: if (rd_en) begin
			output_word_count <= output_word_count + 1'b1;
			if (output_word_count == 17)
				state <= STATE_READ_SRC;
			else
				state <= STATE_INPUT;
		end

		STATE_READ_SRC: begin
			output_word_count <= 0;
			rd_addr <= 0;
			state <= STATE_IDLE;
		end
		endcase
	end

	assign empty = ~(state == STATE_OUTPUT);

	assign word_set_empty = state == STATE_READ_SRC;

endmodule

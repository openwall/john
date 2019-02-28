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

module bcrypt_data(
	input CLK,

	// Input from word_gen
	input [31:0] gen_id,
	input [15:0] word_id, pkt_id,
	input gen_end,

	// Input from expand_key
	input [31:0] ek_in,
	input ek_wr_en,
	output reg ek_full = 1,
	input ek_valid, // valid data on ek_* inputs

	// From cmp_config
	input new_cmp_config,
	output reg cmp_config_applied = 0,
	output reg [3:0] cmp_config_addr = 0,
	input [31:0] cmp_config_data,

	// Output data batch to a core over 10-bit bus
	output reg [7:0] dout,
	output reg [1:0] ctrl = 0,

	// Iteraction with arbiter
	output reg [2:0] error = 0,
	output reg data_ready = 0, init_ready = 1,
	// externalize pkt_id out from data batch for purposes
	// of easy handling by arbiter for accounting
	output reg [15:0] bcdata_pkt_id,
	output reg bcdata_gen_end = 0,
	input start_init_tx, // start transmit
	input start_data_tx,
	// asserted for 1 cycle after transmit is done <-- using ctrl
	output reg data_tx_done = 0, init_tx_done = 0
	);

	integer k;

	reg cmp_configured = 0;

	// Initialization (for PN, S memory):
	//
	// - constant P - offset 0
	// - reserved(6)
	// - constant MW - offset 24
	// - constant S
	// Total words in initialization data: 30 + 1024
	//
	// Data (for PD memory):
	//
	// - EK(18) - offset 32
	// - constant 'd64(1) - off+18
	// - iter_count(1) - off+19 (*)
	// - salt(4) - off+20 (*)
	// - IDs(2) - off+24
	// - cmp_data(5) - off+26 (*)
	// Total words in data for encryption: 31
	// (*) - taken from cmp_config
	//
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [31:0] P [63:0];
	initial begin
		P[0] = 32'h243f6a88; P[1] = 32'h85a308d3; P[2] = 32'h13198a2e; P[3] = 32'h03707344;
		P[4] = 32'ha4093822; P[5] = 32'h299f31d0; P[6] = 32'h082efa98; P[7] = 32'hec4e6c89;
		P[8] = 32'h452821e6; P[9] = 32'h38d01377; P[10] = 32'hbe5466cf; P[11] = 32'h34e90c6c;
		P[12] = 32'hc0ac29b7; P[13] = 32'hc97c50dd; P[14] = 32'h3f84d5b5; P[15] = 32'hb5470917;
		P[16] = 32'h9216d5d9; P[17] = 32'h8979fb1b;

		P[24] = 32'h65616E42; P[25] = 32'h4F727068; // MW[1] <--> MW[0]
		P[26] = 32'h64657253; P[27] = 32'h65686F6C;
		P[28] = 32'h6F756274; P[29] = 32'h63727944;

		P[32+18] = 'd64;
		for (k=0; k < 5; k=k+1)
			P[32+26+k] = 0;
	end


	wire [31:0] P_in;

	reg [5:0] P_count_in; // Input counter.
	reg [5:0] P_count_out = 0; // Output counter.

	reg [1:0] byte_count = 0; // will send over 8-bit bus

	(* RAM_STYLE="BLOCK" *)
	reg [31:0] S [1023:0]; // Constant S
	initial
		$readmemh("bcrypt/S_data.txt", S, 0, 1023);

	reg [9:0] S_count = 0;
	reg [31:0] S_out;
	always @(posedge CLK)
		if (state_out != STATE_OUT_IDLE && byte_count == 3)
			S_out <= S [S_count];

	wire [31:0] dout_tmp = state_out == STATE_OUT_TX_S ? S_out : P [P_count_out];
	always @(posedge CLK)
		if (state_out == STATE_OUT_TX_P
				|| state_out == STATE_OUT_TX_S
				|| state_out == STATE_OUT_TX_DATA)
			dout <=
				byte_count == 0 ? dout_tmp[7:0] :
				byte_count == 1 ? dout_tmp[15:8] :
				byte_count == 2 ? dout_tmp[23:16] :
				dout_tmp[31:24];


	localparam STATE_IN_IDLE = 0,
				STATE_IN_READ_EK0 = 1,
				STATE_IN_READ_ID0 = 2,
				STATE_IN_READ_ID1 = 3,
				STATE_IN_READ_EK1 = 4,
				STATE_IN_ITER_SALT = 5,
				STATE_IN_CMP_DATA = 6,
				STATE_IN_WAIT = 7,
				STATE_IN_ERROR = 8;

	(* FSM_EXTRACT="true" *)
	reg [3:0] state_in = STATE_IN_IDLE;

	localparam STATE_OUT_IDLE = 0,
				STATE_OUT_START_DELAY = 1, // init tx
				STATE_OUT_TX_P = 2,
				STATE_OUT_TX_S = 3,
				STATE_OUT_TX_END = 4,

				STATE_OUT_START_DATA_DELAY = 5,// data tx
				STATE_OUT_TX_DATA = 6,
				STATE_OUT_TX_END_DATA = 7,

				STATE_OUT_ERROR = 8;

	(* FSM_EXTRACT="true" *)
	reg [3:0] state_out = STATE_OUT_IDLE;

	always @(posedge CLK) begin
		case (state_in)
		STATE_IN_IDLE: begin
			if (ek_valid) begin
				P_count_in <= 32;
				ek_full <= 0;
				state_in <= STATE_IN_READ_EK0;
			end
			else if (new_cmp_config) begin
				cmp_config_addr <= 0; // comparator data
				P_count_in <= 32 + 19;
				//error[1] <= 1;
				cmp_config_applied <= 1;
				state_in <= STATE_IN_ITER_SALT;
			end
		end

		STATE_IN_ITER_SALT: begin // 5 words transferred from cmp_config
			cmp_config_applied <= 0;
			cmp_config_addr <= cmp_config_addr + 1'b1;
			if (cmp_config_addr == 4) begin
				P_count_in <= 32 + 26;
				state_in <= STATE_IN_CMP_DATA;
			end
			else
				P_count_in <= P_count_in + 1'b1;
		end

		STATE_IN_CMP_DATA: begin // 5 more words transferred from cmp_config
			cmp_configured <= 1;
			P_count_in <= P_count_in + 1'b1;
			cmp_config_addr <= cmp_config_addr + 1'b1;
			if (cmp_config_addr == 10)
				state_in <= STATE_IN_IDLE;
		end

		// Read 1st word of EK.
		STATE_IN_READ_EK0: if (ek_wr_en) begin
			P_count_in <= 32 + 24;
			ek_full <= 1;
			if (~cmp_configured) begin
				error[0] <= 1;
				state_in <= STATE_IN_ERROR;
			end
			else
				state_in <= STATE_IN_READ_ID0;
		end

		// Started read of EK. That means IDs from word_gen are valid.
		STATE_IN_READ_ID0: begin
			P_count_in <= P_count_in + 1'b1;
			bcdata_pkt_id <= pkt_id;
			bcdata_gen_end <= gen_end;
			state_in <= STATE_IN_READ_ID1;
		end

		STATE_IN_READ_ID1: begin
			P_count_in <= 33;
			ek_full <= 0;
			state_in <= STATE_IN_READ_EK1;
		end

		// Continue reading EK.
		STATE_IN_READ_EK1: if (ek_wr_en) begin
			P_count_in <= P_count_in + 1'b1;
			if (P_count_in == 32 + 17) begin
				data_ready <= 1;
				ek_full <= 1;
				state_in <= STATE_IN_WAIT;
			end
		end

		STATE_IN_WAIT: if (data_tx_done)
			state_in <= STATE_IN_IDLE;

		STATE_IN_ERROR: begin
		end
		endcase


		// Output.
		case (state_out)
		STATE_OUT_IDLE: begin
			byte_count <= 0;
			data_tx_done <= 0;
			init_tx_done <= 0;
			if (start_init_tx) begin
				if (start_data_tx) begin
					error[2] <= 1; // Both start_data_tx and start_init_tx asserted
					state_out <= STATE_OUT_ERROR;
				end
				else begin
					//data_start <= 1; // 1st valid word appears on the 2nd cycle after data_start
					P_count_out <= 0;
					state_out <= STATE_OUT_START_DELAY;
				end
			end

			else if (start_data_tx) begin
				if (~data_ready) begin
					error[2] <= 1;
					state_out <= STATE_OUT_ERROR;
				end
				data_ready <= 0;
				if (bcdata_gen_end) begin
					// Dummy candidate with gen_end set is the last one in the packet
					// Don't transmit anything on start_tx
					state_out <= STATE_OUT_TX_END_DATA;
				end
				else begin
					P_count_out <= 32;
					state_out <= STATE_OUT_START_DATA_DELAY;
				end
			end // start_data_tx
		end

		//
		// Init Transmit: P, MW, S
		//
		STATE_OUT_START_DELAY: begin
			ctrl <= `CTRL_INIT_START;
			state_out <= STATE_OUT_TX_P;
		end

		STATE_OUT_TX_P: begin
			ctrl <= 0;
			byte_count <= byte_count + 1'b1;
			if (byte_count == 3) begin
				P_count_out <= P_count_out + 1'b1;
				if (P_count_out == 29) begin
					S_count <= S_count + 1'b1;
					state_out <= STATE_OUT_TX_S;
				end
			end
		end

		STATE_OUT_TX_S: begin
			byte_count <= byte_count + 1'b1;
			if (byte_count == 3) begin
				if (S_count == 0) begin
					ctrl <= `CTRL_END;
					state_out <= STATE_OUT_TX_END;
				end
				else
					S_count <= S_count + 1'b1;
			end
		end

		STATE_OUT_TX_END: begin
			ctrl <= 0;
			init_tx_done <= 1;
			state_out <= STATE_OUT_IDLE;
		end

		//
		// Data Transmit
		//
		STATE_OUT_START_DATA_DELAY: begin
			ctrl <= `CTRL_DATA_START;
			state_out <= STATE_OUT_TX_DATA;
		end

		STATE_OUT_TX_DATA: begin
			ctrl <= 0;
			byte_count <= byte_count + 1'b1;
			if (byte_count == 3) begin
				if (P_count_out == 32+30) begin
					ctrl <= `CTRL_END;
					state_out <= STATE_OUT_TX_END_DATA;
				end
				else
					P_count_out <= P_count_out + 1'b1;
			end
		end

		STATE_OUT_TX_END_DATA: begin
			ctrl <= 0;
			data_tx_done <= 1;
			state_out <= STATE_OUT_IDLE;
		end

		STATE_OUT_ERROR: begin
		end
		endcase
	end

	assign P_in =
		(state_in == STATE_IN_CMP_DATA | state_in == STATE_IN_ITER_SALT) ? cmp_config_data :
		(state_in == STATE_IN_READ_EK0 | state_in == STATE_IN_READ_EK1) ? ek_in :
		state_in == STATE_IN_READ_ID0 ? { pkt_id, word_id } :
		gen_id;

	always @(posedge CLK) begin
		if (state_in == STATE_IN_CMP_DATA | state_in == STATE_IN_ITER_SALT
				| state_in == STATE_IN_READ_EK0
				| state_in == STATE_IN_READ_EK1 | state_in == STATE_IN_READ_ID0
				| state_in == STATE_IN_READ_ID1)
			P [P_count_in] <= P_in;
	end

endmodule

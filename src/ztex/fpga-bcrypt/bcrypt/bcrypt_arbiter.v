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

module bcrypt_arbiter #(
	parameter NUM_CORES = -1
	)(
	input CLK,
	input mode_cmp,

	// Packages of data from bcrypt_data for cores
	input [7:0] din,
	input [1:0] ctrl,

	// Control exchange with bcrypt_data
	input data_ready, init_ready,
	output reg start_data_tx = 0, start_init_tx = 0,
	input [15:0] bcdata_pkt_id,
	input bcdata_gen_end,

	// Output using memory 16x16
	output reg [`OUTPKT_TYPE_MSB:0] outpkt_type,
	output [15:0] dout,
	input [3:0] rd_addr,
	
	output reg [15:0] pkt_id,
	//output reg [15:0] word_id,
	//output reg [31:0] gen_id,
	output reg [31:0] num_processed = 0,
	output reg [`HASH_NUM_MSB:0] hash_num,
	//output reg [`RESULT_LEN*8-1:0] result,
	input rd_en,
	output reg empty = 1,
	output [3:0] error,
	//output [255:0] debug,

	// Cores are moved to top-level module.
	output reg [7:0] core_din,
	output reg [1:0] core_ctrl,
	output reg [NUM_CORES-1:0] core_wr_en = 0,
	input [NUM_CORES-1:0] core_init_ready_in, core_crypt_ready_in,
	output reg [NUM_CORES-1:0] core_rd_en = 0,
	input [NUM_CORES-1:0] core_empty_in,
	input [NUM_CORES-1:0] core_dout_in
	);

	genvar i;


	//
	// *******************************************************
	//
	reg err_core_output = 0;

	assign error = {
		1'b0, 1'b0, 1'b0, err_core_output
	};


	//
	// *******************************************************
	//
	reg [NUM_CORES-1:0] core_init_ready = 0, core_crypt_ready = 0;
	reg [NUM_CORES-1:0] core_empty = {NUM_CORES{1'b1}}, core_dout = 0;

	always @(posedge CLK) begin
		core_din <= din;
		core_ctrl <= ctrl;
		core_init_ready <= core_init_ready_in;
		core_crypt_ready <= core_crypt_ready_in;
		core_empty <= core_empty_in;
		core_dout <= core_dout_in;
	end

	reg some_cores_init_ready = 0;
	always @(posedge CLK)
		some_cores_init_ready <= |core_init_ready;

	//
	// Count candidates in packets
	// Unlike in descrypt, doing the easiest thing:
	// candidates from only 1 packet can be "in flight"
	//
	reg [15:0] pkt_id_saved;
	reg pkt_id_saved_ok = 0;
	reg [31:0] num_processed_in = 0;

	reg inpkt_done = 0; // All cand's from the packet were sent to cores
	reg outpkt_done = 0; // All cand's processed


	//
	// Write data to cores
	//
	reg [`MSB(NUM_CORES-1):0] wr_core_num = 0;

	localparam STATE_WR_IDLE = 0,
				STATE_WR_CHECK_CORE_INIT_READY = 1,
				STATE_WR_INIT_TX_START = 2,
				STATE_WR_CHECK_CORE_DATA_READY = 3,
				STATE_WR_DATA_TX_START = 4,
				STATE_WR_TX = 5,
				STATE_WR_TX_END = 6,
				STATE_WR_WAIT_PKT = 7;

	(* FSM_EXTRACT="true" *)
	reg [2:0] state_wr = STATE_WR_IDLE;

	always @(posedge CLK) begin
		case (state_wr)
		STATE_WR_IDLE: if (delay_wr_startup)
			state_wr <= STATE_WR_CHECK_CORE_INIT_READY;

		// Broadcast initialization of cores with P, MW, S data.
		STATE_WR_CHECK_CORE_INIT_READY: if (some_cores_init_ready) begin
			start_init_tx <= 1;
			state_wr <= STATE_WR_INIT_TX_START;
		end
		else
			state_wr <= STATE_WR_CHECK_CORE_DATA_READY;

		STATE_WR_INIT_TX_START: begin
			start_init_tx <= 0;
			if (ctrl == `CTRL_INIT_START) begin
				core_wr_en <= core_init_ready;
				state_wr <= STATE_WR_TX;
			end
		end

		STATE_WR_CHECK_CORE_DATA_READY: begin
			// It goes the last "dummy" candidate in the packet.
			if (data_ready & bcdata_gen_end) begin
				inpkt_done <= 1;
				// Set flag for bcdata; actually transmit doesn't start
				start_data_tx <= 1;
				// ~mode_cmp: don't do accounting, skip last "dummy" candidate
				if (mode_cmp)
					state_wr <= STATE_WR_WAIT_PKT;
			end

			else if (data_ready & core_crypt_ready[wr_core_num]) begin
				// On the 1st candidate, save pkt_id
				if (~pkt_id_saved_ok) begin
					pkt_id_saved <= bcdata_pkt_id;
					pkt_id_saved_ok <= 1;
				end

				num_processed_in <= num_processed_in + 1'b1;

				// Data for cores over {din, ctrl} is going
				// to appear in a few cycles
				start_data_tx <= 1;
				state_wr <= STATE_WR_DATA_TX_START;
			end

			else begin
				if (wr_core_num == NUM_CORES-1) begin
					wr_core_num <= 0;
					if (data_ready_timeout)
						state_wr <= STATE_WR_CHECK_CORE_INIT_READY;
				end
				else
					wr_core_num <= wr_core_num + 1'b1;
			end
		end

		STATE_WR_DATA_TX_START: begin
			start_data_tx <= 0;
			if (ctrl == `CTRL_DATA_START) begin
				core_wr_en[wr_core_num] <= 1;
				state_wr <= STATE_WR_TX;
			end
		end

		STATE_WR_TX: if (ctrl == `CTRL_END)
			state_wr <= STATE_WR_TX_END;

		STATE_WR_TX_END: begin
			// wr_en deasserts after the last data byte
			core_wr_en <= 0;
			state_wr <= STATE_WR_CHECK_CORE_DATA_READY;
		end

		// Wait until data from previous packet is processed.
		STATE_WR_WAIT_PKT: begin
			start_data_tx <= 0;
			if (outpkt_done) begin
				inpkt_done <= 0;
				num_processed_in <= 0;
				pkt_id_saved_ok <= 0;
				state_wr <= STATE_WR_CHECK_CORE_INIT_READY;
			end
		end
		endcase
	end

	delay #(.NBITS(12)) delay_wr_startup_inst (.CLK(CLK),
			.in(1'b1), .out(delay_wr_startup) );

	delay #(.NBITS(9)) data_ready_timeout_inst (.CLK(CLK),
			.in(state_wr == STATE_WR_CHECK_CORE_DATA_READY),
			.out(data_ready_timeout) );


	// *************************************************************
	//
	// Cores
	// moved to top-level module
	//
	// *************************************************************

	//
	// Read from cores (over 1-bit bus)
	//
	reg [15:0] output_r [15:0];
	assign dout = output_r [rd_addr];

	reg [`MSB(NUM_CORES-1):0] rd_core_num = 0;
	reg [3:0] rd_count = 2;
	reg [15:0] rd_tmp = 0;
	reg rd_start = 1;
	reg [3:0] result_word_count = 15;
	reg cmp_result;

	reg core_dout_r = 0;
	always @(posedge CLK)
		core_dout_r <= core_dout[rd_core_num];


	localparam STATE_RD_IDLE = 0,
				STATE_RD_CHECK_NOT_EMPTY = 1,
				STATE_RD_WAIT = 2,

				//STATE_RD_HEADER = 10,
				//STATE_RD_ID0 = 11,
				//STATE_RD_ID1 = 12,
				//STATE_RD_RESULT = 13,
				STATE_RD_READ_COMPLETE = 14,

				STATE_RD_HEADER0 = 10,
				STATE_RD_HEADER1 = 11,
				STATE_RD_16 = 12,

				STATE_RD_EQUAL = 3,
				STATE_RD_OUTPKT_RESULT = 4,
				STATE_RD_ACCOUNT = 5,
				STATE_RD_ACCOUNT2 = 6,
				STATE_RD_OUTPKT_PROCESSING_DONE = 7,
				STATE_RD_CLEANUP = 8,
				STATE_RD_ERROR = 9;

	(* FSM_EXTRACT="true" *)
	reg [3:0] state_rd = STATE_RD_IDLE;

	always @(posedge CLK) begin
		case(state_rd)
		STATE_RD_IDLE:
			state_rd <= STATE_RD_CHECK_NOT_EMPTY;

		STATE_RD_CHECK_NOT_EMPTY: begin
			if (~core_empty[rd_core_num]) begin
				core_rd_en[rd_core_num] <= 1;
				state_rd <= STATE_RD_WAIT;
			end
			else
				rd_core_num <= rd_core_num == NUM_CORES-1
						? {`MSB(NUM_CORES-1)+1{1'b0}} : rd_core_num + 1'b1;
		end

		STATE_RD_WAIT: begin
			// It requires to assert rd_en for 1 cycle.
			core_rd_en[rd_core_num] <= 0;

			result_word_count <= 15;
			rd_start <= 1;
			
			rd_count <= 2;
			// 1st bit of data is 1.
			if (core_dout_r)
				state_rd <= STATE_RD_HEADER0;
		end

		// =======================================================
		// Output content:
		// - header (starts with 1'b1; 31 bit; bits after ~24 are not
		//   transferred correctly to save LUTs in cores)
		// - 2x 32-bit IDs. IDs are sent along with encryption data
		//   for accounting purposes.
		// - 6x 32-bit Blowfish encryption result.
		// =======================================================

		STATE_RD_HEADER0: begin
			rd_tmp [rd_count] <= core_dout_r;
			rd_count <= rd_count + 1'b1;
			if (rd_count == 15)
				state_rd <= STATE_RD_HEADER1;
			cmp_result <= rd_tmp[5];
			hash_num <= rd_tmp[`HASH_NUM_MSB+6:6];
		end
		
		STATE_RD_HEADER1: begin
			rd_tmp [rd_count] <= core_dout_r;
			rd_count <= rd_count + 1'b1;
			if (rd_count == 15) begin
				if (rd_tmp[7:0] != 8'hBC) begin
					err_core_output <= 1;
					state_rd <= STATE_RD_ERROR;
				end
				else if (~mode_cmp | cmp_result & mode_cmp)
					state_rd <= STATE_RD_16;
				else
					state_rd <= STATE_RD_READ_COMPLETE;
			end
		end
		
		// read next 16-bit word
		STATE_RD_16: begin
			rd_tmp [rd_count] <= core_dout_r;
			rd_count <= rd_count + 1'b1;
			if (rd_count == 15)
				result_word_count <= result_word_count + 1'b1;

			if (rd_count == 0)
				rd_start <= 0;

			if (rd_count == 0 && ~rd_start) begin
				// output_r content:
				// 0 - word_id
				// 1 - pkt_id
				// 2-3 - gen_id
				// 4-15 - result
				output_r [result_word_count] <= rd_tmp;

				if (result_word_count == 15) // 4x IDs, 12x result
					state_rd <= STATE_RD_READ_COMPLETE;
			end
			if (rd_count == 0 && result_word_count == 1)
				pkt_id <= rd_tmp;
		end

		/*
		// Output using outpkt_v3: uses too much space
		
		// It goes 30-bit header after the 1st bit.
		STATE_RD_HEADER: begin
			rd_tmp [rd_count] <= core_dout_r;
			rd_count <= rd_count + 1'b1;
			if (rd_count == 15)
				state_rd <= STATE_RD_HEADER1;
		end

		STATE_RD_HEADER1: begin
			rd_tmp [rd_count] <= core_dout_r;
			rd_count <= rd_count + 1'b1;
			if (rd_count == 0) begin
				// Process header
				cmp_result <= rd_tmp[5];
				hash_num <= rd_tmp[7:6];
			end
			else if (rd_count == 15)
				state_rd <= STATE_RD_ID0;
		end

		// The header is in rd_tmp.
		// The 1st bit of the 1st 32-bit data word is in core_dout_r.
		STATE_RD_ID0: begin
			rd_tmp [rd_count] <= core_dout_r;
			rd_count <= rd_count + 1'b1;
			if (rd_count == 0) begin
				// Process header
				if (rd_tmp[23:16] != 8'hBC) begin
					err_core_output <= 1;
					state_rd <= STATE_RD_ERROR;
				end
			end

			else if (rd_count == 15)
				state_rd <= STATE_RD_ID1;
		end

		STATE_RD_ID1: begin
			rd_tmp [rd_count] <= core_dout_r;
			rd_count <= rd_count + 1'b1;
			if (rd_count == 0)
				{ pkt_id, word_id } <= rd_tmp;

			if (rd_count == 31)
				state_rd <= STATE_RD_RESULT;
			result_word_count <= 0;
		end

		STATE_RD_RESULT: begin
			rd_tmp [rd_count] <= core_dout_r;
			rd_count <= rd_count + 1'b1;
			if (rd_count == 0) begin
				if (result_word_count == 0)
					gen_id <= rd_tmp;
				if (result_word_count != 0)
					result[32*result_word_count-1 -:32] <= rd_tmp;
				if (result_word_count == 6)
					state_rd <= STATE_RD_READ_COMPLETE;
			end

			if (rd_count == 31)
				result_word_count <= result_word_count + 1'b1;
		end
		*/

		STATE_RD_READ_COMPLETE: begin
			if (~mode_cmp)
				outpkt_type <= `OUTPKT_TYPE_RESULT;
			else
				outpkt_type <= `OUTPKT_TYPE_CMP_RESULT;
			
			if (~mode_cmp | cmp_result & mode_cmp) begin
				empty <= 0;
				state_rd <= STATE_RD_OUTPKT_RESULT;
			end
			else
				state_rd <= STATE_RD_ACCOUNT;
		end

		STATE_RD_OUTPKT_RESULT: if (rd_en) begin // output PKT_RESULT or PKT_CMP_RESULT
			empty <= 1;
			// ~mode_cmp: no accounting, no output of PKT_DONE
			if (mode_cmp)
				state_rd <= STATE_RD_ACCOUNT;
			else
				state_rd <= STATE_RD_CHECK_NOT_EMPTY;
		end

		STATE_RD_ACCOUNT: begin
			pkt_id <= pkt_id_saved;
			num_processed <= num_processed + 1'b1;
			state_rd <= STATE_RD_ACCOUNT2;
		end

		STATE_RD_ACCOUNT2: begin
			outpkt_type <= `OUTPKT_TYPE_PACKET_DONE;
			if (inpkt_done & num_processed == num_processed_in) begin
				empty <= 0;
				state_rd <= STATE_RD_OUTPKT_PROCESSING_DONE;
			end
			else
				state_rd <= STATE_RD_CHECK_NOT_EMPTY;
		end

		STATE_RD_OUTPKT_PROCESSING_DONE: begin // output PKT_PROCESSING_DONE
			if (rd_en) begin
				outpkt_done <= 1;
				empty <= 1;
				num_processed <= 0;
				state_rd <= STATE_RD_CLEANUP;
			end
		end

		STATE_RD_CLEANUP: begin
			outpkt_done <= 0;
			state_rd <= STATE_RD_CHECK_NOT_EMPTY;
		end

		STATE_RD_ERROR: begin
		end
		endcase
	end

endmodule

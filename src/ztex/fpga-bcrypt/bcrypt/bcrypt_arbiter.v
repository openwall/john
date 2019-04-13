`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016,2019 Denis Burykin
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

	// Comparator
	output reg [31:0] cmp_data,
	output reg cmp_start = 0,
	input cmp_found, cmp_finished,
	input [`HASH_NUM_MSB:0] cmp_hash_num,

	// Output using memory 16x16
	output reg [`OUTPKT_TYPE_MSB:0] outpkt_type,
	output [15:0] dout,
	input [3:0] rd_addr,
	
	output reg [15:0] pkt_id,
	output reg [31:0] num_processed = 0,
	output reg [`HASH_NUM_MSB:0] hash_num,
	input rd_en,
	output reg empty = 1,
	output [3:0] error,
	output idle,

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
	reg [31:0] num_processed_in = 0;

	reg inpkt_done = 0; // All cand's from the packet were sent to cores
	reg outpkt_done = 0; // All cand's processed


	// *************************************************************
	//
	// Write data to cores
	//
	// *************************************************************
	reg [`MSB(NUM_CORES-1):0] wr_core_num = 0;

	reg [31:0] delay_shr = 0;

	localparam STATE_WR_IDLE = 0,
				STATE_WR_CHECK_CORE_INIT_READY = 1,
				STATE_WR_INIT_TX_START = 2,
				STATE_WR_CHECK_CORE_DATA_READY = 3,
				STATE_WR_DATA_TX_START = 4,
				STATE_WR_TX = 5,
				STATE_WR_TX_END = 6,
				STATE_WR_WAIT_PKT = 7,
				STATE_WR_WAIT1 = 8;

	(* FSM_EXTRACT="true" *)
	reg [3:0] state_wr = STATE_WR_IDLE;

	always @(posedge CLK) begin
		if (state_wr == STATE_WR_IDLE | delay_shr[31])
			delay_shr <= { delay_shr[30:0], state_wr == STATE_WR_IDLE };

		case (state_wr)
		STATE_WR_IDLE: if (delay_shr[31])
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
				else
					state_wr <= STATE_WR_WAIT1;
			end

			else if (data_ready & core_crypt_ready[wr_core_num]) begin

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
				state_wr <= STATE_WR_CHECK_CORE_INIT_READY;
			end
		end

		STATE_WR_WAIT1: begin
			start_data_tx <= 0;
			state_wr <= STATE_WR_CHECK_CORE_DATA_READY;
		end
		endcase
	end

	delay #(.NBITS(9)) data_ready_timeout_inst (.CLK(CLK),
			.in(state_wr == STATE_WR_CHECK_CORE_DATA_READY),
			.out(data_ready_timeout) );


	// Count number of keys currently in processing
	localparam TOTAL_IN_PROCESSING = NUM_CORES + 3;
	
	reg recv_item = 0;
	reg [`MSB(TOTAL_IN_PROCESSING-1) :0] total_in_processing = 0;
	always @(posedge CLK)
		if (start_data_tx & ~bcdata_gen_end) begin
			if (~recv_item)
				total_in_processing <= total_in_processing + 1'b1;
		end
		else if (recv_item)
			total_in_processing <= total_in_processing - 1'b1;

	// idle: no keys in flight, no data/init transfer in ~1K cycles
	delay #(.INIT(1), .NBITS(10)) delay_idle_inst (.CLK(CLK),
		.in(total_in_processing == 0 & (1'b0
			| state_wr == STATE_WR_IDLE
			| state_wr == STATE_WR_CHECK_CORE_INIT_READY
			| state_wr == STATE_WR_CHECK_CORE_DATA_READY
		)),
		.out(idle) );


	// *************************************************************
	//
	// Read from cores (over 1-bit bus)
	//
	// *************************************************************
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [15:0] output_r [15:0];
	assign dout = output_r [rd_addr];

	reg [`MSB(NUM_CORES-1):0] rd_core_num = 0;
	reg [3:0] rd_count = 0;
	reg [15:0] rd_tmp = 0;
	reg [3:0] result_word_count = 0;
	reg cmp_result;

	localparam UNIT_OUTPUT_WIDTH = 1;
	localparam PKT_NUM_WORDS = 16;

	reg core_dout_r = 0;
	always @(posedge CLK)
		core_dout_r <= core_dout[rd_core_num];

	reg rd_tmp_wr_en = 0;
	reg [`MSB(PKT_NUM_WORDS-1):0] rd_tmp_wr_addr = 0;
	always @(posedge CLK)
		if (rd_tmp_wr_en)
			output_r [rd_tmp_wr_addr] <= rd_tmp;

	reg pkt_id_wr_en = 0, cmp0_wr_en = 0, cmp1_wr_en = 0;
	always @(posedge CLK) begin
		if (pkt_id_wr_en)
			pkt_id <= rd_tmp;
		if (cmp0_wr_en)
			cmp_data[15:0] <= rd_tmp;
		if (cmp1_wr_en)
			cmp_data[31:16] <= rd_tmp;
	end

	reg [31:0] delay_shr2 = 0;

	localparam STATE_RD_IDLE = 0,
				STATE_RD_CHECK_NOT_EMPTY = 1,
				STATE_RD_HEADER = 2,
				STATE_RD_DATA = 3,
				STATE_RD_CMP = 4,
				STATE_RD_READ_COMPLETE = 5,
				STATE_RD_OUTPKT_RESULT = 6,
				STATE_RD_ACCOUNT = 7,
				STATE_RD_ACCOUNT2 = 8,
				STATE_RD_OUTPKT_PROCESSING_DONE = 9,
				STATE_RD_CLEANUP = 10,
				STATE_RD_ERROR = 11;

	(* FSM_EXTRACT="true" *)
	reg [3:0] state_rd = STATE_RD_IDLE;

	always @(posedge CLK) begin
		if (recv_item)
			recv_item <= 0;

		if (rd_tmp_wr_en)
			rd_tmp_wr_en <= 0;

		if (pkt_id_wr_en)
			pkt_id_wr_en <= 0;
		if (cmp0_wr_en)
			cmp0_wr_en <= 0;
		if (cmp1_wr_en)
			cmp1_wr_en <= 0;
		if (cmp_start)
			cmp_start <= 0;

		if (state_rd == STATE_RD_IDLE | delay_shr2[31])
			delay_shr2 <= { delay_shr2[30:0], state_rd == STATE_RD_IDLE };

		case(state_rd)
		STATE_RD_IDLE: if (delay_shr2[31])
			state_rd <= STATE_RD_CHECK_NOT_EMPTY;

		STATE_RD_CHECK_NOT_EMPTY: begin
			if (~core_empty[rd_core_num]) begin
				core_rd_en[rd_core_num] <= 1;
				state_rd <= STATE_RD_HEADER;
			end
			else
				rd_core_num <= rd_core_num == NUM_CORES-1
						? {`MSB(NUM_CORES-1)+1{1'b0}} : rd_core_num + 1'b1;
		end

		// =======================================================
		// Output content:
		// - header (1 bit == 1'b1)
		// - 2x 32-bit IDs. IDs are sent along with encryption data
		//   for accounting purposes.
		// - 6x 32-bit Blowfish encryption result.
		// =======================================================
		STATE_RD_HEADER: begin
			// It requires to assert rd_en for 1 cycle.
			core_rd_en[rd_core_num] <= 0;

			result_word_count <= 0;
			
			rd_count <= 0;
			// header (1 bit == 1'b1)
			if (core_dout_r) begin
				recv_item <= 1;
				state_rd <= STATE_RD_DATA;
			end
		end

		// Collect PKT_NUM_WORDS words X 16 bit in output_r
		STATE_RD_DATA: begin
			rd_tmp [rd_count * UNIT_OUTPUT_WIDTH +:UNIT_OUTPUT_WIDTH]
				<= core_dout_r;
			rd_count <= rd_count + 1'b1;
			if (rd_count == (16 / UNIT_OUTPUT_WIDTH) -1) begin
				rd_tmp_wr_en <= 1;
				rd_tmp_wr_addr <= result_word_count;
				result_word_count <= result_word_count + 1'b1;
				if (result_word_count == PKT_NUM_WORDS-1) begin
					if (mode_cmp)
						state_rd <= STATE_RD_CMP;
					else
						state_rd <= STATE_RD_READ_COMPLETE;
				end
			end

			// 2nd 16-bit word: pkt_id
			if (result_word_count == 1 & rd_count == (16 / UNIT_OUTPUT_WIDTH) -1)
				pkt_id_wr_en <= 1;

			// externalize comparator data, start comparison
			// before all the data received from a computing unit
			if (result_word_count == 4 & rd_count == (16 / UNIT_OUTPUT_WIDTH) -1)
				cmp0_wr_en <= 1;
			if (result_word_count == 5 & rd_count == (16 / UNIT_OUTPUT_WIDTH) -1)
				cmp1_wr_en <= 1;
			if (mode_cmp & result_word_count == 6 & rd_count == 3)
				cmp_start <= 1;
		end

		STATE_RD_CMP: begin
			if (cmp_found) begin
				outpkt_type <= `OUTPKT_TYPE_CMP_RESULT;
				hash_num <= cmp_hash_num;
				empty <= 0;
				state_rd <= STATE_RD_OUTPKT_RESULT;
			end
			else if (cmp_finished)
				state_rd <= STATE_RD_ACCOUNT;
		end

		STATE_RD_READ_COMPLETE: begin
			outpkt_type <= `OUTPKT_TYPE_RESULT;
			empty <= 0;
			state_rd <= STATE_RD_OUTPKT_RESULT;
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

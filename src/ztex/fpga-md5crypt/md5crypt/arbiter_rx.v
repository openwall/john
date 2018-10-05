`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//
// Unit output packet format:
// - header (1 word)
// - IDs (64 bits)
// - MD5 hash (128 bits)
//
// Total: 16+8 = 24 bytes
//
module arbiter_rx #(
	parameter N_UNITS = -1,
	parameter UNIT_OUTPUT_WIDTH = -1,
	parameter PKT_NUM_WORDS = `RESULT_LEN/2 + 4
	)(
	input CLK,
	input mode_cmp,
	// Units
	input [UNIT_OUTPUT_WIDTH * N_UNITS -1 :0] unit_dout,
	output reg [N_UNITS-1:0] unit_rd_en = 0,
	input [N_UNITS-1:0] unit_empty,
	// Iteraction with arbiter_tx
	input [31:0] num_processed_tx,
	input [15:0] pkt_id_tx,
	input pkt_tx_done,
	output reg pkt_rx_done = 0,
	output reg recv_item = 0, // asserts for 1 for every RX item
	// Comparator
	output reg [31:0] cmp_data,
	output reg cmp_start = 0,
	input cmp_found, cmp_finished,
	input [`HASH_NUM_MSB:0] cmp_hash_num,
	// Output
	output reg [`OUTPKT_TYPE_MSB:0] outpkt_type,
	output [15:0] dout,
	input [`MSB(PKT_NUM_WORDS-1):0] rd_addr,
	output reg [15:0] pkt_id,
	output reg [31:0] num_processed = 0,
	output reg [`HASH_NUM_MSB:0] hash_num,
	input rd_en,
	output reg empty = 1,
	
	output reg [1:0] err = 0,
	output reg [15:0] debug = 0
	);

	reg [`MSB(N_UNITS-1):0] unit_num = 0;
	reg [UNIT_OUTPUT_WIDTH-1 :0] din = 0;
	reg unit_empty_r = 1;
	always @(posedge CLK) begin
		din <= unit_dout [unit_num * UNIT_OUTPUT_WIDTH +:UNIT_OUTPUT_WIDTH];
		unit_empty_r <= unit_empty [unit_num];
	end

	(* RAM_STYLE="DISTRIBUTED" *)
	reg [15:0] output_r [0:PKT_NUM_WORDS-1];
	assign dout = output_r [rd_addr];

	reg rd_tmp_wr_en = 0;
	reg [`MSB(PKT_NUM_WORDS-1):0] rd_tmp_wr_addr = 0;
	always @(posedge CLK)
		if (rd_tmp_wr_en)
			output_r [rd_tmp_wr_addr] <= rd_tmp;


	reg [2:0] rd_count = 0;
	reg [15:0] rd_tmp = 0;
	reg [`MSB(PKT_NUM_WORDS-1):0] result_word_count = 0;

	reg [31:0] delay_shr = 0;

	localparam STATE_IDLE = 0,
				STATE_WAIT = 1,
				STATE_WAIT2 = 2,
				STATE_READ = 3,
				STATE_RX_HEADER = 4,
				STATE_RX_DATA = 5,
				STATE_RX_END = 6,
				STATE_CMP = 7,
				STATE_OUTPKT_RESULT = 8,
				STATE_PKT_ACCOUNT = 9,
				STATE_PKT_ACCOUNT2 = 10,
				STATE_PKT_ACCOUNT3 = 11,
				STATE_OUTPKT_PROCESSING_DONE = 12;

	(* FSM_EXTRACT="true" *)
	reg [3:0] state = STATE_IDLE;

	always @(posedge CLK) begin
		if (rd_tmp_wr_en)
			rd_tmp_wr_en <= 0;
		
		if (cmp_start)
			cmp_start <= 0;

		if (pkt_rx_done)
			pkt_rx_done <= 0;

		if (recv_item)
			recv_item <= 0;

		if (state == STATE_IDLE | delay_shr[31])
			delay_shr <= { delay_shr[30:0], state == STATE_IDLE };

		case (state)
		STATE_IDLE: if (delay_shr[31])
			state <= STATE_WAIT;
		
		STATE_WAIT:
			if (~unit_empty_r)// [unit_num])
				state <= STATE_READ;
			else begin
				unit_num <= unit_num == N_UNITS-1
					? {`MSB(N_UNITS-1)+1{1'b0}} : unit_num + 1'b1;
				state <= STATE_WAIT2;
			end
		
		STATE_WAIT2:
			state <= STATE_WAIT;

		STATE_READ: begin
			recv_item <= 1;
			unit_rd_en [unit_num] <= 1;
			state <= STATE_RX_HEADER;
		end
		
		STATE_RX_HEADER: begin
			unit_rd_en <= 0;
			result_word_count <= 0;
			if (din != 0) begin
				if (din != {UNIT_OUTPUT_WIDTH{1'b1}}) begin
					err[0] <= 1;
					debug [unit_num] <= 1;
				end
				else
					state <= STATE_RX_DATA;
			end
		end
		
		// Collect PKT_NUM_WORDS words X 16 bit in output_r
		STATE_RX_DATA: begin
			rd_tmp [rd_count * UNIT_OUTPUT_WIDTH +:UNIT_OUTPUT_WIDTH]
				<= din;
			rd_count <= rd_count + 1'b1;
			if (rd_count == (16 / UNIT_OUTPUT_WIDTH) -1) begin
				rd_tmp_wr_en <= 1;
				rd_tmp_wr_addr <= result_word_count;
				result_word_count <= result_word_count + 1'b1;
				if (result_word_count == PKT_NUM_WORDS-1)
					state <= STATE_RX_END;
			end
			
			// 2nd 16-bit word: pkt_id
			if (result_word_count == 2 & rd_count == 0)
				pkt_id <= rd_tmp;
			
			// externalize comparator data, start comparison
			// before all the data received from a computing unit
			if (result_word_count == 5 & rd_count == 0)
				cmp_data[15:0] <= rd_tmp;
			if (result_word_count == 6 & rd_count == 0) begin
				cmp_data[31:16] <= rd_tmp;
				cmp_start <= 1;
			end
		end
		
		STATE_RX_END: begin
			outpkt_type <= `OUTPKT_TYPE_RESULT;
			if (din != 0) begin
				err[1] <= 1;
				debug [unit_num] <= 1;
			end
			else if (mode_cmp)
				state <= STATE_CMP;
			else begin
				empty <= 0;
				state <= STATE_OUTPKT_RESULT;
			end
		end
		
		STATE_CMP: begin
			if (cmp_found) begin
				outpkt_type <= `OUTPKT_TYPE_CMP_RESULT;
				hash_num <= cmp_hash_num;
				empty <= 0;
				state <= STATE_OUTPKT_RESULT;
			end
			else if (cmp_finished)
				state <= STATE_PKT_ACCOUNT;
		end
		
		// output PKT_RESULT or PKT_CMP_RESULT
		STATE_OUTPKT_RESULT: if (rd_en) begin
			empty <= 1;
			if (mode_cmp)
				state <= STATE_PKT_ACCOUNT;
			else
				state <= STATE_WAIT;
		end
		
		STATE_PKT_ACCOUNT: begin
			num_processed <= num_processed + 1'b1;
			if (pkt_tx_done)
				state <= STATE_PKT_ACCOUNT2;
			else
				state <= STATE_WAIT;
		end

		STATE_PKT_ACCOUNT2:
			if (num_processed_tx == num_processed)
				state <= STATE_PKT_ACCOUNT3;
			else
				state <= STATE_WAIT;
		
		STATE_PKT_ACCOUNT3: begin
			outpkt_type <= `OUTPKT_TYPE_PACKET_DONE;
			pkt_id <= pkt_id_tx;
			empty <= 0;
			pkt_rx_done <= 1;
			state <= STATE_OUTPKT_PROCESSING_DONE;
		end
		
		// output PKT_PROCESSING_DONE
		STATE_OUTPKT_PROCESSING_DONE: if (rd_en) begin
			empty <= 1;
			num_processed <= 0;
			state <= STATE_WAIT;
		end
		endcase
	end


endmodule

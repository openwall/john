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
// - SHA512 hash (512 bits)
//
// Total: 64+8 = 72 bytes
//
module arbiter_rx #(
	parameter N_UNITS = -1,
	parameter UNIT_OUTPUT_WIDTH = -1
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
	// Comparator
	output reg [31:0] cmp_data,
	output reg cmp_start = 0,
	input cmp_found, cmp_finished,
	input [`HASH_NUM_MSB:0] cmp_hash_num,
	// Output
	output reg [`OUTPKT_TYPE_MSB:0] outpkt_type,
	output [15:0] dout,
	input [5:0] rd_addr,
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
	always @(posedge CLK)
		din <= unit_dout [unit_num * UNIT_OUTPUT_WIDTH +:UNIT_OUTPUT_WIDTH];


	(* RAM_STYLE="DISTRIBUTED" *)
	reg [15:0] output_r [0:63];
	assign dout = output_r [rd_addr];

	reg rd_tmp_wr_en = 0;
	reg [5:0] rd_tmp_wr_addr = 0;
	always @(posedge CLK)
		if (rd_tmp_wr_en)
			output_r [rd_tmp_wr_addr] <= rd_tmp;


	reg [2:0] rd_count = 0;
	reg [15:0] rd_tmp = 0;
	reg [5:0] result_word_count = 0;

	reg [5:0] delay_cnt = 0;


	localparam STATE_IDLE = 0,
				STATE_WAIT = 1,
				STATE_READ = 2,
				STATE_RX_HEADER = 3,
				STATE_RX_DATA = 4,
				STATE_RX_END = 5,
				STATE_CMP = 6,
				STATE_OUTPKT_RESULT = 7,
				STATE_PKT_ACCOUNT = 8,
				STATE_OUTPKT_PROCESSING_DONE = 9;

	(* FSM_EXTRACT="true" *)
	reg [3:0] state = STATE_IDLE;

	always @(posedge CLK) begin
		if (rd_tmp_wr_en)
			rd_tmp_wr_en <= 0;
		
		if (cmp_start)
			cmp_start <= 0;

		if (pkt_rx_done)
			pkt_rx_done <= 0;

		case (state)
		STATE_IDLE: begin
			delay_cnt <= delay_cnt + 1'b1;
			if (delay_cnt == 63)
				state <= STATE_WAIT;
		end
		
		STATE_WAIT:
			if (~unit_empty [unit_num])
				state <= STATE_READ;
			else
				unit_num <= unit_num == N_UNITS-1
					? {`MSB(N_UNITS-1)+1{1'b0}} : unit_num + 1'b1;
		
		STATE_READ: begin
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
		
		// Collect 36 words X 16 bit in output_r
		STATE_RX_DATA: begin
			rd_tmp [rd_count * UNIT_OUTPUT_WIDTH +:UNIT_OUTPUT_WIDTH]
				<= din;
			rd_count <= rd_count + 1'b1;
			if (rd_count == (16 / UNIT_OUTPUT_WIDTH) -1) begin
				rd_tmp_wr_en <= 1;
				rd_tmp_wr_addr <= result_word_count;
				result_word_count <= result_word_count + 1'b1;
				if (result_word_count == 35)
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
			outpkt_type <= `OUTPKT_TYPE_PACKET_DONE;
			num_processed <= num_processed + 1'b1;
			pkt_id <= pkt_id_tx;
			if (num_processed_tx == num_processed + 1'b1
					& pkt_tx_done) begin
				empty <= 0;
				pkt_rx_done <= 1;
				state <= STATE_OUTPKT_PROCESSING_DONE;
			end
			else
				state <= STATE_WAIT;
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

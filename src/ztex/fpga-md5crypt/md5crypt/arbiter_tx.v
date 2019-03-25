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
// Tasks for Arbiter, transmit part:
//
// - Gather up necessary data, create data packets for computing units;
// - Transmit data to units ready for computing;
// - Operate mostly at PKT_COMM frequency, send at CORE frequency.
// - Account number of candidates transmitted, handle changes
// in comparator configuration etc.
//
// Packet content is as follows (everything's LE):
// - cnt (number of rounds) - 32 bit
// - salt_len - 32 bit
// - salt data - 16 bytes (2x64 bits), regardless of salt_len
// - IDs - 64 bit
// - key_len - 32 bit
// - unused - 32 bit
// - key data (rounded up to 32 bits), variable size
//
module arbiter_tx #(
	parameter N_UNITS = 1,
	parameter WORD_MAX_LEN = 64, // in bytes
	parameter PKT_LEN = WORD_MAX_LEN + 40
	)(
	input CLK, CORE_CLK,
	// Turn off comparator mode (mode_cmp=0):
	// - next CMP_CONFIG goes on immediately while candidates
	// associated with the previous CMP_CONFIG are still
	// being processed;
	// - don't count number of candidates
	input mode_cmp,
	// Input from word_gen
	input [31:0] gen_id,
	input [15:0] word_id, pkt_id,
	input gen_end,
	input [`MSB(WORD_MAX_LEN):0] word_len,
	// Read from word_gen.word_storage
	input [7:0] din,
	output reg [`MSB(WORD_MAX_LEN-1):0] word_gen_rd_addr = 0,
	output word_set_empty,
	input word_empty, src_totally_empty,
	// From cmp_config
	input new_cmp_config,
	output cmp_config_applied,
	output reg [4:0] cmp_config_addr = 0,
	input [7:0] cmp_config_data,
	// From initialization packet (PKT_TYPE_INIT)
	input [7:0] init_din,
	input init_empty,
	output init_rd_en,
	input [N_UNITS-1:0] unit_tx_mask,

	// Units (CORE_CLK)
	output reg [7:0] unit_in = 0, // broadcast
	output reg unit_in_ctrl = 0, // broadcast
	output reg bcast_en = 0,
	output reg [N_UNITS-1:0] unit_in_wr_en = 0,
	input [N_UNITS-1:0] unit_in_afull, unit_in_ready,
	
	// Iteraction with arbiter_rx
	output reg [31:0] num_processed_tx = 0,
	output reg [15:0] pkt_id_tx,
	output reg pkt_tx_done = 0,
	input pkt_rx_done,
	input recv_item,
	
	output reg idle = 1,
	output reg err = 0
	);

	reg cmp_configured = 0;


	// ***************************************************
	localparam STATE_IN_IDLE = 0,
				STATE_IN_PROCESS_WORDS = 1,
				STATE_IN_WAIT_TX_IDLE = 2,
				STATE_IN_TX_COMPLETE_WAIT = 3,
				STATE_IN_WAIT_RX_DONE = 4,
				STATE_IN_CMP_CONFIG = 5,
				STATE_IN_DELAY1 = 6,
				STATE_IN_DELAY2 = 7,
				STATE_IN_PKT_INIT = 8,
				STATE_IN_START_CLK_GLBL = 9;

	(* FSM_EXTRACT="true" *)
	reg [3:0] state_in = STATE_IN_IDLE;

	always @(posedge CLK) begin
		case (state_in)
		STATE_IN_IDLE: begin
			if (~word_empty) begin
				if (~idle)
					state_in <= STATE_IN_PROCESS_WORDS;
				else
					state_in <= STATE_IN_START_CLK_GLBL;
			end
			
			// loose checks; expecting init packet after
			// fpga startup; transmitter must be idle
			if (~init_empty & src_totally_empty) begin
				if (~idle)
					state_in <= STATE_IN_PKT_INIT;
				else
					state_in <= STATE_IN_START_CLK_GLBL;
			end

			// New "comparator configuration" (incl. salt data).
			// It has to wait until it finishes processing of words
			// associated with the previous comparator configuration.
			if (new_cmp_config & src_totally_empty)
				state_in <= STATE_IN_CMP_CONFIG;
		end

		STATE_IN_PKT_INIT:
			state_in <= STATE_IN_IDLE;

		STATE_IN_START_CLK_GLBL: if (start_clk_glbl_delay) begin
			if (~word_empty)
				state_in <= STATE_IN_PROCESS_WORDS;
			else
				state_in <= STATE_IN_PKT_INIT;
		end

		STATE_IN_PROCESS_WORDS: if (~word_empty) begin
			if (~cmp_configured)
				err <= 1;
			else if (gen_end) begin
				pkt_id_tx <= pkt_id;
				if (mode_cmp) begin
					pkt_tx_done <= 1;
					state_in <= STATE_IN_WAIT_RX_DONE;
				end
				else
					state_in <= STATE_IN_IDLE;
			end
			else begin
				num_processed_tx <= num_processed_tx + 1'b1;
				state_in <= STATE_IN_WAIT_TX_IDLE;
			end
		end
		
		// Wait for transmitter part to be idle
		STATE_IN_WAIT_TX_IDLE: if (tx_idle_sync)
			state_in <= STATE_IN_DELAY1;
		
		STATE_IN_DELAY1:
			state_in <= STATE_IN_TX_COMPLETE_WAIT;

		// Wait until the transmission is complete
		STATE_IN_TX_COMPLETE_WAIT: if (tx_completed_sync)
			state_in <= STATE_IN_DELAY2;

		STATE_IN_DELAY2:
			state_in <= STATE_IN_PROCESS_WORDS;

		// All words in a packet were processed by the receive arbiter.
		STATE_IN_WAIT_RX_DONE: if (pkt_rx_done) begin
			pkt_tx_done <= 0;
			num_processed_tx <= 0;
			state_in <= STATE_IN_IDLE;
		end
		
		STATE_IN_CMP_CONFIG: begin
			cmp_configured <= 1;
			state_in <= STATE_IN_IDLE;
		end
		endcase
	end
	
	assign word_set_empty =
		state_in == STATE_IN_TX_COMPLETE_WAIT & tx_completed_sync
		| state_in == STATE_IN_PROCESS_WORDS & ~word_empty & gen_end;
	
	sync_pulse3 sync_tx_ready( .wr_clk(CLK),
		.sig(state_in == STATE_IN_WAIT_TX_IDLE & tx_idle_sync),
		.busy(), .rd_clk(CORE_CLK), .out(tx_ready_sync) );

	assign cmp_config_applied = state_in == STATE_IN_CMP_CONFIG;

	assign init_rd_en = state_in == STATE_IN_PKT_INIT;

	sync_pulse3 sync_pkt_init( .wr_clk(CLK),
		.sig(state_in == STATE_IN_PKT_INIT),
		.busy(), .rd_clk(CORE_CLK), .out(pkt_init_sync) );


	localparam TOTAL_IN_PROCESSING = N_UNITS * (6 + 16) + 1;
	reg [`MSB(TOTAL_IN_PROCESSING-1) :0] total_in_processing = 0;
	always @(posedge CLK)
		if (state_in == STATE_IN_PROCESS_WORDS & ~word_empty & ~gen_end) begin
			if (~recv_item)
				total_in_processing <= total_in_processing + 1'b1;
		end
		else if (recv_item)
			total_in_processing <= total_in_processing - 1'b1;

	delay #( .NBITS(6) ) delay_start_clk_glbl(
		.CLK(CLK), .in(state_in == STATE_IN_START_CLK_GLBL),
		.out(start_clk_glbl_delay) );

	always @(posedge CLK)
		idle <= state_in == STATE_IN_IDLE & total_in_processing == 0
			| state_in == STATE_IN_CMP_CONFIG;


	// ***************************************************
	reg [`MSB(N_UNITS-1):0] unit_num = 0;
	reg afull = 1, ready = 0;
	reg unit_tx_mask_r = 0;
	always @(posedge CORE_CLK) begin
		afull <= unit_in_afull [unit_num];
		ready <= unit_in_ready [unit_num];
		unit_tx_mask_r <= unit_tx_mask [unit_num];
	end
	
	reg [2:0] cnt = 0;
	wire [63:0] ids = { gen_id, pkt_id, word_id };
	
	wire [`MSB(WORD_MAX_LEN-1):0] word_len_minus1 = word_len - 1'b1;
	reg [`MSB(WORD_MAX_LEN-1):0] word_gen_last_rd_addr;


	localparam STATE_IDLE = 0,
				STATE_SEARCH1 = 1,
				STATE_SEARCH2 = 2,
				//STATE_READY = 3,
				STATE_TX1 = 4,
				STATE_TX2 = 5,
				STATE_TX3 = 6,
				STATE_TX4 = 7,
				STATE_TX5 = 8,
				STATE_TX6 = 9,
				STATE_TX_END = 10,
				STATE_TX_PKT_INIT1 = 11,
				STATE_TX_PKT_INIT2 = 12,
				STATE_TX_PKT_INIT3 = 13;

	(* FSM_EXTRACT="true" *)
	reg [3:0] state = STATE_IDLE;

	always @(posedge CORE_CLK) begin
		case (state)
		STATE_IDLE: begin
			bcast_en <= 0;
			if (pkt_init_sync)
				state <= STATE_TX_PKT_INIT1;
			else if (tx_ready_sync) // ready for transmit
				state <= STATE_SEARCH1;
		end

		STATE_SEARCH1:
			if (~ready | unit_tx_mask_r) begin
				unit_num <= unit_num == N_UNITS-1
					? {`MSB(N_UNITS-1)+1{1'b0}} : unit_num + 1'b1;
				state <= STATE_SEARCH2;
			end
			else
				state <= STATE_TX1;
		
		STATE_SEARCH2:
			state <= STATE_SEARCH1;
		
		STATE_TX1: begin // Start transmission
			bcast_en <= 1;
			unit_in <= 0; // packet header (1 byte).
			unit_in_wr_en [unit_num] <= 1;
			unit_in_ctrl <= 1;
			cmp_config_addr <= 0;
			state <= STATE_TX2;
		end
		
		STATE_TX2: begin // Send cnt, salt_len, salt (24 bytes)
			unit_in <= cmp_config_data;
			unit_in_ctrl <= 0;
			if (~afull) begin
				unit_in_wr_en [unit_num] <= 1;
				cmp_config_addr <= cmp_config_addr + 1'b1;
				if (cmp_config_addr == 23)
					state <= STATE_TX3;
			end
			else
				unit_in_wr_en [unit_num] <= 0;
		end
		
		STATE_TX3: begin // Send IDs (8 bytes)
			unit_in <= ids [cnt*8 +:8];
			if (~afull) begin
				unit_in_wr_en [unit_num] <= 1;
				cnt <= cnt + 1'b1;
				if (cnt == 7)
					state <= STATE_TX4;
			end
			else
				unit_in_wr_en [unit_num] <= 0;
		end
		
		STATE_TX4: begin // Send key_len (1 byte)
			unit_in <= { {7-`MSB(WORD_MAX_LEN){1'b0}}, word_len };
			if (~afull) begin
				unit_in_wr_en [unit_num] <= 1;
				cnt <= cnt + 1'b1;
				state <= STATE_TX5;
			end
			else
				unit_in_wr_en [unit_num] <= 0;

			word_gen_rd_addr <= 0;
			word_gen_last_rd_addr
				<= { word_len_minus1 [`MSB(WORD_MAX_LEN-1):2], 2'b11 };
		end
		
		STATE_TX5: begin // 7 bytes - zeroed
			unit_in <= 0;
			if (~afull) begin
				unit_in_wr_en [unit_num] <= 1;
				cnt <= cnt + 1'b1;
				if (cnt == 7)
					state <= STATE_TX6;
			end
			else
				unit_in_wr_en [unit_num] <= 0;
		end
		
		STATE_TX6: begin // key - rounded up to 32 bits
			unit_in <= din;
			if (~afull) begin
				unit_in_wr_en [unit_num] <= 1;
				word_gen_rd_addr <= word_gen_rd_addr + 1'b1;
				if (word_gen_rd_addr == word_gen_last_rd_addr) begin
					unit_in_ctrl <= 1;
					state <= STATE_TX_END;
				end
			end
			else
				unit_in_wr_en [unit_num] <= 0;
		end
		
		STATE_TX_END: begin
			unit_in_wr_en [unit_num] <= 0;
			unit_in_ctrl <= 0;
			unit_num <= unit_num == N_UNITS-1
				? {`MSB(N_UNITS-1)+1{1'b0}} : unit_num + 1'b1;
			state <= STATE_IDLE;
		end


		// Broadcast transmission of initialization packet
		STATE_TX_PKT_INIT1: begin
			bcast_en <= 1;
			unit_in <= { init_din[4:0], 3'b001 };
			unit_in_wr_en <= {N_UNITS{1'b1}};
			unit_in_ctrl <= 1;
			state <= STATE_TX_PKT_INIT2;
		end

		STATE_TX_PKT_INIT2: begin
			state <= STATE_TX_PKT_INIT3;
		end

		STATE_TX_PKT_INIT3: begin
			unit_in_wr_en <= {N_UNITS{1'b0}};
			unit_in_ctrl <= 0;
			state <= STATE_IDLE;
		end
		endcase
	end

	sync_sig3 sync_tx_idle(.sig(state == STATE_IDLE), .clk(CLK),
		.out(tx_idle_sync) );
	
	sync_pulse3 sync_tx_completed( .wr_clk(CORE_CLK),
		.sig(state == STATE_TX_END), .busy(),
		.rd_clk(CLK), .out(tx_completed_sync) );

endmodule

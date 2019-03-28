`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016-2017,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "descrypt_core/descrypt.vh"

module arbiter #(
	parameter NUM_CORES = -1,
	// This prevents from being built as partition in MPPR
	//parameter [16*NUM_CORES-1 : 0] CORES_CONF = 0,
	parameter WORD_GEN_DOUT_WIDTH = -1
	)(
	input [NUM_CORES-1:0] DUMMY_CORES,
	input WORD_GEN_CLK, // input from generator
	input CORE_CLK, // for most of operations
	input CMP_CLK, // for core's comparator and output

	// read words from the generator (CLK)
	input [WORD_GEN_DOUT_WIDTH-1:0] word_gen_in,
	input wr_en,
	output full, almost_full,

	// read comparator config (CORE_CLK)
	input [`GLOBAL_SALT_LSB-1:0] salt,
	input [`RAM_ADDR_MSB-1:0] addr_start, addr_diff,
	input hash_valid, hash_end,
	input [`HASH_MSB:0] hash,
	input [`RAM_ADDR_MSB:0] hash_addr,
	input cmp_config_wr_en,
	output reg cmp_config_full = 1,
	input new_cmp_config,
	output reg cmp_config_applied = 0, // got new_cmp_config signal, started handling of config

	output [1:0] pkt_type_out,
	// data depends on packet type
	output reg [31:0] gen_id_out,
	output reg [15:0] pkt_id_out, word_id_out,
	output [`RAM_ADDR_MSB:0] hash_num_eq,
	output reg [31:0] num_processed_out,

	input rd_en,
	output empty,
	output [7:0] error,
	output reg idle = 1,
	
	// Cores are moved to upper level module
	input [NUM_CORES-1:0] crypt_ready_out, core_idle_out, core_err_out,
	output reg [NUM_CORES-1:0] core_wr_en = 0,
	// Serial output from cores
	input [4*NUM_CORES-1:0] core_dout_in,
	output [NUM_CORES-1 :0] core_dout_ready,
	// Broadcast
	output reg [`DIN_MSB:0] core_din = 0,
	output reg [2:0] core_addr_in = 0
	);

	// Actually: number of pipeline stages
	localparam NUM_CRYPT_INSTANCES = 16; // crypt instances per core (unchangeable in this version)


	// *************************************************************

	reg err_core = 0, err_cmp = 0; // from cores
	reg err_core_dout = 0, err_rd_ram = 0, err_core_output = 0, err_cmp_no_conf = 0; // from arbiter itself
	reg err_watchdog = 0;
	assign error = {
		err_watchdog, 1'b0, err_cmp, err_core,
		err_core_dout, err_rd_ram, err_core_output, err_cmp_no_conf
	};


	genvar i;
	integer k;

	wire gen_end_in;
	wire [31:0] gen_id_in;
	wire [15:0] pkt_id_in, word_id_in;
	wire [55:0] word_in;

	fifo_sync_very_fast_af #(
		.A_WIDTH(5), .D_WIDTH(WORD_GEN_DOUT_WIDTH)
	) arbiter_input_fifo (
		.CLK(CORE_CLK),
		.din(word_gen_in),
		.wr_en(wr_en),
		.full(full),
		.almost_full(almost_full),

		.dout({ word_end_in, gen_end_in, gen_id_in, pkt_id_in,
				word_id_in, word_in }),
		.rd_en(input_rd_en),
		.empty(input_empty)
	);
/*
	// Arbiter's Input FIFO
	// IP Coregen: FIFO
	// Distributed RAM, Independent clocks
	// First Word Fall-Through
	// width 122
	// Almost Full Flag
	// reset: off
	fifo_122x32 arbiter_input_fifo (
		.wr_clk(WORD_GEN_CLK),
		.din(word_gen_in),
		.wr_en(wr_en),
		.full(full),
		.almost_full(almost_full),

		.rd_clk(CORE_CLK),
		.dout({ word_end_in, gen_end_in, gen_id_in, pkt_id_in,
				word_id_in, word_in }),
		.rd_en(input_rd_en),
		.empty(input_empty)
	);
*/
	wire [63:0] key64;
	crypt3_ascii2bin crypt3_ascii2bin( .din(word_in), .dout(key64) );

	// DES crypt(3): perform Permuted-choice 1
	wire [55:0] key56_pc1;
	pc1 pc1( .din(key64), .dout(key56_pc1) );


	// read from input FIFO
	assign input_rd_en = ~input_empty & ~gen_end_r & wr_state == WR_STATE_WRITE_CORE
			// Empty packet (1 cand. with gen_end) - skip it
			| ~input_empty & ~pkt_id_num_ok & gen_end_in & wr_state == WR_STATE_WAIT;

	reg cmp_configured = 0; // Comparator has non-empty configuration


	// **********************************
	//
	// Write cores
	//
	// **********************************
	reg [`MSB(NUM_CORES-1):0] wr_core_num = 0;
	wire [`MSB(NUM_CORES-1):0] wr_core_num_next = wr_core_num == NUM_CORES-1
			? {`MSB(NUM_CORES-1)+1{1'b0}} : wr_core_num + 1'b1;

	reg [`MSB(NUM_CRYPT_INSTANCES-1):0] wr_instance_num = 0;
	reg [NUM_CORES-1:0] crypt_ready = 0, core_err = 0;
	reg [NUM_CORES-1:0] core_idle = {NUM_CORES{1'b1}};
	reg crypt_ready_r = 0;
	reg all_cores_idle_r = 1;

	// A glitch: core_idle may assert for few cycles when it's actually busy
	delay #( .INIT(1), .NBITS(4)
	) delay_cores_idle(.CLK(CORE_CLK), .in(all_cores_idle_r),
		.out(all_cores_idle_delayed) );

	always @(posedge CORE_CLK) begin
		crypt_ready_r <= crypt_ready[wr_core_num];
		all_cores_idle_r <= &core_idle;
		idle <= all_cores_idle_delayed & input_empty;
		err_core <= |core_err;
	end

	// It writes candidates to cores in batches.
	// Current batch_num is written to core with the batch.
	reg [`NUM_BATCHES_MSB:0] batch_num [NUM_CORES-1:0];
	reg [`NUM_BATCHES_MSB:0] batch_num_r = 0;


	//
	// Packet accounting.
	// * Limited number of packets (`NUM_PKTS) in processing
	// * Count batches
	// * Count candidates
	//
	// Current pkt_num is written to core with the batch.
	//
	reg gen_end_r = 0; // end of packet/generator (attached to input candidate)
	reg pkt_id_num_ok = 0; // 1: some packet is being handled, it's ID is in pkt_id_num
	reg [15:0] pkt_id_num [`NUM_PKTS-1:0];

	reg [`NUM_PKTS_MSB:0] pkt_num = 0; // current packet (being processed)
	reg [`PKT_BATCHES_MSB:0] pkt_num_batches [`NUM_PKTS-1:0]; // number of batches in packets
	reg [`PKT_BATCHES_MSB:0] pkt_num_batches_r = 0;
	reg [`NUM_PKTS-1:0] pkt_done = 0; // accounting for this packet is done
	reg [31:0] pkt_num_processed [`NUM_PKTS-1:0]; // number of candidates in packets
	reg [31:0] pkt_num_processed_r = 0;

	// There's no empty slot for packet accounting
	wire pkt_full = pkt_done [ pkt_num == `NUM_PKTS-1 ? 0 : pkt_num + 1'b1 ];


	localparam	WR_STATE_INIT = 0,
					//WR_STATE_INIT2 = 1,
					WR_STATE_WAIT = 2,
					WR_STATE_WRITE_CORE = 3,
					WR_STATE_START_COMPUTATION = 4,
					WR_STATE_CONFIG_SALT = 5,
					WR_STATE_CONFIG_HASH = 6,
					WR_STATE_PKT_ACCOUNT_WAIT = 7;

	(* FSM_EXTRACT="true", FSM_ENCODING="speed1" *)
	reg [2:0] wr_state = WR_STATE_INIT;

	wire wr_state_pkt_done_rd = wr_state == WR_STATE_WAIT
			| wr_state == WR_STATE_WRITE_CORE | wr_state == WR_STATE_PKT_ACCOUNT_WAIT;

	reg wr_core_num_wait = 0;

	reg wr_instance_num_eq_minus1 = 0, wr_instance_num_eq_minus2 = 0;
	reg new_cmp_config_r = 0;

	always @(posedge CORE_CLK) begin
		if (pkt_done_rd_sync & wr_state_pkt_done_rd)
			pkt_done[pkt_num_done_rd] <= 0;

		wr_instance_num_eq_minus1 <= wr_instance_num == NUM_CRYPT_INSTANCES - 2;
		wr_instance_num_eq_minus2 <= wr_instance_num == NUM_CRYPT_INSTANCES - 3;

		new_cmp_config_r <= new_cmp_config & ~pkt_id_num_ok
			& all_cores_idle_delayed & input_empty;

		// 2 writes into same memory in different FSM states -
		// it doesn't optimize into DRAM, creates array of FFs
		if (wr_state == WR_STATE_WRITE_CORE & wr_instance_num_eq_minus2
				| wr_state == WR_STATE_INIT)
			batch_num[wr_core_num] <= wr_state == WR_STATE_INIT ? {`NUM_BATCHES_MSB+1{1'b0}}
				: batch_num_r == `NUM_BATCHES-1
				? {`NUM_BATCHES_MSB+1{1'b0}} : batch_num_r + 1'b1;

		case (wr_state)
		WR_STATE_INIT: begin
			// initialize memory content
			//batch_num[wr_core_num] <= batch_num_r; <-- creates FFs
			wr_core_num <= wr_core_num_next;
			if (wr_core_num == NUM_CORES-1)
				wr_state <= WR_STATE_WAIT;
		end

		WR_STATE_WAIT: begin
			gen_end_r <= 0;
			batch_num_r <= batch_num[wr_core_num];

			// New comparator configuration is ready.
			// Finish processing of data from input fifo
			// and wait for all computations to finish
			// before loading new comparator configuration.
			if (new_cmp_config_r) begin
				wr_state <= WR_STATE_CONFIG_SALT;
				cmp_config_applied <= 1;
			end

			else if (~input_empty) begin
				// Empty packet (1 cand. with gen_end) - skip it
				if (~pkt_id_num_ok & gen_end_in) begin
				end
				// Core is dummy - skip it
				//else if (CORES_CONF[wr_core_num*16 + 15]) begin
				else if (DUMMY_CORES[wr_core_num]) begin
					wr_core_num_wait <= 0;
					wr_core_num <= wr_core_num_next;
				end
				else if (wr_core_num_wait & crypt_ready_r) begin
					wr_state <= WR_STATE_WRITE_CORE;
					// Store ID of a packet being accounted
					if (~pkt_id_num_ok) begin
						pkt_id_num[pkt_num] <= pkt_id_in;
						pkt_id_num_ok <= 1;
					end
				end
				else
					wr_core_num_wait <= 1;
			end
		end

		WR_STATE_WRITE_CORE: begin
			wr_core_num_wait <= 0;

			// write batch of NUM_CRYPT_INSTANCES candidates.
			// if there's no enough candidates on input, don't wait, write empty candidates
			// (that's a requirement from the core)
			if (wr_instance_num_eq_minus2) begin
				wr_core_num <= wr_core_num_next;
				//batch_num[wr_core_num] <= batch_num_r == `NUM_BATCHES-1 <-- creates FFs
				//		? {`NUM_BATCHES_MSB+1{1'b0}} : batch_num_r + 1'b1;
			end

			if (wr_instance_num_eq_minus1) begin
				pkt_num_batches_r <= pkt_num_batches_r + 1'b1;
				wr_state <= WR_STATE_START_COMPUTATION;
			end
			wr_instance_num <= wr_instance_num + 1'b1;

			// gen_end_in - this is the last candidate in the packet
			// For easier accounting, candidates in a batch must have same pkt_id
			// (after packet ends, add-up empty candidates)
			if (gen_end_in)
				gen_end_r <= 1;

			if (key_valid)
				pkt_num_processed_r <= pkt_num_processed_r + 1'b1;

			if (~cmp_configured)
				err_cmp_no_conf <= 1;
		end

		WR_STATE_START_COMPUTATION: begin
			wr_instance_num <= 0;

			batch_num_r <= batch_num[wr_core_num];

			// packet accounting - count batches
			if (gen_end_r) begin
				pkt_num_batches[pkt_num] <= pkt_num_batches_r;
				pkt_num_batches_r <= 0;
				pkt_num_processed[pkt_num] <= pkt_num_processed_r;
				pkt_num_processed_r <= 0;
				pkt_done[pkt_num] <= 1;
				if (~pkt_full) begin // start accounting a new packet
					pkt_num <= pkt_num == `NUM_PKTS-1 ? {`NUM_PKTS_MSB+1{1'b0}} : pkt_num + 1'b1;
					pkt_id_num_ok <= 0;
					wr_state <= WR_STATE_WAIT;
				end
				else
					wr_state <= WR_STATE_PKT_ACCOUNT_WAIT;
			end
			else begin
				if (~input_empty & crypt_ready_r
						//& ~CORES_CONF[wr_core_num*16 + 15])
						& ~DUMMY_CORES[wr_core_num])
					wr_state <= WR_STATE_WRITE_CORE;
				else
					wr_state <= WR_STATE_WAIT;
			end
		end

		WR_STATE_CONFIG_SALT: begin
			cmp_config_applied <= 0;
			cmp_config_full <= 0;
			wr_state <= WR_STATE_CONFIG_HASH;
		end

		WR_STATE_CONFIG_HASH: begin
			if (cmp_config_wr_en & hash_end) begin
				cmp_config_full <= 1;
				cmp_configured <= 1;
				wr_state <= WR_STATE_WAIT;
			end
		end

		WR_STATE_PKT_ACCOUNT_WAIT: begin
			// Wait until there's a slot for packet accounting
			if (~pkt_full) begin
				pkt_num <= pkt_num == `NUM_PKTS-1 ? {`NUM_PKTS_MSB+1{1'b0}} : pkt_num + 1'b1;
				pkt_id_num_ok <= 0;
				wr_state <= WR_STATE_WAIT;
			end
		end
		endcase
	end

	wire key_valid = input_rd_en & ~gen_end_in;

	// Extra register stage before write to cores
	reg [`MSB(NUM_CORES-1):0] wr_core_num_r1 = 0, wr_core_num_r2 = 0;
	always @(posedge CORE_CLK) begin
		wr_core_num_r1 <= wr_core_num;
		wr_core_num_r2 <= wr_core_num_r1;
	end

	always @(posedge CORE_CLK)
		core_din <=
			wr_state == WR_STATE_CONFIG_HASH ? { hash_addr, hash_valid, hash } :
			wr_state == WR_STATE_CONFIG_SALT ? { addr_diff, addr_start, salt[`GLOBAL_SALT_LSB-1:0] } :
			wr_state == WR_STATE_START_COMPUTATION ? { pkt_num, batch_num_r } :
			{ key_valid, key56_pc1 };

	always @(posedge CORE_CLK)
		core_addr_in <=
			wr_state == WR_STATE_WRITE_CORE ? 3'b100 :
			wr_state == WR_STATE_START_COMPUTATION ? 3'b110 :
			wr_state == WR_STATE_CONFIG_SALT ? 3'b010 :
			3'b001;

	generate
	for (i=0; i < NUM_CORES; i=i+1) begin:core_wr_en_gen
		always @(posedge CORE_CLK)
			core_wr_en[i] <=
				i == wr_core_num_r2 & (wr_state == WR_STATE_WRITE_CORE | wr_state == WR_STATE_START_COMPUTATION)
				// broadcast write cmp_config to all cores
				| wr_state == WR_STATE_CONFIG_SALT | wr_state == WR_STATE_CONFIG_HASH & cmp_config_wr_en;
	end
	endgenerate


	// *******************************************************************
	//
	// While candidates are computed in cores their IDs are stored in RAM.
	// For each core, it requires NUM_CRYPT_INSTANCES * `NUM_BATCHES rows of RAM.
	//
	// *******************************************************************

	localparam RAM_WIDTH = 1 + 32 + 16; // 6 bytes (using CRC bits)
	localparam RAM_DEPTH = NUM_CORES * `NUM_BATCHES * NUM_CRYPT_INSTANCES; // 32 * 4 * 16 = 2K
	localparam RAM_ADDR_MSB = `MSB(RAM_DEPTH-1);

	(* RAM_STYLE = "BLOCK" *)
	reg [RAM_WIDTH-1:0] ram [RAM_DEPTH-1:0];
	initial
		for (k=0; k < RAM_DEPTH; k=k+1)
			ram[k] = 0;

	wire [RAM_ADDR_MSB:0] ram_write_addr = { wr_core_num_r2, batch_num_r, wr_instance_num };

	always @(posedge CORE_CLK)
		if (wr_state == WR_STATE_WRITE_CORE)
			ram[ram_write_addr] <= { key_valid, gen_id_in, word_id_in };


	// ***************************************
	//
	// Cores
	// Each core has NUM_CRYPT_INSTANCES
	// and processes `NUM_BATCHES at the same time in sequence
	//
	//
	// Cores (with wrappers) moved to upper-level module
	//
	// *************************************************

	// Output from cores [(un?)packed], for usage with multiplexers
	wire [3:0] core_dout [NUM_CORES-1:0];
	
	reg [NUM_CORES-1:0] core_rd_en = 0;
	wire [NUM_CORES-1:0] core_empty, err_core_dout_out;
	
	generate
	for (i=0; i < NUM_CORES; i=i+1) begin:core_dout_gen

		// Process serialized output from core
		core_dout_proc core_dout_proc(
			.CLK(CMP_CLK),
			.core_dout_in(core_dout_in[4*i+3 : 4*i]),
			.core_dout_ready(core_dout_ready[i]),
			
			.dout(core_dout[i]),
			.empty(core_empty[i]), .rd_en(core_rd_en[i]),
			.err_core_dout(err_core_dout_out[i]) 
		);

	end
	endgenerate

	always @(posedge CORE_CLK) begin
		crypt_ready <= crypt_ready_out;
		core_idle <= core_idle_out;
		core_err <= core_err_out;
	end


	// ***************************************
	//
	// Read cores (independently from write),
	// process core output.
	// (CMP_CLK is used)
	//
	// ***************************************
	reg [`MSB(NUM_CORES-1):0] rd_core_num = 0;
	reg [3:0] data = 0;
	always @(posedge CMP_CLK)
		 data <= core_dout[rd_core_num];

	reg [`NUM_BATCHES_MSB:0] dout_batch_num_r;
	reg [`NUM_PKTS_MSB:0] dout_pkt_num_r = 0;
	reg dout_equal_r = 0, dout_batch_complete_r = 0, dout_key_valid_r = 0;
	reg [`MSB(NUM_CRYPT_INSTANCES-1):0] dout_instance_r;
	reg [`RAM_ADDR_MSB:0] dout_hash_num_r;

	// packet accounting (process dout_pkt_num_r from core)
	reg [`PKT_BATCHES_MSB:0] pkt_num_batches_rd [`NUM_PKTS-1:0];
	reg [`PKT_BATCHES_MSB:0] pkt_num_batches_rd_r = 0;
	reg [`NUM_PKTS_MSB:0] pkt_num_done_rd;

	reg pkt_done_rd = 0;
	sync_ack sync_pkt_done_rd(
		.sig(pkt_done_rd), .wr_clk(CMP_CLK), .busy(pkt_done_rd_busy),
		.rd_clk(CORE_CLK), .out(pkt_done_rd_sync), .done(wr_state_pkt_done_rd)
	);

	localparam	RD_STATE_INIT = 0,
					RD_STATE_READ_CORE = 1,
					RD_STATE_READ_PREPARE = 15,
					RD_STATE_READ0 = 12,
					RD_STATE_READ1 = 7,
					RD_STATE_READ2 = 8,
					RD_STATE_READ3 = 9,
					RD_STATE_READ4 = 10,
					RD_STATE_READ5 = 11,
					RD_STATE_LOOKUP0 = 2,
					RD_STATE_LOOKUP1 = 3,
					RD_STATE_OUTPUT_CMP_EQUAL = 4,
					RD_STATE_PKT_ACCOUNT0 = 14,
					RD_STATE_PKT_ACCOUNT = 5,
					RD_STATE_PKT_ACCOUNT2 = 13,
					RD_STATE_OUTPUT_PACKET_DONE = 6;

	(* FSM_EXTRACT="true", FSM_ENCODING="one-hot" *)
	reg [3:0] rd_state = RD_STATE_INIT;

	// RAM lookup.
	reg key_valid_ram = 0;
	reg [31:0] gen_id_ram = 0;
	reg [15:0] word_id_ram = 0;

	wire [RAM_ADDR_MSB:0] ram_read_addr = { rd_core_num, dout_batch_num_r, dout_instance_r };
	always @(posedge CMP_CLK)
		if (rd_state == RD_STATE_READ3)
			{key_valid_ram, gen_id_ram, word_id_ram} <= ram[ram_read_addr];


	always @(posedge CMP_CLK) begin
		if (rd_state == RD_STATE_INIT | rd_state == RD_STATE_OUTPUT_PACKET_DONE
				| rd_state == RD_STATE_PKT_ACCOUNT)
			pkt_num_batches_rd[dout_pkt_num_r] <= pkt_num_batches_rd_r;

		case(rd_state)
		RD_STATE_INIT: begin
			//pkt_num_batches_rd[dout_pkt_num_r] <= pkt_num_batches_rd_r; <-- creates FFs
			if (dout_pkt_num_r == `NUM_PKTS - 1)
				rd_state <= RD_STATE_READ_CORE;
			else
				dout_pkt_num_r <= dout_pkt_num_r + 1'b1;
		end

		RD_STATE_READ_CORE: begin
			if (core_empty[rd_core_num]) begin
				if (rd_core_num == NUM_CORES-1)
					rd_core_num <= 0;
				else
					rd_core_num <= rd_core_num + 1'b1;
			end
			else begin
				core_rd_en[rd_core_num] <= 1;
				rd_state <= RD_STATE_READ_PREPARE;
			end
		end

		RD_STATE_READ_PREPARE:
			rd_state <= RD_STATE_READ0;

		RD_STATE_READ0: begin
			if (~data[0])
				err_core_output <= 1;
			{ dout_batch_num_r, dout_pkt_num_r } <= data[3:1];
			rd_state <= RD_STATE_READ1;
		end

		RD_STATE_READ1: begin
			//{ dout_key_valid_r, dout_equal_r, dout_batch_complete_r } <= data[2:0];
			{ dout_equal_r, dout_batch_complete_r } <= data[1:0];
			if (~data[2] & data[1] || ~data[1] & ~data[0])
				err_core_output <= 1;

			pkt_id_out <= pkt_id_num[dout_pkt_num_r];
			pkt_num_batches_rd_r <= pkt_num_batches_rd[dout_pkt_num_r];// + 1'b1;

			if (data[1]) // dout_equal_r
				rd_state <= RD_STATE_READ2;
			else begin
				core_rd_en[rd_core_num] <= 0; // 1 excess read - OK
				rd_state <= RD_STATE_PKT_ACCOUNT0;
			end
		end

		RD_STATE_READ2: begin
			dout_instance_r <= data;
			rd_state <= RD_STATE_READ3;
		end

		RD_STATE_READ3: begin // read from RAM, get IDs
			dout_hash_num_r[3:0] <= data;
			rd_state <= RD_STATE_READ4;
		end

		RD_STATE_READ4: begin // RAM output available
			dout_hash_num_r[7:4] <= data;
			gen_id_out <= gen_id_ram;
			word_id_out <= word_id_ram;
			rd_state <= RD_STATE_READ5;
		end

		RD_STATE_READ5: begin
			core_rd_en[rd_core_num] <= 0; // 1 excess read - OK
			dout_hash_num_r[`RAM_ADDR_MSB:8] <= data[`RAM_ADDR_MSB-8:0];
			rd_state <= RD_STATE_OUTPUT_CMP_EQUAL;
		end

		RD_STATE_OUTPUT_CMP_EQUAL: begin
			if (rd_en & ~empty) begin
				if (dout_batch_complete_r)
					rd_state <= RD_STATE_PKT_ACCOUNT0;
				else
					rd_state <= RD_STATE_READ_CORE;
			end
		end

		RD_STATE_PKT_ACCOUNT0: begin
			pkt_num_batches_rd_r <= pkt_num_batches_rd_r + 1'b1;
			rd_state <= RD_STATE_PKT_ACCOUNT;
		end

		RD_STATE_PKT_ACCOUNT: begin
			if (pkt_done[dout_pkt_num_r]
					& pkt_num_batches[dout_pkt_num_r] == pkt_num_batches_rd_r) begin
				rd_state <= RD_STATE_PKT_ACCOUNT2;
			end
			else begin
				// continue packet accounting
				//pkt_num_batches_rd[dout_pkt_num_r] <= pkt_num_batches_rd_r; <-- creates FFs
				rd_state <= RD_STATE_READ_CORE;
			end
		end

		RD_STATE_PKT_ACCOUNT2: begin
			pkt_num_done_rd <= dout_pkt_num_r;
			pkt_done_rd <= 1;
			pkt_num_batches_rd_r <= 0;
			num_processed_out <= pkt_num_processed[dout_pkt_num_r];
			rd_state <= RD_STATE_OUTPUT_PACKET_DONE;
		end

		RD_STATE_OUTPUT_PACKET_DONE: begin
			pkt_done_rd <= 0;
			//pkt_num_batches_rd[dout_pkt_num_r] <= pkt_num_batches_rd_r; <-- creates FFs
			if (pkt_done_rd_busy) begin // delay until synchronization complete
			end
			else if (rd_en & ~empty)
				rd_state <= RD_STATE_READ_CORE;
		end
		endcase
	end


	// ***************************************
	//
	// Output core results.
	//
	// ***************************************

	assign empty = ~(
		dout_equal_r & rd_state == RD_STATE_OUTPUT_CMP_EQUAL
		| dout_batch_complete_r & rd_state == RD_STATE_OUTPUT_PACKET_DONE
			& ~pkt_done_rd_busy
	);

	assign pkt_type_out =
		rd_state == RD_STATE_OUTPUT_CMP_EQUAL		? 2'b01 :
		rd_state == RD_STATE_OUTPUT_PACKET_DONE	? 2'b10 :
	2'b0;

	assign hash_num_eq = dout_hash_num_r;

	always @(posedge CMP_CLK) begin
		// error signal from comparator
		//if (|err_cmp_out)
		//	err_cmp <= 1;
		// bad output from core (at wrapper)
		if (|err_core_dout_out)
			err_core_dout <= 1;
		// error in RAM content (or core output)
		if (rd_state == RD_STATE_READ4 & ~key_valid_ram)
			err_rd_ram <= 1;
	end

	// Watchdog: data was sent to cores, no output in 1K cycles,
	// it doesn't assert on any other error.
	watchdog #( .NBITS(10) ) watchdog_core_read_timeout(
		.START_CLK(CORE_CLK), .start(wr_state == WR_STATE_START_COMPUTATION),
		.RESET_CLK(CMP_CLK), .reset(rd_state != RD_STATE_READ_CORE),
		.CLK(CMP_CLK), .timeout(watchdog_timeout)
	);
	always @(posedge CMP_CLK)
		if (watchdog_timeout)
			err_watchdog <= 1;

endmodule

`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016-2017,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "bcrypt.vh"

`ifdef	SIMULATION

module bcrypt #(
	parameter NUM_CORES = 12, // Actually number of proxies
	parameter VERSION = `PKT_COMM_VERSION,
	parameter PKT_MAX_LEN = 16*65536,
	parameter PKT_LEN_MSB = `MSB(PKT_MAX_LEN),
	parameter WORD_MAX_LEN = `PLAINTEXT_LEN,
	parameter CHAR_BITS = `CHAR_BITS,
	parameter RANGES_MAX = `RANGES_MAX,
	parameter RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1),
	parameter SIMULATION = 0
	)(
	input CORE_CLK,

	// I/O using hs_io_v2
	input IFCLK,
	input [15:0] hs_input_din,
	input hs_input_wr_en,
	output hs_input_almost_full,
	output hs_input_prog_full,

	output [15:0] output_dout,
	input output_rd_en,
	output output_empty,
	output [15:0] output_limit,
	output output_limit_not_done,
	input output_mode_limit,
	input reg_output_limit,

	// Status signals for internal usage
	output idle,
	output reg error_r = 0,

	// control input (VCR interface)
	input [7:0] app_mode,
	// status output (VCR interface)
	output [7:0] app_status,
	output [7:0] pkt_comm_status,
	output [7:0] debug2, debug3,
	//output [255:0] debug,

	input mode_cmp,
	// Cores are moved to top-level module.
	output [7:0] core_din,
	output [1:0] core_ctrl,
	output [NUM_CORES-1:0] core_wr_en,
	input [NUM_CORES-1:0] core_init_ready, core_crypt_ready,
	output [NUM_CORES-1:0] core_rd_en,
	input [NUM_CORES-1:0] core_empty,
	input [NUM_CORES-1:0] core_dout
	);

	assign CLK = CORE_CLK;

	// ********************************************************
	//
	// Input buffer (via High Speed interface)
	//
	// ********************************************************
	wire [7:0] din;

	input_fifo input_fifo(
		.wr_clk(IFCLK),
		.din(hs_input_din), // to Cypress IO
		.wr_en(hs_input_wr_en), // to Cypress IO
		.full(),
		.almost_full(hs_input_almost_full),
		.prog_full(hs_input_prog_full), // to Cypress IO

		.rd_clk(CLK),
		.dout(din),
		.rd_en(rd_en),
		.almost_empty(),
		.empty(empty)
	);


	// ********************************************************
	//
	// Output buffer (via High-Speed interface)
	//
	// ********************************************************
	wire [15:0] dout;

	output_fifo output_fifo(
		.wr_clk(CLK),
		.din(dout),
		.wr_en(wr_en),
		.full(full),
		.idle(output_fifo_idle),

		.rd_clk(IFCLK),
		.dout(output_dout), // to Cypress IO,
		.rd_en(output_rd_en),
		.empty(output_empty),

		.mode_limit(output_mode_limit),
		.reg_output_limit(reg_output_limit),
		.output_limit(output_limit),
		.output_limit_not_done(output_limit_not_done)
	);

	// ********************************************************

	assign pkt_comm_status = {
		err_cmp_config, err_word_gen_conf, err_template, err_word_list_count,
		err_pkt_version, err_inpkt_type, err_inpkt_len, err_inpkt_checksum
	};

	// Application error or pkt_comm error: Stop clock generation.
	always @(posedge CLK)
		if (|app_status | |pkt_comm_status)
			error_r <= 1;

	// IDLE status: Turn off clock buffer (clock remains running).
	delay #(.INIT(1), .NBITS(6)) delay_idle_inst (.CLK(IFCLK),
		.in(~hs_input_wr_en // no write into input fifo (IFCLK)
			& output_fifo_idle // output "prepend" fifo is empty (IFCLK)
			& pkt_comm_idle_sync
			& arbiter_idle_sync
		),
		.out(idle) );

	reg rd_en_r = 0;
	always @(posedge CLK)
		rd_en_r <= rd_en;

	sync_sig sync_pkt_comm_idle( .sig(~rd_en_r
			& word_list_empty & word_gen_empty & ek_empty),
		.clk(IFCLK), .out(pkt_comm_idle_sync) );

	sync_sig sync_arbiter_idle( .sig(arbiter_idle),
		.clk(IFCLK), .out(arbiter_idle_sync) );


	// **************************************************
	//
	// Application: read packets
	// process data base on packet type
	//
	// **************************************************

	localparam PKT_TYPE_WORD_LIST = 1;
	localparam PKT_TYPE_WORD_GEN = 2;
	localparam PKT_TYPE_CMP_CONFIG = 3;
	localparam PKT_TYPE_TEMPLATE_LIST = 4;

	localparam PKT_MAX_TYPE = 4;


	wire [`MSB(PKT_MAX_TYPE):0] inpkt_type;
	wire [15:0] inpkt_id;

	inpkt_header #(
		.VERSION(VERSION),
		.PKT_MAX_LEN(PKT_MAX_LEN),
		.PKT_MAX_TYPE(PKT_MAX_TYPE),
		.DISABLE_CHECKSUM(SIMULATION)
	) inpkt_header(
		.CLK(CLK),
		.din(din),
		.wr_en(rd_en),
		.pkt_type(inpkt_type), .pkt_id(inpkt_id), .pkt_data(inpkt_data),
		.pkt_end(inpkt_end),
		.err_pkt_version(err_pkt_version), .err_pkt_type(err_inpkt_type),
		.err_pkt_len(err_inpkt_len), .err_pkt_checksum(err_inpkt_checksum)
	);

	// input packet processing: read enable
	assign rd_en = ~empty
			& (~inpkt_data | word_gen_conf_en | word_list_wr_en | cmp_config_wr_en);


	// **************************************************
	//
	// input packet types PKT_TYPE_WORD_LIST (0x01),
	// PKT_TYPE_TEMPLATE_LIST (0x04)
	//
	// **************************************************
	wire word_list_wr_en = ~empty
			& (inpkt_type == PKT_TYPE_WORD_LIST || inpkt_type == PKT_TYPE_TEMPLATE_LIST)
			& inpkt_data & ~word_list_full;


	wire [7:0] word_list_dout;
	wire [`MSB(WORD_MAX_LEN-1):0] word_rd_addr;
	wire [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info;
	wire [15:0] word_id;

	// template_list_b: stores input words in 8-bit wide memory
	template_list_b #(
		.WORD_MAX_LEN(WORD_MAX_LEN), .RANGES_MAX(RANGES_MAX)
	) word_list(
		.CLK(CLK), .din(din),
		.wr_en(word_list_wr_en), .full(word_list_full), .inpkt_end(inpkt_end),
		.is_template_list(inpkt_type == PKT_TYPE_TEMPLATE_LIST),

		.dout(word_list_dout), .rd_addr(word_rd_addr),
		.set_empty(word_list_set_empty), .empty(word_list_empty),
		.range_info(range_info), .word_id(word_id), .word_list_end(word_list_end),

		.err_template(err_template), .err_word_list_count(err_word_list_count)
	);


	// **************************************************
	//
	// input packet type PKT_TYPE_WORD_GEN (0x02)
	//
	// **************************************************
	wire word_gen_conf_en = ~empty
			& inpkt_type == PKT_TYPE_WORD_GEN & inpkt_data & ~word_gen_conf_full;

	wire [7:0] word_gen_dout;
	wire [`MSB(WORD_MAX_LEN-1):0] word_gen_rd_addr;
	wire [15:0] pkt_id, word_id_out;
	wire [31:0] gen_id;

	word_gen_b #(
		.RANGES_MAX(RANGES_MAX), .WORD_MAX_LEN(WORD_MAX_LEN)
	) word_gen(
		.CLK(CLK), .din(din),
		.inpkt_id(inpkt_id), .conf_wr_en(word_gen_conf_en), .conf_full(word_gen_conf_full),

		.word_in(word_list_dout), .word_rd_addr(word_rd_addr),
		.word_set_empty(word_list_set_empty), .word_empty(word_list_empty),
		.range_info(range_info), .word_id(word_id), .word_list_end(word_list_end),

		.dout(word_gen_dout), .rd_addr(word_gen_rd_addr),
		.set_empty(word_gen_set_empty), .empty(word_gen_empty),
		.pkt_id(pkt_id), .word_id_out(word_id_out),
		.gen_id(gen_id), .gen_end(gen_end), .word_end(),

		.err_word_gen_conf(err_word_gen_conf)
	);


	// OK. Got words with ID's.
	//
	//wire [7:0] word_gen_dout; <-- in memory accessed with word_gen_rd_addr
	//wire [15:0] pkt_id, word_id_out;
	//wire [31:0] gen_id;
	//wire gen_end;

	assign debug2 = 8'hd2;
	assign debug3 = 8'hd3;


	// *************************************************************

	wire [2:0] bcdata_error;
	wire [3:0] arbiter_error;

	assign app_status = {
		1'b0, bcdata_error,
		arbiter_error
	};

	// **************************************************
	//
	// input packet type CMP_CONFIG (0x03)
	//
	// **************************************************
	wire cmp_config_wr_en = ~empty
			& inpkt_type == PKT_TYPE_CMP_CONFIG & inpkt_data & ~cmp_config_full;

	wire [`HASH_COUNT_MSB:0] hash_count;
	wire [`HASH_NUM_MSB+2:0] cmp_wr_addr;
	wire [7:0] cmp_din;

	// Data processed by cmp_config stored in cmp_config's memory
	// and accessed asynchronously
	wire [3:0] cmp_config_addr;
	wire [31:0] cmp_config_dout;

	bcrypt_cmp_config cmp_config(
		.CLK(CLK), .din(din), .wr_en(cmp_config_wr_en), .full(cmp_config_full),
		.mode_cmp(mode_cmp),
		.error(err_cmp_config),

		.hash_count(hash_count), .cmp_wr_addr(cmp_wr_addr),
		.cmp_wr_en(cmp_wr_en), .cmp_din(cmp_din),

		.new_cmp_config(new_cmp_config), .cmp_config_applied(cmp_config_applied),
		.addr(cmp_config_addr), .dout(cmp_config_dout), .sign_extension_bug(sign_extension_bug)
	);


	// **************************************************
	//
	// Read plaintext candidate from word generator.
	// Create expanded key (EK) out of plaintext key.
	// EK is 18 words x 32 bit.
	//
	// **************************************************
	wire [31:0] ek_dout;

	bcrypt_expand_key_b bcrypt_expand_key(
		.CLK(CLK),
		.din(word_gen_dout), .rd_addr(word_gen_rd_addr),
		.word_set_empty(word_gen_set_empty), .word_empty(word_gen_empty),
		.sign_extension_bug(sign_extension_bug),

		.dout(ek_dout), .rd_en(ek_rd_en), .empty(ek_empty)
	);


	// **************************************************
	//
	// bcrypt_data concentrates all the data required for computation.
	//
	// - constant P (18 x32bit)
	// - IDs: 2x32 (*)
	// - data for comparator (**)
	// - iteration count: 1x32 (**)
	// - expanded key (EK): 18x32 (*)
	// - salt: 4x32 (**)
	// - constant S (1024 x32bit)
	// (*) - taken from word generator
	// (**) - taken from cmp_config module.
	//
	// Data is send to cores over 32-bit data bus in the order listed above.
	//
	// **************************************************
	assign ek_rd_en = ~ek_empty & ~bcrypt_data_ek_full;
	wire [7:0] bcdata_dout;
	wire [1:0] bcdata_ctrl;
	wire [15:0] bcdata_pkt_id;

	bcrypt_data bcrypt_data(
		.CLK(CLK),
		.pkt_id(pkt_id), .word_id(word_id_out), .gen_id(gen_id), .gen_end(gen_end),
		// read expanded key (EK)
		.ek_in(ek_dout),
		.ek_wr_en(ek_rd_en), .ek_full(bcrypt_data_ek_full), .ek_valid(~ek_empty),

		.new_cmp_config(new_cmp_config), .cmp_config_applied(cmp_config_applied),
		// read cmp_config's local memory
		.cmp_config_addr(cmp_config_addr), .cmp_config_data(cmp_config_dout),

		// Data output to cores
		.dout(bcdata_dout), .ctrl(bcdata_ctrl),
		// Control exchange with arbiter
		.bcdata_gen_end(bcdata_gen_end), .bcdata_pkt_id(bcdata_pkt_id),
		.init_ready(bcdata_init_ready), .data_ready(bcdata_ready),
		.start_init_tx(start_init_tx), .start_data_tx(start_data_tx),
		.init_tx_done(), .data_tx_done(),

		.error(bcdata_error)
	);


	// **********************************************************
	//
	// Arbiter
	//
	// - 2 types of transfer from bcdata: initialization transfer
	//   and data transfer (that contains everything required
	//   for computation of 1 hash)
	// - distributes data among cores
	// - gathers results
	// - summarizes results.
	//
	// **********************************************************
	wire [31:0] cmp_data;
	wire [`HASH_NUM_MSB:0] cmp_hash_num;

	wire [`OUTPKT_TYPE_MSB:0] outpkt_type;
	wire [15:0] arbiter_pkt_id;
	wire [31:0] num_processed;
	wire [`HASH_NUM_MSB:0] hash_num;
	wire [15:0] arbiter_dout;
	wire [3:0] arbiter_rd_addr;

	bcrypt_arbiter #(
		.NUM_CORES(NUM_CORES)
		) arbiter(
		.CLK(CLK), .mode_cmp(mode_cmp),

		// Packages of data for cores
		.din(bcdata_dout), .ctrl(bcdata_ctrl),

		// Control exchange with bcrypt_data
		.init_ready(bcdata_init_ready), .data_ready(bcdata_ready),
		.start_init_tx(start_init_tx), .start_data_tx(start_data_tx),
		.bcdata_gen_end(bcdata_gen_end), .bcdata_pkt_id(bcdata_pkt_id),

		// Comparator
		.cmp_data(cmp_data), .cmp_start(cmp_start),
		.cmp_found(cmp_found), .cmp_finished(cmp_finished),
		.cmp_hash_num(cmp_hash_num),

		// Output (outpkt_bcrypt)
		.dout(arbiter_dout), .rd_addr(arbiter_rd_addr),
		.outpkt_type(outpkt_type), .pkt_id(arbiter_pkt_id),
		.num_processed(num_processed), .hash_num(hash_num),
		.empty(arbiter_empty), .rd_en(arbiter_rd_en),

		.error(arbiter_error), .idle(arbiter_idle),

		// Wrappers and cores are moved to top level module
		// for better usage of Hierarchial Design Methodology
		.core_din(core_din), .core_ctrl(core_ctrl),
		.core_wr_en(core_wr_en),
		.core_init_ready_in(core_init_ready), .core_crypt_ready_in(core_crypt_ready),
		.core_rd_en(core_rd_en), .core_empty_in(core_empty), .core_dout_in(core_dout)
	);


	// **************************************************
	//
	// Comparator
	// if mode_cmp=1 (the default) then computed hashes
	// appear in the comparator.
	//
	// **************************************************
	comparator comparator(
		.CLK(CLK),
		// cmp_config
		.din(cmp_din), .wr_en(cmp_wr_en),
		.wr_addr(cmp_wr_addr), .hash_count(hash_count),
		// arbiter (rx part)
		.cmp_data(cmp_data), .start(cmp_start),
		.found(cmp_found), .finished(cmp_finished), .hash_num(cmp_hash_num)
	);


	// ************************************************
	//
	// Create application packets from output data
	//
	// ************************************************

	assign arbiter_rd_en = ~arbiter_empty & ~outpkt_full;
	assign outpkt_wr_en = arbiter_rd_en;

	outpkt_bcrypt #(
		.HASH_NUM_MSB(`HASH_NUM_MSB), .SIMULATION(SIMULATION)
	) outpkt(
		.CLK(CLK),
		.din(arbiter_dout), .rd_addr(arbiter_rd_addr),
		.source_not_empty(~arbiter_empty),
		.wr_en(outpkt_wr_en), .full(outpkt_full),

		.pkt_type(outpkt_type), .pkt_id(arbiter_pkt_id),
		.hash_num(hash_num), .num_processed(num_processed),

		.dout(dout), .rd_en(wr_en), .empty(outpkt_empty), .pkt_end_out()
	);

	// Write data into output FIFO
	assign wr_en = ~outpkt_empty & ~full;


endmodule

`else

module bcrypt #(
	parameter NUM_CORES = 12,
	parameter VERSION = `PKT_COMM_VERSION,
	parameter PKT_MAX_LEN = 16*65536,
	parameter PKT_LEN_MSB = `MSB(PKT_MAX_LEN),
	parameter WORD_MAX_LEN = `PLAINTEXT_LEN,
	parameter CHAR_BITS = `CHAR_BITS,
	parameter RANGES_MAX = `RANGES_MAX,
	parameter RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1),
	parameter SIMULATION = 0
	)(
	input CORE_CLK,

	// I/O using hs_io_v2
	input IFCLK,
	input [15:0] hs_input_din,
	input hs_input_wr_en,
	output hs_input_almost_full,
	output hs_input_prog_full,

	output [15:0] output_dout,
	input output_rd_en,
	output output_empty,
	output [15:0] output_limit,
	output output_limit_not_done,
	input output_mode_limit,
	input reg_output_limit,

	// Status signals for internal usage
	output reg idle = 0, error_r = 0,

	// control input (VCR interface)
	input [7:0] app_mode,
	// status output (VCR interface)
	output [7:0] app_status,
	output [7:0] pkt_comm_status,
	output [7:0] debug2, debug3,
	//output [255:0] debug,

	input mode_cmp,
	// Cores are moved to top-level module.
	output [7:0] core_din,
	output [1:0] core_ctrl,
	output [NUM_CORES-1:0] core_wr_en,
	input [NUM_CORES-1:0] core_init_ready, core_crypt_ready,
	output [NUM_CORES-1:0] core_rd_en,
	input [NUM_CORES-1:0] core_empty,
	input [NUM_CORES-1:0] core_dout
	);

endmodule

`endif

module bcrypt_dummy #(
	parameter NUM_CORES = 12,
	parameter VERSION = `PKT_COMM_VERSION,
	parameter PKT_MAX_LEN = 16*65536,
	parameter PKT_LEN_MSB = `MSB(PKT_MAX_LEN),
	parameter WORD_MAX_LEN = `PLAINTEXT_LEN,
	parameter CHAR_BITS = `CHAR_BITS,
	parameter RANGES_MAX = `RANGES_MAX,
	parameter RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1),
	parameter SIMULATION = 0
	)(
	input CORE_CLK,

	// I/O using hs_io_v2
	input IFCLK,
	input [15:0] hs_input_din,
	input hs_input_wr_en,
	output hs_input_almost_full,
	output hs_input_prog_full,

	output [15:0] output_dout,
	input output_rd_en,
	output output_empty,
	output [15:0] output_limit,
	output output_limit_not_done,
	input output_mode_limit,
	input reg_output_limit,

	// Status signals for internal usage
	output reg idle = 0, error_r = 0,

	// control input (VCR interface)
	input [7:0] app_mode,
	// status output (VCR interface)
	output [7:0] app_status,
	output [7:0] pkt_comm_status,
	output [7:0] debug2, debug3,
	//output [255:0] debug,

	input mode_cmp,
	// Cores are moved to top-level module.
	output [7:0] core_din,
	output [1:0] core_ctrl,
	output [NUM_CORES-1:0] core_wr_en,
	input [NUM_CORES-1:0] core_init_ready, core_crypt_ready,
	output [NUM_CORES-1:0] core_rd_en,
	input [NUM_CORES-1:0] core_empty,
	input [NUM_CORES-1:0] core_dout
	);

	always @(posedge CORE_CLK)
		idle <= ^core_empty;

endmodule

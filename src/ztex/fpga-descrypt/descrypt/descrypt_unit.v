`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "descrypt_core/descrypt.vh"

//`define UNIT_INCLUDE_SRC

`ifdef UNIT_INCLUDE_SRC

/*
 * Contains:
 * - generator
 * - arbiter
 * - outpkt
 */
module descrypt_unit #(
	parameter NUM_CORES = 16,
	//parameter [16*NUM_CORES-1 : 0] CORES_CONF = 0,
	parameter WORD_MAX_LEN = `PLAINTEXT_LEN,
	parameter CHAR_BITS = `CHAR_BITS,
	parameter RANGES_MAX = `RANGES_MAX,
	parameter RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1)
	)(
	input [NUM_CORES-1:0] DUMMY_CORES,
	input PKT_COMM_CLK, WORD_GEN_CLK,
	input CORE_CLK, CMP_CLK,

	// Generator - configuration
	input [7:0] din,
	input [15:0] inpkt_id,
	input word_gen_conf_en,
	output word_gen_conf_full,
	output err_word_gen_conf,

	// Generator - input from word_list
	input [WORD_MAX_LEN * CHAR_BITS - 1:0] word_list_dout,
	input [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info,
	input [15:0] word_id,
	input word_list_end,
	input word_wr_en,
	output word_full,

	// Arbiter - Comparator configuration
	input [`GLOBAL_SALT_LSB-1:0] salt,
	input [`RAM_ADDR_MSB-1:0] addr_start, addr_diff,
	input hash_valid, hash_end,
	input [`HASH_MSB:0] hash,
	input [`RAM_ADDR_MSB:0] hash_addr,
	input cmp_config_wr_en,
	(* SHREG_EXTRACT="no" *)
	output reg cmp_config_full = 0,
	input new_cmp_config,
	(* SHREG_EXTRACT="no" *)
	output reg cmp_config_applied = 0, // got new_cmp_config signal, started handling of config
	output idle,
	output [7:0] arbiter_error,

	// Output
	output [15:0] outpkt_dout,
	output outpkt_end_out,
	input outpkt_rd_en,
	output outpkt_empty,

	// Cores are moved to upper level module
	input [NUM_CORES-1:0] crypt_ready_out, core_idle_out, core_err_out,
	output[NUM_CORES-1:0] core_wr_en,
	// Serialized output from cores
	// (task: move deserializer logic from nowhere to inside the unit)
	input [4*NUM_CORES-1:0] core_dout_in,
	output [NUM_CORES-1 :0] core_dout_ready,
	// Broadcast
	output [`DIN_MSB:0] core_din,
	output [2:0] core_addr_in
	);


	wire [WORD_MAX_LEN * CHAR_BITS - 1:0] word_gen_dout;
	wire [15:0] pkt_id, word_id_out;
	wire [31:0] gen_id;

	word_gen_v2 #(
		.CHAR_BITS(CHAR_BITS), .RANGES_MAX(RANGES_MAX), .WORD_MAX_LEN(WORD_MAX_LEN)
	) word_gen(
		// Generators are configured in broadcast manner
		.CLK(PKT_COMM_CLK), .din(din), .inpkt_id(inpkt_id),
		.wr_conf_en(word_gen_conf_en), .conf_full(word_gen_conf_full),

		.word_in(word_list_dout), .range_info(range_info),
		.word_id(word_id), .word_list_end(word_list_end),
		.word_wr_en(word_wr_en), .word_full(word_full),

		// Generation runs on WORD_GEN_CLK
		.WORD_GEN_CLK(WORD_GEN_CLK),
		.rd_en(word_gen_rd_en), .empty(word_gen_empty),
		.dout(word_gen_dout), .pkt_id(pkt_id), .word_id_out(word_id_out),
		.gen_id(gen_id), .gen_end(gen_end), .word_end(word_end),

		.err_word_gen_conf(err_word_gen_conf)
	);

	// *************************************************************

	localparam WORD_GEN_DOUT_WIDTH = 2 + 32 + 2*16 + WORD_MAX_LEN*CHAR_BITS;

	wire [WORD_GEN_DOUT_WIDTH-1:0] extra_reg_dout;

	extra_reg_afull #( .WIDTH(WORD_GEN_DOUT_WIDTH)
	) extra_reg(
		.CLK(WORD_GEN_CLK),
		.wr_en(word_gen_rd_en), .full(extra_reg_full),
		.din({word_end, gen_end, gen_id, pkt_id, word_id_out, word_gen_dout}),
		.afull(arbiter_almost_full), .rd_en(arbiter_wr_en), .empty(extra_reg_empty),
		.dout(extra_reg_dout)
	);

	// read from word_gen
	assign word_gen_rd_en = ~word_gen_empty & ~extra_reg_full;
	assign arbiter_wr_en = ~extra_reg_empty & ~arbiter_full;


	// extra register cmp_config -> arbiter
	// flowcontrol doesn't work
	(* EQUIVALENT_REGISTER_REMOVAL="no" *)
	reg hash_valid_r = 0, hash_end_r = 0;
	(* EQUIVALENT_REGISTER_REMOVAL="no" *)
	reg [`HASH_MSB:0] hash_r;
	(* EQUIVALENT_REGISTER_REMOVAL="no" *)
	reg [`RAM_ADDR_MSB:0] hash_addr_r;
	(* EQUIVALENT_REGISTER_REMOVAL="no" *)
	reg cmp_config_wr_en_r = 0, new_cmp_config_r = 0;

	always @(posedge CORE_CLK) begin
		new_cmp_config_r <= new_cmp_config;
		cmp_config_wr_en_r <= cmp_config_wr_en;
		hash_valid_r <= hash_valid;
		hash_end_r <= hash_end;
		hash_r <= hash;
		hash_addr_r <= hash_addr;

		cmp_config_full <= cmp_config_full_in;
		cmp_config_applied <= cmp_config_applied_in;
	end


	// *********************
	//
	// Arbiter
	//
	// *********************
	wire [`OUTPKT_TYPE_MSB:0] pkt_type_outpkt;
	wire [15:0] pkt_id_outpkt, word_id_outpkt;
	wire [`RAM_ADDR_MSB:0] hash_num_outpkt;
	wire [31:0] gen_id_outpkt, num_processed_outpkt;

	arbiter #(
		.NUM_CORES(NUM_CORES),
		//.CORES_CONF(CORES_CONF[16*NUM_CORES-1 : 0]),
		.WORD_GEN_DOUT_WIDTH(WORD_GEN_DOUT_WIDTH)
	) arbiter(
		.DUMMY_CORES(DUMMY_CORES),
		.WORD_GEN_CLK(WORD_GEN_CLK),
		.CORE_CLK(CORE_CLK), .CMP_CLK(CMP_CLK),

		// read from word_gen (with extra register)
		.word_gen_in(extra_reg_dout),
		.wr_en(arbiter_wr_en), .full(arbiter_full), .almost_full(arbiter_almost_full),

		.idle(idle), .error(arbiter_error),

		// read from cmp_config
		.salt(salt),
		.addr_start(addr_start), .addr_diff(addr_diff),
		//.num_hashes(num_hashes), .num_hashes_remain(num_hashes_remain),
//		.hash(hash), .hash_valid(hash_valid), .hash_addr(hash_addr), .hash_end(hash_end),
		//.lvl1_wr_en(lvl1_wr_en), .lvl2_wr_en(lvl2_wr_en),
//		.cmp_config_wr_en(cmp_config_wr_en), .cmp_config_full(cmp_config_full),
//		.new_cmp_config(new_cmp_config), .cmp_config_applied(cmp_config_applied),
		.hash(hash_r), .hash_valid(hash_valid_r), .hash_addr(hash_addr_r), .hash_end(hash_end_r),
		.cmp_config_wr_en(cmp_config_wr_en_r), .new_cmp_config(new_cmp_config_r),
		.cmp_config_full(cmp_config_full_in), .cmp_config_applied(cmp_config_applied_in),

		.pkt_type_out(pkt_type_outpkt), .gen_id_out(gen_id_outpkt), .pkt_id_out(pkt_id_outpkt),
		.word_id_out(word_id_outpkt), .num_processed_out(num_processed_outpkt),
		.hash_num_eq(hash_num_outpkt),
		.rd_en(arbiter_rd_en), .empty(arbiter_empty),

		// Cores are moved to upper level module
		.crypt_ready_out(crypt_ready_out), .core_idle_out(core_idle_out),
		.core_err_out(core_err_out), .core_wr_en(core_wr_en),
		// Serialized output from cores
		.core_dout_in(core_dout_in), .core_dout_ready(core_dout_ready),
		// Broadcast
		.core_din(core_din), .core_addr_in(core_addr_in)
	);


	// ************************************************
	//
	// Create application packets from output data
	//
	// ************************************************

	// read from arbiter
	assign arbiter_rd_en = ~arbiter_empty & ~outpkt_full;
	wire outpkt_wr_en = arbiter_rd_en;

	outpkt_v3 #(
		.HASH_NUM_MSB(`RAM_ADDR_MSB), .SIMULATION(0)
		) outpkt(
		.CLK(CMP_CLK), .wr_en(outpkt_wr_en), .full(outpkt_full),

		.pkt_type(pkt_type_outpkt),
		.pkt_id(pkt_id_outpkt), .word_id(word_id_outpkt),
		.gen_id(gen_id_outpkt), .num_processed(num_processed_outpkt),
		.hash_num(hash_num_outpkt),

		.dout(outpkt_dout), .pkt_end_out(outpkt_end_out),
		.rd_en(outpkt_rd_en), .empty(outpkt_empty)
	);


endmodule

`else

module descrypt_unit #(
	parameter NUM_CORES = 16,
	//parameter [16*NUM_CORES-1 : 0] CORES_CONF = 0,
	parameter WORD_MAX_LEN = `PLAINTEXT_LEN,
	parameter CHAR_BITS = `CHAR_BITS,
	parameter RANGES_MAX = `RANGES_MAX,
	parameter RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1)
	)(
	input [NUM_CORES-1:0] DUMMY_CORES,
	input PKT_COMM_CLK, WORD_GEN_CLK,
	input CORE_CLK, CMP_CLK,

	// Generator - configuration
	input [7:0] din,
	input [15:0] inpkt_id,
	input word_gen_conf_en,
	output word_gen_conf_full,
	output err_word_gen_conf,

	// Generator - input from word_list
	input [WORD_MAX_LEN * CHAR_BITS - 1:0] word_list_dout,
	input [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info,
	input [15:0] word_id,
	input word_list_end,
	input word_wr_en,
	output word_full,

	// Arbiter - Comparator configuration
	input [`GLOBAL_SALT_LSB-1:0] salt,
	input [`RAM_ADDR_MSB-1:0] addr_start, addr_diff,
	input hash_valid, hash_end,
	input [`HASH_MSB:0] hash,
	input [`RAM_ADDR_MSB:0] hash_addr,
	input cmp_config_wr_en,
	(* SHREG_EXTRACT="no" *)
	output reg cmp_config_full = 0,
	input new_cmp_config,
	(* SHREG_EXTRACT="no" *)
	output reg cmp_config_applied = 0, // got new_cmp_config signal, started handling of config
	output idle,
	output [7:0] arbiter_error,

	// Output
	output [15:0] outpkt_dout,
	output outpkt_end_out,
	input outpkt_rd_en,
	output outpkt_empty,

	// Cores are moved to upper level module
	input [NUM_CORES-1:0] crypt_ready_out, core_idle_out, core_err_out,
	output[NUM_CORES-1:0] core_wr_en,
	// Serialized output from cores
	// (task: move deserializer logic from nowhere to inside the unit)
	input [4*NUM_CORES-1:0] core_dout_in,
	output [NUM_CORES-1 :0] core_dout_ready,
	// Broadcast
	output [`DIN_MSB:0] core_din,
	output [2:0] core_addr_in
	);

endmodule

`endif

module descrypt_unit_dummy #(
	parameter NUM_CORES = 16,
	//parameter [16*NUM_CORES-1 : 0] CORES_CONF = 0,
	parameter WORD_MAX_LEN = `PLAINTEXT_LEN,
	parameter CHAR_BITS = `CHAR_BITS,
	parameter RANGES_MAX = `RANGES_MAX,
	parameter RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1)
	)(
	input [NUM_CORES-1:0] DUMMY_CORES,
	input PKT_COMM_CLK, WORD_GEN_CLK,
	input CORE_CLK, CMP_CLK,

	// Generator - configuration
	input [7:0] din,
	input [15:0] inpkt_id,
	input word_gen_conf_en,
	output word_gen_conf_full,
	output err_word_gen_conf,

	// Generator - input from word_list
	input [WORD_MAX_LEN * CHAR_BITS - 1:0] word_list_dout,
	input [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info,
	input [15:0] word_id,
	input word_list_end,
	input word_wr_en,
	output word_full,

	// Arbiter - Comparator configuration
	input [`GLOBAL_SALT_LSB-1:0] salt,
	input [`RAM_ADDR_MSB-1:0] addr_start, addr_diff,
	input hash_valid, hash_end,
	input [`HASH_MSB:0] hash,
	input [`RAM_ADDR_MSB:0] hash_addr,
	input cmp_config_wr_en,
	(* SHREG_EXTRACT="no" *)
	output reg cmp_config_full = 0,
	input new_cmp_config,
	(* SHREG_EXTRACT="no" *)
	output reg cmp_config_applied = 0, // got new_cmp_config signal, started handling of config
	output idle,
	output [7:0] arbiter_error,

	// Output
	output [15:0] outpkt_dout,
	output outpkt_end_out,
	input outpkt_rd_en,
	output outpkt_empty,

	// Cores are moved to upper level module
	input [NUM_CORES-1:0] crypt_ready_out, core_idle_out, core_err_out,
	output[NUM_CORES-1:0] core_wr_en,
	// Serialized output from cores
	// (task: move deserializer logic from nowhere to inside the unit)
	input [4*NUM_CORES-1:0] core_dout_in,
	output [NUM_CORES-1 :0] core_dout_ready,
	// Broadcast
	output [`DIN_MSB:0] core_din,
	output [2:0] core_addr_in
	);

endmodule

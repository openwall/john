`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "descrypt_core/descrypt.vh"

module descrypt #(
	parameter VERSION = `PKT_COMM_VERSION,
	parameter PKT_MAX_LEN = 16*65536,
	parameter PKT_LEN_MSB = `MSB(PKT_MAX_LEN),
	parameter WORD_MAX_LEN = `PLAINTEXT_LEN,
	parameter CHAR_BITS = `CHAR_BITS,
	parameter RANGES_MAX = `RANGES_MAX,
	parameter RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1),
	parameter DISABLE_CHECKSUM = 0
	)(
	input PKT_COMM_CLK,
	input WORD_GEN_CLK,
	input CORE_CLK,
	input CMP_CLK,

	// read from some internal FIFO (recieved via high-speed interface)
	input [7:0] din,
	output rd_en,
	input empty,

	// write into some internal FIFO (to be send via high-speed interface)
	output [15:0] dout,
	output wr_en,
	input full,
	output idle,

	// control input (VCR interface)
	input [7:0] app_mode,
	// status output (VCR interface)
	output [7:0] app_status,
	output [7:0] pkt_comm_status,
	output [7:0] debug2, debug3
	);


	// *****************************************************
	// NUM_WORD_GEN: Number of big units. Each unit includes
	// generator, arbiter, output, interface to cores
	//
	localparam NUM_WORD_GEN = 2;

	localparam [32*NUM_WORD_GEN-1:0] WORD_GEN_CONF = {
	// reserved |start_core_num |end_core_num
		16'b0, 8'd16, 8'd31,		// unit #1: cores 16-31
		16'b0, 8'd0, 8'd15		// unit #0: cores 0-15
	};

	// *****************************************************
	// Cores are connected to cores' interfaces with wrappers.
	//
	localparam NUM_WRAPPERS = 4;

	localparam [32*NUM_WRAPPERS-1:0] WRAPPERS_CONF = {
	// reserved |word_gen_num |start_core_num |end_core_num
		8'b0, 8'd1, 8'd25, 8'd31,	// wrapper #3: unit 1, cores 25-31
		8'b0, 8'd1, 8'd16, 8'd24,	// wrapper #2: unit 1, cores 16-24
		8'b0, 8'd0, 8'd8, 8'd15,	// wrapper #1: unit 0, cores 8-15
		8'b0, 8'd0, 8'd0, 8'd7		// wrapper #0: unit 0, cores 0-7
	};

	// *****************************************************
	// Cores are built separately.
	// Each one has independent configuration.
	//
	localparam NUM_CORES = 32;

	localparam [16*NUM_CORES-1:0] CORES_CONF = {
	// is_dummy |reserved |input_regs |output_regs
		// wrapper #3 (bottom right) - 7 cores
		1'b0, 7'b0, 4'd1, 4'd1,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd1, 4'd1,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd2, 4'd2,
		// wrapper #2 (top right) - 9 cores
		1'b0, 7'b0, 4'd1, 4'd1,
		1'b0, 7'b0, 4'd1, 4'd1,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd1, 4'd1,
		1'b0, 7'b0, 4'd1, 4'd1,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd2, 4'd2,
		// wrapper #1 (bottom left) - 8 cores
		1'b0, 7'b0, 4'd1, 4'd1,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd1, 4'd1,
		1'b0, 7'b0, 4'd1, 4'd1,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd2, 4'd2,
		// wrapper #0 (top left) - 8 cores
		1'b0, 7'b0, 4'd1, 4'd1,
		1'b0, 7'b0, 4'd1, 4'd1,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd1, 4'd1,
		1'b0, 7'b0, 4'd1, 4'd1,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd2, 4'd2,
		1'b0, 7'b0, 4'd2, 4'd2
	};

	// *****************************************************

	assign pkt_comm_status = {
		err_cmp_config, err_word_gen_conf, err_template, err_word_list_count,
		err_pkt_version, err_inpkt_type, err_inpkt_len, err_inpkt_checksum
	};	


	assign idle = ~rd_en & cmp_config_idle & app_idle_sync;

	sync_sig #( .INIT(1) ) sync_cores_idle(
		.sig(all_units_idle & word_list_empty),
		.clk(PKT_COMM_CLK), .out(app_idle_sync) );


	assign debug2 = app_mode;
	assign debug3 = 8'h00;

	genvar i, j;

	// **************************************************
	//
	// Read packets
	// Process data base on packet type
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
		.DISABLE_CHECKSUM(DISABLE_CHECKSUM)
	) inpkt_header(
		.CLK(PKT_COMM_CLK), 
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

	wire [WORD_MAX_LEN * CHAR_BITS - 1:0] word_list_dout;
	wire [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info;
	wire [15:0] word_id;

	template_list #(
		.CHAR_BITS(CHAR_BITS), .WORD_MAX_LEN(WORD_MAX_LEN), .RANGES_MAX(RANGES_MAX)
	) word_list(
		.wr_clk(PKT_COMM_CLK), .din(din), 
		.wr_en(word_list_wr_en), .full(word_list_full), .inpkt_end(inpkt_end),
		.is_template_list(inpkt_type == PKT_TYPE_TEMPLATE_LIST),

		.rd_clk(WORD_GEN_CLK),
		.dout(word_list_dout), .range_info(range_info), .word_id(word_id), .word_list_end(word_list_end),
		.rd_en(word_list_rd_en), .empty(word_list_empty),

		.err_template(err_template), .err_word_list_count(err_word_list_count)
	);


	// **************************************************
	//
	// Distribute input words among several word generators
	//
	// **************************************************
	localparam WORD_DATA_WIDTH = WORD_MAX_LEN * CHAR_BITS
			+ RANGES_MAX * (RANGE_INFO_MSB+1) + 16 + 1; // word + range_info + IDs + word_list_end

	assign word_list_rd_en = ~word_distrib_full & ~word_list_empty;

	wire [NUM_WORD_GEN*WORD_DATA_WIDTH-1:0] word_distrib_dout;
	wire [NUM_WORD_GEN-1:0] word_distrib_rd_en, word_distrib_empty;

	distributor #(
		.WIDTH(WORD_DATA_WIDTH), .N(NUM_WORD_GEN)
	) word_distrib(
		.CLK(WORD_GEN_CLK),
		.din({word_list_dout, range_info, word_id, word_list_end}),
		.bcast(word_list_end), .wr_en(word_list_rd_en), .full(word_distrib_full),

		.dout(word_distrib_dout),
		.rd_en(word_distrib_rd_en), .empty(word_distrib_empty)
	);


	// **************************************************
	//
	// input packet type CMP_CONFIG (0x03)
	//
	// **************************************************
	wire cmp_config_wr_en = ~empty
			& inpkt_type == PKT_TYPE_CMP_CONFIG & inpkt_data & ~cmp_config_full;

	// Data processed by cmp_config goes into dedicated inputs of arbiter
	wire [`GLOBAL_SALT_LSB-1:0] salt;
	wire [`GLOBAL_SALT_MSB:`GLOBAL_SALT_LSB] global_salt_in, global_salt;
	wire [`RAM_ADDR_MSB-1:0] addr_start, addr_diff;
	wire [`HASH_MSB:0] hash;
	wire [`RAM_ADDR_MSB:0] hash_addr;

	cmp_config cmp_config(
		.wr_clk(PKT_COMM_CLK), .din(din), .wr_en(cmp_config_wr_en),
		.full(cmp_config_full), .idle(cmp_config_idle),

		.rd_clk(CORE_CLK),
		.salt_out({global_salt_in, salt}),
		.read_addr_start(addr_start), .addr_diff_start(addr_diff),
		.hash_out(hash), .hash_valid(hash_valid), .hash_addr_out(hash_addr), .hash_end(hash_end),
		.rd_en(arbiter_cmp_config_wr_en), .empty(cmp_config_empty),
		.new_cmp_config(new_cmp_config), .config_applied(config_applied), 
		.error(err_cmp_config)
	);

	wire [NUM_WORD_GEN-1:0] cmp_config_applied;

	cmp_config_distrib #( .N(NUM_WORD_GEN)
	) cmp_config_distrib(
		.CLK(CORE_CLK),
		.new_cmp_config(new_cmp_config), .cmp_config_applied(cmp_config_applied),
		.all_cmp_config_applied(config_applied),

		.global_salt_in(global_salt_in), .global_salt_out(global_salt)
		//.num_hashes_in(num_hashes_in), .num_hashes_remain_in(num_hashes_remain_in),
		//.num_hashes(num_hashes), .num_hashes_remain(num_hashes_remain)
	);


	// **************************************************
	//
	// input packet type PKT_TYPE_WORD_GEN (0x02)
	// is handled by all generators at the same time
	//
	// **************************************************
	wire word_gen_conf_en = ~empty
			& inpkt_type == PKT_TYPE_WORD_GEN & inpkt_data & ~any_word_gen_conf_full;

	wire [NUM_WORD_GEN-1:0] word_gen_conf_full, word_gen_word_full, word_gen_conf_err;
	assign any_word_gen_conf_full = |word_gen_conf_full;
	assign err_word_gen_conf = |word_gen_conf_err;

	// Broadcast cmp_config
	wire [NUM_WORD_GEN-1:0] arbiter_cmp_config_full;
	assign arbiter_cmp_config_wr_en = ~(|arbiter_cmp_config_full) & ~cmp_config_empty;

	wire [NUM_WORD_GEN-1:0] unit_idle;
	assign all_units_idle = &unit_idle;

	// Arbiter errors
	wire [8*NUM_WORD_GEN-1:0] arbiter_error;
	square_OR #( .WIDTH(8), .N(NUM_WORD_GEN)
	) arbiter_error_OR( .din(arbiter_error), .dout(app_status) );

	// Arbiter outputs
	wire [16*NUM_WORD_GEN-1:0] outpkt_dout;
	wire [NUM_WORD_GEN-1:0] outpkt_end_out, outpkt_rd_en, outpkt_empty, outpkt_join_full;


	// **************************************************
	//
	// The design is divided into big units. Each one contains
	// generator, arbiter, number of cores, distribution network
	//
	// **************************************************
	wire [NUM_CORES-1:0] crypt_ready_out, core_idle_out, core_err_out;
	wire [NUM_CORES-1:0] core_wr_en;
	// Serialized output from cores
	wire [4*NUM_CORES-1:0] core_dout_in;
	wire [NUM_CORES-1:0] core_dout_ready;
	// Broadcast
	wire [(`DIN_MSB+1) * NUM_WORD_GEN-1:0] core_din;
	wire [3 * NUM_WORD_GEN-1:0] core_addr_in;

	generate
	for (i=0; i < NUM_WORD_GEN; i=i+1) begin:units

		wire [WORD_MAX_LEN * CHAR_BITS - 1:0] word_list_dout_in;
		wire [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info_in;
		wire [15:0] word_id_in;
		assign {word_list_dout_in, range_info_in, word_id_in, word_list_end_in}
				= word_distrib_dout[WORD_DATA_WIDTH*(i+1)-1 : WORD_DATA_WIDTH*i];

		assign word_distrib_rd_en[i] = ~word_distrib_empty[i] & ~word_gen_word_full[i];

		localparam START = WORD_GEN_CONF[32*i+15 -:8];
		localparam END = WORD_GEN_CONF[32*i+7 -:8];
		localparam NUM_CORES = END - START + 1;

		wire [NUM_CORES-1:0] DUMMY_CORES;
		for (j=0; j < NUM_CORES; j=j+1) begin:dummy_cores_init
			assign DUMMY_CORES[j] = CORES_CONF[(START+j)*16 + 15];
		end

		(* KEEP_HIERARCHY="true" *)
		descrypt_unit #(//_dummy #(
			.NUM_CORES(NUM_CORES)
			//.CORES_CONF(CORES_CONF[16*(END+1)-1 : 16*START])
		) unit(
			.DUMMY_CORES(DUMMY_CORES),
			.PKT_COMM_CLK(PKT_COMM_CLK), .WORD_GEN_CLK(WORD_GEN_CLK),
			.CORE_CLK(CORE_CLK), .CMP_CLK(CMP_CLK),

			// Generators are configured in broadcast manner
			.din(din), .inpkt_id(inpkt_id),
			.word_gen_conf_full(word_gen_conf_full[i]),
			.word_gen_conf_en(word_gen_conf_en),
			.err_word_gen_conf(word_gen_conf_err[i]),

			// words are transferred to word_gen (WORD_GEN_CLK)
			.word_list_dout(word_list_dout_in), .range_info(range_info_in),
			.word_id(word_id_in), .word_list_end(word_list_end_in),
			.word_wr_en(word_distrib_rd_en[i]), .word_full(word_gen_word_full[i]),

			// cmp_config data is transferred to arbiter
			.salt(salt),
			.addr_start(addr_start), .addr_diff(addr_diff),
			.hash(hash), .hash_valid(hash_valid),
			.hash_addr(hash_addr), .hash_end(hash_end),
			.cmp_config_wr_en(arbiter_cmp_config_wr_en),
			.cmp_config_full(arbiter_cmp_config_full[i]),
			.new_cmp_config(new_cmp_config), .cmp_config_applied(cmp_config_applied[i]),
			
			// misc
			.idle(unit_idle[i]),
			.arbiter_error(arbiter_error[8*(i+1)-1 -:8]),

			// Output
			.outpkt_dout(outpkt_dout[16*(i+1)-1 : 16*i]), .outpkt_end_out(outpkt_end_out[i]),
			.outpkt_rd_en(outpkt_rd_en[i]), .outpkt_empty(outpkt_empty[i]),

			// Cores are moved to upper level module
			.crypt_ready_out(crypt_ready_out[END : START]),
			.core_idle_out(core_idle_out[END : START]),
			.core_err_out(core_err_out[END : START]),
			.core_wr_en(core_wr_en[END : START]),
			// Serialized output from cores
			.core_dout_in(core_dout_in[4*END+3 : 4*START]),
			.core_dout_ready(core_dout_ready[END:START]),
			// Broadcast
			.core_din(core_din[(`DIN_MSB+1)*(i+1)-1 -:`DIN_MSB+1]),
			.core_addr_in(core_addr_in[3*(i+1)-1 -:3])
		);

	end
	endgenerate


	// ******************************************
	//
	// Join output packets from several units
	//
	// ******************************************
	assign outpkt_rd_en = ~outpkt_empty & ~outpkt_join_full;
	
	outpkt_join #( .N(NUM_WORD_GEN)
	) outpkt_join(
		.CLK(CMP_CLK),
		.din(outpkt_dout), .pkt_end(outpkt_end_out),
		.wr_en(outpkt_rd_en), .full(outpkt_join_full),
		.dout(dout), .rd_en(wr_en), .empty(outpkt_join_empty)
	);

	assign wr_en = ~outpkt_join_empty & ~full;


	// **************************************************
	//
	// Cores in wrappers.
	//
	// **************************************************
	generate
	for (i=0; i < NUM_WRAPPERS; i=i+1) begin:wrappers

		localparam START = WRAPPERS_CONF [i*32+15 -:8];
		localparam END = WRAPPERS_CONF [i*32+7 -:8];
		localparam WORD_GEN_NUM = WRAPPERS_CONF [i*32+23 -:8];

		wrapper #(
			.N_CORES(END - START + 1),
			.CORES_CONF(CORES_CONF[16*(END+1)-1 : 16*START])
		) wrapper (
			.CORE_CLK(CORE_CLK), .CMP_CLK(CMP_CLK),
			 // broadcast input
			.din(core_din[(`DIN_MSB+1)*(WORD_GEN_NUM+1)-1 -:`DIN_MSB+1]),
			.addr_in(core_addr_in[3*(WORD_GEN_NUM+1)-1 -:3]),
			.global_salt(global_salt),

			.wr_en(core_wr_en[END:START]), .crypt_ready(crypt_ready_out[END:START]),
			.core_idle(core_idle_out[END:START]), .err_core(core_err_out[END:START]),

			.err_cmp(),
			.core_dout_in(core_dout_in[4*END+3 : 4*START]),
			.core_dout_ready(core_dout_ready[END:START])
		);

	end
	endgenerate


endmodule


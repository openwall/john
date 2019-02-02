`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018-2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "sha512.vh"

module sha512crypt #(
	parameter VERSION = `PKT_COMM_VERSION,
	parameter WORD_MAX_LEN = `PLAINTEXT_LEN,
	parameter CHAR_BITS = `CHAR_BITS,
	parameter RANGES_MAX = `RANGES_MAX,
	parameter RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1),
	parameter DISABLE_CHECKSUM = 0
	)(
	input PKT_COMM_CLK,
	input CORE_CLK,

	// read from some internal FIFO (recieved via high-speed interface)
	input [7:0] din,
	output rd_en,
	input empty,

	// write into some internal FIFO (to be send via high-speed interface)
	output [15:0] dout,
	output wr_en,
	input full,

	// control input (VCR interface)
	input [7:0] app_mode,
	// status output (VCR interface)
	output cores_idle,
	output [7:0] app_status,
	output [7:0] pkt_comm_status,
	output [7:0] debug2, debug3
	);


	// ************************************************************
	//
	// The design is divided into units.
	// Configuration for each unit define unit-specific properties
	// such as number of cores, node# the unit is connected to, etc.
	//
	// ************************************************************

	localparam N_UNITS = 12;
	localparam [64*N_UNITS-1 :0] UNITS_CONF = {
	// unit_dummy| reserved| core_dummy| in_r| node#
	// warning: in_r must match the count of pass-by nodes

		//1'b1, 4'b1111,	47'd0,	4'd4, 8'd10,	// unit #11
		1'b0, 4'b0000,	47'd0,	4'd4, 8'd10,	// unit #11
		//1'b1, 4'b1111,	47'd0,	4'd2, 8'd2,		// unit #10
		1'b0, 4'b0000,	47'd0,	4'd2, 8'd2,		// unit #10
		1'b1, 4'b1111,	47'd0,	4'd3, 8'd9,		// unit #9
		//1'b0, 4'b0000,	47'd0,	4'd3, 8'd9,		// unit #9
		1'b1, 4'b1111,	47'd0,	4'd2, 8'd8,		// unit #8
		//1'b0, 4'b0000,	47'd0,	4'd2, 8'd8,		// unit #8
		//1'b1, 4'b1111,	47'd0,	4'd1, 8'd7,		// unit #7
		1'b0, 4'b0000,	47'd0,	4'd1, 8'd7,		// unit #7
		//1'b1, 4'b1111,	47'd0,	4'd0, 8'd0,		// unit #6
		1'b0, 4'b0000,	47'd0,	4'd0, 8'd0,		// unit #6
		//1'b1, 4'b1111,	47'd0, 	4'd1, 8'd1,		// unit #5
		1'b0, 4'b0000,	47'd0, 	4'd1, 8'd1,		// unit #5
		//1'b1, 4'b1111,	47'd0, 	4'd0, 8'd0,		// unit #4
		1'b0, 4'b0000,	47'd0, 	4'd0, 8'd0,		// unit #4
		//1'b1, 4'b1111,	47'd0, 	4'd4, 8'd10,		// unit #3
		1'b0, 4'b0000,	47'd0, 	4'd4, 8'd10,		// unit #3
		//1'b1, 4'b1111,	47'd0, 	4'd4, 8'd10,		// unit #2
		1'b0, 4'b0000,	47'd0, 	4'd4, 8'd10,		// unit #2
		//1'b1, 4'b1111,	47'd0, 	4'd3, 8'd3,		// unit #1
		1'b0, 4'b0000,	47'd0, 	4'd3, 8'd3,		// unit #1
		//1'b1, 4'b1111,	47'd0,	4'd4, 8'd4		// unit #0
		1'b0, 4'b0000,	47'd0,	4'd4, 8'd4		// unit #0

	// unit_dummy| reserved| core_dummy| in_r| node#
	};


	// There's a network for broadcast signals to units.
	// The network consists of nodes. The configuration for each node
	// points to the upper level node.
	localparam N_NODES = 11;
	localparam [8*N_NODES-1 :0] NODES_CONF = {
		8'd9,		// #10
		8'd8,		// #9: connected #10
		8'd7,		// #8: connected #9
		8'd0,		// #7: connected #8

		8'd5,		// #6
		8'd4,		// #5: connected #6
		8'd3,		// #4: connected #5
		8'd2,		// #3: connected #4
		8'd1,		// #2: connected #3
		8'd0,		// #1: connected #2

		8'd255	// #0 is the entry to the network
	};


	// ************************************************************
	//
	// pkt_comm error codes:
	//
	// 0x01 - wrong input packet checksum
	// 0x02 - bad input packet length
	// 0x04 - bad input packet type
	// 0x08 - unsupported pkt_comm version
	// 0x10 - number of words in WORD_LIST/TEMPLATE_LIST exceeds 2**16-1
	// 0x20 - error in WORD_LIST/TEMPLATE_LIST packet
	// 0x40 - error in WORD_GEN packet
	// 0x80 - error in CMP_CONFIG packet
	//
	// ************************************************************
	assign pkt_comm_status = {
		err_cmp_config, err_word_gen_conf, err_template, err_word_list_count,
		err_pkt_version, err_inpkt_type, err_inpkt_len, err_inpkt_checksum
	};


	// ************************************************************
	//
	// app_status error codes:
	//
	// 0x01 - candidates received, comparator is unconfigured (arbiter_tx)
	// 0x02, 0x04 - bad output from a computing unit (arbiter_rx)
	// 0x08 - received from a computing unit (arbiter_rx), nothing was sent
	// 0x10 - error in PKT_TYPE_CONFIG
	//
	// ************************************************************
	assign app_status[7:5] = 0;

	(* KEEP="true" *) wire mode_cmp = ~app_mode[6]; // Use comparator

	// 10 us (USB transfer takes at least ~100 us)
	delay #( .INIT(1), .NBITS(10) ) delay_cores_idle(
		.CLK(PKT_COMM_CLK), .in(arbiter_tx_idle), .out(cores_idle) );


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
	localparam PKT_TYPE_INIT = 5;
	localparam PKT_TYPE_CONFIG = 6;

	localparam PKT_MAX_TYPE = `PKT_MAX_TYPE;


	wire [`MSB(PKT_MAX_TYPE):0] inpkt_type;
	wire [15:0] inpkt_id;

	inpkt_header #(
		.VERSION(VERSION),
		.DISABLE_CHECKSUM(DISABLE_CHECKSUM)
	) inpkt_header(
		.CLK(PKT_COMM_CLK),
		.din(din),
		.wr_en(rd_en), .err(inpkt_error),
		.pkt_type(inpkt_type), .pkt_id(inpkt_id), .pkt_data(inpkt_data),
		.pkt_end(inpkt_end),
		.err_pkt_version(err_pkt_version), .err_pkt_type(err_inpkt_type),
		.err_pkt_len(err_inpkt_len), .err_pkt_checksum(err_inpkt_checksum)
	);

	// input packet processing: read enable
	assign rd_en = ~empty & (~inpkt_data & ~inpkt_error
		| inpkt_config_wr_rdy | inpkt_init_wr_rdy
		| word_list_wr_rdy | word_gen_conf_rdy | cmp_config_wr_rdy
	);


	// **************************************************
	//
	// input packet type PKT_TYPE_CONFIG (0x06)
	//
	// **************************************************
	wire inpkt_config_wr_rdy = inpkt_type == PKT_TYPE_CONFIG
		& inpkt_data & ~inpkt_config_full;

	wire [N_UNITS-1:0] config_data1; // used to mask units in arbiter_tx

	inpkt_config #( .SUBTYPE1_WIDTH(N_UNITS)
	) inpkt_config(
		.CLK(PKT_COMM_CLK),
		.din(din), .wr_en(inpkt_config_wr_rdy & ~empty),
		.pkt_end(inpkt_end), .full(inpkt_config_full),
		.dout1(config_data1), .err(app_status[4])
	);


	// **************************************************
	//
	// input packet type PKT_TYPE_INIT (0x05)
	//
	// **************************************************
`ifdef ENTRY_PTS_EN
	wire inpkt_init_wr_rdy = inpkt_type == PKT_TYPE_INIT
		& inpkt_data & ~inpkt_init_full;

	wire [7:0] init_data;
	inpkt_type_init_1b inpkt_init(
		.CLK(PKT_COMM_CLK),
		.din(din), .wr_en(inpkt_init_wr_rdy & ~empty), .full(inpkt_init_full),
		.dout(init_data), .rd_en(init_rd_en), .empty(init_empty)
	);
`else

	wire inpkt_init_wr_rdy = 1'b0;
	wire [7:0] init_data = 0;
`endif


	// **************************************************
	//
	// input packet types PKT_TYPE_WORD_LIST (0x01),
	// PKT_TYPE_TEMPLATE_LIST (0x04)
	//
	// **************************************************
	wire word_list_wr_rdy = (inpkt_type == PKT_TYPE_WORD_LIST
			| inpkt_type == PKT_TYPE_TEMPLATE_LIST)
		& inpkt_data & ~word_list_full;


	wire [7:0] word_list_dout;
	wire [`MSB(WORD_MAX_LEN-1):0] word_rd_addr;
	wire [`MSB(WORD_MAX_LEN):0] word_len;
	wire [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info;
	wire [15:0] word_id;

	// template_list_b: stores input words in 8-bit wide memory
	// Variable word length: not padded with zeroes, length is output.
	template_list_b_varlen word_list(
		.CLK(PKT_COMM_CLK), .din(din),
		.wr_en(word_list_wr_rdy & ~empty), .full(word_list_full),
		.inpkt_end(inpkt_end),
		.is_template_list(inpkt_type == PKT_TYPE_TEMPLATE_LIST),

		.dout(word_list_dout), .rd_addr(word_rd_addr),
		.set_empty(word_list_set_empty), .empty(word_list_empty),
		.range_info(range_info), .word_id(word_id), .word_len(word_len),
		.word_list_end(word_list_end), .totally_empty(word_list_totally_empty),

		.err_template(err_template), .err_word_list_count(err_word_list_count)
	);


	// **************************************************
	//
	// input packet type PKT_TYPE_WORD_GEN (0x02)
	//
	// **************************************************
	wire word_gen_conf_rdy = inpkt_type == PKT_TYPE_WORD_GEN
		& inpkt_data & ~word_gen_conf_full;

	wire [7:0] word_gen_dout;
	wire [`MSB(WORD_MAX_LEN-1):0] word_gen_rd_addr;
	wire [`MSB(WORD_MAX_LEN):0] word_len_out;
	wire [15:0] pkt_id, word_id_out;
	wire [31:0] gen_id;

	word_gen_b_varlen word_gen(
		.CLK(PKT_COMM_CLK), .din(din),
		.inpkt_id(inpkt_id), .conf_wr_en(word_gen_conf_rdy & ~empty),
		.conf_full(word_gen_conf_full),

		.word_in(word_list_dout), .word_rd_addr(word_rd_addr),
		.word_set_empty(word_list_set_empty), .word_empty(word_list_empty),
		.range_info(range_info), .word_id(word_id), .word_len(word_len),
		.word_list_end(word_list_end),

		.dout(word_gen_dout), .rd_addr(word_gen_rd_addr),
		.set_empty(word_gen_set_empty), .empty(word_gen_empty),
		.pkt_id(pkt_id), .word_id_out(word_id_out),
		.word_len_out(word_len_out), .gen_id(gen_id), .gen_end(gen_end),
		.totally_empty(word_gen_totally_empty),

		.err(err_word_gen_conf)
	);


	// **************************************************
	//
	// input packet type CMP_CONFIG (0x03)
	//
	// **************************************************
	wire cmp_config_wr_rdy = inpkt_type == PKT_TYPE_CMP_CONFIG
		& inpkt_data & ~cmp_config_full;

	wire [`HASH_COUNT_MSB:0] hash_count;
	wire [`HASH_NUM_MSB+2:0] cmp_wr_addr;
	wire [7:0] cmp_din;

	wire [4:0] cmp_config_addr;
	wire [7:0] cmp_config_data;

	xcrypt_cmp_config cmp_config(
		.CLK(PKT_COMM_CLK), .mode_cmp(mode_cmp),
		.din(din), .wr_en(cmp_config_wr_rdy & ~empty),
		.full(cmp_config_full), .err(err_cmp_config),

		.hash_count(hash_count), .cmp_wr_addr(cmp_wr_addr),
		.cmp_wr_en(cmp_wr_en), .cmp_din(cmp_din),

		.new_cmp_config(new_cmp_config),
		.cmp_config_applied(cmp_config_applied),
		.addr(cmp_config_addr), .dout(cmp_config_data)
	);


	// **************************************************
	//
	// Arbiter, transmit part
	// - Gather up necessary data, create data packets for computing units;
	// - Transmit data to units ready for computing;
	// - Operate mostly at PKT_COMM frequency, send at CORE frequency.
	// - Account number of candidates transmitted, handle changes
	// in comparator configuration etc.
	//
	// **************************************************
	wire [`UNIT_INPUT_WIDTH-1:0] unit_in;
	wire [N_UNITS-1:0] unit_in_wr_en, unit_in_afull, unit_in_ready;

	wire [31:0] num_processed_tx;

	arbiter_tx #(
		.N_UNITS(N_UNITS), .WORD_MAX_LEN(WORD_MAX_LEN)
	) arbiter_tx(
		.CLK(PKT_COMM_CLK), .CORE_CLK(CORE_CLK), .mode_cmp(mode_cmp),
		.pkt_id(pkt_id), .word_id(word_id_out), .gen_id(gen_id),
		.gen_end(gen_end), .word_len(word_len_out),

		.din(word_gen_dout), .word_gen_rd_addr(word_gen_rd_addr),
		.word_set_empty(word_gen_set_empty), .word_empty(word_gen_empty),
		.src_totally_empty(word_list_totally_empty & word_gen_totally_empty),

		.new_cmp_config(new_cmp_config),
		.cmp_config_applied(cmp_config_applied),
		.cmp_config_addr(cmp_config_addr), .cmp_config_data(cmp_config_data),

		.init_din(init_data), .init_rd_en(init_rd_en),
		.init_empty(init_empty),
		.unit_tx_mask(config_data1[N_UNITS-1:0]),

		.unit_in(unit_in), .unit_in_ctrl(unit_in_ctrl), .bcast_en(bcast_en),
		.unit_in_wr_en(unit_in_wr_en),
		.unit_in_afull(unit_in_afull), .unit_in_ready(unit_in_ready),

		.num_processed_tx(num_processed_tx),
		.pkt_tx_done(pkt_tx_done), .pkt_rx_done(pkt_rx_done),
		.recv_item(recv_item),

		.idle(arbiter_tx_idle), .err(app_status[0])
	);


	// **************************************************
	//
	// Network for broadcast signals
	//
	// **************************************************
	localparam BCAST_WIDTH = `UNIT_INPUT_WIDTH + 1;
	wire [N_NODES*BCAST_WIDTH-1 :0] bcast;

	bcast_net #( .BCAST_WIDTH(BCAST_WIDTH),
		.N_NODES(N_NODES), .NODES_CONF(NODES_CONF)
	) bcast_net(
		.CLK(CORE_CLK), .en(bcast_en),
		.in({ unit_in, unit_in_ctrl }), .out(bcast)
	);


	// **************************************************
	//
	// Units
	//
	// **************************************************
	wire [`UNIT_OUTPUT_WIDTH * N_UNITS -1 :0] unit_dout;
	wire [N_UNITS-1:0] unit_rd_en, unit_empty;

	genvar i;
	generate
	for (i=0; i < N_UNITS; i=i+1) begin:units

		// unit input
		wire unit_in_wr_en_u, unit_in_afull_u, unit_in_ready_u;
		// unit output
		wire [`UNIT_OUTPUT_WIDTH-1 :0] dout_u;
		wire rd_en_u, empty_u;
		regs2d #( .IN_WIDTH(2), .OUT_WIDTH(`UNIT_OUTPUT_WIDTH+3),
			.STAGES(UNIT_CONF[8 +:4])
		) unit_io_regs(
			.CLK(CORE_CLK),
			.enter_in({ unit_in_wr_en[i], unit_rd_en[i] }),
			.enter_out({ unit_in_afull[i], unit_in_ready[i], unit_empty[i],
				unit_dout[`UNIT_OUTPUT_WIDTH*i +:`UNIT_OUTPUT_WIDTH] }),
			.exit_in({ unit_in_wr_en_u, rd_en_u }),
			.exit_out({ unit_in_afull_u, unit_in_ready_u, empty_u, dout_u })
		);


		localparam [63:0] UNIT_CONF = UNITS_CONF [64*i +:64];
		localparam NODE_NUM = UNIT_CONF [0 +:8];

		(* KEEP_HIERARCHY="true" *)
		sha512unit #( .UNIT_CONF(UNIT_CONF)
		) unit(
			.CLK(CORE_CLK),
			.unit_in(bcast[NODE_NUM*BCAST_WIDTH+1 +:BCAST_WIDTH-1]),
			.unit_in_ctrl(bcast[NODE_NUM*BCAST_WIDTH]),
			.unit_in_wr_en(unit_in_wr_en_u),
			.unit_in_afull(unit_in_afull_u), .unit_in_ready(unit_in_ready_u),
			.dout(dout_u), .rd_en(rd_en_u), .empty(empty_u)
		);

	end
	endgenerate


	// **************************************************
	//
	// Arbiter, receive part
	//
	// **************************************************
	wire [31:0] cmp_data;
	wire [`HASH_NUM_MSB:0] cmp_hash_num;

	wire [`OUTPKT_TYPE_MSB:0] outpkt_type;
	wire [15:0] arbiter_pkt_id;
	wire [31:0] arbiter_num_processed;
	wire [`HASH_NUM_MSB:0] hash_num;
	wire [15:0] arbiter_dout;
	wire [`MSB(4 +`RESULT_LEN/2 -1):0] arbiter_rd_addr;

	arbiter_rx #(
		.N_UNITS(N_UNITS), .UNIT_OUTPUT_WIDTH(`UNIT_OUTPUT_WIDTH),
		.PKT_NUM_WORDS(4 +`RESULT_LEN/2)
	) arbiter_rx(
		.CLK(PKT_COMM_CLK), .CORE_CLK(CORE_CLK), .mode_cmp(mode_cmp),
		.unit_dout(unit_dout),
		.unit_rd_en(unit_rd_en), .unit_empty(unit_empty),
		// Iteraction with arbiter_tx
		.num_processed_tx(num_processed_tx),
		.pkt_tx_done(pkt_tx_done), .pkt_rx_done(pkt_rx_done),
		.recv_item(recv_item),
		// Comparator
		.cmp_data(cmp_data), .cmp_start(cmp_start),
		.cmp_found(cmp_found), .cmp_finished(cmp_finished),
		.cmp_hash_num(cmp_hash_num),
		// Output
		.dout(arbiter_dout), .rd_addr(arbiter_rd_addr),
		.outpkt_type(outpkt_type), .pkt_id(arbiter_pkt_id),
		.num_processed(arbiter_num_processed), .hash_num(hash_num),
		.empty(arbiter_empty), .rd_en(arbiter_rd_en),
		.err(app_status[3:1]), .debug({debug3, debug2})
	);


	// **************************************************
	//
	// Comparator
	// if mode_cmp=1 (the default) then computed hashes
	// appear in the comparator.
	//
	// **************************************************
	comparator comparator(
		.CLK(PKT_COMM_CLK),
		// cmp_config
		.din(cmp_din), .wr_en(cmp_wr_en),
		.wr_addr(cmp_wr_addr), .hash_count(hash_count),
		// arbiter_rx
		.cmp_data(cmp_data), .start(cmp_start),
		.found(cmp_found), .finished(cmp_finished), .hash_num(cmp_hash_num)
	);


	// ************************************************
	//
	// Create application packets from output data
	//
	// ************************************************
	assign arbiter_rd_en = ~arbiter_empty & ~outpkt_full;

	outpkt #(
		.HASH_NUM_MSB(`HASH_NUM_MSB), .SIMULATION(DISABLE_CHECKSUM)
	) outpkt(
		.CLK(PKT_COMM_CLK),
		.din(arbiter_dout), .rd_addr(arbiter_rd_addr),
		.source_not_empty(~arbiter_empty),
		.wr_en(arbiter_rd_en), .full(outpkt_full),

		.pkt_type(outpkt_type), .pkt_id(arbiter_pkt_id),
		.hash_num(hash_num), .num_processed(arbiter_num_processed),

		.dout(dout), .rd_en(wr_en), .empty(outpkt_empty), .pkt_end_out()
	);


	// Write data into output FIFO
	assign wr_en = ~outpkt_empty & ~full;


endmodule

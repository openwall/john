/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
//
// pkt_comm_input.vh
// This file is for inclusion after module declaration.
//

// *********************************************************
//
// pkt_comm_v2 changes:
// * Used template_list in place of word_list
// * Used word_gen_v2
//
// Packet-Based Communication for FPGA Application
//
// Host Software sends data:
// * to different subsystems of FPGA application
// * in sequential packets
//
// see pkt_comm.h for packet format
//
// Naming: in*, out* from the point of view from FPGA application
//
// *********************************************************

//module pkt_comm_v2 #(

	// OK. Parameters and Ports
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
	
	// control input (VCR interface)
	input [7:0] app_mode,
	// status output (VCR interface)
	output [7:0] app_status,
	output [7:0] pkt_comm_status,
	output [7:0] debug2, debug3
	);
	
	wire [15:0] dout_app_mode2;


`ifndef TEST_MODES_01

	assign rd_en = inpkt_rd_en;
	assign wr_en = output_fifo_wr_en;
	assign dout = dout_app_mode2;

	// **************************************************
	//
	// Application modes 0 & 1: send back what received
	// used by simple_test.c and test.c
	//
	// **************************************************
`else		
	//assign dout = din;

	// convert 8-bit to 16-bit
	reg [15:0] dout_app_mode01;
	reg dout_app_mode01_ready = 0;
	reg counter = 0;

	assign rd_en =
		app_mode==2 || app_mode==3 ? inpkt_rd_en :
		app_mode==0 || app_mode==1 ? ~empty & ~full :
		1'b0;
		
	assign wr_en =
		app_mode==2 ? output_fifo_wr_en :
		app_mode==0 || app_mode==1 ? dout_app_mode01_ready :
		//app_mode==3 ?
		1'b0;
	
	assign dout =
		app_mode==2 ? dout_app_mode2 :
		app_mode==0 || app_mode==1 ? dout_app_mode01 :
		//app_mode==3 ? 
		16'b0;
		
	always @(posedge PKT_COMM_CLK) begin
		if (counter == 0)
			dout_app_mode01_ready <= 0;
		if (rd_en && (app_mode == 8'h00 || app_mode == 8'h01) ) begin
			if (counter == 0)
				dout_app_mode01[7:0] <= din;
			else if (counter == 1) begin
				dout_app_mode01[15:8] <= din;
				dout_app_mode01_ready <= 1;
			end
			counter <= counter + 1'b1;
		end
	end

	// !DISABLE_TEST_MODES_0_AND_1
`endif

	assign pkt_comm_status = {
		1'b0, err_word_gen_conf, err_template, err_word_list_count,
		err_pkt_version, err_inpkt_type, err_inpkt_len, err_inpkt_checksum
	};	

	reg error = 0;
	always @(posedge PKT_COMM_CLK)
		error <= |pkt_comm_status;
	

	// **************************************************
	//
	// Application mode 2: read packets
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
		.DISABLE_CHECKSUM(DISABLE_CHECKSUM)
	) inpkt_header(
		.CLK(PKT_COMM_CLK), 
		.din(din), 
		.wr_en(inpkt_rd_en),
		.pkt_type(inpkt_type), .pkt_id(inpkt_id), .pkt_data(inpkt_data),
		.pkt_end(inpkt_end),
		.err_pkt_version(err_pkt_version), .err_pkt_type(err_inpkt_type),
		.err_pkt_len(err_inpkt_len), .err_pkt_checksum(err_inpkt_checksum)
	);

	// input packet processing: read enable
	assign inpkt_rd_en = ~empty & ~error
			& (~inpkt_data | word_gen_conf_en | word_list_wr_en | inpkt_extra_rd_en);


	// **************************************************
	//
	// input packet types PKT_TYPE_WORD_LIST (0x01),
	// PKT_TYPE_TEMPLATE_LIST (0x04)
	//
	// **************************************************
	wire word_list_wr_en = ~empty & ~error
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
	// input packet type PKT_TYPE_WORD_GEN (0x02)
	//
	// **************************************************
	wire word_gen_conf_en = ~empty & ~error
			& inpkt_type == PKT_TYPE_WORD_GEN & inpkt_data & ~word_gen_conf_full;

	wire word_wr_en = ~word_list_empty & ~word_full;
	assign word_list_rd_en = word_wr_en;
	
	wire [WORD_MAX_LEN * CHAR_BITS - 1:0] word_gen_dout;
	wire [15:0] pkt_id, word_id_out;
	wire [31:0] gen_id;

	word_gen_v2 #(
		.CHAR_BITS(CHAR_BITS), .RANGES_MAX(RANGES_MAX), .WORD_MAX_LEN(WORD_MAX_LEN)
	) word_gen(
		.CLK(PKT_COMM_CLK), .din(din), 
		.inpkt_id(inpkt_id), .wr_conf_en(word_gen_conf_en), .conf_full(word_gen_conf_full),
		
		.word_in(word_list_dout), .range_info(range_info),
		.word_id(word_id), .word_list_end(word_list_end),
		.word_wr_en(word_wr_en), .word_full(word_full),
		
		.WORD_GEN_CLK(WORD_GEN_CLK),
		.rd_en(word_gen_rd_en), .empty(word_gen_empty),
		.dout(word_gen_dout), .pkt_id(pkt_id), .word_id_out(word_id_out), .gen_id(gen_id), .gen_end(gen_end),
		
		.err_word_gen_conf(err_word_gen_conf)
	);
	//
	// OK. Got words with ID's.
	//
	//wire [32 + 16 + WORD_MAX_LEN * CHAR_BITS -1 :0] word_gen_out =
	//		{ gen_id, word_id_out, word_gen_dout };
	//
	// also [15:0] pkt_id.


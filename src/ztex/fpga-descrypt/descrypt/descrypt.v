`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "descrypt_core/descrypt.vh"

module descrypt #(

	// pkt_comm_input.vh contains:
	// * Parameters and Ports for pkt_comm module
	// * Test modes 0 & 1
	// * Error handling (pkt_comm_status)
	// * PKT_TYPE_* localparams, inpkt_header
	// * template_list
	// * word_gen_v2
	//
	`include "../pkt_comm/pkt_comm_input.vh"

	// OK. Got words with ID's.
	//
	//wire [WORD_MAX_LEN * CHAR_BITS - 1:0] word_gen_dout;
	//wire [15:0] pkt_id, word_id_out;
	//wire [31:0] gen_id;
	//wire gen_end;

	//assign word_gen_rd_en = ~word_gen_empty & ~fifo120_almost_full_r;
	assign debug2 = 8'hd2;
	assign debug3 = 8'hd3;

	//assign app_status = 8'h00;

	// extra read from input fifo (din)
	//assign inpkt_extra_rd_en = 0;

	// *************************************************************



	// **************************************************
	//
	// input packet type CMP_CONFIG (0x03)
	//
	// **************************************************
	wire cmp_config_wr_en = ~empty & ~error
			& inpkt_type == PKT_TYPE_CMP_CONFIG & inpkt_data & ~cmp_config_full;
			
	assign inpkt_extra_rd_en = cmp_config_wr_en;

	// Data processed by cmp_config goes into dedicated inputs of arbiter
	wire [`SALT_MSB:0] salt;
	wire [`RAM_ADDR_MSB-1:0] read_addr_start, addr_diff_start;
	wire [`HASH_MSB:0] hash;
	wire [`RAM_ADDR_MSB:0] hash_addr;
	
	cmp_config cmp_config(
		.wr_clk(PKT_COMM_CLK), .din(din), .wr_en(cmp_config_wr_en), .full(cmp_config_full),
		
		.rd_clk(CORE_CLK),
		.salt_out(salt), .read_addr_start(read_addr_start), .addr_diff_start(addr_diff_start),
		.hash_out(hash), .hash_valid(hash_valid), .hash_addr_out(hash_addr), .hash_end(hash_end),
		.rd_en(arbiter_cmp_config_wr_en), .empty(cmp_config_empty),
		.new_cmp_config(new_cmp_config), .config_applied(config_applied), 
		.error(err_cmp_config)
	);

	// read from cmp_config
	assign arbiter_cmp_config_wr_en = ~arbiter_cmp_config_full & ~cmp_config_empty;
	
	// read from word_gen
	assign word_gen_rd_en = ~word_gen_empty & ~arbiter_almost_full_r;
	wire extra_reg_wr_en = word_gen_rd_en;

	//
	// It requires extra register word_gen -> arbiter
	//
	reg arbiter_almost_full_r = 0;
	always @(posedge WORD_GEN_CLK)
		arbiter_almost_full_r <= arbiter_almost_full;
	
	reg [WORD_MAX_LEN * CHAR_BITS - 1:0] word_gen_dout_r;
	reg [15:0] pkt_id_r, word_id_out_r;
	reg [31:0] gen_id_r;
	reg gen_end_r;
	reg extra_reg_empty = 1;
	
	always @(posedge WORD_GEN_CLK)
		if (extra_reg_wr_en) begin
			extra_reg_empty <= 0;
			word_gen_dout_r <= word_gen_dout;
			pkt_id_r <= pkt_id; word_id_out_r <= word_id_out;
			gen_id_r <= gen_id; gen_end_r <= gen_end;
		end
		else if (arbiter_wr_en)
			extra_reg_empty <= 1;
	
	wire arbiter_wr_en = ~extra_reg_empty & ~arbiter_full;

	
	// *********************
	//
	// Arbiter
	//
	// *********************
	wire [1:0] pkt_type_outpkt;
	wire [15:0] pkt_id_outpkt, word_id_outpkt;
	wire [`RAM_ADDR_MSB:0] hash_num_eq_outpkt;
	wire [31:0] gen_id_outpkt, num_processed_outpkt;
	wire [6:0] arbiter_error;
	
	arbiter arbiter(
		.WORD_GEN_CLK(WORD_GEN_CLK), .CORE_CLK(CORE_CLK), .CMP_CLK(CMP_CLK),
		
		// read from word_gen
		//.word(word_gen_dout), .pkt_id(pkt_id), .word_id(word_id_out),
		//.gen_id(gen_id), .gen_end(gen_end),
		//.wr_en(arbiter_wr_en), .full(arbiter_full),
		
		// read from word_gen (with extra register)
		.word(word_gen_dout_r), .pkt_id(pkt_id_r), .word_id(word_id_out_r),
		.gen_id(gen_id_r), .gen_end(gen_end_r),
		.wr_en(arbiter_wr_en), .full(arbiter_full), .almost_full(arbiter_almost_full),
		
		// read from cmp_config
		.salt(salt), .read_addr_start(read_addr_start), .addr_diff_start(addr_diff_start),
		.hash(hash), .hash_valid(hash_valid), .hash_addr(hash_addr), .hash_end(hash_end),
		.cmp_config_wr_en(arbiter_cmp_config_wr_en), .cmp_config_full(arbiter_cmp_config_full),
		.new_cmp_config(new_cmp_config), .cmp_config_applied(config_applied),
		
		.pkt_type_out(pkt_type_outpkt), .gen_id_out(gen_id_outpkt), .pkt_id_out(pkt_id_outpkt),
		.word_id_out(word_id_outpkt), .num_processed_out(num_processed_outpkt),
		.hash_num_eq(hash_num_eq_outpkt),
		.rd_en(arbiter_rd_en), .empty(arbiter_empty),
		.error(arbiter_error)
	);

	assign app_status = { err_cmp_config, arbiter_error };

	// read from arbiter
	assign arbiter_rd_en = ~arbiter_empty & ~outpkt_full;
	wire outpkt_wr_en = arbiter_rd_en;
	
	outpkt_v2 #(
		.HASH_NUM_MSB(`RAM_ADDR_MSB)
		) outpkt(
		.CLK(CMP_CLK), .wr_en(outpkt_wr_en), .full(outpkt_full),
		
		.pkt_type({ 1'b0, pkt_type_outpkt }),
		.pkt_id(pkt_id_outpkt),
		.gen_id(gen_id_outpkt), .word_id(word_id_outpkt), .num_processed(num_processed_outpkt),
		.hash_num(hash_num_eq_outpkt),
		
		.dout(dout_app_mode2), .rd_en(outpkt_rd_en), .empty(outpkt_empty)
	);

	assign outpkt_rd_en = ~outpkt_empty & ~full;
	assign output_fifo_wr_en = outpkt_rd_en;


endmodule


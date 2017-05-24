`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// *********************************************************
//
// An example application: pkt_test
//
// * Reads packets via high-speed communication interface (pkt_comm)
//
// * Processes input packets of types:
//   PKT_TYPE_WORD_LIST, PKT_TYPE_TEMPLATE_LIST, PKT_TYPE_WORD_GEN
//
// * Outputs resulting words with IDs
//
// *********************************************************

module pkt_test #(

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

	assign app_status = 8'h00;

	// extra read from input fifo (din)
	assign inpkt_extra_rd_en = 0;



	// *************************************************************
	//
	// Going to output generated plaintext candidates via outpkt_v2

	// 1. Convert 7-bit to 8-bit if necessary
	//
	wire [8*`RESULT_LEN-1:0] plaintext;

	genvar i;
	generate
	for (i=0; i < WORD_MAX_LEN; i=i+1)
	begin: convert7_to8_gen
		assign plaintext[8*(i+1)-1 : 8*i] = CHAR_BITS == 7
			? { 1'b0, word_gen_dout[(i+1)*CHAR_BITS-1 -:CHAR_BITS] }
			: word_gen_dout[8*(i+1)-1 : 8*i];
	end
	endgenerate

		
	// 2. Data is entering different clock domain
	//
	wire [15:0] pkt_id_2, word_id_out_2;
	wire [31:0] gen_id_2;
	wire [8*`RESULT_LEN-1:0] plaintext_2;	

	assign word_gen_rd_en = ~word_gen_empty & ~xdc_reg_full;
	
	xdc_reg #( .WIDTH(16 + 16 + 32 + 8*`RESULT_LEN)
	) xdc_reg (
		.wr_clk(WORD_GEN_CLK), .wr_en(word_gen_rd_en), .full(xdc_reg_full),
		.din({ pkt_id, word_id_out, gen_id, plaintext }),
		.rd_clk(PKT_COMM_CLK), .rd_en(outpkt_wr_en), .empty(xdc_reg_empty),
		.dout({ pkt_id_2, word_id_out_2, gen_id_2, plaintext_2 })
	);
	

	// 3. Write data into outpkt_v2
	//
	assign outpkt_wr_en = ~xdc_reg_empty & ~outpkt_full;

	outpkt_v2 outpkt(
		.CLK(PKT_COMM_CLK), .wr_en(outpkt_wr_en), .full(outpkt_full),
		
		.pkt_type(3'b100),
		.pkt_id(pkt_id_2), .word_id(word_id_out_2),
		.gen_id(gen_id_2), .result(plaintext_2),
		
		.dout(dout_app_mode2), .rd_en(outpkt_rd_en), .empty(outpkt_empty)
	);


	// 4. Write data into output FIFO
	assign outpkt_rd_en = ~outpkt_empty & ~full;
	assign output_fifo_wr_en = outpkt_rd_en;


endmodule


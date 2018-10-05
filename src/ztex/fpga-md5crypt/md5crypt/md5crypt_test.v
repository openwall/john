`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module md5crypt_test();

	reg READ_ALL_FROM_OUTPUT_FIFO = 0;

	genvar i;
	integer k, k1, k2;
	reg [7:0] char;

	reg [7:0] app_mode = 0;

	initial begin

		// *****************************************************************
		//
		// Send data packets exactly as they arrive from USB controller.
		//
		// Output packets appear in output_fifo.fifo_output0.ram
		// exactly as before they leave FPGA.
		// On errors it sets pkt_comm_status and app_status available
		// via low-speed interface.
		//
		// It has no internal check for the count of rounds.
		//
		// *****************************************************************
		#500;


		// *****************************************************************
		//
		// Test #1.
		//
		// crypt_md5("abc","12345678");
		// 1000 ROUNDS
		// hash: $1$12345678$GVDEjIF51EkM3MPmFX6dO1
		// result: c9631d40 15f8d1a4 da88b604 05032f52
		//
		// Data packet for computing unit (sha512unit_test.v):
		// send_data_packet(1000,8,3,"12345678","abc");
		//
		// *****************************************************************

		// Usage: send_config_packet(subtype,data_len,data);
		// exclude units 0,6,7,12
		//send_config_packet(1,2,32'b_0000_0000_0001_0000_1100_0001);

		// Usage: cmp_config_create(cnt,salt_len,"salt");
		//cmp_config_create(1000,8,"12345678");
		cmp_config_create(3,8,"12345678");
		cmp_config_add_hash(32'h2222_2222);
		cmp_config_add_hash(32'hc963_1d40);
		cmp_config_add_hash(32'h473e_124d); // 3 rounds
		cmp_config_add_hash(32'h3333_3333);
		send_cmp_config();

		send_empty_word_gen(1);

		//word_list_add("mypwd123");
		//word_list_add("pass_len_is15..");

		// limit is 64K (fifo_input1, internal buffer in pkt_comm_helper.vh)
		for (k=0; k < 500; k=k+1)
		//for (k=0; k < 60; k=k+1)
			word_list_add("a");//bcdefgh");
		
		word_list_add("abc");

		word_list_add("key_len=11.");
		word_list_add("key_len=12.");
		send_word_list();



		// *****************************************************************
		//
		// Test #2: key_len > 15
		//
		// crypt_md5("key_len=32...................../","12345678");
		// $1$12345678$/Y8HRXkjaI0wpCjIOG1xv1
		//
		// *****************************************************************
/*
		cmp_config_create(1000,8,"12345678");
		cmp_config_add_hash(32'he80a_ce54);
		send_cmp_config();

		send_empty_word_gen(2);

		word_list_add("key_len=32...................../");
		send_word_list();
*/

		// *****************************************************************
		//
		// Test #3: phpass
		//
		// {"$P$900000000m6YEJzWtTmNBBL4jypbHv1", "openwall"}
		// hash (1st 4 bytes): 0x32 0x42 0x42 0xd5
		//
		// *****************************************************************
/*
		#1000;
		send_init_packet(1);

		cmp_config_create(2048,8,"00000000");
		cmp_config_add_hash(32'h2222_2222);
		cmp_config_add_hash(32'hd542_4232);
		//cmp_config_add_hash(32'h3333_3333);
		send_cmp_config();

		send_empty_word_gen(3);

		//word_list_add("mypwd123");
		word_list_add("openwall");
		send_word_list();
*/
	end



	// ***************************************************************
	//
	//
	//
	// ***************************************************************
	reg CORE_CLK = 0, PKT_COMM_CLK = 0, IFCLK = 0;

	reg [7:0] din;
	reg wr_en = 0;

`include "../pkt_comm/pkt_comm_test_helper.vh"


	// ***************************************************************
	//
	// Simulating input via USB controller, FPGA's Input fifo
	//
	// ***************************************************************
	wire [15:0] app_dout;
	wire [7:0] app_status, pkt_comm_status, debug2, debug3;
	wire [7:0] hs_input_dout;

	fifo_sync_small #( .A_WIDTH(16), .D_WIDTH(8)
	) fifo_input1(
		.CLK(PKT_COMM_CLK),
		.din(din),
		.wr_en(wr_en),
		.full(),

		.dout(hs_input_dout),
		.rd_en(hs_input_rd_en),
		.empty(hs_input_empty)
	);

	md5crypt #(.DISABLE_CHECKSUM(1)) pkt_comm(
	//pkt_comm_v2 pkt_comm(
		.PKT_COMM_CLK(PKT_COMM_CLK),
		.CORE_CLK(CORE_CLK),
		// High-Speed FPGA input
		.din(hs_input_dout),
		.rd_en(hs_input_rd_en),
		.empty(hs_input_empty),
		// High-Speed FPGA output
		.dout(app_dout),
		.wr_en(app_wr_en),
		.full(app_full),
		// Application control (via VCR I/O). Set with fpga_set_app_mode()
		.app_mode(app_mode),
		// Application status. Available at fpga->wr.io_state.app_status
		.cores_idle(cores_idle),
		.app_status(app_status), .pkt_comm_status(pkt_comm_status),
		.debug2(debug2), .debug3(debug3)
	);


	// ********************************************************
	//
	// Output buffer (via High-Speed interface)
	//
	// ********************************************************
	output_fifo output_fifo(
		.wr_clk(PKT_COMM_CLK),
		.din(app_dout),
		.wr_en(app_wr_en),
		.full(app_full),

		.rd_clk(IFCLK),
		.dout(), // to Cypress IO,
		.rd_en(READ_ALL_FROM_OUTPUT_FIFO), // to Cypress IO,
		.empty(), // to Cypress IO
		.mode_limit(1'b1),
		.reg_output_limit(READ_ALL_FROM_OUTPUT_FIFO),
		.output_limit(),
		.output_limit_not_done()
	);


	// This does not reflect actual timing
	initial begin
		#3;
		while (1) begin
			CORE_CLK <= ~CORE_CLK; #6;
		end
	end

	initial begin
		#5;
		while (1) begin
			PKT_COMM_CLK <= ~PKT_COMM_CLK; #10;
		end
	end

	initial begin
		#35;
		while (1) begin
			IFCLK <= ~IFCLK; #70;
		end
	end

endmodule

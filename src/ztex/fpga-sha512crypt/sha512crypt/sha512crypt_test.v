`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018-2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module sha512crypt_test();

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
		// Hash formatted as in reference implementation (sha512crypt.c):
		//	{ "$6$rounds=10$ssssssss", "11111111",
		//		"$6$rounds=10$ssssssss$1pzpbYbN3IQuS6xYu0CAfKMVtZmcTyMdI"
		//		"MufpgJ7uljsKxOPG4F0xKjAQfh9/W6.Edy18.Mt6l1qOmjXFazEy1"	},
		//
		// Data packet for computing unit (sha512unit_test.v):
		// send_data_packet(10,8,8,"ssssssss","11111111");
		//
		// Hash (MSB 1st): fe43fc48e5ea812e ... 9fa385ba93c527d7
		//
		// *****************************************************************

		// Usage: send_config_packet(subtype,data_len,data);
		//send_config_packet(1,2,16'b_0000_0001_0000_1100);
		
		// Usage: cmp_config_create(cnt,salt_len,"salt");
		cmp_config_create(10,8,"ssssssss");
		cmp_config_add_hash(32'h93c527d7);
		send_cmp_config();
		
		send_empty_word_gen(1);

		word_list_add("keylen7");
		word_list_add("mypwd123");
		word_list_add("mypwd1234");
		word_list_add("mypwd12345");
		word_list_add("pass_len_is15..");

		//for (k=0; k < 500; k=k+1)
		for (k=0; k < 30; k=k+1)
			word_list_add("11111110-b");

		word_list_add("11111111");
		word_list_add("11111101");
		word_list_add("11111011");

		send_word_list();

		// *****************************************************************
		//
		// Test #2.
		//
		//	{ "$6$rounds=101$saltSALTsaltSALT", "salt_len=16, key_len=64, contains 8-bit chars (ÀÁÂÃÄ) .........z",
		//		"$6$rounds=101$saltSALTsaltSALT$Z5uHBwC.vjuBsI5/Iuy0EHx/tVUpAz0F9Lnv"
		//		"CU2WHPM8BYTzfsQ7KSxnTIfywQxZDZng/rhWx6l5tafzp0wvT." },
		//
		// Hash (MSB 1st): 1fefb93d8a393cfa ... ccd6d49404ab0d4f
		//
		// *****************************************************************
/*
		cmp_config_create(101,16,"saltSALTsaltSALT");
		// add-up 25 dummy hashes to the comparator
		for (k=0; k < 25; k=k+1)
			cmp_config_add_hash(32'h00000100 + k);
		
		cmp_config_add_hash(32'h04ab0d4f);
		
		for (k=0; k < 25; k=k+1)
			cmp_config_add_hash(32'hff000000 + k);
		send_cmp_config();
		
		send_empty_word_gen(2);
		

		word_list_add("mypwd123");
		word_list_add("mypwd12345");
		word_list_add("11111111");
		word_list_add({ "0123456789012345678901234567890",
			8'd192,8'd193,8'd194,8'd195,8'd196 }); // 35 bytes, 8-bit

		word_list_add({ "0123456789012345678901234567890",
			"12345678901234567890123456789012" }); // 63 bytes
		word_list_add({ "0123456789012345678901234567890",
			"123456789012345678901234567890123" }); // 64 bytes
		word_list_add({ "0123456789012345678901234567890",
			"12345678901234567890",8'd193,"1234567890" }); // 62 bytes
		word_list_add({ "0123456789012345678901234567890",
			"12345678901234567890",8'd192,8'd193,"1234567890" });
		word_list_add({ "0123456789012345678901234567890",
			"12345678901234567890",8'd192,8'd193,8'd194,"1234567890" });
		word_list_add({ "salt_len=16, key_len=64, contains 8-bit chars (",
			8'd192,8'd193, 8'd194,8'd196,8'd195,") .........z" });

		for (k=0; k < 10; k=k+1) begin
			char <= 8'd200 + k;
			word_list_add({ "salt_len=16, key_len=64, contains 8-bit chars (",
				8'd192,8'd193, 8'd194,8'd195,char,") .........z" });
		end

		word_list_add({ "salt_len=16, key_len=64, contains 8-bit chars (",
			8'd192,8'd193, 8'd194,8'd195,8'd196,") .........z" }); // <-- right 1
		word_list_add({ "salt_len=16, key_len=64, contains 8-bit chars (",
			8'd192,8'd193, 8'd195,8'd195,8'd196,") .........z" });
		word_list_add({ "salt_len=16, key_len=64, contains 8-bit chars (",
			8'd192,8'd193, 8'd194,8'd196,8'd196,") .........z" });
		
		// 23 candidates total. Running time (on 2 units) --- us.
		// CMP_RESULT: pkt_id=2, word_id=20, gen_id=0, hash_num=25
		send_word_list();
*/

		// *****************************************************************
		//
		// Test #3.
		//
		// 3 hashes with same salt from John the Ripper, sha512crypt_common.h
		//
		//	{"$6$LKO/Ute40T3FNF95$6S/6T2YuOIHY0N3XpLKABJ3soYcXD9mB7uVbtEZDj"
		//		"/LNscVhZoZ9DEH.sBciDrMsHOWOoASbNLTypH/5X26gN0", "U*U*U*U*"},
		//	{"$6$LKO/Ute40T3FNF95$wK80cNqkiAUzFuVGxW6eFe8J.fSVI65MD5yEm8EjY"
		//		"MaJuDrhwe5XXpHDJpwF/kY.afsUs1LlgQAaOapVNbggZ1", "U*U***U"},
		//	{"$6$LKO/Ute40T3FNF95$YS81pp1uhOHTgKLhSMtQCr2cDiUiN03Ud3gyD4ame"
		//		"viK1Zqz.w3oXsMgO6LrqmIEcG3hiqaUqHi/WEE2zrZqa/", "U*U***U*"},
		//
		// Hashes (MSB 1st):
		// 99b014d9 9d26cfba ... cf8e55f5 8c351f20
		// e5b2592c c58a0147 ... 1485aabd 4a036808
		// 66da04f6 8254b6dd ... 99ba4d1e b536750c
		//
		// *****************************************************************
/*
		cmp_config_create(5000,16,"LKO/Ute40T3FNF95");

		// We send hashes in ascending order. Currently that doesn't
		// matter as linear search is implemented.
		for (k=0; k < 200; k=k+1)
			cmp_config_add_hash(32'h49000000 + k);

		cmp_config_add_hash(32'h4a0368_00);
		cmp_config_add_hash(32'h4a0368_28);
		cmp_config_add_hash(32'h4a0368_18);
		cmp_config_add_hash(32'h4a0368_08); // <-- the right 1
		cmp_config_add_hash(32'h4a0368_09);

		for (k=0; k < 200; k=k+1)
			cmp_config_add_hash(32'h8b000000 + k);

		cmp_config_add_hash(32'h8c351_e20);
		cmp_config_add_hash(32'h8c351_f20); // <-- the right 1
		cmp_config_add_hash(32'h8c351_f21);
		cmp_config_add_hash(32'h8c351_f00);
		cmp_config_add_hash(32'h8c351_f24);

		for (k=410; k < `NUM_HASHES - 1; k=k+1)
			cmp_config_add_hash(32'h99001100 + k);

		cmp_config_add_hash(32'hb536750c); // <-- the right 1
		// Total `NUM_HASHES hashes in CMP_CONFIG
		send_cmp_config();


		// Candidates are split into several packets.
		// ID from input WORD_GEN packets are used in output packets.
		// Packet #1 (pkt_id=3).
		send_empty_word_gen(3);

		word_list_add("mypwd123");
		word_list_add(""); // 0-length word
		word_list_add("11111111");
		for (k=0; k < 27; k=k+1) begin
			char <= "*" + 1 + k;
			word_list_add({"U*U*U*U",char});
		end

		// Must output CMP_RESULT packet (type 0xD4) containing:
		// 512-bit hash, pkt_id=3, word_id=30, gen_id=0, hash_num=406
		word_list_add("U*U*U*U*");
		send_word_list();


		// Packet #2 (pkt_id=4), 32 words. Same CMP_CONFIG applies.
		send_empty_word_gen(4);
		for (k=0; k < 31; k=k+1) begin
			char <= "U" - 10 + k;
			word_list_add({char,"*U***U*"});
		end
		word_list_add("U*U***U");

		// Hashes are 5,000 rounds. The test takes time.
		// Running time (2 units X 4 cores, at 20 ns simulation clock)
		// is ---.
		send_word_list();
*/

		// *****************************************************************
		//
		// Test #4.
		//
		// Using onboard generator. Hash:
		//
		//	{ "$6$rounds=5$1234567", "Pass012",
		//		"$6$rounds=5$1234567$gzYyIG.wBGAzHp8bNIw69VXJtMkr9cKSi38D9x1VuQz"
		//		"/JitL1x.1q3y6rqgEHNWa/Z.XGBmHxYK/NIGR3pYgH1" },
		//
		// d3b2253d4f095342 .. 9acd760c 9b3a84a1 0bdf3819 9cc494fa
		//
		// *****************************************************************
/*
		cmp_config_create(5,7,"1234567"); // rounds=5, salt_len=7
		cmp_config_add_hash(32'h9cc494fa);
		send_cmp_config();

		word_gen_add_range("012");
		word_gen_add_range("012");
		send_word_gen(5);

		// range_info: placeholders in positions 4,5
		word_list_add("Pass##2"); range_info_add(8'h84,8'h85,0,0);
		word_list_add("Pass##1"); range_info_add(8'h84,8'h85,0,0);
		word_list_add("Pass##0"); range_info_add(8'h84,8'h85,0,0);
		send_word_list();
*/

		// *****************************************************************
		//
		// Test #5.
		//
		// Compute, output hashes w/o usage of comparator.
		// Results appear in PKT_RESULT (type 0xD3) packets.
		//
		// *****************************************************************
/*
		// It requires to be idle when app_mode changes.
		// Typically app_mode is set after the GSR and doesn't change
		// during runtime.
		//
		app_mode <= 8'h40;
		//
		//	{ "$6$rounds=1$ssssssss", "11111111",
		//		"$6$rounds=1$ssssssss$qunghpov5q2ivheRC8iomgzuu843t4EsV8"
		//		"5x5u8JCVeIf.bMqb9qAjQY/NmPxIom8agzWm/W0stDhHbrKtfcZ."	},
		//
		//	25a2740288c93d6f ... b914fb8e764d6db3
		//
		cmp_config_create(1,8,"ssssssss");
		//cmp_config_add_hash(32'h4a0368_00);
		send_cmp_config();
		send_empty_word_gen(6);
		word_list_add("11111111");
		send_word_list();

		//	{ "$6$rounds=51$salt_length13", "",
		//		"$6$rounds=51$salt_length13$gKRKWpplj6e3.bJ0mbfgbIihDBLHC"
		//		"LqFQAkyVcWpi1Y6zpsUdTsb9HpuOsIFAT/wQ9ezHVHNnYio6WAe30OUK1" },
		//
		// d681c83365a2cc45 ... ce4de5f209a26259
		//
		cmp_config_create(51,13,"salt_length13");
		send_cmp_config();
		send_empty_word_gen(7);
		word_list_add("");
		send_word_list();

		//	{ "$6$rounds=11$salt_len9", "password 16chars",
		//		"$6$rounds=11$salt_len9$gLFJl32iZRSwMQuyOVLFleb/rooFoP7uZ"
		//		"W/YgNc/wuG892uVTfCqN.ubNBd0UPFKd4M3UUFyrge345y3KExp2." },
		//
		// 04d7e137f981e00a ... f4477a5afbe77155
		//
		cmp_config_create(11,9,"salt_len9");
		send_cmp_config();
		send_empty_word_gen(8);
		word_list_add("password 16chars");
		send_word_list();
*/

		// *****************************************************************
		//
		// Test #6.
		//
		// Drupal7 hashes.
		//
		// *****************************************************************
/*
		// Set Drupal7 program
		#2000;
		send_init_packet(1);
		
		// {"$S$CFURCPa.k6FAEbJPgejaW4nijv7rYgGc4dUJtChQtV4KLJTPTC/u", "password"}
		cmp_config_create(16384,8,"FURCPa.k");
		cmp_config_add_hash(32'h6740c448);
		send_cmp_config();
		
		send_empty_word_gen(6);
		
		word_list_add("passwor-");
		word_list_add("password");
		word_list_add("passwor");
		send_word_list();
*/
	end



	// ***************************************************************
	//
	//
	//
	// ***************************************************************
	reg PKT_COMM_CLK = 0, IFCLK = 0, CORE_CLK = 0;

	//wire CORE_CLK = PKT_COMM_CLK;

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

	sha512crypt #(.DISABLE_CHECKSUM(1)) pkt_comm(
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

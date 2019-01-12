`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module sha256crypt_test();

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
		// Hash formatted as in reference implementation:
		// { "$5$rounds=10$0//3456789//edef", "key_len=11.",
		// "$5$rounds=10$0//3456789//edef$PSqu85Ls/ajCpozZe"
		// "xq3yEZhffR0avwyFklOQhdAgD5" },
		//
		// Data packet for computing unit (sha512unit_test.v):
		// send_data_packet(10,16,11,"0//3456789//edef","key_len=11.");
		//
		// Hash (MSB 1st): 73ec5c1c ... 978171eb
		//
		// *****************************************************************

		// Usage: send_config_packet(subtype,data_len,data);
		// exclude units 0,6,7,12
		//send_config_packet(1,2,32'b_0000_0000_0001_0000_1100_0001);

		// Usage: cmp_config_create(cnt,salt_len,"salt");
		cmp_config_create(10,16,"0//3456789//edef");
		cmp_config_add_hash(32'h978171eb);
		send_cmp_config();

		send_empty_word_gen(1);

		word_list_add("mypwd123");
		word_list_add("mypwd1234");
		word_list_add("mypwd12345");
		word_list_add("pass_len_is15..");

		//for (k=0; k < 180; k=k+1)
		//for (k=0; k < 60; k=k+1)
			word_list_add("0123456789abc");
			//word_list_add("abc");

		word_list_add("key_len=11z");
		word_list_add("key_len=11.");
		word_list_add("key_len=12.");
		// 8 candidates total
		send_word_list();



		// *****************************************************************
		//
		// Test #6.
		//
		// *****************************************************************
/*
		#2000;
		send_init_packet(1);

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

	sha256crypt #(.DISABLE_CHECKSUM(1)) pkt_comm(
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

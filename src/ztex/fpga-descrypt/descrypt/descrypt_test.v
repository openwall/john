`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016-2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module descrypt_test();

	integer i;
	integer k;

	reg CLK = 0, CORE_CLK = 0, IFCLK = 0;//, CMP_CLK = 0, WORD_GEN_CLK = 0;
	assign WORD_GEN_CLK = CORE_CLK;
	assign CMP_CLK = CORE_CLK;

	reg [7:0] din;

	wire [15:0] app_dout;
	reg [7:0] app_mode = 8'd02;
	wire [7:0] app_status, pkt_comm_status, debug2;

	wire [7:0] hs_input_dout;
	reg wr_en = 0;

	fifo_sync_small #( .A_WIDTH(12), .D_WIDTH(8)
	) fifo_input1(
		.CLK(CLK),
		.din(din),
		.wr_en(wr_en),
		.full(),

		.dout(hs_input_dout),
		.rd_en(hs_input_rd_en),
		.empty(hs_input_empty)
	);

	descrypt #(.DISABLE_CHECKSUM(1)) pkt_comm(
		.PKT_COMM_CLK(CLK),
		.WORD_GEN_CLK(WORD_GEN_CLK),
		.CORE_CLK(CORE_CLK),
		.CMP_CLK(CMP_CLK),
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
		// Application status (via VCR I/O). Available at fpga->wr.io_state.app_status
		.pkt_comm_status(pkt_comm_status),
		.debug2(debug2), .debug3(),
		.app_status(app_status)
	);

	output_fifo output_fifo(
		.wr_clk(CMP_CLK),
		.din(app_dout),
		.wr_en(app_wr_en),
		.full(app_full),

		.rd_clk(IFCLK),
		.dout(), // wired to Cypress IO,
		.rd_en(1'b0), // wired to Cypress IO,
		.empty(), // wired to Cypress IO
		.mode_limit(1'b1),
		.reg_output_limit(1'b0),
		.output_limit(),
		.output_limit_not_done()
	);

	// *** TEST #1 ***
	initial begin
		#1000;
		wr_en <= 1;
		// write cmp_config packet (type 3)
		din <= 2; #20; // ver
		din <= 3; #20; // type
		din <= 0; #40; // reserved0
		din <= 5 + 10*5; #20; // len[7:0]
		din <= 0; #40; // len[23:8]
		din <= 0; #20; // reserved1
		din <= 8'hAB; #20; // id0
		din <= 8'hCD; #20; // id1;
		din <= 0; #80; // checksum

		// 10 hashes
		din <= 8'hC7; #20; // salt "55" (2 bytes)
		din <= 8'h01; #20;
		din <= 8'd10; #20; // number of hashes (2 bytes)
		din <= 8'h00; #20;
		din <= 8'hbb; #1000; // binary hashes (5 bytes each hash)
		din <= 8'hCC; #20; // "magic" 0xCC at the end of the packet

		din <= 0; #80; // checksum
		wr_en <= 0;
	end

	// *** TEST #2 ***
	initial begin
		#50000;
		wr_en <= 1;
		// write cmp_config packet (2 hashes). It replaces
		// the previous comparator configuration.
		din <= 2; #20; // ver
		din <= 3; #20; // type
		din <= 0; #40; // reserved0
		din <= 5+2*5; #20; // len[7:0]
		din <= 0; #40; // len[23:8]
		din <= 0; #20; // reserved1
		din <= 8'hAB; #20; // id0
		din <= 8'hCD; #20; // id1;
		din <= 0; #80; // checksum

		din <= 8'hC7; #20; // salt "55"
		din <= 8'h01; #20;
		din <= 8'h02; #20; // 2 hashes
		din <= 8'h00; #20;
		// hash for "mypwd123"
		din <= 8'had; #20;  din <= 8'h31; #20;  din <= 8'h87; #20;  din <= 8'hcc; #20;
		din <= 8'he3; #20;
		// "mypwd999"
		din <= 8'hcb; #20;  din <= 8'h68; #20;  din <= 8'h00; #20;  din <= 8'h08; #20;
		din <= 8'h8f; #20;
		din <= 8'hCC; #20;
		din <= 0; #80; // checksum

		// word_gen packet (type 2) - "empty" generator (words pass-by)
		din <= 2; #20;  din <= 2; #20; din <= 0; #40;
		din <= 6; #20; // len[7:0]
		din <= 0; #60;  din <= 8'h07; #40;  din <= 0; #80;
		din <= 0; #20; // num_ranges
		din <= 0; #80; din <= 8'hbb; #20;
		din <= 0; #80; // checksum

		// word_list packet (type 1) containing 1 word "mypwd123".
		// length of the word equals to max_len=8, hence not 0-terminated.
		din <= 2; #20;  din <= 1; #20; din <= 0; #40;
		din <= 8; #20; // len[7:0]
		din <= 0; #60;  din <= 8'h07; #40;  din <= 0; #80;
		// body
		din <= "m"; #20; din <= "y"; #20; din <= "p"; #20; din <= "w"; #20;
		din <= "d"; #20; din <= "1"; #20; din <= "2"; #20; din <= "3"; #20;
		din <= 0; #80; // checksum

		wr_en <= 0;
	end

	// *** TEST #3 ***
	initial begin
		#100000;
		wr_en <= 1;
		// write cmp_config packet (42 hashes)
		din <= 2; #20; // ver
		din <= 3; #20; // type
		din <= 0; #40; // reserved0
		din <= 5 + 42*5; #20; // len[7:0]
		din <= 0; #40; // len[23:8]
		din <= 0; #20; // reserved1
		din <= 8'hAB; #20; // id0
		din <= 8'hCD; #20; // id1;
		din <= 0; #80; // checksum

		din <= 8'hC7; #20; // salt "55"
		din <= 8'h01; #20;
		din <= 8'd42; #20; // 42 hashes
		din <= 8'h00; #20;
		// 15 dummy hashes.
		// Hashes must be sorted in ascending order using 35 least-significant bits.
		// 5 upper bits are not used.
		din <= 8'h00; #(20*5 *15);
		// hash for "mypwd123"
		din <= 8'had; #20;  din <= 8'h31; #20;  din <= 8'h87; #20;  din <= 8'hcc; #20;
		din <= 8'he3; #20;
		// "mypwd999"
		din <= 8'hcb; #20;  din <= 8'h68; #20;  din <= 8'h00; #20;  din <= 8'h08; #20;
		din <= 8'h8f; #20;
		// 25 dummy hashes.
		din <= 8'hff; #(20*5 *25);
		din <= 8'hCC; #20;
		din <= 0; #80; // checksum

		// To check the correctness of the testbench you can do:
		// - check descrypt.v:pkt_comm_status for errors (0 = no packet parse errors)
		// - check inpkt_header.v:pkt_state (!= PKT_STATE_VERSION would mean
		//   it awaits more data, that might be because of incorrect packet length)

		// Repeat k times
		for (k=0; k < 2; k=k+1) begin

		// word_gen packet header
		din <= 2; #20;  din <= 2; #20; din <= 0; #40;
		din <= 6 + 3*12; #20; // 3 ranges X 12 bytes
		din <= 0; #60;  din <= 8'h07; #40;  din <= 0; #80;
		// body
		din <= 3; #20; // num_ranges
		din <= 10; #20;  din <= 0; #20; // range #0: 10 chars [0-9]
		din <= "0"; #20; din <= "1"; #20; din <= "2"; #20; din <= "3"; #20; din <= "4"; #20;
		din <= "5"; #20; din <= "6"; #20; din <= "7"; #20; din <= "8"; #20; din <= "9"; #20;
		din <= 10; #20;  din <= 0; #20; // range #1: 10 chars [0-9]
		din <= "0"; #20; din <= "1"; #20; din <= "2"; #20; din <= "3"; #20; din <= "4"; #20;
		din <= "5"; #20; din <= "6"; #20; din <= "7"; #20; din <= "8"; #20; din <= "9"; #20;
		din <= 10; #20;  din <= 0; #20; // range #2: 10 chars [0-9]
		din <= "0"; #20; din <= "1"; #20; din <= "2"; #20; din <= "3"; #20; din <= "4"; #20;
		din <= "5"; #20; din <= "6"; #20; din <= "7"; #20; din <= "8"; #20; din <= "9"; #20;
		din <= 0; #80; din <= 8'hbb; #20; // num_generate(not used), "magic" 0xbb
		din <= 0; #80; // checksum

		// template_list packet (type 4): 1 template key
		din <= 2; #20;  din <= 4; #20; din <= 0; #40;
		din <= 8 + 4; #20; // len[7:0]
		din <= 0; #60;  din <= 8'h07; #40;  din <= 0; #80;
		// body
		din <= "m"; #20; din <= "y"; #20; din <= "p"; #20; din <= "w"; #20;
		din <= "d"; #20; din <= "#"; #20; din <= "#"; #20; din <= "#"; #20;
		// after template key it expects range_info bytes
		// Placeholders are in positions 5,6,7.
		din <= 8'h85; #20; din <= 8'h86; #20; din <= 8'h87; #20;
		// if number of range_info bytes are less than RANGES_MAX
		// then range_info bytes are terminated with 0
		din <= 0; #20;
		din <= 0; #80; // packet checksum

		end // for(k=...

		wr_en <= 0;
	end


	initial begin
		#5;
		while (1) begin
			CLK <= ~CLK; #10;
		end
	end

	initial begin
		#4;
		while (1) begin
			CORE_CLK <= ~CORE_CLK; #8;
		end
	end
/*
	initial begin
		#7;
		while (1) begin
			CMP_CLK <= ~CMP_CLK; #14;
		end
	end
*/
	initial begin
		#35;
		while (1) begin
			IFCLK <= ~IFCLK; #70;
		end
	end
/*
	initial begin
		#3;
		while (1) begin
			WORD_GEN_CLK <= ~WORD_GEN_CLK; #6;
		end
	end
*/
endmodule

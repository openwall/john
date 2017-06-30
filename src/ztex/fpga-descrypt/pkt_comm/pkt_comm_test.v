`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module pkt_comm_test();
	
	integer i;
	integer k;

	reg CLK = 0, CMP_CLK = 0, CORE_CLK = 0, IFCLK = 0, WORD_GEN_CLK = 0;
	
	reg [7:0] din;
	
	wire [15:0] app_dout;
	reg [7:0] app_mode = 8'd02;
	wire [7:0] app_status, pkt_comm_status, debug2;
	
	wire [7:0] hs_input_dout;
	reg wr_en = 0;
	
	fifo_bram_8x1024_fwft fifo_bram_8x1024_fwft(
		.wr_clk(CLK),
		.din(din),
		.wr_en(wr_en),
		.full(),

		.rd_clk(CLK),
		.dout(hs_input_dout),
		.rd_en(hs_input_rd_en),
		.empty(hs_input_empty)
	);

	pkt_comm_arbiter #(.DISABLE_CHECKSUM(1)) pkt_comm(
		.CLK(CLK),
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
		.debug2(debug2),
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

/*
	reg [15:0] r [127:0];
	initial
		for (i=0; i < 128; i=i+1)
			r[i] = 0;
	
	reg [15:0] cnt = 0;
	always @(posedge CMP_CLK)
		if (app_wr_en) begin
			r[cnt] <= app_dout;
			cnt <= cnt + 1'b1;
		end
*/
	initial begin
		#1000;
		wr_en <= 1;
		// write cmp_config packet
		din <= 1; #20; // ver
		din <= 3; #20; // type
		din <= 0; #40; // reserved0
		din <= 13 + 9*8; #20; // len[7:0]
		din <= 0; #40; // len[23:0]
		din <= 0; #20; // reserved1
		din <= 8'hAB; #20; // id0
		din <= 8'hCD; #20; // id1;
		din <= 0; #80; // checksum
		
		// 10 hashes
		din <= 8'hC7; #20;
		din <= 8'h01; #20;
		din <= 8'd10; #20;
		din <= 8'h00; #20;
		din <= 8'hbb; #1600;
		din <= 8'hCC; #20;
		
		din <= 0; #80; // checksum
		wr_en <= 0;
	end

	initial begin
		#50000;
		wr_en <= 1;
		// write cmp_config packet
		din <= 1; #20; // ver
		din <= 3; #20; // type
		din <= 0; #40; // reserved0
		din <= 5+2*8; #20; // len[7:0]
		din <= 0; #40; // len[23:0]
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
		din <= 8'he3; #20;  din <= 8'hf4; #20;  din <= 8'h51; #20;  din <= 8'hac; #20; 
		// "mypwd999"
		din <= 8'hcb; #20;  din <= 8'h68; #20;  din <= 8'h00; #20;  din <= 8'h08; #20; 
		din <= 8'h8f; #20;  din <= 8'h7a; #20;  din <= 8'h7d; #20;  din <= 8'he4; #20; 
		din <= 8'hCC; #20;
		
		din <= 0; #80; // checksum
		wr_en <= 0;
	end
	
	initial begin
		#100000;
		
		for (k=0; k < 2; k=k+1) begin
		
		wr_en <= 1;
		// word_gen packet
		din <= 1; #20;  din <= 2; #20;  din <= 0; #40;
		din <= 35; #20; // len[7:0]
		din <= 0; #60;  din <= 8'h07; #40;  din <= 0; #80;
		// body
		din <= 8; #20; // num_ranges
		din <= 1; #20;  din <= 0; #20;  din <= "m"; #20;
		din <= 1; #20;  din <= 0; #20;  din <= "y"; #20;
		din <= 1; #20;  din <= 0; #20;  din <= "p"; #20;
		din <= 1; #20;  din <= 0; #20;  din <= "w"; #20;
		din <= 1; #20;  din <= 0; #20;  din <= "d"; #20;
		din <= 1; #20;  din <= 0; #20;  din <= "9"; #20; //din <= "1"; #20;
		din <= 1; #20;  din <= 0; #20;  din <= "9"; #20; //din <= "2"; #20;
		din <= 5; #20;  din <= 0; #20;  din <= "9"; #100; //din <= "0"; #20; din <= "3"; #20; 
		
		din <= 0; #20; // num_words
		din <= 0; #80; din <= 8'hbb; #20;
		din <= 0; #80; // checksum
		wr_en <= 0;
		
		end
		
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

	initial begin
		#7;
		while (1) begin
			CMP_CLK <= ~CMP_CLK; #14;
		end
	end

	initial begin
		#35;
		while (1) begin
			IFCLK <= ~IFCLK; #70;
		end
	end

	initial begin
		#3;
		while (1) begin
			WORD_GEN_CLK <= ~WORD_GEN_CLK; #6;
		end
	end

endmodule

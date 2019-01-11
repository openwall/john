`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


`include "../sha256.vh"

module sha256core_test();

	integer k;

	reg CLK = 0; // Each cycle is 20ns

	reg start = 0, ctx_num = 0, seq_num = 0;
	reg [8:0] round_cnt = 0;
	always @(posedge CLK) begin
		if (start)
			start <= 0;

		if (round_cnt == 287)
			round_cnt <= 0;
		else
			round_cnt <= round_cnt + 1'b1;

		if (round_cnt == 0 | round_cnt == 144
				| round_cnt == 23 | round_cnt == 167)
			start <= 1;

		ctx_num <= round_cnt[0];
		
		seq_num <= ~round_cnt[0]
			? ~(round_cnt >= 0 & round_cnt <= 142) // ctx0
			: ~(round_cnt >= 23 & round_cnt <= 165) // ctx1
		;

	end


	reg wr_en = 0;
	reg [31:0] i;
	reg [3:0] wr_addr;
	reg [`BLK_OP_MSB:0] blk_op = 0;
	reg input_ctx = 0;
	reg input_seq = 0;
	reg set_input_ready = 0;
	wire [3:0] ready;

	wire [31:0] core_dout;

	sha256core sha256core(
		.CLK(CLK),

		.start(start), .ctx_num(ctx_num), .seq_num(seq_num),
		.ready(ready),

		.wr_en(wr_en),
		.din(i), .wr_addr(wr_addr),
		.input_blk_op(blk_op),
		.input_ctx(input_ctx), .input_seq(input_seq),
		.set_input_ready(set_input_ready),

		.dout(core_dout), .dout_en(core_dout_en),
		.dout_seq_num(core_dout_seq_num),
		.dout_ctx_num(core_dout_ctx_num)
	);


	initial begin
		#20;
		//
		// TEST 1.
		//
		// Sending 1st block from the 1st element from the test vector
		// from sha256crypt reference implementation [1] as follows:
		//
		// { "$5$saltstring", "Hello world!",
		// "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5" },
		//
		// Sending 16 words X 32 bit.
		// Actually that's concatenated "Hello world!", salt "saltstring"
		// and one more "Hello world!" plus SHA512 padding and data length.
		// Data size is 1 block.
		//
		wr_en <= 1;
		`BLK_OP_IF_NEW_CTX(blk_op) <= 1; // new context
		`BLK_OP_END_COMP_OUTPUT(blk_op) <= 0; // don't output result
		i <= 32'h6c6c6548; wr_addr <= 0; #20;
		i <= 32'h6f77206f; wr_addr <= 1; #20;
		i <= 32'h21646c72; wr_addr <= 2; #20;
		i <= 32'h746c6173; wr_addr <= 3; #20;
		i <= 32'h69727473; wr_addr <= 4; #20;
		i <= 32'h6548676e; wr_addr <= 5; #20;
		i <= 32'h206f6c6c; wr_addr <= 6; #20;
		i <= 32'h6c726f77; wr_addr <= 7; #20;
		i <= 32'h00802164; wr_addr <= 8; #20;
		
		for (k=9; k <= 14; k=k+1) begin
			i <= 32'h0; wr_addr <= k; #20;
		end
		set_input_ready <= 1;
		i <= 32'h10010000; wr_addr <= 15; #20;
		set_input_ready <= 0;
		wr_en <= 0;
		#20;
		//start <= 1; #20;
		//start <= 0;

		//
		// After the run, memory must contain: (no SWAP)
		// (cells 32-39 of sha256block.w_mem.mem0)
		// [39] 4b30312f
		// [38] 1a4b690a
		// ...
		// [33] 6a322253
		// [32] bd37bfc1
		//

		while (~ready) #20;

		//
		// TEST 2.
		//
		// Performing 2nd computation from the 1st element from the reference
		// implementation.
		// The content also begins with "Hello world!saltstring"
		// Follows binary data derived from the previous computation:
		// - 12 first bytes (=key_len) from the previous result ("alternate sum")
		// - "Take the binary representation of the length of the key and for every
      //   1 add the alternate sum, for every 0 the key."
		// Data size is 2 blocks.
		//
/*	
	wr_en <= 1;
		`BLK_OP_IF_NEW_CTX(blk_op) <= 1; // new context
		`BLK_OP_END_COMP_OUTPUT(blk_op) <= 0; // don't output result
		i <= 32'h6c6c6548; wr_addr <= 0; #20;
		i <= 32'h6f77206f; wr_addr <= 1; #20;
		i <= 32'h21646c72; wr_addr <= 2; #20;
		i <= 32'h746c6173; wr_addr <= 3; #20;
		i <= 32'h69727473; wr_addr <= 4; #20;
		i <= 32'h304b676e; wr_addr <= 5; #20;
		i <= 32'h4b1a2f31; wr_addr <= 6; #20;
		i <= 32'he12f0a69; wr_addr <= 7; #20;
		i <= 32'h65488c9a; wr_addr <= 8; #20;
		i <= 32'h206f6c6c; wr_addr <= 9; #20;
		i <= 32'h6c726f77; wr_addr <= 10; #20;
		i <= 32'h65482164; wr_addr <= 11; #20;
		i <= 32'h206f6c6c; wr_addr <= 12; #20;
		i <= 32'h6c726f77; wr_addr <= 13; #20;
		i <= 32'h304b2164; wr_addr <= 14; #20;
		set_input_ready <= 1;
		i <= 32'h4b1a2f31; wr_addr <= 15; #20;
		set_input_ready <= 0;
		wr_en <= 0;
		// [7] 4d2bbb07
		// [0] b3c2ba3e
*/
		while (~ready) #20;
/*
		// Sending the 2nd block (final)
		wr_en <= 1;
		`BLK_OP_IF_NEW_CTX(blk_op) <= 0; // continue context
		`BLK_OP_END_COMP_OUTPUT(blk_op) <= 1; // output result
		set_input_ready <= 1;
		i <= 64'h06ad7ce39ea3893f; wr_addr <= 0; #20;
		set_input_ready <= 0;
		i <= 64'hedff998f3b647fb3; wr_addr <= 1; #20;
		i <= 64'hd5cfed28ff76201b; wr_addr <= 2; #20;
		i <= 64'h6e12f50c6dce61bc; wr_addr <= 3; #20;
		i <= 64'he19f993d7cd8e59a; wr_addr <= 4; #20;
		i <= 64'h0bf90ddc132c1287; wr_addr <= 5; #20;
		i <= 64'h93d246618124ee15; wr_addr <= 6; #20;
		i <= 64'h0000000000802cf9; wr_addr <= 7; #20;
		for (k=8; k <= 14; k=k+1) begin
			i <= 64'h0; wr_addr <= k; #20;
		end
		i <= 64'hd005000000000000; wr_addr <= 15; #20;
		wr_en <= 0;
		// memory:
		// [7] d31227da_ebe0b43e
		// [0] d8a1cff2_fbd26c81

		while (~ready) #20;
*/
	end

	// *****************************************************
	//
	// Collect output from the core (16 x 16)
	//
	// *****************************************************
/*
	reg [15:0] CORE_OUTPUT [15:0];
	
	initial begin
		#20;
		while (~core_out_ready) #20;
		rd_en <= 1; #20;
		rd_en <= 0;
		// Using: core_output_buf_bram
		// core_rd_en to core_out_start delay: 2 cycles
		// core_out_start to 1st data word delay: 1 cycle
		while (~core_out_start) #20;
		#20;
		for (k=0; k < 16; k=k+1) begin
			CORE_OUTPUT [k] <= core_dout; #20;
		end
		
	end
*/

	initial begin
		#5;
		while(1) begin
			CLK <= ~CLK; #10;
		end
	end

endmodule

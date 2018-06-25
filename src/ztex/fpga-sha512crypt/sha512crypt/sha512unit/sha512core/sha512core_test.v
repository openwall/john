`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// !!!!!!!!
//
// At the moment, this testbench doesn't work - requires
// an adjustment as core's interface was modified
//
// !!!!!!!!

//
// Version 121217 of sha512core works well. However
// it would require some (relatively) minor changes
// to allow the connection of several cores to sha512crypt engine.
// Issues:
// - only context0 is handled by control logic; control logic
// itself might require optimization
// - output is to be finalized;
//
`include "../sha512.vh"

module sha512core_test();

	integer k;

	reg CLK = 0; // Each cycle is 20ns

	wire [63:0] out;

	reg wr_en = 0;
	reg [63:0] i;
	reg [3:0] wr_addr;
	reg input_ctx = 0;
	reg [`BLK_OP_MSB:0] blk_op;
	reg set_input_ready = 0;

	sha512core sha512core(
		.CLK(CLK),
		.ready0(ready0), .ready1(ready1),

		.wr_en(wr_en), .in(i), .wr_addr(wr_addr),
		.input_ctx(input_ctx), .input_blk_op(blk_op),
		.input_seq(1'b0), .set_input_ready(set_input_ready),

		.dout(out), .valid(valid)
	);


	initial begin
		#20;
		//
		// TEST 1.
		//
		// Sending 1st block from the 1st element from the test vector
		// from sha512crypt reference implementation [1] as follows:
		//
		// { "$6$saltstring", "Hello world!",
		// "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu"
		// "esI68u4OTLiBFdcbYEdFCoEOfaS35inz1" },
		//
		// Sending 16 words X 64 bit.
		// Actually that's concatenated "Hello world!", salt "saltstring"
		// and one more "Hello world!" plus SHA512 padding and data length.
		// Data size is 1 block.
		//
		wr_en <= 1;
		`BLK_OP_IF_CONTINUE_CTX(blk_op) <= 0;
		`BLK_OP_IF_NEW_CTX(blk_op) <= 1; // new context
		//`BLK_OP_LOAD_CTX_NUM(blk_op) <= 0;
		`BLK_OP_SAVE_CTX_NUM(blk_op) <= 0; // save to slot 0
		set_input_ready <= 1;
		i <= 64'h6f77206f6c6c6548; wr_addr <= 0; #20;
		set_input_ready <= 0;
		i <= 64'h746c617321646c72; wr_addr <= 1; #20;
		i <= 64'h6548676e69727473; wr_addr <= 2; #20;
		i <= 64'h6c726f77206f6c6c; wr_addr <= 3; #20;
		i <= 64'h0000000000802164; wr_addr <= 4; #20;
		for (k=5; k <= 14; k=k+1) begin
			i <= 64'h0; wr_addr <= k; #20;
		end
		i <= 64'h1001000000000000; wr_addr <= 15; #20;
		wr_en <= 0;
		//
		// After the run, memory must contain: (no SWAP)
		// [7] 91b834ddbfa43f89
		// [6] a39e..b37f
		// ...
		// [1] 2c13..15ee
		// [0] 2481..f92c
		//

		while (~ready0) #20;
		// Using ctx1, to allow 2 computattions run in parallel
		//input_ctx <= 1;

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
		wr_en <= 1;
		`BLK_OP_IF_CONTINUE_CTX(blk_op) <= 0;
		`BLK_OP_IF_NEW_CTX(blk_op) <= 1; // new context
		//`BLK_OP_LOAD_CTX_NUM(blk_op) <= 0;
		`BLK_OP_SAVE_CTX_NUM(blk_op) <= 1; // save into slot 1
		set_input_ready <= 1;
		i <= 64'h6f77206f6c6c6548; wr_addr <= 0; #20;
		set_input_ready <= 0;
		i <= 64'h746c617321646c72; wr_addr <= 1; #20;
		i <= 64'hb891676e69727473; wr_addr <= 2; #20;
		i <= 64'h9ea3893fa4bfdd34; wr_addr <= 3; #20;
		i <= 64'h206f6c6c65487ce3; wr_addr <= 4; #20;
		i <= 64'h654821646c726f77; wr_addr <= 5; #20;
		i <= 64'h6c726f77206f6c6c; wr_addr <= 6; #20;
		i <= 64'ha4bfdd34b8912164; wr_addr <= 7; #20;
		i <= 64'h06ad7ce39ea3893f; wr_addr <= 8; #20;
		i <= 64'hedff998f3b647fb3; wr_addr <= 9; #20;
		i <= 64'hd5cfed28ff76201b; wr_addr <= 10; #20;
		i <= 64'h6e12f50c6dce61bc; wr_addr <= 11; #20;
		i <= 64'he19f993d7cd8e59a; wr_addr <= 12; #20;
		i <= 64'h0bf90ddc132c1287; wr_addr <= 13; #20;
		i <= 64'h93d246618124ee15; wr_addr <= 14; #20;
		i <= 64'ha4bfdd34b8912cf9; wr_addr <= 15; #20;
		wr_en <= 0;
		// [7] 05cabd063f060ca8
		// [0] 90dd3da42de5e37e

		while (~ready0) #20;
		//while (~ready1) #20;
		//#5000; // Test delay between 2 blocks from same computation

		// Sending the 2nd block (final)
		wr_en <= 1;
		`BLK_OP_IF_CONTINUE_CTX(blk_op) <= 1; // the next block, continue context
		`BLK_OP_IF_NEW_CTX(blk_op) <= 0;
		`BLK_OP_LOAD_CTX_NUM(blk_op) <= 1; // slot# with values from previous block
		`BLK_OP_SAVE_CTX_NUM(blk_op) <= 3; // save into slot 3
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

		while (~ready1) #20;

	end


	initial begin
		#5;
		while(1) begin
			CLK <= ~CLK; #10;
		end
	end

endmodule

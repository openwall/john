`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


`include "../md5.vh"

module md5core_test();

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

	md5core_type2 md5core(
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
		// pass: "abc" salt: "12345678"
		// $1$12345678$GVDEjIF51EkM3MPmFX6dO1
		//
		// Block #0
		//
		input_ctx <= 0;
		wr_en <= 1;
		`BLK_OP_IF_NEW_CTX(blk_op) <= 1; // new context
		`BLK_OP_END_COMP_OUTPUT(blk_op) <= 0; // don't output result (save into mem2)
		i <= 32'h31636261; wr_addr <= 0; #20;
		i <= 32'h35343332; wr_addr <= 1; #20;
		i <= 32'h61383736; wr_addr <= 2; #20;
		i <= 32'h00806362; wr_addr <= 3; #20;
		for (k=4; k <= 13; k=k+1) begin
			i <= 32'h0; wr_addr <= k; #20;
		end
		i <= 32'h00000070; wr_addr <= 14; #20;
		set_input_ready <= 1;
		i <= 32'h0; wr_addr <= 15; #20;
		set_input_ready <= 0;
		wr_en <= 0;
		#20;
		//while (~ready[0]) #20;
		//
		// After the run mem2 contains:
		// [0] 4d5d219e
		// [1] 0a38ffaf
		// [2] 87e11a6d
		// [3] 9aef84fa
		//
		// TEST 2.
		// crypt_md5("bcdef","01234567");
		// $1$01234567$4hMtkRag.AaWvm433LDEW1
		// Block #0
		//
		input_ctx <= 1;
		input_seq <= 1;
		wr_en <= 1;
		`BLK_OP_IF_NEW_CTX(blk_op) <= 1; // new context
		`BLK_OP_END_COMP_OUTPUT(blk_op) <= 0; // don't output result (save into mem2)
		i <= 32'h65646362; wr_addr <= 0; #20;
		i <= 32'h32313066; wr_addr <= 1; #20;
		i <= 32'h36353433; wr_addr <= 2; #20;
		i <= 32'h64636237; wr_addr <= 3; #20;
		i <= 32'h00806665; wr_addr <= 4; #20;
		for (k=5; k <= 13; k=k+1) begin
			i <= 32'h0; wr_addr <= k; #20;
		end
		i <= 32'h00000090; wr_addr <= 14; #20;
		set_input_ready <= 1;
		i <= 32'h0; wr_addr <= 15; #20;
		set_input_ready <= 0;
		wr_en <= 0;
		#20;
		//
		// After the run, mem2 contains:
		// [12] 40593c8c
		// [15] ad91ecaa

		//while (~ready[0]) #20;
	end



	// *****************************************************
	//
	// OUTDATED !
	// Collect output from the core
	//
	// *****************************************************


	initial begin
		#5;
		while(1) begin
			CLK <= ~CLK; #10;
		end
	end

endmodule

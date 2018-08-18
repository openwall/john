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

`ifdef SIMULATION
//
// - fully performs SHA-256 computation, incl. addition after each block
// - it's able for multiple blocks
// - 2 blocks are performed in 2*(64+8) = 144 cycles, given
//   input buffer always has supply of data in time.
//
module sha256core #(
	parameter ID = -1
	)(
	input CLK,
	// Synchronization of several cores
	input start, // asserts on cycle 0 of each sequence
	output reg ready = 1, // input buffer is ready for data

	input wr_en,
	input [31:0] in,
	input [3:0] wr_addr,
	input [`BLK_OP_MSB:0] input_blk_op, // registered on set_input_ready
	input input_seq, // registered on set_input_ready
	input set_input_ready, // valid only when wr_en is asserted

	output [31:0] dout,
	output dout_seq,
	output reg dout_en = 0
	//output dout_en // Asserts 1 cycle before actual data
	);


	// ***************************************************************
	//
	//   STATE, ROUND COUNTERS
	//
	// ***************************************************************
	reg [6:0] cnt = 72; // round count 0..71. (72 - idle)
	
	wire start_eqn = start & input_ready & (cnt == 71 | cnt == 72)
		// Same sequence, same computation - wait until IVs are saved
		& (`BLK_OP_IF_NEW_CTX(input_blk_op_r)
			| input_seq_num_r != dout_seq
			| after_cnt >= 6);

	always @(posedge CLK)
		if (start_eqn) begin
			// If new block has same sequence number - wait
			cnt <= 0;
			blk_op <= input_blk_op_r;
			seq_num <= input_seq_num_r;
		end
		else if (cnt != 72)
			cnt <= cnt + 1'b1;

	// it requires to finish operation after "main" counter is done
	reg [3:0] after_cnt = 12;
	always @(posedge CLK)
		if (cnt == 69) begin
			after_cnt <= 0;
			after_blk_op <= blk_op;
			after_seq_num <= seq_num;
		end
		else if (after_cnt < 12)
			after_cnt <= after_cnt + 1'b1;

	reg ctx_en = 0; // clock enable for A..G
	always @(posedge CLK)
		if (input_ready)
			ctx_en <= 1;
		else if (cnt == 72 & after_cnt == 12)
			ctx_en <= 0;


	// ***************************************************************
	//
	//   INPUT CONTROLS
	//
	// ***************************************************************
	always @(posedge CLK)
		if (wr_en)
			ready <= 0;
		else if (cnt == 8)
			ready <= 1;

	reg input_ready = 0; // input buffer has required data
	always @(posedge CLK)
		if (wr_en & set_input_ready)
			input_ready <= 1;
		else if (start_eqn)
			input_ready <= 0;

`ifdef SIMULATION
	reg z = 0;
	reg [16:0] X_BLK_NUM = 0;
	always @(posedge CLK)
		if (wr_en & set_input_ready) begin
			X_BLK_NUM <= X_BLK_NUM + 1'b1;
			if (X_BLK_NUM == 9 | X_BLK_NUM == 10 | X_BLK_NUM == 11 | X_BLK_NUM == 12)
				z <= 1;
			if (ID==0 & input_seq==1)
				z <= 1;
		end
`endif

	// Options for block computation
	reg [`BLK_OP_MSB:0] input_blk_op_r, blk_op, after_blk_op;
	reg input_seq_num_r, seq_num, after_seq_num;
	always @(posedge CLK)
		if (wr_en & set_input_ready) begin
			input_blk_op_r <= input_blk_op;
			input_seq_num_r <= input_seq;
		end

	assign dout_seq = after_seq_num;


	// ***************************************************************
	//
	//   INPUT - BUFFER & OTHER DATA
	//
	// allows to perform input independently from other operations.
	// If input data is ready, computaion for the next block
	// starts before it finishes the current block.
	//
	// ***************************************************************

	wire input_buf_rd_en = cnt >= 7 & cnt <= 22;
	wire [3:0] input_buf_rd_addr = cnt - 7;
	wire [31:0] input_buf_dout;

	core_input_buf core_input_buf(
		.CLK(CLK), .din(in), .wr_en(wr_en),
		.wr_addr(wr_addr),
		.dout(input_buf_dout), .rd_en(input_buf_rd_en),
		.rd_addr(input_buf_rd_addr)
	);



	// ***************************************************************
	//
	//   BLOCK & CONTEXT OPERATION.
	//
	// ***************************************************************

	// Block controls - read from input buffer & memory
	reg external_input_en = 0;
	always @(posedge CLK)
		external_input_en <= input_buf_rd_en;

	wire mem_rd_en1 =
		// Read starts 1 cycle before mem0 to fill-in W[t-16]
		cnt >= 21 & cnt <= 69
		// load context from mem1 via block2ctx
		| cnt >= 0 & cnt <= 7;

	wire [3:0] rd_addr1_16_63 = cnt - 22 - 15;
	wire [6:0] rd_addr1 =
		// Load context from mem1 via block2ctx
		cnt >= 0 & cnt <= 7 ?
			( `BLK_OP_IF_NEW_CTX(blk_op) ? { 4'b0011, cnt[2:0] } :
				{ seq_num, 1'b1, `BLK_OP_LOAD_CTX_NUM(blk_op), cnt[2:0] }
			)
		: { 3'b000, rd_addr1_16_63 }; // Read W[t-15]


	wire mem_rd_en0 = //cnt >= 22 & cnt <= 69
		cnt >= 21 & cnt <= 69 // opt.
		| after_cnt >= 0 & after_cnt <= 7; // Load IVs for post-additions
	
	wire [3:0] rd_addr0_16_63 = cnt - 22 - 7;
	wire [6:0] rd_addr0 =
		// Load IVs for post-additions
		after_cnt >= 0 & after_cnt <= 7 ?
			( `BLK_OP_IF_NEW_CTX(after_blk_op) ? { 4'b0011, after_cnt[2:0] } :
				{ after_seq_num, 1'b1, `BLK_OP_LOAD_CTX_NUM(after_blk_op),
					after_cnt[2:0] }
			)
		: { 3'b000, rd_addr0_16_63 }; // Read W[t-7]


	// Block controls - write into memory
	reg ctx_save_en = 0;
	always @(posedge CLK)
		ctx_save_en <= after_cnt >= 3 & after_cnt <= 10;

	wire mem_wr_en =
		cnt >= 10 & cnt <= 66 // Write W[t] for t in 0..47
		//| after_cnt >= 4 & after_cnt <= 11; // write result
		| ctx_save_en;// & ~BLK_OP_END_COMP_OUTPUT(after_blk_op);
	
	wire [3:0] mem_wr_addr_0_56 = cnt - 10;
	wire [2:0] mem_wr_addr_result = after_cnt - 4;

	wire [6:0] mem_wr_addr =
		ctx_save_en ?
			// Save context into slot 0..N
			{ after_seq_num, 1'b1, `BLK_OP_SAVE_CTX_NUM(after_blk_op),
				mem_wr_addr_result }
		: { 3'b000, mem_wr_addr_0_56 };
	

	// Block controls - R0, R1, W[t-2], W[t-15]
	//wire R0_en = cnt >= 23 & cnt <= 71;
	reg R0_en = 0;
	always @(posedge CLK)
		R0_en <= cnt >= 22 & cnt <= 70;

	wire Wt_2_en = cnt >= 9 & cnt <= 70;

	//wire R1_rst = cnt == 71;
	//wire R1_en = cnt >= 23 & cnt <= 70;
	reg R1_en = 0;
	always @(posedge CLK)
		R1_en <= cnt >= 23 & cnt <= 70;
	
	wire W16_rst = cnt == 71;
	wire W16_en = cnt >= 23 & cnt <= 70;

	// K unit controls
	wire Kt_en = cnt >= 7 & cnt <= 70;
	wire [6:0] K_round_num = cnt;


	// Context controls
	reg block2ctx_en = 0;
	always @(posedge CLK)
		block2ctx_en <= cnt >= 1 & cnt <= 8;

	wire MAJ_en = ~block2ctx_en;

	wire S0_en = ~block2ctx_en;

	wire S1_CH_I_rst = after_cnt == 3;
	reg S1_CH_I_en = 0;
	always @(posedge CLK)
		S1_CH_I_en <= cnt >= 8 & cnt <= 71;

	reg output_en = 0;
	always @(posedge CLK)
		output_en <= after_cnt >= 2 & after_cnt <= 9;
	
	always @(posedge CLK)
		dout_en <= after_cnt >= 2 & after_cnt <= 9
			& `BLK_OP_END_COMP_OUTPUT(after_blk_op);

	//assign dout_en = output_en;


	wire [31:0] block_output;
	sha256block sha256block(
		.CLK(CLK),
		.external_input_en(external_input_en), .ctx_save_en(ctx_save_en),
		.in(input_buf_dout),// .save_en(1'b1),
		
		.mem_wr_en(mem_wr_en), .wr_addr(mem_wr_addr),
		.mem_rd_en0(mem_rd_en0), .mem_rd_en1(mem_rd_en1),
		.rd_addr0(rd_addr0), .rd_addr1(rd_addr1),

		.R0_en(R0_en), .R1_en(R1_en),// .R1_rst(R1_rst),
		.W16_rst(W16_rst), .W16_en(W16_en), .Wt_2_en(Wt_2_en),

		.Kt_en(Kt_en), .K_round_num(K_round_num),
		
		.S1_CH_I_rst(S1_CH_I_rst), .S1_CH_I_en(S1_CH_I_en),
		.S0_en(S0_en), .MAJ_en(MAJ_en), .block2ctx_en(block2ctx_en),
		.ctx_en(ctx_en), .output_en(output_en),
		.o(block_output)
	);

	assign dout = `SWAP(block_output);

endmodule

`else

module sha256core #(
	parameter ID = -1
	)(
	input CLK,
	// Synchronization of several cores
	input start, // asserts on cycle 0 of each sequence
	output reg ready = 1, // input buffer is ready for data

	input wr_en,
	input [31:0] in,
	input [3:0] wr_addr,
	input [`BLK_OP_MSB:0] input_blk_op, // registered on set_input_ready
	input input_seq, // registered on set_input_ready
	input set_input_ready, // valid only when wr_en is asserted

	output [31:0] dout,
	output dout_seq,
	output reg dout_en = 0
	);

endmodule

`endif


module sha256core_dummy(
	input CLK,
	// Synchronization of several cores
	input start, // asserts on cycle 0 of each sequence
	output ready, // input buffer is ready for data

	input wr_en,
	input [31:0] in,
	input [3:0] wr_addr,
	input [`BLK_OP_MSB:0] input_blk_op, // registered on set_input_ready
	input input_seq, // registered on set_input_ready
	input set_input_ready, // valid only when wr_en is asserted

	output [31:0] dout,
	output dout_seq,
	output dout_en
	);

	(* KEEP="true" *) assign ready = 1'b1;
	//(* KEEP="true" *) assign dout = 1'b0;
	(* KEEP="true" *) assign dout_seq = 1'b0;
	(* KEEP="true" *) assign dout_en = 1'b0;

endmodule


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
//
module sha256core #(
	parameter ID = -1
	)(
	input CLK,
	// External sync. of several cores
	input start, // asserts on cycle 0 of each sequence
	input ctx_num,
	input seq_num,
	output reg [3:0] ready = 4'b1111, // input buffer is ready for data

	input wr_en,
	input [31:0] din,
	input [3:0] wr_addr,
	input [`BLK_OP_MSB:0] input_blk_op, // registered on set_input_ready
	input input_ctx, input_seq,
	input set_input_ready, // valid only when wr_en is asserted

	output [31:0] dout,
	output dout_seq_num, dout_ctx_num,
	output reg dout_en = 0
	);

	reg seq_num_r = 0, start_r = 0;
	always @(posedge CLK) begin
		seq_num_r <= seq_num;
		start_r <= start;
	end


	// ***************************************************************
	//
	//   INPUT CONTROLS
	//
	// Input buffer (for 4 contexts) consists of:
	// - memory [0:63]
	// - input_blk_op_r[0:3]
	//
	// ***************************************************************
	always @(posedge CLK) begin
		if (wr_en)
			ready [{input_ctx, input_seq}] <= 0;
		if (cnte == 22)//67)
			ready [{ctxe, seq_num_curr}] <= 1;
	end

	reg [3:0] input_ready = 4'b0000; // input buffer has required data
	always @(posedge CLK) begin
		if (wr_en & set_input_ready)
			input_ready [{input_seq, input_ctx}] <= 1;
		if (start_eqn)
			input_ready [{seq_num_r, ctxe}] <= 0;
	end

	(* RAM_STYLE="DISTRIBUTED" *)
	reg [`BLK_OP_MSB:0] input_blk_op_r[0:3], blk_op[0:1];
	always @(posedge CLK)
		if (wr_en & set_input_ready)
			input_blk_op_r [{input_seq, input_ctx}] <= input_blk_op;


	// ***************************************************************
	//
	//   STATE, ROUND COUNTERS
	//
	// - Every 2 computation are (RND_CNT_MAX+1)*2 rounds.
	// - Rounds are "interleaved": one cycle it goes context #0
	//   and on the next round it goes context #1.
	// - Cycles are labeled "even" and "odd".
	//
	// ***************************************************************
	localparam RND_CNT_MAX = 71;
	localparam AFTER_CNT_MAX = 11;

	reg ctxe = 0; // context_number in "even" cycle
	// round count (RND_CNT_MAX+1 means idle) for contexts 0,1
	reg [6:0] cnt0 = RND_CNT_MAX+1, cnt1 = RND_CNT_MAX+1;
	// round count for even,odd cycles
	reg [6:0] cnte = RND_CNT_MAX+1, cnto = RND_CNT_MAX+1;
	reg [1:0] ctx_idle = 2'b11;
	reg seq_num_curr = 0, seq_num_curr_r = 0, seq_num0 = 0, seq_num1 = 0;

	always @(posedge CLK) begin
		cnte <= ctxe ? cnt0 : cnt1;
		cnto <= cnte;
		ctxe <= ctx_num;
		seq_num_curr <= ctxe ? seq_num0 : seq_num1;
		seq_num_curr_r <= seq_num_curr;
	end

	// Enable operation of the core
	reg glbl_en = 0;
	always @(posedge CLK)
		glbl_en <= ~(&ctx_idle) | after_cnt != AFTER_CNT_MAX+1;

	wire start_eqn = start_r & input_ready [{seq_num_r, ctxe}];

	always @(posedge CLK) begin
		if (start_eqn) begin
			if (~ctxe) begin
				cnt0 <= 0;
				seq_num0 <= seq_num_r;
			end
			else begin
				cnt1 <= 0;
				seq_num1 <= seq_num_r;
			end
			ctx_idle [ctxe] <= 0;
			blk_op [ctxe] <= input_blk_op_r [{seq_num_r, ctxe}];
		end
		else begin
			if (cnte == RND_CNT_MAX)
				ctx_idle [ctxe] <= 1;
			if (cnte != RND_CNT_MAX+1 & ~ctxe)
				cnt0 <= cnte + 1'b1;
			if (cnte != RND_CNT_MAX+1 & ctxe)
				cnt1 <= cnte + 1'b1;
		end
	end

	// it requires to finish operation after "main" counter is done
	reg [3:0] after_cnt = AFTER_CNT_MAX+1;
	// Only 1 context at a time is performing finishing operation
	// after "main" counter
	reg after_ctx;
	reg after_seq_num;
	reg [`BLK_OP_MSB:0] after_blk_op;

	always @(posedge CLK) begin
		if (after_cnt != AFTER_CNT_MAX+1 & after_ctx == ctxe)
			after_cnt <= after_cnt + 1'b1;
		if (cnte == 69) begin
			after_cnt <= 0;
			after_ctx <= ctxe;
			after_seq_num <= seq_num_curr;
			after_blk_op <= blk_op [ctxe];
		end
	end


	// ***************************************************************
	//
	//   BLOCK & CONTEXT OPERATION.
	//
	// ***************************************************************
	wire input_buf_rd_en = cnte >= 6 & cnte <= 21;
	wire [3:0] cnte_minus6 = cnte - 6;
	wire [5:0] input_buf_rd_addr = { seq_num_curr, ctxe, cnte_minus6 };

	reg input_buf_en = 0;
	always @(posedge CLK)
		input_buf_en <= input_buf_rd_en;

	reg R0_en = 0;
	always @(posedge CLK)
		R0_en <= cnto >= 22 & cnto <= 69;

	reg cnte_in22_69 = 0;
	always @(posedge CLK)
		cnte_in22_69 <= cnto >= 21 & cnto <= 68;

	wire [3:0] Wt_minus7 = cnte - 7 - 22;
	wire [6:0] mem_rd_addr0 =
		cnte_in22_69
			? { seq_num_curr, ctxe, 1'b0, Wt_minus7 }
			: (`BLK_OP_IF_NEW_CTX(after_blk_op)
				? { 4'b0011, after_cnt[2:0] }
				: { after_seq_num, after_ctx, 2'b10, after_cnt[2:0] }
			);

	wire mem_rd_en0 = cnte_in22_69 | after_cnt != AFTER_CNT_MAX+1;

	wire [3:0] Wt_minus15 = cnte - 15 - 22;
	wire [6:0] mem_rd_addr1 =
		cnte >= 0 & cnte <= 7 ? ( // IVs
			`BLK_OP_IF_NEW_CTX(blk_op[ctxe])
				? { 4'b0011, cnte[2:0] }
				: { seq_num_curr, ctxe, 2'b10, cnte[2:0] }
		) : { seq_num_curr, ctxe, 1'b0, Wt_minus15 };

	wire mem_rd_en1 = ~(cnte >= 8 & cnte <= 19) & glbl_en;


	reg ctx_save_en = 0, mem_wr_en2 = 0;
	always @(posedge CLK) begin
		dout_en <= after_cnt >= 3 & after_cnt <= 10
			& after_ctx != ctxe & `BLK_OP_END_COMP_OUTPUT(after_blk_op);
		ctx_save_en <= after_cnt >= 3 & after_cnt <= 10
			& after_ctx != ctxe;
		mem_wr_en2 <= ctx_save_en
			& ~`BLK_OP_END_COMP_OUTPUT(after_blk_op);
	end

	// Write W[t] for t in 0..56
	wire mem_wr_en1 = cnto >= 9 & cnto <= 65;

	wire mem_wr_en = mem_wr_en1 | mem_wr_en2;

	wire [3:0] cnto_minus9 = cnto - 9;
	wire [2:0] after_cnt_minus4 = after_cnt - 4;
	wire [6:0] mem_wr_addr = mem_wr_en2
		? { after_seq_num, after_ctx, 2'b10, after_cnt_minus4 }
		: { seq_num_curr_r, ~ctxe, 1'b0, cnto_minus9 };


	wire W16_rst = cnte <= 22 | cnte >= RND_CNT_MAX;

	wire R1_rst = cnte <= 22 | cnte >= RND_CNT_MAX;

	wire Kt_en = cnto >= 7 & cnto < RND_CNT_MAX;

	reg R1_2_en = 0;
	always @(posedge CLK)
		R1_2_en <= cnte >= 8 & cnte < RND_CNT_MAX-1;

	reg block2ctx_en = 0;
	always @(posedge CLK)
		block2ctx_en <= cnto >= 0 & cnto <= 7;

	wire S0_rst = block2ctx_en;//cnte >= 1 & cnte <= 8;
	wire T1_rst = S0_rst;

	wire S1_CH_rst = cnto >= 0 & cnto <= 7;

	reg D2E_en = 0;
	always @(posedge CLK)
		D2E_en <= block2ctx_en//cnte >= 1 & cnte <= 8
			| after_cnt >= 3
			& after_cnt <= 6 & after_ctx == ctxe;


	wire [31:0] block_output;
	sha256block sha256block(
		.CLK(CLK),
		// input buffer
		.wr_en(wr_en), .din( `SWAP(din) ),
		.input_buf_wr_addr({ input_seq, input_ctx, wr_addr }),
		.input_buf_rd_en(input_buf_rd_en),
		.input_buf_rd_addr(input_buf_rd_addr),

		.glbl_en(glbl_en),
		.input_buf_en(input_buf_en), .ctx_save_en(ctx_save_en),
		.save_r_en(glbl_en),

		.mem_wr_en(mem_wr_en), .wr_addr(mem_wr_addr),
		.mem_rd_en0(mem_rd_en0), .mem_rd_en1(mem_rd_en1),
		.rd_addr0(mem_rd_addr0), .rd_addr1(mem_rd_addr1),

		.R0_en(R0_en), .R1_rst(R1_rst), .R1_en(glbl_en),
		.W16_rst(W16_rst), .W16_en(glbl_en), .R1_2_en(R1_2_en),

		.Kt_en(Kt_en), .K_round_num(cnto),

		.S1_CH_rst(S1_CH_rst), .S0_rst(S0_rst),
		.D2E_en(D2E_en),
		.block2ctx_en(block2ctx_en), .T1_rst(T1_rst),

		.o(block_output)
	);

	assign dout = `SWAP(block_output);
	assign dout_seq_num = after_seq_num;
	assign dout_ctx_num = after_ctx;

endmodule

`else

module sha256core #(
	parameter ID = -1
	)(
	input CLK,
	// External sync. of several cores
	input start, // asserts on cycle 0 of each sequence
	input ctx_num,
	input seq_num,
	output reg [3:0] ready = 4'b1111, // input buffer is ready for data

	input wr_en,
	input [31:0] din,
	input [3:0] wr_addr,
	input [`BLK_OP_MSB:0] input_blk_op, // registered on set_input_ready
	input input_ctx, input_seq,
	input set_input_ready, // valid only when wr_en is asserted

	output [31:0] dout,
	output dout_seq_num, dout_ctx_num,
	output reg dout_en = 0
	);

endmodule

`endif


module sha256core_dummy(
	input CLK,
	// External sync. of several cores
	input start, // asserts on cycle 0 of each sequence
	input ctx_num,
	input seq_num,
	output [3:0] ready, // input buffer is ready for data

	input wr_en,
	input [31:0] din,
	input [3:0] wr_addr,
	input [`BLK_OP_MSB:0] input_blk_op, // registered on set_input_ready
	input input_ctx, input_seq,
	input set_input_ready, // valid only when wr_en is asserted

	output [31:0] dout,
	output dout_seq_num, dout_ctx_num,
	output dout_en
	);

	reg x = 0;
	always @(posedge CLK)
		x <= ~x;

	(* KEEP="true" *) assign dout_seq_num = x;

endmodule


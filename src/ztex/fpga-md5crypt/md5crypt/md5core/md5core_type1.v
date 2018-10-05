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

// md5core Type 1: reduced number of BRAMs (2 x 1K)

`ifdef SIMULATION

module md5core_type1(
	input CLK,
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
	// - memory (rows 0-63)
	// - input_blk_op_r[0:3]
	//
	// ***************************************************************
	always @(posedge CLK) begin
		if (wr_en)
			ready [{input_ctx, input_seq}] <= 0;
		if (cnte == 67)
			ready [{ctxe, seq_num_curr[ctxe]}] <= 1;
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

	(* RAM_STYLE="DISTRIBUTED" *)
	reg [0:0] seq_num_curr [0:1];
	always @(posedge CLK)
		if (start_eqn)
			seq_num_curr [ctxe] <= seq_num_r;


	// ***************************************************************
	//
	//   STATE, ROUND COUNTERS
	//
	// - Every 2 computation are (RND_CNT_MAX+1)*2 rounds.
	// - Rounds are "interleaved": one cycle it goes context #0
	//   and on the next round it goes context #1.
	// - Cycles are labeled "even" (read mem, write B,C,D) and "odd".
	//
	// ***************************************************************
	localparam RND_CNT_MAX = 71;
	localparam AFTER_CNT_MAX = 5;

	reg ctxe = 0; // context # in "even" cycle
	// round count 0..RND_CNT_MAX (RND_CNT_MAX+1 means idle)
	//(* RAM_STYLE="DISTRIBUTED" *)
	//reg [6:0] cnt [1:0];
	//initial cnt[0] = RND_CNT_MAX+1;
	//initial cnt[1] = RND_CNT_MAX+1;
	reg [6:0] cnt0 = RND_CNT_MAX+1, cnt1 = RND_CNT_MAX+1;

	reg [6:0] cnte = RND_CNT_MAX+1, cnto = RND_CNT_MAX+1;
	reg [1:0] ctx_idle = 2'b11;

	always @(posedge CLK) begin
		//cnte <= cnt [~ctxe];
		cnte <= ctxe ? cnt0 : cnt1;

		cnto <= cnte;
		ctxe <= ctx_num;
	end

	// Enable operation of the core
	reg glbl_en = 0;
	always @(posedge CLK)
		glbl_en <= ~(&ctx_idle) | after_cnt != AFTER_CNT_MAX+1;


	wire start_eqn = start_r & input_ready [{seq_num_r, ctxe}];

	always @(posedge CLK) begin
		if (start_eqn) begin
			if (~ctxe)
				cnt0 <= 0;
			else
				cnt1 <= 0;
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
	reg [2:0] after_cnt = AFTER_CNT_MAX+1;
	// Only 1 context at a time is performing finishing operation
	// after "main" counter
	reg after_ctx;
	reg after_seq_num;
	reg [`BLK_OP_MSB:0] after_blk_op;

	always @(posedge CLK) begin
		if (after_cnt != AFTER_CNT_MAX+1 & after_ctx == ctxe)
			after_cnt <= after_cnt + 1'b1;
		//else
		if (cnte == 67) begin
			after_cnt <= 0;
			after_ctx <= ctxe;
			after_seq_num <= seq_num_curr [ctxe];
			after_blk_op <= blk_op [ctxe];
		end
	end


	// ***************************************************************
	//
	//   BLOCK & CONTEXT OPERATION.
	//
	// ***************************************************************
	// Write memory1 (from input)
	wire [5:0] mem_wr_addr = { input_seq, input_ctx, wr_addr };

	// Write memory2 (save context)
	reg mem2_wr_en = 0;
	always @(posedge CLK) begin
		mem2_wr_en <= after_cnt >= 2 & after_cnt <= 5
			& after_ctx != ctxe & ~`BLK_OP_END_COMP_OUTPUT(after_blk_op);
		// 'dout_en' asserts 1 cycle before actual data
		dout_en <= after_cnt >= 1 & after_cnt <= 4
			& after_ctx == ctxe & `BLK_OP_END_COMP_OUTPUT(after_blk_op);
	end

	wire [1:0] mem2_wr_addr_local = after_cnt - 2'd2;
	wire [3:0] mem2_wr_addr =
		{ after_seq_num, after_ctx, mem2_wr_addr_local };


	//
	// Memory, K[t] - Read
	//
	wire [3:0] mem_rd_addr_data;
	cnte2addr_type1 cnte2addr( .cnte(cnte), .rd_addr(mem_rd_addr_data) );

	// Memory1 layout:
	// 0..63 input data (x4 contexts)
	wire [5:0] mem_rd_addr =
		{ seq_num_curr[ctxe], ctxe, mem_rd_addr_data };


	wire mem2_rd_en_add = after_cnt <= 3 & after_ctx == ctxe;
	wire mem2_rd_en = mem2_rd_en_add | cnte >= 0 & cnte <= 3;
	// Memory2 layout:
	// 0..15 saved IVs (x4)
	// 16..19 IVs for a new computation
	wire [4:0] mem2_rd_addr =
		~mem2_rd_en_add ? ( // Initial load of IVs
			`BLK_OP_IF_NEW_CTX(blk_op[ctxe]) ? { 3'b100, cnte[1:0] }
				: { 1'b0, seq_num_curr[ctxe], ctxe, cnte[1:0] }
		) : ( // Load IVs for additions at the end of block
			`BLK_OP_IF_NEW_CTX(after_blk_op) ? { 3'b100, after_cnt[1:0] }
				: { 1'b0, after_seq_num, after_ctx, after_cnt[1:0] }
		);

	wire K_rst = cnto >= 0 & cnto <= 3;
	wire [6:0] K_rnd_num = cnte;


	//
	// Various Controls
	//
	reg ctx_mem2_en = 0;
	always @(posedge CLK)
		ctx_mem2_en <=
			after_cnt >= 1 & after_cnt <= 4 & after_ctx != ctxe
			| cnto >= 0 & cnto <= 3;

	reg ctx_in_rotate = 0;
	always @(posedge CLK)
		ctx_in_rotate <= after_cnt >= 1 & after_cnt <= 4
			& after_ctx != ctxe;

	wire A_rst = cnte >= 1 & cnte <= 4;

	//wire addB2en = cnte >= 6 & cnte <= 69;
	reg addB2en = 0;
	always @(posedge CLK)
		addB2en <= cnto >= 5 & cnto <= 68;

	reg F_en = 0;
	reg [1:0] F_rnd_num = 0;
	always @(posedge CLK) begin
		F_en <= cnte >= 5 & cnte <= 68;
		F_rnd_num <=
			cnte >= 5 & cnte <= 20 ? 2'b00 :
			cnte >= 21 & cnte <= 36 ? 2'b01 :
			cnte >= 37 & cnte <= 52 ? 2'b10 :
			2'b11;
	end

	wire [3:0] rotate_opt;
	cnto2rotate_opt_type1 cnto2rotate_opt(
		.CLK(CLK), .cnto(cnto), .rotate_opt(rotate_opt) );


	md5ctx_type1 md5ctx(
		.CLK(CLK),
		.din(din), .mem_wr_en(wr_en), .mem_wr_addr(mem_wr_addr),
		.mem2_wr_en(mem2_wr_en), .mem2_wr_addr(mem2_wr_addr),
		.mem2_rd_en(mem2_rd_en), .mem2_rd_addr(mem2_rd_addr),

		.mem_rd_en(glbl_en), .mem_rd_addr(mem_rd_addr),
		.en(glbl_en), .F_en(F_en), .addB2en(addB2en), .A_rst(A_rst),
		.F_rnd_num(F_rnd_num),

		.rotate_opt1(rotate_opt[1:0]), .rotate_opt2(rotate_opt[3:2]),
		.ctx_in_rotate(ctx_in_rotate), .ctx_mem2_en(ctx_mem2_en),
		.K_rnd_num(K_rnd_num), .K_rst(K_rst),
		.out({dout[15:0], dout[31:16]})
	);


	assign dout_seq_num = after_seq_num;
	assign dout_ctx_num = after_ctx;

endmodule


module md5ctx_type1(
	input CLK,
	input [31:0] din,
	input mem_wr_en, mem_rd_en,
	input [5:0] mem_wr_addr, mem_rd_addr,
	input mem2_wr_en, mem2_rd_en,
	input [3:0] mem2_wr_addr,
	input [4:0] mem2_rd_addr,

	input en, F_en, addB2en, A_rst, K_rst,
	input ctx_in_rotate, ctx_mem2_en,
	input [1:0] F_rnd_num,
	input [1:0] rotate_opt1, rotate_opt2,
	input [6:0] K_rnd_num,
	output [31:0] out
	);

	// Memory with input data blocks
	(* RAM_STYLE="block" *)
	reg [31:0] mem [0:63];
	always @(posedge CLK)
		if (mem_wr_en)
			mem [{1'b0, mem_wr_addr}] <= din;

	reg [31:0] mem_r;
	always @(posedge CLK)
		if (mem_rd_en)
			mem_r <= mem [mem_rd_addr];

	// Prevent inference of BRAM output regs
	wire [31:0] mem_out;
	ff32 ff_reg(
		.CLK(CLK), .en(en), .rst(1'b0),
		.i(mem_r), .o(mem_out)
	);


	// Memory with IVs and results
	(* RAM_STYLE="distributed" *)
	reg [31:0] mem2 [0:31];
	initial begin
		// Context is saved in order: A D C B
		mem2[16] = 32'h23016745; // A
		mem2[17] = 32'h54761032; // D
		mem2[18] = 32'hdcfe98ba; // C
		mem2[19] = 32'hab89efcd; // B
	end

	always @(posedge CLK)
		if (mem2_wr_en)
			mem2 [{1'b0, mem2_wr_addr}] <= out;

	reg mem2_rd_en_r = 0;
	reg [4:0] mem2_rd_addr_r;
	reg [31:0] mem2_out;
	always @(posedge CLK) begin
		mem2_rd_en_r <= mem2_rd_en;
		mem2_rd_addr_r <= mem2_rd_addr;
		if (mem2_rd_en_r)
			mem2_out <= mem2 [mem2_rd_addr_r];
	end
	

	wire [31:0] Kt;
	md5_Kt_bram Kt_inst(
		.CLK(CLK), .t(K_rnd_num), .en(en), .rst(K_rst),
		.Kt(Kt)
	);

	reg [31:0] ctx_in;
	always @(posedge CLK)
		if (en) // 1 LUT/bit
			ctx_in <= (ctx_mem2_en ? 0 : Kt)
				+ (~ctx_mem2_en ? mem_out :
					ctx_in_rotate ? {mem2_out[15:0], mem2_out[31:16]} :
					mem2_out);


	reg [31:0] B = 0, B2 = 0, C = 0;

	wire [31:0] A, D;
	shreg #(.DEPTH(2)) D_inst( .CLK(CLK), .en(en), .i(C), .o(D) );
	shreg_ff #(.DEPTH(2)) A_inst( .CLK(CLK), .en(en), .rst(A_rst),
		.i(D), .o(A) );

	wire [31:0] F = ~F_en ? 0 :
		F_rnd_num == 0 ? ((B & C) | (~B & D)) :
		F_rnd_num == 1 ? ((B & D) | (C & ~D)) :
		F_rnd_num == 2 ? (B ^ C ^ D) :
		(C ^ (B | ~D));

	wire [31:0] add1result;// = F + A + in;
	add3 add1_inst( .CLK(CLK), .en(en), .rst(1'b0),
		.a(A), .b(F), .c(ctx_in), .o(add1result) );

	//(* KEEP="true" *)
	wire [31:0] rotate1result =
		rotate_opt1 == 2'b00 ? {add1result[27:0], add1result[31:28]} :
		rotate_opt1 == 2'b01 ? {add1result[22:0], add1result[31:23]} :
		rotate_opt1 == 2'b10 ? {add1result[17:0], add1result[31:18]} :
		{add1result[11:0], add1result[31:12]};

	//(* KEEP="true" *)
	wire [31:0] rotate2result =
		rotate_opt2 == 2'b00 ? rotate1result :
		rotate_opt2 == 2'b01 ? {rotate1result[30:0], rotate1result[31]} :
		rotate_opt2 == 2'b10 ? {rotate1result[29:0], rotate1result[31:30]} :
		{rotate1result[28:0], rotate1result[31:29]};

	wire [31:0] add2result = (addB2en ? B2 : 0) + rotate2result;

	always @(posedge CLK)
		if (en) begin
			B <= add2result;
			B2 <= B;
			C <= B2;
		end

	assign out = {rotate1result[29:0], rotate1result[31:30]};

endmodule


// Counter for "even" cycles -> data addr
module cnte2addr_type1(
	input [6:0] cnte,
	output [3:0] rd_addr
	);

	localparam [72*4-1 :0] RD_ADDR = {
		4'd9, 4'd2, 4'd11, 4'd4, 4'd13, 4'd6, 4'd15, 4'd8,
		4'd1, 4'd10, 4'd3, 4'd12, 4'd5, 4'd14, 4'd7, 4'd0,
		4'd2, 4'd15, 4'd12, 4'd9, 4'd6, 4'd3, 4'd0, 4'd13,
		4'd10, 4'd7, 4'd4, 4'd1, 4'd14, 4'd11, 4'd8, 4'd5,
		4'd12, 4'd7, 4'd2, 4'd13, 4'd8, 4'd3, 4'd14, 4'd9,
		4'd4, 4'd15, 4'd10, 4'd5, 4'd0, 4'd11, 4'd6, 4'd1,
		4'd15, 4'd14, 4'd13, 4'd12, 4'd11, 4'd10, 4'd9, 4'd8,
		4'd7, 4'd6, 4'd5, 4'd4, 4'd3, 4'd2, 4'd1, 4'd0,
		4'd0, 4'd0, 4'd0, 4'd0
	};

	assign rd_addr = RD_ADDR [cnte*4 +:4];

endmodule


module cnto2rotate_opt_type1(
	input CLK,
	input [6:0] cnto,
	output reg [3:0] rotate_opt = 4'b1010 // s=16
	);

	localparam [73*8-1 :0] S = {
		8'd16, 8'd16, 8'd16, 8'd16, 8'd16,
		8'd7, 8'd12, 8'd17, 8'd22, 8'd7, 8'd12, 8'd17, 8'd22,
		8'd7, 8'd12, 8'd17, 8'd22, 8'd7, 8'd12, 8'd17, 8'd22,
		8'd5, 8'd9, 8'd14, 8'd20, 8'd5, 8'd9, 8'd14, 8'd20,
		8'd5, 8'd9, 8'd14, 8'd20, 8'd5, 8'd9, 8'd14, 8'd20,
		8'd4, 8'd11, 8'd16, 8'd23, 8'd4, 8'd11, 8'd16, 8'd23,
		8'd4, 8'd11, 8'd16, 8'd23, 8'd4, 8'd11, 8'd16, 8'd23,
		8'd6, 8'd10, 8'd15, 8'd21, 8'd6, 8'd10, 8'd15, 8'd21,
		8'd6, 8'd10, 8'd15, 8'd21, 8'd6, 8'd10, 8'd15, 8'd21,
		8'd16, 8'd16, 8'd16, 8'd16
	};

	integer k, s, opt1, opt2;

	(* RAM_STYLE="DISTRIBUTED" *)
	reg [3:0] rotate_opt_mem [0:72];
	initial
		for (k=0; k < 73; k=k+1) begin
			s = S [(7'd73 - k)*8-4 -:5];
			opt1 =
				s >= 4 & s <= 7 ? 2'b00 :
				s >= 9 & s <= 12 ? 2'b01 :
				s >= 14 & s <= 17 ? 2'b10 :
				2'b11;
			opt2 =
				s == 4 | s == 9 | s == 14 | s == 20 ? 2'b00 :
				s == 5 | s == 10 | s == 15 | s == 21 ? 2'b01 :
				s == 6 | s == 11 | s == 16 | s == 22 ? 2'b10 :
				2'b11;
			rotate_opt_mem[k] = {opt2[1:0], opt1[1:0]};
		end

	always @(posedge CLK)
		rotate_opt <= rotate_opt_mem [cnto];

endmodule


`else

module md5core_type1(
	input CLK,
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


`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../sha512.vh"

`ifdef SIMULATION
//
// - fully performs SHA-512 computation, incl. addition after each block
// - it's able for multiple blocks
// - 4 blocks are in the flight: two blocks are "interleaved" 
//   (one cycle is block0, other cycle is block1);
//   for each of above two blocks, 2nd block is loaded,
//   computation starts before the previous block is finished
//   and output.
// - each 2 blocks are performed in 2*(80+8) = 176 cycles, given
//   input buffer always has supply of data in time.
//
module sha512core #(
	parameter ID = -1
	)(
	input CLK,
	
	output reg ready0 = 1, ready1 = 1,
	
	input wr_en,
	input [63:0] in,
	input [3:0] wr_addr,
	input input_ctx,
	input [`BLK_OP_MSB:0] input_blk_op, // registered on set_input_ready
	input input_seq, // registered on set_input_ready
	input set_input_ready, // valid only when wr_en is asserted
	
	output [31:0] dout,
	output core_out_ready, core_out_start,
	output core_out_ctx_num, core_out_seq_num,
	input rd_en
	);

	reg ctx_num = 0;
	always @(posedge CLK)
		ctx_num <= ~ctx_num;


	// ***************************************************************
	//
	//   INPUT BUFFER
	//
	// allows to perform input independently from other operations.
	// If input data is ready, computaion for the next block
	// starts before it finishes the current block.
	//
	// ***************************************************************

	// Data block 1024-bit (2x)
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [63:0] input_buf [31:0];
	reg input_buf_rd_en = 0;
	reg [63:0] input_buf_r;
	reg [4:0] input_buf_addr;
	
	always @(posedge CLK) begin
		if (input_buf_rd_en)
			input_buf_r <= input_buf [input_buf_addr];
		if (wr_en)
			input_buf [ {input_ctx, wr_addr} ] <= `SWAP(in);
	end
	
	// 'ready[0|1]' asserts when it's ready for a new data block
	// (data from input buffer is used up, when 'next'
	// block becomes 'current' one)
	// Deasserts on the 1st word of input of new data block.
	wire set_ready0, set_ready1;

	always @(posedge CLK) begin
		if (wr_en & ~input_ctx)
			ready0 <= 0;
		else if (set_ready0)
			ready0 <= 1;
		if (wr_en & input_ctx)
			ready1 <= 0;
		else if (set_ready1)
			ready1 <= 1;
	end
	
	// 'ready_int' is used internally. Asserts on set_input_ready.
	// Enables the start of the 'next' context.
	// Deasserts after some processing.
	reg ready_int0 = 0, ready_int1 = 0;

	// Options for block computation (context selection etc.)
	reg [`BLK_OP_MSB:0] in_blk_op0, in_blk_op1;
	reg in_seq0, in_seq1;
	
	always @(posedge CLK) begin
		if (set_input_ready & wr_en & ~input_ctx) begin
			ready_int0 <= 1;
			in_blk_op0 <= input_blk_op;
			in_seq0 <= input_seq;
		end
		else if (set_ready0)
			ready_int0 <= 0;

		if (set_input_ready & wr_en & input_ctx) begin
			ready_int1 <= 1;
			in_blk_op1 <= input_blk_op;
			in_seq1 <= input_seq;
		end
		else if (set_ready1)
			ready_int1 <= 0;
	end

	
	// ***************************************************************
	//
	//   1024-bit BLOCK OPERATION.
	//
	// Also contains IVs, saved contexts.
	//
	// ***************************************************************

	// Controls
	reg external_input_en = 0, ctx_save_en = 0;
	reg [7:0] mem_wr_addr, rd_addr0, rd_addr1;
	(* EQUIVALENT_REGISTER_REMOVAL="no" *)
	reg mem_wr_en = 0, W16_R1_rst = 0, R0_rst = 0, Wt_rst = 0;

	wire [63:0] Wt, ctx2block, block2ctx;
	wire [63:0] mem0_out;

	sha512block sha512block(
		.CLK(CLK),
		.external_input_en(external_input_en), .ctx_save_en(ctx_save_en),
		.in(input_buf_r), .ctx_in(ctx2block),

		.mem_wr_en(mem_wr_en), .wr_addr(mem_wr_addr),
		.rd_addr0(rd_addr0), .rd_addr1(rd_addr1),

		.W16_R1_rst(W16_R1_rst), .Wt_rst(Wt_rst),
		.R0_rst(R0_rst),

		.block2ctx(block2ctx), .Wt(Wt)
	);


	// ***************************************************************
	//
	//   CONTEXT OPERATION
	//
	// 2 contexts run "interleaved", referred to as 'ctx 0' and 'ctx 1'
	// For each of 'ctx 0' and 'ctx 1', two contexts run one after another,
	// referred to as 'next' and 'current' ones.
	//
	// ***************************************************************

	reg [6:0] K_round_num = 0;
	reg Kt_rst = 0;
	wire [63:0] Kt;
	
	sha512_Kt_bram sha512_Kt(
		.CLK(CLK),
		.rst(Kt_rst),
		.t(K_round_num), .Kt(Kt),
		.wr_en(1'b0), .wr_addr(7'b0)
	);

	(* EQUIVALENT_REGISTER_REMOVAL="no" *)
	reg S1_CH_rst = 0, S0_rst = 0, MAJ_rst = 0,
		block2ctx_en = 0, T1_rst = 0, D2E_en = 0;
	
	sha512ctx sha512ctx(
		.CLK(CLK),
		.S1_CH_rst(S1_CH_rst), .S0_rst(S0_rst),
		.MAJ_rst(MAJ_rst), .D2E_en(D2E_en),
		.block2ctx_en(block2ctx_en), .T1_rst(T1_rst),
		.block2ctx(block2ctx), .Wt(Wt), .Kt(Kt), .o(ctx2block)
	);


	// *****************************************************************
	//
	//   CONTROL LOGIC
	//
	// *****************************************************************

	// Options for block computation, current context
	reg [`BLK_OP_MSB:0] blk_op0, blk_op1;
	reg seq0, seq1;


	// ==============================================================
	// 'next' context (the one being fetched from input buffer)
	localparam STATE_NEXT_WAIT = 0,
					STATE_NEXT_LOAD_CTX = 1,
					STATE_NEXT_CONTINUE_CTX = 2,
					STATE_NEXT_END = 3;

	(* FSM_EXTRACT="true", FSM_ENCODING="one-hot" *)
	reg [1:0] state_next0 = STATE_NEXT_WAIT, state_next1 = STATE_NEXT_WAIT;
	reg [3:0] next_cnt0 = 0, next_cnt1 = 0; // Counter for the next context

	// ==============================================================
	// 'current' context
	localparam STATE_CURR_NONE = 0,
					STATE_CURR_GOING = 1;

	reg state_curr0 = STATE_CURR_NONE, state_curr1 = STATE_CURR_NONE;
	reg [6:0] cur_cnt0 = 0, cur_cnt1 = 0; // Counter for the current context
	
	// Optimization attempts
	reg cur_cnt0_eq0 = 1, cur_cnt1_eq0 = 1;
	reg cur_cnt0_in1_16 = 0, cur_cnt1_in1_16 = 0;
	reg cur_cnt0_in4_76 = 0, cur_cnt1_in4_76 = 0;
	reg [6:0] cur_cnt0_minus1 = 0, cur_cnt1_minus1 = 0;
	always @(posedge CLK) if (~ctx_num)
			cur_cnt0_minus1 <= cur_cnt0;
		else
			cur_cnt1_minus1 <= cur_cnt1;


	// ==============================================================
	// When the 'next' context becomes the 'current' one, the
	// 'current' context is still finishing operation.
	// Introducing save_cnt to handle the issue.
	// When cur_cnt is 80 save_cnt is 1.
	reg [3:0] save_cnt0 = 0, save_cnt1 = 0;
	reg save_cnt0_in4_11 = 0, save_cnt1_in4_11 = 0;
	reg save_cnt0_in5_12 = 0, save_cnt1_in5_12 = 0;
	
	reg [`BLK_OP_MSB:0] save_blk_op0, save_blk_op1;
	reg save_seq0, save_seq1;

	always @(posedge CLK) if (~ctx_num) begin
		if (cur_cnt0 == 79) begin
			save_cnt0 <= 1;
			save_blk_op0 <= blk_op0;
			save_seq0 <= seq0;
		end
		else if (save_cnt0 == 12)
			save_cnt0 <= 0;
		else if (save_cnt0 != 0)
			save_cnt0 <= save_cnt0 + 1'b1;
			
		save_cnt0_in4_11 <= save_cnt0 >= 3 & save_cnt0 <= 10;
		save_cnt0_in5_12 <= save_cnt0 >= 4 & save_cnt0 <= 11;
	end
	
	always @(posedge CLK) if (ctx_num) begin
		if (cur_cnt1 == 79) begin
			save_cnt1 <= 1;
			save_blk_op1 <= blk_op1;
			save_seq1 <= seq1;
		end
		else if (save_cnt1 == 12)
			save_cnt1 <= 0;
		else if (save_cnt1 != 0)
			save_cnt1 <= save_cnt1 + 1'b1;

		save_cnt1_in4_11 <= save_cnt1 >= 3 & save_cnt1 <= 10;
		save_cnt1_in5_12 <= save_cnt1 >= 4 & save_cnt1 <= 11;
	end


	// ==============================================================
	//
	always @(posedge CLK) if (~ctx_num)
		case(state_next0)
		STATE_NEXT_WAIT: if (ready_int0) begin
			// BLK_OP_IF_CONTINUE_CTX means the result (sha512sum) remains
			// on the circle pipeline and if the next data block
			// is already in the input buffer, no cycles lost.
			// Else, it would lose 4 cycles on save and load, unless 
			// the next block is from the other computation (other seq_num).
			//
			//if (~`BLK_OP_IF_CONTINUE_CTX(in_blk_op0)
			//		&& (cur_cnt0_eq0 & save_cnt0 == 0 | save_cnt0 >= 8))//3) )
			//	state_next0 <= STATE_NEXT_LOAD_CTX;
			
			
			if (`BLK_OP_IF_CONTINUE_CTX(in_blk_op0) & save_cnt0 == 7)
				// the next block follows immediately
				state_next0 <= STATE_NEXT_CONTINUE_CTX;

			else if (`BLK_OP_IF_CONTINUE_CTX(in_blk_op0)
					| in_seq0 == seq0) begin
				if (save_cnt0 > 7 | cur_cnt0_eq0 & save_cnt0 == 0)
				// Same sequence number, take extra 5 cycles for save/load; or
				// The context data circles and is out of sync.
				state_next0 <= STATE_NEXT_LOAD_CTX;
			end
			
			else if (save_cnt0 >= 3 | cur_cnt0_eq0 & save_cnt0 == 0)
				state_next0 <= STATE_NEXT_LOAD_CTX;
		end
		
		STATE_NEXT_CONTINUE_CTX: begin
			state_next0 <= STATE_NEXT_END;
		end
		
		STATE_NEXT_LOAD_CTX: begin // loading 8 IVs via block2ctx; delay 1
			next_cnt0 <= next_cnt0 + 1'b1;
			if (next_cnt0 == 8) begin
			// last word of loaded ctx is in MAJ; 1st in G2;
			// W[0] in Wt; Kt[0] is on Kt;
			// last word of curr_ctx in save_r
				state_next0 <= STATE_NEXT_END;
			end
		end
		
		STATE_NEXT_END: begin
			blk_op0 <= in_blk_op0;
			seq0 <= in_seq0;
			next_cnt0 <= 0;
			if (set_ready0)
				state_next0 <= STATE_NEXT_WAIT;
		end
		endcase

	always @(posedge CLK) if (ctx_num)
		case(state_next1)
		STATE_NEXT_WAIT: if (ready_int1) begin
			//if (~`BLK_OP_IF_CONTINUE_CTX(in_blk_op1)
			//		&& (cur_cnt1_eq0 & save_cnt1 == 0 | save_cnt1 >= 8))//3) )
			//	state_next1 <= STATE_NEXT_LOAD_CTX;

			if (`BLK_OP_IF_CONTINUE_CTX(in_blk_op1) & save_cnt1 == 7)
				state_next1 <= STATE_NEXT_CONTINUE_CTX;

			else if (`BLK_OP_IF_CONTINUE_CTX(in_blk_op1)
					| in_seq1 == seq1) begin
				if (save_cnt1 > 7 | cur_cnt1_eq0 & save_cnt1 == 0)
					state_next1 <= STATE_NEXT_LOAD_CTX;
			end
			
			else if (save_cnt1 >= 3 | cur_cnt1_eq0 & save_cnt1 == 0)
				state_next1 <= STATE_NEXT_LOAD_CTX;
		end
		
		STATE_NEXT_CONTINUE_CTX:
			state_next1 <= STATE_NEXT_END;
		
		STATE_NEXT_LOAD_CTX: begin // loading 8 IVs via block2ctx; delay 1
			next_cnt1 <= next_cnt1 + 1'b1;
			if (next_cnt1 == 8) begin
				state_next1 <= STATE_NEXT_END;
			end
		end
		
		STATE_NEXT_END: begin
			blk_op1 <= in_blk_op1;
			seq1 <= in_seq1;
			next_cnt1 <= 0;
			if (set_ready1)
				state_next1 <= STATE_NEXT_WAIT;
		end
		endcase

	
	// ==============================================================
	//
	always @(posedge CLK) if (~ctx_num)
		case(state_curr0)
		STATE_CURR_NONE: if (state_next0 == STATE_NEXT_LOAD_CTX
				&& next_cnt0 == 5 // cur_cnt0 == 86
				|| state_next0 == STATE_NEXT_CONTINUE_CTX) begin
			state_curr0 <= STATE_CURR_GOING;
		end
		
		STATE_CURR_GOING: begin
			if (cur_cnt0 == 84) begin // min.84 (save_cnt0 == 5)
				cur_cnt0 <= 0;
				cur_cnt0_eq0 <= 1;
				cur_cnt0_in1_16 <= 0;
				state_curr0 <= STATE_CURR_NONE;
			end
			else begin
				cur_cnt0 <= cur_cnt0 + 1'b1;
				cur_cnt0_eq0 <= 0;
				cur_cnt0_in1_16 <= cur_cnt0 <= 15;
			end
			
			cur_cnt0_in4_76 <= cur_cnt0 >= 3 && cur_cnt0 <= 75;
		end
		endcase
	
	assign set_ready0 = cur_cnt0 == 17;
	
	
	always @(posedge CLK) if (ctx_num)
		case(state_curr1)
		STATE_CURR_NONE: if (state_next1 == STATE_NEXT_LOAD_CTX
				&& next_cnt1 == 5
				|| state_next1 == STATE_NEXT_CONTINUE_CTX) begin
			state_curr1 <= STATE_CURR_GOING;
		end
		
		STATE_CURR_GOING: begin
			if (cur_cnt1 == 84) begin
				cur_cnt1 <= 0;
				cur_cnt1_eq0 <= 1;
				cur_cnt1_in1_16 <= 0;
				state_curr1 <= STATE_CURR_NONE;
			end
			else begin
				cur_cnt1 <= cur_cnt1 + 1'b1;
				cur_cnt1_eq0 <= 0;
				cur_cnt1_in1_16 <= cur_cnt1 <= 15;
			end
			
			cur_cnt1_in4_76 <= cur_cnt1 >= 3 && cur_cnt1 <= 75;
		end
		endcase

	assign set_ready1 = cur_cnt1 == 17;


	// *****************************************************************
	//
	//   OUTPUT BUFFER
	//
	// - Result is collected in 64-bit wide memory.
	//
	// *****************************************************************
	reg output_wr_en = 0;
	reg [3:0] output_addr = 0;
	
	core_output_buf_bram core_output_buf(
		.CLK(CLK),
		.din( `SWAP(ctx2block) ),
		.wr_en(output_wr_en), .wr_addr(output_addr),
		.wr_seq(ctx_num ? save_seq0 : save_seq1),
		
		.dout(dout),
		.core_out_ready(core_out_ready), .core_out_start(core_out_start),
		.core_out_ctx_num(core_out_ctx_num),
		.core_out_seq_num(core_out_seq_num), .rd_en(rd_en)
	);


	// ==============================================================
	//
	wire [3:0] wr_addr_ctx0_0_72 = cur_cnt0 - 4;
	wire [3:0] rd_addr_ctx0_mem0 = cur_cnt0 - 7;
	wire [3:0] rd_addr_ctx0_mem1 = cur_cnt0 - 15;
	wire [3:0] input_buf_ctx0 = cur_cnt0_minus1;
	
	wire [2:0] rd_addr_ctx0_add = save_cnt0 - 1;
	wire [2:0] wr_addr_ctx0_add = save_cnt0 - 5;
	wire [2:0] output_buf_addr_ctx0 = save_cnt0 - 4;

	wire [3:0] wr_addr_ctx1_0_72 = cur_cnt1 - 4;
	wire [3:0] rd_addr_ctx1_mem0 = cur_cnt1 - 7;
	wire [3:0] rd_addr_ctx1_mem1 = cur_cnt1 - 15;
	wire [3:0] input_buf_ctx1 = cur_cnt1_minus1;
	
	wire [2:0] rd_addr_ctx1_add = save_cnt1 - 1;
	wire [2:0] wr_addr_ctx1_add = save_cnt1 - 5;
	wire [2:0] output_buf_addr_ctx1 = save_cnt1 - 4;
	

	always @(posedge CLK) begin
		rd_addr0 <= ~ctx_num ? (
			// Read W[t-7] from mem0 for rounds 16..79
			save_cnt0 == 0 ? rd_addr_ctx0_mem0 :
			// Load data from mem0 for post-block additions
			`BLK_OP_IF_NEW_CTX(save_blk_op0) ? { 5'b00011, rd_addr_ctx0_add }
				: { 1'b0, save_seq0, 1'b1,
				`BLK_OP_LOAD_CTX_NUM(save_blk_op0), rd_addr_ctx0_add }
			) : (
			save_cnt1 == 0 ? { 4'b1000, rd_addr_ctx1_mem0 } :
			`BLK_OP_IF_NEW_CTX(save_blk_op1) ? { 5'b00011, rd_addr_ctx1_add }
				: { 1'b1, save_seq1, 1'b1,
				`BLK_OP_LOAD_CTX_NUM(save_blk_op1), rd_addr_ctx1_add }
			);

		rd_addr1 <= ~ctx_num ? (
			// Read W[t-15] from mem1 for rounds 16..79
			state_next0 != STATE_NEXT_LOAD_CTX ? rd_addr_ctx0_mem1 :
			// Loading context from mem1 via block2ctx
			`BLK_OP_IF_NEW_CTX(in_blk_op0) ? { 5'b00011, next_cnt0[2:0] }
				: { 1'b0, in_seq0, 1'b1,
				`BLK_OP_LOAD_CTX_NUM(in_blk_op0), next_cnt0[2:0] }
			) : (
			state_next1 != STATE_NEXT_LOAD_CTX ? { 4'b1000, rd_addr_ctx1_mem1 } :
			`BLK_OP_IF_NEW_CTX(in_blk_op1) ? { 5'b00011, next_cnt1[2:0] }
				: { 1'b1, in_seq1, 1'b1,
				`BLK_OP_LOAD_CTX_NUM(in_blk_op1), next_cnt1[2:0] }
			);

		block2ctx_en <= ~ctx_num
			? state_next0 == STATE_NEXT_LOAD_CTX & next_cnt0 != 0
			: state_next1 == STATE_NEXT_LOAD_CTX & next_cnt1 != 0;

		S0_rst <= ~ctx_num ? (
			state_next0 == STATE_NEXT_LOAD_CTX & next_cnt0 != 0
				| save_cnt0_in4_11 | cur_cnt0_eq0
			) : (
			state_next1 == STATE_NEXT_LOAD_CTX & next_cnt1 != 0
				| save_cnt1_in4_11 | cur_cnt1_eq0
			);

		MAJ_rst <= ~ctx_num
			? ~(state_next0 == STATE_NEXT_LOAD_CTX & next_cnt0 != 0)
				& (save_cnt0_in4_11 | cur_cnt0_eq0)
			: ~(state_next1 == STATE_NEXT_LOAD_CTX & next_cnt1 != 0)
				& (save_cnt1_in4_11 | cur_cnt1_eq0);

		T1_rst <= ~ctx_num
			? state_next0 == STATE_NEXT_LOAD_CTX & next_cnt0 != 0
			: state_next1 == STATE_NEXT_LOAD_CTX & next_cnt1 != 0;

		input_buf_addr <= ctx_num
			? { 1'b0, input_buf_ctx0 } : { 1'b1, input_buf_ctx1 };

		input_buf_rd_en <= ctx_num ? cur_cnt0_in1_16 : cur_cnt1_in1_16;

		external_input_en <= ~ctx_num ? cur_cnt0_in1_16 : cur_cnt1_in1_16;
			
		W16_R1_rst <= ~ctx_num
			? cur_cnt0_in1_16 | save_cnt0 >= 2 & save_cnt0 <= 9
			: cur_cnt1_in1_16 | save_cnt1 >= 2 & save_cnt1 <= 9;

		R0_rst <= ctx_num
			? cur_cnt0_in1_16 | save_cnt0 >= 2 & save_cnt0 <= 9
			: cur_cnt1_in1_16 | save_cnt1 >= 2 & save_cnt1 <= 9;

		Kt_rst <= ~ctx_num
			? cur_cnt0_eq0 | save_cnt0 >= 3 & save_cnt0 <= 10
			: cur_cnt1_eq0 | save_cnt1 >= 3 & save_cnt1 <= 10;

		K_round_num <= ~ctx_num ? cur_cnt0_minus1 : cur_cnt1_minus1;

		mem_wr_addr <= ctx_num ? (
			cur_cnt0_in4_76 ? wr_addr_ctx0_0_72 :
			// Saving context into slot 0..N
			{ 1'b0, save_seq0, 1'b1, `BLK_OP_SAVE_CTX_NUM(save_blk_op0),
				wr_addr_ctx0_add }
			) : (
			cur_cnt1_in4_76 ? { 4'b1000, wr_addr_ctx1_0_72 } :
			{ 1'b1, save_seq1, 1'b1, `BLK_OP_SAVE_CTX_NUM(save_blk_op1),
				wr_addr_ctx1_add }
			);

		mem_wr_en <= ctx_num
			? cur_cnt0_in4_76 | save_cnt0_in5_12
			: cur_cnt1_in4_76 | save_cnt1_in5_12;

		ctx_save_en <= ~ctx_num
			? save_cnt0_in4_11
			: save_cnt1_in4_11;
		
		output_wr_en <= ~ctx_num
			? `BLK_OP_END_COMP_OUTPUT(save_blk_op0) & save_cnt0_in4_11
			: `BLK_OP_END_COMP_OUTPUT(save_blk_op1) & save_cnt1_in4_11;

		output_addr <= ~ctx_num
			? { 1'b0, output_buf_addr_ctx0 }
			: { 1'b1, output_buf_addr_ctx1 };
			
		S1_CH_rst <= ctx_num
			? cur_cnt0_eq0 | save_cnt0_in4_11
			: cur_cnt1_eq0 | save_cnt1_in4_11;
		
		D2E_en <= ctx_num
			? cur_cnt0_eq0 | save_cnt0_in5_12
			: cur_cnt1_eq0 | save_cnt1_in5_12;

		Wt_rst <= ~ctx_num
			? (save_cnt0 == 0 | save_cnt0 >= 11) & cur_cnt0_eq0
			: (save_cnt1 == 0 | save_cnt1 >= 11) & cur_cnt1_eq0;
	end
		
endmodule


`else

module sha512core #(
	parameter ID = -1
	)(
	input CLK,
	
	output reg ready0 = 1, ready1 = 1,
	
	input wr_en,
	input [63:0] in,
	input [3:0] wr_addr,
	input input_ctx,
	input [`BLK_OP_MSB:0] input_blk_op, // registered on set_input_ready
	input input_seq, // registered on set_input_ready
	input set_input_ready, // valid only when wr_en is asserted
	
	output [31:0] dout,
	output core_out_ready, core_out_start,
	output core_out_ctx_num, core_out_seq_num,
	input rd_en
	);

endmodule

`endif


module sha512core_dummy(
	input CLK,
	
	output reg ready0 = 0, ready1 = 0,
	
	input wr_en,
	input [63:0] in,
	input [3:0] wr_addr,
	input input_ctx,
	input [`BLK_OP_MSB:0] input_blk_op, // registered on set_input_ready
	input input_seq, // registered on set_input_ready
	input set_input_ready, // valid only when wr_en is asserted
	
	output [31:0] dout,
	output core_out_ready, core_out_start,
	output core_out_ctx_num, core_out_seq_num,
	input rd_en
	);

	(* KEEP="true" *) assign dout = 0;
	(* KEEP="true" *) assign core_out_ready = 0;
	(* KEEP="true" *) assign core_out_start = 0;
	(* KEEP="true" *) assign core_out_ctx_num = 0;
	(* KEEP="true" *) assign core_out_seq_num = 0;//rd_en ^ wr_en ^ ^in ^ wr_addr
		//^ input_ctx ^ ^input_blk_op ^ input_seq ^ set_input_ready;

endmodule


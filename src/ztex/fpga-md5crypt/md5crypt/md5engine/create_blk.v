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

//
// Task: given procb records and other data,
// create datasets for memory read and further processing.
//
// That was divided into 2 parts:
// - Part I (process_bytes) form datasets for memory reads
// without respect to blocks;
// - Part II (this one) operates with respect to blocks,
// cuts datasets and saves state after the end of a block.
// It's also responsible for padding and addition of total.
//
module create_blk #(
	parameter N_THREADS = -1,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,

	input wr_en,
	input [2:0] in_len,
	input [`MEM_ADDR_MSB+2 :0] in_addr,
	input [`PROCB_CNT_MSB :0] in_bytes_left_prev,
	input in_fin, in_padded0x80,
	input [`PROCB_TOTAL_MSB :0] in_total,
	input [N_THREADS_MSB :0] in_thread_num,
	input [`BLK_OP_MSB:0] in_blk_op,
	input blk_start, new_comp,
	// the last portion of bytes in the current procb record.
	// At the same time 'in_len' can be 0.
	input bytes_end,

	output reg full = 0, // busy with padding
	output reg blk_end = 0, // asserts for 1 cycle at the end of the block

	output reg save_wr_en = 1, // initialize procb_saved_state on startup
	output reg [N_THREADS_MSB :0] save_thread_num = 0,
	output [`PROCB_SAVE_WIDTH-1 :0] save_data,

	output reg mem_rd_en = 0,
	output reg [N_THREADS_MSB :0] thread_num,
	output reg [`MEM_ADDR_MSB :0] mem_rd_addr,
	output reg [2:0] len = 4,
	output reg [1:0] off = 0,
	output reg add0x80pad = 0, add0pad = 0, add_total = 0,
	output reg [`PROCB_TOTAL_MSB :0] total = 0,
	output reg [`BLK_OP_MSB:0] blk_op = 0,

	output reg err = 0
	);

	//
	// State for save
	//
	reg [`MEM_ADDR_MSB+2 :0] save_addr = 0;
	reg [`PROCB_CNT_MSB :0] save_bytes_left = 0;
	reg save_fin = 0, save_padded0x80 = 0;
	reg comp_active = 0, procb_active = 0;

	assign save_data = { save_addr, save_bytes_left, total,
		save_fin, save_padded0x80, comp_active, procb_active };


	//
	// Current block state
	//
	reg [6:0] blk_left = 64, blk_left2 = 60;


	localparam STATE_INIT = 0,
				STATE_PROCB = 2,
				STATE_PAD_0x80 = 3,
				STATE_PAD0 = 4,
				STATE_TOTAL1 = 5,
				STATE_TOTAL2 = 6;

	(* FSM_EXTRACT="true" *)//, FSM_ENCODING="one-hot" *)
	reg [2:0] state = STATE_INIT;

	wire wr_en_effective = wr_en & ~full & ~blk_end;

	wire [2:0] len_effective = in_len >= blk_left ? blk_left : in_len;

	always @(posedge CLK) begin
		if (blk_end)
			blk_end <= 0;

		save_wr_en <= save_eqn;

		if (blk_start) begin
			save_padded0x80 <= 1'b0;
			thread_num <= in_thread_num;
			blk_op <= in_blk_op;
		end

		case(state)
		STATE_INIT: begin
			save_thread_num <= save_thread_num == N_THREADS-1
				? {N_THREADS_MSB+1{1'b0}} : save_thread_num + 1'b1;
			if (save_thread_num == N_THREADS-1) begin
				//save_wr_en <= 0;
				state <= STATE_PROCB;
			end
		end

		STATE_PROCB: begin

			if (wr_en_effective) begin
				mem_rd_addr <= in_addr[`MEM_ADDR_MSB+2 :2];
				off <= in_addr[1:0];
				len <= len_effective;
			end
			mem_rd_en <= wr_en_effective & in_len > 0 & blk_left > 0;

			if (blk_start)
				save_thread_num <= in_thread_num;

			if (blk_start & ~new_comp & in_len == 0) begin
				if (in_padded0x80)
					add0x80pad <= 0;
				else
					add0x80pad <= 1;

				add0pad <= 1;
				off <= 0;
				len <= 4;
				blk_left2 <= 60;
				full <= 1;
				state <= STATE_PAD0;
			end

			// block ends
			else if (wr_en_effective & in_len >= blk_left) begin
				//save_wr_en <= 1;
				blk_end <= 1;
				blk_left <= 64;
				blk_left2 <= blk_left - in_len;
				add0x80pad <= 0;
				add0pad <= 0;

				// bytes end exactly at the end of the block
				if (bytes_end & in_len == blk_left) begin
					if (in_fin) begin
						comp_active <= 1; procb_active <= 1;
					end
					else begin // computation continues at the next block
						comp_active <= 1; procb_active <= 0;
					end
				end

				// more bytes remain for processing (for the next block)
				else begin
					comp_active <= 1; procb_active <= 1;
				end
			end

			// block doesn't end
			else if (wr_en_effective) begin

				blk_left <= blk_left - in_len;
				blk_left2 <= blk_left - in_len;
				add0x80pad <= 0;
				add0pad <= 0;

				if (bytes_end & in_fin) begin
					full <= 1;
					state <= STATE_PAD_0x80;
				end
			end

			else begin
				add0x80pad <= 0;
				add0pad <= 0;
			end

			add_total <= 0;
		end

		// pad with 0x80 and optionally 0's; align to 8 bytes
		STATE_PAD_0x80: begin
			mem_rd_en <= 0;
			add0x80pad <= 1;
			add0pad <= 1;
			save_padded0x80 <= 1;
			off <= 0;

			//save_bytes_left <= 0;

			if (blk_left2[1:0] != 0) begin
				len <= blk_left2[1:0];
				blk_left2 <= { blk_left2[6:2], 2'b00 };
			end
			else begin // at 8-byte boundary
				len <= 4;
				blk_left2 <= blk_left2 - 3'd4;
			end

			comp_active <= 1;
			procb_active <= 1;
			if (blk_left2 <= 4) begin // block is finished
				//save_wr_en <= 1;
				full <= 0;
				blk_end <= 1;
				blk_left <= 64;
				state <= STATE_PROCB;
			end
			else if (blk_left2 >= 9 & blk_left2 <= 12)
				state <= STATE_TOTAL1;
			else
				state <= STATE_PAD0;
		end

		STATE_PAD0: begin
			add0x80pad <= 0;
			add0pad <= 1;
			len <= 4;

			//save_bytes_left <= 0;

			blk_left2 <= blk_left2 - 3'd4;

			comp_active <= 1;
			procb_active <= 1;
			if (blk_left2 <= 4) begin
				// block is finished (padded with 0x80 and 0-15 zero bytes)
				//save_wr_en <= 1;
				full <= 0;
				blk_end <= 1;
				blk_left <= 64;
				state <= STATE_PROCB;
			end
			else if (blk_left2 >= 9 & blk_left2 <= 12)
				state <= STATE_TOTAL1;
		end

		STATE_TOTAL1: begin
			add0x80pad <= 0;
			add0pad <= 0;
			add_total <= 1;
			len <= 4;
			state <= STATE_TOTAL2;
		end

		STATE_TOTAL2: begin
			add0x80pad <= 0;
			add0pad <= 1;
			add_total <= 0;

			`BLK_OP_END_COMP_OUTPUT(blk_op) <= 1;
			comp_active <= 0; // Computation is finished

			procb_active <= 0;
			//save_wr_en <= 1; // Block is finished
			full <= 0;
			blk_end <= 1;
			blk_left <= 64;
			state <= STATE_PROCB;
		end
		endcase
	end

	always @(posedge CLK)
		if (wr_en_effective)
			total <= (
				(blk_start & new_comp) ? {`PROCB_TOTAL_MSB+1{1'b0}} :
				blk_start ? in_total :
				total
			) + len_effective;

	assign save_eqn = (1'b0
		| state == STATE_INIT
		| state == STATE_PROCB & wr_en_effective & in_len >= blk_left
		| state == STATE_PAD_0x80 & blk_left2 <= 4
		| state == STATE_PAD0 & blk_left2 <= 4
		| state == STATE_TOTAL2
	);

	always @(posedge CLK) if (save_eqn) begin
		save_addr <= in_addr + blk_left[2:0];
		save_bytes_left <= (state == STATE_PAD_0x80
				| state == STATE_PAD0 | state == STATE_TOTAL2)
			? {`PROCB_CNT_MSB+1{1'b0}} : in_bytes_left_prev - blk_left[2:0];
		save_fin <= in_fin;
		//save_thread_num <= in_thread_num;
	end


endmodule

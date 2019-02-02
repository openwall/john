`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../sha512.vh"

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
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,

	input wr_en,
	input [3:0] in_len,
	input [`MEM_ADDR_MSB+3 :0] in_addr,
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
	output [N_THREADS_MSB :0] save_thread_num,
	output [`PROCB_SAVE_WIDTH-1 :0] save_data,

	output reg mem_rd_en = 0,
	output reg [N_THREADS_MSB :0] thread_num = 0,
	output reg [`MEM_ADDR_MSB :0] mem_rd_addr,
	output reg [3:0] len = 4,
	output reg [2:0] off = 0,
	output reg add0x80pad = 0, add0pad = 0, add_total = 0,
	output reg [`PROCB_TOTAL_MSB :0] total = 0,
	output reg [`BLK_OP_MSB:0] blk_op = 0,

	output reg err = 0
	);

	localparam BLK_SIZE = 128;

	//
	// State for save
	//
	reg [`MEM_ADDR_MSB+3 :0] save_addr = 0;
	reg [`PROCB_CNT_MSB :0] save_bytes_left = 0;
	reg save_fin = 0, save_padded0x80 = 0;
	reg comp_active = 0, procb_active = 0;

	wire [3:0] save_align_limit = 4'd8 - save_addr[2:0];
	wire align_limit_effective = save_align_limit < save_bytes_left;
	wire [3:0] save_bytes_limit = align_limit_effective
		? save_align_limit
		: save_bytes_left < 8 ? save_bytes_left[2:0] : 4'd8;

	assign save_data = { save_bytes_limit, save_addr, save_bytes_left,
		total, save_fin, save_padded0x80, comp_active, procb_active };

	assign save_thread_num = thread_num;

	//
	// Current block state
	//
	reg [`MSB(BLK_SIZE):0] blk_left = BLK_SIZE, blk_left2 = BLK_SIZE - 8;


	localparam STATE_INIT = 0,
				STATE_PROCB = 2,
				STATE_PAD_0x80 = 3,
				STATE_PAD0 = 4,
				STATE_TOTAL1 = 5,
				STATE_TOTAL2 = 6;

	(* FSM_EXTRACT="true", FSM_ENCODING="one-hot" *)
	reg [2:0] state = STATE_INIT;

	//(* KEEP="true" *)
	wire wr_en_effective = wr_en & ~full & ~blk_end;

	wire [3:0] len_effective = in_len >= blk_left ? blk_left : in_len;

	always @(posedge CLK) begin
		if (blk_end)
			blk_end <= 0;

		if (save_wr_en & state != STATE_INIT)
			save_wr_en <= 0;

		if (blk_start) begin
			save_padded0x80 <= 1'b0;
			blk_op <= in_blk_op;
		end

		case(state)
		STATE_INIT: begin
			thread_num <= thread_num == N_THREADS-1
				? {N_THREADS_MSB+1{1'b0}} : thread_num + 1'b1;
			if (thread_num == N_THREADS-1)
				state <= STATE_PROCB;
		end

		STATE_PROCB: begin

			if (wr_en_effective) begin
				mem_rd_addr <= in_addr[`MEM_ADDR_MSB+3 :3];
				off <= in_addr[2:0];
				len <= len_effective;
			end
			mem_rd_en <= wr_en_effective & in_len > 0 & blk_left > 0;

			if (blk_start)
				thread_num <= in_thread_num;

			if (blk_start & ~new_comp & in_len == 0) begin
				if (in_padded0x80)
					add0x80pad <= 0;
				else
					add0x80pad <= 1;

				add0pad <= 1;
				off <= 0;
				len <= 8;
				blk_left2 <= BLK_SIZE - 8;
				full <= 1;
				state <= STATE_PAD0;
			end

			// block ends
			else if (wr_en_effective & in_len >= blk_left) begin
				save_wr_en <= 1;
				save_addr <= in_addr + blk_left[3:0];
				//save_bytes_left <= in_bytes_left_prev - blk_left[3:0];
				save_fin <= in_fin;

				blk_end <= 1;
				blk_left <= BLK_SIZE;
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
			save_fin <= in_fin;

			if (blk_left2[2:0] != 0) begin
				len <= blk_left2[2:0];
				blk_left2 <= { blk_left2[7:3], 3'b000 };
			end
			else begin
				len <= 8;
				blk_left2 <= blk_left2 - 4'd8;
			end

			comp_active <= 1;
			procb_active <= 1;
			if (blk_left2 <= 8) begin // block is finished
				save_wr_en <= 1;
				full <= 0;
				blk_end <= 1;
				blk_left <= BLK_SIZE;
				state <= STATE_PROCB;
			end
			else if (blk_left2 >= 17 & blk_left2 <= 24)
				state <= STATE_TOTAL1;
			else
				state <= STATE_PAD0;
		end

		STATE_PAD0: begin
			add0x80pad <= 0;
			add0pad <= 1;
			len <= 8;

			//save_bytes_left <= 0;
			save_fin <= in_fin;

			blk_left2 <= blk_left2 - 4'd8;

			comp_active <= 1;
			procb_active <= 1;
			if (blk_left2 <= 8) begin
				// block is finished (padded with 0x80 and 0-15 zero bytes)
				save_wr_en <= 1;
				full <= 0;
				blk_end <= 1;
				blk_left <= BLK_SIZE;
				state <= STATE_PROCB;
			end
			else if (blk_left2 >= 17 & blk_left2 <= 24)
				state <= STATE_TOTAL1;
		end

		STATE_TOTAL1: begin
			add0x80pad <= 0;
			add0pad <= 1;
			len <= 8;
			state <= STATE_TOTAL2;
		end

		STATE_TOTAL2: begin
			add0x80pad <= 0;
			add0pad <= 0;
			add_total <= 1;

			`BLK_OP_END_COMP_OUTPUT(blk_op) <= 1;
			comp_active <= 0; // Computation is finished
			procb_active <= 0;

			save_wr_en <= 1; // Block is finished
			//save_bytes_left <= 0;

			full <= 0;
			blk_end <= 1;
			blk_left <= BLK_SIZE;
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

	always @(posedge CLK)
		if (state == STATE_PAD_0x80 | state == STATE_PAD0
				| state == STATE_TOTAL2)
			save_bytes_left <= 0;
		else if (wr_en_effective & in_len >= blk_left
				& state == STATE_PROCB)
			save_bytes_left <= in_bytes_left_prev - blk_left[3:0];

endmodule

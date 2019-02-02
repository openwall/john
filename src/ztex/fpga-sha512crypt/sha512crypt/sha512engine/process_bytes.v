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

`ifdef SIMULATION
//
// The task is:
//
// - perform "process_bytes" ("procb") actions for each thread;
// - form blocks, send to cores;
// - after 1 block is sent, it switches to the next core/context,
// keeps internal state.
//
module process_bytes #(
	parameter N_CORES = `N_CORES,
	parameter N_CORES_MSB = `MSB(N_CORES-1),
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,

	// thread_state (ts)
	output [N_THREADS_MSB :0] ts_wr_num, ts_rd_num, // Thread #
	output reg ts_wr_en = 1,
	output reg [`THREAD_STATE_MSB :0] ts_wr = `THREAD_STATE_NONE,
	input [`THREAD_STATE_MSB :0] ts_rd,

	// *** Computation data set #1 ***
	input [N_THREADS_MSB :0] comp_data1_thread_num,
	input comp_data1_wr_en,
	input [`COMP_DATA1_MSB :0] comp_wr_data1,

	// *** process_bytes records ***
	output [N_THREADS_MSB :0] procb_rd_thread_num,
	output procb_rd_en, procb_rd_rst, procb_lookup_en,
	//input procb_aempty, procb_lookup_aempty,
	input procb_lookup_empty,
	input [`PROCB_D_WIDTH-1 :0] procb_dout,

	// *** Input to cores ***
	// Memory connection.
	output [`MEM_TOTAL_MSB :0] mem_rd_addr,
	output mem_rd_en,
	// Realign connection
	output [3:0] len,
	output [2:0] off,
	output add0x80pad, add0pad, add_total,
	output [`PROCB_TOTAL_MSB :0] total,
	// "core_input"
	output [N_THREADS_MSB :0] core_thread_num,
	output [`BLK_OP_MSB:0] blk_op,

	// Ready flags from cores
	input [4*N_CORES-1 :0] ready,

	output err
	);

	genvar i;
	integer k;


	reg [N_THREADS_MSB :0] thread_num = 0;
	wire [N_THREADS_MSB :0] thread_num_next;
	next_thread_num #( .N_CORES(N_CORES), .N_THREADS(N_THREADS)
	) next_thread_num( .in(thread_num), .out(thread_num_next) );

	always @(posedge CLK)
		if (set_next_thread_num)
			thread_num <= thread_num_next;

	assign procb_rd_thread_num = thread_num;

	// Thread Status
	assign ts_rd_num = thread_num;
	assign ts_wr_num = thread_num;


	// =================================================================
	// *** ready flags from cores ***
	//
	reg core_ready_r = 0; // Next core/context/sequence is ready for input
	always @(posedge CLK)
		core_ready_r <= ready [thread_num];


	// =================================================================
	// *** Computation data (set #1) ***
	//
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [`COMP_DATA1_MSB :0] comp_data1 [0: N_THREADS-1];
	always @(posedge CLK)
		if (comp_data1_wr_en)
			comp_data1 [comp_data1_thread_num] <= comp_wr_data1;

	assign { comp_if_new_ctx } = comp_data1 [thread_num];


	// =================================================================
	// *** Current computation data ***
	//
	// - It forms data for memory read, realign and core_input
	// almost every cycle; keeps previous dataset for the case
	// if the current dataset doesn't go on.
	//
	reg [`BLK_OP_MSB:0] cur_blk_op = 0;

	// *** Current process_bytes (procb) data ***
	//
	// Data for the current process_bytes. We include padding and
	// total length in process_bytes (if flag finish_ctx is set).
	// These are saved in saved_procb_state when block is finished
	// and current thread changes.
	//
	reg [`MEM_ADDR_MSB+3 :0] cur_addr;
	reg [3:0] cur_len = 8;
	reg [`PROCB_CNT_MSB :0] cur_bytes_left, prev_bytes_left;
	reg finish_ctx = 0;
	reg bytes_end = 0; // End portion of bytes for the current procb record
	// Start of a new block - asserts on the 1st write
	reg blk_start = 0;


	// =================================================================
	// *** saved process_bytes (procb) data ***
	//
	// When a block is done, unfinished procb record is saved here.
	// It still counts if bytes are over and padding/total remain.
	//
	wire [`PROCB_SAVE_WIDTH-1 :0] save_data;
	wire [N_THREADS_MSB:0] save_thread_num;

	wire [3:0] saved_bytes_limit;
	wire [`MEM_ADDR_MSB+3 :0] saved_addr;
	wire [`PROCB_CNT_MSB :0] saved_bytes_left;
	wire [`PROCB_TOTAL_MSB :0] saved_total;
	wire saved_finish_ctx, saved_padded0x80, saved_comp_active, saved_procb_active;
	//
	// Some outputs from procb_saved_state are not
	// required on the next cycle (KEEP,TIG)
	//
	(* KEEP="true" *) wire [3:0] saved_bytes_limit_t = saved_bytes_limit;
	(* KEEP="true" *) wire [`MEM_ADDR_MSB+3 :0] saved_addr_t = saved_addr;
	(* KEEP="true" *) wire [`PROCB_TOTAL_MSB :0] saved_total_t = saved_total;
	(* KEEP="true" *) wire saved_finish_ctx_t = saved_finish_ctx;
	(* KEEP="true" *) wire saved_padded0x80_t = saved_padded0x80;
	(* KEEP="true" *) wire saved_comp_active_t = saved_comp_active;
	(* KEEP="true" *) wire saved_procb_active_t = saved_procb_active;
	(* KEEP="true" *) wire [`PROCB_CNT_MSB :0] loaded_bytes_left_t
			= saved_bytes_left - saved_bytes_limit;

	procb_saved_state procb_saved_state(
		.CLK(CLK),
		.wr_thread_num(save_thread_num), .wr_en(save_wr_en),
		.din(save_data),
		.rd_thread_num(thread_num_next), .rd_en(set_next_thread_num),
		.dout({ saved_bytes_limit, saved_addr, saved_bytes_left, saved_total,
			saved_finish_ctx, saved_padded0x80,
			saved_comp_active, saved_procb_active })
	);


	// =================================================================
	// *** Create data blocks out of procb data ***
	//
	reg blk_wr_en = 0;

	create_blk create_blk(
		.CLK(CLK),
		.wr_en(blk_wr_en), .full(blk_full),
		.in_len(cur_len),
		.in_addr(cur_addr), .in_bytes_left_prev(prev_bytes_left),
		.in_fin(finish_ctx), .in_padded0x80(saved_padded0x80_t),
		.in_total(saved_total_t),
		.blk_start(blk_start), .new_comp(~saved_comp_active_t),
		.bytes_end(bytes_end),
		.in_thread_num(thread_num), .in_blk_op(cur_blk_op),
		// save state when block is done
		.blk_end(blk_end), .save_thread_num(save_thread_num),
		.save_data(save_data), .save_wr_en(save_wr_en),
		// output for memory read, realign, core_input
		.mem_rd_en(mem_rd_en), .mem_rd_addr(mem_rd_addr[`MEM_ADDR_MSB:0]),
		.len(len), .off(off), .total(total),
		.add0x80pad(add0x80pad), .add0pad(add0pad), .add_total(add_total),
		.thread_num(core_thread_num), .blk_op(blk_op),
		.err(err)
	);

	assign mem_rd_addr[`MEM_TOTAL_MSB:`MEM_ADDR_MSB+1] = core_thread_num;


	// =================================================================
	// Load data for the next internal state
	//
	// Data can be loaded from:
	// - from saved_procb_state (loaded_*)
	// - from procb_buf
	//
	// each process_bytes (procb) element consists of 4 items:
	// starting address; count of bytes; 2 flags.
	//
	reg load_from_saved = 0;

	wire [`MEM_ADDR_MSB :0] procb_addr;
	wire [`PROCB_CNT_MSB :0] procb_bytes_left;
	assign { procb_addr, procb_bytes_left, procb_finish_ctx } = procb_dout;


	task do_load_state;
		begin
			cur_addr <= load_from_saved
				? saved_addr_t
				: { procb_addr, 3'b000 };
			cur_bytes_left <= load_from_saved
				? loaded_bytes_left_t
				: procb_bytes_left < 8
					? {`PROCB_CNT_MSB+1{1'b0}} : procb_bytes_left - 4'd8;
			cur_len <= load_from_saved
				? saved_bytes_limit_t
				: procb_bytes_left < 8
					? procb_bytes_left[2:0] : 4'd8;

			bytes_end <= load_from_saved
				? loaded_bytes_left_t == 0
				: procb_bytes_left <= 8;

			// prev_bytes_left is meaningful only at the end of the block
			prev_bytes_left <= procb_bytes_left;

			finish_ctx <= load_from_saved
				? saved_finish_ctx_t
				: procb_finish_ctx;

			blk_wr_en <= 1;
		end
	endtask


	task do_update_state;
		begin
			cur_addr <= cur_addr + cur_len;
			cur_len <= cur_bytes_left <= 8 ? cur_bytes_left[3:0] : 4'd8;
			cur_bytes_left <= cur_bytes_left <= 8
				? {`PROCB_CNT_MSB+1{1'b0}} : cur_bytes_left - 4'd8;
			bytes_end <= cur_bytes_left <= 8;
			prev_bytes_left <= cur_bytes_left;

			blk_wr_en <= 1;
		end
	endtask


	// =================================================================
	localparam STATE_INIT = 0,
				STATE_INIT2 = 1,
				STATE_NEXT_THREAD1 = 2,
				STATE_NEXT_THREAD2 = 3,
				//STATE_NEXT_THREAD3 = 4,
				STATE_PROCESS_BYTES = 5,
				STATE_CHECK_BLK_END = 6,
				STATE_PROCB_WAIT = 7;

	(* FSM_EXTRACT="true", FSM_ENCODING="one-hot" *)
	reg [3:0] state = STATE_INIT;

	reg init_going = 1;
	reg [N_THREADS-1 :0] init_cnt = 0;

	reg [7:0] procb_empty_wait = 0;
	reg procb_loaded = 0;

`ifdef SIMULATION
	reg [23:0] X_THREAD_SWITCH_OK = 0;
	reg [23:0] X_THREAD_NOT_RDY = 0;
	reg [31:0] X_CYCLES = 0;
	reg [31:0] X_CYCLES_WAIT = 0;
`endif

	always @(posedge CLK) begin
`ifdef SIMULATION
		X_CYCLES <= X_CYCLES + 1'b1;
`endif
		init_cnt <= { init_cnt[N_THREADS-2 :0], init_going };

		if (ts_wr_en & ~init_going)
			ts_wr_en <= 0;

		if (blk_start)
			blk_start <= 0;

		procb_empty_wait[7:0]
			<= { procb_empty_wait[6:0], state == STATE_PROCB_WAIT };

		case(state)
		// Initialize: procb_buf, procb_saved_state, ts
		STATE_INIT: if (init_cnt[N_THREADS-1])
			state <= STATE_INIT2;

		STATE_INIT2: begin
			init_going <= 0;
			ts_wr_en <= 0;
			state <= STATE_NEXT_THREAD1;
		end

		STATE_NEXT_THREAD1: begin // updated thread_num
			load_from_saved <= saved_procb_active;
			state <= STATE_NEXT_THREAD2;
		end

/*
`ifdef SIMULATION
	X_CYCLES_WAIT <= X_CYCLES_WAIT + 1'b1;
`endif

`ifdef SIMULATION
	X_THREAD_SWITCH_OK <= X_THREAD_SWITCH_OK + 1'b1;
`endif

`ifdef SIMULATION
	X_THREAD_NOT_RDY <= X_THREAD_NOT_RDY + 1'b1;
`endif
*/

		STATE_NEXT_THREAD2: begin
			if (ts_rd == `THREAD_STATE_NONE)
				state <= STATE_NEXT_THREAD1;

			else if (~core_ready_r) begin // wait until core's ready
			end

			else if (~saved_procb_active_t
					& ts_rd != `THREAD_STATE_RD_RDY) begin // wait for core/CPU
			end

			else begin
				// load saved state or next procb record
				// if saved state is inactive - procb records can't be empty
				load_from_saved <= 0;
				do_load_state;
				procb_loaded <= ~saved_procb_active_t;
				blk_start <= 1;

				if (saved_comp_active_t)
					`BLK_OP_IF_NEW_CTX(cur_blk_op) <= 0;
				else // New computation
					`BLK_OP_IF_NEW_CTX(cur_blk_op) <= comp_if_new_ctx;

				state <= STATE_PROCESS_BYTES;
			end
		end

		STATE_PROCESS_BYTES: begin
			if (blk_end) begin // data from the previous cycle didn't go
				procb_loaded <= 0;
				blk_wr_en <= 0;
				state <= STATE_NEXT_THREAD1;
			end
			else if (blk_full) begin // create_blk is busy with padding
				procb_loaded <= 0;
				blk_wr_en <= 0;
			end
			else if (bytes_end) begin
				if (~finish_ctx) begin
					if (~procb_lookup_empty) begin
						do_load_state;
						procb_loaded <= 1;
					end
					else begin
						// It has to load procb record, procb records empty.
						procb_loaded <= 0;
						blk_wr_en <= 0;
						state <= STATE_CHECK_BLK_END;
						ts_wr_en <= 1;
						ts_wr <= `THREAD_STATE_WR_RDY;
					end
				end
				else begin // bytes_end, finish
					// blk_{end|full} must assert on the next cycle
					procb_loaded <= 0;
					blk_wr_en <= 0;
					ts_wr_en <= 1;
					ts_wr <= `THREAD_STATE_BUSY;
				end
			end
			else begin // bytes, block didn't end
				do_update_state;
				procb_loaded <= 0;
			end
		end

		STATE_CHECK_BLK_END: begin
			if (blk_end) begin
				// no fin here
				//if (finish_ctx)
				state <= STATE_NEXT_THREAD1;
			end
			else
				// data is stuck in realign - all threads suspend
				state <= STATE_PROCB_WAIT;
		end

		STATE_PROCB_WAIT: if (procb_empty_wait[7] & ~procb_lookup_empty
				& ts_rd == `THREAD_STATE_RD_RDY) begin
			state <= STATE_PROCESS_BYTES;
		end
		endcase
	end


	assign set_next_thread_num = (1'b0
		| state == STATE_INIT
		| state == STATE_NEXT_THREAD2 & ts_rd == `THREAD_STATE_NONE
		| blk_end
	);

	// Read-ahead procb records
	wire load_next_procb_record = (1'b0
		| state == STATE_PROCESS_BYTES & ~procb_lookup_empty
			& bytes_end & ~finish_ctx
		| state == STATE_NEXT_THREAD2 & core_ready_r
			& ~saved_procb_active_t
			& (ts_rd == `THREAD_STATE_RD_RDY)
	);

	assign procb_lookup_en =
		| load_next_procb_record
	;

	// Read procb record 1 cycle after lookup, if data went for processing
	assign procb_rd_en = (1'b0
		| state == STATE_INIT
		| procb_loaded & ~blk_end
	);

	assign procb_rd_rst = state == STATE_INIT;


endmodule

`else

module process_bytes #(
	parameter N_CORES = `N_CORES,
	parameter N_CORES_MSB = `MSB(N_CORES-1),
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,

	// thread_state (ts)
	output [N_THREADS_MSB :0] ts_wr_num, ts_rd_num, // Thread #
	output reg ts_wr_en = 1,
	output reg [`THREAD_STATE_MSB :0] ts_wr = `THREAD_STATE_NONE,
	input [`THREAD_STATE_MSB :0] ts_rd,

	// *** Computation data set #1 ***
	input [N_THREADS_MSB :0] comp_data1_thread_num,
	input comp_data1_wr_en,
	input [`COMP_DATA1_MSB :0] comp_wr_data1,

	// *** process_bytes records ***
	output [N_THREADS_MSB :0] procb_rd_thread_num,
	output procb_rd_en, procb_rd_rst, procb_lookup_en,
	//input procb_aempty, procb_lookup_aempty,
	input procb_lookup_empty,
	input [`PROCB_D_WIDTH-1 :0] procb_dout,

	// *** Input to cores ***
	// Memory connection.
	output [`MEM_TOTAL_MSB :0] mem_rd_addr,
	output mem_rd_en,
	// Realign connection
	output [3:0] len,
	output [2:0] off,
	output add0x80pad, add0pad, add_total,
	output [`PROCB_TOTAL_MSB :0] total,
	// "core_input"
	output [N_THREADS_MSB :0] core_thread_num,
	output [`BLK_OP_MSB:0] blk_op,

	// Ready flags from cores
	input [4*N_CORES-1 :0] ready,

	output err
	);

endmodule

`endif


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


module engine #(
	parameter MEM_WIDTH = `MEM_WIDTH,
	parameter N_CORES = `N_CORES,
	parameter N_CORES_MSB = `MSB(N_CORES-1),
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,

	// *** CPU Interface ***
	// procb_buf
	input [N_THREADS_MSB:0] procb_wr_thread_num,
	input procb_wr_en,
	input [`PROCB_D_WIDTH-1 :0] procb_wr_data,
	output [`PROCB_A_WIDTH-1 :0] procb_wr_cnt,
	input comp_data1_wr_en,
	input [`COMP_DATA1_MSB :0] comp_wr_data1,
	// thread_state
	input [N_THREADS_MSB :0] ts_wr_num1, ts_rd_num1, ts_wr_num4, ts_rd_num4,
	input [`THREAD_STATE_MSB :0] ts_wr1, ts_wr4,
	input ts_wr_en1, ts_wr_en4,
	output [`THREAD_STATE_MSB :0] ts_rd1, ts_rd4,
	// memory
	input comp_data2_wr_en,
	input [`COMP_DATA2_MSB :0] comp_wr_data2,
	input [MEM_WIDTH-1 :0] ext_din,
	input [`MEM_TOTAL_MSB :0] ext_wr_addr,
	input ext_wr_en,
	output ext_full,
	input mem_rd_cpu_request,
	input [`MSB(`MEM_CPU_RATIO-1) :0] rd_cpu_delay,
	input [`MEM_TOTAL_MSB :0] mem_rd_addr_cpu,
	output [MEM_WIDTH-1 :0] mem_dout,
	output mem_rd_cpu_valid,

	// *** Cores ***
	// (are kept separate because of Placement & Routing issues)
	output [N_CORES-1:0] core_wr_en,
	input [4*N_CORES-1:0] core_ready,
	output [MEM_WIDTH-1 :0] core_din,
	output [3:0] core_wr_addr,
	output [`BLK_OP_MSB:0] core_blk_op,
	output core_input_ctx, core_input_seq, core_set_input_ready,

	input [N_CORES-1:0] core_dout_en, core_dout_seq_num,
	input [N_CORES-1:0] core_dout_ctx_num,
	input [MEM_WIDTH*N_CORES-1 :0] core_dout,

	output [4:0] err
	);



	// **********************************************************
	//
	//   THREAD STATE (TS)
	//
	// Each thread is in some defined state. There're multiple
	// channels to read/modify state of threads.
	//
	// **********************************************************
	wire [N_THREADS_MSB :0] ts_wr_num2, ts_rd_num2, ts_num3;
	wire [`THREAD_STATE_MSB :0] ts_wr2, ts_wr3, ts_rd2, ts_rd3;

	thread_state thread_state(
		.CLK(CLK),
		.wr_num1(ts_wr_num1), .wr_en1(ts_wr_en1), // channel 1 - CPU
		.wr_state1(ts_wr1), .rd_num1(ts_rd_num1), .rd_state1(ts_rd1),
		.wr_num2(ts_wr_num2), .wr_en2(ts_wr_en2), // channel 2 - procb
		.wr_state2(ts_wr2), .rd_num2(ts_rd_num2), .rd_state2(ts_rd2),
		.wr_num3(ts_num3), .wr_en3(ts_wr_en3), // 3 - memory
		.wr_state3(ts_wr3), .rd_num3(ts_num3), .rd_state3(ts_rd3),
		.wr_num4(ts_wr_num4), .wr_en4(ts_wr_en4), // 4 - unit_input
		.wr_state4(ts_wr4), .rd_num4(ts_rd_num4), .rd_state4(ts_rd4),
		.err(err[0])
	);


	// **********************************************************
	//
	//   "MAIN" MEMORY
	//
	// **********************************************************
	wire [`MEM_TOTAL_MSB :0] mem_rd_addr_procb;

	memory memory(
		.CLK(CLK),
		// computation data set #2
		.comp_data2_thread_num(procb_wr_thread_num),
		.comp_data2_wr_en(comp_data2_wr_en), .comp_wr_data2(comp_wr_data2),
		// Write
		.core_din(core_dout), .core_dout_en(core_dout_en),
		.core_dout_seq_num(core_dout_seq_num),
		.core_dout_ctx_num(core_dout_ctx_num),
		.ext_din(ext_din), .ext_wr_addr(ext_wr_addr), .ext_wr_en(ext_wr_en),
		.ext_full(ext_full),
		// Thread State
		.ts_num(ts_num3), .ts_wr_en(ts_wr_en3), .ts_wr(ts_wr3),
		// Read
		.rd_en_procb(mem_rd_en_procb), .rd_cpu_request(mem_rd_cpu_request),
		.rd_addr_procb(mem_rd_addr_procb), .rd_addr_cpu(mem_rd_addr_cpu),
		.dout(mem_dout), .rd_cpu_valid(mem_rd_cpu_valid),
		.rd_cpu_delay(rd_cpu_delay),
		.err(err[1])
	);


	// **********************************************************
	//
	// realign & core_input
	//
	// **********************************************************
	wire [3:0] len;
	wire [2:0] off;
	wire [`PROCB_TOTAL_MSB :0] total;
	wire [N_THREADS_MSB :0] core_thread_num;
	wire [`BLK_OP_MSB:0] blk_op;

	reg [3:0] len_r = 4;
	reg [2:0] off_r = 0;
	reg add0x80pad_r = 0, add0pad_r = 0, add_total_r = 0;
	reg [`PROCB_TOTAL_MSB :0] total_r = 0;
	reg [N_THREADS_MSB :0] core_thread_num_r;
	reg [`BLK_OP_MSB:0] blk_op_r;

	always @(posedge CLK) begin
		len_r <= len; off_r <= off;
		add0x80pad_r <= add0x80pad; add0pad_r <= add0pad;
		add_total_r <= add_total; core_thread_num_r <= core_thread_num;
		blk_op_r <= blk_op;
		if (add_total)
			total_r <= total;
	end


	reg realign_wr_en = 0;
	always @(posedge CLK)
		realign_wr_en <= mem_rd_en_procb;

	realign8_pad realign8_pad(
		.CLK(CLK),
		.wr_en(realign_wr_en),
		.din(mem_dout),

		.len(len_r), .off(off_r),
		.add0x80pad(add0x80pad_r), .add0pad(add0pad_r),
		.add_total(add_total_r), .total_bytes(total_r),

		.valid_eqn(realign_valid_eqn), .valid(realign_valid),
		.wr_en_r(realign_wr_en_r),
		.err(err[2]), .out(core_din)
	);

	core_input core_input(
		.CLK(CLK),
		.realign_wr_en_r(realign_wr_en_r),
		.realign_valid_eqn(realign_valid_eqn), .realign_valid(realign_valid),

		.thread_num(core_thread_num_r), .blk_op(blk_op_r),

		.core_wr_en(core_wr_en), .core_wr_addr(core_wr_addr),
		.core_blk_op(core_blk_op),
		.core_input_seq(core_input_seq), .core_input_ctx(core_input_ctx),
		.set_input_ready(core_set_input_ready)
	);


	// **********************************************************
	//
	//   procb_buf
	//
	// A write into the buffer resembles the call to process_bytes()
	// software function.
	// So-called "procb records" are written.
	//
	// **********************************************************
	wire [N_THREADS_MSB :0] procb_rd_thread_num;
	wire [`PROCB_D_WIDTH-1 :0] procb_dout;

	procb_buf procb_buf(
		.CLK(CLK),
		.wr_thread_num(procb_wr_thread_num), .wr_en(procb_wr_en),
		.din(procb_wr_data), .wr_cnt(procb_wr_cnt),
		// read by process_bytes
		.rd_thread_num(procb_rd_thread_num),
		.rd_en(procb_rd_en), .rd_rst(procb_rd_rst),
		// read-ahead
		.lookup_en(procb_lookup_en), .lookup_empty(procb_lookup_empty),
		.aempty(procb_aempty), .dout(procb_dout),
		.err(err[3])
	);


	// **********************************************************
	//
	// process_bytes.
	// - operates controls for realign4, core_input.
	// That allows to create 16x32-bit data blocks out of
	// procb records and send them to cores. Padding & total are
	// added where required.
	//
	// **********************************************************
	process_bytes process_bytes(
		.CLK(CLK),
		// thread_state (ts) - using channel 2
		.ts_wr_num(ts_wr_num2), .ts_wr_en(ts_wr_en2),
		.ts_wr(ts_wr2), .ts_rd_num(ts_rd_num2), .ts_rd(ts_rd2),

		// comp_buf
		.comp_data1_thread_num(procb_wr_thread_num),
		.comp_data1_wr_en(comp_data1_wr_en), .comp_wr_data1(comp_wr_data1),

		// procb_buf
		.procb_rd_thread_num(procb_rd_thread_num),
		.procb_rd_en(procb_rd_en), .procb_rd_rst(procb_rd_rst),
		//.procb_aempty(procb_aempty),
		.procb_dout(procb_dout),
		.procb_lookup_en(procb_lookup_en),
		.procb_lookup_empty(procb_lookup_empty),

		// Memory read, supplementary data for realign4_pad, core_input
		.mem_rd_addr(mem_rd_addr_procb), .mem_rd_en(mem_rd_en_procb),
		.len(len), .off(off),
		.add0x80pad(add0x80pad), .add0pad(add0pad),
		.add_total(add_total), .total(total),
		.core_thread_num(core_thread_num), .blk_op(blk_op),

		// Connections from cores
		.ready(core_ready),
		.err(err[4])
	);



endmodule

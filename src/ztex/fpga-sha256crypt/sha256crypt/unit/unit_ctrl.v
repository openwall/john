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
//   Unit Controls
//
// Everything in the unit except for cores is placed here
// because of Placement & Routing issues.
//
module unit_ctrl #(
	parameter N_CORES = `N_CORES,
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,
	// Unit Input
	input [`UNIT_INPUT_WIDTH-1 :0] unit_in,
	input unit_in_ctrl, unit_in_wr_en,
	output unit_in_afull, unit_in_ready,
	// Unit Output
	output [`UNIT_OUTPUT_WIDTH-1 :0] dout,
	input rd_en,
	output empty,
	// *** Cores ***
	// (are kept separate because of Placement & Routing issues)
	output [N_CORES-1:0] core_wr_en, core_start, core_seq_num,
	output core_ctx_num,
	input [4*N_CORES-1:0] core_ready,
	output [31:0] core_din,
	output [3:0] core_wr_addr,
	output [`BLK_OP_MSB:0] core_blk_op,
	output core_input_ctx, core_input_seq, core_set_input_ready,
	
	input [N_CORES-1:0] core_dout_en, core_dout_seq_num,
	input [N_CORES-1:0] core_dout_ctx_num,
	input [32*N_CORES-1 :0] core_dout,

	output [5:0] err
	);


	// **********************************************************
	//
	//   CORES' CONTROLS
	//
	// **********************************************************
	core_ctrl #( .N_CORES(N_CORES) ) core_ctrl(
		.CLK(CLK), .core_start(core_start),
		.ctx_num(core_ctx_num), .seq_num(core_seq_num)
	);


	// **********************************************************
	//
	//   ENGINE
	//
	// **********************************************************
	// engine - procb
	wire [N_THREADS_MSB:0] comp_procb_wr_thread_num;
	wire [`PROCB_D_WIDTH-1 :0] procb_wr_data;
	wire [`PROCB_A_WIDTH-1 :0] procb_wr_cnt;
	wire [`COMP_DATA1_MSB :0] comp_wr_data1;
	// engine - thread_state
	wire [N_THREADS_MSB :0] ts_wr_num1, ts_rd_num1, ts_num4;
	wire [`THREAD_STATE_MSB :0] ts_wr1, ts_wr4;
	wire ts_wr_en1, ts_wr_en4;
	wire [`THREAD_STATE_MSB :0] ts_rd1, ts_rd4;
	// engine - memory
	wire [`COMP_DATA2_MSB :0] comp_wr_data2;
	wire [31:0] ext_din;
	wire [`MEM_TOTAL_MSB :0] ext_wr_addr;
	wire [`MEM_TOTAL_MSB :0] mem_rd_addr_cpu;
	wire [31:0] mem_dout;


	engine #( .N_CORES(N_CORES) ) engine(
		.CLK(CLK),
		// procb_buf
		.procb_wr_thread_num(comp_procb_wr_thread_num),
		.procb_wr_en(procb_wr_en),
		.procb_wr_data(procb_wr_data), .procb_wr_cnt(procb_wr_cnt),
		.comp_data1_wr_en(comp_wr_en), .comp_wr_data1(comp_wr_data1),
		// thread_state
		.ts_wr_num1(ts_wr_num1), .ts_rd_num1(ts_rd_num1), .ts_num4(ts_num4),
		.ts_wr1(ts_wr1), .ts_wr_en1(ts_wr_en1), .ts_rd1(ts_rd1),
		.ts_wr4(ts_wr4), .ts_wr_en4(ts_wr_en4), .ts_rd4(ts_rd4),
		// memory
		.comp_data2_wr_en(comp_wr_en), .comp_wr_data2(comp_wr_data2),
		.ext_din(ext_din), .ext_wr_addr(ext_wr_addr), .ext_wr_en(ext_wr_en),
		.ext_full(ext_full),
		.mem_rd_cpu_request(mem_rd_cpu_request),
		.mem_rd_addr_cpu(mem_rd_addr_cpu),
		.mem_dout(mem_dout), .mem_rd_cpu_valid(mem_rd_cpu_valid),
		// cores
		.core_wr_en(core_wr_en), .core_ready(core_ready), .core_din(core_din),
		.core_wr_addr(core_wr_addr), .core_blk_op(core_blk_op),
		.core_input_seq(core_input_seq), .core_input_ctx(core_input_ctx), 
		.core_set_input_ready(core_set_input_ready),
		.core_dout(core_dout), .core_dout_en(core_dout_en),
		.core_dout_seq_num(core_dout_seq_num),
		.core_dout_ctx_num(core_dout_ctx_num),
		.err(err[4:0])
	);


	// **********************************************************
	//
	//   UNIT INPUT
	//
	// - operates independently from the CPU
	// - finds idle thread (THREAD_STATE_NONE)
	// - accepts data packet, writes into the beginning of the
	// thread's memory, sets THREAD_STATE_WR_RDY
	//
	// **********************************************************
	wire [`ENTRY_PT_MSB:0] entry_pt_curr;

	unit_input #( .N_CORES(N_CORES)
	) unit_input(
		.CLK(CLK),
		.in(unit_in), .ctrl(unit_in_ctrl), .wr_en(unit_in_wr_en),
		.afull(unit_in_afull), .ready(unit_in_ready),

		.out(ext_din), .mem_addr(ext_wr_addr),
		.rd_en(ext_wr_en), .empty(unit_input_empty),

		.ts_num(ts_num4), .ts_wr_en(ts_wr_en4),
		.ts_wr(ts_wr4), .ts_rd(ts_rd4),

		.entry_pt_curr(entry_pt_curr)
	);

	assign ext_wr_en = ~unit_input_empty & ~ext_full;


	// **********************************************************
	//
	//   UNIT OUTPUT BUFFER
	//
	// **********************************************************
	wire [15:0] uob_data;
	wire [`UOB_ADDR_MSB :0] uob_wr_addr;

	uob unit_output_buf(
		.clk_wr(CLK),
		.din(uob_data), .wr_en(uob_wr_en), .wr_addr(uob_wr_addr),
		.full(uob_full), .ready(uob_ready),
		.set_input_complete(uob_set_input_complete),

		.clk_rd(CLK),
		.dout(dout), .rd_en(rd_en), .empty(empty)
	);


	// **********************************************************
	//
	//   CPU
	//
	// **********************************************************

	cpu #( .WIDTH(16), .N_CORES(N_CORES) ) cpu(
		.CLK(CLK),
		.entry_pt_curr(entry_pt_curr),
		// thread_state (ts) - using channel 1
		.ts_wr_num(ts_wr_num1), .ts_rd_num(ts_rd_num1), .ts_wr_en(ts_wr_en1),
		.ts_wr(ts_wr1), .ts_rd(ts_rd1),
		// comp_buf & procb_buf
		.comp_wr_en(comp_wr_en), .procb_wr_en(procb_wr_en),
		.procb_wr_cnt(procb_wr_cnt),
		.comp_procb_wr_thread_num(comp_procb_wr_thread_num),
		.comp_dout({ comp_wr_data1, comp_wr_data2 }),
		.procb_dout(procb_wr_data),
		// memory read
		.mem_rd_request(mem_rd_cpu_request), .mem_rd_addr(mem_rd_addr_cpu),
		.mem_rd_valid(mem_rd_cpu_valid), .mem_din(mem_dout),
		// unit_output_buf
		.uob_dout(uob_data), .uob_wr_en(uob_wr_en),
		.uob_wr_addr(uob_wr_addr), .uob_ready(uob_ready), .uob_full(uob_full),
		.uob_set_input_complete(uob_set_input_complete),
		.err(err[5])
	);


endmodule

`else

module unit_ctrl #(
	parameter N_CORES = `N_CORES,
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,
	// Unit Input
	input [`UNIT_INPUT_WIDTH-1 :0] unit_in,
	input unit_in_ctrl, unit_in_wr_en,
	output unit_in_afull, unit_in_ready,
	// Unit Output
	output [`UNIT_OUTPUT_WIDTH-1 :0] dout,
	input rd_en,
	output empty,
	// *** Cores ***
	// (are kept separate because of Placement & Routing issues)
	output [N_CORES-1:0] core_wr_en, core_start, core_seq_num,
	output core_ctx_num,
	input [4*N_CORES-1:0] core_ready,
	output [31:0] core_din,
	output [3:0] core_wr_addr,
	output [`BLK_OP_MSB:0] core_blk_op,
	output core_input_ctx, core_input_seq, core_set_input_ready,
	
	input [N_CORES-1:0] core_dout_en, core_dout_seq_num,
	input [N_CORES-1:0] core_dout_ctx_num,
	input [32*N_CORES-1 :0] core_dout,

	output [5:0] err
	);

endmodule

`endif


module unit_ctrl_dummy #(
	parameter N_CORES = `N_CORES,
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,
	// Unit Input
	input [`UNIT_INPUT_WIDTH-1 :0] unit_in,
	input unit_in_ctrl, unit_in_wr_en,
	output unit_in_afull, unit_in_ready,
	// Unit Output
	output [`UNIT_OUTPUT_WIDTH-1 :0] dout,
	input rd_en,
	output empty,
	// *** Cores ***
	// (are kept separate because of Placement & Routing issues)
	output [N_CORES-1:0] core_wr_en, core_start, core_seq_num,
	output core_ctx_num,
	input [4*N_CORES-1:0] core_ready,
	output [31:0] core_din,
	output [3:0] core_wr_addr,
	output [`BLK_OP_MSB:0] core_blk_op,
	output core_input_ctx, core_input_seq, core_set_input_ready,
	
	input [N_CORES-1:0] core_dout_en, core_dout_seq_num,
	input [N_CORES-1:0] core_dout_ctx_num,
	input [32*N_CORES-1 :0] core_dout,

	output [5:0] err
	);

	(* KEEP="true" *) assign unit_in_afull = 0;
	(* KEEP="true" *) assign unit_in_ready = 0;
	(* KEEP="true" *) assign dout = 0;
	(* KEEP="true" *) assign empty = 1;
	(* KEEP="true" *) assign core_wr_en = 0;
	(* KEEP="true" *) assign core_dout_en = 0;
	(* KEEP="true" *) assign core_dout_seq = 0;
	(* KEEP="true" *) assign core_din = 0;
	(* KEEP="true" *) assign core_wr_addr = 0;
	(* KEEP="true" *) assign core_blk_op = 0;
	(* KEEP="true" *) assign core_seq = 0;
	(* KEEP="true" *) assign core_set_input_ready = 0;
	(* KEEP="true" *) assign err = 0;

endmodule


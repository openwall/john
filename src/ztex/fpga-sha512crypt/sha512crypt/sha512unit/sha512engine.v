`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017-2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "sha512.vh"


`ifdef SIMULATION

module sha512engine #(
	parameter N_CORES = 4,
	parameter N_THREADS = 4 * N_CORES,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	// Unit Input
	input CLK,
	input [`UNIT_INPUT_WIDTH-1 :0] unit_in,
	input unit_in_ctrl, unit_in_wr_en,
	output unit_in_afull, unit_in_ready,

	// Unit Output
	input PKT_COMM_CLK,
	output [`UNIT_OUTPUT_WIDTH-1 :0] dout,
	input rd_en,
	output empty,

	// connections to cores (core's input) - per-core
	input [N_CORES-1:0] ready0, ready1,
	output [N_CORES-1:0] core_wr_en,
	// connections to cores (core's input) - broadcast
	output [63:0] core_in,
	output [3:0] core_wr_addr,
	output [`BLK_OP_MSB:0] input_blk_op,
	output input_ctx, input_seq, set_input_ready,
	// connections to cores (core's output)
	input [32*N_CORES-1 :0] core_out,
	input [N_CORES-1 :0] core_out_ready, core_out_start,
	input [N_CORES-1 :0] core_out_ctx_num, core_out_seq_num,
	output [N_CORES-1 :0] core_rd_en
	);


	// **********************************************************
	//
	// I. Main memory: 32-bit input, 64-bit output, 4 Kbytes
	//    (32 words x64-bit = 256 bytes per thread, 16 threads max)
	//
	// IP Coregen: Block Memory Generator
	// Port A: Width 32, Depth 1024, Use ENA
	// Port B: Width 64, Use ENB
	//
	// **********************************************************
	wire [`MEM_TOTAL_MSB+1 :0] mem_wr_addr;
	wire [31:0] mem_input;

	wire [`MEM_TOTAL_MSB :0] mem_rd_addr, mem_rd_addr_procb,
		mem_rd_addr_cpu;
	wire [63:0] mem_doutb, mem_dinb;

	mem_32in_64out_4k mem_main(
		.clka(CLK),
		.ena(mem_wr_en),
		.wea(1'b1),
		.addra(mem_wr_addr), // input [9 : 0] addra
		.dina(mem_input), // input [31 : 0] dina
		.douta(),
		.clkb(CLK),
		.enb(mem_rd_en),
		.web(1'b0),
		.addrb(mem_rd_addr), // input [8 : 0] addrb
		.dinb(mem_dinb), // unused; remove 64 warnings
		.doutb(mem_doutb) // output [63 : 0] doutb
	);

	// Remove cpu read
	//assign mem_rd_en = mem_rd_en_procb;
	//assign mem_rd_addr = mem_rd_addr_procb;


	// **********************************************************
	//
	// Memory output. CPU read (reg <- memory) occurs when
	// process_bytes doesn't read.
	// - cpu sets up mem_rd_cpu_request, mem_rd_addr_cpu
	// - read is 1 word
	// - after the read, mem_rd_cpu_valid asserts for 1 cycle
	// - many reads in a row are possible
	//
	// **********************************************************
	reg mem_rd_cpu_valid = 0;

	assign mem_rd_en = mem_rd_en_procb
		| (mem_rd_cpu_request & ~mem_rd_cpu_valid);

	assign mem_rd_addr = mem_rd_en_procb
		? mem_rd_addr_procb : mem_rd_addr_cpu;

	always @(posedge CLK) begin
		if (mem_rd_cpu_valid)
			mem_rd_cpu_valid <= 0;
		else if (mem_rd_cpu_request & ~mem_rd_en_procb)
			mem_rd_cpu_valid <= 1;
	end


	// **********************************************************
	//
	// thread_state (ts)
	// Each thread is in some defined state. There're multiple
	// channels to read/modify state of threads.
	//
	// **********************************************************
	wire [N_THREADS_MSB :0] ts_wr_num1, ts_rd_num1,
		ts_wr_num2, ts_rd_num2, ts_num3, ts_num4;
	wire [`THREAD_STATE_MSB :0] ts_wr1, ts_wr2, ts_wr3, ts_wr4,
		ts_rd1, ts_rd2, ts_rd3, ts_rd4;

	thread_state #( .N_THREADS(N_THREADS)
	) thread_state(
		.CLK(CLK),
		.wr_num1(ts_wr_num1), .wr_en1(ts_wr_en1), // channel 1 - CPU
		.wr_state1(ts_wr1), .rd_num1(ts_rd_num1), .rd_state1(ts_rd1),
		.wr_num2(ts_wr_num2), .wr_en2(ts_wr_en2), // channel 2 - procb
		.wr_state2(ts_wr2), .rd_num2(ts_rd_num2), .rd_state2(ts_rd2),
		.wr_num3(ts_num3), .wr_en3(ts_wr_en3), // 3 - memory_input_mgr
		.wr_state3(ts_wr3), .rd_num3(ts_num3), .rd_state3(ts_rd3),
		.wr_num4(ts_num4), .wr_en4(ts_wr_en4), // 4 - unit_input
		.wr_state4(ts_wr4), .rd_num4(ts_num4), .rd_state4(ts_rd4),
		.err()
	);


	// **********************************************************
	//
	// comp_buf contains data for the current computation
	// (1 data set for each thread, divided into 2 parts).
	//
	// **********************************************************
	wire [N_THREADS_MSB :0] comp_procb_wr_thread_num;
	wire [N_THREADS_MSB :0] comp_rd_thread_num1, comp_rd_thread_num2;
	wire [`COMP_DATA1_MSB :0] comp_wr_data1, comp_dout1;
	wire [`COMP_DATA2_MSB :0] comp_wr_data2, comp_dout2;

	comp_buf #( .N_THREADS(N_THREADS)
	) comp_buf(
		.CLK(CLK),
		.wr_thread_num(comp_procb_wr_thread_num), .wr_en(comp_wr_en),
		.wr_data1(comp_wr_data1), .wr_data2(comp_wr_data2),

		.rd_thread_num1(comp_rd_thread_num1), .dout1(comp_dout1),
		.rd_thread_num2(comp_rd_thread_num2), .dout2(comp_dout2)
	);


	// **********************************************************
	//
	// Memory input manager
	//
	// **********************************************************
	wire [31:0] ext_din;
	wire [`MEM_TOTAL_MSB+1 :0] ext_wr_addr; //+1 bit for 32-bit input

	memory_input_mgr #( .N_CORES(N_CORES)
	) memory_input_mgr(
		.CLK(CLK),
		// Output from cores
		.core_out(core_out),
		.core_out_ready(core_out_ready), .core_out_start(core_out_start),
		.core_out_ctx_num(core_out_ctx_num),
		.core_out_seq_num(core_out_seq_num), .core_rd_en(core_rd_en),
		// computation data #2
		.comp_data2_thread_num(comp_rd_thread_num2),
		.comp_data2(comp_dout2),
		// Thread Status
		.ts_num(ts_num3), .ts_wr_en(ts_wr_en3), .ts_wr(ts_wr3),
		// External input
		.ext_din(ext_din), .ext_wr_en(ext_wr_en),
		.ext_wr_addr(ext_wr_addr), .ext_full(ext_full),
		// Memory
		.dout(mem_input), .mem_wr_addr(mem_wr_addr),
		.mem_wr_en(mem_wr_en)
	);


	// **********************************************************
	//
	// Unit input
	// - operates independently from the CPU
	// - finds idle thread (THREAD_STATE_NONE)
	// - accepts data packet, writes into the beginning of the
	// thread's memory, sets THREAD_STATE_WR_RDY
	//
	// **********************************************************
	wire [`ENTRY_PT_MSB:0] entry_pt_curr;

	unit_input_async #( .N_CORES(N_CORES)
	) unit_input(
		.WR_CLK(PKT_COMM_CLK),
		.in(unit_in), .ctrl(unit_in_ctrl), .wr_en(unit_in_wr_en),
		.afull(unit_in_afull), .ready(unit_in_ready),

		.RD_CLK(CLK),
		.out(ext_din), .mem_addr(ext_wr_addr),
		.rd_en(ext_wr_en), .empty(unit_input_empty),

		.ts_num(ts_num4), .ts_wr_en(ts_wr_en4),
		.ts_wr(ts_wr4), .ts_rd(ts_rd4),

		.entry_pt_curr(entry_pt_curr)
	);

	assign ext_wr_en = ~unit_input_empty & ~ext_full;


	// **********************************************************
	//
	// realign & core_input
	//
	// **********************************************************
	wire [3:0] len;
	wire [2:0] off;
	wire [`PROCB_TOTAL_MSB :0] bytes_total;
	wire [N_THREADS_MSB :0] core_thread_num;
	wire [`BLK_OP_MSB:0] blk_op;

	reg [3:0] len_r = 8;
	reg [2:0] off_r = 0;
	reg add0x80pad_r = 0, add0pad_r = 0, add_total_r = 0;
	reg [`PROCB_TOTAL_MSB :0] bytes_total_r = 0;
	reg [N_THREADS_MSB :0] core_thread_num_r;
	reg [`BLK_OP_MSB:0] blk_op_r;

	always @(posedge CLK) begin
		len_r <= len; off_r <= off;
		add0x80pad_r <= add0x80pad; add0pad_r <= add0pad;
		add_total_r <= add_total; bytes_total_r <= bytes_total;
		core_thread_num_r <= core_thread_num; blk_op_r <= blk_op;
	end

	reg realign_wr_en = 0;
	always @(posedge CLK)
		realign_wr_en <= mem_rd_en_procb;

	realign8_pad realign8_pad(
		.CLK(CLK),
		.wr_en(realign_wr_en),
		.din(mem_doutb),

		.len(len_r), .off(off_r),
		.add0x80pad(add0x80pad_r), .add0pad(add0pad_r),
		.add_total(add_total_r), .total_bytes(bytes_total_r),

		.valid_eqn(realign_valid_eqn), .valid(realign_valid),
		.wr_en_r(realign_wr_en_r),
		.err(realign_err), .out(core_in)
	);

	core_input #( .N_CORES(N_CORES)
	) core_input(
		.CLK(CLK),
		.realign_wr_en_r(realign_wr_en_r),
		.realign_valid_eqn(realign_valid_eqn), .realign_valid(realign_valid),

		.thread_num(core_thread_num_r), .blk_op(blk_op_r),

		.core_wr_en(core_wr_en), .core_wr_addr(core_wr_addr),
		.input_blk_op(input_blk_op), .input_ctx(input_ctx),
		.input_seq(input_seq), .set_input_ready(set_input_ready)
	);


	// **********************************************************
	//
	// procb_buf
	//
	// A write into the buffer resembles
	// the call to process_bytes() software function.
	// So-called "procb records" are written.
	//
	// **********************************************************
	wire [N_THREADS_MSB :0] procb_rd_thread_num;
	wire [`PROCB_D_WIDTH-1 :0] procb_wr_data, procb_dout;
	wire [`PROCB_A_WIDTH-1 :0] procb_wr_cnt;

	procb_buf #( .N_THREADS(N_THREADS)
	) procb_buf(
		.CLK(CLK),
		.wr_thread_num(comp_procb_wr_thread_num), .wr_en(procb_wr_en),
		.din(procb_wr_data), .wr_cnt(procb_wr_cnt),
		// read by procb
		.rd_thread_num(procb_rd_thread_num),
		.rd_en(procb_rd_en), .rd_rst(procb_rd_rst),
		//.aempty(procb_aempty),
		// read-ahead
		.lookup_en(procb_lookup_en), .lookup_empty(procb_lookup_empty),
		.dout(procb_dout)
	);


	// **********************************************************
	//
	// process_bytes.
	// - operates controls for realign8, core_input.
	// That allows to create 16x64-bit data blocks out of
	// procb records and send them to cores. Padding & total are
	// added where required.
	//
	// **********************************************************
	process_bytes #( .N_CORES(N_CORES)
	) process_bytes(
		.CLK(CLK),
		// thread_state (ts) - using channel 2
		.ts_wr_num(ts_wr_num2), .ts_wr_en(ts_wr_en2),
		.ts_wr(ts_wr2), .ts_rd_num(ts_rd_num2), .ts_rd(ts_rd2),

		// comp_buf
		.comp_data1_thread_num(comp_rd_thread_num1),
		.comp_data1(comp_dout1),

		// procb_buf
		.procb_rd_thread_num(procb_rd_thread_num),
		.procb_rd_en(procb_rd_en), .procb_rd_rst(procb_rd_rst),
		//.procb_aempty(procb_aempty),
		.procb_dout(procb_dout),
		.procb_lookup_en(procb_lookup_en),
		.procb_lookup_empty(procb_lookup_empty),

		// Memory read, supplementary data for realign8_pad, core_input
		.mem_rd_addr(mem_rd_addr_procb), .mem_rd_en(mem_rd_en_procb),

		.len(len), .off(off),
		.add0x80pad(add0x80pad), .add0pad(add0pad),
		.add_total(add_total), .total(bytes_total),

		.core_thread_num(core_thread_num), .blk_op(blk_op),

		// Connections from cores
		.ready0(ready0), .ready1(ready1),
		.err()
	);


	// **********************************************************
	//
	// Unit Output Buffer
	//
	// **********************************************************
	wire [31:0] uob_data;
	wire [`UOB_ADDR_MSB :0] uob_wr_addr;

	unit_output_buf unit_output_buf(
		.clk_wr(CLK),
		.din(uob_data), .wr_en(uob_wr_en), .wr_addr(uob_wr_addr),
		.full(uob_full), .ready(uob_ready),
		.set_input_complete(uob_set_input_complete),

		.clk_rd(PKT_COMM_CLK),
		.dout(dout), .rd_en(rd_en), .empty(empty)
	);


	// **********************************************************
	//
	// Instruction execution (CPU)
	// - "main" instructions are NEW_CTX, PROCESS_BYTES, FINISH_CTX
	// - input/output instructions
	// - execution flow instructions
	// - supplementary integer operations
	//
	// **********************************************************
	cpu #( .N_CORES(N_CORES)
	) cpu(
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
		.mem_rd_valid(mem_rd_cpu_valid), .mem_din(mem_doutb),
		// unit_output_buf
		.uob_dout(uob_data), .uob_wr_en(uob_wr_en),
		.uob_wr_addr(uob_wr_addr), .uob_ready(uob_ready), .uob_full(uob_full),
		.uob_set_input_complete(uob_set_input_complete)
	);


endmodule

`else

module sha512engine #(
	parameter N_CORES = 4,
	parameter N_THREADS = 4 * N_CORES,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	// Unit Input
	input CLK,
	input [`UNIT_INPUT_WIDTH-1 :0] unit_in,
	input unit_in_ctrl, unit_in_wr_en,
	output unit_in_afull, unit_in_ready,

	// Unit Output
	input PKT_COMM_CLK,
	output [`UNIT_OUTPUT_WIDTH-1 :0] dout,
	input rd_en,
	output empty,

	// connections to cores (core's input) - per-core
	input [N_CORES-1:0] ready0, ready1,
	output [N_CORES-1:0] core_wr_en,
	// connections to cores (core's input) - broadcast
	output [63:0] core_in,
	output [3:0] core_wr_addr,
	output [`BLK_OP_MSB:0] input_blk_op,
	output input_ctx, input_seq, set_input_ready,
	// connections to cores (core's output)
	input [32*N_CORES-1 :0] core_out,
	input [N_CORES-1 :0] core_out_ready, core_out_start,
	input [N_CORES-1 :0] core_out_ctx_num, core_out_seq_num,
	output [N_CORES-1 :0] core_rd_en
	);

endmodule

`endif



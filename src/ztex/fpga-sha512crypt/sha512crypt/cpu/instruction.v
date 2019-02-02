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


module instruction #(
	parameter N_CORES = `N_CORES,
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,

	// Program entry point
	input [`ENTRY_PT_MSB:0] entry_pt_curr,
	output [N_THREADS_MSB :0] ts_rd_num,
	input [`THREAD_STATE_MSB :0] ts_rd,

	// current thread_num (being executed)
	output [`MSB(N_THREADS-1) :0] thread_num,
	// asserts 1 cycle before instruction is available on output
	output thread_almost_switched,

	output reg [`INSTR_LEN-1 :0] instruction, // right out from BRAM
	// Instruction gets partially decoded here

	input INVALIDATE, // Invalidate partially loaded and decoded
	// instructions, pre-fetched data etc.
	// INVALIDATE appears 1 cycle before NEXT_THREAD
	// (in case JMP switches thread)
	input INSTR_WAIT,
	// Advance effective Instruction Pointer
	// (w/o respect to actual result).
	input	EXECUTED, // does not apply to JUMP
	input NEXT_THREAD,
	input JUMP, // assuming NEXT_THREAD always set with JUMP
	input [`IADDR_LEN-1 :0] jump_addr,

	output [`N_STAGES-1:0] stage_allow,
	output reg err = 0,

	// "dummy" 2nd write-only port for BRAM
	(* KEEP="true" *) input wr_en_dummy,
	(* KEEP="true" *) input wr_addr_dummy
	);


	// **********************************************************
	//
	// Program entry points
	//
	// **********************************************************
`ifdef ENTRY_PTS_EN
	reg [`IADDR_LEN-1 :0] entry_pts [2**(`ENTRY_PT_MSB+1)-1 :0];
	initial begin
		entry_pts[0] = 0;
		entry_pts[1] = 150;
	end

	reg [`ENTRY_PT_MSB:0] entry_pt_last = 0;
	always @(posedge CLK)
		entry_pt_last <= entry_pt_curr;

	wire entry_pt_switch = entry_pt_last != entry_pt_curr;
	wire [`IADDR_LEN-1 :0] entry_pt = entry_pts [entry_pt_curr];

`else
	wire entry_pt_switch = 1'b0;
	wire [`IADDR_LEN-1 :0] entry_pt = 0;
`endif


	// **********************************************************
	//
	// Current thread number, switching threads
	// - While it runs the program in some thread, it looks ahead
	// for a thread in WR_RDY state. When NEXT_THREAD asserts,
	// it doesn't waste time and starts loading Instruction
	// Pointer for the next thread immediately.
	//
	// **********************************************************
	wire [`MSB(N_THREADS-1) :0] thread_num_ahead;

	thread_number #( .N_CORES(N_CORES), .N_THREADS(N_THREADS)
	) thread_number(
		.CLK(CLK),
		.entry_pt_switch(entry_pt_switch),
		.ts_rd_num(ts_rd_num), .ts_rd(ts_rd),
		.NEXT_THREAD(NEXT_THREAD),
		.RELOAD(RELOAD), // start loading the instruction
		.thread_num(thread_num), .thread_num_ahead(thread_num_ahead),
		.thread_init(init)
	);


	// **********************************************************
	//
	// Instruction Execution State
	// - Currently, INVALIDATE asserts 1 cycle before NEXT_THREAD
	// - RELOAD asserts on the same cycle as NEXT_THREAD, or later.
	// - On the next cycle after RELOAD, stage_allow=0001
	//
	// **********************************************************
	cpu_state cpu_state(
		.CLK(CLK),
		.invalidate(INVALIDATE), .instr_wait(INSTR_WAIT), .reload(RELOAD),
		.thread_almost_switched(thread_almost_switched),
		.stage_allow(stage_allow)
	);


	// **********************************************************
	//
	// Instruction pointer
	//
	// **********************************************************
	reg [`IADDR_LEN-1 :0] IP_curr;
	reg [`IADDR_LEN-1 :0] IP_effective;
	reg [`IADDR_LEN-1 :0] IP_mem [0: N_THREADS-1];
	wire [`IADDR_LEN-1 :0] IP_mem_dout = IP_mem [thread_num_ahead];

	(* KEEP="true" *)
	wire [1:0] IP_mem_wr_select =
		JUMP ? 2'b00 :
		EXECUTED ? 2'b01 :
		~init ? 2'b10 :
		2'b11;

	// Q. NEXT_THREAD and EXECUTE at the same time - OK
	// Q2. INVALIDATE & INSRT_WAIT - can't happen
	always @(posedge CLK)
		if (init | NEXT_THREAD)
			IP_mem [thread_num] <=
				IP_mem_wr_select == 2'b00 ? jump_addr :
				IP_mem_wr_select == 2'b01 ? IP_effective + 1'b1 :
				IP_mem_wr_select == 2'b10 ? IP_effective :
				entry_pt;
/*
				JUMP ? jump_addr :
				EXECUTED ? IP_effective + 1'b1 :
				~init ? IP_effective :
				entry_pt;
*/
	always @(posedge CLK)
		if (RELOAD) begin
			IP_curr <= IP_mem_dout;
			IP_effective <= IP_mem_dout;
		end
		else begin
			if (stage_allow[0])
				IP_curr <= IP_curr + 1'b1;
			if (EXECUTED)
				IP_effective <= IP_effective + 1'b1;
		end


	// Simulation / debug
	reg z;
	always @(posedge CLK)
		if (IP_curr == 65)
			z <= 1;


	// **********************************************************
	//
	// Instruction memory
	//
	// **********************************************************
	(* RAM_STYLE="BLOCK" *)
	reg [`INSTR_LEN-1 :0] instr_mem [0: 2**`IADDR_LEN-1];

	always @(posedge CLK)
		if (stage_allow[0])
			instruction <= instr_mem [IP_curr];

	// Partial decoding
	//wire op_code = instruction [];
	always @(posedge CLK) begin
	end


	always @(posedge CLK) begin
		// INVALIDATE asserted 2+ cycles in a row
		if (INVALIDATE & RELOAD)
			err <= 1;
		// ?
		//if (INVALIDATE & INSRT_WAIT)
	end


	// **********************************************************
	//
	// Declaring "dummy" 2nd write-only port
	// to force 1K BRAM in SDP mode (else it infers 2K TDP)
	//
	// **********************************************************
	always @(posedge CLK)
		if (wr_en_dummy)
			instr_mem[wr_addr_dummy] <= 1'b0;

`include "program.vh"


endmodule



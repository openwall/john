`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "sha512.vh"


//
// Task.
// Provide addresses for the current and next threads (= {core,ctx,seq})
// for various usages within process_bytes.
//
module procb_thread_addr #(
	parameter N_CORES = 4,
	parameter N_CORES_MSB = `MSB(N_CORES-1),
	parameter N_THREADS = 4 * N_CORES,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,
	// for "core_input": addressing the core for input
	input set_next_core_ctx_num, set_next_seq_num,
	output [N_THREADS_MSB :0] core_thread_num,
	// for procb_buf, procb_saved_state, ts - next thread,
	// often ahead of the "core_input"
	input set_next_procb_rd_thread_num,
	output [N_THREADS_MSB :0] procb_rd_thread_num,
	output [N_THREADS_MSB :0] procb_rd_thread_num2 // Replica
	);


	// core, context (0 or 1) currently being serviced; next core,context
	// 1. Uses cores 0 to N-1, context0; 2. Uses cores 0 to N-1, context1.
	// Such order ensures output conflicts.
	//
/*	reg [N_CORES_MSB:0] core_num = 0, core_num_next = N_CORES == 1 ? 0 : 1;
	reg ctx_num = 0, ctx_num_next = N_CORES == 1 ? 1 : 0;

	// Set next core,context for "core_input"
	always @(posedge CLK) if (set_next_core_ctx_num) begin
		core_num <= core_num_next;
		core_num_next <= core_num_next == N_CORES-1
			? {N_CORES_MSB+1{1'b0}} : core_num_next + 1'b1;
		
		ctx_num <= ctx_num_next;
		ctx_num_next <= core_num == N_CORES-1
			? ~ctx_num_next : ctx_num_next;
	end
*/

	reg [N_CORES_MSB+1 :0] core_ctx_num = 0, core_ctx_num_next = 1;

	// Set next core,context for "core_input"
	always @(posedge CLK) if (set_next_core_ctx_num) begin
		core_ctx_num <= core_ctx_num_next;
		core_ctx_num_next <= core_ctx_num_next == 2*N_CORES-1
			? {N_CORES_MSB+2{1'b0}} : core_ctx_num_next + 1'b1;
	end

	
	// 2. Sequence numbers
	//
	// Each of 2 parallel contexts in each core perform 2 computations
	// in sequence. After computation is finished, sequence number changes.
	// (seq_num doesn't change between blocks of the same computation)
	//
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [0:0] corectx_seq_num [2*N_CORES-1 :0];
	
	integer k;
	initial // Actually IVs don't matter; required for simulation
		for (k=0; k < 2*N_CORES; k=k+1)
			corectx_seq_num[k] = 0;
/*
	wire seq_num, seq_num_next;
	assign seq_num = corectx_seq_num [{core_num, ctx_num}];
	assign seq_num_next = corectx_seq_num [{core_num_next, ctx_num_next}];

	// Set next sequence number for the current core,context
	always @(posedge CLK)
		if (set_next_seq_num)
			corectx_seq_num [{core_num, ctx_num}] <= ~seq_num;

	//assign core_thread_num = {core_num,ctx_num,seq_num};
	reg seq_num_r;
	always @(posedge CLK)
		if (set_next_core_ctx_num)
			seq_num_r <= seq_num_next;
	
	assign core_thread_num = {core_num, ctx_num, seq_num_r};
*/

	wire seq_num, seq_num_next;
	assign seq_num = corectx_seq_num [core_ctx_num];
	assign seq_num_next = corectx_seq_num [core_ctx_num_next];
	reg seq_num_r = 0;

	always @(posedge CLK) begin
		if (set_next_seq_num)
			corectx_seq_num [core_ctx_num] <= ~seq_num;
		if (set_next_core_ctx_num)
			seq_num_r <= seq_num_next;
	end

	assign core_thread_num = {core_ctx_num, seq_num_r};


	// 3. procb_rd_thread_num
	//
	// This one typically points to the next thread in advance,
	// to get data in advance. Used for:
	//
	// - getting data from procb_buf
	// - etc
	//
/*
	reg [N_CORES_MSB:0] core_num_procb = 0;
	reg ctx_num_procb = 0, seq_num_procb = 0;
	
	always @(posedge CLK) if (set_next_procb_rd_thread_num) begin
		core_num_procb <= core_num_next;
		ctx_num_procb <= ctx_num_next;
		seq_num_procb <= seq_num_next;
	end

	assign procb_rd_thread_num = {core_num_procb,
			ctx_num_procb, seq_num_procb};
*/

	(* EQUIVALENT_REGISTER_REMOVAL="no" *)
	reg [N_CORES_MSB+1:0] core_ctx_num_procb = 0, core_ctx_num_procb2 = 0;
	(* EQUIVALENT_REGISTER_REMOVAL="no" *)
	reg seq_num_procb = 0, seq_num_procb2 = 0;
	
	always @(posedge CLK) if (set_next_procb_rd_thread_num) begin
		core_ctx_num_procb <= core_ctx_num_next;
		core_ctx_num_procb2 <= core_ctx_num_next;
		seq_num_procb <= seq_num_next;
		seq_num_procb2 <= seq_num_next;
	end
	
	assign procb_rd_thread_num = {core_ctx_num_procb, seq_num_procb};

	assign procb_rd_thread_num2 = {core_ctx_num_procb2, seq_num_procb2};


endmodule

`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018-2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../sha512.vh"

//
// Relevant:
// next_thread_num
//
module core_ctrl #(
	parameter N_CORES = `N_CORES,
	parameter N_CORES_MSB = `MSB(N_CORES-1),
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1),
	parameter TOTAL_CYCLES = 352,
	parameter COMP_INTERVAL = TOTAL_CYCLES / N_THREADS // must be 22
	)(
	input CLK,
	output reg [N_CORES-1:0] core_start = 0,
	output reg ctx_num = 1,// seq_num = 1
	output reg [N_CORES-1:0] seq_num = {N_CORES{1'b1}}
	);

	// 1. Traverse cores, ctx 0, seq0
	// 2. ctx1, seq0
	reg [`MSB(COMP_INTERVAL-1) :0] cnt = 0;
	reg ctx_num_curr = 0;
	reg [`MSB(N_CORES-1) :0] core_num = 0;

	always @(posedge CLK) begin
		ctx_num <= ~ctx_num;

		if (|core_start)
			core_start <= 0;

		if (cnt != COMP_INTERVAL-1)
			cnt <= cnt + 1'b1;
		else begin
			cnt <= 0;
			if (core_num == N_CORES-1) begin
				core_num <= 0;
				ctx_num_curr <= ~ctx_num_curr;
				if (ctx_num_curr)
					seq_num <= ~seq_num;
			end
			else
				core_num <= core_num + 1'b1;
		end

		if (cnt == 0 & ~ctx_num_curr | cnt == 1 & ctx_num_curr)
			core_start[core_num] <= 1;
	end

/*
	// 1. For each core - first ctx0, then ctx1
	reg [`MSB(COMP_INTERVAL-1) :0] cnt = 0;
	reg odd = 0; // Asserts on sequence #1
	reg [`MSB(N_CORES-1) :0] core_num = 0;
	
	always @(posedge CLK) begin
		ctx_num <= ~ctx_num;

		if (|core_start)
			core_start <= 0;

		if (cnt == COMP_INTERVAL-1) begin
			cnt <= 0;
			odd <= ~odd;
			if (odd) begin
				if (core_num == N_CORES-1) begin
					core_num <= 0;
				end
				else
					core_num <= core_num + 1'b1;
			end
		end
		else
			cnt <= cnt + 1'b1;

		if (cnt == 0 & ~odd | cnt == 1 & odd) begin
			core_start[core_num] <= 1;
			if (~odd)
				seq_num[core_num] <= ~seq_num[core_num];
		end
	end
*/
/*
	//
	//   This works fine, takes ~2X LUT
	//
	// 1. For each core - first ctx0, then ctx1
	reg [8:0] cnt = 0;
	always @(posedge CLK)
		cnt <= cnt == TOTAL_CYCLES-1 ? 9'b0 : cnt + 1'b1;

	always @(posedge CLK)
		ctx_num <= cnt[0];

	genvar i;
	generate
	for (i=0; i < N_CORES; i=i+1) begin:for_start

		always @(posedge CLK) begin
			if (core_start[i])
				core_start[i] <= 0;

			if (cnt == 2*i * COMP_INTERVAL
					| cnt == (2*i + 1) * COMP_INTERVAL -1
					| cnt == TOTAL_CYCLES/2 + 2*i * COMP_INTERVAL
					| cnt == TOTAL_CYCLES/2 + (2*i + 1) * COMP_INTERVAL -1)
				core_start[i] <= 1;

			if (cnt == 2*i * COMP_INTERVAL)
				seq_num[i] <= 0;

			if (cnt == TOTAL_CYCLES/2 + 2*i * COMP_INTERVAL)
				seq_num[i] <= 1;

		end

	end
	endgenerate
*/
endmodule

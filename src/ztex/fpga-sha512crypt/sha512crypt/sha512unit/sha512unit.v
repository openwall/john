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


module sha512unit #(
	parameter [63:0] UNIT_CONF = 0,
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
	output empty
	);

	localparam UNIT_IS_DUMMY = UNIT_CONF[63];

	genvar i;


	// *********************************************************
	//
	// Cores
	//
	// *********************************************************
	wire [N_CORES-1:0] ready0, ready1, core_wr_en;
	wire [63:0] core_in;
	wire [3:0] core_wr_addr;
	wire [`BLK_OP_MSB:0] blk_op;
	wire input_ctx, input_seq, set_input_ready;

	wire [32*N_CORES-1 :0] core_out;
	wire [N_CORES-1 :0] core_out_ready, core_out_start;
	wire [N_CORES-1 :0] core_out_ctx_num, core_out_seq_num;
	wire [N_CORES-1 :0] core_rd_en;

	generate
	for (i=0; i < N_CORES; i=i+1) begin:cores

		localparam [0:0] CORE_IS_DUMMY = UNIT_CONF[20 + i];

		wire ready0_in, ready1_in, core_out_ready_in, core_out_start_in,
			core_out_ctx_num_in, core_out_seq_num_in;

		if (~CORE_IS_DUMMY) begin

			(* KEEP_HIERARCHY="true" *)
			sha512core core(
				.CLK(CLK),
				.ready0(ready0[i]), .ready1(ready1[i]),
				.wr_en(core_wr_en[i]), .in(core_in),
				.wr_addr(core_wr_addr), .input_blk_op(blk_op),
				.input_ctx(input_ctx), .input_seq(input_seq),
				.set_input_ready(set_input_ready),

				.dout(core_out [32*i +:32]),
				.core_out_ready(core_out_ready[i]),
				.core_out_start(core_out_start[i]),
				.core_out_ctx_num(core_out_ctx_num[i]),
				.core_out_seq_num(core_out_seq_num[i]),
				.rd_en(core_rd_en[i])
			);

		end else begin // CORE_IS_DUMMY

			(* KEEP_HIERARCHY="true" *)
			sha512core_dummy core(
				.CLK(CLK),
				.ready0(ready0[i]), .ready1(ready1[i]),
				.wr_en(core_wr_en[i]), .in(core_in),
				.wr_addr(core_wr_addr), .input_blk_op(blk_op),
				.input_ctx(input_ctx), .input_seq(input_seq),
				.set_input_ready(set_input_ready),

				.dout(core_out [32*i +:32]),
				.core_out_ready(core_out_ready[i]),
				.core_out_start(core_out_start[i]),
				.core_out_ctx_num(core_out_ctx_num[i]),
				.core_out_seq_num(core_out_seq_num[i]),
				.rd_en(core_rd_en[i])
			);

		end

	end
	endgenerate


	// *********************************************************
	//
	// Engine
	//
	// *********************************************************

	if (~UNIT_IS_DUMMY) begin

		(* KEEP_HIERARCHY="true" *)
		//sha512engine #( .N_CORES(N_CORES) ) engine(
		sha512engine engine(
			.CLK(CLK),
			.unit_in(unit_in), .unit_in_ctrl(unit_in_ctrl),
			.unit_in_wr_en(unit_in_wr_en),
			.unit_in_afull(unit_in_afull), .unit_in_ready(unit_in_ready),

			.PKT_COMM_CLK(PKT_COMM_CLK),
			.dout(dout), .rd_en(rd_en), .empty(empty),

			// Connections to cores - input
			.ready0(ready0), .ready1(ready1),
			.core_wr_en(core_wr_en), .core_in(core_in),
			.core_wr_addr(core_wr_addr), .input_blk_op(blk_op),
			.input_ctx(input_ctx), .input_seq(input_seq),
			.set_input_ready(set_input_ready),
			// Connections to cores - output
			.core_out(core_out),
			.core_out_ready(core_out_ready), .core_out_start(core_out_start),
			.core_out_ctx_num(core_out_ctx_num),
			.core_out_seq_num(core_out_seq_num), .core_rd_en(core_rd_en)
		);

	end else begin

		(* KEEP_HIERARCHY="true" *)
		sha512engine_dummy engine(
			.CLK(CLK),
			.unit_in(unit_in), .unit_in_ctrl(unit_in_ctrl),
			.unit_in_wr_en(unit_in_wr_en),
			.unit_in_afull(unit_in_afull), .unit_in_ready(unit_in_ready),

			.PKT_COMM_CLK(PKT_COMM_CLK),
			.dout(dout), .rd_en(rd_en), .empty(empty),

			// Connections to cores - input
			.ready0(ready0), .ready1(ready1),
			.core_wr_en(core_wr_en), .core_in(core_in),
			.core_wr_addr(core_wr_addr), .input_blk_op(blk_op),
			.input_ctx(input_ctx), .input_seq(input_seq),
			.set_input_ready(set_input_ready),
			// Connections to cores - output
			.core_out(core_out),
			.core_out_ready(core_out_ready), .core_out_start(core_out_start),
			.core_out_ctx_num(core_out_ctx_num),
			.core_out_seq_num(core_out_seq_num), .core_rd_en(core_rd_en)
		);

	end


endmodule


module sha512engine_dummy #(
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

	(* KEEP="true" *) assign unit_in_afull = 1'b1;
	(* KEEP="true" *) assign unit_in_ready = 1'b0;
	(* KEEP="true" *) assign dout = 0;
	(* KEEP="true" *) assign empty = 1'b1;

endmodule


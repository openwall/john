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


module sha512unit #(
	parameter [63:0] UNIT_CONF = 0,
	parameter N_CORES = `N_CORES,
	parameter N_CORES_MSB = `MSB(N_CORES-1),
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
	output empty
	);

	localparam UNIT_IS_DUMMY = UNIT_CONF[63];

	genvar i;


	// **********************************************************
	//
	//   SHA512 CORES
	//
	// **********************************************************
	wire [N_CORES-1:0] core_wr_en, core_start, core_seq_num;
	wire [4*N_CORES-1:0] core_ready;
	wire [63:0] core_din;
	wire [3:0] core_wr_addr;
	wire [`BLK_OP_MSB:0] core_blk_op;
	wire core_ctx_num,// core_seq_num,
		core_input_seq, core_input_ctx, core_set_input_ready;

	wire [N_CORES-1:0] core_dout_en, core_dout_seq_num, core_dout_ctx_num;
	wire [64*N_CORES-1 :0] core_dout;

	generate
	for (i=0; i < N_CORES; i=i+1) begin:cores

		localparam [0:0] CORE_IS_DUMMY = UNIT_CONF[59 + i];

		if (~CORE_IS_DUMMY) begin

		(* KEEP_HIERARCHY="true" *)
		core core(
			.CLK(CLK),
			.start(core_start[i]), .ctx_num(core_ctx_num),
			.seq_num(core_seq_num[i]), .ready(core_ready[4*i +:4]),
			.wr_en(core_wr_en[i]), .din(core_din), .wr_addr(core_wr_addr),
			.input_blk_op(core_blk_op), .input_seq(core_input_seq),
			.input_ctx(core_input_ctx), .set_input_ready(core_set_input_ready),

			.dout(core_dout[64*i +:64]), .dout_en(core_dout_en[i]),
			.dout_seq_num(core_dout_seq_num[i]),
			.dout_ctx_num(core_dout_ctx_num[i])
		);

		end else begin // CORE_IS_DUMMY

		(* KEEP_HIERARCHY="true" *)
		core_dummy core(
			.CLK(CLK),
			.start(core_start[i]), .ctx_num(core_ctx_num),
			.seq_num(core_seq_num[i]), .ready(core_ready[4*i +:4]),
			.wr_en(core_wr_en[i]), .din(core_din), .wr_addr(core_wr_addr),
			.input_blk_op(core_blk_op), .input_seq(core_input_seq),
			.input_ctx(core_input_ctx), .set_input_ready(core_set_input_ready),

			.dout(core_dout[64*i +:64]), .dout_en(core_dout_en[i]),
			.dout_seq_num(core_dout_seq_num[i]),
			.dout_ctx_num(core_dout_ctx_num[i])
		);

		end

	end
	endgenerate


	// **********************************************************
	//
	//   UNIT CONTROLS
	//
	// **********************************************************

	if (~UNIT_IS_DUMMY) begin

		(* KEEP_HIERARCHY="true" *)
		unit_ctrl ctrl(
			.CLK(CLK),
			// Unit Input
			.unit_in(unit_in), .unit_in_ctrl(unit_in_ctrl),
			.unit_in_wr_en(unit_in_wr_en),
			.unit_in_afull(unit_in_afull), .unit_in_ready(unit_in_ready),
			// Unit Output
			.dout(dout), .rd_en(rd_en), .empty(empty),
			// Cores
			.core_start(core_start), .core_ctx_num(core_ctx_num),
			.core_seq_num(core_seq_num), .core_ready(core_ready),
			.core_wr_en(core_wr_en), .core_din(core_din), .core_wr_addr(core_wr_addr),
			.core_blk_op(core_blk_op), .core_input_seq(core_input_seq),
			.core_input_ctx(core_input_ctx),
			.core_set_input_ready(core_set_input_ready),

			.core_dout(core_dout), .core_dout_en(core_dout_en),
			.core_dout_seq_num(core_dout_seq_num),
			.core_dout_ctx_num(core_dout_ctx_num),
			.err() // 5:0
		);

	end else begin // UNIT_IS_DUMMY

		(* KEEP_HIERARCHY="true" *)
		unit_ctrl_dummy ctrl(
			.CLK(CLK),
			// Unit Input
			.unit_in(unit_in), .unit_in_ctrl(unit_in_ctrl),
			.unit_in_wr_en(unit_in_wr_en),
			.unit_in_afull(unit_in_afull), .unit_in_ready(unit_in_ready),
			// Unit Output
			.dout(dout), .rd_en(rd_en), .empty(empty),
			// Cores
			.core_start(core_start), .core_ctx_num(core_ctx_num),
			.core_seq_num(core_seq_num), .core_ready(core_ready),
			.core_wr_en(core_wr_en), .core_din(core_din), .core_wr_addr(core_wr_addr),
			.core_blk_op(core_blk_op), .core_input_seq(core_input_seq),
			.core_input_ctx(core_input_ctx),
			.core_set_input_ready(core_set_input_ready),

			.core_dout(core_dout), .core_dout_en(core_dout_en),
			.core_dout_seq_num(core_dout_seq_num),
			.core_dout_ctx_num(core_dout_ctx_num),
			.err() // 5:0
		);

	end

endmodule

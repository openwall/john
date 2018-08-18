`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "sha256.vh"


module sha256unit #(
	parameter [63:0] UNIT_CONF = 0,
	parameter N_CORES = 3,
	parameter N_CORES_MSB = `MSB(N_CORES-1),
	parameter N_THREADS = 2 * N_CORES,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,
	// Unit Input
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


	// **********************************************************
	//
	//   SHA256 CORES
	//
	// **********************************************************
	wire [N_CORES-1:0] core_wr_en, core_start;
	wire [31:0] core_din;
	wire [3:0] core_wr_addr;
	wire [`BLK_OP_MSB:0] core_blk_op;
	wire core_seq, core_set_input_ready;
	wire [N_CORES-1:0] core_ready, core_dout_en, core_dout_seq;
	wire [32*N_CORES-1 :0] core_dout;

	generate
	for (i=0; i < N_CORES; i=i+1) begin:cores

		localparam [0:0] CORE_IS_DUMMY = UNIT_CONF[20 + i];
		
		if (~CORE_IS_DUMMY) begin
		
		(* KEEP_HIERARCHY="true" *)
	//`ifdef SIMULATION
	//	sha256core #( .ID(i) ) core(
	//`else
		sha256core core(
	//`endif
			.CLK(CLK),
			.start(core_start[i]), .ready(core_ready[i]),
			.wr_en(core_wr_en[i]), .in(core_din), .wr_addr(core_wr_addr),
			.input_blk_op(core_blk_op),
			.input_seq(core_seq), .set_input_ready(core_set_input_ready),
			.dout(core_dout[32*i +:32]), .dout_en(core_dout_en[i]),
			.dout_seq(core_dout_seq[i])
		);

		end else begin // CORE_IS_DUMMY

		(* KEEP_HIERARCHY="true" *)
		sha256core_dummy core(
			.CLK(CLK),
			.start(core_start[i]), .ready(core_ready[i]),
			.wr_en(core_wr_en[i]), .in(core_din), .wr_addr(core_wr_addr),
			.input_blk_op(core_blk_op),
			.input_seq(core_seq), .set_input_ready(core_set_input_ready),
			.dout(core_dout[32*i +:32]), .dout_en(core_dout_en[i]),
			.dout_seq(core_dout_seq[i])
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
		unit_ctrl #( .N_CORES(N_CORES)
		) ctrl(
			.CLK(CLK), .PKT_COMM_CLK(PKT_COMM_CLK),
			// Unit Input
			.unit_in(unit_in), .unit_in_ctrl(unit_in_ctrl),
			.unit_in_wr_en(unit_in_wr_en),
			.unit_in_afull(unit_in_afull), .unit_in_ready(unit_in_ready),
			// Unit Output
			.dout(dout), .rd_en(rd_en), .empty(empty),
			// Cores
			.core_wr_en(core_wr_en), .core_start(core_start),
			.core_ready(core_ready),
			.core_din(core_din), .core_wr_addr(core_wr_addr),
			.core_blk_op(core_blk_op), .core_seq(core_seq),
			.core_set_input_ready(core_set_input_ready),
			.core_dout(core_dout), .core_dout_en(core_dout_en),
			.core_dout_seq(core_dout_seq),
			.err() // 5:0
		);

	end else begin // UNIT_IS_DUMMY

		(* KEEP_HIERARCHY="true" *)
		unit_ctrl_dummy #( .N_CORES(N_CORES)
		) ctrl(
			.CLK(CLK), .PKT_COMM_CLK(PKT_COMM_CLK),
			// Unit Input
			.unit_in(unit_in), .unit_in_ctrl(unit_in_ctrl),
			.unit_in_wr_en(unit_in_wr_en),
			.unit_in_afull(unit_in_afull), .unit_in_ready(unit_in_ready),
			// Unit Output
			.dout(dout), .rd_en(rd_en), .empty(empty),
			// Cores
			.core_wr_en(core_wr_en), .core_start(core_start),
			.core_ready(core_ready),
			.core_din(core_din), .core_wr_addr(core_wr_addr),
			.core_blk_op(core_blk_op), .core_seq(core_seq),
			.core_set_input_ready(core_set_input_ready),
			.core_dout(core_dout), .core_dout_en(core_dout_en),
			.core_dout_seq(core_dout_seq),
			.err() // 5:0
		);

	end

endmodule

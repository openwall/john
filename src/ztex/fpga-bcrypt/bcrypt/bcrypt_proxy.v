`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "bcrypt.vh"

// It happens that e.g. 20 cores are connected with 120 wires
// (except for those that used in broadcast mode).
// That results in difficulty in placement.
// Wires passing-by other cores disrupt timing.
//
// The purpose of the proxy module is that it has same interface
// as bcrypt_core. Typically 10-12 cores are behind each proxy, thus greatly
// reduces number of connections between arbiter and cores.
//
// Correction: after moving to 8-bit bus, proxy's interface
// became different from core's interface
//
module bcrypt_proxy #(
	parameter NUM_CORES = -1,
	parameter DUMMY = 0,
	parameter CORES_NOT_DUMMY = 0
	)(
	input CLK,
	input mode_cmp,

	// Packages of data from bcrypt_data via arbiter for cores
	input [7:0] din,
	input [1:0] ctrl,
	input wr_en,
	output init_ready, crypt_ready,

	// Output from cores
	input rd_en,
	output empty,
	output dout
	);

	genvar i;


	reg [NUM_CORES-1:0] wr_core_select = 0;
	wire [NUM_CORES:0] wr_core_select_in;
	assign wr_core_select_in[NUM_CORES] = 1'b0;

	generate
	for (i=0; i < NUM_CORES; i=i+1) begin:wr_core_select_gen

		// Select left (most-significant) core from the vector
		assign wr_core_select_in[i] =
			|wr_core_select_in[NUM_CORES : i+1] ? 1'b0 :
			core_crypt_ready[i] ? 1'b1 :
			1'b0;

	end
	endgenerate


	(* SHREG_EXTRACT="no" *) reg [NUM_CORES-1:0]
			core_init_ready = 0, core_crypt_ready = 0;

	(* SHREG_EXTRACT="no" *) reg [NUM_CORES-1:0] core_rd_en = 0,
			core_empty = {NUM_CORES{1'b1}}, core_dout = 0;


	// ******************************************************
	//
	// Input
	//
	// ******************************************************

	localparam STATE_IN_NONE = 0,
				STATE_IN_START = 1,
				STATE_IN_WAIT_END = 2,
				STATE_IN_END = 3;

	(* FSM_EXTRACT="true" *)
	reg [1:0] state_in = STATE_IN_NONE;

	always @(posedge CLK) begin
		case(state_in)
		STATE_IN_NONE: begin
			if (wr_en & ctrl == `CTRL_DATA_START) begin
				// Incoming data transfer.
				wr_core_select <= wr_core_select_in[NUM_CORES-1:0];
				state_in <= STATE_IN_START;
			end
			else if (wr_en & ctrl == `CTRL_INIT_START) begin
				// Initialization transfer.
				wr_core_select <= core_init_ready;
				state_in <= STATE_IN_START;
			end
		end

		STATE_IN_START:
			state_in <= STATE_IN_WAIT_END;

		STATE_IN_WAIT_END: if (ctrl == `CTRL_END) begin
			wr_core_select <= 0;
			state_in <= STATE_IN_END;
		end

		STATE_IN_END:
			state_in <= STATE_IN_NONE;

		endcase
	end

	assign crypt_ready = |core_crypt_ready;

	assign init_ready = |core_init_ready;


	// ******************************************************
	//
	// Cores
	//
	// ******************************************************
	generate
	for (i=0; i < NUM_CORES; i=i+1) begin:cores

		wire init_ready_in, crypt_ready_in, empty_in, dout_in;

		// Cores were originally designed for 32-bit input,
		// then input data width was reduced to 8-bit
		// to save routing resources
		reg [3:0] byte_wr_en_r = 4'b0001;
		always @(posedge CLK)
			if (state_in == STATE_IN_END)
				byte_wr_en_r <= 4'b0001;
			else if (wr_core_select[i])
				byte_wr_en_r <= { byte_wr_en_r[2:0], byte_wr_en_r[3] };

		if (~DUMMY | CORES_NOT_DUMMY[i]) begin

			(* KEEP_HIERARCHY="true" *)
			bcrypt_core core(
				.CLK(CLK), .mode_cmp(mode_cmp),
				.din(din),
				.start(wr_core_select[i] && state_in == STATE_IN_START),
				.byte_wr_en({ byte_wr_en_r[3:1], byte_wr_en_r[0] & wr_core_select[i] }),

				.init_ready(init_ready_in), .crypt_ready(crypt_ready_in),

				.rd_en(core_rd_en[i]),
				.empty(empty_in), .dout(dout_in)
			);

		// DUMMY proxy: all cores are dummy,
		// except for cores selected in CORES_NOT_DUMMY
		end else begin

			(* KEEP_HIERARCHY="true" *)
			bcrypt_core_dummy core(
				.CLK(CLK), .mode_cmp(mode_cmp),
				.din(din),
				.start(wr_core_select[i] && state_in == STATE_IN_START),
				.byte_wr_en({ byte_wr_en_r[3:1], byte_wr_en_r[0] & wr_core_select[i] }),

				.init_ready(init_ready_in), .crypt_ready(crypt_ready_in),

				.rd_en(core_rd_en[i]),
				.empty(empty_in), .dout(dout_in)
			);

		end

		always @(posedge CLK) begin
			core_init_ready[i] <= init_ready_in;
			core_crypt_ready[i] <= crypt_ready_in;
			core_empty[i] <= empty_in;
			core_dout[i] <= dout_in;
		end

	end
	endgenerate


	// ******************************************************
	//
	// Output
	//
	// ******************************************************
	(* EQUIVALENT_REGISTER_REMOVAL="no" *)
	reg [`MSB(NUM_CORES-1):0] rd_core_num = 0;

	localparam STATE_OUT_NONE = 0,
				STATE_OUT_EMPTY = 1,
				STATE_OUT_READ = 2;

	(* FSM_EXTRACT="true" *)
	reg [1:0] state_out = STATE_OUT_NONE;

	always @(posedge CLK) begin
		case(state_out)
		STATE_OUT_NONE: begin
			if (~core_empty[rd_core_num])
				state_out <= STATE_OUT_EMPTY;
			else if (rd_core_num == NUM_CORES-1)
				rd_core_num <= 0;
			else
				rd_core_num <= rd_core_num + 1'b1;
		end

		STATE_OUT_EMPTY: if (rd_en) begin
			core_rd_en[rd_core_num] <= 1;
			state_out <= STATE_OUT_READ;
		end

		STATE_OUT_READ: begin
			core_rd_en[rd_core_num] <= 0;
			if (delay_rd)
				state_out <= STATE_OUT_NONE;
		end
		endcase
	end

	assign empty = ~(state_out == STATE_OUT_EMPTY);

	assign dout = core_dout[rd_core_num];

	delay #(.NBITS(9)) delay_rd_inst(.CLK(CLK), .in(state_out == STATE_OUT_READ),
		.out(delay_rd) );

endmodule


module bcrypt_core_dummy (
	input CLK,
	input mode_cmp,
	input [3:0] byte_wr_en,
	input [7:0] din,
	input start,
	output init_ready, // Ready for initialization with P, MW, S data
	output crypt_ready, // Ready to get EK, salt etc.

	input rd_en,
	output empty,
	output dout
	);

	assign init_ready = 0;
	assign crypt_ready = 0;
	assign empty = 1;

	reg dout_r;
	assign dout = dout_r;

	always @(posedge CLK)
		dout_r <= mode_cmp ^ ^din ^ ^byte_wr_en ^ start ^ rd_en;

endmodule

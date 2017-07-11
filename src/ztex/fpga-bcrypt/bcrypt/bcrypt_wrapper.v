`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//
// 2 proxies are in each wrapper
//
module bcrypt_wrapper #(
	parameter NUM_PROXIES = 2,
	parameter [32*NUM_PROXIES-1 :0] PROXY_CONF = {
	// is_dummy |reserved |regs |num_cores
		1'b0, 19'b0, 4'd2, 8'd1,	// proxy #1: 2 regs, 1 cores
		1'b0, 19'b0, 4'd1, 8'd1		// proxy #0: 1 regs, 1 cores
	}
	)(
	input CLK,
	input mode_cmp,

	// Packages of data from bcrypt_data for cores
	input [7:0] din,
	input [1:0] ctrl,
	input [NUM_PROXIES-1:0] wr_en,
	output [NUM_PROXIES-1:0] init_ready, crypt_ready,

	// Output from cores
	input [NUM_PROXIES-1:0] rd_en,
	output [NUM_PROXIES-1:0] empty,
	output [NUM_PROXIES-1:0] dout
	);

	//
	// Signals in the direction to cores: 1 or 2 input registers
	//
	(* EQUIVALENT_REGISTER_REMOVAL="no",SHREG_EXTRACT="no" *)
	reg [7:0] din_r1, din_r2;
	(* EQUIVALENT_REGISTER_REMOVAL="no",SHREG_EXTRACT="no" *)
	reg [1:0] ctrl_r1 = 0, ctrl_r2 = 0;

	(* SHREG_EXTRACT="no" *)
	reg [NUM_PROXIES-1:0] wr_en_r1 = 0, wr_en_r2 = 0,
			rd_en_r1 = 0, rd_en_r2 = 0;

	always @(posedge CLK) begin
		if (wr_en) begin
			din_r1 <= din;
			ctrl_r1 <= ctrl;
		end
		wr_en_r1 <= wr_en;
		rd_en_r1 <= rd_en;

		if (wr_en_r1) begin
			din_r2 <= din_r1;
			ctrl_r2 <= ctrl_r1;
		end
		wr_en_r2 <= wr_en_r1;
		rd_en_r2 <= rd_en_r1;
	end


	//
	// Signals in the direction from cores to arbiter: 1 or 2 output registers
	//
	(* SHREG_EXTRACT="no" *) reg [NUM_PROXIES-1:0] init_ready_r1 = 0, init_ready_r2 = 0,
			crypt_ready_r1 = 0, crypt_ready_r2 = 0,
			empty_r1 = {NUM_PROXIES{1'b1}}, empty_r2 = {NUM_PROXIES{1'b1}},
			dout_r1 = 0, dout_r2 = 0;

	assign init_ready = init_ready_r1;
	assign crypt_ready = crypt_ready_r1;
	assign empty = empty_r1;
	assign dout = dout_r1;

	genvar i;
	generate
	for (i=0; i < NUM_PROXIES; i=i+1) begin:proxies

		localparam REGS = PROXY_CONF[32*i+11 -:4];
		localparam NUM_CORES = PROXY_CONF[32*i+7 -:8];
		localparam DUMMY = PROXY_CONF[32*i+31];

		bcrypt_proxy #(
			.NUM_CORES(NUM_CORES), .DUMMY(DUMMY),
			.CORES_NOT_DUMMY(PROXY_CONF[32*i+30 -:19])
		) proxy(
			.CLK(CLK), .mode_cmp(mode_cmp),

			.din(REGS==1 ? din_r1 : din_r2),
			.ctrl(REGS==1 ? ctrl_r1 : ctrl_r2),

			.wr_en(REGS==1 ? wr_en_r1[i] : wr_en_r2[i]),
			.rd_en(REGS==1 ? rd_en_r1[i] : rd_en_r2[i]),

			.init_ready(init_ready_in),
			.crypt_ready(crypt_ready_in),
			.empty(empty_in),
			.dout(dout_in)
		);

		always @(posedge CLK) begin
			init_ready_r1[i] <= REGS==1 ? init_ready_in : init_ready_r2[i];
			crypt_ready_r1[i] <= REGS==1 ? crypt_ready_in : crypt_ready_r2[i];
			empty_r1[i] <= REGS==1 ? empty_in : empty_r2[i];
			dout_r1[i] <= REGS==1 ? dout_in : dout_r2[i];

			if (REGS==2) begin
				init_ready_r2[i] <= init_ready_in;
				crypt_ready_r2[i] <= crypt_ready_in;
				empty_r2[i] <= empty_in;
				dout_r2[i] <= dout_in;
			end
		end

	end
	endgenerate

endmodule


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


module memory #(
	parameter N_CORES = `N_CORES,
	parameter N_THREADS = `N_THREADS,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,

	// *** Computation data set #2 ***
	input [N_THREADS_MSB :0] comp_data2_thread_num,
	input comp_data2_wr_en,
	input [`COMP_DATA2_MSB :0] comp_wr_data2,

	// Write
	input [32*N_CORES-1 :0] core_din,
	input [N_CORES-1 :0] core_dout_en,
	input [N_CORES-1 :0] core_dout_seq_num, core_dout_ctx_num,

	input [31:0] ext_din,
	input [`MEM_TOTAL_MSB :0] ext_wr_addr,
	input ext_wr_en,
	output reg ext_full = 0,

	// Thread State
	output [N_THREADS_MSB :0] ts_num,
	output reg ts_wr_en = 0,
	output [`THREAD_STATE_MSB :0] ts_wr,

	// Read
	input rd_en_procb, rd_cpu_request,
	input [`MEM_TOTAL_MSB :0] rd_addr_procb, rd_addr_cpu,
	output reg [31:0] dout,
	output reg rd_cpu_valid = 0,

	output reg err = 0
	);


	// =================================================================
	//
	integer k;
	
	reg [31:0] mem [0: 2**(`MEM_TOTAL_MSB+1)-1];
	initial begin
`ifdef SIMULATION
		// For simulation with engine_test.v, memory for thread #0
		// contains key and salt from the 1st element from
		// the reference implementation.
		mem[0] = 32'h746c6173; // salt
		mem[1] = 32'h69727473; // stri
		mem[2] = 32'h0000676e; // ng
		mem[3] = 32'h6c6c6548; // Hell
		mem[4] = 32'h6f77206f; // o wo
		mem[5] = 32'h21646c72; // rld!
`endif
	end


	// =================================================================
	// *** Input core selection ***
	//
	wire [`MSB(N_CORES-1):0] core_num;
	encoder4 #( .N_CORES(N_CORES)
	) encoder( .in(core_dout_en), .out(core_num) );

	reg [2:0] cnt = 0;
	reg [`MSB(N_CORES-1):0] core_num_r;
	reg seq_num_r, ctx_num_r;

	localparam STATE_NONE = 0,
				STATE_WR1 = 1,
				STATE_WR2 = 2;

	(* FSM_EXTRACT="true" *)
	reg [1:0] state = STATE_NONE;

	always @(posedge CLK) begin
		case(state)
		STATE_NONE: if (|core_dout_en) begin
			core_num_r <= core_num;
			seq_num_r <= core_dout_seq_num [core_num];
			ctx_num_r <= core_dout_ctx_num [core_num];
			state <= STATE_WR1;
		end

		// Actual data is 1 cycle behind 'core_dout_en';
		// 'core_dout_en' doesn't assert every cycle
		STATE_WR1: begin
			cnt <= cnt - 1'b1;
			if (cnt == 1)
				state <= STATE_NONE;
			else if ( ~(|core_dout_en) )
				state <= STATE_WR2;
		end
		
		STATE_WR2: if (|core_dout_en)
			state <= STATE_WR1;
		endcase
	end

	// Update thread_state
	assign ts_num = {core_num_r, ctx_num_r, seq_num_r};
	assign ts_wr = `THREAD_STATE_WR_RDY;
	always @(posedge CLK)
		if (ts_wr_en)
			ts_wr_en <= 0;
		else if (cnt == 1)
			ts_wr_en <= 1;

	// FULL flag for external input
	always @(posedge CLK)
		ext_full <= |core_dout_en;



	// =================================================================
	// *** Computation data (set #2) ***
	//
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [`COMP_DATA2_MSB :0] comp_data2 [0: N_THREADS-1];
	always @(posedge CLK)
		if (comp_data2_wr_en)
			comp_data2 [comp_data2_thread_num] <= comp_wr_data2;

	reg [`MEM_ADDR_MSB :0] comp_save_addr;
	reg [3:0] comp_save_len;
	always @(posedge CLK)
		if (state != STATE_NONE)
			{ comp_save_addr, comp_save_len }
				<= comp_data2 [ {core_num_r, ctx_num_r, seq_num_r} ];


	// =================================================================
	// *** Write ***
	//
	reg [31:0] input_r;
	reg [`MEM_TOTAL_MSB :0] ext_wr_addr_r;
	reg wr_en_r = 0, ext_wr_en_r = 0;

	if (N_CORES == 3) begin

		// Optimization for N_CORES=3 (saves 15 LUT)
		wire [32 + 32*N_CORES-1 :0] input_mux = {ext_din, core_din};
		(* KEEP="true" *) wire [1:0] input_mux_addr = ext_wr_en
			? 2'b11 : core_num_r;
		wire input_r_wr_en = ext_wr_en | state == STATE_WR1;

		always @(posedge CLK)
			if (input_r_wr_en) begin
				input_r <= input_mux [32*input_mux_addr +:32];
				wr_en_r <= 1;
			end
			else
				wr_en_r <= 0;

	end else begin // N_CORES != 3

		always @(posedge CLK)
			if (ext_wr_en) begin
				wr_en_r <= 1;
				input_r <= ext_din;
			end
			else if (state == STATE_WR1) begin
				wr_en_r <= 1;
				input_r <= core_din [32*core_num_r +:32];
			end
			else
				wr_en_r <= 0;

	end // N_CORES


	always @(posedge CLK) begin
		ext_wr_en_r <= ext_wr_en;
		if (ext_wr_en)
			ext_wr_addr_r <= ext_wr_addr;
	end

	wire [`MEM_ADDR_MSB :0] wr_addr_local = comp_save_addr + cnt;
	wire [`MEM_TOTAL_MSB :0] wr_addr
		= {core_num_r, ctx_num_r, seq_num_r, wr_addr_local};

	always @(posedge CLK)
		if (ext_wr_en_r | wr_en_r & ({1'b0, cnt}) < comp_save_len)
			mem [ext_wr_en_r ? ext_wr_addr_r : wr_addr] <= input_r;


	// =================================================================
	// *** Read ***
	//
	wire rd_en = rd_en_procb | (rd_cpu_request & ~rd_cpu_valid);

	wire [`MEM_TOTAL_MSB :0] rd_addr =
		rd_en_procb ? rd_addr_procb : rd_addr_cpu;

	always @(posedge CLK)
		if (rd_en)
			dout <= mem [rd_addr];

	always @(posedge CLK) begin
		if (rd_cpu_valid)
			rd_cpu_valid <= 0;
		else if (rd_cpu_request & ~rd_en_procb)
			rd_cpu_valid <= 1;
	end

endmodule


module encoder4 #(
	parameter N_CORES = 4
	)(
	input [N_CORES-1 :0] in,
	output [1:0] out
	);

	assign out =
		in[0] ? 2'b00 :
		//in[1] & N_CORES > 1 ? 2'b01 : // generates out-of-bound warnings
		in[N_CORES > 1 ? 1 :0] & N_CORES > 1 ? 2'b01 :
		in[N_CORES > 2 ? 2 :0] & N_CORES > 2 ? 2'b10 :
		in[N_CORES > 3 ? 3 :0] & N_CORES > 3 ? 2'b11 : 2'b00;

endmodule


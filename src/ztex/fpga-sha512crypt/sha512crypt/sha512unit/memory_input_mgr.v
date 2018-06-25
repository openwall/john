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

//                +---------+
//     core #0    |         |
//  ------------> |         |   memory
//     core #1    | memory  |   input
//  ------------> | input   |----------->
//      .         | manager |
//      .         | (32-bit)|
//      .         |         |
//     core #N    |         |
//  ------------> |         |
//                |         |     +--------+
//                |         |---> | thread |
// +--------+     |         |     | state  |
// | comp.  |---> |         |     +--------+
// | buffer |     |         |    (sets WR_RDY)
// +--------+     +---------+
// (contains           ^ 
// save_addr,          | external
// save_len)           | input
//
//
module memory_input_mgr #(
	parameter N_CORES = 4,
	parameter N_CORES_MSB = `MSB(N_CORES),
	parameter N_THREADS = 4 * N_CORES,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,
	// Output from cores
	input [32*N_CORES-1 :0] core_out,
	input [N_CORES-1 :0] core_out_ready, core_out_start,
	input [N_CORES-1 :0] core_out_ctx_num, core_out_seq_num,
	output reg [N_CORES-1 :0] core_rd_en = 0,
	// computation data #2
	output [N_THREADS_MSB :0] comp_data2_thread_num,
	input [`COMP_DATA2_MSB :0] comp_data2,
	// Thread State
	output [N_THREADS_MSB :0] ts_num,
	output reg ts_wr_en = 0,
	output [`THREAD_STATE_MSB :0] ts_wr,
	// External input
	input [31:0] ext_din,
	input [`MEM_TOTAL_MSB+1 :0] ext_wr_addr, //+1 bit for 32-bit input
	input ext_wr_en,
	output ext_full,
	// Memory
	output reg [31:0] dout,
	output [`MEM_TOTAL_MSB+1 :0] mem_wr_addr, //+1 bit for 32-bit input
	output reg mem_wr_en = 0
	);


	wire [1:0] core_num;
	encoder4 #( .N_CORES(N_CORES)
	) encoder( .in(core_out_ready), .out(core_num) );
	

	reg [1:0] core_num_r = 0, core_num_rd = 0;
	reg [3:0] cnt = 0;
	reg output_going = 0, output_skip = 0;

	reg [N_THREADS_MSB :0] thread_num, wr_thread_num;
	reg [`MEM_ADDR_MSB+1 :0] wr_addr;
	assign mem_wr_addr = { wr_thread_num, wr_addr };

	wire [`MEM_ADDR_MSB :0] comp_save_addr;
	wire [3:0] comp_save_len;
	assign { comp_save_addr, comp_save_len } = comp_data2;
	// Output from a core is performed in reverse order (bits 448-511 first)
	wire [`MEM_ADDR_MSB :0] end_addr = comp_save_addr + 4'd8;
	reg [`MEM_ADDR_MSB :0] end_save_addr;

	assign comp_data2_thread_num = thread_num;


	localparam STATE_NONE = 0,
				STATE_PREPARE_OUTPUT1 = 1,
				STATE_PREPARE_OUTPUT2 = 2,
				STATE_PREPARE_OUTPUT3 = 3,
				STATE_PREPARE_OUTPUT4 = 4;
				
	(* FSM_EXTRACT="true", FSM_ENCODING="one-hot" *)
	reg [2:0] state = STATE_NONE;

	always @(posedge CLK) begin
		if (ts_wr_en)
			ts_wr_en <= 0;

		if (~output_going) begin
			//cnt <= 0;
			if (ext_wr_en & ~ext_full) begin
				mem_wr_en <= 1;
				{ wr_thread_num, wr_addr } <= ext_wr_addr;
				dout <= ext_din;
			end
			else
				mem_wr_en <= 0;
		end
		else if (output_going) begin
			dout <= core_out [32*core_num_rd +:32];
			mem_wr_en <= ~output_skip;

			wr_addr <= wr_addr - 1'b1;
			if (wr_addr == { end_save_addr, 1'b1 })
				output_skip <= 0;

			cnt <= cnt + 1'b1;
			
			if (cnt == 14)
				ts_wr_en <= 1;
				
			if (cnt == 15)
				output_going <= 0;
		end
		

		case(state)
		STATE_NONE: if (|core_out_ready) begin
			core_num_r <= core_num;
			state <= STATE_PREPARE_OUTPUT1;
		end
		
		STATE_PREPARE_OUTPUT1: begin
			thread_num <= { core_num_r,
				core_out_ctx_num [core_num_r],
				core_out_seq_num [core_num_r]
			};

			//
			// Using: core_output_buf_bram
			// core_rd_en to core_out_start delay: 2 cycles
			// core_out_start to 1st data word delay: 1 cycle
			//
			if (cnt == 0 | cnt > 12) begin
				core_rd_en [core_num_r] <= 1;
				state <= STATE_PREPARE_OUTPUT2;
			end
		end
		
		STATE_PREPARE_OUTPUT2: begin
			core_rd_en [core_num_r] <= 0;
			state <= STATE_PREPARE_OUTPUT3;
		end
		
		STATE_PREPARE_OUTPUT3:
			state <= STATE_PREPARE_OUTPUT4;
				
		STATE_PREPARE_OUTPUT4: begin
			core_num_rd <= core_num_r;
			wr_thread_num <= thread_num;
			wr_addr <= { end_addr, 1'b0 }; // comp_data2 is available
			end_save_addr <= comp_save_addr + comp_save_len;
			output_skip <= comp_save_len < 8; // skip some if save_len < 8
			
			if (core_out_start [core_num_r]) begin
				output_going <= 1;
				state <= STATE_NONE;
			end
		end
		endcase
	end
	
	assign ts_num = wr_thread_num;
	assign ts_wr = `THREAD_STATE_WR_RDY;

	assign ext_full = output_going | state == STATE_PREPARE_OUTPUT4;
	
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

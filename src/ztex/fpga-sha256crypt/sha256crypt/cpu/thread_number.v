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


module thread_number #(
	parameter N_CORES = -1,
	parameter N_THREADS = -1,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,
	input entry_pt_switch,
	
	output [N_THREADS_MSB :0] ts_rd_num,
	input [`THREAD_STATE_MSB :0] ts_rd,
	
	input NEXT_THREAD,
	output RELOAD,

	output reg [`MSB(N_THREADS-1) :0] thread_num = 0, thread_num_ahead = 1,
	output reg thread_init = 1
	);

	reg suspended_r = 1;

	// Next thread (in sequence)
	wire [`MSB(N_THREADS-1) :0] thread_num_next;
	next_thread_num #( .N_CORES(N_CORES), .N_THREADS(N_THREADS)
	) next_thread_num( .in(thread_num), .out(thread_num_next) );

	
	// Look ahead for WR_RDY thread 
	assign ts_rd_num = thread_num_ahead;
	wire thread_ahead_not_ready = ts_rd != `THREAD_STATE_WR_RDY;
	
	wire [`MSB(N_THREADS-1) :0] thread_num_ahead_next;
	next_thread_num #( .N_CORES(N_CORES), .N_THREADS(N_THREADS)
	) next_thread_num_ahead( .in(thread_num_ahead), .out(thread_num_ahead_next) );


	// Allow to select the same thread after thread_state propagates
	localparam TS_DELAY = 2;
	reg [TS_DELAY-1:0] allow_same_thread = {TS_DELAY{1'b0}};
	always @(posedge CLK)
		allow_same_thread <= { allow_same_thread[TS_DELAY-2:0], suspended_r };

	task thread_num_ahead_next_set;
		begin
			thread_num_ahead <= (thread_num_ahead_next == thread_num
					& ~allow_same_thread[TS_DELAY-1])
				? thread_num_next : thread_num_ahead_next;
		end
	endtask
	

	always @(posedge CLK) begin
		if (entry_pt_switch)
			thread_init <= 1;
		
		if (thread_init) begin // traverse all threads on init
			thread_num <= thread_num_next;
			if (thread_num == N_THREADS-1)
				thread_init <= 0;
		end
		else begin
			if (suspended_r & ~thread_ahead_not_ready) begin
				suspended_r <= 0;
				thread_num <= thread_num_ahead;
				thread_num_ahead_next_set();
			end
			
			else if (NEXT_THREAD) begin
				if (thread_ahead_not_ready) begin
					suspended_r <= 1;
				end
				else begin
					thread_num <= thread_num_ahead;
					thread_num_ahead_next_set();
				end
			end

			else begin
				if (thread_ahead_not_ready)
					thread_num_ahead_next_set();
			end
		end
	end

	assign RELOAD = ~thread_init & (
		suspended_r & ~thread_ahead_not_ready
		| NEXT_THREAD & ~thread_ahead_not_ready
	);


`ifdef SIMULATION
	reg [31:0] X_CYCLES_TOTAL = 0;
	reg [31:0] X_CYCLES_SUSPENDED = 0;
	
	always @(posedge CLK) begin
		X_CYCLES_TOTAL <= X_CYCLES_TOTAL + 1'b1;
		if (suspended_r)
			X_CYCLES_SUSPENDED <= X_CYCLES_SUSPENDED + 1'b1;
	end
`endif

endmodule

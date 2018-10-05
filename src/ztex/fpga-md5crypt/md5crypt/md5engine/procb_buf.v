`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../md5.vh"


//
// process_bytes (procb) records (several elements per thread)
//
// The task for an engine is to accumulate a sequence of
// procb elements for each thread
// so formation of SHA data blocks goes w/o interruption.
//
// Read-ahead buffer.
//
module procb_buf #(
	parameter N_THREADS = 6,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,

	input [N_THREADS_MSB :0] wr_thread_num,
	input wr_en,
	input [`PROCB_D_WIDTH-1 :0] din,
	// Number of procb records currently in the buffer
	output reg [`PROCB_A_WIDTH-1 :0] wr_cnt = 0,
	output reg err = 0,

	input [N_THREADS_MSB :0] rd_thread_num,
	input rd_en, rd_rst, lookup_en,
	output aempty, lookup_empty,
	output [`PROCB_D_WIDTH-1 :0] dout
	);

	(* RAM_STYLE="DISTRIBUTED" *)
	reg [`PROCB_D_WIDTH-1 :0] mem [0: `PROCB_N_RECORDS*N_THREADS-1];

	(* RAM_STYLE="DISTRIBUTED" *)
	reg [`PROCB_A_WIDTH-1 :0] wr_addr_mem [0 :N_THREADS-1],
		rd_addr_mem [0 :N_THREADS-1];

	reg [`PROCB_A_WIDTH-1 :0] wr_addr_rd = 0, rd_addr = 0;


	// *****************************************************************
	//
	//      Read procb records
	//
	// - 1st Word Fall-Through
	// - Data appears on output on the next cycle after changing rd_thread_num.
	// - After read is complete, read pointer resets. Reader is expected
	//   to set thread_status or take other measures to evade
	//   more reads from itself.
	//
	// - Read-ahead operation. Read-ahead pointer resets to actually
	// read values after rd_thread changes.
	//
	// *****************************************************************

	assign dout = mem [{ rd_thread_num, lookup_addr[`PROCB_A_WIDTH-2 :0] }];

	reg [N_THREADS_MSB :0] rd_thread_prev = 0;
	always @(posedge CLK)
		rd_thread_prev <= rd_thread_num;

	reg [`PROCB_A_WIDTH-1 :0] lookup_addr = 0;

	always @(posedge CLK) begin
		wr_addr_rd <= wr_addr_mem [rd_thread_num];

		rd_addr <= rd_en ? rd_addr + 1'b1 : rd_addr_mem [rd_thread_num];

		if (rd_en)
			rd_addr_mem [rd_thread_num]
				<= (aempty | empty | rd_rst) ? {`PROCB_A_WIDTH{1'b0}} : rd_addr + 1'b1;

		// lookup (read-ahead)
		if (rd_thread_prev != rd_thread_num)
			lookup_addr <= rd_addr_mem [rd_thread_num];

		// lookup addr resets after read thread change
		// or on write
		if (wr_en & wr_thread_num == rd_thread_num) begin
			lookup_addr <= 0;
		end

		if (lookup_en)
			lookup_addr <= lookup_addr + 1'b1;

	end

	assign empty = wr_addr_rd == rd_addr;

	assign aempty = wr_addr_rd == rd_addr + 1'b1; // opt!

	//assign lookup_aempty = wr_addr_rd == lookup_addr + 1'b1;

	assign lookup_empty = wr_addr_rd == lookup_addr | wr_addr_rd == 0;


	// *****************************************************************
	//
	//   Write procb records - new approach
	//   (more CPU friendly interface)
	//
	// 1. Writer is expected to read wr_cnt (count of procb records
	//    currently in the buffer), write until finish/stop record
	//    or until `PROCB_N_RECORDS.
	// 2. Reader resets wr_cnt on startup and after read is complete.
	//
	// *****************************************************************
	reg [N_THREADS_MSB :0] wr_rst_thread_num;
	reg wr_rst_en = 0;

	wire wr_rst_enqueue = rd_en & (aempty | rd_rst);

	always @(posedge CLK) begin
		if (wr_rst_enqueue) begin
			wr_rst_en <= 1; // enqueued reset of wr_cnt
			wr_rst_thread_num <= rd_thread_num;
		end

		wr_cnt <= wr_addr_mem [wr_thread_num];

		if (wr_en | wr_rst_en) begin
			if (~wr_en & ~wr_rst_enqueue)
				wr_rst_en <= 0;

			wr_addr_mem [wr_en ? wr_thread_num : wr_rst_thread_num]
				<= wr_en ? wr_cnt + 1'b1 : {`PROCB_A_WIDTH{1'b0}};
		end

		if (wr_en & wr_rst_en & wr_rst_enqueue)
			err <= 1;

		if (wr_en) begin
			mem [{ wr_thread_num, wr_cnt[`PROCB_A_WIDTH-2 :0] }] <= din;
			wr_cnt <= wr_cnt + 1'b1;
		end
	end


endmodule

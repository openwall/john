`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//
//  *** OUTDATED ! ***
//

`include "../sha256.vh"

module sha256engine_test();

	integer k;

	reg CLK = 0; // Each cycle is 20ns

	localparam N_CORES = 3;
	localparam N_THREADS_MSB = 2;

	// procb
	reg [N_THREADS_MSB:0] procb_wr_thread_num = 0;
	reg procb_wr_en = 0;
	reg [`PROCB_D_WIDTH-1 :0] procb_wr_data = 0;
	reg comp_data1_wr_en = 0;
	reg [`COMP_DATA1_MSB :0] comp_wr_data1 = 0;
	// thread_state
	reg [N_THREADS_MSB :0] ts_wr_num1 = 0, ts_rd_num1 = 0;
	reg [`THREAD_STATE_MSB :0] ts_wr1 = 0;
	reg ts_wr_en1 = 0;
	// memory
	reg comp_data2_wr_en = 0;
	reg [`COMP_DATA2_MSB :0] comp_wr_data2 = 0;

	wire [`PROCB_A_WIDTH-1 :0] procb_wr_cnt;
	wire [`THREAD_STATE_MSB :0] ts_rd1;


	initial begin
		#1000;
		//
		// Doing the 1st block from the reference implementation:
		// "Hello world!" | "saltstring" | "Hello world!"
		// Using thread #0.
		//
		comp_data1_wr_en <= 1; comp_data2_wr_en <= 1;
		comp_wr_data1 <= 5'b10000; // new context, load/save slot #0
		comp_wr_data2 <= { 5'd24, 4'd8 }; // save_addr=24, save_len=8
		#20;
		comp_data1_wr_en <= 0; comp_data2_wr_en <= 0;
		
		procb_wr_en <= 1;
		// Expecting MEM_ADDR_MSB=4, PROCB_CNT_MSB=5
		procb_wr_data <= { 5'd3, 6'd12, 2'b00 }; #20;
		procb_wr_data <= { 5'd0, 6'd10, 2'b00 }; #20;
		procb_wr_data <= { 5'd3, 6'd12, 2'b10 }; #20;
		procb_wr_en <= 0;
		
		ts_wr_num1 <= 0; ts_wr1 <= `THREAD_STATE_RD_RDY; ts_wr_en1 <= 1; #20;
		ts_wr_en1 <= 0;
		#80;
		while (ts_rd1 != `THREAD_STATE_WR_RDY) #20;

		//
		// Result appears in rows 24-31.
		//
		// Performing the 2nd computation (3 blocks):
		// "Hello world!" | "saltstring" | result(first 12 bytes)
		// | "Hello world!" | "Hello world!"
		// | result(32 bytes) | result(32 bytes)
		//
		// The outcome would be
		// "unsigned char alt_result[32]", "Create intermediate result"
		// in reference implementation
		//
		comp_data1_wr_en <= 1; comp_data2_wr_en <= 1;
		comp_wr_data1 <= 5'b10000; // new context, load/save slot #0
		comp_wr_data2 <= { 5'd8, 4'd8 }; // save_addr=8, save_len=8
		#20;
		comp_data1_wr_en <= 0; comp_data2_wr_en <= 0;
		
		procb_wr_en <= 1;
		procb_wr_data <= { 5'd3, 6'd12, 2'b00 }; #20;
		procb_wr_data <= { 5'd0, 6'd10, 2'b00 }; #20;
		procb_wr_data <= { 5'd24, 6'd12, 2'b00 }; #20;
		procb_wr_data <= { 5'd3, 6'd12, 2'b00 }; #20;
		procb_wr_en <= 0;
		// procb_buf has 4 elements/thread. CPU would check 'procb_wr_cnt'.

		ts_wr_num1 <= 0; ts_wr1 <= `THREAD_STATE_RD_RDY; ts_wr_en1 <= 1; #20;
		ts_wr_en1 <= 0;
		#80;
		while (ts_rd1 != `THREAD_STATE_WR_RDY) #20;

		// Ready for the next 4 procb elements.
		procb_wr_en <= 1;
		procb_wr_data <= { 5'd3, 6'd12, 2'b00 }; #20;
		procb_wr_data <= { 5'd24, 6'd32, 2'b00 }; #20;
		procb_wr_data <= { 5'd24, 6'd32, 2'b10 }; #20; // finish_ctx flag
		procb_wr_en <= 0;

		ts_wr_num1 <= 0; ts_wr1 <= `THREAD_STATE_RD_RDY; ts_wr_en1 <= 1; #20;
		ts_wr_en1 <= 0;
		#80;
		while (ts_rd1 != `THREAD_STATE_WR_RDY) #20;
		
		// Result appears in rows 8-15:
		// [8] f5697bf1
		// ...
		// [15] d5e5a8b4
		#20;
	end



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

	sha256core core(
		.CLK(CLK),

		.start(core_start[i]), .ready(core_ready[i]),

		.wr_en(core_wr_en[i]), .in(core_din), .wr_addr(core_wr_addr),
		.input_blk_op(core_blk_op),
		.input_seq(core_seq), .set_input_ready(core_set_input_ready),

		.dout(core_dout[32*i +:32]), .dout_en(core_dout_en[i]),
		.dout_seq(core_dout_seq[i])
	);

	end
	endgenerate


	// **********************************************************
	//
	//   ENGINE
	//
	// **********************************************************

	engine engine(
		.CLK(CLK),
		// procb_buf
		.procb_wr_thread_num(procb_wr_thread_num), .procb_wr_en(procb_wr_en),
		.procb_wr_data(procb_wr_data), .procb_wr_cnt(procb_wr_cnt),
		.comp_data1_wr_en(comp_data1_wr_en), .comp_wr_data1(comp_wr_data1),
		// thread_state
		.ts_wr_num1(ts_wr_num1), .ts_rd_num1(ts_rd_num1),
		.ts_wr1(ts_wr1), .ts_wr_en1(ts_wr_en1), .ts_rd1(ts_rd1),
		// memory
		.comp_data2_wr_en(comp_data2_wr_en), .comp_wr_data2(comp_wr_data2),
		// cores
		.core_wr_en(core_wr_en), .core_start(core_start),
		.core_ready(core_ready),
		.core_din(core_din), .core_wr_addr(core_wr_addr),
		.core_blk_op(core_blk_op), .core_seq(core_seq),
		.core_set_input_ready(core_set_input_ready),
		.core_dout(core_dout), .core_dout_en(core_dout_en),
		.core_dout_seq(core_dout_seq)
	);



	initial begin
		#5;
		while(1) begin
			CLK <= ~CLK; #10;
		end
	end

endmodule

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

// ***********************************************************
//
// Test "engine" (memory & various glue logic) without a CPU.
//
// ***********************************************************
module md5engine_test();

	integer k;

	reg CLK = 0; // Each cycle is 20ns

	localparam N_CORES = 3;
	localparam N_THREADS_MSB = `MSB(4*N_CORES-1);

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
		// Doing the 1st block from:
		// crypt_md5("abc","12345678");
		// Using thread #0.
		//
		comp_data1_wr_en <= 1; comp_data2_wr_en <= 1;
		comp_wr_data1 <= 1'b1; // new context
		comp_wr_data2 <= { 5'd24, 3'd4 }; // save_addr=24, save_len=4
		#20;
		comp_data1_wr_en <= 0; comp_data2_wr_en <= 0;

		procb_wr_en <= 1;
		// Expecting MEM_ADDR_MSB=4, PROCB_CNT_MSB=5
		procb_wr_data <= { 5'd3, 6'd3, 1'b0 }; #20;
		procb_wr_data <= { 5'd0, 6'd8, 1'b0 }; #20;
		procb_wr_data <= { 5'd3, 6'd3, 1'b1 }; #20;
		procb_wr_en <= 0;

		ts_wr_num1 <= 0; ts_wr1 <= `THREAD_STATE_RD_RDY; ts_wr_en1 <= 1; #20;
		ts_wr_en1 <= 0;
		#80;
		while (ts_rd1 != `THREAD_STATE_WR_RDY) #20;
		#20;
		//
		// Result appears in rows 24-27 of "main" memory.
		// 219e4d5d 84fa9aef 1a6d87e1 ffaf0a38
		//

		#20;
	end



	genvar i;
	// **********************************************************
	//
	//   CORES
	//
	// **********************************************************
	wire [N_CORES-1:0] core_wr_en, core_start, core_seq_num;
	wire core_ctx_num;
	wire [4*N_CORES-1:0] core_ready;
	wire [31:0] core_din;
	wire [3:0] core_wr_addr;
	wire [`BLK_OP_MSB:0] core_blk_op;
	wire core_input_ctx, core_input_seq, core_set_input_ready;
	
	wire [N_CORES-1:0] core_dout_en, core_dout_seq_num;
	wire [32*N_CORES-1 :0] core_dout;

	generate
	for (i=0; i < N_CORES; i=i+1) begin:cores

		md5core core(
			.CLK(CLK),
			.start(core_start[i]), .ctx_num(core_ctx_num),
			.seq_num(core_seq_num[i]), .ready(core_ready[4*i +:4]),
			.wr_en(core_wr_en[i]), .din(core_din), .wr_addr(core_wr_addr),
			.input_blk_op(core_blk_op), .input_seq(core_input_seq),
			.input_ctx(core_input_ctx), .set_input_ready(core_set_input_ready),

			.dout(core_dout[32*i +:32]), .dout_en(core_dout_en[i]),
			.dout_seq_num(core_dout_seq_num[i])
		);

	end
	endgenerate


	// **********************************************************
	//
	//   ENGINE
	//
	// **********************************************************

	engine #( .N_CORES(N_CORES) ) engine(
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
		.ext_wr_en(1'b0), .mem_rd_cpu_request(1'b0),
		// cores
		.core_wr_en(core_wr_en), .core_ready(core_ready), .core_din(core_din),
		.core_wr_addr(core_wr_addr), .core_blk_op(core_blk_op),
		.core_input_seq(core_input_seq), .core_input_ctx(core_input_ctx), 
		.core_set_input_ready(core_set_input_ready),
		.core_dout(core_dout), .core_dout_en(core_dout_en),
		.core_dout_seq_num(core_dout_seq_num)
	);

	core_ctrl #( .N_CORES(N_CORES) ) core_ctrl(
		.CLK(CLK), .core_start(core_start),
		.ctx_num(core_ctx_num), .seq_num(core_seq_num)
	);


	initial begin
		#5;
		while(1) begin
			CLK <= ~CLK; #10;
		end
	end

endmodule

`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module bcrypt_test();

	reg READ_ALL_FROM_OUTPUT_FIFO = 0;

	genvar i;
	integer k, k1, k2;


	initial begin
		// *****************************************************************
		//
		// Send data packets exactly as they arrive from USB controller.
		//
		// Output packets appear in output_fifo.fifo_output0.ram
		// exactly as before they leave FPGA.
		// On errors it sets pkt_comm_status and app_status available
		// via low-speed interface.
		//
		// It has no internal check for the count of rounds.
		//
		// *****************************************************************
		#1000;
		
		// *****************************************************************
		//
		// Test #1.
		//
		//	{"$2a$00$////////..............XiwFBK8OLIKiLUZR11iwkDeHZvypH9y",
		//		"abcde"},
		//
		// Hash (network byte order, 0 to 23):
		// 0c 87 4c 66 a3 34 90 cf d3 66 35 24 98 32 79 df 1d 6f 09 58 ca fd 27 2b
		//
		// *****************************************************************
		
		// Usage: cmp_config_create(cnt,salt_len,"salt");
		// Note: in bcrypt, salt is not sent in ASCII but encoded.
		//
		bcrypt_cmp_config_create(32,{8'h04, 8'h41, 8'h10, 8'h04,
			8'h00, 8'h00, 8'h41, 8'h10, {8{8'h00}} });
		cmp_config_add_hash(32'h_664c_870c);
		send_bcrypt_cmp_config();
		
		send_empty_word_gen(16'h1234);
/*
		word_list_add("keylen7");
		word_list_add("mypwd123");
		word_list_add("mypwd1234");
		word_list_add("mypwd12345");
		word_list_add("pass_len_is15..");

		for (k=0; k < 30; k=k+1)
			word_list_add("11111110-b");

		word_list_add("11111111");
		word_list_add("11111101");
		word_list_add("11111011");
*/
		word_list_add("abcde");

		send_word_list();

	end

		// *****************************************************************
		//
		// Test #2.
		//
		//	{"$2a$01$////////..............fgo7Kiqupvy1qW.K1sadl0ELN2AVYb.",
		//		"aaa"},
		//
		// *****************************************************************


	// ******************************************************************
	//
	// Simulating input from USB controller over high-speed interface
	//
	// ******************************************************************
	reg CORE_CLK = 0, IFCLK = 0;

	reg [7:0] din;
	reg wr_en = 0;

`include "../pkt_comm/pkt_comm_test_helper.vh"

	wire [7:0] app_mode = 0;

	wire [7:0] input_dout;

	fifo_sync_small #( .D_WIDTH(8), .A_WIDTH(15)
	) fifo_sync_small_in(
		.CLK(CORE_CLK),
		.din(din), .wr_en(wr_en), .full(),
		.dout(input_dout), .rd_en(hs_input_rd_en), .empty(hs_input_empty)
	);

	reg [15:0] hs_input_din;
	reg [1:0] state = 0;

	always @(posedge CORE_CLK) begin
		case(state)
		0: if (~hs_input_empty) begin
			hs_input_din[7:0] <= input_dout;
			state <= 1;
		end
		1: if (~hs_input_empty) begin
			hs_input_din[15:8] <= input_dout;
			state <= 2;
		end
		2: if (~hs_input_almost_full)
			state <= 0;
		endcase
	end

	assign hs_input_rd_en = ~hs_input_empty & (state == 0 || state == 1);
	assign hs_input_wr_en = ~hs_input_almost_full & state == 2;
	//
	// End simulation input from USB controller


	localparam NUM_PROXIES = 2;

	localparam NUM_WRAPPERS = 1;

	localparam [32*NUM_WRAPPERS-1 :0] WRAPPERS_CONF = {
	// is_dummy |reserved |start_proxy_num |end_proxy_num
		1'b0, 15'b0, 8'd2, 8'd3,	// wrapper #1: proxies 2-3
		1'b0, 15'b0, 8'd0, 8'd1 	// wrapper #0: proxies 0-1
	};

	parameter [32*NUM_PROXIES-1 :0] PROXY_CONF = {
	// is_dummy |reserved |regs |num_cores
		1'b0, 19'b0, 4'd2, 8'd1,	// proxy #3: 2 regs, 1 cores
		1'b0, 19'b0, 4'd1, 8'd1,	// proxy #2: 1 regs, 1 cores
		1'b0, 19'b0, 4'd2, 8'd1,//9,	// proxy #1 (0_1): 2 regs, 9 cores
		1'b0, 19'b0, 4'd1, 8'd1//10	// proxy #0 (0_0): 1 regs, 10 cores
	};


	// ********************************************************
	//
	// bcrypt application
	// 8-bit input, 16-bit output
	//
	// ********************************************************
	wire [7:0] app_status, pkt_comm_status;

	(* KEEP="true" *) wire mode_cmp = ~app_mode[6];

	wire [7:0] core_din;
	wire [1:0] core_ctrl;
	wire [NUM_PROXIES-1:0] core_wr_en, core_init_ready, core_crypt_ready;
	wire [NUM_PROXIES-1:0] core_rd_en, core_empty, core_dout;

	bcrypt #(
		.NUM_CORES(NUM_PROXIES),
		.SIMULATION(1)
	) pkt_comm(
		.CORE_CLK(CORE_CLK),
		// Moved buffers to inside pkt_comm
		// for better usage of Hierarchial Design Methodology
		.IFCLK(CORE_CLK),//IFCLK),
		.hs_input_din( {hs_input_din[7:0],hs_input_din[15:8]} ),
		.hs_input_wr_en(hs_input_wr_en),
		.hs_input_almost_full(hs_input_almost_full),
		.hs_input_prog_full(hs_input_prog_full),

		.output_dout(),//app_dout),
		.output_rd_en(READ_ALL_FROM_OUTPUT_FIFO),//app_rd_en),
		.output_empty(),//app_empty),
		.output_limit(),//output_limit),
		.output_limit_not_done(),//output_limit_not_done),
		.output_mode_limit(1'b0),//output_mode_limit),
		.reg_output_limit(1'b0),//reg_output_limit),

		// Status signals for internal usage (PKT_COMM_CLK)
		.idle(app_idle), .error_r(error_r),
		// Application control (via VCR I/O). Set with fpga_set_app_mode()
		.app_mode(app_mode),
		// Application status (via VCR I/O). Available at fpga->wr.io_state.app_status
		.pkt_comm_status(pkt_comm_status),
		.app_status(app_status),
		.debug2(), .debug3(),
		//.debug(),

		// Wrappers and cores are moved to top level module
		// for better usage of Hierarchial Design Methodology
		.mode_cmp(mode_cmp),
		// 10 broadcast signals
		.core_din(core_din), .core_ctrl(core_ctrl),
		// 2 x NUM_PROXIES signals to cores, 4 x NUM_PROXIES from cores
		.core_wr_en(core_wr_en), .core_init_ready(core_init_ready), .core_crypt_ready(core_crypt_ready),
		.core_rd_en(core_rd_en), .core_empty(core_empty), .core_dout(core_dout)
	);

	//
	// Signals to/from cores, including broadcast signals,
	// enter distribution network.
	//
	generate
	for (i=0; i < NUM_WRAPPERS; i=i+1) begin:wrappers

		localparam START_PROXY_NUM = WRAPPERS_CONF[32*i+15 -:8];
		localparam END_PROXY_NUM = WRAPPERS_CONF[32*i+7 -:8];
		localparam IS_DUMMY = WRAPPERS_CONF[32*i+31];

		bcrypt_wrapper #(
			.NUM_PROXIES(END_PROXY_NUM - START_PROXY_NUM + 1),
			.PROXY_CONF(PROXY_CONF [32*END_PROXY_NUM+31 : 32*START_PROXY_NUM])
		) wrapper(
			.CLK(CORE_CLK), .mode_cmp(mode_cmp),
			.din(core_din), .ctrl(core_ctrl),
			.wr_en(core_wr_en [END_PROXY_NUM : START_PROXY_NUM]),
			.init_ready(core_init_ready [END_PROXY_NUM : START_PROXY_NUM]),
			.crypt_ready(core_crypt_ready [END_PROXY_NUM : START_PROXY_NUM]),
			.rd_en(core_rd_en [END_PROXY_NUM : START_PROXY_NUM]),
			.empty(core_empty [END_PROXY_NUM : START_PROXY_NUM]),
			.dout(core_dout [END_PROXY_NUM : START_PROXY_NUM])
		);

	end
	endgenerate




	// This does not reflect actual timing
	initial begin
		#5;
		while (1) begin
			CORE_CLK <= ~CORE_CLK; #10;
		end
	end

	initial begin
		#35;
		while (1) begin
			IFCLK <= ~IFCLK; #70;
		end
	end

endmodule

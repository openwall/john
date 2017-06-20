`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module pkt_comm_bcrypt_test();

	reg READ_ALL_FROM_OUTPUT_FIFO = 0;

	genvar i;
	integer k, k1, k2;

	reg CORE_CLK = 0, IFCLK = 0;

	reg [7:0] din;
	reg wr_en = 0;


	// ******************************************************************
	//
	// Simulating input from USB controller over high-speed interface
	//
	// ******************************************************************
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
	// Some example application
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




	initial begin
		#10000;
		// ****************** TEST 1. ******************
		wr_en <= 1;
		// write cmp_config packet
		// hash: $2x$05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS
		// password: "\xd1\x91"
		din <= 2; #20; // ver
		din <= 3; #20; // type
		din <= 0; #40; // reserved0
		din <= 28; #20; // len[7:0]
		din <= 0; #40; // len[23:0]
		din <= 0; #20; // reserved1
		din <= 8'h22; #20; // id0
		din <= 8'h33; #20; // id1;
		din <= 0; #80; // checksum - not checked in simulation

		// salt - 16 bytes
		// 0xe0 0xf2 0xd3 0xf1 0x0b 0x6a 0x52 0x93 0xe1 0x40 0x6b 0x09 0x05 0xb1 0xeb 0x34
		din <= 8'he0; #20; din <= 8'hf2; #20; din <= 8'hd3; #20;
		din <= 8'hf1; #20; din <= 8'h0b; #20; din <= 8'h6a; #20;
		din <= 8'h52; #20; din <= 8'h93; #20; din <= 8'he1; #20;
		din <= 8'h40; #20; din <= 8'h6b; #20; din <= 8'h09; #20;
		din <= 8'h05; #20; din <= 8'hb1; #20; din <= 8'heb; #20;
		din <= 8'h34; #20;
		din <= "x"; #20; // extension
		din <= 32; #20; din <= 0; #60; // iteration count (32 for $05$)
		din <= 8'h01; #20; // 1 hash
		din <= 8'h00; #20;
		// hash - first 4 bytes ( 0xd2 0x15 0x2b 0x93 )
		din <= 8'hd2; #20;
		din <= 8'h15; #20;
		din <= 8'h2b; #20;
		din <= 8'h93; #20;
		din <= 8'hCC; #20;
		din <= 0; #80; // checksum

		// empty word_gen packet
		din <= 2; #20;  din <= 2; #20; din <= 0; #40;
		din <= 6 + 3*0; #20; // len[7:0]
		din <= 0; #60; din <= 8'hf0; #20; din <= 8'h0f; #20; din <= 0; #80;
		// body
		din <= 0; #20; // num_ranges
		din <= 0; #80; din <= 8'hbb; #20;
		din <= 0; #80; // checksum

		// word_list packet
		din <= 2; #20;  din <= 1; #20; din <= 0; #40;
		din <= 3; #20; // len[7:0]
		din <= 0; #60;  din <= 8'h07; #40;  din <= 0; #80;

		// body: 1 word: \xd1\x91
		din <= 8'hd1; #20; din <= 8'h91; #20; din <= 0; #20;
		din <= 0; #80; // checksum
		wr_en <= 0;


		#10000;
		// ****************** TEST 2. ******************
		wr_en <= 1;
		// write cmp_config packet
		din <= 2; #20; // ver
		din <= 3; #20; // type
		din <= 0; #40; // reserved0
		din <= 28; #20; // len[7:0]
		din <= 0; #40; // len[23:0]
		din <= 0; #20; // reserved1
		din <= 8'hAB; #20; // id0
		din <= 8'hCD; #20; // id1;
		din <= 0; #80; // checksum

		// salt - 16 bytes
		din <= 8'h65; #20; din <= 8'h59; #20; din <= 8'h96; #20;
		din <= 8'h65; #20; din <= 8'h96; #20; din <= 8'h65; #20;
		din <= 8'h59; #20; din <= 8'h96; #20; din <= 8'h59; #20;
		din <= 8'h96; #20; din <= 8'h65; #20; din <= 8'h59; #20;
		din <= 8'h65; #20; din <= 8'h59; #20; din <= 8'h96; #20;
		din <= 8'h65; #20;
		din <= "a"; #20; // extension
		din <= 32; #20; din <= 0; #60; // iteration count (32 for $05$)
		din <= 8'h01; #20; // 1 hash
		din <= 8'h00; #20;
		// hash for "U*U*U"
		din <= 8'ha3; #20; din <= 8'h73; #20; din <= 8'he6; #20; din <= 8'h09; #20;
		din <= 8'hCC; #20;

		din <= 0; #80; // checksum
		wr_en <= 0;


		#1000;
		for (k=0; k < 1; k=k+1) begin

		wr_en <= 1;
		// word_gen packet
		din <= 2; #20;  din <= 2; #20; din <= 0; #40;
		//din <= 6 + 3*0; #20; // len[7:0]
		din <= 6 + 2*4; #20; // len[7:0]
		din <= 0; #60;  din <= 8'hb0; #40;  din <= 0; #80;
		// body. It generates 4 candidates for insertion into template: Zz ZU Uz UU
		din <= 2; #20; // num_ranges
		din <= 2; #20; din <= 0; #20; din <= "Z"; #20; din <= "U"; #20;
		din <= 2; #20; din <= 0; #20; din <= "z"; #20; din <= "U"; #20;
		din <= 0; #80; din <= 8'hbb; #20;
		din <= 0; #80; // checksum

		// template_list packet
		din <= 2; #20;  din <= 4; #20; din <= 0; #40;
		din <= 9; #20; // len[7:0]
		din <= 0; #60;  din <= 8'h07; #40;  din <= 0; #80;
		// body:
		din <= "#"; #20; din <= "*"; #20; din <= "#"; #20; din <= "*"; #20; din <= "U"; #20; din <= 0; #20;
		din <= 8'h80; #20; din <= 8'h82; #20; din <= 0; #20;
		din <= 0; #80; // checksum
/*
		// word_list packet
		din <= 2; #20;  din <= 1; #20; din <= 0; #40;
		din <= 4*6; #20; // len[7:0]
		din <= 0; #60;  din <= 8'h07; #40;  din <= 0; #80;

		// body:
		din <= "Z"; #20; din <= "*"; #20; din <= "U"; #20; din <= "*"; #20; din <= "U"; #20; din <= 0; #20;
		din <= "U"; #20; din <= "*"; #20; din <= "U"; #20; din <= "*"; #20; din <= "U"; #20; din <= 0; #20;
		din <= "U"; #20; din <= "*"; #20; din <= "U"; #20; din <= "*"; #20; din <= "U"; #20; din <= 0; #20;
		din <= "U"; #20; din <= "*"; #20; din <= "U"; #20; din <= "*"; #20; din <= "U"; #20; din <= 0; #20;
		din <= 0; #80; // checksum
*/
		wr_en <= 0;
		end


		// ****************** TEST 3. ******************
		// TODO

	end


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

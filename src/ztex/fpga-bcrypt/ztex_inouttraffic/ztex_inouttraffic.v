`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016-2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Used ISE version: 14.5
 *
 * bcrypt-ztex for John The Ripper password cracker -
 * bitstream for ZTEX 1.15y USB-FPGA module (4x Spartan-6 LX150)
 *
 */

module ztex_inouttraffic(
	input CS_IN,
	input [2:0] FPGA_ID,

	// Both IFCLK_IN and FXCLK_IN are at 48 MHz.
	input IFCLK_IN,
	input FXCLK_IN,

	// Vendor Command/Request I/O
	inout [7:0] PC, //  Vendor Command/Request (VCR) address/data
	input PA0,
	input PA1,
	input PA7,

	// High-Speed I/O Interface
	inout [15:0] FIFO_DATA,
	output FIFOADR0,
	output FIFOADR1,
	output SLOE,
	output SLRD,
	output SLWR,
	output PKTEND,
	input FLAGA,
	input FLAGB, // FULL
	input FLAGC, // EMPTY

	output INT4,
	output INT5
	);

	genvar i;


	// PC_RAW is available when VCR interface is off with cmd 0x00
	wire [7:0] PC_RAW = CS & vcr_inout_raw ? PC : 8'b0;

	clocks clocks(
		// Input clocks go to Clock Management Tile via dedicated routing
		.IFCLK_IN(IFCLK_IN),
		.FXCLK_IN(FXCLK_IN),
		// Up to 4 Programmable clocks
		.progen(PC_RAW[5:2]), .progdata(PC_RAW[1]), .progclk(PC_RAW[0]),
		.pll_reset(error_r), // Stop application clocks on error
		.progdone_inv(progdone_inv),
		// Produced clocks
		.IFCLK(IFCLK), 	// for operating I/O pins
		.clk_glbl_en(~app_idle),
		.CORE_CLK(CORE_CLK)	// <-- the clock for running bcrypt application
	);

	chip_select chip_select(
		.CS_IN(CS_IN), .CLK(IFCLK), .CS(CS), .out_z_wait1(out_z_wait1)
	);

	wire [255:0] debug;
	wire [7:0] debug2, debug3;

	// ********************************************************

	localparam NUM_PROXIES = 12;

	localparam NUM_WRAPPERS = 6;

	localparam [32*NUM_WRAPPERS-1 :0] WRAPPERS_CONF = {
	// reserved |start_proxy_num |end_proxy_num
		16'b0, 8'd10, 8'd11,	// wrapper #5: proxies 10-11
		16'b0, 8'd8, 8'd9,	// wrapper #4: proxies 8-9
		16'b0, 8'd6, 8'd7, 	// wrapper #3: proxies 6-7
		16'b0, 8'd4, 8'd5,	// wrapper #2: proxies 4-5
		16'b0, 8'd2, 8'd3,	// wrapper #1: proxies 2-3
		16'b0, 8'd0, 8'd1 	// wrapper #0: proxies 0-1
	};

	localparam [32*NUM_PROXIES-1 :0] PROXY_CONF = {
	// is_dummy |core_is_not_dummy |regs |num_cores
		1'b0, 19'b0000000_0000_0000_0000, 4'd2, 8'd12, 	// proxy #11 (5_1)
		1'b0, 19'b0000000_0000_0000_0000, 4'd1, 8'd11, 	// proxy #10 (5_0)
		1'b0, 19'b0000000_0000_0000_0000, 4'd2, 8'd10, 	// proxy #9 (4_1)
		1'b0, 19'b0000000_0000_0000_0000, 4'd1, 8'd8, 	// proxy #8 (4_0)
		1'b0, 19'b0000000_0000_0000_0000, 4'd2, 8'd10, 	// proxy #7 (3_1)
		1'b0, 19'b0000000_0000_0000_0000, 4'd1, 8'd13, 	// proxy #6 (3_0)
		1'b0, 19'b0000000_0000_0000_0000, 4'd2, 8'd10,	// proxy #5 (2_1)
		1'b0, 19'b0000000_0000_0000_0000, 4'd1, 8'd12, 	// proxy #4 (2_0): 1 regs, 12 cores
		1'b0, 19'b0000000_0000_0000_0000, 4'd2, 8'd4,	// proxy #3 (1_1): 2 regs, 4 cores
		1'b0, 19'b0000000_0000_0000_0000, 4'd1, 8'd12,	// proxy #2 (1_0): 1 regs, 12 cores
		1'b0, 19'b0000000_0000_0000_0000, 4'd2, 8'd10,	// proxy #1 (0_1): 2 regs, 10 cores
		1'b0, 19'b0000000_0000_0000_0000, 4'd1, 8'd12	// proxy #0 (0_0): 1 regs, 12 cores
	};


	// ********************************************************
	//
	// Some example application
	// 16-bit input, 16-bit output
	//
	// ********************************************************
	wire [15:0] hs_input_din;
	wire [15:0] app_dout;
	wire [15:0] output_limit;

	wire [7:0] app_mode;
	wire [7:0] app_status, pkt_comm_status;

	(* KEEP="true" *) wire mode_cmp = ~app_mode[6];

	wire [7:0] core_din;
	wire [1:0] core_ctrl;
	wire [NUM_PROXIES-1:0] core_wr_en, core_init_ready, core_crypt_ready;
	wire [NUM_PROXIES-1:0] core_rd_en, core_empty, core_dout;

	bcrypt #(//_dummy #(
		.NUM_CORES(NUM_PROXIES)
	) bcrypt(
		.CORE_CLK(CORE_CLK),
		// Moved I/O buffers to inside pkt_comm
		// for better usage of Hierarchial Design Methodology
		.IFCLK(IFCLK),
		.hs_input_din( {hs_input_din[7:0],hs_input_din[15:8]} ),
		.hs_input_wr_en(hs_input_wr_en),
		.hs_input_almost_full(hs_input_almost_full),
		.hs_input_prog_full(hs_input_prog_full),

		.output_dout(app_dout),
		.output_rd_en(app_rd_en),
		.output_empty(app_empty),
		.output_limit(output_limit),
		.output_limit_not_done(output_limit_not_done),
		.output_mode_limit(output_mode_limit),
		.reg_output_limit(reg_output_limit),

		// Status signals for internal usage
		.idle(app_idle), .error_r(error_r),
		// Application control (via VCR I/O). Set with fpga_set_app_mode()
		.app_mode(app_mode),
		// Application status (via VCR I/O). Available at fpga->wr.io_state.app_status
		.pkt_comm_status(pkt_comm_status),
		.app_status(app_status),
		.debug2(debug2), .debug3(debug3),
		//.debug(debug),

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


	// ********************************************************
	//
	// High-Speed I/O Interface (Slave FIFO)
	//
	// ********************************************************
	wire [7:0] hs_io_timeout;

	hs_io_v2 #(
		.USB_ENDPOINT_IN(2),
		.USB_ENDPOINT_OUT(6)
	) hs_io_inst(
		.IFCLK(IFCLK), .CS(CS), .out_z_wait1(out_z_wait1), .EN(hs_en),
		.FIFO_DATA(FIFO_DATA), .FIFOADR0(FIFOADR0), .FIFOADR1(FIFOADR1),
		.SLOE(SLOE), .SLRD(SLRD), .SLWR(SLWR), .PKTEND(PKTEND), .FLAGA(FLAGA), .FLAGB(FLAGB), .FLAGC(FLAGC),
		// data output from Cypress IO, received by FPGA
		.dout(hs_input_din),	.wr_en(hs_input_wr_en), .almost_full(hs_input_almost_full),
		.din(app_dout), .rd_en(app_rd_en), .empty(app_empty), // to Cypress IO, out of FPGA
		.io_timeout(hs_io_timeout), .sfifo_not_empty(sfifo_not_empty),
		.io_fsm_error(io_fsm_error), .io_err_write(io_err_write)
	);


	// ********************************************************
	//
	// Vendor Command/Request (VCR) I/O interface
	//
	// ********************************************************
	wire [7:0] vcr_out;
	assign PC = CS && PA7 ? vcr_out : 8'bz;

	vcr vcr_inst(
		.CS(CS), .vcr_in(PC), .vcr_out(vcr_out),
		.clk_vcr_addr(PA0), .clk_vcr_data(PA1),
		// i/o goes with respect to IFCLK
		.IFCLK(IFCLK),
		// various inputs to be read by CPU
		.FPGA_ID(FPGA_ID),
		.hs_io_timeout(hs_io_timeout), .hs_input_prog_full(hs_input_prog_full),
		.sfifo_not_empty(sfifo_not_empty), .io_fsm_error(io_fsm_error), .io_err_write(io_err_write),
		.output_limit(output_limit), .output_limit_not_done(output_limit_not_done),
		.app_status(app_status),
		.pkt_comm_status(pkt_comm_status), .debug2(debug2), .debug3(debug3),
		//.debug(debug),
		.progdone_inv(progdone_inv), // Programmable clock
		// various control wires
		.inout_raw(vcr_inout_raw),
		.hs_en(hs_en),
		.output_mode_limit(output_mode_limit),
		.reg_output_limit(reg_output_limit),
		.app_mode(app_mode)
	);


	// External interrupts for USB controller - put into defined state
	assign INT4 = 1'b0;
	assign INT5 = 1'b1;

endmodule

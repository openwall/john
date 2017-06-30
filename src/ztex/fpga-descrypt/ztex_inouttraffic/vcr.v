`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//***********************************************************
//
// Vendor Command / Vendor Request feature
// Commands or requests are sent to EZ-USB via USB EP0
// and handled by EZ-USB processor.
//
//***********************************************************

//***********************************************************
//
// New feature: cmd 0x00 disables the interface, allows
// usage of raw I/O port PC[7:0]. A pulse on clk_vcr_addr returns from raw mode.
//
// There's up to 256 VCR addresses (subsystems) for read or(and) write.
// Sequential multi-byte read or/and write is possible.
// For some actions, there's no need to read or write, just select address.
//
// EZ-USB uses 11 lines to FPGA. Typical exchange is as follows:
// 1. set direction towards FPGA (vcr_dir=0). Assert CPU I/O controls accordingly.
// 2. assert address on [7:0] vcr_inout.
// 3. assert vcr_set_addr, then deassert vcr_set_addr. This selects address.
// Optionally write:
// 4. setup data byte on [7:0] vcr_inout.
// 5. assert vcr_set_data, then deassert vcr_set_data. This performs write of the byte from step 4.
// 6. go to step 4 if nesessary.
// Optionally read:
// 7. set direction for input from FPGA (vcr_dir=1). Assert CPU I/O controls accordingly.
// 8. read data byte from [7:0] vcr_inout.
// 9. assert vcr_set_data, then deassert vcr_set_data. This let next data byte appear on [7:0] vcr_inout.
// 10. go to step 7 if necessary.
//
//***********************************************************

module vcr(
	input CS,
	
	input [7:0] vcr_in, //  Vendor Command/Request (VCR) address/data
	output [7:0] vcr_out,
	input clk_vcr_addr, // on posedge, set (internal to FPGA) VCR IO address
	input clk_vcr_data, // on posedge, perform write or synchronous read
	
	input IFCLK,
	
	input [2:0] FPGA_ID,
	input [7:0] hs_io_timeout,
	input hs_input_prog_full,
	//input output_err_overflow,
	input sfifo_not_empty,
	input io_fsm_error, io_err_write,
	input [15:0] output_limit,
	input output_limit_not_done,
	input progdone_inv,
	input [7:0] app_status,
	input [7:0] pkt_comm_status, debug2, debug3,
	//input [255:0] debug,
	
	//
	// Defaults for various controls; see also VCR_RESET
	//
	output reg inout_raw = 0, // use PC[7:0] in raw mode
	output reg hs_en = 0, // enable high-speed i/o
	output reg output_mode_limit = 1, // output_limit 
	output reg reg_output_limit = 0, // with respect to IFCLK
	output reg [7:0] app_mode = 0 // default mode: 0
	);

	wire ENABLE = CS;
	
	// VCR address definitions
	localparam VCR_SET_HS_IO_ENABLE = 8'h80;
	localparam VCR_SET_HS_IO_DISABLE = 8'h81;
	localparam VCR_SET_APP_MODE = 8'h82;
	localparam VCR_GET_IO_STATUS = 8'h84;
	// registers output limit (in output_limit_fifo words); starts
	// output of that many via high-speed interface
	localparam VCR_REG_OUTPUT_LIMIT = 8'h85;
	localparam VCR_SET_OUTPUT_LIMIT_ENABLE = 8'h86;
	localparam VCR_SET_OUTPUT_LIMIT_DISABLE = 8'h87;
	localparam VCR_ECHO_REQUEST = 8'h88;
	localparam VCR_GET_FPGA_ID = 8'h8A;
	localparam VCR_RESET = 8'h8B;
	localparam VCR_GET_ID_DATA = 8'hA1;
	//localparam VCR_ = 8'h;

	async2sync sync_addr_inst( .async(clk_vcr_addr), .clk(IFCLK), .clk_en(clk_addr_en) );
	async2sync sync_data_inst( .async(clk_vcr_data), .clk(IFCLK), .clk_en(clk_data_en) );
	
	reg [7:0] vcr_addr;
	reg [5:0] vcr_state = 0;

	/////////////////////////////////////////////////////////
	//
	// declarations for Command / Request specific stuff
	//
	/////////////////////////////////////////////////////////
	localparam [15:0] BITSTREAM_TYPE = `BITSTREAM_TYPE;
	reg [7:0] echo_content [3:0];
	reg RESET_R = 0;
	
	// declarations for Command / Request specific stuff end


	/////////////////////////////////////////////////////////
	//
	// Input
	//
	/////////////////////////////////////////////////////////

	always @(posedge IFCLK) begin
		if (ENABLE && clk_addr_en) begin
			vcr_addr <= vcr_in;
			vcr_state <= 0;

			if (inout_raw)
				inout_raw <= 0;
			else if (vcr_in == 8'h00)
				inout_raw <= 1;
			else if (vcr_in == VCR_SET_HS_IO_ENABLE)
				hs_en <= 1;
			else if (vcr_in == VCR_SET_HS_IO_DISABLE)
				hs_en <= 0;
			else if (vcr_in == VCR_SET_OUTPUT_LIMIT_ENABLE)
				output_mode_limit <= 1;
			else if (vcr_in == VCR_SET_OUTPUT_LIMIT_DISABLE)
				output_mode_limit <= 0;
			else if (vcr_in == VCR_RESET)
				RESET_R <= 1;
			else if (vcr_in == VCR_REG_OUTPUT_LIMIT)
				reg_output_limit <= 1;
			
		end // clk_addr_en

		else if (ENABLE && clk_data_en) begin
			vcr_state <= vcr_state + 1'b1;
			
			if (vcr_addr == VCR_ECHO_REQUEST)
				echo_content[ vcr_state[1:0] ] <= vcr_in;
			else if (vcr_addr == VCR_SET_APP_MODE)
				app_mode <= vcr_in;
		end // clk_data_en
		
		else begin // !ENABLE
			if (reg_output_limit)
				reg_output_limit <= 0;
		end
	end

	
	
	/////////////////////////////////////////////////////////
	//
	// Output
	//
	/////////////////////////////////////////////////////////

	assign vcr_out =
		(vcr_addr == VCR_REG_OUTPUT_LIMIT && vcr_state == 0) ? output_limit[7:0] :
		(vcr_addr == VCR_REG_OUTPUT_LIMIT && vcr_state == 1) ? output_limit[15:8] :
		
		(vcr_addr == VCR_GET_IO_STATUS && vcr_state == 0) ? {
			progdone_inv, 1'b0, io_err_write, io_fsm_error,
			sfifo_not_empty, 1'b0, output_limit_not_done, hs_input_prog_full
		} :
		(vcr_addr == VCR_GET_IO_STATUS && vcr_state == 1) ? hs_io_timeout :
		(vcr_addr == VCR_GET_IO_STATUS && vcr_state == 2) ? app_status :
		(vcr_addr == VCR_GET_IO_STATUS && vcr_state == 3) ? pkt_comm_status :
		(vcr_addr == VCR_GET_IO_STATUS && vcr_state == 4) ? debug2 :
		(vcr_addr == VCR_GET_IO_STATUS && vcr_state == 5) ? debug3 :
		
		(vcr_addr == VCR_ECHO_REQUEST) ? echo_content[ vcr_state[1:0] ] ^ 8'h5A :
		
		(vcr_addr == VCR_GET_ID_DATA && vcr_state == 0) ? BITSTREAM_TYPE[7:0] :
		(vcr_addr == VCR_GET_ID_DATA && vcr_state == 1) ? BITSTREAM_TYPE[15:8] :
		
		(vcr_addr == VCR_GET_FPGA_ID) ? { {5{1'b0}}, FPGA_ID } :
		//(vcr_addr ==  && vcr_state == ) ?  :
		8'b0;


	startup_spartan6 startup_spartan6(.rst(RESET_R));

endmodule

`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//*****************************************************************************
//
// High-Speed communtcation to USB device controller's Slave FIFO
//
// For Slave FIFO's signaling and timing diagram, see CY7C68013-56PVC-Datasheet
//
// Version 1 comment:
//
// It is implemented on a state machine with outputs dependent on both input
// and internal state. That's slow and is unable to operate at 48 MHz IFCLK.
//
// Version 2 improvements:
//
// 1. Removed asynchronous circuitry. That allows to operate at 48 MHz,
//		removes synchronization to CPU issues.
// 2. I/O registers placed most close to pins - into ILOGIC/OLOGIC components.
//		That removes the nesessity to manually allocate areas in UCF file.
//		IFCLK appears to arrive too late, added some phase backshift.
// 3. One cycle delay when switching control outputs into Z-state on CS deassertion
//		so controls for Slave FIFO (active low) always in a defined state.
//
//*****************************************************************************

module hs_io_v2 #(
	parameter USB_ENDPOINT_IN = 2, // from the point of view from the host
	parameter USB_ENDPOINT_OUT = 6
	)(
	input IFCLK,
	// Low CS puts all outputs into Z-state,
	// exactly as examples/intraffic is doing
	input CS,
	input out_z_wait1,
	
	// enable read/write
	// Deasserted EN doesn't perform read/write,
	// keeps signals for Slave FIFO in proper state.
	input EN,

	// Attention: attempt to send data to FPGA not aligned to
	// 2-byte word would result in a junk in upper byte
	inout [15:0] FIFO_DATA,
	output FIFOADR0,
	output FIFOADR1,
	// Following signals are active low.
	output SLOE, // Slave output enable
	output SLRD,
	output SLWR,
	output PKTEND,
	// FLAGA/B/C are fixed (independent from FIFOADR)
	input FLAGA, // PROG_FULL
	input FLAGB, // FULL
	input FLAGC, // EMPTY

	// write into some internal FIFO
	output [15:0] dout,
	output wr_en,
	//input full,
	input almost_full,
	
	// read from some internal FIFO
	input [15:0] din,
	output rd_en,
	input empty,

	// status information
	output [7:0] io_timeout, // in ~1us intervals @30MHz IFCLK
	output reg io_fsm_error = 0, // CS or EN deasserted while active I/O
	output reg sfifo_not_empty = 0,
	output reg io_err_write = 0
	);

	reg rw_direction = 0; // 1: FPGA writes

	always @(posedge IFCLK)
		if (CS & EN)
			sfifo_not_empty <= FLAGC_R;
	
	// Timeout
	localparam TIMEOUT_MSB = 12;
	reg [TIMEOUT_MSB:0] timeout = {TIMEOUT_MSB+1{1'b1}};
	assign io_timeout = timeout[TIMEOUT_MSB : TIMEOUT_MSB-7];


	// FIFOADR (Address for USB endpoint buffer)
	// - at 48 MHz, sometimes takes 2 cycles to propagate
	localparam USB_EP_OUT_B = (USB_ENDPOINT_OUT-2) >> 1;
	localparam USB_EP_IN_B = (USB_ENDPOINT_IN-2) >> 1;
	assign {FIFOADR1, FIFOADR0} =
		out_z_wait1 ? 2'bz :
		rw_direction ? USB_EP_IN_B[1:0] :
		USB_EP_OUT_B[1:0];


	// *************************
	//
	// High-Speed Input
	//
	// *************************

	// FPGA's Input register (data-out from hs_io)
	(* IOB="true" *) reg [15:0] input_r;
	assign dout = input_r;
	always @(posedge IFCLK)
		input_r <= FIFO_DATA;
	
	(* IOB="true" *) reg FLAGC_R = 0;
	always @(posedge IFCLK)
		FLAGC_R <= FLAGC;

	(* IOB="true" *) reg SLOE_R = 1;
	assign SLOE = out_z_wait1 ? 1'bz : SLOE_R;

	(* IOB="true" *) reg SLRD_R = 1;
	assign SLRD = out_z_wait1 ? 1'bz : SLRD_R;
	
	// input_r_ok indicates there was read last cycle (SLRD was active)
	reg input_r_ok = 0;
	always @(posedge IFCLK)
		input_r_ok <= ~SLRD_R;
	assign wr_en = input_r_ok & FLAGC_R;

	
	// *************************
	//
	// High-Speed Output
	//
	// *************************
	
	// FLAGA(active low) is configured to be active when 0 bytes in buffer
	(* IOB="true" *) reg FLAGA_R = 1;
	always @(posedge IFCLK)
		FLAGA_R <= FLAGA;
	
	(* IOB="true" *) reg FLAGB_R = 0;
	always @(posedge IFCLK)
		FLAGB_R <= FLAGB;
		
	(* IOB="true" *) reg SLWR_R = 1;
	assign SLWR = out_z_wait1 ? 1'bz : SLWR_R;
	
	// FPGA's output register.
	// valid data must be present on output 9.2 ns before write
	(* IOB="true" *) reg [15:0] output_r;
	// Tristate-enable FF inside OLOGIC component
	(* IOB="true" *) reg out_z = 1;
	assign FIFO_DATA = out_z ? 16'bz : output_r;
	always @(posedge IFCLK)
		out_z <= ~(CS & EN & rw_direction);
		
	// Flag indicates valid data in output register.
	// Could be better if output FIFO had almost_empty flag.
	reg output_r_valid = 0;
	assign rd_en = (~SLWR_R | io_state == IO_STATE_WR_SETUP1 & ~output_r_valid);

	(* IOB="true" *) reg PKTEND_R = 1;
	assign PKTEND = out_z_wait1 ? 1'bz : PKTEND_R;


	// It works as follows:
	// 1. reads as long as possible;
	// 2. writes up to USB_PKT_SIZE.
	localparam USB_PKT_SIZE = 256; // in 16-bit words
	reg [8:0] word_counter = 0;
	
	// Finally deal with PKTEND issue.
	// - when output FIFO is in mode_limit, there's no problem:
	// FIFO already has all the data, so it outputs every cycle
	// until EMPTY.
	// - when mode_limit is off, the data might arrive from FPGA's output FIFO
	// in small pieces such as 2-8 bytes or so, with intervals like 2-4 cycles.
	// That might result in partial reads by the host and overall performance degradation.
	// 
	localparam PKTEND_WR_TIMEOUT = 5;
	reg [2:0] wr_timeout = 0;

	
	//localparam IO_STATE_RESET = 1;
	localparam IO_STATE_READ_SETUP0 = 2;
	localparam IO_STATE_READ_SETUP1 = 3;
	localparam IO_STATE_READ_SETUP2 = 4;
	localparam IO_STATE_READ = 6;
	localparam IO_STATE_WR_SETUP0 = 7;
	localparam IO_STATE_WR_SETUP1 = 8;
	localparam IO_STATE_WR_SETUP2 = 9;
	localparam IO_STATE_WR = 11;
	localparam IO_STATE_DISABLED = 13;
	localparam IO_STATE_WR_WAIT = 14;
	localparam IO_STATE_PKT_COMMIT = 15;
	
	(* FSM_EXTRACT="YES" *)
	reg [4:0] io_state = IO_STATE_DISABLED;
	
	always @(posedge IFCLK)
	begin
		if ( ! (&timeout[TIMEOUT_MSB : TIMEOUT_MSB-7])
					& io_state != IO_STATE_READ & io_state != IO_STATE_WR)
			timeout <= timeout + 1'b1;

		// Disabled: EN is off, outputs in proper state
		if (io_state == IO_STATE_DISABLED) begin
			if (CS & EN)
				io_state <= IO_STATE_READ_SETUP0;
		end

		else if (~CS | ~EN) begin
			// Expecting EZ-USB to disable hs_io before selecting other fpga 
			if (!io_timeout | (~CS & EN))
				io_fsm_error <= 1;
			
			SLOE_R <= 1;
			SLRD_R <= 1;
			SLWR_R <= 1;
			output_r_valid <= 0;
			PKTEND_R <= 1;
			rw_direction <= 0;
			io_state <= IO_STATE_DISABLED;
		end

		else // CS & EN
		(* FULL_CASE, PARALLEL_CASE *) case (io_state)

		IO_STATE_READ_SETUP0: begin
			if (almost_full | ~FLAGC_R)
				io_state <= IO_STATE_WR_SETUP0;
			else begin
				io_state <= IO_STATE_READ_SETUP1;
			end
		end

		IO_STATE_READ_SETUP1: begin
			io_state <= IO_STATE_READ_SETUP2;
		end

		IO_STATE_READ_SETUP2: begin
			// must assert 18.7 ns before read
			SLOE_R <= 0;
			SLRD_R <= 0;
			io_state <= IO_STATE_READ;
		end
		
		IO_STATE_READ: begin
			if (!almost_full & FLAGC_R) begin
				timeout <= 0;
			end
			else begin
				SLOE_R <= 1;
				SLRD_R <= 1;
				io_state <= IO_STATE_WR_SETUP0;
			end
		end

		IO_STATE_WR_SETUP0: begin
			//if (empty | ~FLAGB_R)
			if ((empty & ~output_r_valid) | FLAGA_R)
				io_state <= IO_STATE_READ_SETUP0;
			// go on transmit
			else begin
				rw_direction <= 1;
				word_counter <= 0;
				io_state <= IO_STATE_WR_SETUP1;
			end
		end

		IO_STATE_WR_SETUP1: begin
			if (~output_r_valid) begin
				output_r <= din;
				output_r_valid <= 1;
			end
			io_state <= IO_STATE_WR_SETUP2;
		end
		
		IO_STATE_WR_SETUP2: begin
			// must assert 18.1 ns before write
			SLWR_R <= 0;
			io_state <= IO_STATE_WR;
		end

		IO_STATE_WR: begin
			output_r <= din;
			timeout <= 0;
			wr_timeout <= 0;
			word_counter <= word_counter + 1'b1;
			if (empty)
				output_r_valid <= 0;
				
			if (word_counter == USB_PKT_SIZE - 1) begin
				SLWR_R <= 1;
				rw_direction <= 0;
				io_state <= IO_STATE_READ_SETUP0;
			end
			else if (empty) begin
				SLWR_R <= 1;
				io_state <= IO_STATE_WR_WAIT;
			end
			
			if (~FLAGB_R)
				io_err_write <= 1;
		end
		
		IO_STATE_WR_WAIT: begin
			wr_timeout <= wr_timeout + 1'b1;
			
			if (wr_timeout == PKTEND_WR_TIMEOUT) begin
				PKTEND_R <= 0;
				io_state <= IO_STATE_PKT_COMMIT;
			end
			else if (!empty)
				io_state <= IO_STATE_WR_SETUP1;
		end
		
		IO_STATE_PKT_COMMIT: begin
			PKTEND_R <= 1;
			rw_direction <= 0;
			io_state <= IO_STATE_READ_SETUP0;
		end
		
		endcase
		// CS & EN
		
	end // IFCLK
	

endmodule


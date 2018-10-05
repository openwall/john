`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// **********************************************************************
//
// Input clocks:
// * IFCLK_IN 48 MHz.
// * FXCLK_IN 48 MHz.
//
// Output:
// * IFCLK - equal to IFCLK_IN, some phase backshift
// * other clocks
//
// **********************************************************************


module clocks #(
	// Using CLK2X
	//parameter PKT_COMM_FREQ = 135, // adjust UCF
	parameter CORE_FREQ = 135 // cmt3 - programmable (adjust UCF)
	)(
	input IFCLK_IN,
	input FXCLK_IN,
	
	// Programmable clock
	input [3:0] progen, 
	input progdata, progclk,
	input pll_reset,
	output progdone_inv,

	output IFCLK,
	output PKT_COMM_CLK,
	input core_clk_glbl_en,
	output CORE_CLK
	);


	// ********************************************************************************
	//
	// Attention developer!
	//
	// * On ZTEX 1.15y board, clocks coming from USB device controller do bypass a CPLD.
	// That's unknown why. To get Slave FIFO working, that requires clock phase backshift
	// (DCM can do) or equal measure. That might be the placement of input registers deep
	// into FPGA fabric or usage of IDELAY components.
	//
	// * If several DCMs and/or PLLs are used and their placement is not manually defined,
	// tools (ISE 14.5) place them randomly without a respect to dedicated lines.
	// That results in a usage of general routing for clocks, that in turn can
	// result in an unroutable condition if it's full of wires.
	//
	// * When tools notice derived clocks, they mess up with timing at Place and Route stage.
	//
	// ********************************************************************************



	// ****************************************************************************
	//
	// Spartan-6 Clocking Resources (Xilinx UG382) is anything but straightforward.
	//
	// ****************************************************************************

	// Tasks:
	// - generate a number of clocks for various parts of application
	// - don't use general routing for clocks
	// - define frequencies in MHz, not in magic units
	// - don't define derived clocks, 1 constraint should apply only to 1 clock.

	
	// IFCLK_IN and FXCLK_IN are located near each other.
	// There's some I/O clocking region there.
	// Limited number of dedicated routes from that region to CMTs are available.
	//
	// Each input clock can go to up to 2 CMTs, one of them must be
	// in the top half of fpga and other one must be in the bottom half.
	//
	// CMTs are numbered 0 to 5 from bottom to top.
	
	// Delay line waits 4 cycles after GSR deasserted
	reg [3:0] delay_line = 0;
	always @(posedge IFCLK)
		delay_line[3:0] <= { delay_line[2:0], 1'b1 };
	wire CE = &delay_line[3:0];


	cmt2 #(
		.PLL_FREQ(),//PKT_COMM_FREQ),
		.PHASE_SHIFT(-15)
	) cmt2(
		.I(IFCLK_IN),
		.CLK0(IFCLK),
		.CLK2X(),//PKT_COMM_CLK),
		.PLL_CLK()//PKT_COMM_CLK)
	);

/*
	// Route FXCLK via BUFG to feed 2+ CMT's
	BUFG FXCLK_BUFG_inst(
		.I(FXCLK_IN),
		.O(FXCLK)
	);

	// Programmable clock #1:
	cmt_prog #( .F(CMP_FREQ)
	) cmt1(
		.I(FXCLK),
		.progen(progen[1]), .progdata(progdata), .progclk(progclk),
		.pll_reset(pll_reset),
		.CE(CE),
		.progdone_inv(progdone_inv1),
		.O(CMP_CLK)
	);
*/

	// Programmable clock #0:
	//cmt_prog_m3d5 #( .F(CORE_FREQ)
	cmt_prog #( .F(CORE_FREQ)
	) cmt3(
		.I(FXCLK_IN),
		.progen(progen[0]), .progdata(progdata), .progclk(progclk),
		.pll_reset(pll_reset),
		.CE(CE & core_clk_glbl_en),
		.progdone_inv(progdone_inv0),
		.O(CORE_CLK)
	);

	assign progdone_inv = progdone_inv0;// | progdone_inv1;


endmodule

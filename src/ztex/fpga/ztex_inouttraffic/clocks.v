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
	parameter WORD_GEN_FREQ = 228,
	parameter PKT_COMM_FREQ = 162,
	parameter CORE_FREQ = 222, 
	parameter CMP_FREQ = 162//186
	)(
	input IFCLK_IN,
	input FXCLK_IN,
	
	output IFCLK,
	output WORD_GEN_CLK,
	output PKT_COMM_CLK,
	output CORE_CLK,
	output CMP_CLK
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
	
	cmt2 #(
		.PLL_FREQ(WORD_GEN_FREQ),
		.PHASE_SHIFT(-15)
	) cmt2(
		.I(IFCLK_IN),
		.CLK0(IFCLK),
		.PLL_CLK(WORD_GEN_CLK),
		.IFCLK1_BUFG(IFCLK1_BUFG)
	);


	cmt_common #(
		//.CLK2_FREQ(),
		.PLL_FREQ(CMP_FREQ)
	) cmt1(
		.I(FXCLK_IN),
		.CLK2(),
		.PLL_CLK(CMP_CLK)
	);

	cmt_common #(
		//.CLK2_FREQ(),
		.PLL_FREQ(CORE_FREQ)
	) cmt3(
		.I(FXCLK_IN),
		.CLK2(),
		.PLL_CLK(CORE_CLK)
	);


	
	// ********************************************************************
	//
	// If more PLLs are used, they can source input clock signal from BUFG.
	//
	// ********************************************************************

	cmt_common #(
		//.CLK2_FREQ(),
		.PLL_FREQ(PKT_COMM_FREQ)
	) cmt_bufg0(
		.I(IFCLK1_BUFG),
		.CLK2(),
		.PLL_CLK(PKT_COMM_CLK)
	);

endmodule

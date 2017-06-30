`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// *******************************************
//
// Clock Management Tile #2
//
// *******************************************

module cmt2 #(
	parameter PHASE_SHIFT = 0,
	parameter FREQ_IN = 48,
	//parameter BUFIO2_DIVIDE = 1,
	parameter CLK2_DIVIDE = 8,
	parameter CLK2_FREQ = 210,
	parameter PLL_FREQ = 0
	)(
	input I,
	output CLK0, 
	//output CLK2,
	output PLL_CLK
	);

	// ******************************************************
	//
	// Available frequencies 
	// (*) - default value
	//
	// BUFIO2_DIVIDE = 1:
	//
	//    CLK1_DIVIDE = 8: step 6 MHz, max. 192 MHz
	// (*)CLK1_DIVIDE = 6: step 8 MHz, max. 256 MHz
	//    CLK1_DIVIDE = 4: step 12 MHz, max. 384 MHz
	//
	// (*)CLK2_DIVIDE = 8: step 6 MHz, max. ~260 MHz
	//    CLK2_DIVIDE = 6: step 8 MHz, max. ~320 MHz
	//
	// BUFIO2_DIVIDE = 2:
	//
	// (*)CLK1_DIVIDE = 6: step 4 MHz, max. 128 MHz
	//    CLK1_DIVIDE = 4: step 6 MHz, max. 192 MHz
	//    CLK1_DIVIDE = 3: step 8 MHz, max. 256 MHz
	//    CLK1_DIVIDE = 2: step 12 MHz, max. 384 MHz
	//
	//    CLK2_DIVIDE = 16: step 1.5 MHz, max. ~380 MHz
	//    CLK2_DIVIDE = 12: step 2 MHz, max. >400 MHz
	// (*)CLK2_DIVIDE = 8: step 3 MHz, max. >400 MHz
	//    CLK2_DIVIDE = 6: step 4 MHz, max. >400 MHz
	//    CLK2_DIVIDE = 4: step 6 MHz, max. >400 MHz
	//
	// ******************************************************

	localparam BUFIO2_DIVIDE = 1;
	localparam FREQ_IN_DIVIDED = FREQ_IN / BUFIO2_DIVIDE;
	
	localparam CLK2_MULTIPLY = CLK2_FREQ / (FREQ_IN_DIVIDED / CLK2_DIVIDE);

	localparam DCM0_DIVIDE = 2;
	
	/*
		//
		// Some problems with manual usage of BUFIO2.
		//
		BUFIO2 #(
			.DIVIDE(BUFIO2_DIVIDE),             // DIVCLK divider (1-8)
			.DIVIDE_BYPASS(BUFIO2_DIVIDE == 1 ? "TRUE" : "FALSE"), // Bypass the divider circuitry (TRUE/FALSE)
			.I_INVERT("FALSE"),     // Invert clock (TRUE/FALSE)
			.USE_DOUBLER("FALSE")   // Use doubler circuitry (TRUE/FALSE)
		)
		BUFIO2_inst (
			.DIVCLK(),//DIVCLK),             // 1-bit output: Divided clock output
			.IOCLK( CLK_IN ),               // 1-bit output: I/O output clock
			.SERDESSTROBE(),//SERDESSTROBE), // 1-bit output: Output SERDES strobe (connect to ISERDES2/OSERDES2)
			.I( I )                        // 1-bit input: Clock input (connect to IBUFG)
		);
	*/
	

	// **********************************************************************
	
	
	(* BUFFER_TYPE="NONE" *) wire dcm0_clk90, dcm0_clkdv;

	DCM_SP #(.CLKDV_DIVIDE    ( DCM0_DIVIDE ),
		.CLKFX_DIVIDE          (),
		.CLKFX_MULTIPLY        (),
		.CLKIN_DIVIDE_BY_2     ("FALSE"),
		.CLKIN_PERIOD          (),
		.CLKOUT_PHASE_SHIFT    ("FIXED"),
		.CLK_FEEDBACK          ("1X"),
		.DESKEW_ADJUST         ("SYSTEM_SYNCHRONOUS"),//("SOURCE_SYNCHRONOUS"),
		.PHASE_SHIFT           ( PHASE_SHIFT ), // -12: phase backshift 1 ns
		.STARTUP_WAIT          ("FALSE")
	) DCM_0 (
		// Input clock
		.CLKIN                 ( I ),
		.CLKFB                 (dcm0_clkfb),
		// Output clocks
		.CLK0                  (dcm0_clk0),
		.CLK90                 (dcm0_clk90),
		.CLK180                (),//dcm0_clk180),
		.CLK270                (),
		.CLK2X                 (),
		.CLK2X180              (),
		.CLKFX                 (),
		.CLKFX180              (),
		.CLKDV                 (dcm0_clkdv),
		// Ports for dynamic phase shift
		.PSCLK(1'b0), .PSEN(1'b0), .PSINCDEC(1'b0), .PSDONE(),
		.LOCKED(), .STATUS(), .RST(1'b0), .DSSEN(1'b0)
	);

	assign dcm0_clkfb = dcm0_clk0; // Adds BUFIO2FB
	assign CLK0 = dcm0_clk0;
		
/*
	BUFG BUFG_1(
		.I(dcm0_clk180),
		.O(IFCLK1_BUFG)
	);
*/	
	// *****************************************************
	//
	// Usage of PLL:
	//
	// * Unless LOCated properly (in UCF), placer would probably place it in wrong place
	// and that would result in routing problems
	// * in UCF, uncomment dcm0_clkdv
	//
	if (PLL_FREQ) begin
	
	localparam PLL_DIVIDE = 4; // with FREQ_IN=48, DCM0_DIVIDE=2: step 6 MHz, max. ~270 MHz

	localparam PLL_MULT = PLL_FREQ / (FREQ_IN / DCM0_DIVIDE / PLL_DIVIDE);

	PLL_BASE #(
		.BANDWIDTH("OPTIMIZED"),
		.CLKFBOUT_MULT( PLL_MULT ),
		.CLKOUT0_DIVIDE( PLL_DIVIDE ),
		.CLKOUT0_DUTY_CYCLE(0.5),
		.CLKIN_PERIOD(0.0),
		.CLK_FEEDBACK("CLKFBOUT"),
		.COMPENSATION("DCM2PLL"),//SYSTEM_SYNCHRONOUS"),
		.DIVCLK_DIVIDE(1),
		.REF_JITTER(0.10),
		.RESET_ON_LOSS_OF_LOCK("FALSE")
	) PLL_0 (
		.CLKFBOUT(pll0_clkfb),
		.CLKOUT0(pll0_clkout0),
		.CLKOUT1(),
		.CLKOUT2(),
		.CLKOUT3(),
		.CLKOUT4(),
		.CLKOUT5(),
		.LOCKED(),
		.CLKFBIN(pll0_clkfb),
		.CLKIN( dcm0_clkdv ),
		.RST(1'b0)
	);

	BUFG BUFG_0(
		.I(pll0_clkout0),
		.O(PLL_CLK)
	);
	
	end else begin // PLL_FREQ
	
		assign PLL_CLK = 1'b0;
	
	end

	// *****************************************************

/*
	DCM_CLKGEN #(
		.CLKFXDV_DIVIDE(2),       		// CLKFXDV divide value (2, 4, 8, 16, 32)
		.CLKFX_DIVIDE( CLK2_DIVIDE ),			// Divide value - D - (1-256)
		.CLKFX_MD_MAX(0.0),       		// Specify maximum M/D ratio for timing anlysis
		.CLKFX_MULTIPLY( CLK2_MULTIPLY ),  // Multiply value - M - (2-256)
		.CLKIN_PERIOD(),      		// Input clock period specified in nS
		.SPREAD_SPECTRUM("NONE"), 		// Spread Spectrum mode "NONE", "CENTER_LOW_SPREAD", "CENTER_HIGH_SPREAD",
												// "VIDEO_LINK_M0", "VIDEO_LINK_M1" or "VIDEO_LINK_M2" 
		.STARTUP_WAIT("FALSE")    		// Delay config DONE until DCM_CLKGEN LOCKED (TRUE/FALSE)
	) DCM_CLKGEN_0 (
		.CLKFX( CLK2 ),           		// 1-bit output: Generated clock output
		.CLKFX180(),// dcm1_clkfx180 ),    // 1-bit output: Generated clock output 180 degree out of phase from CLKFX.
		.CLKFXDV(),// dcm1_clkfxdv ),    	// 1-bit output: Divided clock output
		.LOCKED(),       		// 1-bit output: Locked output
		.PROGDONE(),  // 1-bit output: Active high output to indicate the successful re-programming
		.STATUS(),             		// 2-bit output: DCM_CLKGEN status
		.CLKIN( dcm0_clk90 ),          		// 1-bit input: Input clock
		.FREEZEDCM(1'b0),      		// 1-bit input: Prevents frequency adjustments to input clock
		.PROGCLK(1'b0),    		// 1-bit input: Clock input for M/D reconfiguration
		.PROGDATA(1'b0),  // 1-bit input: Serial data input for M/D reconfiguration
		.PROGEN(1'b0),      // 1-bit input: Active high program enable
		.RST(1'b0)                // 1-bit input: Reset input pin
	);
*/
endmodule

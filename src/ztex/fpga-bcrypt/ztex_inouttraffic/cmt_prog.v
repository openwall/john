`timescale 1ns / 1ps

//
// * Programmable clock for internal parts of application
// * Wide range of possible frequencies 135..355 MHz
// * Programmable with step ~0.5-1 Mhz until ~300 Mhz
// * Everything calculated for FREQ_IN=48
//
module cmt_prog #(
	parameter FREQ_IN = 48,
	parameter F = 225, // 1. Set startup frequency
	// 2. Adjust timing constraint in UCF file!
	parameter M = 
		F >=275 ? 38 :	F >=270 ? 32 :	F >=265 ? 34 :	F >=260 ? 35 :
		F >=255 ? 21 :	F >=250 ? 37 :	F >=245 ? 25 :	F >=240 ? 30 :
		F >=235 ? 34 :	F >=230 ? 31 :	F >=225 ? 20 :	F >=220 ? 21 :
		F >=215 ? 29 :	F >=210 ? 38 :	F >=205 ? 33 :	F >=200 ? 27 :
		F >=195 ? 25 :	F >=190 ? 35 :	F >=185 ? 31 :	F >=180 ? 29 :
		F >=175 ? 38 :	F >=170 ? 33 :	F >=165 ? 38 :	F >=160 ? 30 :
		F >=155 ? 25 :	F >=150 ? 39 :	F >=145 ? 31 :	F >=140 ? 35 :
	36, // default:135 MHz
	parameter D =
		F >=275 ? 42 :	F >=270 ? 36 :	F >=265 ? 39 :	F >=260 ? 41 :
		F >=255 ? 25 :	F >=250 ? 45 :	F >=245 ? 31 :	F >=240 ? 38 :
		F >=235 ? 44 :	F >=230 ? 41 :	F >=225 ? 27 :	F >=220 ? 29 :
		F >=215 ? 41 :	F >=210 ? 55 :	F >=205 ? 49 :	F >=200 ? 41 :
		F >=195 ? 39 :	F >=190 ? 56 :	F >=185 ? 51 :	F >=180 ? 49 :
		F >=175 ? 66 :	F >=170 ? 59 :	F >=165 ? 70 :	F >=160 ? 57 :
		F >=155 ? 49 :	F >=150 ? 79 :	F >=145 ? 65 :	F >=140 ? 76 :
	81, // default:135 MHz
	parameter PLL_CLKIN_PERIOD = 1000.0 / ((FREQ_IN+0.0) * (M+0.0) / (D+0.0))
	)(
	input I,
	input progen, progdata, progclk,
	input pll_reset,
	input CE,
	output progdone_inv,
	output O
	);

	localparam DCM_CLKIN_PERIOD = 1000.0 / (FREQ_IN+0.0);

	wire [2:1] dcm_status;
	
	DCM_CLKGEN #(
		.CLKFXDV_DIVIDE(2),       		// CLKFXDV divide value (2, 4, 8, 16, 32)
		.CLKFX_DIVIDE( D ),			// Divide value - D - (1-256)
		.CLKFX_MD_MAX(0.0),       		// Specify maximum M/D ratio for timing anlysis
		.CLKFX_MULTIPLY( M ),        // Multiply value - M - (2-256)
		.CLKIN_PERIOD(DCM_CLKIN_PERIOD),      // Input clock period specified in nS
		.SPREAD_SPECTRUM("NONE"), 		// Spread Spectrum mode "NONE", "CENTER_LOW_SPREAD", "CENTER_HIGH_SPREAD",
												// "VIDEO_LINK_M0", "VIDEO_LINK_M1" or "VIDEO_LINK_M2" 
		.STARTUP_WAIT("FALSE")    		// Delay config DONE until DCM_CLKGEN LOCKED (TRUE/FALSE)
	) DCM_CLKGEN_0 (
		.CLKFX( dcm0_clkfx ),           		// 1-bit output: Generated clock output
		.CLKFX180(),    // 1-bit output: Generated clock output 180 degree out of phase from CLKFX.
		.CLKFXDV(),   	// 1-bit output: Divided clock output
		.LOCKED( dcm_locked ),       		// 1-bit output: Locked output
		.PROGDONE( progdone ),  // 1-bit output: Active high output to indicate the successful re-programming
		.STATUS( dcm_status ),             		// 2-bit output: DCM_CLKGEN status
		.CLKIN( I ),          		// 1-bit input: Input clock
		.FREEZEDCM(1'b0),      		// 1-bit input: Prevents frequency adjustments to input clock
		.PROGCLK( progclk ),    		// 1-bit input: Clock input for M/D reconfiguration
		.PROGDATA( progdata ),  // 1-bit input: Serial data input for M/D reconfiguration
		.PROGEN( progen ),      // 1-bit input: Active high program enable
		.RST(~dcm_locked & dcm_status[2])      // 1-bit input: Reset input pin
	);

	reg unprog = 1; // unprogrammed (after reset)
	always @(posedge progclk)
		if (progen)
			unprog <= 0;
	assign progdone_inv = ~(progdone | unprog);


	// After clock is generated with CLKGEN
	// and arrives into PLL the frequency is multiplied. 
	// PLL allows input frequency no less than 19 MHz,
	// after multiplied internally it should be in range 400 - 1,080 MHz
	//
	// Fixed M=19, D=3 allows input to PLL 21..56 MHz, produces 133..355 MHz.
	localparam PLL_MULTIPLY = 19;
	localparam PLL_DIVIDE = 3;


	PLL_BASE #(
		.BANDWIDTH("OPTIMIZED"),
		.CLKFBOUT_MULT( PLL_MULTIPLY ),
		.CLKOUT0_DIVIDE( PLL_DIVIDE ),
		.CLKOUT0_DUTY_CYCLE(0.5),
		.CLKIN_PERIOD( PLL_CLKIN_PERIOD ),
		.CLK_FEEDBACK("CLKFBOUT"),
		.COMPENSATION("DCM2PLL"),
		.DIVCLK_DIVIDE(1),
		.REF_JITTER(0.10),
		.RESET_ON_LOSS_OF_LOCK("FALSE")
	) PLL_0 (
		.CLKFBOUT( pll0_clkfb ),
		.CLKOUT0( pll0_clkout0 ),
		.CLKOUT1(),
		.CLKOUT2(),
		.CLKOUT3(),
		.CLKOUT4(),
		.CLKOUT5(),
		.LOCKED( pll_locked ),
		.CLKFBIN( pll0_clkfb ),
		.CLKIN( dcm0_clkfx ),
		.RST(pll_reset | ~dcm_locked)
	);

	BUFGCE BUFGCE_inst (
		.O(O),   // 1-bit output: Clock buffer output
		.CE(pll_locked & CE), // 1-bit input: Clock buffer select
		.I(pll0_clkout0)    // 1-bit input: Clock buffer input (S=0)
	);


endmodule

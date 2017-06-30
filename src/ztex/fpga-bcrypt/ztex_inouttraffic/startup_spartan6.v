`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

module startup_spartan6 (
	input rst
	);

	STARTUP_SPARTAN6 STARTUP_SPARTAN6_inst (
		.CFGCLK(),//CFGCLK),       // 1-bit output: Configuration logic main clock output.
		.CFGMCLK(),//CFGMCLK),     // 1-bit output: Configuration internal oscillator clock output.
		.EOS(),//EOS),             // 1-bit output: Active high output signal indicates the End Of Configuration.
		.CLK(1'b0),             // 1-bit input: User startup-clock input
		.GSR(rst),             // 1-bit input: Global Set/Reset input (GSR cannot be used for the port name)
		.GTS(1'b0),             // 1-bit input: Global 3-state input (GTS cannot be used for the port name)
		.KEYCLEARB(1'b0)  // 1-bit input: Clear AES Decrypter Key input from Battery-Backed RAM (BBRAM)
	);


endmodule

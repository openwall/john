`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../sha512.vh"

// It takes several stages to load an instruction
// and execute it.
//
// Stages:
// RELOAD. IP_curr (Instruction pointer) for given thread - loaded
// 0. Instruction loaded from the memory
// 1. Read0 from register bank, partial decoding
// 2. Completed reading registers, instruction decoded
// 3. Execution
//
// Controls:
// - instr_wait. No movement through pipeline. Possible only
// when the last stage is available.
// - invalidate. All stages get invalidated.
//
module cpu_state #(
	parameter N_STAGES = `N_STAGES
	)(
	input CLK,

	input invalidate, instr_wait, reload,

	output reg thread_almost_switched = 0,
	output reg [N_STAGES-1:0] stage_allow = 0
	);

	reg [N_STAGES-1:0] stage_reached = 0;

	genvar i;
	generate
	for (i=0; i < N_STAGES; i=i+1) begin:stages

		if (i==0) begin

			always @(posedge CLK)
				if (invalidate)
					stage_reached[i] <= 0;
				else if (reload)
					stage_reached[i] <= 1;

			always @(posedge CLK)
				stage_allow[i] <= ~invalidate & ~instr_wait
					& (reload | stage_reached[i]);

		end
		else begin

			always @(posedge CLK)
				stage_reached[i] <= ~invalidate & stage_reached[i<1 ? 0 : i-1];

			always @(posedge CLK)
				stage_allow[i] <= ~invalidate & ~instr_wait
					& stage_reached[i<1 ? 0 : i-1];

		end

	end
	endgenerate


	always @(posedge CLK)
		thread_almost_switched <= stage_reached[1] & ~stage_reached[2];

endmodule

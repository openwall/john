`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../sha256.vh"


module engine_ctrl #(
	parameter N_CORES = 3,
	parameter N_CORES_MSB = `MSB(N_CORES-1),
	parameter N_THREADS = 2 * N_CORES,
	parameter N_THREADS_MSB = `MSB(2*N_CORES-1),
	parameter COMP_INTERVAL = 144 / N_THREADS
	)(
	input CLK,
	output reg [N_CORES-1:0] core_start = 0
	);

	reg [7:0] cnt = 0;
	always @(posedge CLK)
		cnt <= cnt == 143 ? 8'b0 : cnt + 1'b1;


	genvar i;
	generate
	for (i=0; i < N_CORES; i=i+1) begin:for_start

		always @(posedge CLK) begin
			if (core_start[i])
				core_start[i] <= 0;
			if (cnt == i * COMP_INTERVAL
					|| cnt == 72 + i * COMP_INTERVAL)
				core_start[i] <= 1;
		end

	end
	endgenerate

endmodule

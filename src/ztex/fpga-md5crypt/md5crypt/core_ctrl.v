`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "md5.vh"


module core_ctrl #(
	parameter N_CORES = 3,
	parameter N_CORES_MSB = `MSB(N_CORES-1),
	parameter N_THREADS = 4 * N_CORES,
	parameter N_THREADS_MSB = `MSB(2*N_CORES-1),
	parameter COMP_INTERVAL = 288 / N_THREADS // must be 24
	)(
	input CLK,
	output reg [N_CORES-1:0] core_start = 0,
	output reg ctx_num,
	output reg [N_CORES-1:0] seq_num = 0
	);

	reg [8:0] cnt = 0;
	always @(posedge CLK)
		cnt <= cnt == 287 ? 9'b0 : cnt + 1'b1;

	always @(posedge CLK)
		ctx_num <= cnt[0];

	genvar i;
	generate
	for (i=0; i < N_CORES; i=i+1) begin:for_start

		always @(posedge CLK) begin
			if (core_start[i])
				core_start[i] <= 0;
			if (cnt == 2*i * COMP_INTERVAL
					| cnt == 2*i * COMP_INTERVAL + COMP_INTERVAL-1
					| cnt == 144 + 2*i * COMP_INTERVAL
					| cnt == 144 + 2*i * COMP_INTERVAL + COMP_INTERVAL-1)
				core_start[i] <= 1;

			if (cnt == 2*i * COMP_INTERVAL
					| 2*i * COMP_INTERVAL + COMP_INTERVAL-1)
				seq_num[i] <= 0;

			if (cnt == 144 + 2*i * COMP_INTERVAL
					| cnt == 144 + 2*i * COMP_INTERVAL + COMP_INTERVAL-1)
				seq_num[i] <= 1;
		end

	end
	endgenerate

endmodule

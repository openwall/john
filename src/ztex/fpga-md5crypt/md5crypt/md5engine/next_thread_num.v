`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

module next_thread_num #(
	parameter N_CORES = 3,
	parameter N_CORES_MSB = `MSB(N_CORES-1),
	parameter N_THREADS = 4 * N_CORES,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input [`MSB(N_THREADS-1) :0] in,
	output [`MSB(N_THREADS-1) :0] out
	);

	// bit 0: seq_num
	// bit 1: ctx_num
	wire [N_CORES_MSB+1 :0] core_num;
	assign { core_num, seq_num } = in;

	wire [N_CORES_MSB+1 :0] core_num_next =
		core_num == 2*N_CORES-1 ? {2*(N_CORES_MSB+1){1'b0}}
		: core_num + 1'b1;

	wire seq_num_next = core_num == 2*N_CORES-1 ? ~seq_num : seq_num;

	assign out = { core_num_next, seq_num_next };

endmodule

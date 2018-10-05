`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`include "../md5.vh"

module cpu_flags #(
	parameter N = `N_FLAGS,
	parameter N_THREADS = 16,
	parameter N_THREADS_MSB = `MSB(N_THREADS-1)
	)(
	input CLK,
	input [N_THREADS_MSB :0] thread_num,
	input load_en, save_en,
	output reg [N-1 :0] flags, // Flags themselves

	input [`CONDITION_LEN-1 :0] op_condition,
	output condition_is_true,

	input set_flags,
	input [N-1 :0] iop_flag_mask, flags_in
	);

	integer k;
	
	//
	// Store flags for each thread
	//
	(* RAM_STYLE="DISTRIBUTED" *)
	reg [N-1 :0] flags_mem [0: N_THREADS-1];
	//reg [N-1 :0] flags_r;

	always @(posedge CLK) begin
		//flags_r <= flags_mem [thread_num];
		if (save_en)
			flags_mem [thread_num] <= flags;
	end


	//
	// Check conditions
	//
	assign condition_is_true = op_condition == `IF_NONE
		| op_condition == `IF_ZERO & `FLAG_ZERO(flags)
		| op_condition == `IF_NOT_ZERO & ~`FLAG_ZERO(flags)
		| op_condition == `IF_ONE & `FLAG_ONE(flags)
		| op_condition == `IF_NOT_ONE & ~`FLAG_ONE(flags)
		| op_condition == `IF_CARRY & `FLAG_CARRY(flags)
		| op_condition == `IF_NOT_CARRY & ~`FLAG_CARRY(flags)
		| op_condition == `IF_UF & `FLAG_USER(flags)
		| op_condition == `IF_NOT_UF & ~`FLAG_USER(flags)
	;


	//
	// Set flags
	//
	always @(posedge CLK) begin
		if (load_en)
			//flags <= flags_r;
			flags <= flags_mem [thread_num];
		else if (set_flags)
			for (k=0; k < N; k=k+1)
				if (iop_flag_mask[k])
					flags[k] <= flags_in[k];
	end


endmodule

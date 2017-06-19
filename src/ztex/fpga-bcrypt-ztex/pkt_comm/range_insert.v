`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// Inserts ranges into word, into positions specified in range_info
//
// MSB in range_info is range_active bit: 1 - range is active, 0 - no.
// Other bits are 'shift_count' bits that specify position.
//
module range_insert #(
	parameter CHAR_BITS = -1,
	parameter WORD_MAX_LEN = -1,
	parameter RANGES_MAX = -1,
	parameter RANGE_INFO_MSB = 1 + `MSB(WORD_MAX_LEN-1)
	)(
	input [WORD_MAX_LEN * CHAR_BITS - 1 :0] word,
	input [RANGES_MAX * CHAR_BITS - 1 :0] ranges,
	//input [RANGES_MAX * (RANGE_INFO_MSB+1) - 1 :0] range_info,
	input [WORD_MAX_LEN-1:0] if_range,
	input [WORD_MAX_LEN*(RANGE_INFO_MSB)-1:0] range_shift_val,
	output [WORD_MAX_LEN * CHAR_BITS - 1 :0] dout
	);

	genvar i, j, j1, j2;

/*
	// This stuff moved a cycle back to range_info_process.v

	// Break down range_info into ranges_active and ranges_shift.
	//
	// MSB in range_info is range_active bit.
	// Other bits are 'shift_count' bits.
	//
	wire [RANGES_MAX-1:0] ranges_active;
	wire [RANGE_INFO_MSB-1:0] ranges_shift [RANGES_MAX-1:0];
	
	generate
	for (i=0; i < RANGES_MAX; i=i+1)
	begin: range_info_gen
	
		assign ranges_active[i] = range_info [(i+1) * (RANGE_INFO_MSB+1) - 1];
		assign ranges_shift[i] = range_info [(i+1) * (RANGE_INFO_MSB+1) - 2 -:RANGE_INFO_MSB];
		
	end
	endgenerate


	// Determine if resulting char to be taken from range,
	// and shift value.
	// A collision is possible (attempt to insert 2+ ranges into same position),
	// in that case character in that position is undefined.
	//
	wire [WORD_MAX_LEN-1:0] if_range;
	wire [RANGE_INFO_MSB-1:0] range_shift_val [WORD_MAX_LEN-1:0];

	generate
	for (i=0; i < WORD_MAX_LEN; i=i+1)
	begin: if_range_gen
	
		wire [RANGES_MAX-1:0] use_range;
		wire [RANGE_INFO_MSB-1:0] use_shift_val [RANGES_MAX-1:0];
	
		for (j=0; j < RANGES_MAX; j=j+1)
		begin: use_range_gen
			
			assign use_range[j] = ranges_active[j] && ranges_shift[j] + j == i;
			assign use_shift_val[j] = use_range[j] ? ranges_shift[j] : {RANGE_INFO_MSB{1'b0}};
			
		end
	
		assign if_range[i] = |use_range;
		
		wire [RANGE_INFO_MSB-1:0] shift_val_reduced;
		assign range_shift_val[i] = shift_val_reduced;
		
		// Reduce use_shift_val to shift_val_reduced
		for (j1=0; j1 < RANGE_INFO_MSB; j1=j1+1)
		begin: shift_val_reduce1
		
			wire [RANGES_MAX-1:0] bit_in_ranges;
			assign shift_val_reduced[j1] = |bit_in_ranges;
			
			for (j2=0; j2 < RANGES_MAX; j2=j2+1)
			begin: shift_val_reduce2
				assign bit_in_ranges[j2] = use_shift_val[j2][j1];
			end
			
		end

	end
	endgenerate
*/

	//
	// Ranges shifted. Shift is from 0 to WORD_MAX_LEN-1
	//
	wire [WORD_MAX_LEN * CHAR_BITS - 1 :0] ranges_shifted [WORD_MAX_LEN-1:0];

	generate
	for (i=0; i < WORD_MAX_LEN; i=i+1)
	begin: shifts_gen
	
		// TODO: remove warnings by cutting ranges
		assign ranges_shifted[i] = {
			//{ CHAR_BITS * (WORD_MAX_LEN-RANGES_MAX) {1'b0} },
			//ranges[(RANGES_MAX-i) * CHAR_BITS - 1 :0],
			ranges,
			{i*CHAR_BITS{1'b0}}
		};
	
	end
	endgenerate


	//
	// Resulting MUX
	//
	generate
	for (i=0; i < WORD_MAX_LEN; i=i+1)
	begin: dout_gen

		assign dout [(i+1)*CHAR_BITS-1 -:CHAR_BITS] = 
			
			// Take resulting char from ranges, using position from range_info
			if_range[i]	? ranges_shifted
					[ range_shift_val[(i+1)*RANGE_INFO_MSB-1 -:RANGE_INFO_MSB] ]
					[(i+1)*CHAR_BITS-1 -:CHAR_BITS] :
			
			//if_range[i]	? ranges_shifted [ range_shift_val[i] ] [(i+1)*CHAR_BITS-1 -:CHAR_BITS] :
			
			// Take resulting char from input word
			word [(i+1)*CHAR_BITS-1 -:CHAR_BITS];
	end
	endgenerate
	
	//assign dout = word;


endmodule

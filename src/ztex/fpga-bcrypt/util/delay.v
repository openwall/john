`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//
// After 'in' is asserted for 2**NBITS cycles,
// 'out' gets asserted.
// Deassertion of 'in' resets count and
// deasserts 'out' in 1 cycle.
// 
module delay #(
	parameter NBITS = 3
	)(
	input CLK,
	input in,
	output reg out = 0
	);
	
	localparam LSBIT = NBITS > 4 ? NBITS-4 : 1;
	
	reg [NBITS-1:0] counter = 0;
	always @(posedge CLK)
		if (~in) begin
			counter <= 0;
			out <= 0;
		end
		else begin
			if (in & ~out)
				counter <= counter + 1'b1;
			out <= &counter[NBITS-1:LSBIT];
		end

endmodule

/*
	reg [NBITS-1:0] counter = 0;
	
	always @(posedge CLK) begin
		if (~in) begin
			counter <= 0;
			out <= 0;
		end
		else begin
			if (in & ~out)//(&counter))
				counter <= counter + 1'b1;
			out <= &counter[NBITS-1:1];
		end
	end

module delay32 #(
	parameter NBITS_MINUS5 = 4
	)(
	input CLK,
	input in,
	output out
	);

	reg [31:0] shreg = 0;
	reg shreg_active = 0;

	wire shreg_in = shreg[31] 
	
	always @(posedge CLK) begin
		if (in & shreg_active)
			shreg_active <= 1;
		shreg[31:0] <= { shreg[30:0],
	end

endmodule
*/
/*
	wire [NUM_DIGITS:0] carry;

	genvar i;
	generate
	for (i=N; i > 0; i=i>>5) begin:digits
	
		localparam BASE = 32;
		
		reg zero = 1;
		reg [BASE-1:0] shift = 0;

		assign carry[i+1] = ~zero & shift[BASE-1];
		
		always @(posedge CLK)
			if (rst_phase1)
				shift[BASE-1:0] <= { shift[BASE-2:0], 1'b0 };
			else if (rst_phase2)
				zero <= 1;
			else if (carry[i]) begin
				shift[BASE-1:0] <= { shift[BASE-2:0], zero };
				if (zero)
					zero <= 0;
				else if (carry[i+1])
					zero <= 1;
			end
			
	end
	endgenerate
*/
		

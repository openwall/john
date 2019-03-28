`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

module core_dout_proc (
	input CLK,
	
	input [3:0] core_dout_in,
	output reg core_dout_ready = 1,
	output [3:0] dout,
	output reg empty = 1,
	input rd_en,
	output reg err_core_dout = 0
	);

	reg [3:0] core_dout = 0;
	always @(posedge CLK)
		core_dout <= core_dout_in;

	// Output from the core is stored in 4x6 bit memory
	reg [2:0] count = 0;
	reg [3:0] data [5:0];
	assign dout = data[count];
		
	always @(posedge CLK) begin
		if (empty & count == 0 & core_dout[0]) begin
			data[count] <= core_dout;
			count <= count + 1'b1;
			if (~core_dout_ready)
				err_core_dout <= 1;
			core_dout_ready <= 0;
		end
		else if (empty & count != 0) begin
			data[count] <= core_dout;
			if (count == 5 || count == 1 & ~core_dout[1]) begin
				count <= 0;
				empty <= 0;
			end
			else
				count <= count + 1'b1;
			if (count == 1 & ~core_dout[1] & ~core_dout[0]) // !EQUAL & !BATCH_COMPLETE
				err_core_dout <= 1;
		end
		
		else if (~empty & rd_en) begin
			if (count == 5 || count == 1 & ~dout[1]) begin // !EQUAL
				count <= 0;
				empty <= 1;
				core_dout_ready <= 1;
			end
			else
				count <= count + 1'b1;
		end
		
	end

	
endmodule

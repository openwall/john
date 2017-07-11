`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

//**********************************************************
//
// Provides active 'clk_en' for 1 'clk' cycle per 1 'async' pulse
//
//**********************************************************

module async2sync(
	input async,
	input clk,
	output reg clk_en = 0
	);

	reg async_r;
	always @(posedge clk or posedge async)
		if (async)
			async_r <= 1'b1;
		else if (done || !init_done)
			async_r <= 0;

	reg done = 0;
	reg init_done = 0;
	
	always @(posedge clk) begin
		if (!async && !init_done)
			init_done <= 1;
			
		if (async_r && init_done)
			if (!clk_en && !done) begin
				clk_en <= 1;
				done <= 1;
			end
			else
				clk_en <= 0;
		else
			done <= 0;
	end
	
endmodule

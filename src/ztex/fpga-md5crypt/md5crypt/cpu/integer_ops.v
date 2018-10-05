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


module integer_ops #(
	parameter WIDTH = 16
	)(
	input CLK,

	input [WIDTH-1:0] dina,
	input [7:0] dinb,
	input en, in_cf,
	
	input [5:0] iops,
	input [1:0] iop_grp2_select,
	
	output reg [1:0] dout_select = 0,
	output reg [WIDTH-1:0] dout1 = 0, dout3 = 0,
	output [WIDTH-1:0] dout2,
	output flag_cf, flag_of, flag_zf
	);

	assign { iop_addsub, iop_sub, iop_use_cf,
		iop_grp2, iop_grp3, iop_shr1 } = iops;


	wire [WIDTH-1+1:0] addsub_result = iop_sub
		? dina - dinb - (iop_use_cf ? in_cf : 1'b0)
		: dina + dinb + (iop_use_cf ? in_cf : 1'b0);
	assign flag_cf = addsub_result[WIDTH-1+1];

	// grp2 includes INC_RST, MV_R_C, AND_R_C
	// 8-bit operation; upper 24 zeroed
	reg [7:0] reg_grp2 = 0;
	wire [7:0] grp2_result =
		iop_grp2_select == 2'd1 ?
			(dina[7:0] == dinb ? 8'b0 : dina[7:0] + 1'b1) :
		iop_grp2_select == 2'd2 ? (dina[7:0] & dinb) :
		dinb;

	// grp3 includes SHR1, MV_R_R
	wire [WIDTH-1:0] grp3_result = iop_shr1 ? { 1'b0, dina[WIDTH-1:1] } : dina;
	// Removal of MV_R_R (usage of SUB_R_C instead) would save 4 LUT
	//wire [31:0] grp3_result = { 1'b0, dina[31:1] };

	always @(posedge CLK) if (en) begin
		if (iop_addsub)
			dout1 <= addsub_result[WIDTH-1:0];
		
		if (iop_grp2)
			reg_grp2 <= grp2_result;
		
		if (iop_grp3)
			dout3 <= grp3_result;
		
		dout_select <=
			iop_addsub	? 2'd1 :
			iop_grp2		? 2'd2 :
			iop_grp3		? 2'd3 :
			2'd0;
	end

	assign dout2 = { {WIDTH-8{1'b0}}, reg_grp2 };
	
	assign flag_zf = dina[WIDTH-1:8] == 0
		& (iop_shr1 ? dina[7:0] == 0 : dina[7:0] == dinb);

	assign flag_of = dina[0];
	
endmodule

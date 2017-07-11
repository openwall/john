`timescale 1ns / 1ns
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// Final permutation, FP = IP^(-1)
module IP1(
	input [63:0] din,
	output [63:0] dout
	);

	assign dout = {
		din[24],	din[56],	din[16],	din[48],	din[8],	din[40],	din[0],	din[32],	
		din[25],	din[57],	din[17],	din[49],	din[9],	din[41],	din[1],	din[33],	
		din[26],	din[58],	din[18],	din[50],	din[10],	din[42],	din[2],	din[34],	
		din[27],	din[59],	din[19],	din[51],	din[11],	din[43],	din[3],	din[35],	
		din[28],	din[60],	din[20],	din[52],	din[12],	din[44],	din[4],	din[36],	
		din[29],	din[61],	din[21],	din[53],	din[13],	din[45],	din[5],	din[37],	
		din[30],	din[62],	din[22],	din[54],	din[14],	din[46],	din[6],	din[38],	
		din[31],	din[63],	din[23],	din[55],	din[15],	din[47],	din[7],	din[39]
	};

endmodule

`timescale 1ns / 1ns
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */


module rotate_1or2_pc2(
	input rotate2,
	input [55:0] CiDi_in,
	output [55:0] CiDi_out,
	output [47:0] k
	);

	wire [27:0] Ci = CiDi_in[27:0];
	wire [27:0] Di = CiDi_in[55:28];
	wire [55:0] cd;
	assign cd = rotate2 ?
		{ Di[1], Di[0], Di[27:2], Ci[1], Ci[0], Ci[27:2] } :
		{ Di[0], Di[27:1], Ci[0], Ci[27:1] };
	
	assign CiDi_out = cd;

	assign k = {
		cd[31], cd[28], cd[35], cd[49], cd[41], cd[45], cd[52], cd[33], cd[55], cd[38], cd[48], cd[43],
		cd[47], cd[32], cd[44], cd[50], cd[39], cd[29], cd[54], cd[46], cd[36], cd[30], cd[51], cd[40],
		
		cd[1], cd[12], cd[19], cd[26], cd[6], cd[15], cd[7], cd[25], cd[3], cd[11], cd[18], cd[22],
		cd[9], cd[20], cd[5], cd[14], cd[27], cd[2], cd[4], cd[0], cd[23], cd[10], cd[16], cd[13]
		};

endmodule

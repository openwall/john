`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// Converts 8 ASCII characters (7 bit each) into 64-bit
// exactly like crypt(3) is doing
// for further use in PC1

module crypt3_ascii2bin(
	input [55:0] din,
	output [63:0] dout
	);

	assign dout = {
		1'b0, din[49], din[50], din[51], din[52], din[53], din[54], din[55],
		1'b0, din[42], din[43], din[44], din[45], din[46], din[47], din[48],
		1'b0, din[35], din[36], din[37], din[38], din[39], din[40], din[41],
		1'b0, din[28], din[29], din[30], din[31], din[32], din[33], din[34],

		1'b0, din[21], din[22], din[23], din[24], din[25], din[26], din[27],
		1'b0, din[14], din[15], din[16], din[17], din[18], din[19], din[20],
		1'b0, din[7], din[8], din[9], din[10], din[11], din[12], din[13],
		1'b0, din[0], din[1], din[2], din[3], din[4], din[5], din[6]
	};

endmodule

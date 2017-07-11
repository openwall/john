`timescale 1ns / 1ps
/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// ******************************************************************
// * Permuted-choice 1 from the key bits to yield C and D.
// * Note that bits 8,16... are left out:
// * They are intended for a parity check.
// ******************************************************************

module pc1(
	input [64:1] din,
	output [55:0] dout
	);

	assign dout = {
		din[4], din[12], din[20], din[28], din[5], din[13], din[21],
		din[29], din[37], din[45], din[53], din[61], din[6], din[14],
		din[22], din[30], din[38], din[46], din[54], din[62], din[7],
		din[15], din[23], din[31], din[39], din[47], din[55], din[63],

		din[36], din[44], din[52], din[60], din[3], din[11], din[19],
		din[27], din[35], din[43], din[51], din[59], din[2], din[10],
		din[18], din[26], din[34], din[42], din[50], din[58], din[1],
		din[9], din[17], din[25], din[33], din[41], din[49], din[57]
	};

endmodule

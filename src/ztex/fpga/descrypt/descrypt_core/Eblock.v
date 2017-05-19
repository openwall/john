/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

`include "descrypt.vh"


module Eblock(
	input [`SALT_MSB:0] salt,
	input [31:0] R,
	output [47:0] result
	);

assign result = {

	R[0], R[31], R[30], R[29], R[28], R[27], R[28], R[27], R[26], R[25], R[24], R[23],

	salt[11]? R[8] : R[24],
	salt[10]? R[7] : R[23],
	salt[9] ? R[6] : R[22],
	salt[8] ? R[5] : R[21],
	salt[7] ? R[4] : R[20],
	salt[6] ? R[3] : R[19],
	salt[5] ? R[4] : R[20],
	salt[4] ? R[3] : R[19],
	salt[3] ? R[2] : R[18],
	salt[2] ? R[1] : R[17],
	salt[1] ? R[0] : R[16],
	salt[0] ? R[31] : R[15],

	R[16], R[15], R[14], R[13], R[12], R[11], R[12], R[11], R[10], R[9], R[8], R[7],

	!salt[11]? R[8] : R[24],
	!salt[10]? R[7] : R[23],
	!salt[9] ? R[6] : R[22],
	!salt[8] ? R[5] : R[21],
	!salt[7] ? R[4] : R[20],
	!salt[6] ? R[3] : R[19],
	!salt[5] ? R[4] : R[20],
	!salt[4] ? R[3] : R[19],
	!salt[3] ? R[2] : R[18],
	!salt[2] ? R[1] : R[17],
	!salt[1] ? R[0] : R[16],
	!salt[0] ? R[31] : R[15]

};


endmodule

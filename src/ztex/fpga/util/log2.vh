/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`ifndef _LOG2_VH_
`define _LOG2_VH_

`define MSB(x) ( \
	//x >= *65536 ?: \
	x >= 256 *65536 ? 24 : \
	x >= 128 *65536 ? 23 : \
	x >= 64 *65536 ? 22 : \
	x >= 32 *65536 ? 21 : \
	x >= 16 *65536 ? 20 : \
	x >= 8 *65536 ? 19 : \
	x >= 4 *65536 ? 18 : \
	x >= 2 *65536 ? 17 : \
	x >= 65536 ? 16 : \
	x >= 32768 ? 15 : \
	x >= 16384 ? 14 : \
	x >= 8192 ?	13 : \
	x >= 4096 ? 12 : \
	x >= 2048 ? 11 : \
	x >= 1024 ? 10 : \
	x >= 512 ? 9 : \
	x >= 256 ? 8 : \
	x >= 128 ? 7 : \
	x >= 64 ? 6 : \
	x >= 32 ? 5 : \
	x >= 16 ? 4 : \
	x >= 8 ? 3 : \
	x >= 4 ? 2 : \
	x >= 2 ? 1 : \
	x >= 1 ? 0 : \
	x == 0 ? 0 : \
	-1 )

`endif

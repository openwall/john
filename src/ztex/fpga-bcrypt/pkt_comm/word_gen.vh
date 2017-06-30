/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

// Extra stage suggested if BRAM is used.
localparam EXTRA_REGISTER_STAGE = 1;

localparam	OP_STATE_READY = 0,
				OP_STATE_START = 1,
				OP_STATE_EXTRA_STAGE = 2,
				OP_STATE_NEXT_CHAR = 3,
				OP_STATE_NEXT_WORD = 4,
				OP_STATE_DONE = 5;
				

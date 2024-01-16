/*
 * This software is
 * Copyright (c) 2011-2015 JimF,
 * Copyright (c) 2011-2015 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef __SSE_INTRINS_LOAD_FLAGS__
#define __SSE_INTRINS_LOAD_FLAGS__

/***************************************************************
 * WARNING!!!! any changes to these numbers requires a new
 * build of simd-intrinsics-32.S and simd-intrinsics-64.S
 ***************************************************************/

/*
 * SSEi_MIXED_IN
 * Input is a ready-to-use array of 16xCOEF ints that are properly SIMD
 * interleaved, cleaned, appended with 0x80 and has a proper a length word.
 * The data will be copied to stack workspace.
 *
 * SSEi_FLAT_IN
 * Input is an array of 64xCOEF (128xCOEF_64 for 64 bit crypts) byte 'flat'
 * values, the hash function has to shuffle it. But 0x80 and length must be
 * in place.
 *
 * SSEi_HALF_IN
 * Input is like SSEi_MIXED_IN, but length must be exactly half the block,
 * and the second half is unused (the implementation takes care of the 0x80
 * and the length field on its own). Currently only implemented for SHA-512.
 *
 * SSEi_FLAT_OUT
 * Output will be just as from OpenSSL. Swapped if applicable, not interleaved.
 * This should only be used for "final" crypt (and only for slow formats).
 *
 * SSEi_RELOAD
 * No init; state from last crypt is held in output buffer.
 *
 * SSEi_RELOAD_INP_FMT
 * No init; state from last crypt is held in output buffer. However, it is in
 * 'INPUT' format. This is a no-op unless PARA > 1.
 *
 * SSEi_OUTPUT_AS_INP_FMT
 * Write final output using 'INPUT' format. Will not matter unless PARA > 1
 *
 * SSEi_REVERSE_STEPS
 * Reverse some steps, at minimum the "a = a + init". Only valid if not doing
 * reload, and if format does corresponding things in binary() et. al.
 *
 * SSEi_2BUF_INPUT
 * Input array is 2x in size, for a possible max input of 64+55 (119) bytes.
 *
 * SSEi_2BUF_INPUT_FIRST_BLK
 * Input array 2x in size. This is the first block, so we must rotate element
 * 14/15 if in flat mode.
 *
 * SSEi_4BUF_INPUT
 * Input array is 4x in size (This is seen in the dynamic type, for sha256. We
 * have 256 byte input buffers there).
 *
 * SSEi_4BUF_INPUT_FIRST_BLK
 * Input array 4x in size. This is the first block, so we must rotate element
 * 14/15 if in flat mode.
 *
 * SSEi_FLAT_RELOAD_SWAPLAST
 * Similar to SSEi_4BUF_INPUT_FIRST_BLK, but simply says we will have more
 * buffers coming after this one. Currently only enabled/used for SHA-256.
 *
 * SSEi_CRYPT_SHA224     use SHA224 IV.
 * SSEi_CRYPT_SHA384     use SHA384 IV.
 * These are specific to SHA2 hashes. Reusing the same bit, since only 1 will
 * be used (i.e. it is not valid to do SSE_CRYPT_SHA224|SSE_CRYPT_SHA224)
 *
 * WARNING, SHA224 requires a FULL SHA256 width output buffer, and SHA384
 * requires a full SHA512 width output buffer.  This is to allow proper
 * reloading and doing multi-limb crypts.
 *
 * SSEi_LOOP
 * Iterated hashing, with hash output reused as input for the next iteration.
 * Currently supported only for SHA-512 and only along with SSEi_MIXED_IN or
 * SSEi_HALF_IN.
 * Without SSEi_FLAT_OUT, *reload_state is reused as the iteration count (and
 * is clobbered), and the final output is in the input format (full or half).
 * With SSEi_FLAT_OUT, reload_state is reused as pointer to the end of the
 * multi-hash output, which is in a format similar to that of SSEi_FLAT_OUT
 * alone but without byte order swapping, and the input data is overwritten
 * with the final output in the SSEi_HALF_IN format, which this mode requires.
 */

typedef enum {
	SSEi_NO_OP                   = 0x0, /* No-op */
	SSEi_MIXED_IN                = 0x0,
	SSEi_FLAT_IN                 = 0x1,
	SSEi_HALF_IN                 = 0x2,
	SSEi_FLAT_OUT                = 0x4,
	SSEi_RELOAD                  = 0x8,
	SSEi_RELOAD_INP_FMT          = 0x10 | SSEi_RELOAD,
	SSEi_OUTPUT_AS_INP_FMT       = 0x20,
	SSEi_REVERSE_STEPS           = 0x40,
	SSEi_REVERSE_3STEPS          = 0x4000,
	SSEi_2BUF_INPUT              = 0x80,
	SSEi_2BUF_INPUT_FIRST_BLK    = 0x100 | SSEi_2BUF_INPUT,
	SSEi_4BUF_INPUT              = 0x200,
	SSEi_4BUF_INPUT_FIRST_BLK    = 0x400 | SSEi_4BUF_INPUT,
	SSEi_FLAT_RELOAD_SWAPLAST    = 0x800,
	SSEi_CRYPT_SHA224            = 0x1000,
	SSEi_CRYPT_SHA384            = 0x1000,
	SSEi_OUTPUT_AS_2BUF_INP_FMT  = 0x2000 | SSEi_OUTPUT_AS_INP_FMT,
	SSEi_LOOP                    = 0x8000
} SSEi_FLAGS;


#endif /* __SSE_INTRINS_LOAD_FLAGS__  */

/* $Id: sph_sha1.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * SHA-1 interface.
 *
 * SHA-1 is described in FIPS 180-1 (now superseded by FIPS 180-2, but the
 * description of SHA-1 is still included and has not changed). FIPS
 * standards can be found at: http://csrc.nist.gov/publications/fips/
 *
 * @warning   A theoretical collision attack against SHA-1, with work
 * factor 2^63, has been published. SHA-1 should not be used in new
 * protocol designs.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @file     sph_sha1.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_SHA1_H__
#define SPH_SHA1_H__

#include <stddef.h>
#include "sph_types.h"

/**
 * Output size (in bits) for SHA-1.
 */
#define SPH_SIZE_sha1   160

/**
 * This structure is a context for SHA-1 computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * a SHA-1 computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running SHA-1 computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char buf[64];    /* first field, for alignment */
	sph_u32 val[5];
#if SPH_64
	sph_u64 count;
#else
	sph_u32 count_high, count_low;
#endif
#endif
} sph_sha1_context;

/**
 * Initialize a SHA-1 context. This process performs no memory allocation.
 *
 * @param cc   the SHA-1 context (pointer to a <code>sph_sha1_context</code>)
 */
void sph_sha1_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the SHA-1 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_sha1(void *cc, const void *data, size_t len);

/**
 * Terminate the current SHA-1 computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to
 * accomodate the result (20 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the SHA-1 context
 * @param dst   the destination buffer
 */
void sph_sha1_close(void *cc, void *dst);

/**
 * Add a few additional bits (0 to 7) to the current computation, then
 * terminate it and output the result in the provided buffer, which must
 * be wide enough to accomodate the result (20 bytes). If bit number i
 * in <code>ub</code> has value 2^i, then the extra bits are those
 * numbered 7 downto 8-n (this is the big-endian convention at the byte
 * level). The context is automatically reinitialized.
 *
 * @param cc    the SHA-1 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the destination buffer
 */
void sph_sha1_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst);

/**
 * Apply the SHA-1 compression function on the provided data. The
 * <code>msg</code> parameter contains the 16 32-bit input blocks,
 * as numerical values (hence after the big-endian decoding). The
 * <code>val</code> parameter contains the 5 32-bit input blocks for
 * the compression function; the output is written in place in this
 * array.
 *
 * @param msg   the message block (16 values)
 * @param val   the function 160-bit input and output
 */
void sph_sha1_comp(const sph_u32 msg[16], sph_u32 val[5]);

#endif

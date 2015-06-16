/* $Id: sph_md2.h 154 2010-04-26 17:00:24Z tp $ */
/**
 * MD2 interface.
 *
 * MD2 is described in RFC 1319. Note: RFC 1319 contains both pseudo-code
 * for the algorithm, and a C implementation. The pseudo-code is erroneous;
 * an errata is available on: http://www.rfc-editor.org/errata.html .
 * This implementation is compatible with the corrected MD2 and the C
 * reference implementation.
 *
 * @warning   A theoretical attack on MD2 has been published, which finds
 * a second preimage with work factor 2^104, instead of the 2^128 which
 * a good hash function with 128-bit output should feature. Use only with
 * care.
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
 * @file     sph_md2.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_MD2_H__
#define SPH_MD2_H__

#include <stddef.h>
#include "sph_types.h"

/**
 * Output size (in bits) for MD2.
 */
#define SPH_SIZE_md2   128

/**
 * This structure is a context for MD2 computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * a MD2 computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running MD5 computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char buf[16];    /* first field, for alignment */
	union {
		unsigned char X[48];
		sph_u32 W[12];
	} u;
	unsigned char C[16];
	unsigned L, count;
#endif
} sph_md2_context;

/**
 * Initialize a MD2 context. This process performs no memory allocation.
 *
 * @param cc   the MD2 context (pointer to a <code>sph_md2_context</code>)
 */
void sph_md2_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the MD2 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_md2(void *cc, const void *data, size_t len);

/**
 * Terminate the current MD2 computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to
 * accommodate the result (16 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the MD2 context
 * @param dst   the destination buffer
 */
void sph_md2_close(void *cc, void *dst);

#endif

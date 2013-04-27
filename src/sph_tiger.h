/* $Id: sph_tiger.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * Tiger / Tiger-2 interface.
 *
 * Tiger has been published in: R. Anderson, E. Biham, "Tiger: A Fast
 * New Hash Function", Fast Software Encryption - FSE'96, LNCS 1039,
 * Springer (1996), pp. 89--97.
 *
 * Tiger2 has never been formally published, but it was described as
 * identical to Tiger, except for the padding which is the same in
 * Tiger2 as it is in MD4. Fortunately, an implementation of Tiger2
 * was submitted to NESSIE, which produced test vectors; the sphlib
 * implementation of Tiger2 is compatible with the NESSIE test vectors.
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
 * @file     sph_tiger.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_TIGER_H__
#define SPH_TIGER_H__

#include <stddef.h>
#include "sph_types.h"

#if SPH_64

/**
 * Output size (in bits) for Tiger.
 */
#define SPH_SIZE_tiger   192

/**
 * Output size (in bits) for Tiger2.
 */
#define SPH_SIZE_tiger2   192

/**
 * This structure is a context for Tiger computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * a Tiger computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running Tiger computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char buf[64];    /* first field, for alignment */
	sph_u64 val[3];
	sph_u64 count;
#endif
} sph_tiger_context;

/**
 * Initialize a Tiger context. This process performs no memory allocation.
 *
 * @param cc   the Tiger context (pointer to
 *             a <code>sph_tiger_context</code>)
 */
void sph_tiger_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the Tiger context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_tiger(void *cc, const void *data, size_t len);

/**
 * Terminate the current Tiger computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to
 * accomodate the result (24 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the Tiger context
 * @param dst   the destination buffer
 */
void sph_tiger_close(void *cc, void *dst);

/**
 * Apply the Tiger compression function on the provided data. The
 * <code>msg</code> parameter contains the 8 64-bit input blocks,
 * as numerical values (hence after the little-endian decoding). The
 * <code>val</code> parameter contains the 3 64-bit input blocks for
 * the compression function; the output is written in place in this
 * array.
 *
 * @param msg   the message block (8 values)
 * @param val   the function 192-bit input and output
 */
void sph_tiger_comp(const sph_u64 msg[8], sph_u64 val[3]);

/**
 * This structure is a context for Tiger2 computations. It is identical
 * to the Tiger context, and they may be freely exchanged, since the
 * difference between Tiger and Tiger2 resides solely in the padding, which
 * is computed only in the last computation step.
 */
typedef sph_tiger_context sph_tiger2_context;

#ifdef DOXYGEN_IGNORE
/**
 * Initialize a Tiger2 context. This function is identical to
 * <code>sph_tiger_init()</code>.
 *
 * @param cc   the Tiger2 context (pointer to
 *             a <code>sph_tiger2_context</code>)
 */
void sph_tiger2_init(void *cc);
#endif

#ifndef DOXYGEN_IGNORE
#define sph_tiger2_init   sph_tiger_init
#endif

#ifdef DOXYGEN_IGNORE
/**
 * Process some data bytes. This function is identical to
 * <code>sph_tiger()</code>.
 *
 * @param cc     the Tiger2 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_tiger2(void *cc, const void *data, size_t len);
#endif

#ifndef DOXYGEN_IGNORE
#define sph_tiger2   sph_tiger
#endif

/**
 * Terminate the current Tiger2 computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to
 * accomodate the result (24 bytes). The context is automatically
 * reinitialized. Note that this function is NOT identical to
 * <code>sph_tiger2_close()</code>: this is the exact and unique point
 * where Tiger and Tiger2 differ.
 *
 * @param cc    the Tiger context
 * @param dst   the destination buffer
 */
void sph_tiger2_close(void *cc, void *dst);

#ifdef DOXYGEN_IGNORE
/**
 * Apply the Tiger2 compression function, which is identical to the Tiger
 * compression function.
 *
 * @param msg   the message block (8 values)
 * @param val   the function 192-bit input and output
 */
void sph_tiger2_comp(const sph_u64 msg[8], sph_u64 val[3]);
#endif

#ifndef DOXYGEN_IGNORE
#define sph_tiger2_comp   sph_tiger_comp
#endif

#endif

#endif

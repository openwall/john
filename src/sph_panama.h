/* $Id: sph_panama.h 154 2010-04-26 17:00:24Z tp $ */
/**
 * PANAMA interface.
 *
 * PANAMA has been published in: J. Daemen and C. Clapp, "Fast Hashing
 * and Stream Encryption with PANAMA", Fast Software Encryption -
 * FSE'98, LNCS 1372, Springer (1998), pp. 60--74.
 *
 * PANAMA is not fully defined with regards to endianness and related
 * topics. This implementation follows strict little-endian conventions:
 * <ul>
 * <li>Each 32-byte input block is split into eight 32-bit words, the
 * first (leftmost) word being numbered 0.</li>
 * <li>Each such 32-bit word is decoded from memory in little-endian
 * convention.</li>
 * <li>The additional padding bit equal to "1" is added by considering
 * the least significant bit in a byte to come first; practically, this
 * means that a single byte of value 0x01 is appended to the (byte-oriented)
 * message, and then 0 to 31 bytes of value 0x00.</li>
 * <li>The output consists of eight 32-bit words; the word numbered 0 is
 * written first (in leftmost position) and it is encoded in little-endian
 * convention.
 * </ul>
 * With these conventions, PANAMA is sometimes known as "PANAMA-LE". The
 * PANAMA reference implementation uses our conventions for input, but
 * prescribes no convention for output.
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
 * @file     sph_panama.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_PANAMA_H__
#define SPH_PANAMA_H__

#include <stddef.h>
#include "sph_types.h"

/**
 * Output size (in bits) for PANAMA.
 */
#define SPH_SIZE_panama   256

/**
 * This structure is a context for PANAMA computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * a PANAMA computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running PANAMA computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char data[32];   /* first field, for alignment */
	unsigned data_ptr;

	sph_u32 buffer[32][8];
	unsigned buffer_ptr;

	sph_u32 state[17];
#endif
} sph_panama_context;

/**
 * Initialize a PANAMA context. This process performs no memory allocation.
 *
 * @param cc   the PANAMA context (pointer to a <code>sph_panama_context</code>)
 */
void sph_panama_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the PANAMA context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_panama(void *cc, const void *data, size_t len);

/**
 * Terminate the current PANAMA computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to
 * accommodate the result (32 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the PANAMA context
 * @param dst   the destination buffer
 */
void sph_panama_close(void *cc, void *dst);

#endif

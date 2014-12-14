/* $Id: sph_haval.h 218 2010-06-08 17:06:34Z tp $ */
/**
 * HAVAL interface.
 *
 * HAVAL is actually a family of 15 hash functions, depending on whether
 * the internal computation uses 3, 4 or 5 passes, and on the output
 * length, which is 128, 160, 192, 224 or 256 bits. This implementation
 * provides interface functions for all 15, which internally map to
 * three cores (depending on the number of passes). Note that output
 * lengths other than 256 bits are not obtained by a simple truncation
 * of a longer result; the requested length is encoded within the
 * padding data.
 *
 * HAVAL was published in: Yuliang Zheng, Josef Pieprzyk and Jennifer
 * Seberry: "HAVAL -- a one-way hashing algorithm with variable length
 * of output", Advances in Cryptology -- AUSCRYPT'92, Lecture Notes in
 * Computer Science, Vol.718, pp.83-104, Springer-Verlag, 1993.
 *
 * This paper, and a reference implementation, are available on the
 * Calyptix web site: http://labs.calyptix.com/haval.php
 *
 * The HAVAL reference paper is quite unclear on the data encoding
 * details, i.e. endianness (both byte order within a 32-bit word, and
 * word order within a message block). This implementation has been
 * made compatible with the reference implementation referenced above.
 *
 * @warning   A collision for HAVAL-128/3 (HAVAL with three passes and
 * 128-bit output) has been published; this function is thus considered
 * as cryptographically broken. The status for other variants is unclear;
 * use only with care.
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
 * @file     sph_haval.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_HAVAL_H__
#define SPH_HAVAL_H__

#include <stddef.h>
#include "sph_types.h"

/**
 * Output size (in bits) for HAVAL-128/3.
 */
#define SPH_SIZE_haval128_3   128

/**
 * Output size (in bits) for HAVAL-128/4.
 */
#define SPH_SIZE_haval128_4   128

/**
 * Output size (in bits) for HAVAL-128/5.
 */
#define SPH_SIZE_haval128_5   128

/**
 * Output size (in bits) for HAVAL-160/3.
 */
#define SPH_SIZE_haval160_3   160

/**
 * Output size (in bits) for HAVAL-160/4.
 */
#define SPH_SIZE_haval160_4   160

/**
 * Output size (in bits) for HAVAL-160/5.
 */
#define SPH_SIZE_haval160_5   160

/**
 * Output size (in bits) for HAVAL-192/3.
 */
#define SPH_SIZE_haval192_3   192

/**
 * Output size (in bits) for HAVAL-192/4.
 */
#define SPH_SIZE_haval192_4   192

/**
 * Output size (in bits) for HAVAL-192/5.
 */
#define SPH_SIZE_haval192_5   192

/**
 * Output size (in bits) for HAVAL-224/3.
 */
#define SPH_SIZE_haval224_3   224

/**
 * Output size (in bits) for HAVAL-224/4.
 */
#define SPH_SIZE_haval224_4   224

/**
 * Output size (in bits) for HAVAL-224/5.
 */
#define SPH_SIZE_haval224_5   224

/**
 * Output size (in bits) for HAVAL-256/3.
 */
#define SPH_SIZE_haval256_3   256

/**
 * Output size (in bits) for HAVAL-256/4.
 */
#define SPH_SIZE_haval256_4   256

/**
 * Output size (in bits) for HAVAL-256/5.
 */
#define SPH_SIZE_haval256_5   256

/**
 * This structure is a context for HAVAL computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * a HAVAL computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running HAVAL computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char buf[128];    /* first field, for alignment */
	sph_u32 s0, s1, s2, s3, s4, s5, s6, s7;
	unsigned olen, passes;
#if SPH_64
	sph_u64 count;
#else
	sph_u32 count_high, count_low;
#endif
#endif
} sph_haval_context;

/**
 * Type for a HAVAL-128/3 context (identical to the common context).
 */
typedef sph_haval_context sph_haval128_3_context;

/**
 * Type for a HAVAL-128/4 context (identical to the common context).
 */
typedef sph_haval_context sph_haval128_4_context;

/**
 * Type for a HAVAL-128/5 context (identical to the common context).
 */
typedef sph_haval_context sph_haval128_5_context;

/**
 * Type for a HAVAL-160/3 context (identical to the common context).
 */
typedef sph_haval_context sph_haval160_3_context;

/**
 * Type for a HAVAL-160/4 context (identical to the common context).
 */
typedef sph_haval_context sph_haval160_4_context;

/**
 * Type for a HAVAL-160/5 context (identical to the common context).
 */
typedef sph_haval_context sph_haval160_5_context;

/**
 * Type for a HAVAL-192/3 context (identical to the common context).
 */
typedef sph_haval_context sph_haval192_3_context;

/**
 * Type for a HAVAL-192/4 context (identical to the common context).
 */
typedef sph_haval_context sph_haval192_4_context;

/**
 * Type for a HAVAL-192/5 context (identical to the common context).
 */
typedef sph_haval_context sph_haval192_5_context;

/**
 * Type for a HAVAL-224/3 context (identical to the common context).
 */
typedef sph_haval_context sph_haval224_3_context;

/**
 * Type for a HAVAL-224/4 context (identical to the common context).
 */
typedef sph_haval_context sph_haval224_4_context;

/**
 * Type for a HAVAL-224/5 context (identical to the common context).
 */
typedef sph_haval_context sph_haval224_5_context;

/**
 * Type for a HAVAL-256/3 context (identical to the common context).
 */
typedef sph_haval_context sph_haval256_3_context;

/**
 * Type for a HAVAL-256/4 context (identical to the common context).
 */
typedef sph_haval_context sph_haval256_4_context;

/**
 * Type for a HAVAL-256/5 context (identical to the common context).
 */
typedef sph_haval_context sph_haval256_5_context;

/**
 * Initialize the context for HAVAL-128/3.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval128_3_context</code> structure)
 */
void sph_haval128_3_init(void *cc);

/**
 * Process some data bytes for HAVAL-128/3. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-128/3 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval128_3(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-128/3 computation. The output buffer must be wide
 * enough to accommodate the result (16 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-128/3 context
 * @param dst   the output buffer
 */
void sph_haval128_3_close(void *cc, void *dst);

/**
 * Close a HAVAL-128/3 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (16
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-128/3 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval128_3_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-128/4.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval128_4_context</code> structure)
 */
void sph_haval128_4_init(void *cc);

/**
 * Process some data bytes for HAVAL-128/4. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-128/4 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval128_4(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-128/4 computation. The output buffer must be wide
 * enough to accommodate the result (16 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-128/4 context
 * @param dst   the output buffer
 */
void sph_haval128_4_close(void *cc, void *dst);

/**
 * Close a HAVAL-128/4 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (16
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-128/4 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval128_4_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-128/5.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval128_5_context</code> structure)
 */
void sph_haval128_5_init(void *cc);

/**
 * Process some data bytes for HAVAL-128/5. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-128/5 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval128_5(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-128/5 computation. The output buffer must be wide
 * enough to accommodate the result (16 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-128/5 context
 * @param dst   the output buffer
 */
void sph_haval128_5_close(void *cc, void *dst);

/**
 * Close a HAVAL-128/5 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (16
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-128/5 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval128_5_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-160/3.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval160_3_context</code> structure)
 */
void sph_haval160_3_init(void *cc);

/**
 * Process some data bytes for HAVAL-160/3. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-160/3 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval160_3(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-160/3 computation. The output buffer must be wide
 * enough to accommodate the result (20 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-160/3 context
 * @param dst   the output buffer
 */
void sph_haval160_3_close(void *cc, void *dst);

/**
 * Close a HAVAL-160/3 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (20
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-160/3 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval160_3_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-160/4.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval160_4_context</code> structure)
 */
void sph_haval160_4_init(void *cc);

/**
 * Process some data bytes for HAVAL-160/4. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-160/4 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval160_4(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-160/4 computation. The output buffer must be wide
 * enough to accommodate the result (20 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-160/4 context
 * @param dst   the output buffer
 */
void sph_haval160_4_close(void *cc, void *dst);

/**
 * Close a HAVAL-160/4 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (20
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-160/4 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval160_3_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-160/5.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval160_5_context</code> structure)
 */
void sph_haval160_5_init(void *cc);

/**
 * Process some data bytes for HAVAL-160/5. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-160/5 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval160_5(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-160/5 computation. The output buffer must be wide
 * enough to accommodate the result (20 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-160/5 context
 * @param dst   the output buffer
 */
void sph_haval160_5_close(void *cc, void *dst);

/**
 * Close a HAVAL-160/5 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (20
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-160/5 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval160_5_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-192/3.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval192_3_context</code> structure)
 */
void sph_haval192_3_init(void *cc);

/**
 * Process some data bytes for HAVAL-192/3. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-192/3 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval192_3(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-192/3 computation. The output buffer must be wide
 * enough to accommodate the result (24 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-192/3 context
 * @param dst   the output buffer
 */
void sph_haval192_3_close(void *cc, void *dst);

/**
 * Close a HAVAL-192/3 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (24
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-192/3 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval192_3_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-192/4.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval192_4_context</code> structure)
 */
void sph_haval192_4_init(void *cc);

/**
 * Process some data bytes for HAVAL-192/4. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-192/4 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval192_4(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-192/4 computation. The output buffer must be wide
 * enough to accommodate the result (24 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-192/4 context
 * @param dst   the output buffer
 */
void sph_haval192_4_close(void *cc, void *dst);

/**
 * Close a HAVAL-192/4 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (24
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-192/4 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval192_4_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-192/5.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval192_5_context</code> structure)
 */
void sph_haval192_5_init(void *cc);

/**
 * Process some data bytes for HAVAL-192/5. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-192/5 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval192_5(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-192/5 computation. The output buffer must be wide
 * enough to accommodate the result (24 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-192/5 context
 * @param dst   the output buffer
 */
void sph_haval192_5_close(void *cc, void *dst);

/**
 * Close a HAVAL-192/5 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (24
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-192/5 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval192_5_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-224/3.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval224_3_context</code> structure)
 */
void sph_haval224_3_init(void *cc);

/**
 * Process some data bytes for HAVAL-224/3. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-224/3 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval224_3(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-224/3 computation. The output buffer must be wide
 * enough to accommodate the result (28 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-224/3 context
 * @param dst   the output buffer
 */
void sph_haval224_3_close(void *cc, void *dst);

/**
 * Close a HAVAL-224/3 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (28
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-224/3 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval224_3_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-224/4.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval224_4_context</code> structure)
 */
void sph_haval224_4_init(void *cc);

/**
 * Process some data bytes for HAVAL-224/4. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-224/4 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval224_4(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-224/4 computation. The output buffer must be wide
 * enough to accommodate the result (28 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-224/4 context
 * @param dst   the output buffer
 */
void sph_haval224_4_close(void *cc, void *dst);

/**
 * Close a HAVAL-224/4 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (28
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-224/4 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval224_4_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-224/5.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval224_5_context</code> structure)
 */
void sph_haval224_5_init(void *cc);

/**
 * Process some data bytes for HAVAL-224/5. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-224/5 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval224_5(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-224/5 computation. The output buffer must be wide
 * enough to accommodate the result (28 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-224/5 context
 * @param dst   the output buffer
 */
void sph_haval224_5_close(void *cc, void *dst);

/**
 * Close a HAVAL-224/5 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (28
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-224/5 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval224_5_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-256/3.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval256_3_context</code> structure)
 */
void sph_haval256_3_init(void *cc);

/**
 * Process some data bytes for HAVAL-256/3. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-256/3 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval256_3(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-256/3 computation. The output buffer must be wide
 * enough to accommodate the result (32 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-256/3 context
 * @param dst   the output buffer
 */
void sph_haval256_3_close(void *cc, void *dst);

/**
 * Close a HAVAL-256/3 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (32
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-256/3 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval256_3_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-256/4.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval256_4_context</code> structure)
 */
void sph_haval256_4_init(void *cc);

/**
 * Process some data bytes for HAVAL-256/4. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-256/4 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval256_4(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-256/4 computation. The output buffer must be wide
 * enough to accommodate the result (32 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-256/4 context
 * @param dst   the output buffer
 */
void sph_haval256_4_close(void *cc, void *dst);

/**
 * Close a HAVAL-256/4 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (32
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-256/4 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval256_4_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-256/5.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval256_5_context</code> structure)
 */
void sph_haval256_5_init(void *cc);

/**
 * Process some data bytes for HAVAL-256/5. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-256/5 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval256_5(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-256/5 computation. The output buffer must be wide
 * enough to accommodate the result (32 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-256/5 context
 * @param dst   the output buffer
 */
void sph_haval256_5_close(void *cc, void *dst);

/**
 * Close a HAVAL-256/5 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accommodate the result (32
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-256/5 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval256_5_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Apply the HAVAL compression function on the provided data. The
 * <code>msg</code> parameter contains the 32 32-bit input blocks,
 * as numerical values (hence after the little-endian decoding). The
 * <code>val</code> parameter contains the 8 32-bit input blocks for
 * the compression function; the output is written in place in this
 * array. This function uses three internal passes.
 *
 * @param msg   the message block (32 values)
 * @param val   the function 256-bit input and output
 */
void sph_haval_3_comp(const sph_u32 msg[32], sph_u32 val[8]);

/**
 * Apply the HAVAL compression function on the provided data. The
 * <code>msg</code> parameter contains the 32 32-bit input blocks,
 * as numerical values (hence after the little-endian decoding). The
 * <code>val</code> parameter contains the 8 32-bit input blocks for
 * the compression function; the output is written in place in this
 * array. This function uses four internal passes.
 *
 * @param msg   the message block (32 values)
 * @param val   the function 256-bit input and output
 */
void sph_haval_4_comp(const sph_u32 msg[32], sph_u32 val[8]);

/**
 * Apply the HAVAL compression function on the provided data. The
 * <code>msg</code> parameter contains the 32 32-bit input blocks,
 * as numerical values (hence after the little-endian decoding). The
 * <code>val</code> parameter contains the 8 32-bit input blocks for
 * the compression function; the output is written in place in this
 * array. This function uses five internal passes.
 *
 * @param msg   the message block (32 values)
 * @param val   the function 256-bit input and output
 */
void sph_haval_5_comp(const sph_u32 msg[32], sph_u32 val[8]);

#endif

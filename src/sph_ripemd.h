/* $Id: sph_ripemd.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * RIPEMD, RIPEMD-128 and RIPEMD-160 interface.
 *
 * RIPEMD was first described in: Research and Development in Advanced
 * Communication Technologies in Europe, "RIPE Integrity Primitives:
 * Final Report of RACE Integrity Primitives Evaluation (R1040)", RACE,
 * June 1992.
 *
 * A new, strengthened version, dubbed RIPEMD-160, was published in: H.
 * Dobbertin, A. Bosselaers, and B. Preneel, "RIPEMD-160, a strengthened
 * version of RIPEMD", Fast Software Encryption - FSE'96, LNCS 1039,
 * Springer (1996), pp. 71--82.
 *
 * This article describes both RIPEMD-160, with a 160-bit output, and a
 * reduced version called RIPEMD-128, which has a 128-bit output. RIPEMD-128
 * was meant as a "drop-in" replacement for any hash function with 128-bit
 * output, especially the original RIPEMD.
 *
 * @warning   Collisions, and an efficient method to build other collisions,
 * have been published for the original RIPEMD, which is thus considered as
 * cryptographically broken. It is also very rarely encountered, and there
 * seems to exist no free description or implementation of RIPEMD (except
 * the sphlib code, of course). As of january 2007, RIPEMD-128 and RIPEMD-160
 * seem as secure as their output length allows.
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
 * @file     sph_ripemd.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 *
 * Added RIPEMD256 and RIPEMD320, JimF, 2013.
 */

#ifndef SPH_RIPEMD_H__
#define SPH_RIPEMD_H__

#include <stddef.h>
#include "sph_types.h"

/**
 * Output size (in bits) for RIPEMD.
 */
#define SPH_SIZE_ripemd   128

/**
 * Output size (in bits) for RIPEMD-128.
 */
#define SPH_SIZE_ripemd128   128

/**
 * Output size (in bits) for RIPEMD-160.
 */
#define SPH_SIZE_ripemd160   160

/**
 * This structure is a context for RIPEMD computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * a RIPEMD computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running RIPEMD computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char buf[64];    /* first field, for alignment */
	sph_u32 val[4];
#if SPH_64
	sph_u64 count;
#else
	sph_u32 count_high, count_low;
#endif
#endif
} sph_ripemd_context;

/**
 * Initialize a RIPEMD context. This process performs no memory allocation.
 *
 * @param cc   the RIPEMD context (pointer to
 *             a <code>sph_ripemd_context</code>)
 */
void sph_ripemd_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the RIPEMD context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_ripemd(void *cc, const void *data, size_t len);

/**
 * Terminate the current RIPEMD computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to
 * accommodate the result (16 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the RIPEMD context
 * @param dst   the destination buffer
 */
void sph_ripemd_close(void *cc, void *dst);

/**
 * Apply the RIPEMD compression function on the provided data. The
 * <code>msg</code> parameter contains the 16 32-bit input blocks,
 * as numerical values (hence after the little-endian decoding). The
 * <code>val</code> parameter contains the 5 32-bit input blocks for
 * the compression function; the output is written in place in this
 * array.
 *
 * @param msg   the message block (16 values)
 * @param val   the function 128-bit input and output
 */
void sph_ripemd_comp(const sph_u32 msg[16], sph_u32 val[4]);

/* ===================================================================== */

/**
 * This structure is a context for RIPEMD-128 computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * a RIPEMD-128 computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running RIPEMD-128 computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char buf[64];    /* first field, for alignment */
	sph_u32 val[4];
#if SPH_64
	sph_u64 count;
#else
	sph_u32 count_high, count_low;
#endif
#endif
} sph_ripemd128_context;

/**
 * Initialize a RIPEMD-128 context. This process performs no memory allocation.
 *
 * @param cc   the RIPEMD-128 context (pointer to
 *             a <code>sph_ripemd128_context</code>)
 */
void sph_ripemd128_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the RIPEMD-128 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_ripemd128(void *cc, const void *data, size_t len);

/**
 * Terminate the current RIPEMD-128 computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to
 * accommodate the result (16 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the RIPEMD-128 context
 * @param dst   the destination buffer
 */
void sph_ripemd128_close(void *cc, void *dst);

/**
 * Apply the RIPEMD-128 compression function on the provided data. The
 * <code>msg</code> parameter contains the 16 32-bit input blocks,
 * as numerical values (hence after the little-endian decoding). The
 * <code>val</code> parameter contains the 5 32-bit input blocks for
 * the compression function; the output is written in place in this
 * array.
 *
 * @param msg   the message block (16 values)
 * @param val   the function 128-bit input and output
 */
void sph_ripemd128_comp(const sph_u32 msg[16], sph_u32 val[4]);

/* ===================================================================== */

/**
 * This structure is a context for RIPEMD-160 computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * a RIPEMD-160 computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running RIPEMD-160 computation
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
} sph_ripemd160_context;

/**
 * Initialize a RIPEMD-160 context. This process performs no memory allocation.
 *
 * @param cc   the RIPEMD-160 context (pointer to
 *             a <code>sph_ripemd160_context</code>)
 */
void sph_ripemd160_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the RIPEMD-160 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_ripemd160(void *cc, const void *data, size_t len);

/**
 * Terminate the current RIPEMD-160 computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to
 * accommodate the result (20 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the RIPEMD-160 context
 * @param dst   the destination buffer
 */
void sph_ripemd160_close(void *cc, void *dst);

/**
 * Apply the RIPEMD-160 compression function on the provided data. The
 * <code>msg</code> parameter contains the 16 32-bit input blocks,
 * as numerical values (hence after the little-endian decoding). The
 * <code>val</code> parameter contains the 5 32-bit input blocks for
 * the compression function; the output is written in place in this
 * array.
 *
 * @param msg   the message block (16 values)
 * @param val   the function 160-bit input and output
 */
void sph_ripemd160_comp(const sph_u32 msg[16], sph_u32 val[5]);


/****** Code added for RIPEMD256 and RIPEMD320 ****/
#define SPH_SIZE_ripemd256   256
#define SPH_SIZE_ripemd320   320

typedef struct {
	unsigned char buf[64];    /* first field, for alignment */
	sph_u32 val[8];
#if SPH_64
	sph_u64 count;
#else
	sph_u32 count_high, count_low;
#endif
} sph_ripemd256_context;
void sph_ripemd256_init(void *cc);
void sph_ripemd256(void *cc, const void *data, size_t len);
void sph_ripemd256_close(void *cc, void *dst);

typedef struct {
	unsigned char buf[64];    /* first field, for alignment */
	sph_u32 val[10];
#if SPH_64
	sph_u64 count;
#else
	sph_u32 count_high, count_low;
#endif
} sph_ripemd320_context;
void sph_ripemd320_init(void *cc);
void sph_ripemd320(void *cc, const void *data, size_t len);
void sph_ripemd320_close(void *cc, void *dst);

#endif

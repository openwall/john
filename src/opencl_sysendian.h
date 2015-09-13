/*-
 * Copyright 2007-2009 Colin Percival
 * Copyright 2015 Agnieszka Bielec
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */
#ifndef _OPENCL_SYSENDIAN_H_
#define _OPENCL_SYSENDIAN_H_

inline uint be32dec(void *pp)
{
	uchar *p = (uchar *)pp;

	return ((uint)(p[3]) + ((uint)(p[2]) << 8) +
	    ((uint)(p[1]) << 16) + ((uint)(p[0]) << 24));
}

inline void be32enc(void *pp, uint x)
{
	uchar * p = (uchar *)pp;

	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}

inline ulong be64dec(void *pp)
{
	uchar *p = (uchar *)pp;

	return ((ulong)(p[7]) + ((ulong)(p[6]) << 8) +
	    ((ulong)(p[5]) << 16) + ((ulong)(p[4]) << 24) +
	    ((ulong)(p[3]) << 32) + ((ulong)(p[2]) << 40) +
	    ((ulong)(p[1]) << 48) + ((ulong)(p[0]) << 56));
}

inline void be64enc(void *pp, ulong x)
{
	uchar * p = (uchar *)pp;

	p[7] = x & 0xff;
	p[6] = (x >> 8) & 0xff;
	p[5] = (x >> 16) & 0xff;
	p[4] = (x >> 24) & 0xff;
	p[3] = (x >> 32) & 0xff;
	p[2] = (x >> 40) & 0xff;
	p[1] = (x >> 48) & 0xff;
	p[0] = (x >> 56) & 0xff;
}


inline uint le32dec(__global void *pp)
{
	__global uchar *p = (__global uchar *)pp;

	return ((uint)(p[0]) + ((uint)(p[1]) << 8) +
	    ((uint)(p[2]) << 16) + ((uint)(p[3]) << 24));
}

inline void le32enc(__global void *pp, uint x)
{
	__global uchar * p = (__global uchar *)pp;

	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
}

inline ulong le64dec(const void *pp)
{
	const uchar *p = (uchar const *)pp;

	return ((ulong)(p[0]) + ((ulong)(p[1]) << 8) +
	    ((ulong)(p[2]) << 16) + ((ulong)(p[3]) << 24) +
	    ((ulong)(p[4]) << 32) + ((ulong)(p[5]) << 40) +
	    ((ulong)(p[6]) << 48) + ((ulong)(p[7]) << 56));
}

inline void le64enc(void *pp, ulong x)
{
	uchar * p = (uchar *)pp;

	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
	p[4] = (x >> 32) & 0xff;
	p[5] = (x >> 40) & 0xff;
	p[6] = (x >> 48) & 0xff;
	p[7] = (x >> 56) & 0xff;
}

#endif /* !_OPENCL_SYSENDIAN_H_ */

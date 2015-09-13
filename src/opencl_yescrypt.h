/*-
 * Copyright 2009 Colin Percival
 * Copyright 2013-2015 Alexander Peslyak
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

#ifndef _OPENCL_YESCRYPT_H
#define _OPENCL_YESCRYPT_H


#undef PWXsimple
#undef PWXgather
#undef PWXrounds
#undef Swidth
#undef PWXbytes
#undef PWXwords
#undef Sbytes
#undef Swords
#undef Smask
#undef Smask2
#undef rmin

/* These are tunable */
#define PWXsimple 2
#define PWXgather 4
#define PWXrounds 6
#define Swidth 8

/* Derived values.  Not tunable on their own. */
#define PWXbytes (PWXgather * PWXsimple * 8)
#define PWXwords (PWXbytes / sizeof(ulong))
#define Sbytes (2 * (1 << Swidth) * PWXsimple * 8)
#define Swords (Sbytes / sizeof(ulong))
#define Smask (((1 << Swidth) - 1) * PWXsimple * 8)
#define Smask2 (((ulong)Smask << 32) | Smask)
#define rmin ((PWXbytes + 127) / 128)

#if PWXbytes % 32 != 0
#error "blkcpy() and blkxor() currently work on multiples of 32."
#endif

#endif

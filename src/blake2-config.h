/*
   BLAKE2 reference source code package - optimized C implementations

   Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/
#pragma once
#ifndef __BLAKE2_CONFIG_H__
#define __BLAKE2_CONFIG_H__

// These don't work everywhere
#if defined(__SSE2__) && !defined(HAVE_SSE2)
#define HAVE_SSE2	1
#endif

#if defined(__SSSE3__) && !defined(HAVE_SSSE3)
#define HAVE_SSSE3	1
#endif

#if defined(__SSE4_1__) && !defined(HAVE_SSE41)
#define HAVE_SSE41	1
#endif

#if defined(__AVX__) && !defined(HAVE_AVX)
#define HAVE_AVX	1
#endif

#if defined(__XOP__) && !defined(HAVE_XOP)
#define HAVE_XOP	1
#endif

#if defined(HAVE_AVX2) && !defined(HAVE_AVX)
#define HAVE_AVX	1
#endif

#if defined(HAVE_XOP) && !defined(HAVE_AVX)
#define HAVE_AVX	1
#endif

#if defined(HAVE_AVX) && !defined(HAVE_SSE41)
#define HAVE_SSE41	1
#endif

#if defined(HAVE_SSE41) && !defined(HAVE_SSSE3)
#define HAVE_SSSE3	1
#endif

#if defined(HAVE_SSSE3) && !defined(HAVE_SSE2)
#define HAVE_SSE2	1
#endif

#if !defined(HAVE_SSE2)
#error "This code requires at least SSE2."
#endif

#endif


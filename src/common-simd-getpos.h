#if !defined (__COMMON_SIMD_GETPOS_H__)
#define __COMMON_SIMD_GETPOS_H__

/*
 * This software is Copyright (c) 2017 jfoug : jfoug AT cox dot net
 *  Parts taken from code previously written by:
 *    magnumripper
 *    Alain Espinosa
 *    Simon Marechal
 *    and possibly others.
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
/*
 * !!NOTE!! if used on a BE format (SHA1/256/512), then before including
 *   this file, define  'FMT_IS_BE'  so that the proper macros for the
 *   hash typ[e are the being ones that will used.  the ARCH_LITTLE_ENDIAN,
 *   SIMD_COEFp[32][64] are global defines, and will already be correctly
 *   for your build. You DO NOT have to reset them before including this
 *   generic code header.
 */

#if !defined(FMT_IS_64BIT)

#if defined (SIMD_COEF_32)

#if !defined (MD5_BUF_SIZ)
#define MD5_BUF_SIZ 16
#endif
#if !defined (MD4_BUF_SIZ)
#define MD4_BUF_SIZ 16
#endif

#define GETPOSW32(i, index)             ( (index&(SIMD_COEF_32-1)) + i*SIMD_COEF_32 + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32 )
// for MD4/5 use GETOUT4POSW32. SHA1 use #5.  For SHA224/256, use #8
#define GETOUT4POSW32(i, index, WORDS)  ( (index&(SIMD_COEF_32-1)) + i*SIMD_COEF_32 + (unsigned int)index/SIMD_COEF_32*4*SIMD_COEF_32 )
#define GETOUT5POSW32(i, index, WORDS)  ( (index&(SIMD_COEF_32-1)) + i*SIMD_COEF_32 + (unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32 )
#define GETOUT8POSW32(i, index, WORDS)  ( (index&(SIMD_COEF_32-1)) + i*SIMD_COEF_32 + (unsigned int)index/SIMD_COEF_32*8*SIMD_COEF_32 )

#if defined (FMT_IS_BE)
#if ARCH_LITTLE_ENDIAN
#define GETPOS(i, index)   ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 )
#else
#define GETPOS(i, index)   ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 +     ((i)&3) + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 )
#endif
#else
#if ARCH_LITTLE_ENDIAN
#define GETPOS(i, index)   ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 +    ((i)&3)  + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 )
#else
#define GETPOS(i, index)   ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 )
#endif
#endif
#else
// dummy macros if SIMD_COEF_32 is not defined
#define GETPOSW32(i, index)
#define GETOUTPOSW32(i, index, BYTES)
#define GETPOS(i, index)

#endif // SIMD_COEF_32

#else // FMT_IS_64BIT

#if defined (SIMD_COEF_64)

#define GETPOSW64(i, index)             ( (index&(SIMD_COEF_64-1)) + i*SIMD_COEF_64 + (unsigned int)index/SIMD_COEF_64*16*SIMD_COEF_64 )
#define GETOUTPOS8W64(i, index)  ( (index&(SIMD_COEF_64-1)) + i*SIMD_COEF_64 + (unsigned int)index/SIMD_COEF_64*8*SIMD_COEF_64 )

// SHA512 defines for doing SIMD mixed buffer work.
#if !ARCH_LITTLE_ENDIAN
#define GETPOS(i, index)   ( (index&(SIMD_COEF_64-1))*8 + ((i)  &(0xffffffff-7))*SIMD_COEF_64 +    ((i)&7)  + (unsigned int)index/SIMD_COEF_64*128*SIMD_COEF_64 )
#else
#define GETPOS(i, index)   ( (index&(SIMD_COEF_64-1))*8 + ((i)  &(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + (unsigned int)index/SIMD_COEF_64*128*SIMD_COEF_64 )
#endif

#else
// dummy macros if SIMD_COEF_64 is not defined
#define GETPOS_SHA512_W64(i, index)
#define GETOUTPOS_SHA512_W64(i, index)
#define GETPOS_SHA512(i, index)

#endif // SIMD_COEF_64

#endif // FMT_IS_64BIT

#endif // __COMMON_SIMD_GETPOS_H__

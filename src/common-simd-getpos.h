#if !defined (__COMMON_SIMD_GETPOS_H__)
#define __COMMON_SIMD_GETPOS_H__

/*
 * This software was written by JimF : jfoug AT cox dot net
 * in 2017. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2017 JimF
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
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

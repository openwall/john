#if ARCH_LITTLE_ENDIAN
#define __GOST3411_LITTLE_ENDIAN__
#endif

#if !JOHN_NO_SIMD && __SSE2__
#define __GOST3411_HAS_SSE2__
#endif

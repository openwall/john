#if !defined(_STDINT_H) && !defined(_STDINT_H_)

#if !defined(_OPENCL_COMPILER)
#include "arch.h"
#endif

#if !defined(_OPENCL_COMPILER) && ((AC_BUILT && defined (HAVE_STDINT_H)) ||	\
	(!AC_BUILT && (defined(__STDC__) || defined(__STDC_VERSION__))))
#include <stdint.h>
#else
#define _STDINT_H 1
#define _STDINT_H_ 1

#undef uint8_t
#define uint8_t _john_uint8_t
#undef int8_t
#define int8_t _john_int8_t
#undef uint16_t
#define uint16_t _john_uint16_t
#undef int16_t
#define int16_t _john_int16_t
#undef uint32_t
#define uint32_t _john_uint32_t
#undef int32_t
#define int32_t _john_int32_t
#undef uint64_t
#define uint64_t _john_uint64_t
#undef int64_t
#define int64_t _john_int64_t
#undef uintmax_t
#define uintmax_t _john_uintmax_t
#undef intmax_t
#define intmax_t _john_intmax_t

#ifdef __UINT8_TYPE__
typedef __UINT8_TYPE__ uint8_t;
#else
typedef unsigned char uint8_t;
#endif
#ifdef __INT8_TYPE__
typedef __INT8_TYPE__ int8_t;
#else
typedef signed char int8_t;
#endif
#ifdef __UINT16_TYPE__
typedef __UINT16_TYPE__ uint16_t;
#else
typedef unsigned short uint16_t;
#endif
#ifdef __INT16_TYPE__
typedef __INT16_TYPE__ int16_t;
#else
typedef short int16_t;
#endif
#ifdef __UINT32_TYPE__
typedef __UINT32_TYPE__ uint32_t;
#else
typedef unsigned int uint32_t;
#endif
#ifdef __INT32_TYPE__
typedef __INT32_TYPE__ int32_t;
#else
typedef int int32_t;
#endif
#ifdef _OPENCL_COMPILER
typedef unsigned long uint64_t;
typedef long int64_t;
typedef unsigned long uintmax_t;
typedef long intmax_t;
#else
#ifdef __UINT64_TYPE__
typedef __UINT64_TYPE__ uint64_t;
#else
typedef unsigned long long uint64_t;
#endif
#ifdef __INT64_TYPE__
typedef __INT64_TYPE__ int64_t;
#else
typedef long long int64_t;
#endif
#ifdef __UINTMAX_TYPE__
typedef __UINTMAX_TYPE__ uintmax_t;
#else
typedef unsigned long long uintmax_t;
#endif
#ifdef __INTMAX_TYPE__
typedef __INTMAX_TYPE__ intmax_t;
#else
typedef long long intmax_t;
#endif
#endif

#if defined(SIZEOF_SIZE_T) && !defined(SIZE_MAX)
#if SIZEOF_SIZE_T == 8
#define SIZE_MAX		(18446744073709551615UL)
#else
#define SIZE_MAX		(4294967295U)
#endif
#endif

#if !defined(UINT32_MAX)
#define UINT32_MAX		(4294967295U)
#endif

#endif

#endif

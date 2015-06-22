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
#undef uint16_t
#define uint16_t _john_uint16_t
#undef uint32_t
#define uint32_t _john_uint32_t
#undef int32_t
#define int32_t _john_int32_t
#undef uint64_t
#define uint64_t _john_uint64_t

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef int int32_t;
#ifdef _OPENCL_COMPILER
typedef unsigned long uint64_t;
#else
typedef unsigned long long uint64_t;
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

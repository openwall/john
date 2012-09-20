#ifndef _STDINT_H
#if defined(__STDC__) || defined(__STDC_VERSION__)
#include <stdint.h>
#else
#define _STDINT_H 1

#undef uint8_t
#define uint8_t _john_uint8_t
#undef uint16_t
#define uint16_t _john_uint16_t
#undef uint32_t
#define uint32_t _john_uint32_t
#undef uint64_t
#define uint64_t _john_uint64_t

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#endif
#endif

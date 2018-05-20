/*
 * This software is Copyright (c) 2015 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _INT128_H
#define _INT128_H

#include <stdint.h>

#if HAVE___INT128 || HAVE_INT128 || HAVE___INT128_T
#undef int128_t
#define int128_t our_int128_t
#undef uint128_t
#define uint128_t our_uint128_t

#if HAVE___INT128
typedef __int128                int128_t;
typedef unsigned __int128       uint128_t;
#elif HAVE_INT128
typedef int128                  int128_t;
typedef unsigned int128         uint128_t;
#elif HAVE___INT128_T
typedef __int128_t              int128_t;
typedef __uint128_t             uint128_t;
#endif

#ifndef UINT128_MAX
#define UINT128_MAX             ((uint128_t)-1)
#endif

#ifndef INT128_MAX
#define INT128_MAX              ((int128_t)(UINT128_MAX >> 1))
#endif

#define JTR_HAVE_INT128         1

#else
#undef JTR_HAVE_INT128

#endif /* HAVE___INT128 || HAVE_INT128 || HAVE___INT128_T */

#endif /* _INT128_H */

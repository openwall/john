/*
 * Copyright (c) 2013, Alexey Degtyarev <alexey@renatasystems.org>.
 * All rights reserved.
 *
 * $Id$
 */

#include <string.h>

#include "gost3411-2012-config.h"

#if defined _MSC_VER
#define ALIGN(x) __declspec(align(x))
#else
#define ALIGN(x) __attribute__ ((__aligned__(x)))
#endif

#if defined __GOST3411_HAS_SSE2__
#include "gost3411-2012-sse2.h"
#else
#include "gost3411-2012-ref.h"
#endif

typedef union {
    unsigned long long QWORD[8];
} uint512_u;

#include "gost3411-2012-const.h"
#include "gost3411-2012-precalc.h"

typedef struct {
    ALIGN(16) unsigned char buffer[64];
    ALIGN(16) uint512_u hash;
    ALIGN(16) uint512_u h;
    ALIGN(16) uint512_u N;
    ALIGN(16) uint512_u Sigma;
    size_t bufsize;
    unsigned int digest_size;
} GOST34112012Context;

void GOST34112012Init(GOST34112012Context *CTX,
        const unsigned int digest_size);

void GOST34112012Update(GOST34112012Context *CTX, const unsigned char *data,
        size_t len);

void GOST34112012Final(GOST34112012Context *CTX, unsigned char *digest);

void GOST34112012Cleanup(GOST34112012Context *CTX);

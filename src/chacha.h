/* $OpenBSD: chacha.h,v 1.4 2016/08/27 04:04:56 guenther Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ifndef CHACHA_H
#define CHACHA_H

#include <sys/types.h>
#include <stdlib.h>

/* Avoid clash with system headers */
#undef u8
#define u8 john_u8
#undef u_char
#define u_char john_u_char
#undef u32
#define u32 john_u32
#undef u_int
#define u_int john_u_int

typedef unsigned char u8;
typedef unsigned char u_char;
typedef unsigned int u32;
typedef unsigned int u_int;

struct chacha_ctx {
	u_int input[16];
};

#define CHACHA_MINKEYLEN        16
#define CHACHA_NONCELEN         8
#define CHACHA_CTRLEN           8
#define CHACHA_STATELEN         (CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN         64

void chacha_keysetup(struct chacha_ctx *x, const u_char *k, u_int kbits);
void chacha_ivsetup(struct chacha_ctx *x, const u_char *iv, const u_char *ctr, u_int length);
void chacha_encrypt_bytes(struct chacha_ctx *x, const u_char *m, u_char *c, u_int bytes, int rounds);
void chacha_decrypt_bytes(struct chacha_ctx *x, const u_char *c, u_char *m, u_int bytes, int rounds);

#endif	/* CHACHA_H */

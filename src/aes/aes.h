/*
 * (c) 2014 Harrison Neal. Licensed under GPLv2.
 * A set of convenience functions that return a function pointer to an
 * appropriate AES implementation depending on your platform.
 *
 * NOTE: These functions are intended to be used by algorithms that
 * continuously switch out AES keys - with each computation, state is
 * built, used and torn down.
 * Consider using straight OpenSSL EVP methods if your algorithm would
 * do a lot of work with any single key.
 */

#include <stdio.h>
#include <string.h>

// Input, output, key, number of blocks
typedef void (*aes_fptr_vanilla)(unsigned char *, unsigned char *, unsigned char *, size_t);
// Input, output, key, number of blocks, iv
typedef void (*aes_fptr_cbc)(unsigned char *, unsigned char *, unsigned char *, size_t, unsigned char *);
// Input, output, key, number of blocks, iv
typedef void (*aes_fptr_ctr)(unsigned char *, unsigned char *, unsigned char *, size_t, unsigned char *);

#define FUNC(r,p) aes_fptr_##r get_##p();

#include "aes_func.h"

#undef FUNC

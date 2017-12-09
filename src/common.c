/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2015 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <string.h>

#include "arch.h"
#include "common.h"
#include "memdbg.h"
#include "misc.h"
#include "base64_convert.h"

/* This is the base64 that is used in crypt(3). It differs from MIME Base64
   and the latter can be found in base64.[ch] */
const char itoa64[64] = BASE64_CRYPT;
unsigned char atoi64[0x100];
const char itoa16[16]  = HEXCHARS_lc;
const char itoa16u[16] = HEXCHARS_uc;

unsigned char atoi16[0x100], atoi16l[0x100], atoi16u[0x100];

static int initialized = 0;

void common_init(void)
{







}

int ishex(const char *q)
{
}
int ishex_oddOK(const char *q)
{
}

int ishexuc(const char *q)
{
}
int ishexlc(const char *q)
{
}

int ishexn(const char *q, int n)
{
}
int ishexucn(const char *q, int n)
{
}
int ishexlcn(const char *q, int n)
{
}

int ishexuc_oddOK(const char *q) {
}
int ishexlc_oddOK(const char *q) {
}

static MAYBE_INLINE size_t _hexlen(const char *q, unsigned char dic[0x100], int *extra_chars)
{

}
size_t hexlen(const char *q, int *extra_chars)
{
}
size_t hexlenu(const char *q, int *extra_chars)
{
}
size_t hexlenl(const char *q, int *extra_chars)
{
}

}
int isdec_negok(const char *q)
{


}
int isdecu(const char *q) {
}

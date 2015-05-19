/*  Authored by Jeremi Gosney, 2014
    Placed in the public domain.
 */

#pragma once

#include <stdint.h>
#include "pufferfish_common.h"

#define HMAC_SHA512(a,b,c,d) \
    (HMAC (EVP_sha512(), (a), (b), (const unsigned char *) (c), (d), NULL, NULL))

typedef struct pf_context
{
    uint64_t P[PUF_N + 2];          /* p-array */
    uint64_t *S[NUM_SBOXES];        /* s-boxes */
    uint64_t key[KEYSIZ];           /* generated key */
    uint64_t salt[KEYSIZ];          /* hashed salt */
    unsigned int m_cost;            /* in KiB  */
    unsigned int sbox_words;        /* words per sbox */
    unsigned int log2_sbox_words;   /* log2 words per sbox */
} puf_ctx;

extern void *pufferfish (const char *pass, size_t passlen, char *settings, size_t outlen, bool raw);
extern void *pufferfish_custom (const char *pass, size_t passlen, char *settings, unsigned char *out, size_t outlen, bool raw);

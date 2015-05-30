/* PHC Candidate pufferfish - reference implementation
   Authored by Jeremi Gosney, 2014
   Placed in the public domain.
 */
#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_EVP_SHA512

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "pufferfish_common.h"
#include "pufferfish_itoa64.h"
#include "pufferfish_api.h"
#include "pufferfish.h"
#include "memdbg.h"

static void pf_init ( puf_ctx *ctx, const void *pass, size_t len_p, const void *salt, size_t len_s, unsigned int m_cost )
{
    int i, j;
    uint64_t *state;
    unsigned char *key_hash, *salt_hash;

    puf_ctx initstate = {
        {
            0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0,
            0x082efa98ec4e6c89, 0x452821e638d01377, 0xbe5466cf34e90c6c,
            0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917, 0x9216d5d98979fb1b,
            0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
            0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16,
            0x636920d871574e69, 0xa458fea3f4933d7e, 0x0d95748f728eb658
        }
    };

    initstate.m_cost = 1 << m_cost;
    initstate.log2_sbox_words = m_cost + 5;
    initstate.sbox_words = 1 << initstate.log2_sbox_words;

    salt_hash = HMAC_SHA512 ((const unsigned char *) &initstate.P, sizeof (uint64_t), salt, len_s );
    state = ( uint64_t* ) HMAC_SHA512 ( salt_hash, DIGEST_LEN, pass, len_p );

    for ( i = 0; i < NUM_SBOXES; i++ )
    {
        initstate.S[i] = ( uint64_t * ) calloc ( initstate.sbox_words, WORDSIZ );

        for ( j = 0; j < initstate.sbox_words; j += STATE_N )
        {
            initstate.S[i][j] = *( ( uint64_t * ) HMAC_SHA512 ( salt_hash, DIGEST_LEN, state, DIGEST_LEN ) );
            state = &initstate.S[i][j];
        }
    }

    key_hash = HMAC_SHA512 ( ( const unsigned char * ) state, DIGEST_LEN, pass, len_p );

    *ctx = initstate;

    memmove ( ctx->key,  key_hash,  DIGEST_LEN );
    memmove ( ctx->salt, salt_hash, DIGEST_LEN );

    memset ( key_hash, 0, DIGEST_LEN );
}


static uint64_t pf_f ( puf_ctx *ctx, uint64_t x )
{
    return (( ctx->S[0][( x >> ( 64 - ctx->log2_sbox_words ) )                            ] ^
              ctx->S[1][( x >> ( 48 - ctx->log2_sbox_words ) ) & ( ctx->sbox_words - 1 )] ) +
              ctx->S[2][( x >> ( 32 - ctx->log2_sbox_words ) ) & ( ctx->sbox_words - 1 )] ) ^
              ctx->S[3][( x >> ( 16 - ctx->log2_sbox_words ) ) & ( ctx->sbox_words - 1 )];
}


static void pf_encipher ( puf_ctx *ctx, uint64_t *LL, uint64_t *RR )
{
    int i = 0;
    uint64_t L = *LL, R = *RR;

    for ( i = 0; i < PUF_N; i += 2 )
    {
        L ^= ctx->P[i];
        R ^= pf_f ( ctx, L );
        R ^= ctx->P[i + 1];
        L ^= pf_f ( ctx, R );
    }

    L ^= ctx->P[16];
    R ^= ctx->P[17];

    *LL = R;
    *RR = L;
}


static void pf_ecb_encrypt ( puf_ctx *ctx, uint8_t *data, size_t len )
{
    uint64_t i, L = 0, R = 0;

    for ( i = 0; i < len; i += BLOCKSIZ )
    {
        uint8_to_uint64 ( L, data, 0 );
        uint8_to_uint64 ( R, data, 8 );

        pf_encipher ( ctx, &L, &R );

        uint64_to_uchar ( L, data, 0 );
        uint64_to_uchar ( R, data, 8 );

        data += BLOCKSIZ;
    }
}


static void pf_expandkey ( puf_ctx *ctx, const uint64_t data[KEYSIZ], const uint64_t key[KEYSIZ] )
{
    int i, j;
    uint64_t L = 0, R = 0;

    for ( i = 0; i < PUF_N + 2; i++ )
        ctx->P[i] ^= key[i % KEYSIZ];

    for ( i = 0; i < PUF_N + 2; i += 2 )
    {
        L ^= data[i % KEYSIZ];
        R ^= data[( i + 1 ) % KEYSIZ];

        pf_encipher ( ctx, &L, &R );

        ctx->P[i]     = L;
        ctx->P[i + 1] = R;
    }

    for ( i = 0; i < NUM_SBOXES; i++ )
    {
        for ( j = 0; j < ctx->sbox_words; j += 2 )
        {
            L ^= data[j % KEYSIZ];
            R ^= data[( j + 1 ) % KEYSIZ];

            pf_encipher ( ctx, &L, &R );

            ctx->S[i][j]   = L;
            ctx->S[i][j + 1] = R;
        }
    }
}

void *pufferfish ( const char *pass, size_t len_p, char *settings, size_t outlen, bool raw )
{
    puf_ctx ctx;
    static unsigned char *out;
    uint64_t null_data[8] = { 0 };
    long t_cost = 0, m_cost = 0, count = 0;
    int i, j, len_settings, saltlen, blockcnt, bytes = 0, pos = 0;

    char *sptr;
    char tcost_str[5] = { '0', 'x', 0 };
    char mcost_str[11] = { '0', 'x', 0 };

    unsigned char *rawbuf;
    unsigned char decoded[255] = { 0 };
    unsigned char rawsalt[255] = { 0 };
    unsigned char ctext[] = "Drab as a fool, aloof as a bard.";

    if ( strncmp ( PUF_ID, settings, PUF_ID_LEN ) )
        return NULL;

    len_settings = strlen ( settings );
    sptr = settings + PUF_ID_LEN;

    while ( *sptr++ != '$' && pos < len_settings ) pos++;

    len_settings = pos + PUF_ID_LEN + 1;

    bytes = decode64 ( decoded, pos, settings + PUF_ID_LEN );
    saltlen = bytes - 4;

    memmove ( tcost_str + 2, decoded, 2 );
    t_cost = strtol ( tcost_str, NULL, 16 );

    memmove ( mcost_str + 2, decoded + 2, 2 );
    m_cost = strtol ( mcost_str, NULL, 16 );

    memmove ( rawsalt, decoded + 4, saltlen );

    pf_init ( &ctx, pass, len_p, rawsalt, saltlen, m_cost );
    pf_expandkey ( &ctx, ctx.salt, ctx.key );

    count = 1 << t_cost;
    do
    {
        pf_expandkey ( &ctx, null_data, ctx.salt );
        pf_expandkey ( &ctx, null_data, ctx.key );
    }
    while ( --count );

    blockcnt = ( outlen + DIGEST_LEN - 1 ) / DIGEST_LEN;
    rawbuf = ( unsigned char * ) calloc ( blockcnt * DIGEST_LEN, sizeof ( unsigned char ) );

    for ( i = 0; i < blockcnt; i++ )
    {
        for ( j = 0; j < 64; j++ )
            pf_ecb_encrypt ( &ctx, ctext, 32 );

        memcpy ( rawbuf + ( i * DIGEST_LEN ), HMAC_SHA512 ( ctx.salt, DIGEST_LEN, ctext, 32 ), DIGEST_LEN );
    }

    if ( raw )
    {
        out = ( unsigned char * ) calloc ( blockcnt * DIGEST_LEN, sizeof ( unsigned char ) );
        memmove ( out, rawbuf, outlen );
    }
    else
    {
        out = ( unsigned char * ) calloc ( len_settings + 1 + ( blockcnt * DIGEST_LEN * 2 ), sizeof ( unsigned char ) );
        memmove ( out, settings, len_settings );
        encode64 ( ( char * ) &out[len_settings], rawbuf, outlen );
    }

    for ( i = 0; i < NUM_SBOXES; i++ )
    {
        for ( j = 0; j < ctx.sbox_words; j++ )
            ctx.S[i][j] = 0;

        free ( ctx.S[i] );
    }

    memset ( &ctx, 0, sizeof ( puf_ctx ) );
    memset ( ctext, 0, 32 );

    free ( rawbuf );

    return out;
}

void *pufferfish_custom ( const char *pass, size_t len_p, char *settings, unsigned char *out, size_t outlen, bool raw )
{
    puf_ctx ctx;
    uint64_t null_data[8] = { 0 };
    long t_cost = 0, m_cost = 0, count = 0;
    int i, j, len_settings, original_len_settings, saltlen, blockcnt, bytes = 0, pos = 0;

    char *sptr;
    char tcost_str[5] = { '0', 'x', 0 };
    char mcost_str[11] = { '0', 'x', 0 };

    unsigned char *rawbuf;
    unsigned char decoded[255] = { 0 };
    unsigned char rawsalt[255] = { 0 };
    unsigned char ctext[] = "Drab as a fool, aloof as a bard.";

    if ( strncmp ( PUF_ID, settings, PUF_ID_LEN ) )
        return NULL;

    len_settings = strlen ( settings );
    original_len_settings = strlen ( settings );
    sptr = settings + PUF_ID_LEN;

    while ( *sptr++ != '$' && pos < len_settings ) pos++;

    len_settings = pos + PUF_ID_LEN + 1;

    bytes = decode64 ( decoded, pos, settings + PUF_ID_LEN );
    saltlen = bytes - 4;

    memmove ( tcost_str + 2, decoded, 2 );
    t_cost = strtol ( tcost_str, NULL, 16 );

    memmove ( mcost_str + 2, decoded + 2, 2 );
    m_cost = strtol ( mcost_str, NULL, 16 );

    memmove ( rawsalt, decoded + 4, saltlen );

    pf_init ( &ctx, pass, len_p, rawsalt, saltlen, m_cost );
    pf_expandkey ( &ctx, ctx.salt, ctx.key );

    count = 1 << t_cost;
    do
    {
        pf_expandkey ( &ctx, null_data, ctx.salt );
        pf_expandkey ( &ctx, null_data, ctx.key );
    }
    while ( --count );

    blockcnt = ( outlen + DIGEST_LEN - 1 ) / DIGEST_LEN;
    rawbuf = ( unsigned char * ) calloc ( blockcnt * DIGEST_LEN, sizeof ( unsigned char ) );

    for ( i = 0; i < blockcnt; i++ )
    {
        for ( j = 0; j < 64; j++ )
            pf_ecb_encrypt ( &ctx, ctext, 32 );

        memcpy ( rawbuf + ( i * DIGEST_LEN ), HMAC_SHA512 ( ctx.salt, DIGEST_LEN, ctext, 32 ), DIGEST_LEN );
    }

    if ( raw )
    {
        memcpy ( out, rawbuf, outlen );
    }
    else
    {
	len_settings = original_len_settings;
        memcpy ( out, settings, len_settings );
        encode64 ( ( char * ) &out[len_settings], rawbuf, outlen );
    }

     for ( i = 0; i < NUM_SBOXES; i++ )
    {
        for ( j = 0; j < ctx.sbox_words; j++ )
            ctx.S[i][j] = 0;

        free ( ctx.S[i] );
    }

    free ( rawbuf );

    return out;
}

#endif /* HAVE_EVP_SHA512 */

#pragma once

#define shr(x,n) (x >> n)
#define shl(x,n) (x << n)
#define rotr64(x,n) (shr(x,n) | (x << (64 - n)))
#define rotl64(x,n) (shl(x,n) | (x >> (64 - n)))

#define uint8_to_uint64(n,b,c)                  \
{                                               \
    (n) = ( (uint64_t) (b)[(c)  ] << 56 )       \
        | ( (uint64_t) (b)[(c)+1] << 48 )       \
        | ( (uint64_t) (b)[(c)+2] << 40 )       \
        | ( (uint64_t) (b)[(c)+3] << 32 )       \
        | ( (uint64_t) (b)[(c)+4] << 24 )       \
        | ( (uint64_t) (b)[(c)+5] << 16 )       \
        | ( (uint64_t) (b)[(c)+6] <<  8 )       \
        | ( (uint64_t) (b)[(c)+7]       );      \
}

#define uint64_to_uchar(n,b,c)                          \
{                                                       \
    (b)[(c)  ] = (unsigned char) ( (n) >> 56 & 0xff );  \
    (b)[(c)+1] = (unsigned char) ( (n) >> 48 & 0xff );  \
    (b)[(c)+2] = (unsigned char) ( (n) >> 40 & 0xff );  \
    (b)[(c)+3] = (unsigned char) ( (n) >> 32 & 0xff );  \
    (b)[(c)+4] = (unsigned char) ( (n) >> 24 & 0xff );  \
    (b)[(c)+5] = (unsigned char) ( (n) >> 16 & 0xff );  \
    (b)[(c)+6] = (unsigned char) ( (n) >>  8 & 0xff );  \
    (b)[(c)+7] = (unsigned char) ( (n)       & 0xff );  \
}

#define PUF_ID "$PF$"                               /* hash identification str */
#define PUF_ID_LEN 4                                /* length of the identifier */
#define NUM_SBOXES 4                                /* number of sboxes */
#define PUF_N 16                                    /* number of subkeys */
#define STATE_N 8                                   /* number of words in state */
#define WORDSIZ sizeof (uint64_t)                   /* number of bytes per word */
#define BLOCKSIZ 16                                 /* number of bytes in a block */
#define DIGEST_LEN 64                               /* length of sha512 output */
#define KEYSIZ (DIGEST_LEN / sizeof (uint64_t))     /* number of words in the key */

typedef enum { false, true } bool;

/*  Authored by Jeremi Gosney, 2014
    Placed in the public domain.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_EVP_SHA512

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "jumbo.h"
#include "pufferfish_itoa64.h"
#include "pufferfish_common.h"
#include "pufferfish_api.h"

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "pufferfish.h"
#include "memdbg.h"


char *pf_gensalt ( const unsigned char *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost )
{
    /* simple function to generate a salt and build the settings string.
       string format is $id$itoa64( hex( t_cost ).hex( m_cost ).salt )$ */

    FILE *fp;
    unsigned char *buf;
    static char *out;
    int bytes;

    buf = ( unsigned char * ) calloc ( 4 + saltlen, sizeof ( unsigned char ) );

    /* we have two cost parameters, so in an effort to keep the hash
       string relatively clean, we convert them to hex and concatenate
       them so we always know their length. */

    snprintf ( ( char * ) buf, 11, "%02x%02x", t_cost, m_cost );

    /* if the user didn't supply a salt, generate one for them */
    if ( salt == NULL )
    {
        fp = fopen ( "/dev/urandom", "r" );
        bytes = fread  ( buf + 4, sizeof ( unsigned char ), saltlen, fp );
        fclose ( fp );
    }
    else
    {
        memmove ( buf + 4, salt, saltlen );
    }

    /* the output buffer is a bit large, but better too big than too small */
    out = ( char * ) calloc ( PUF_ID_LEN + ( ( 4 + saltlen ) * 2 ), sizeof ( char ) );

    /* copy hash identifer to the output string */
    memmove ( out, PUF_ID, PUF_ID_LEN );

    /* encode the buffer and copy it to the output string */
    bytes = encode64 ( &out[PUF_ID_LEN], buf, saltlen + 4 );

    /* add the trailing $ to the output string */
    out[PUF_ID_LEN + bytes] = '$';

    /* cleanup */
    free ( buf );

    return out;
}

char *pufferfish_easy ( const char *pass, unsigned int t_cost, unsigned int m_cost )
{
    /* this is the simple api for password hashing */

    const unsigned int saltlen = 16;
    const unsigned int outlen  = 32;
    static char *hash;
    char *settings;

    settings = pf_gensalt ( NULL, saltlen, t_cost, m_cost );
    hash = ( char * ) pufferfish ( pass, strlen ( pass ), settings, outlen, false );
    free ( settings );

    return hash;
}

int pufferfish_validate ( const char *pass, char *correct_hash )
{
    /* constant-time comparison of password hashes */

    int i, diff = 0;
    char *hash = ( char * ) pufferfish ( pass, strlen ( pass ), correct_hash, 32, false );

    diff = strlen ( hash ) ^ strlen ( correct_hash );

    for ( i = 0; i < strlen ( hash ) && i < strlen ( correct_hash ); i++ )
        diff |= hash[i] ^ correct_hash[i];

    free ( hash );

    return ( diff != 0 );
}

unsigned char *pfkdf ( unsigned int outlen, const char *pass, unsigned int t_cost, unsigned int m_cost )
{
    /* this is the simple api for deriving a key.
       outlen is specified in BITS, not bytes!
    */

    const unsigned int saltlen = 16;
    static unsigned char *key;
    unsigned int len;
    char *settings;

    len = outlen / 8;

    settings = pf_gensalt ( NULL, saltlen, t_cost, m_cost );
    key = pufferfish ( pass, strlen ( pass ), settings, len, true );
    free ( settings );

    return key;
}

int PHS ( void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost )
{
    /* required PHS api */

    char *hash;
    char *settings = pf_gensalt ( salt, saltlen, t_cost, m_cost );

    if ( ! ( hash = ( char * ) pufferfish ( in, inlen, settings, outlen, true ) ) )
    {
        free ( settings );
        return 1;
    }

    memmove ( out, hash, outlen );
    free ( settings );
    free ( hash );

    return 0;
}

#endif /* HAVE_EVP_SHA512 */

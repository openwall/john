/*
 *  PKCS#12 Personal Information Exchange Syntax
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

// https://github.com/ARMmbed/mbedtls/blob/development/library/pkcs12.c

#include <string.h>
#include <stdio.h>
#include "sha.h"
#include "pkcs12.h"

#define PKCS12_MAX_PWDLEN 128

int pkcs12_pbe_derive_key( int md_type, int iterations, int id, const unsigned
		char *pwd,  size_t pwdlen, const unsigned char *salt, size_t
		saltlen, unsigned char *key, size_t keylen)
{
    int ret;
    size_t i;
    unsigned char unipwd[PKCS12_MAX_PWDLEN * 2 + 2];

    if( pwdlen > PKCS12_MAX_PWDLEN )
        return -1;

    memset( &unipwd, 0, sizeof(unipwd) );

    for( i = 0; i < pwdlen; i++ )
        unipwd[i * 2 + 1] = pwd[i];

    if( ( ret = mbedtls_pkcs12_derivation( key, keylen, unipwd, pwdlen * 2 + 2,
                                   salt, saltlen, md_type,
                                   id, iterations ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}


static void pkcs12_fill_buffer( unsigned char *data, size_t data_len,
                                const unsigned char *filler, size_t fill_len )
{
    unsigned char *p = data;
    size_t use_len;

    while( data_len > 0 )
    {
        use_len = ( data_len > fill_len ) ? fill_len : data_len;
        memcpy( p, filler, use_len );
        p += use_len;
        data_len -= use_len;
    }
}

int mbedtls_pkcs12_derivation( unsigned char *data, size_t datalen, const
		unsigned char *pwd, size_t pwdlen, const unsigned char *salt,
		size_t saltlen, int md_type, int id, int iterations )
{
    int ret;
    unsigned int j;

    unsigned char diversifier[128];
    unsigned char salt_block[128], pwd_block[128], hash_block[128];
    unsigned char hash_output[1024];
    unsigned char *p;
    unsigned char c;

    size_t hlen, use_len, v, i;

    SHA_CTX md_ctx;

    // This version only allows max of 64 bytes of password or salt
    if( datalen > 128 || pwdlen > 64 || saltlen > 64 )
        return -1; // MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA

    hlen = 20; // for SHA1

    if( hlen <= 32 )
        v = 64;
    else
        v = 128;

    memset( diversifier, (unsigned char) id, v );

    pkcs12_fill_buffer( salt_block, v, salt, saltlen );
    pkcs12_fill_buffer( pwd_block,  v, pwd,  pwdlen  );

    p = data;
    while( datalen > 0 )
    {
        // Calculate hash( diversifier || salt_block || pwd_block )
        SHA1_Init( &md_ctx );

        SHA1_Update( &md_ctx, diversifier, v );
        SHA1_Update( &md_ctx, salt_block, v );
        SHA1_Update( &md_ctx, pwd_block, v );
        SHA1_Final( hash_output, &md_ctx );

        // Perform remaining ( iterations - 1 ) recursive hash calculations
        for( i = 1; i < (size_t) iterations; i++ )
        {
            SHA1_Init(&md_ctx);
            SHA1_Update(&md_ctx, hash_output, hlen);
            SHA1_Final(hash_output, &md_ctx);
        }

        use_len = ( datalen > hlen ) ? hlen : datalen;
        memcpy( p, hash_output, use_len );
        datalen -= use_len;
        p += use_len;

        if( datalen == 0 )
            break;

        // Concatenating copies of hash_output into hash_block (B)
        pkcs12_fill_buffer( hash_block, v, hash_output, hlen );

        // B += 1
        for( i = v; i > 0; i-- )
            if( ++hash_block[i - 1] != 0 )
                break;

        // salt_block += B
        c = 0;
        for( i = v; i > 0; i-- )
        {
            j = salt_block[i - 1] + hash_block[i - 1] + c;
            c = (unsigned char) (j >> 8);
            salt_block[i - 1] = j & 0xFF;
        }

        // pwd_block  += B
        c = 0;
        for( i = v; i > 0; i-- )
        {
            j = pwd_block[i - 1] + hash_block[i - 1] + c;
            c = (unsigned char) (j >> 8);
            pwd_block[i - 1] = j & 0xFF;
        }
    }

    ret = 0;

    return( ret );
}

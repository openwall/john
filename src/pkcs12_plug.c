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

/*
 *  Enhanced with SIMD code, JimF, July 2016
 *  JtR changes placed in public domain.
 */

// https://github.com/ARMmbed/mbedtls/blob/development/library/pkcs12.c

#include <string.h>
#include <stdio.h>
#include "sha.h"
#include "simd-intrinsics.h"
#include "pkcs12.h"

#define PKCS12_MAX_PWDLEN 128


extern int mbedtls_pkcs12_derivation( unsigned char *data, size_t datalen, const
		unsigned char *pwd, size_t pwdlen, const unsigned char *salt,
		size_t saltlen, int md_type, int id, int iterations );

extern int mbedtls_pkcs12_derivation_sha256( unsigned char *data, size_t datalen, const
		unsigned char *pwd, size_t pwdlen, const unsigned char *salt,
		size_t saltlen, int md_type, int id, int iterations );

int pkcs12_pbe_derive_key( int md_type, int iterations, int id, const unsigned
		char *pwd,  size_t pwdlen, const unsigned char *salt, size_t
		saltlen, unsigned char *key, size_t keylen)
{
    size_t i;
    unsigned char unipwd[PKCS12_MAX_PWDLEN * 2 + 2], *cp=unipwd;

    if( pwdlen > PKCS12_MAX_PWDLEN )
        return -1;

    for( i = 0; i < pwdlen; i++ ) {
	*cp++ = 0;
        *cp++ = pwd[i];
    }
    *cp++ = 0;
    *cp = 0;

    if (md_type == 0)
	mbedtls_pkcs12_derivation(key, keylen, unipwd, pwdlen * 2 + 2, salt,
			saltlen, md_type, id, iterations);
    else if (md_type == 256)
	mbedtls_pkcs12_derivation_sha256(key, keylen, unipwd, pwdlen * 2 + 2, salt,
			saltlen, md_type, id, iterations);

    return 0;
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

    return 0;
}

int mbedtls_pkcs12_derivation_sha256( unsigned char *data, size_t datalen, const
		unsigned char *pwd, size_t pwdlen, const unsigned char *salt,
		size_t saltlen, int md_type, int id, int iterations )
{
    unsigned int j;

    unsigned char diversifier[128];
    unsigned char salt_block[128], pwd_block[128], hash_block[128];
    unsigned char hash_output[1024];
    unsigned char *p;
    unsigned char c;

    size_t hlen, use_len, v, i;

    SHA256_CTX md_ctx;

    // This version only allows max of 64 bytes of password or salt
    if( datalen > 128 || pwdlen > 64 || saltlen > 64 )
        return -1; // MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA

    hlen = 32; // for SHA-256

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
        SHA256_Init( &md_ctx );

        SHA256_Update( &md_ctx, diversifier, v );
        SHA256_Update( &md_ctx, salt_block, v );
        SHA256_Update( &md_ctx, pwd_block, v );
        SHA256_Final( hash_output, &md_ctx );

        // Perform remaining ( iterations - 1 ) recursive hash calculations
        for( i = 1; i < (size_t) iterations; i++ )
        {
            SHA256_Init(&md_ctx);
            SHA256_Update(&md_ctx, hash_output, hlen);
            SHA256_Final(hash_output, &md_ctx);
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

    return 0;
}

#if defined(SIMD_COEF_32)
// SIMD method
#define GETPOS1(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 ) //for endianity conversion


extern int mbedtls_pkcs12_derivation_simd( unsigned char *data[SSE_GROUP_SZ_SHA1],
	        size_t datalen, const unsigned char *pwd[SSE_GROUP_SZ_SHA1],
	        size_t pwdlen[SSE_GROUP_SZ_SHA1], const unsigned char *salt, size_t saltlen,
	        int id, int iterations );
int mbedtls_pkcs12_derivation_simd_sha256( unsigned char *data[SSE_GROUP_SZ_SHA256],
                size_t datalen, const unsigned char *pwd[SSE_GROUP_SZ_SHA256],
                size_t pwdlen[SSE_GROUP_SZ_SHA256], const unsigned char *salt, size_t saltlen,
                int id, int iterations );


int pkcs12_pbe_derive_key_simd(int iterations, int id, const unsigned char *pwd[SSE_GROUP_SZ_SHA1],
		size_t pwdlen[SSE_GROUP_SZ_SHA1], const unsigned char *salt, size_t saltlen,
		unsigned char *key[SSE_GROUP_SZ_SHA1], size_t keylen)
{
	size_t i, j;
	unsigned char unipwd_[SSE_GROUP_SZ_SHA1][PKCS12_MAX_PWDLEN * 2 + 2];
	const unsigned char *unipwd[SSE_GROUP_SZ_SHA1];

	for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
		unsigned char *cpo;
		const unsigned char *cpi = pwd[j];
		size_t len = pwdlen[j];

		unipwd[j] = unipwd_[j];
		cpo = (unsigned char*)unipwd[j];
		if( len > PKCS12_MAX_PWDLEN )
			return -1;
		for( i = 0; i < len; i++ ) {
			*cpo++ = 0;
			*cpo++ = *cpi++;
		}
		*cpo++ = 0;
		*cpo = 0;
	}
	mbedtls_pkcs12_derivation_simd(key, keylen, unipwd, pwdlen, salt, saltlen, id, iterations);
	return 0;
}

int pkcs12_pbe_derive_key_simd_sha256( int iterations, int id, const unsigned char *pwd[SSE_GROUP_SZ_SHA256],
		size_t pwdlen[SSE_GROUP_SZ_SHA256], const unsigned char *salt, size_t saltlen,
		unsigned char *key[SSE_GROUP_SZ_SHA256], size_t keylen)
{
	size_t i, j;
	unsigned char unipwd_[SSE_GROUP_SZ_SHA256][PKCS12_MAX_PWDLEN * 2 + 2];
	const unsigned char *unipwd[SSE_GROUP_SZ_SHA256];

	for (j = 0; j < SSE_GROUP_SZ_SHA256; ++j) {
		unsigned char *cpo;
		const unsigned char *cpi = pwd[j];
		size_t len = pwdlen[j];

		unipwd[j] = unipwd_[j];
		cpo = (unsigned char*)unipwd[j];
		if( len > PKCS12_MAX_PWDLEN )
			return -1;
		for( i = 0; i < len; i++ ) {
			*cpo++ = 0;
			*cpo++ = *cpi++;
		}
		*cpo++ = 0;
		*cpo = 0;
	}
	mbedtls_pkcs12_derivation_simd_sha256(key, keylen, unipwd, pwdlen, salt, saltlen, id, iterations);
	return 0;
}


static void pkcs12_fill_salt_buffer_simd(unsigned char *data[SSE_GROUP_SZ_SHA1], size_t data_len,
                                    const unsigned char *filler, size_t fill_len)
{
	int j;
	unsigned char *p;
	size_t use_len;

	size_t len = data_len;
	p = data[0];
	while( len > 0 )
	{
		use_len = ( len > fill_len ) ? fill_len : len;
		memcpy( p, filler, use_len );
		p += use_len;
		len -= use_len;
	}
	for (j = 1; j < SSE_GROUP_SZ_SHA1; ++j) {
		memcpy(data[j], data[0], data_len );
	}
}

static void pkcs12_fill_buffer_simd(unsigned char *data[SSE_GROUP_SZ_SHA1], size_t data_len,
                                    const unsigned char *filler[SSE_GROUP_SZ_SHA1], size_t fill_len[SSE_GROUP_SZ_SHA1])
{
	int j;
	unsigned char *p;
	size_t use_len;

	for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
		size_t len = data_len;
		p = data[j];
		while( len > 0 )
		{
			use_len = ( len > fill_len[j] ) ? fill_len[j] : len;
			memcpy( p, filler[j], use_len );
			p += use_len;
			len -= use_len;
		}
	}
}

int mbedtls_pkcs12_derivation_simd( unsigned char *data[SSE_GROUP_SZ_SHA1], size_t datalen,
	        const unsigned char *pwd[SSE_GROUP_SZ_SHA1], size_t pwdlen[SSE_GROUP_SZ_SHA1],
	        const unsigned char *salt, size_t saltlen, int id, int iterations )
{
	unsigned int j, k, off=0;
	size_t hlens[SSE_GROUP_SZ_SHA1];

	unsigned char diversifier[128];
	unsigned char salt_block_[SSE_GROUP_SZ_SHA1][128], *salt_block[SSE_GROUP_SZ_SHA1], pwd_block_[SSE_GROUP_SZ_SHA1][128], *pwd_block[SSE_GROUP_SZ_SHA1], hash_block_[SSE_GROUP_SZ_SHA1][128], *hash_block[SSE_GROUP_SZ_SHA1];
	unsigned char hash_output_[SSE_GROUP_SZ_SHA1][128], *hash_output[SSE_GROUP_SZ_SHA1], hash[128];
	unsigned char *p;
	unsigned char c;
	JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char sse_buf[SHA_BUF_SIZ*sizeof(ARCH_WORD_32)*SSE_GROUP_SZ_SHA1];

	size_t hlen, use_len, v, i;

	SHA_CTX md_ctx;

	// This version only allows max of 64 bytes of password or salt
	if( datalen > 128 || saltlen > 64 )
		return -1;
	for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
		pwd_block[j] = pwd_block_[j];
		salt_block[j] = salt_block_[j];
		pwdlen[j] <<= 1;
		pwdlen[j] += 2;
		//if(pwdlen[j] > 64)
		//	return -1; // MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA
	}

	hlen = 20; // for SHA1

	if( hlen <= 32 )
		v = 64;
	else
		v = 128;

	memset(diversifier, (unsigned char) id, v);
	memset(sse_buf, 0, sizeof(sse_buf));

	pkcs12_fill_salt_buffer_simd(salt_block, v, salt, saltlen);
	pkcs12_fill_buffer_simd(pwd_block,  v, pwd,  pwdlen);

	while( datalen > 0 )
	{
		for (k = 0; k< SSE_GROUP_SZ_SHA1; ++k) {
			// Calculate hash( diversifier || salt_block || pwd_block )
			SHA1_Init( &md_ctx );

			SHA1_Update( &md_ctx, diversifier, v );
			SHA1_Update( &md_ctx, salt_block[k], v );
			SHA1_Update( &md_ctx, pwd_block[k], v );
			SHA1_Final( hash, &md_ctx );
			for (i = 0; i < SHA_DIGEST_LENGTH; ++i) {
				sse_buf[GETPOS1(i, k)] = hash[i];
			}
			sse_buf[GETPOS1(20,k)] = 0x80;
			sse_buf[GETPOS1(63,k)] = (SHA_DIGEST_LENGTH<<3);
		}

		// Perform remaining ( iterations - 1 ) recursive hash calculations
		for( i = 1; i < (size_t) iterations; i++ )
			SIMDSHA1body(sse_buf, (ARCH_WORD_32*)sse_buf, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);

		// Now unmarshall the data from sse_buf
		use_len = ( datalen > hlen ) ? hlen : datalen;
		datalen -= use_len;
		for (k = 0; k< SSE_GROUP_SZ_SHA1; ++k) {
			p = data[k];
			p += off;
			for (i = 0; i < use_len; ++i) {
				*p++ = sse_buf[GETPOS1(i,k)];
			}
		}
		if (!datalen)
			break;
		off += use_len;

		// Concatenating copies of hash_output into hash_block (B)
		for (k = 0; k< SSE_GROUP_SZ_SHA1; ++k) {
			hlens[k] = hlen;
			hash_output[k] = hash_output_[k];
			hash_block[k] = hash_block_[k];
			p = hash_output[k];
			for (i = 0; i < hlen; ++i) {
				*p++ = sse_buf[GETPOS1(i,k)];
			}
		}
		pkcs12_fill_buffer_simd( hash_block, v, (const unsigned char**)hash_output, hlens );

		for (k = 0; k< SSE_GROUP_SZ_SHA1; ++k) {
			// B += 1
			for( i = v; i > 0; i-- )
				if( ++hash_block[k][i - 1] != 0 )
					break;

			// salt_block += B
			c = 0;
			for( i = v; i > 0; i-- )
			{
				j = salt_block[k][i - 1] + hash_block[k][i - 1] + c;
				c = (unsigned char) (j >> 8);
				salt_block[k][i - 1] = j & 0xFF;
			}

			// pwd_block  += B
			c = 0;
			for( i = v; i > 0; i-- )
			{
				j = pwd_block[k][i - 1] + hash_block[k][i - 1] + c;
				c = (unsigned char) (j >> 8);
				pwd_block[k][i - 1] = j & 0xFF;
			}
		}
	}
	return 0;
}

int mbedtls_pkcs12_derivation_simd_sha256( unsigned char *data[SSE_GROUP_SZ_SHA256], size_t datalen,
	        const unsigned char *pwd[SSE_GROUP_SZ_SHA256], size_t pwdlen[SSE_GROUP_SZ_SHA256],
	        const unsigned char *salt, size_t saltlen, int id, int iterations )
{
	unsigned int j, k, off=0;
	size_t hlens[SSE_GROUP_SZ_SHA256];

	unsigned char diversifier[128];
	unsigned char salt_block_[SSE_GROUP_SZ_SHA256][128], *salt_block[SSE_GROUP_SZ_SHA256], pwd_block_[SSE_GROUP_SZ_SHA256][128], *pwd_block[SSE_GROUP_SZ_SHA256], hash_block_[SSE_GROUP_SZ_SHA256][128], *hash_block[SSE_GROUP_SZ_SHA256];
	unsigned char hash_output_[SSE_GROUP_SZ_SHA256][128], *hash_output[SSE_GROUP_SZ_SHA256], hash[128];
	unsigned char *p;
	unsigned char c;
	JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char sse_buf[SHA_BUF_SIZ*sizeof(ARCH_WORD_32)*SSE_GROUP_SZ_SHA256];

	size_t hlen, use_len, v, i;

	SHA256_CTX md_ctx;

	// This version only allows max of 64 bytes of password or salt
	if( datalen > 128 || saltlen > 64 )
		return -1;
	for (j = 0; j < SSE_GROUP_SZ_SHA256; ++j) {
		pwd_block[j] = pwd_block_[j];
		salt_block[j] = salt_block_[j];
		pwdlen[j] <<= 1;
		pwdlen[j] += 2;
	}

	hlen = 32; // for SHA256

	if( hlen <= 32 )
		v = 64;
	else
		v = 128;

	memset(diversifier, (unsigned char) id, v);
	memset(sse_buf, 0, sizeof(sse_buf));

	pkcs12_fill_salt_buffer_simd(salt_block, v, salt, saltlen);
	pkcs12_fill_buffer_simd(pwd_block,  v, pwd,  pwdlen);

	while( datalen > 0 )
	{
		for (k = 0; k< SSE_GROUP_SZ_SHA256; ++k) {
			// Calculate hash( diversifier || salt_block || pwd_block )
			SHA256_Init( &md_ctx );

			SHA256_Update( &md_ctx, diversifier, v );
			SHA256_Update( &md_ctx, salt_block[k], v );
			SHA256_Update( &md_ctx, pwd_block[k], v );
			SHA256_Final( hash, &md_ctx );
			for (i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
				sse_buf[GETPOS1(i, k)] = hash[i];
			}
			sse_buf[GETPOS1(32,k)] = 0x80;
			sse_buf[GETPOS1(62,k)] = 1; // (SHA256_DIGEST_LENGTH<<3);
		}

		// Perform remaining ( iterations - 1 ) recursive hash calculations
		for( i = 1; i < (size_t) iterations; i++ )
			SIMDSHA256body(sse_buf, (ARCH_WORD_32*)sse_buf, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);

		// Now unmarshall the data from sse_buf
		use_len = ( datalen > hlen ) ? hlen : datalen;
		datalen -= use_len;
		for (k = 0; k< SSE_GROUP_SZ_SHA256; ++k) {
			p = data[k];
			p += off;
			for (i = 0; i < use_len; ++i) {
				*p++ = sse_buf[GETPOS1(i,k)];
			}
		}
		if (!datalen)
			break;
		off += use_len;

		// Concatenating copies of hash_output into hash_block (B)
		for (k = 0; k< SSE_GROUP_SZ_SHA256; ++k) {
			hlens[k] = hlen;
			hash_output[k] = hash_output_[k];
			hash_block[k] = hash_block_[k];
			p = hash_output[k];
			for (i = 0; i < hlen; ++i) {
				*p++ = sse_buf[GETPOS1(i,k)];
			}
		}
		pkcs12_fill_buffer_simd( hash_block, v, (const unsigned char**)hash_output, hlens );

		for (k = 0; k< SSE_GROUP_SZ_SHA256; ++k) {
			// B += 1
			for( i = v; i > 0; i-- )
				if( ++hash_block[k][i - 1] != 0 )
					break;

			// salt_block += B
			c = 0;
			for( i = v; i > 0; i-- )
			{
				j = salt_block[k][i - 1] + hash_block[k][i - 1] + c;
				c = (unsigned char) (j >> 8);
				salt_block[k][i - 1] = j & 0xFF;
			}

			// pwd_block  += B
			c = 0;
			for( i = v; i > 0; i-- )
			{
				j = pwd_block[k][i - 1] + hash_block[k][i - 1] + c;
				c = (unsigned char) (j >> 8);
				pwd_block[k][i - 1] = j & 0xFF;
			}
		}
	}
	return 0;
}

#endif

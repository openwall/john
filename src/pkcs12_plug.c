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
#include "sha2.h"
#include "simd-intrinsics.h"
#include "pkcs12.h"
#include "sph_whirlpool.h"

#define PKCS12_MAX_PWDLEN 128


static int mbedtls_pkcs12_derivation( unsigned char *data, size_t datalen, const
		unsigned char *pwd, size_t pwdlen, const unsigned char *salt,
		size_t saltlen, int md_type, int id, int iterations );

int pkcs12_pbe_derive_key( int md_type, int iterations, int id, const unsigned
		char *pwd,  size_t pwdlen, const unsigned char *salt, size_t
		saltlen, unsigned char *key, size_t keylen)
{
	union {
		UTF16 s[PKCS12_MAX_PWDLEN + 1];
		UTF8 c[1];
	} unipwd;

	int len = enc_to_utf16_be(unipwd.s, PKCS12_MAX_PWDLEN, pwd, pwdlen);

	if (len < 0)
		len = strlen16(unipwd.s);

	pwdlen = 2 * (len + 1);

	// 2  => BestCrypt specific PKCS12 Whirlpool-512, hack
	// 10 => BestCrypt specific PKCS12 SHA-512, hack
	if (md_type == 1 || md_type == 256 || md_type == 512 || md_type == 224 || md_type == 384 || md_type == 2 || md_type == 10)
		mbedtls_pkcs12_derivation(key, keylen, unipwd.c, pwdlen, salt,
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

static int mbedtls_pkcs12_derivation( unsigned char *data, size_t datalen, const
		unsigned char *pwd, size_t pwdlen, const unsigned char *salt,
		size_t saltlen, int md_type, int id, int iterations )
{
    unsigned int j;

    unsigned char diversifier[128];
    unsigned char salt_block[128], pwd_block[128], hash_block[128];
    unsigned char hash_output[1024];
    unsigned char *p;
    unsigned char c;

    size_t hlen, use_len, v, i, v2;

    SHA_CTX md_ctx;
    SHA256_CTX md_ctx256;
    SHA512_CTX md_ctx512;
    sph_whirlpool_context md_ctx_whrl;

    // This version only allows max of 48 bytes of password or salt
    if ( datalen > 128 || pwdlen > 48*2+2 || saltlen > 64 )
        return -1; // MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA

    switch (md_type) {
	//case 0:
	//	hlen = 20;
	//	v = 64;		// for sha0  (Note, not handled by ans1crypt.py)
	//	break;
	case 1:
		hlen = 20;	// for SHA1
		v = 64;
		v2 = ((pwdlen+64-1)/64)*64;
		break;

//	case 2:			// for mdc2  (Note, not handled by ans1crypt.py)

//	case 4:
//		hlen = 16;	// for md4  (Note, not handled by ans1crypt.py)
//		v = 64;
//		break;
//	case 5:			// for md5  (Note, not handled by ans1crypt.py)
//		hlen = 16;
//		v = 64;
//		break;
//	case 160:		// for ripemd160  (Note, not handled by ans1crypt.py)
//		hlen = 20;
//		v = 64;
//		break;
	case 224:
		hlen = 28;	// for SHA224
		v = 64;
		v2 = ((pwdlen+64-1)/64)*64;
		break;
	case 256:
		hlen = 32;	// for SHA256
		v = 64;
		v2 = ((pwdlen+64-1)/64)*64;
		break;
	case 384:
		hlen = 48;	// for SHA384
		v2 = v = 128;
		break;
	case 512:
		hlen = 64;	// for SHA512
		v2 = v = 128;
		break;
	case 2:
		hlen = 64;	// for Whirlpool 512
		v2 = v = 64;    // BestCrypt always sets this to 64 for all cases!
		break;
	case 10:
		hlen = 64;	// for SHA512
		v2 = v = 64;	// BestCrypt always sets this to 64 for all cases!
		break;
	default:
		return -1;
    }

    memset( diversifier, (unsigned char) id, v );

    pkcs12_fill_buffer( salt_block, v, salt, saltlen );
    pkcs12_fill_buffer( pwd_block,  v2, pwd,  pwdlen  );

    p = data;
    while( datalen > 0 )
    {
        // Calculate hash( diversifier || salt_block || pwd_block )
	    switch (md_type) {
	    case 1:
		    SHA1_Init(&md_ctx);
		    SHA1_Update(&md_ctx, diversifier, v);
		    SHA1_Update(&md_ctx, salt_block, v);
		    SHA1_Update(&md_ctx, pwd_block, v2);
		    SHA1_Final(hash_output, &md_ctx);
		    // Perform remaining ( iterations - 1 ) recursive hash calculations
		    for ( i = 1; i < (size_t) iterations; i++ ) {
			    SHA1_Init(&md_ctx);
			    SHA1_Update(&md_ctx, hash_output, hlen);
			    SHA1_Final(hash_output, &md_ctx);
		    }
		    break;
	    case 224:
		    SHA224_Init(&md_ctx256);
		    SHA224_Update(&md_ctx256, diversifier, v);
		    SHA224_Update(&md_ctx256, salt_block, v);
		    SHA224_Update(&md_ctx256, pwd_block, v2);
		    SHA224_Final(hash_output, &md_ctx256);
		    // Perform remaining ( iterations - 1 ) recursive hash calculations
		    for ( i = 1; i < (size_t) iterations; i++ ) {
			    SHA224_Init(&md_ctx256);
			    SHA224_Update(&md_ctx256, hash_output, hlen);
			    SHA224_Final(hash_output, &md_ctx256);
		    }
		    break;
	    case 256:
		    SHA256_Init(&md_ctx256);
		    SHA256_Update(&md_ctx256, diversifier, v);
		    SHA256_Update(&md_ctx256, salt_block, v);
		    SHA256_Update(&md_ctx256, pwd_block, v2);
		    SHA256_Final(hash_output, &md_ctx256);
		    // Perform remaining ( iterations - 1 ) recursive hash calculations
		    for ( i = 1; i < (size_t) iterations; i++ ) {
			    SHA256_Init(&md_ctx256);
			    SHA256_Update(&md_ctx256, hash_output, hlen);
			    SHA256_Final(hash_output, &md_ctx256);
		    }
		    break;
	    case 384:
		    SHA384_Init(&md_ctx512);
		    SHA384_Update(&md_ctx512, diversifier, v);
		    SHA384_Update(&md_ctx512, salt_block, v);
		    SHA384_Update(&md_ctx512, pwd_block, v);
		    SHA384_Final(hash_output, &md_ctx512);
		    // Perform remaining ( iterations - 1 ) recursive hash calculations
		    for ( i = 1; i < (size_t) iterations; i++ ) {
			    SHA384_Init(&md_ctx512);
			    SHA384_Update(&md_ctx512, hash_output, hlen);
			    SHA384_Final(hash_output, &md_ctx512);
		    }
		    break;
	    case 10: // fall through
	    case 512:
		    SHA512_Init(&md_ctx512);
		    SHA512_Update(&md_ctx512, diversifier, v);
		    SHA512_Update(&md_ctx512, salt_block, v);
		    SHA512_Update(&md_ctx512, pwd_block, v);
		    SHA512_Final(hash_output, &md_ctx512);
		    // Perform remaining ( iterations - 1 ) recursive hash calculations
		    for ( i = 1; i < (size_t) iterations; i++ ) {
			    SHA512_Init(&md_ctx512);
			    SHA512_Update(&md_ctx512, hash_output, hlen);
			    SHA512_Final(hash_output, &md_ctx512);
		    }
		    break;
	    case 2:
		    sph_whirlpool_init(&md_ctx_whrl);
		    sph_whirlpool(&md_ctx_whrl, diversifier, v);
		    sph_whirlpool(&md_ctx_whrl, salt_block, v);
		    sph_whirlpool(&md_ctx_whrl, pwd_block, v);
		    sph_whirlpool_close(&md_ctx_whrl, hash_output);
		    // Perform remaining ( iterations - 1 ) recursive hash calculations
		    for ( i = 1; i < (size_t) iterations; i++ ) {
			    sph_whirlpool_init(&md_ctx_whrl);
			    sph_whirlpool(&md_ctx_whrl, hash_output, hlen);
			    sph_whirlpool_close(&md_ctx_whrl, hash_output);
		    }
		    break;
	    }

        use_len = ( datalen > hlen ) ? hlen : datalen;
        memcpy( p, hash_output, use_len );
        datalen -= use_len;
        p += use_len;

        if ( datalen == 0 )
            break;

        // Concatenating copies of hash_output into hash_block (B)
        pkcs12_fill_buffer( hash_block, v, hash_output, hlen );

        // B += 1
        for ( i = v; i > 0; i-- )
            if ( ++hash_block[i - 1] != 0 )
                break;

        // salt_block += B
        c = 0;
        for ( i = v; i > 0; i-- )
        {
            j = salt_block[i - 1] + hash_block[i - 1] + c;
            c = (unsigned char) (j >> 8);
            salt_block[i - 1] = j & 0xFF;
        }

        // pwd_block  += B
        c = 0;
        for ( i = v; i > 0; i-- )
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
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS1(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 ) //for endianity conversion
#else
#define GETPOS1(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 ) //for endianity conversion
#endif


static int mbedtls_pkcs12_derivation_simd_sha1( unsigned char *data[SSE_GROUP_SZ_SHA1],
	        size_t datalen, const unsigned char *pwd[SSE_GROUP_SZ_SHA1],
	        size_t pwdlen[SSE_GROUP_SZ_SHA1], const unsigned char *salt, size_t saltlen,
	        int id, int iterations );
static int mbedtls_pkcs12_derivation_simd_sha256( unsigned char *data[SSE_GROUP_SZ_SHA256],
                size_t datalen, const unsigned char *pwd[SSE_GROUP_SZ_SHA256],
                size_t pwdlen[SSE_GROUP_SZ_SHA256], const unsigned char *salt, size_t saltlen,
                int id, int iterations );

int pkcs12_pbe_derive_key_simd(int md_type, int iterations, int id, const unsigned char *pwd[SIMD_MAX_GROUP_PFX],
		size_t pwdlen[SIMD_MAX_GROUP_PFX], const unsigned char *salt, size_t saltlen,
		unsigned char *key[SIMD_MAX_GROUP_PFX], size_t keylen)
{
	if (md_type == 1) {
		return pkcs12_pbe_derive_key_simd_sha1(iterations, id, pwd, pwdlen, salt, saltlen, key, keylen);
	}
	if (md_type == 256) {
		return pkcs12_pbe_derive_key_simd_sha256(iterations, id, pwd, pwdlen, salt, saltlen, key, keylen);
	}
#if defined(SIMD_COEF_64)
	if (md_type == 512) {
		return pkcs12_pbe_derive_key_simd_sha512(iterations, id, pwd, pwdlen, salt, saltlen, key, keylen);
	}
#endif
	return -1;
}

int pkcs12_pbe_derive_key_simd_sha1( int iterations, int id, const unsigned char *pwd[SSE_GROUP_SZ_SHA1],
		size_t pwdlen[SSE_GROUP_SZ_SHA1], const unsigned char *salt, size_t saltlen,
		unsigned char *key[SSE_GROUP_SZ_SHA256], size_t keylen)
{
	size_t j;
	union {
		UTF16 s[PKCS12_MAX_PWDLEN + 1];
		uint8_t c[1];
	} unibuf[SSE_GROUP_SZ_SHA1];
	const unsigned char *unipwd[SSE_GROUP_SZ_SHA1];

	for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
		unipwd[j] = unibuf[j].c;

		int len = enc_to_utf16_be(unibuf[j].s, PKCS12_MAX_PWDLEN, pwd[j], pwdlen[j]);

		if (len < 0)
			len = strlen16(unibuf[j].s);

		pwdlen[j] = 2 * (len + 1);
	}
	mbedtls_pkcs12_derivation_simd_sha1(key, keylen, unipwd, pwdlen, salt, saltlen, id, iterations);
	return 0;
}

int pkcs12_pbe_derive_key_simd_sha256( int iterations, int id, const unsigned char *pwd[SSE_GROUP_SZ_SHA256],
		size_t pwdlen[SSE_GROUP_SZ_SHA256], const unsigned char *salt, size_t saltlen,
		unsigned char *key[SSE_GROUP_SZ_SHA256], size_t keylen)
{
	size_t j;
	union {
		UTF16 s[PKCS12_MAX_PWDLEN + 1];
		uint8_t c[1];
	} unibuf[SSE_GROUP_SZ_SHA256];
	const unsigned char *unipwd[SSE_GROUP_SZ_SHA256];

	for (j = 0; j < SSE_GROUP_SZ_SHA256; ++j) {
		unipwd[j] = unibuf[j].c;

		int len = enc_to_utf16_be(unibuf[j].s, PKCS12_MAX_PWDLEN, pwd[j], pwdlen[j]);

		if (len < 0)
			len = strlen16(unibuf[j].s);

		pwdlen[j] = 2 * (len + 1);
	}
	mbedtls_pkcs12_derivation_simd_sha256(key, keylen, unipwd, pwdlen, salt, saltlen, id, iterations);
	return 0;
}


static void pkcs12_fill_salt_buffer_simd(unsigned char *data[SIMD_MAX_GROUP_PFX], size_t data_len,
                                    const unsigned char *filler, size_t fill_len, int fill_count)
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
	for (j = 1; j < fill_count; ++j) {
		memcpy(data[j], data[0], data_len );
	}
}

static void pkcs12_fill_buffer_simd(unsigned char *data[SIMD_MAX_GROUP_PFX], size_t data_len,
                                    const unsigned char *filler[SIMD_MAX_GROUP_PFX],
				    size_t fill_len[SIMD_MAX_GROUP_PFX], int fill_count)
{
	int j;
	unsigned char *p;
	size_t use_len;

	for (j = 0; j < fill_count; ++j) {
		size_t len = data_len;
		p = data[j];
		if (data_len == 64)
			len = ((fill_len[j]+64)/64)*64;
		while( len > 0 )
		{
			use_len = ( len > fill_len[j] ) ? fill_len[j] : len;
			memcpy( p, filler[j], use_len );
			p += use_len;
			len -= use_len;
		}
	}
}

static int mbedtls_pkcs12_derivation_simd_sha1( unsigned char *data[SSE_GROUP_SZ_SHA1], size_t datalen,
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
	JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char sse_buf[SHA_BUF_SIZ*sizeof(uint32_t)*SSE_GROUP_SZ_SHA1];

	size_t hlen, use_len, v, v2, i;

	SHA_CTX md_ctx;

	for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
		pwd_block[j] = pwd_block_[j];
		salt_block[j] = salt_block_[j];
	}

	hlen = 20; // for SHA1
	v = 64;

	memset(diversifier, (unsigned char) id, v);
	memset(sse_buf, 0, sizeof(sse_buf));

	pkcs12_fill_salt_buffer_simd(salt_block, v, salt, saltlen, SSE_GROUP_SZ_SHA1);
	pkcs12_fill_buffer_simd(pwd_block,  v, pwd,  pwdlen, SSE_GROUP_SZ_SHA1);

	while( datalen > 0 )
	{
		for (k = 0; k< SSE_GROUP_SZ_SHA1; ++k) {
			// Calculate hash( diversifier || salt_block || pwd_block )
			SHA1_Init( &md_ctx );

			SHA1_Update( &md_ctx, diversifier, v );
			SHA1_Update( &md_ctx, salt_block[k], v );
			v2 = ((pwdlen[k]+64-1)/64)*64;
			SHA1_Update( &md_ctx, pwd_block[k], v2 );
			SHA1_Final( hash, &md_ctx );
			for (i = 0; i < SHA_DIGEST_LENGTH; ++i) {
				sse_buf[GETPOS1(i, k)] = hash[i];
			}
			sse_buf[GETPOS1(20,k)] = 0x80;
			sse_buf[GETPOS1(63,k)] = (SHA_DIGEST_LENGTH<<3);
		}

		// Perform remaining ( iterations - 1 ) recursive hash calculations
		for ( i = 1; i < (size_t) iterations; i++ )
			SIMDSHA1body(sse_buf, (uint32_t*)sse_buf, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);

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
		pkcs12_fill_buffer_simd( hash_block, v, (const unsigned char**)hash_output, hlens, SSE_GROUP_SZ_SHA1);

		for (k = 0; k< SSE_GROUP_SZ_SHA1; ++k) {
			// B += 1
			for ( i = v; i > 0; i-- )
				if ( ++hash_block[k][i - 1] != 0 )
					break;

			// salt_block += B
			c = 0;
			for ( i = v; i > 0; i-- )
			{
				j = salt_block[k][i - 1] + hash_block[k][i - 1] + c;
				c = (unsigned char) (j >> 8);
				salt_block[k][i - 1] = j & 0xFF;
			}

			// pwd_block  += B
			c = 0;
			for ( i = v; i > 0; i-- )
			{
				j = pwd_block[k][i - 1] + hash_block[k][i - 1] + c;
				c = (unsigned char) (j >> 8);
				pwd_block[k][i - 1] = j & 0xFF;
			}
		}
	}
	return 0;
}

static int mbedtls_pkcs12_derivation_simd_sha256( unsigned char *data[SSE_GROUP_SZ_SHA256], size_t datalen,
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
	JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char sse_buf[SHA_BUF_SIZ*sizeof(uint32_t)*SSE_GROUP_SZ_SHA256];

	size_t hlen, use_len, v, v2, i;

	SHA256_CTX md_ctx;

	for (j = 0; j < SSE_GROUP_SZ_SHA256; ++j) {
		pwd_block[j] = pwd_block_[j];
		salt_block[j] = salt_block_[j];
	}

	hlen = 32; // for SHA256
	v = 64;

	memset(diversifier, (unsigned char) id, v);
	memset(sse_buf, 0, sizeof(sse_buf));

	pkcs12_fill_salt_buffer_simd(salt_block, v, salt, saltlen, SSE_GROUP_SZ_SHA256);
	pkcs12_fill_buffer_simd(pwd_block,  v, pwd,  pwdlen, SSE_GROUP_SZ_SHA256);

	while( datalen > 0 )
	{
		for (k = 0; k< SSE_GROUP_SZ_SHA256; ++k) {
			// Calculate hash( diversifier || salt_block || pwd_block )
			SHA256_Init( &md_ctx );

			SHA256_Update( &md_ctx, diversifier, v );
			SHA256_Update( &md_ctx, salt_block[k], v );
			v2 = ((pwdlen[k]+64-1)/64)*64;
			SHA256_Update( &md_ctx, pwd_block[k], v2 );
			SHA256_Final( hash, &md_ctx );
			for (i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
				sse_buf[GETPOS1(i, k)] = hash[i];
			}
			sse_buf[GETPOS1(32,k)] = 0x80;
			sse_buf[GETPOS1(62,k)] = 1; // (SHA256_DIGEST_LENGTH<<3);
		}

		// Perform remaining ( iterations - 1 ) recursive hash calculations
		for ( i = 1; i < (size_t) iterations; i++ )
			SIMDSHA256body(sse_buf, (uint32_t*)sse_buf, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);

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
		pkcs12_fill_buffer_simd( hash_block, v, (const unsigned char**)hash_output, hlens, SSE_GROUP_SZ_SHA256);

		for (k = 0; k< SSE_GROUP_SZ_SHA256; ++k) {
			// B += 1
			for ( i = v; i > 0; i-- )
				if ( ++hash_block[k][i - 1] != 0 )
					break;

			// salt_block += B
			c = 0;
			for ( i = v; i > 0; i-- )
			{
				j = salt_block[k][i - 1] + hash_block[k][i - 1] + c;
				c = (unsigned char) (j >> 8);
				salt_block[k][i - 1] = j & 0xFF;
			}

			// pwd_block  += B
			c = 0;
			for ( i = v; i > 0; i-- )
			{
				j = pwd_block[k][i - 1] + hash_block[k][i - 1] + c;
				c = (unsigned char) (j >> 8);
				pwd_block[k][i - 1] = j & 0xFF;
			}
		}
	}
	return 0;
}

#if defined(SIMD_COEF_64)

/* We use SSEi_HALF_IN, so can halve SHA_BUF_SIZ */
#undef SHA_BUF_SIZ
#define SHA_BUF_SIZ 8

// 64 bit mixer
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS4(i, index)        ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
#else
#define GETPOS4(i, index)        ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + ((i)&7) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
#endif

static int mbedtls_pkcs12_derivation_simd_sha512( unsigned char *data[SSE_GROUP_SZ_SHA512], size_t datalen,
	        const unsigned char *pwd[SSE_GROUP_SZ_SHA512], size_t pwdlen[SSE_GROUP_SZ_SHA512],
	        const unsigned char *salt, size_t saltlen, int id, int iterations );

int pkcs12_pbe_derive_key_simd_sha512(int iterations, int id, const unsigned char *pwd[SSE_GROUP_SZ_SHA512],
		size_t pwdlen[SSE_GROUP_SZ_SHA512], const unsigned char *salt, size_t saltlen,
		unsigned char *key[SSE_GROUP_SZ_SHA512], size_t keylen)
{
	size_t j;
	union {
		UTF16 s[PKCS12_MAX_PWDLEN + 1];
		uint8_t c[1];
	} unibuf[SSE_GROUP_SZ_SHA512];
	const unsigned char *unipwd[SSE_GROUP_SZ_SHA512];

	for (j = 0; j < SSE_GROUP_SZ_SHA512; ++j) {
		unipwd[j] = unibuf[j].c;

		int len = enc_to_utf16_be(unibuf[j].s, PKCS12_MAX_PWDLEN, pwd[j], pwdlen[j]);

		if (len < 0)
			len = strlen16(unibuf[j].s);

		pwdlen[j] = 2 * (len + 1);
	}
	mbedtls_pkcs12_derivation_simd_sha512(key, keylen, unipwd, pwdlen, salt, saltlen, id, iterations);
	return 0;
}

static int mbedtls_pkcs12_derivation_simd_sha512( unsigned char *data[SSE_GROUP_SZ_SHA512], size_t datalen,
	        const unsigned char *pwd[SSE_GROUP_SZ_SHA512], size_t pwdlen[SSE_GROUP_SZ_SHA512],
	        const unsigned char *salt, size_t saltlen, int id, int iterations )
{
	unsigned int j, k, off=0;
	size_t hlens[SSE_GROUP_SZ_SHA512];

	unsigned char diversifier[128];
	unsigned char salt_block_[SSE_GROUP_SZ_SHA512][128], *salt_block[SSE_GROUP_SZ_SHA512], pwd_block_[SSE_GROUP_SZ_SHA512][128], *pwd_block[SSE_GROUP_SZ_SHA512], hash_block_[SSE_GROUP_SZ_SHA512][128], *hash_block[SSE_GROUP_SZ_SHA512];
	unsigned char hash_output_[SSE_GROUP_SZ_SHA512][128], *hash_output[SSE_GROUP_SZ_SHA512], hash[128];
	unsigned char *p;
	unsigned char c;
	JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char sse_buf[SHA_BUF_SIZ*sizeof(uint64_t)*SSE_GROUP_SZ_SHA512];

	size_t hlen, use_len, v, i;

	SHA512_CTX md_ctx;

	// This version only allows max of 64 bytes of password or salt
	if ( datalen > 128 || saltlen > 64 )
		return -1;
	for (j = 0; j < SSE_GROUP_SZ_SHA512; ++j) {
		pwd_block[j] = pwd_block_[j];
		salt_block[j] = salt_block_[j];
	}

	hlen = 64; // for SHA512
	v = 128;

	memset(diversifier, (unsigned char) id, v);

	pkcs12_fill_salt_buffer_simd(salt_block, v, salt, saltlen, SSE_GROUP_SZ_SHA512);
	pkcs12_fill_buffer_simd(pwd_block,  v, pwd,  pwdlen, SSE_GROUP_SZ_SHA512);

	while( datalen > 0 )
	{
		for (k = 0; k< SSE_GROUP_SZ_SHA512; ++k) {
			// Calculate hash( diversifier || salt_block || pwd_block )
			SHA512_Init( &md_ctx );

			SHA512_Update( &md_ctx, diversifier, v );
			SHA512_Update( &md_ctx, salt_block[k], v );
			SHA512_Update( &md_ctx, pwd_block[k], v );
			SHA512_Final( hash, &md_ctx );
			for (i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
				sse_buf[GETPOS4(i, k)] = hash[i];
			}
		}

		// Perform remaining ( iterations - 1 ) recursive hash calculations
		uint64_t rounds = iterations - 1;
		SIMDSHA512body(sse_buf, (uint64_t*)sse_buf, &rounds, SSEi_HALF_IN|SSEi_LOOP);

		// Now unmarshall the data from sse_buf
		use_len = ( datalen > hlen ) ? hlen : datalen;
		datalen -= use_len;
		for (k = 0; k< SSE_GROUP_SZ_SHA512; ++k) {
			p = data[k];
			p += off;
			for (i = 0; i < use_len; ++i) {
				*p++ = sse_buf[GETPOS4(i,k)];
			}
		}
		if (!datalen)
			break;
		off += use_len;

		// Concatenating copies of hash_output into hash_block (B)
		for (k = 0; k< SSE_GROUP_SZ_SHA512; ++k) {
			hlens[k] = hlen;
			hash_output[k] = hash_output_[k];
			hash_block[k] = hash_block_[k];
			p = hash_output[k];
			for (i = 0; i < hlen; ++i) {
				*p++ = sse_buf[GETPOS4(i,k)];
			}
		}
		pkcs12_fill_buffer_simd( hash_block, v, (const unsigned char**)hash_output, hlens, SSE_GROUP_SZ_SHA512 );

		for (k = 0; k< SSE_GROUP_SZ_SHA512; ++k) {
			// B += 1
			for ( i = v; i > 0; i-- )
				if ( ++hash_block[k][i - 1] != 0 )
					break;

			// salt_block += B
			c = 0;
			for ( i = v; i > 0; i-- )
			{
				j = salt_block[k][i - 1] + hash_block[k][i - 1] + c;
				c = (unsigned char) (j >> 8);
				salt_block[k][i - 1] = j & 0xFF;
			}

			// pwd_block  += B
			c = 0;
			for ( i = v; i > 0; i-- )
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

#endif

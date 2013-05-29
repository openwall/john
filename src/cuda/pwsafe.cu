/*
* This software is Copyright (c) 2012-2013
* Lukas Odzioba <ukasz at openwall.net> and Brian Wallace <brian.wallace9809 at gmail.com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "../cuda_pwsafe.h"
#include "cuda_common.cuh"

#define PWSAFE_IN_SIZE (KEYS_PER_CRYPT * sizeof(pwsafe_pass))
#define PWSAFE_OUT_SIZE (KEYS_PER_CRYPT * sizeof(pwsafe_hash))
#define PWSAFE_SALT_SIZE (sizeof(pwsafe_salt))

__global__ void kernel_pwsafe(pwsafe_pass * in, pwsafe_salt * salt,
    pwsafe_hash * out)
{
        uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
        uint32_t pl = in[idx].length, j, i;

        const uint32_t k[] = {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
                0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74,
                0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
                0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
                0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354,
                0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
                0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3,
                0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa,
                0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        const uint32_t H[] = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
                0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        uint32_t w[64];
        for (i = 0; i <= 14; i++)
                w[i] = 0;
        for (j = 0; j < pl; j++) {
                uint32_t tmp;
                tmp = (((uint32_t) in[idx].v[j]) << ((3 - (j & 0x3)) << 3));
                w[j / 4] |= tmp;
        }
        for (; j < 32 + pl; j++) {
                uint32_t tmp;
                tmp =
                    (((uint32_t) salt->salt[j - pl]) << ((3 -
                            (j & 0x3)) << 3));
                w[j / 4] |= tmp;
        }
        w[j / 4] |= (((uint32_t) 0x80) << ((3 - (j & 0x3)) << 3));
        w[15] = 0x00000000 | (j * 8);

#pragma unroll 48
        for (j = 16; j < 64; j++) {
                w[j] =
                    sigma1(w[j - 2]) + w[j - 7] + sigma0(w[j - 15]) + w[j -
                    16];
        }

        uint32_t a = H[0];
        uint32_t b = H[1];
        uint32_t c = H[2];
        uint32_t d = H[3];
        uint32_t e = H[4];
        uint32_t f = H[5];
        uint32_t g = H[6];
        uint32_t h = H[7];
#pragma unroll 64
        for (uint32_t j = 0; j < 64; j++) {
                uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + k[j] + w[j];
                uint32_t t2 = Sigma0(a) + Maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
        }


	w[0] = a + H[0];
	w[1] = b + H[1];
	w[2] = c + H[2];
	w[3] = d + H[3];
	w[4] = e + H[4];
	w[5] = f + H[5];
	w[6] = g + H[6];
	w[7] = h + H[7];
        for (i = 0; i < salt->iterations; i++) {
		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];
		f = H[5];
		g = H[6];
		h = H[7];

		h += Sigma1( e ) + Ch( e, f, g ) + 0x428a2f98 + (w[0]);
		d += h;
		h += Sigma0( a ) + Maj( a, b, c );

		g += Sigma1( d ) + Ch( d, e, f ) + 0x71374491 + (w[1]);
		c += g;
		g += Sigma0( h ) + Maj( h, a, b );

		f += Sigma1( c ) + Ch( c, d, e ) + 0xb5c0fbcf + (w[2]);
		b += f;
		f += Sigma0( g ) + Maj( g, h, a );

		e += Sigma1( b ) + Ch( b, c, d ) + 0xe9b5dba5 + (w[3]);
		a += e;
		e += Sigma0( f ) + Maj( f, g, h );

		d += Sigma1( a ) + Ch( a, b, c ) + 0x3956c25b + (w[4]);
		h += d;
		d += Sigma0( e ) + Maj( e, f, g );

		c += Sigma1( h ) + Ch( h, a, b ) + 0x59f111f1 + (w[5]);
		g += c;
		c += Sigma0( d ) + Maj( d, e, f );

		b += Sigma1( g ) + Ch( g, h, a ) + 0x923f82a4 + (w[6]);
		f += b;
		b += Sigma0( c ) + Maj( c, d, e );

		a += Sigma1( f ) + Ch( f, g, h ) + 0xab1c5ed5 + (w[7]);
		e += a;
		a += Sigma0( b ) + Maj( b, c, d );

		h += Sigma1( e ) + Ch( e, f, g ) + 0x5807aa98;
		d += h;
		h += Sigma0( a ) + Maj( a, b, c );

		g += Sigma1( d ) + Ch( d, e, f ) + 0x12835b01;
		c += g;
		g += Sigma0( h ) + Maj( h, a, b );

		f += Sigma1( c ) + Ch( c, d, e ) + 0x243185be;
		b += f;
		f += Sigma0( g ) + Maj( g, h, a );

		e += Sigma1( b ) + Ch( b, c, d ) + 0x550c7dc3;
		a += e;
		e += Sigma0( f ) + Maj( f, g, h );

		d += Sigma1( a ) + Ch( a, b, c ) + 0x72be5d74;
		h += d;
		d += Sigma0( e ) + Maj( e, f, g );

		c += Sigma1( h ) + Ch( h, a, b ) + 0x80deb1fe;
		g += c;
		c += Sigma0( d ) + Maj( d, e, f );

		b += Sigma1( g ) + Ch( g, h, a ) + 0x9bdc06a7;
		f += b;
		b += Sigma0( c ) + Maj( c, d, e );


		a += Sigma1( f ) + Ch( f, g, h ) + 0xc19bf274;
		e += a;
		a += Sigma0( b ) + Maj( b, c, d );



		w[0] += sigma0( w[1] );
		h += Sigma1( e ) + Ch( e, f, g ) + 0xe49b69c1 + ( (w[0]) );
		d += h;
		h += Sigma0( a ) + Maj( a, b, c );

		w[1] += sigma1(256) + sigma0( w[2] );
		g += Sigma1( d ) + Ch( d, e, f ) + 0xefbe4786 + ( (w[1]) );
		c += g;
		g += Sigma0( h ) + Maj( h, a, b );

		w[2] += sigma1( w[0] ) + sigma0( w[3] );
		f += Sigma1( c ) + Ch( c, d, e ) + 0x0fc19dc6 + ( (w[2]) );
		b += f;
		f += Sigma0( g ) + Maj( g, h, a );

		w[3] += sigma1( w[1] ) + sigma0( w[4] );
		e += Sigma1( b ) + Ch( b, c, d ) + 0x240ca1cc + ( (w[3]) );
		a += e;
		e += Sigma0( f ) + Maj( f, g, h );

		w[4] += sigma1( w[2] ) + sigma0( w[5] );
		d += Sigma1( a ) + Ch( a, b, c ) + 0x2de92c6f + ( (w[4]) );
		h += d;
		d += Sigma0( e ) + Maj( e, f, g );

		w[5] += sigma1( w[3] ) + sigma0( w[6] );
		c += Sigma1( h ) + Ch( h, a, b ) + 0x4a7484aa + ( (w[5]) );
		g += c;
		c += Sigma0( d ) + Maj( d, e, f );

		w[6] += sigma1( w[4] ) + 256 + sigma0( w[7] );
		b += Sigma1( g ) + Ch( g, h, a ) + 0x5cb0a9dc + ( (w[6]) );
		f += b;
		b += Sigma0( c ) + Maj( c, d, e );

		w[7] += sigma1( w[5] ) + w[0] + sigma0( 0x80000000 );
		a += Sigma1( f ) + Ch( f, g, h ) + 0x76f988da + ( (w[7]) );
		e += a;
		a += Sigma0( b ) + Maj( b, c, d );

		w[8] = 0x80000000 + sigma1( w[6] ) + w[1];
		h += Sigma1( e ) + Ch( e, f, g ) + 0x983e5152 + ( (w[8]) );
		d += h;
		h += Sigma0( a ) + Maj( a, b, c );

		w[9] = sigma1( w[7] ) + w[2];
		g += Sigma1( d ) + Ch( d, e, f ) + 0xa831c66d + ( (w[9]) );
		c += g;
		g += Sigma0( h ) + Maj( h, a, b );

		w[10] = sigma1( w[8] ) + w[3];
		f += Sigma1( c ) + Ch( c, d, e ) + 0xb00327c8 + ( (w[10]) );
		b += f;
		f += Sigma0( g ) + Maj( g, h, a );

		w[11] = sigma1( w[9] ) + w[4];
		e += Sigma1( b ) + Ch( b, c, d ) + 0xbf597fc7 + ( (w[11]) );
		a += e;
		e += Sigma0( f ) + Maj( f, g, h );

		w[12] = sigma1( w[10] ) + w[5];
		d += Sigma1( a ) + Ch( a, b, c ) + 0xc6e00bf3 + ( (w[12]) );
		h += d;
		d += Sigma0( e ) + Maj( e, f, g );

		w[13] = sigma1( w[11] ) + w[6];
		c += Sigma1( h ) + Ch( h, a, b ) + 0xd5a79147 + ( (w[13]) );
		g += c;
		c += Sigma0( d ) + Maj( d, e, f );

		w[14] = sigma1( w[12] ) + w[7] + sigma0( 256 );
		b += Sigma1( g ) + Ch( g, h, a ) + 0x06ca6351 + ( (w[14]) );
		f += b;
		b += Sigma0( c ) + Maj( c, d, e );

		w[15] = 256 + sigma1( w[13] ) + w[8] + sigma0( w[0] );
		a += Sigma1( f ) + Ch( f, g, h ) + 0x14292967 + ( (w[15]) );
		e += a;
		a += Sigma0( b ) + Maj( b, c, d );



		w[0] += sigma1( w[14] ) + w[9] + sigma0( w[1] );
		h += Sigma1( e ) + Ch( e, f, g ) + 0x27b70a85 + ( (w[0]) );
		d += h;
		h += Sigma0( a ) + Maj( a, b, c );

		w[1] += sigma1( w[15] ) + w[10] + sigma0( w[2] );
		g += Sigma1( d ) + Ch( d, e, f ) + 0x2e1b2138 + ( (w[1]) );
		c += g;
		g += Sigma0( h ) + Maj( h, a, b );

		w[2] += sigma1( w[0] ) + w[11] + sigma0( w[3] );
		f += Sigma1( c ) + Ch( c, d, e ) + 0x4d2c6dfc + ( (w[2]) );
		b += f;
		f += Sigma0( g ) + Maj( g, h, a );

		w[3] += sigma1( w[1] ) + w[12] + sigma0( w[4] );
		e += Sigma1( b ) + Ch( b, c, d ) + 0x53380d13 + ( (w[3]) );
		a += e;
		e += Sigma0( f ) + Maj( f, g, h );

		w[4] += sigma1( w[2] ) + w[13] + sigma0( w[5] );
		d += Sigma1( a ) + Ch( a, b, c ) + 0x650a7354 + ( (w[4]) );
		h += d;
		d += Sigma0( e ) + Maj( e, f, g );

		w[5] += sigma1( w[3] ) + w[14] + sigma0( w[6] );
		c += Sigma1( h ) + Ch( h, a, b ) + 0x766a0abb + ( (w[5]) );
		g += c;
		c += Sigma0( d ) + Maj( d, e, f );

		w[6] += sigma1( w[4] ) + w[15] + sigma0( w[7] );
		b += Sigma1( g ) + Ch( g, h, a ) + 0x81c2c92e + ( (w[6]) );
		f += b;
		b += Sigma0( c ) + Maj( c, d, e );

		w[7] += sigma1( w[5] ) + w[0] + sigma0( w[8] );
		a += Sigma1( f ) + Ch( f, g, h ) + 0x92722c85 + ( (w[7]) );
		e += a;
		a += Sigma0( b ) + Maj( b, c, d );

		w[8] += sigma1( w[6] ) + w[1] + sigma0( w[9] );
		h += Sigma1( e ) + Ch( e, f, g ) + 0xa2bfe8a1 + ( (w[8]) );
		d += h;
		h += Sigma0( a ) + Maj( a, b, c );

		w[9] += sigma1( w[7] ) + w[2] + sigma0( w[10] );
		g += Sigma1( d ) + Ch( d, e, f ) + 0xa81a664b + ( (w[9]) );
		c += g;
		g += Sigma0( h ) + Maj( h, a, b );

		w[10] += sigma1( w[8] ) + w[3] + sigma0( w[11] );
		f += Sigma1( c ) + Ch( c, d, e ) + 0xc24b8b70 + ( (w[10]) );
		b += f;
		f += Sigma0( g ) + Maj( g, h, a );

		w[11] += sigma1( w[9] ) + w[4] + sigma0( w[12] );
		e += Sigma1( b ) + Ch( b, c, d ) + 0xc76c51a3 + ( (w[11]) );
		a += e;
		e += Sigma0( f ) + Maj( f, g, h );

		w[12] += sigma1( w[10] ) + w[5] + sigma0( w[13] );
		d += Sigma1( a ) + Ch( a, b, c ) + 0xd192e819 + ( (w[12]) );
		h += d;
		d += Sigma0( e ) + Maj( e, f, g );

		w[13] += sigma1( w[11] ) + w[6] + sigma0( w[14] );
		c += Sigma1( h ) + Ch( h, a, b ) + 0xd6990624 + ( (w[13]) );
		g += c;
		c += Sigma0( d ) + Maj( d, e, f );

		w[14] += sigma1( w[12] ) + w[7] + sigma0( w[15] );
		b += Sigma1( g ) + Ch( g, h, a ) + 0xf40e3585 + ( (w[14]) );
		f += b;
		b += Sigma0( c ) + Maj( c, d, e );

		w[15] += sigma1( w[13] ) + w[8] + sigma0( w[0] );
		a += Sigma1( f ) + Ch( f, g, h ) + 0x106aa070 + ( (w[15]) );
		e += a;
		a += Sigma0( b ) + Maj( b, c, d );



		w[0] += sigma1( w[14] ) + w[9] + sigma0( w[1] );
		h += Sigma1( e ) + Ch( e, f, g ) + 0x19a4c116 + ( (w[0]) );
		d += h;
		h += Sigma0( a ) + Maj( a, b, c );

		w[1] += sigma1( w[15] ) + w[10] + sigma0( w[2] );
		g += Sigma1( d ) + Ch( d, e, f ) + 0x1e376c08 + ( (w[1]) );
		c += g;
		g += Sigma0( h ) + Maj( h, a, b );

		w[2] += sigma1( w[0] ) + w[11] + sigma0( w[3] );
		f += Sigma1( c ) + Ch( c, d, e ) + 0x2748774c + ( (w[2]) );
		b += f;
		f += Sigma0( g ) + Maj( g, h, a );

		w[3] += sigma1( w[1] ) + w[12] + sigma0( w[4] );
		e += Sigma1( b ) + Ch( b, c, d ) + 0x34b0bcb5 + ( (w[3]) );
		a += e;
		e += Sigma0( f ) + Maj( f, g, h );

		w[4] += sigma1( w[2] ) + w[13] + sigma0( w[5] );
		d += Sigma1( a ) + Ch( a, b, c ) + 0x391c0cb3 + ( (w[4]) );
		h += d;
		d += Sigma0( e ) + Maj( e, f, g );

		w[5] += sigma1( w[3] ) + w[14] + sigma0( w[6] );
		c += Sigma1( h ) + Ch( h, a, b ) + 0x4ed8aa4a + ( (w[5]) );
		g += c;
		c += Sigma0( d ) + Maj( d, e, f );

		w[6] += sigma1( w[4] ) + w[15] + sigma0( w[7] );
		b += Sigma1( g ) + Ch( g, h, a ) + 0x5b9cca4f + ( (w[6]) );
		f += b;
		b += Sigma0( c ) + Maj( c, d, e );

		w[7] += sigma1( w[5] ) + w[0] + sigma0( w[8] );
		a += Sigma1( f ) + Ch( f, g, h ) + 0x682e6ff3 + ( (w[7]) );
		e += a;
		a += Sigma0( b ) + Maj( b, c, d );

		w[8] += sigma1( w[6] ) + w[1] + sigma0( w[9] );
		h += Sigma1( e ) + Ch( e, f, g ) + 0x748f82ee + ( (w[8]) );
		d += h;
		h += Sigma0( a ) + Maj( a, b, c );

		w[9] += sigma1( w[7] ) + w[2] + sigma0( w[10] );
		g += Sigma1( d ) + Ch( d, e, f ) + 0x78a5636f + ( (w[9]) );
		c += g;
		g += Sigma0( h ) + Maj( h, a, b );

		w[10] += sigma1( w[8] ) + w[3] + sigma0( w[11] );
		f += Sigma1( c ) + Ch( c, d, e ) + 0x84c87814 + ( (w[10]) );
		b += f;
		f += Sigma0( g ) + Maj( g, h, a );

		w[11] += sigma1( w[9] ) + w[4] + sigma0( w[12] );
		e += Sigma1( b ) + Ch( b, c, d ) + 0x8cc70208 + ( (w[11]) );
		a += e;
		e += Sigma0( f ) + Maj( f, g, h );

		w[12] += sigma1( w[10] ) + w[5] + sigma0( w[13] );
		d += Sigma1( a ) + Ch( a, b, c ) + 0x90befffa + ( (w[12]) );
		h += d;
		d += Sigma0( e ) + Maj( e, f, g );

		w[13] += sigma1( w[11] ) + w[6] + sigma0( w[14] );
		c += Sigma1( h ) + Ch( h, a, b ) + 0xa4506ceb + ( (w[13]) );
		g += c;
		c += Sigma0( d ) + Maj( d, e, f );

		w[14] += sigma1( w[12] ) + w[7] + sigma0( w[15] );
		b += Sigma1( g ) + Ch( g, h, a ) + 0xbef9a3f7 + ( (w[14]) );
		f += b;
		b += Sigma0( c ) + Maj( c, d, e );

		w[15] += sigma1( w[13] ) + w[8] + sigma0( w[0] );
		a += Sigma1( f ) + Ch( f, g, h ) + 0xc67178f2 + ( (w[15]) );
		e += a;
		a += Sigma0( b ) + Maj( b, c, d );

		w[0] = H[0] + a;
		w[1] = H[1] + b;
		w[2] = H[2] + c;
		w[3] = H[3] + d;
		w[4] = H[4] + e;
		w[5] = H[5] + f;
		w[6] = H[6] + g;
		w[7] = H[7] + h;
	}


        uint32_t cmp = 0;
        uint32_t *v = (uint32_t *) salt->hash;
	a = H[0];
	b = H[1];
	c = H[2];
	d = H[3];
	e = H[4];
	f = H[5];
	g = H[6];
	h = H[7];

	h += Sigma1( e ) + Ch( e, f, g ) + 0x428a2f98 + (w[0]);
	d += h;
	h += Sigma0( a ) + Maj( a, b, c );

	g += Sigma1( d ) + Ch( d, e, f ) + 0x71374491 + (w[1]);
	c += g;
	g += Sigma0( h ) + Maj( h, a, b );

	f += Sigma1( c ) + Ch( c, d, e ) + 0xb5c0fbcf + (w[2]);
	b += f;
	f += Sigma0( g ) + Maj( g, h, a );

	e += Sigma1( b ) + Ch( b, c, d ) + 0xe9b5dba5 + (w[3]);
	a += e;
	e += Sigma0( f ) + Maj( f, g, h );

	d += Sigma1( a ) + Ch( a, b, c ) + 0x3956c25b + (w[4]);
	h += d;
	d += Sigma0( e ) + Maj( e, f, g );

	c += Sigma1( h ) + Ch( h, a, b ) + 0x59f111f1 + (w[5]);
	g += c;
	c += Sigma0( d ) + Maj( d, e, f );

	b += Sigma1( g ) + Ch( g, h, a ) + 0x923f82a4 + (w[6]);
	f += b;
	b += Sigma0( c ) + Maj( c, d, e );

	a += Sigma1( f ) + Ch( f, g, h ) + 0xab1c5ed5 + (w[7]);
	e += a;
	a += Sigma0( b ) + Maj( b, c, d );

	h += Sigma1( e ) + Ch( e, f, g ) + 0x5807aa98;
	d += h;
	h += Sigma0( a ) + Maj( a, b, c );

	g += Sigma1( d ) + Ch( d, e, f ) + 0x12835b01;
	c += g;
	g += Sigma0( h ) + Maj( h, a, b );

	f += Sigma1( c ) + Ch( c, d, e ) + 0x243185be;
	b += f;
	f += Sigma0( g ) + Maj( g, h, a );

	e += Sigma1( b ) + Ch( b, c, d ) + 0x550c7dc3;
	a += e;
	e += Sigma0( f ) + Maj( f, g, h );

	d += Sigma1( a ) + Ch( a, b, c ) + 0x72be5d74;
	h += d;
	d += Sigma0( e ) + Maj( e, f, g );

	c += Sigma1( h ) + Ch( h, a, b ) + 0x80deb1fe;
	g += c;
	c += Sigma0( d ) + Maj( d, e, f );

	b += Sigma1( g ) + Ch( g, h, a ) + 0x9bdc06a7;
	f += b;
	b += Sigma0( c ) + Maj( c, d, e );


	a += Sigma1( f ) + Ch( f, g, h ) + 0xc19bf274;
	e += a;
	a += Sigma0( b ) + Maj( b, c, d );



	w[0] += sigma0( w[1] );
	h += Sigma1( e ) + Ch( e, f, g ) + 0xe49b69c1 + ( (w[0]) );
	d += h;
	h += Sigma0( a ) + Maj( a, b, c );

	w[1] += sigma1(256) + sigma0( w[2] );
	g += Sigma1( d ) + Ch( d, e, f ) + 0xefbe4786 + ( (w[1]) );
	c += g;
	g += Sigma0( h ) + Maj( h, a, b );

	w[2] += sigma1( w[0] ) + sigma0( w[3] );
	f += Sigma1( c ) + Ch( c, d, e ) + 0x0fc19dc6 + ( (w[2]) );
	b += f;
	f += Sigma0( g ) + Maj( g, h, a );

	w[3] += sigma1( w[1] ) + sigma0( w[4] );
	e += Sigma1( b ) + Ch( b, c, d ) + 0x240ca1cc + ( (w[3]) );
	a += e;
	e += Sigma0( f ) + Maj( f, g, h );

	w[4] += sigma1( w[2] ) + sigma0( w[5] );
	d += Sigma1( a ) + Ch( a, b, c ) + 0x2de92c6f + ( (w[4]) );
	h += d;
	d += Sigma0( e ) + Maj( e, f, g );

	w[5] += sigma1( w[3] ) + sigma0( w[6] );
	c += Sigma1( h ) + Ch( h, a, b ) + 0x4a7484aa + ( (w[5]) );
	g += c;
	c += Sigma0( d ) + Maj( d, e, f );

	w[6] += sigma1( w[4] ) + 256 + sigma0( w[7] );
	b += Sigma1( g ) + Ch( g, h, a ) + 0x5cb0a9dc + ( (w[6]) );
	f += b;
	b += Sigma0( c ) + Maj( c, d, e );

	w[7] += sigma1( w[5] ) + w[0] + sigma0( 0x80000000 );
	a += Sigma1( f ) + Ch( f, g, h ) + 0x76f988da + ( (w[7]) );
	e += a;
	a += Sigma0( b ) + Maj( b, c, d );

	w[8] = 0x80000000 + sigma1( w[6] ) + w[1];
	h += Sigma1( e ) + Ch( e, f, g ) + 0x983e5152 + ( (w[8]) );
	d += h;
	h += Sigma0( a ) + Maj( a, b, c );

	w[9] = sigma1( w[7] ) + w[2];
	g += Sigma1( d ) + Ch( d, e, f ) + 0xa831c66d + ( (w[9]) );
	c += g;
	g += Sigma0( h ) + Maj( h, a, b );

	w[10] = sigma1( w[8] ) + w[3];
	f += Sigma1( c ) + Ch( c, d, e ) + 0xb00327c8 + ( (w[10]) );
	b += f;
	f += Sigma0( g ) + Maj( g, h, a );

	w[11] = sigma1( w[9] ) + w[4];
	e += Sigma1( b ) + Ch( b, c, d ) + 0xbf597fc7 + ( (w[11]) );
	a += e;
	e += Sigma0( f ) + Maj( f, g, h );

	w[12] = sigma1( w[10] ) + w[5];
	d += Sigma1( a ) + Ch( a, b, c ) + 0xc6e00bf3 + ( (w[12]) );
	h += d;
	d += Sigma0( e ) + Maj( e, f, g );

	w[13] = sigma1( w[11] ) + w[6];
	c += Sigma1( h ) + Ch( h, a, b ) + 0xd5a79147 + ( (w[13]) );
	g += c;
	c += Sigma0( d ) + Maj( d, e, f );

	w[14] = sigma1( w[12] ) + w[7] + sigma0( 256 );
	b += Sigma1( g ) + Ch( g, h, a ) + 0x06ca6351 + ( (w[14]) );
	f += b;
	b += Sigma0( c ) + Maj( c, d, e );

	w[15] = 256 + sigma1( w[13] ) + w[8] + sigma0( w[0] );
	a += Sigma1( f ) + Ch( f, g, h ) + 0x14292967 + ( (w[15]) );
	e += a;
	a += Sigma0( b ) + Maj( b, c, d );



	w[0] += sigma1( w[14] ) + w[9] + sigma0( w[1] );
	h += Sigma1( e ) + Ch( e, f, g ) + 0x27b70a85 + ( (w[0]) );
	d += h;
	h += Sigma0( a ) + Maj( a, b, c );

	w[1] += sigma1( w[15] ) + w[10] + sigma0( w[2] );
	g += Sigma1( d ) + Ch( d, e, f ) + 0x2e1b2138 + ( (w[1]) );
	c += g;
	g += Sigma0( h ) + Maj( h, a, b );

	w[2] += sigma1( w[0] ) + w[11] + sigma0( w[3] );
	f += Sigma1( c ) + Ch( c, d, e ) + 0x4d2c6dfc + ( (w[2]) );
	b += f;
	f += Sigma0( g ) + Maj( g, h, a );

	w[3] += sigma1( w[1] ) + w[12] + sigma0( w[4] );
	e += Sigma1( b ) + Ch( b, c, d ) + 0x53380d13 + ( (w[3]) );
	a += e;
	e += Sigma0( f ) + Maj( f, g, h );

	w[4] += sigma1( w[2] ) + w[13] + sigma0( w[5] );
	d += Sigma1( a ) + Ch( a, b, c ) + 0x650a7354 + ( (w[4]) );
	h += d;
	d += Sigma0( e ) + Maj( e, f, g );

	w[5] += sigma1( w[3] ) + w[14] + sigma0( w[6] );
	c += Sigma1( h ) + Ch( h, a, b ) + 0x766a0abb + ( (w[5]) );
	g += c;
	c += Sigma0( d ) + Maj( d, e, f );

	w[6] += sigma1( w[4] ) + w[15] + sigma0( w[7] );
	b += Sigma1( g ) + Ch( g, h, a ) + 0x81c2c92e + ( (w[6]) );
	f += b;
	b += Sigma0( c ) + Maj( c, d, e );

	w[7] += sigma1( w[5] ) + w[0] + sigma0( w[8] );
	a += Sigma1( f ) + Ch( f, g, h ) + 0x92722c85 + ( (w[7]) );
	e += a;
	a += Sigma0( b ) + Maj( b, c, d );

	w[8] += sigma1( w[6] ) + w[1] + sigma0( w[9] );
	h += Sigma1( e ) + Ch( e, f, g ) + 0xa2bfe8a1 + ( (w[8]) );
	d += h;
	h += Sigma0( a ) + Maj( a, b, c );

	w[9] += sigma1( w[7] ) + w[2] + sigma0( w[10] );
	g += Sigma1( d ) + Ch( d, e, f ) + 0xa81a664b + ( (w[9]) );
	c += g;
	g += Sigma0( h ) + Maj( h, a, b );

	w[10] += sigma1( w[8] ) + w[3] + sigma0( w[11] );
	f += Sigma1( c ) + Ch( c, d, e ) + 0xc24b8b70 + ( (w[10]) );
	b += f;
	f += Sigma0( g ) + Maj( g, h, a );

	w[11] += sigma1( w[9] ) + w[4] + sigma0( w[12] );
	e += Sigma1( b ) + Ch( b, c, d ) + 0xc76c51a3 + ( (w[11]) );
	a += e;
	e += Sigma0( f ) + Maj( f, g, h );

	w[12] += sigma1( w[10] ) + w[5] + sigma0( w[13] );
	d += Sigma1( a ) + Ch( a, b, c ) + 0xd192e819 + ( (w[12]) );
	h += d;
	d += Sigma0( e ) + Maj( e, f, g );

	w[13] += sigma1( w[11] ) + w[6] + sigma0( w[14] );
	c += Sigma1( h ) + Ch( h, a, b ) + 0xd6990624 + ( (w[13]) );
	g += c;
	c += Sigma0( d ) + Maj( d, e, f );

	w[14] += sigma1( w[12] ) + w[7] + sigma0( w[15] );
	b += Sigma1( g ) + Ch( g, h, a ) + 0xf40e3585 + ( (w[14]) );
	f += b;
	b += Sigma0( c ) + Maj( c, d, e );

	w[15] += sigma1( w[13] ) + w[8] + sigma0( w[0] );
	a += Sigma1( f ) + Ch( f, g, h ) + 0x106aa070 + ( (w[15]) );
	e += a;
	a += Sigma0( b ) + Maj( b, c, d );



	w[0] += sigma1( w[14] ) + w[9] + sigma0( w[1] );
	h += Sigma1( e ) + Ch( e, f, g ) + 0x19a4c116 + ( (w[0]) );
	d += h;
	h += Sigma0( a ) + Maj( a, b, c );

	w[1] += sigma1( w[15] ) + w[10] + sigma0( w[2] );
	g += Sigma1( d ) + Ch( d, e, f ) + 0x1e376c08 + ( (w[1]) );
	c += g;
	g += Sigma0( h ) + Maj( h, a, b );

	w[2] += sigma1( w[0] ) + w[11] + sigma0( w[3] );
	f += Sigma1( c ) + Ch( c, d, e ) + 0x2748774c + ( (w[2]) );
	b += f;
	f += Sigma0( g ) + Maj( g, h, a );

	w[3] += sigma1( w[1] ) + w[12] + sigma0( w[4] );
	e += Sigma1( b ) + Ch( b, c, d ) + 0x34b0bcb5 + ( (w[3]) );
	a += e;
	e += Sigma0( f ) + Maj( f, g, h );

	w[4] += sigma1( w[2] ) + w[13] + sigma0( w[5] );
	d += Sigma1( a ) + Ch( a, b, c ) + 0x391c0cb3 + ( (w[4]) );
	h += d;
	d += Sigma0( e ) + Maj( e, f, g );

	w[5] += sigma1( w[3] ) + w[14] + sigma0( w[6] );
	c += Sigma1( h ) + Ch( h, a, b ) + 0x4ed8aa4a + ( (w[5]) );
	g += c;
	c += Sigma0( d ) + Maj( d, e, f );

	w[6] += sigma1( w[4] ) + w[15] + sigma0( w[7] );
	b += Sigma1( g ) + Ch( g, h, a ) + 0x5b9cca4f + ( (w[6]) );
	f += b;
	b += Sigma0( c ) + Maj( c, d, e );

	w[7] += sigma1( w[5] ) + w[0] + sigma0( w[8] );
	a += Sigma1( f ) + Ch( f, g, h ) + 0x682e6ff3 + ( (w[7]) );
	e += a;
	a += Sigma0( b ) + Maj( b, c, d );

	w[8] += sigma1( w[6] ) + w[1] + sigma0( w[9] );
	h += Sigma1( e ) + Ch( e, f, g ) + 0x748f82ee + ( (w[8]) );
	d += h;
	h += Sigma0( a ) + Maj( a, b, c );

	w[9] += sigma1( w[7] ) + w[2] + sigma0( w[10] );
	g += Sigma1( d ) + Ch( d, e, f ) + 0x78a5636f + ( (w[9]) );
	c += g;
	g += Sigma0( h ) + Maj( h, a, b );

	w[10] += sigma1( w[8] ) + w[3] + sigma0( w[11] );
	f += Sigma1( c ) + Ch( c, d, e ) + 0x84c87814 + ( (w[10]) );
	b += f;
	f += Sigma0( g ) + Maj( g, h, a );

	w[11] += sigma1( w[9] ) + w[4] + sigma0( w[12] );
	e += Sigma1( b ) + Ch( b, c, d ) + 0x8cc70208 + ( (w[11]) );
	a += e;
	e += Sigma0( f ) + Maj( f, g, h );

	w[12] += sigma1( w[10] ) + w[5] + sigma0( w[13] );
	d += Sigma1( a ) + Ch( a, b, c ) + 0x90befffa + ( (w[12]) );
	h += d;
	if(h + H[7] == v[7])
	{
		d += Sigma0( e ) + Maj( e, f, g );
		w[13] += sigma1( w[11] ) + w[6] + sigma0( w[14] );
		c += Sigma1( h ) + Ch( h, a, b ) + 0xa4506ceb + ( (w[13]) );
		g += c;
		c += Sigma0( d ) + Maj( d, e, f );
		w[14] += sigma1( w[12] ) + w[7] + sigma0( w[15] );
		b += Sigma1( g ) + Ch( g, h, a ) + 0xbef9a3f7 + ( (w[14]) );
		f += b;
		b += Sigma0( c ) + Maj( c, d, e );
		w[15] += sigma1( w[13] ) + w[8] + sigma0( w[0] );
		a += Sigma1( f ) + Ch( f, g, h ) + 0xc67178f2 + ( (w[15]) );
		e += a;
		if(a + Sigma0( b ) + Maj( b, c, d ) + H[0] == v[0] && b + H[1] == v[1] && c + H[2] == v[2] && d + H[3] == v[3] && e + H[4] == v[4] && f + H[5] == v[5] && g + H[6] == v[6])
		{
			cmp = 1;
		}
	}
        out[idx].cracked = cmp;
}

extern "C" void gpu_pwpass(pwsafe_pass * host_in, pwsafe_salt * host_salt,
                           pwsafe_hash * host_out, int count)
{
        pwsafe_pass *cuda_pass = NULL;  ///passwords
        pwsafe_salt *cuda_salt = NULL;  ///salt
        pwsafe_hash *cuda_hash = NULL;  ///hashes
	int blocks = (count + THREADS - 1) / THREADS;

        ///Aloc memory and copy data to gpu
        cudaMalloc(&cuda_pass, PWSAFE_IN_SIZE);
        cudaMalloc(&cuda_salt, PWSAFE_SALT_SIZE);
        cudaMalloc(&cuda_hash, PWSAFE_OUT_SIZE);
	///Somehow this memset, which is not required, speeds things up a bit
	cudaMemset(cuda_hash, 0, PWSAFE_OUT_SIZE);
        cudaMemcpy(cuda_pass, host_in, PWSAFE_IN_SIZE, cudaMemcpyHostToDevice);
        cudaMemcpy(cuda_salt, host_salt, PWSAFE_SALT_SIZE,
            cudaMemcpyHostToDevice);

        ///Run kernel and wait for execution end
        kernel_pwsafe <<< blocks, THREADS >>> (cuda_pass, cuda_salt,
            cuda_hash);
        cudaThreadSynchronize();
	HANDLE_ERROR(cudaGetLastError());

        ///Free memory and copy results back
        cudaMemcpy(host_out, cuda_hash, PWSAFE_OUT_SIZE,
            cudaMemcpyDeviceToHost);
        cudaFree(cuda_pass);
        cudaFree(cuda_salt);
        cudaFree(cuda_hash);
}


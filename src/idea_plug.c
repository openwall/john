/* crypto/idea/idea.h */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the routines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgment:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publicly available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef IDEA_H_JtR
#define IDEA_H_JtR

#define IDEA_ENCRYPT	1
#define IDEA_DECRYPT	0

#define IDEA_BLOCK	8
#define IDEA_KEY_LENGTH	16

#include "idea-JtR.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


/* crypto/idea/idea_lcl.h */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 */

/* The new form of this macro (check if the a*b == 0) was suggested by
 * Colin Plumb <colin@nyx10.cs.du.edu> */
/* Removal of the inner if from from Wei Dai 24/4/96 */
#define idea_mul(r,a,b,ul) \
ul=(unsigned long)a*b; \
if (ul != 0) \
	{ \
	r=(ul&0xffff)-(ul>>16); \
	r-=((r)>>16); \
	} \
else \
	r=(-(int)a-b+1); /* assuming a or b is 0 and in range */

#ifdef undef
#define idea_mul(r,a,b,ul,sl) \
if (a == 0) r=(0x10001-b)&0xffff; \
else if (b == 0) r=(0x10001-a)&0xffff; \
else	{ \
	ul=(unsigned long)a*b; \
	sl=(ul&0xffff)-(ul>>16); \
	if (sl <= 0) sl+=0x10001; \
	r=sl; \
	}
#endif

/*  7/12/95 - Many thanks to Rhys Weatherley <rweather@us.oracle.com>
 * for pointing out that I was assuming little endian
 * byte order for all quantities what idea
 * actually used bigendian.  No where in the spec does it mention
 * this, it is all in terms of 16 bit numbers and even the example
 * does not use byte streams for the input example :-(.
 * If you byte swap each pair of input, keys and iv, the functions
 * would produce the output as the old version :-(.
 */

/* NOTE - c is not incremented as per n2l */
#define n2ln(c,l1,l2,n)	{ \
			c+=n; \
			l1=l2=0; \
			switch (n) { \
			case 8: l2 =((unsigned long)(*(--(c))))    ; \
			case 7: l2|=((unsigned long)(*(--(c))))<< 8; \
			case 6: l2|=((unsigned long)(*(--(c))))<<16; \
			case 5: l2|=((unsigned long)(*(--(c))))<<24; \
			case 4: l1 =((unsigned long)(*(--(c))))    ; \
			case 3: l1|=((unsigned long)(*(--(c))))<< 8; \
			case 2: l1|=((unsigned long)(*(--(c))))<<16; \
			case 1: l1|=((unsigned long)(*(--(c))))<<24; \
				} \
			}

/* NOTE - c is not incremented as per l2n */
#define l2nn(l1,l2,c,n)	{ \
			c+=n; \
			switch (n) { \
			case 8: *(--(c))=(unsigned char)(((l2)    )&0xff); \
			case 7: *(--(c))=(unsigned char)(((l2)>> 8)&0xff); \
			case 6: *(--(c))=(unsigned char)(((l2)>>16)&0xff); \
			case 5: *(--(c))=(unsigned char)(((l2)>>24)&0xff); \
			case 4: *(--(c))=(unsigned char)(((l1)    )&0xff); \
			case 3: *(--(c))=(unsigned char)(((l1)>> 8)&0xff); \
			case 2: *(--(c))=(unsigned char)(((l1)>>16)&0xff); \
			case 1: *(--(c))=(unsigned char)(((l1)>>24)&0xff); \
				} \
			}

#undef n2l
#define n2l(c,l)        (l =((unsigned long)(*((c)++)))<<24L, \
                         l|=((unsigned long)(*((c)++)))<<16L, \
                         l|=((unsigned long)(*((c)++)))<< 8L, \
                         l|=((unsigned long)(*((c)++))))

#undef l2n
#define l2n(l,c)        (*((c)++)=(unsigned char)(((l)>>24L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                         *((c)++)=(unsigned char)(((l)     )&0xff))

#undef s2n
#define s2n(l,c)	(*((c)++)=(unsigned char)(((l)     )&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8L)&0xff))

#undef n2s
#define n2s(c,l)	(l =((IDEA_INT)(*((c)++)))<< 8L, \
			 l|=((IDEA_INT)(*((c)++)))      )

#ifdef undef
/* NOTE - c is not incremented as per c2l */
#define c2ln(c,l1,l2,n)	{ \
			c+=n; \
			l1=l2=0; \
			switch (n) { \
			case 8: l2 =((unsigned long)(*(--(c))))<<24; \
			case 7: l2|=((unsigned long)(*(--(c))))<<16; \
			case 6: l2|=((unsigned long)(*(--(c))))<< 8; \
			case 5: l2|=((unsigned long)(*(--(c))));     \
			case 4: l1 =((unsigned long)(*(--(c))))<<24; \
			case 3: l1|=((unsigned long)(*(--(c))))<<16; \
			case 2: l1|=((unsigned long)(*(--(c))))<< 8; \
			case 1: l1|=((unsigned long)(*(--(c))));     \
				} \
			}

/* NOTE - c is not incremented as per l2c */
#define l2cn(l1,l2,c,n)	{ \
			c+=n; \
			switch (n) { \
			case 8: *(--(c))=(unsigned char)(((l2)>>24)&0xff); \
			case 7: *(--(c))=(unsigned char)(((l2)>>16)&0xff); \
			case 6: *(--(c))=(unsigned char)(((l2)>> 8)&0xff); \
			case 5: *(--(c))=(unsigned char)(((l2)    )&0xff); \
			case 4: *(--(c))=(unsigned char)(((l1)>>24)&0xff); \
			case 3: *(--(c))=(unsigned char)(((l1)>>16)&0xff); \
			case 2: *(--(c))=(unsigned char)(((l1)>> 8)&0xff); \
			case 1: *(--(c))=(unsigned char)(((l1)    )&0xff); \
				} \
			}

#undef c2s
#define c2s(c,l)	(l =((unsigned long)(*((c)++)))    , \
			 l|=((unsigned long)(*((c)++)))<< 8L)

#undef s2c
#define s2c(l,c)	(*((c)++)=(unsigned char)(((l)     )&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8L)&0xff))

#undef c2l
#define c2l(c,l)	(l =((unsigned long)(*((c)++)))     , \
			 l|=((unsigned long)(*((c)++)))<< 8L, \
			 l|=((unsigned long)(*((c)++)))<<16L, \
			 l|=((unsigned long)(*((c)++)))<<24L)

#undef l2c
#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)     )&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>24L)&0xff))
#endif

#define E_IDEA(num) \
	x1&=0xffff; \
	idea_mul(x1,x1,*p,ul); p++; \
	x2+= *(p++); \
	x3+= *(p++); \
	x4&=0xffff; \
	idea_mul(x4,x4,*p,ul); p++; \
	t0=(x1^x3)&0xffff; \
	idea_mul(t0,t0,*p,ul); p++; \
	t1=(t0+(x2^x4))&0xffff; \
	idea_mul(t1,t1,*p,ul); p++; \
	t0+=t1; \
	x1^=t1; \
	x4^=t0; \
	ul=x2^t0; /* do the swap to x3 */ \
	x2=x3^t1; \
	x3=ul;

/* crypto/idea/i_skey.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 */

static IDEA_INT inverse(unsigned int xin);

void JtR_idea_set_encrypt_key(const unsigned char *key, IDEA_KEY_SCHEDULE *ks)
	{
	int i;
	register IDEA_INT *kt,*kf,r0,r1,r2;

	kt= &(ks->data[0][0]);
	n2s(key,kt[0]); n2s(key,kt[1]); n2s(key,kt[2]); n2s(key,kt[3]);
	n2s(key,kt[4]); n2s(key,kt[5]); n2s(key,kt[6]); n2s(key,kt[7]);

	kf=kt;
	kt+=8;
	for (i=0; i<6; i++)
		{
		r2= kf[1];
		r1= kf[2];
		*(kt++)= ((r2<<9) | (r1>>7))&0xffff;
		r0= kf[3];
		*(kt++)= ((r1<<9) | (r0>>7))&0xffff;
		r1= kf[4];
		*(kt++)= ((r0<<9) | (r1>>7))&0xffff;
		r0= kf[5];
		*(kt++)= ((r1<<9) | (r0>>7))&0xffff;
		r1= kf[6];
		*(kt++)= ((r0<<9) | (r1>>7))&0xffff;
		r0= kf[7];
		*(kt++)= ((r1<<9) | (r0>>7))&0xffff;
		r1= kf[0];
		if (i >= 5) break;
		*(kt++)= ((r0<<9) | (r1>>7))&0xffff;
		*(kt++)= ((r1<<9) | (r2>>7))&0xffff;
		kf+=8;
		}
	}

void JtR_idea_set_decrypt_key(IDEA_KEY_SCHEDULE *ek, IDEA_KEY_SCHEDULE *dk)
	{
	int r;
	register IDEA_INT *fp,*tp,t;

	tp= &(dk->data[0][0]);
	fp= &(ek->data[8][0]);
	for (r=0; r<9; r++)
		{
		*(tp++)=inverse(fp[0]);
		*(tp++)=((int)(0x10000L-fp[2])&0xffff);
		*(tp++)=((int)(0x10000L-fp[1])&0xffff);
		*(tp++)=inverse(fp[3]);
		if (r == 8) break;
		fp-=6;
		*(tp++)=fp[4];
		*(tp++)=fp[5];
		}

	tp= &(dk->data[0][0]);
	t=tp[1];
	tp[1]=tp[2];
	tp[2]=t;

	t=tp[49];
	tp[49]=tp[50];
	tp[50]=t;
	}

/* taken directly from the 'paper' I'll have a look at it later */
static IDEA_INT inverse(unsigned int xin)
	{
	long n1,n2,q,r,b1,b2,t;

	if (xin == 0)
		b2=0;
	else
		{
		n1=0x10001;
		n2=xin;
		b2=1;
		b1=0;

		do	{
			r=(n1%n2);
			q=(n1-r)/n2;
			if (r == 0)
				{ if (b2 < 0) b2=0x10001+b2; }
			else
				{
				n1=n2;
				n2=r;
				t=b2;
				b2=b1-q*b2;
				b1=t;
				}
			} while (r != 0);
		}
	return((IDEA_INT)b2);
	}
/* crypto/idea/i_cbc.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 */

void JtR_idea_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
	     IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int encrypt)
	{
	register unsigned long tin0,tin1;
	register unsigned long tout0,tout1,xor0,xor1;
	register long l=length;
	unsigned long tin[2];

	if (encrypt)
		{
		n2l(iv,tout0);
		n2l(iv,tout1);
		iv-=8;
		for (l-=8; l>=0; l-=8)
			{
			n2l(in,tin0);
			n2l(in,tin1);
			tin0^=tout0;
			tin1^=tout1;
			tin[0]=tin0;
			tin[1]=tin1;
			JtR_idea_encrypt(tin,ks);
			tout0=tin[0]; l2n(tout0,out);
			tout1=tin[1]; l2n(tout1,out);
			}
		if (l != -8)
			{
			n2ln(in,tin0,tin1,l+8);
			tin0^=tout0;
			tin1^=tout1;
			tin[0]=tin0;
			tin[1]=tin1;
			JtR_idea_encrypt(tin,ks);
			tout0=tin[0]; l2n(tout0,out);
			tout1=tin[1]; l2n(tout1,out);
			}
		l2n(tout0,iv);
		l2n(tout1,iv);
		}
	else
		{
		n2l(iv,xor0);
		n2l(iv,xor1);
		iv-=8;
		for (l-=8; l>=0; l-=8)
			{
			n2l(in,tin0); tin[0]=tin0;
			n2l(in,tin1); tin[1]=tin1;
			JtR_idea_encrypt(tin,ks);
			tout0=tin[0]^xor0;
			tout1=tin[1]^xor1;
			l2n(tout0,out);
			l2n(tout1,out);
			xor0=tin0;
			xor1=tin1;
			}
		if (l != -8)
			{
			n2l(in,tin0); tin[0]=tin0;
			n2l(in,tin1); tin[1]=tin1;
			JtR_idea_encrypt(tin,ks);
			tout0=tin[0]^xor0;
			tout1=tin[1]^xor1;
			l2nn(tout0,tout1,out,l+8);
			xor0=tin0;
			xor1=tin1;
			}
		l2n(xor0,iv);
		l2n(xor1,iv);
		}
	tin0=tin1=tout0=tout1=xor0=xor1=0;
	tin[0]=tin[1]=0;
	}

void JtR_idea_encrypt(unsigned long *d, IDEA_KEY_SCHEDULE *key)
	{
	register IDEA_INT *p;
	register unsigned long x1,x2,x3,x4,t0,t1,ul;

	x2=d[0];
	x1=(x2>>16);
	x4=d[1];
	x3=(x4>>16);

	p= &(key->data[0][0]);

	E_IDEA(0);
	E_IDEA(1);
	E_IDEA(2);
	E_IDEA(3);
	E_IDEA(4);
	E_IDEA(5);
	E_IDEA(6);
	E_IDEA(7);

	x1&=0xffff;
	idea_mul(x1,x1,*p,ul); p++;

	t0= x3+ *(p++);
	t1= x2+ *(p++);

	x4&=0xffff;
	idea_mul(x4,x4,*p,ul);

	d[0]=(t0&0xffff)|((x1&0xffff)<<16);
	d[1]=(x4&0xffff)|((t1&0xffff)<<16);
	}
/* crypto/idea/i_cfb64.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the routines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgment:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publicly available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* The input and output encrypted as though 64bit cfb mode is being
 * used.  The extra state information to record how much of the
 * 64bit block we have used is contained in *num;
 */

void JtR_idea_cfb64_encrypt(const unsigned char *in, unsigned char *out,
			long length, IDEA_KEY_SCHEDULE *schedule,
			unsigned char *ivec, int *num, int encrypt)
	{
	register unsigned long v0,v1,t;
	register int n= *num;
	register long l=length;
	unsigned long ti[2];
	unsigned char *iv,c,cc;

	iv=(unsigned char *)ivec;
	if (encrypt)
		{
		while (l--)
			{
			if (n == 0)
				{
				n2l(iv,v0); ti[0]=v0;
				n2l(iv,v1); ti[1]=v1;
				JtR_idea_encrypt((unsigned long *)ti,schedule);
				iv=(unsigned char *)ivec;
				t=ti[0]; l2n(t,iv);
				t=ti[1]; l2n(t,iv);
				iv=(unsigned char *)ivec;
				}
			c= *(in++)^iv[n];
			*(out++)=c;
			iv[n]=c;
			n=(n+1)&0x07;
			}
		}
	else
		{
		while (l--)
			{
			if (n == 0)
				{
				n2l(iv,v0); ti[0]=v0;
				n2l(iv,v1); ti[1]=v1;
				JtR_idea_encrypt((unsigned long *)ti,schedule);
				iv=(unsigned char *)ivec;
				t=ti[0]; l2n(t,iv);
				t=ti[1]; l2n(t,iv);
				iv=(unsigned char *)ivec;
				}
			cc= *(in++);
			c=iv[n];
			iv[n]=cc;
			*(out++)=c^cc;
			n=(n+1)&0x07;
			}
		}
	v0=v1=ti[0]=ti[1]=t=c=cc=0;
	*num=n;
	}

/* crypto/idea/i_ecb.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the routines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgment:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publicly available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* const char *idea_options(void)
	{
	if (sizeof(short) != sizeof(IDEA_INT))
		return("idea(int)");
	else
		return("idea(short)");
	}
*/

void JtR_idea_ecb_encrypt(const unsigned char *in, unsigned char *out,
	     IDEA_KEY_SCHEDULE *ks)
	{
	unsigned long l0,l1,d[2];

	n2l(in,l0); d[0]=l0;
	n2l(in,l1); d[1]=l1;
	JtR_idea_encrypt(d,ks);
	l0=d[0]; l2n(l0,out);
	l1=d[1]; l2n(l1,out);
	l0=l1=d[0]=d[1]=0;
	}

/* crypto/idea/i_ofb64.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the routines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgment:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publicly available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* The input and output encrypted as though 64bit ofb mode is being
 * used.  The extra state information to record how much of the
 * 64bit block we have used is contained in *num;
 */
void JtR_idea_ofb64_encrypt(const unsigned char *in, unsigned char *out,
			long length, IDEA_KEY_SCHEDULE *schedule,
			unsigned char *ivec, int *num)
	{
	register unsigned long v0,v1,t;
	register int n= *num;
	register long l=length;
	unsigned char d[8];
	register char *dp;
	unsigned long ti[2];
	unsigned char *iv;
	int save=0;

	iv=(unsigned char *)ivec;
	n2l(iv,v0);
	n2l(iv,v1);
	ti[0]=v0;
	ti[1]=v1;
	dp=(char *)d;
	l2n(v0,dp);
	l2n(v1,dp);
	while (l--)
		{
		if (n == 0)
			{
			JtR_idea_encrypt((unsigned long *)ti,schedule);
			dp=(char *)d;
			t=ti[0]; l2n(t,dp);
			t=ti[1]; l2n(t,dp);
			save++;
			}
		*(out++)= *(in++)^d[n];
		n=(n+1)&0x07;
		}
	if (save)
		{
		v0=ti[0];
		v1=ti[1];
		iv=(unsigned char *)ivec;
		l2n(v0,iv);
		l2n(v1,iv);
		}
	t=v0=v1=ti[0]=ti[1]=0;
	*num=n;
	}

/* crypto/idea/ideatest.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the routines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgment:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publicly available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifdef IDEATEST
unsigned char k[16]={
	0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
	0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08};

unsigned char in[8]={0x00,0x00,0x00,0x01,0x00,0x02,0x00,0x03};
unsigned char  c[8]={0x11,0xFB,0xED,0x2B,0x01,0x98,0x6D,0xE5};
unsigned char out[80];

char *text="Hello to all people out there";

static unsigned char cfb_key[16]={
	0xe1,0xf0,0xc3,0xd2,0xa5,0xb4,0x87,0x96,
	0x69,0x78,0x4b,0x5a,0x2d,0x3c,0x0f,0x1e,
	};
static unsigned char cfb_iv[80]={0x34,0x12,0x78,0x56,0xab,0x90,0xef,0xcd};
static unsigned char cfb_buf1[40],cfb_buf2[40],cfb_tmp[8];
#define CFB_TEST_SIZE 24
static unsigned char plain[CFB_TEST_SIZE]=
        {
        0x4e,0x6f,0x77,0x20,0x69,0x73,
        0x20,0x74,0x68,0x65,0x20,0x74,
        0x69,0x6d,0x65,0x20,0x66,0x6f,
        0x72,0x20,0x61,0x6c,0x6c,0x20
        };
static unsigned char cfb_cipher64[CFB_TEST_SIZE]={
	0x59,0xD8,0xE2,0x65,0x00,0x58,0x6C,0x3F,
	0x2C,0x17,0x25,0xD0,0x1A,0x38,0xB7,0x2A,
	0x39,0x61,0x37,0xDC,0x79,0xFB,0x9F,0x45

/*	0xF9,0x78,0x32,0xB5,0x42,0x1A,0x6B,0x38,
	0x9A,0x44,0xD6,0x04,0x19,0x43,0xC4,0xD9,
	0x3D,0x1E,0xAE,0x47,0xFC,0xCF,0x29,0x0B,*/
	};

static int cfb64_test(unsigned char *cfb_cipher);
static char *pt(unsigned char *p);

int main(int argc, char *argv[])
	{
	int i,err=0;
	IDEA_KEY_SCHEDULE key,dkey;
	unsigned char iv[8];

	JtR_idea_set_encrypt_key(k,&key);
	JtR_idea_ecb_encrypt(in,out,&key);
	if (memcmp(out,c,8) != 0)
		{
		printf("ecb idea error encrypting\n");
		printf("got     :");
		for (i=0; i<8; i++)
			printf("%02X ",out[i]);
		printf("\n");
		printf("expected:");
		for (i=0; i<8; i++)
			printf("%02X ",c[i]);
		err=20;
		printf("\n");
		}

	JtR_idea_set_decrypt_key(&key,&dkey);
	JtR_idea_ecb_encrypt(c,out,&dkey);
	if (memcmp(out,in,8) != 0)
		{
		printf("ecb idea error decrypting\n");
		printf("got     :");
		for (i=0; i<8; i++)
			printf("%02X ",out[i]);
		printf("\n");
		printf("expected:");
		for (i=0; i<8; i++)
			printf("%02X ",in[i]);
		printf("\n");
		err=3;
		}

	if (err == 0) printf("ecb idea ok\n");

	memcpy(iv,k,8);
	JtR_idea_cbc_encrypt((unsigned char *)text,out,strlen(text)+1,&key,iv,1);
	memcpy(iv,k,8);
	JtR_idea_cbc_encrypt(out,out,8,&dkey,iv,0);
	JtR_idea_cbc_encrypt(&(out[8]),&(out[8]),strlen(text)+1-8,&dkey,iv,0);
	if (memcmp(text,out,strlen(text)+1) != 0)
		{
		printf("cbc idea bad\n");
		err=4;
		}
	else
		printf("cbc idea ok\n");

	printf("cfb64 idea ");
	if (cfb64_test(cfb_cipher64))
		{
		printf("bad\n");
		err=5;
		}
	else
		printf("ok\n");

	return(err);
	}

static int cfb64_test(unsigned char *cfb_cipher)
        {
        IDEA_KEY_SCHEDULE eks,dks;
        int err=0,i,n;

        JtR_idea_set_encrypt_key(cfb_key,&eks);
        JtR_idea_set_decrypt_key(&eks,&dks);
        memcpy(cfb_tmp,cfb_iv,8);
        n=0;
        JtR_idea_cfb64_encrypt(plain,cfb_buf1,(long)12,&eks,
                cfb_tmp,&n,IDEA_ENCRYPT);
        JtR_idea_cfb64_encrypt(&(plain[12]),&(cfb_buf1[12]),
                (long)CFB_TEST_SIZE-12,&eks,
                cfb_tmp,&n,IDEA_ENCRYPT);
        if (memcmp(cfb_cipher,cfb_buf1,CFB_TEST_SIZE) != 0)
                {
                err=1;
                printf("idea_cfb64_encrypt encrypt error\n");
                for (i=0; i<CFB_TEST_SIZE; i+=8)
                        printf("%s\n",pt(&(cfb_buf1[i])));
                }
        memcpy(cfb_tmp,cfb_iv,8);
        n=0;
        JtR_idea_cfb64_encrypt(cfb_buf1,cfb_buf2,(long)17,&eks,
                cfb_tmp,&n,IDEA_DECRYPT);
        JtR_idea_cfb64_encrypt(&(cfb_buf1[17]),&(cfb_buf2[17]),
                (long)CFB_TEST_SIZE-17,&dks,
                cfb_tmp,&n,IDEA_DECRYPT);
        if (memcmp(plain,cfb_buf2,CFB_TEST_SIZE) != 0)
                {
                err=1;
                printf("idea_cfb_encrypt decrypt error\n");
                for (i=0; i<24; i+=8)
                        printf("%s\n",pt(&(cfb_buf2[i])));
                }
        return(err);
        }

static char *pt(unsigned char *p)
	{
	static char bufs[10][20];
	static int bnum=0;
	char *ret;
	int i;
	static char *f="0123456789ABCDEF";

	ret= &(bufs[bnum++][0]);
	bnum%=10;
	for (i=0; i<8; i++)
		{
		ret[i*2]=f[(p[i]>>4)&0xf];
		ret[i*2+1]=f[p[i]&0xf];
		}
	ret[16]='\0';
	return(ret);
	}
#endif

#endif

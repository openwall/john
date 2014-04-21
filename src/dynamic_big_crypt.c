/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2013. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2013 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Generic 'scriptable' hash cracker for JtR.  These are the 'larger' crypt
 * items. They have been separated from dynamic_fmt.c, and placed into this
 * stand alone file.  In this code, there are a lot of lines of code, but
 * the code is very cookie cutter.
 *
 */

#include "arch.h"

/* OMP code is b0rken - it assumes all PARA's are the same */
#if defined(_OPENMP) && defined(MMX_COEF) &&	  \
	(SHA1_SSE_PARA != MD5_SSE_PARA || \
	SHA1_SSE_PARA != MD4_SSE_PARA || \
	 MD4_SSE_PARA != MD5_SSE_PARA)
#undef _OPENMP
#define WAS_OPENMP
#endif

#if defined (MMX_COEF) && MMX_COEF==2 && defined (_OPENMP)
// NO thread support for MMX.  Only OpenSSL (CTX model), or SSE intrinsics have
// thread support.  The older md5_mmx.S/sha1_mmx.S files are NOT thread safe.
#undef _OPENMP
#define WAS_OPENMP
#endif
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "sha2.h"
#include "md5.h"
#include "md4.h"
#include "stdint.h"
#include "gost.h"
// this one is going to be harder.  only haval_256_5 is implemented in CPAN perl, making genation of test cases harder.
// Also, there are 15 different hashes in this 'family'.
#include "sph_haval.h"

#include "sph_ripemd.h"
#include "sph_tiger.h"
#include "sph_whirlpool.h"

#include "dynamic.h"
#include "johnswap.h"
#include "sse-intrinsics.h"

#if OPENSSL_VERSION_NUMBER >= 0x10000000
#include "openssl/whrlpool.h"
#else
// on my 32 bit cygwin builds, this code is about 4x slower than the oSSL code.
#define WHIRLPOOL_CTX             sph_whirlpool_context
#define WHIRLPOOL_Init(a)         sph_whirlpool_init(a)
#define WHIRLPOOL_Update(a,b,c)   sph_whirlpool(a,b,c)
#define WHIRLPOOL_Final(a,b)      sph_whirlpool_close(b,a)
#endif

#ifdef _OPENMP
#include <omp.h>
#endif

#include "dynamic_types.h"

#include "memdbg.h"

#define m_count m_Dynamic_Count
extern int m_count;

#define eLargeOut dyna_eLargeOut
extern eLargeOut_t *eLargeOut;

extern MD5_OUT *crypt_key_X86;
extern MD5_OUT *crypt_key2_X86;
extern MD5_IN *input_buf_X86;
extern MD5_IN *input_buf2_X86;
extern unsigned int *total_len_X86;
extern unsigned int *total_len2_X86;

extern const char *dynamic_itoa16;

#define curdat Dynamic_curdat
extern private_subformat_data curdat;

#define itoa16_w2 __Dynamic_itoa_w2
#define itoa16_w2_u __Dynamic_itoa_w2_u
#define itoa16_w2_l __Dynamic_itoa_w2_l
extern unsigned short itoa16_w2_u[256], *itoa16_w2;

static inline void eLargeOut_set(eLargeOut_t what, int tid) {
	eLargeOut[tid] = what;
}
static inline int eLargeOut_get(int tid) {
	return eLargeOut[tid];
}

#if !defined (_OPENMP)
#define eLargeOut_set(what, tid)  eLargeOut_set(what, 0)
#define eLargeOut_get(tid)        eLargeOut_get(0)
#endif

/* These SIMPLE setter functions, change how the large hash output format is performed   */
/* Once set, it stays that way, until set a different way.  By DEFAULT (i.e. it is reset */
/* this way each time), when crypt_all is called, the large output is in eBase16 mode    */
// These MIGHT have problems in _OPENMP builds!!
void DynamicFunc__LargeHash_OUTMode_base16(DYNA_OMP_PARAMS) {
	eLargeOut_set(eBase16,tid);
}
void DynamicFunc__LargeHash_OUTMode_base16u(DYNA_OMP_PARAMS) {
	eLargeOut_set(eBase16u,tid);
}
void DynamicFunc__LargeHash_OUTMode_base64(DYNA_OMP_PARAMS) {
	eLargeOut_set(eBase64,tid);
}
void DynamicFunc__LargeHash_OUTMode_base64_nte(DYNA_OMP_PARAMS) {
	eLargeOut_set(eBase64_nte,tid);
}
void DynamicFunc__LargeHash_OUTMode_raw(DYNA_OMP_PARAMS) {
	eLargeOut_set(eBaseRaw,tid);
}

/******************************************************************************
 *****  These helper functions are used by all of the 'LARGE' hash functions.
 *****  These are used to convert an 'out' into the proper format, and writing
 *****  it to the buffer.  Currently we handle base-16, base-16u, base-64 and
 *****  raw buffer writting. These functions do not return any count of bytes
 *****  nor deal with things like overwrite/appending.  That has to be done in
 *****  the calling function.  The caller will get the pointers setup, then call
 *****  these helpers.  Then the caller will update any length values if needed
 *****  based upon what the output pointer was, and what was returned by these
 *****  helpers.  Doing things like this will reduce the size of the large hash
 *****  primative functions.
 ******************************************************************************/
static inline unsigned char *hex_out_buf(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	int j;
	for (j = 0; j < in_byte_cnt; ++j) {
#if ARCH_ALLOWS_UNALIGNED
		*((unsigned short*)cpo) = itoa16_w2[*cpi++];
		cpo += 2;
#else
		*cpo++ = dynamic_itoa16[*cpi>>4];
		*cpo++ = dynamic_itoa16[*cpi&0xF];
		++cpi;
#endif
	}
	return cpo;
}
// NOTE, cpo must be at least in_byte_cnt*2 bytes of buffer
static inline unsigned char *hexu_out_buf(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	int j;
	for (j = 0; j < in_byte_cnt; ++j) {
#if ARCH_ALLOWS_UNALIGNED
		*((unsigned short*)cpo) = itoa16_w2_u[*cpi++];
		cpo += 2;
#else
		*cpo++ = itoa16u[*cpi>>4];
		*cpo++ = itoa16u[*cpi&0xF];
		++cpi;
#endif
	}
	return cpo;
}
// NOTE, cpo must be at least in_byte_cnt bytes of buffer
static inline unsigned char *raw_out_buf(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	int j;
#if ARCH_ALLOWS_UNALIGNED
	// note, all of these 'should' be even divisible by 4.  If not, then we need to rethink this logic.
	uint32_t *pi = (uint32_t*)cpi;
	uint32_t *po = (uint32_t*)cpo;
	in_byte_cnt>>=2;
	for (j = 0; j < in_byte_cnt; ++j)
		*po++ = *pi++;
	return (unsigned char*)po;
#else
	for (j = 0; j < in_byte_cnt; ++j)
		*cpo++ = *cpi++;
	return cpo;
#endif
}

// compatible 'standard' MIME base-64 encoding.
static inline unsigned char *base64_out_buf(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt, int add_eq) {
	static char *_itoa64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	while (in_byte_cnt > 2) {
		*cpo++ = _itoa64[(cpi[0] & 0xfc) >> 2];
		*cpo++ = _itoa64[((cpi[0] & 0x03) << 4) + ((cpi[1] & 0xf0) >> 4)];
		*cpo++ = _itoa64[((cpi[1] & 0x0f) << 2) + ((cpi[2] & 0xc0) >> 6)];
		*cpo++ = _itoa64[cpi[2] & 0x3f];
		cpi += 3;
		in_byte_cnt -= 3;
	}
	// easiest way is to simply have 2 'special' cases to handle these lengths
	if (in_byte_cnt==2)
	{
		*cpo++ = _itoa64[(cpi[0] & 0xfc) >> 2];
		*cpo++ = _itoa64[((cpi[0] & 0x03) << 4) + ((cpi[1] & 0xf0) >> 4)];
		*cpo++ = _itoa64[((cpi[1] & 0x0f) << 2)];
		if (add_eq) *cpo++ = '=';
	}
	if (in_byte_cnt==1)
	{
		*cpo++ = _itoa64[(cpi[0] & 0xfc) >> 2];
		*cpo++ = _itoa64[((cpi[0] & 0x03) << 4)];
		if (add_eq) { *cpo++ = '='; *cpo++ = '='; }
	}
	return cpo;
}

#if 0
void TEST_MIME_crap() {
	SHA_CTX ctx1;
	MD5_CTX ctx;
	SHA256_CTX ctx256;
	SHA512_CTX ctx512;
	unsigned char Data[64], Res[129];
	char *pw="password";

	printf ("pw = %s\n", pw);

	SHA384_Init(&ctx512); 	SHA384_Update(&ctx512, pw, strlen(pw)); 	SHA384_Final(Data, &ctx512);
	memset(Res,0,sizeof(Res));
	hex_out_buf(Data, Res, 48);
	printf ("\nSHA384 data:\nb16=%s\n", Res);
	memset(Res,0,sizeof(Res));
	base64_out_buf(Data, Res, 48);
	printf ("b64=%s\n", Res);

	SHA224_Init(&ctx256); 	SHA224_Update(&ctx256, pw, strlen(pw)); 	SHA224_Final(Data, &ctx256);
	memset(Res,0,sizeof(Res));
	hex_out_buf(Data, Res, 28);
	printf ("\nSHA224 data:\nb16=%s\n", Res);
	memset(Res,0,sizeof(Res));
	base64_out_buf(Data, Res, 28);
	printf ("b64=%s\n", Res);

	SHA1_Init(&ctx1); 	SHA1_Update(&ctx1, pw, strlen(pw)); 	SHA1_Final(Data, &ctx1);
	memset(Res,0,sizeof(Res));
	hex_out_buf(Data, Res, 20);
	printf ("\nSHA1 data:\nb16=%s\n", Res);
	memset(Res,0,sizeof(Res));
	base64_out_buf(Data, Res, 20);
	printf ("b64=%s\n", Res);

	MD5_Init(&ctx); 	MD5_Update(&ctx, pw, strlen(pw)); 	MD5_Final(Data, &ctx);
	memset(Res,0,sizeof(Res));
	hex_out_buf(Data, Res, 16);
	printf ("\nMD5 data:\nb16=%s\n", Res);
	memset(Res,0,sizeof(Res));
	base64_out_buf(Data, Res, 16);
	printf ("b64=%s\n", Res);

	memset(Res,0,sizeof(Res));
	base64_out_buf(Data, Res, 15);
	printf ("\n15 byte MD5 base-16 (should be no trailing ==\nb64=%s\n", Res);

	exit(0);

}
#endif

int large_hash_output(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt, int tid) {
	unsigned char *cpo2=cpo;
	switch(eLargeOut_get(tid)) {
		case eBase16:
			cpo2 = hex_out_buf(cpi, cpo, in_byte_cnt);
			break;
		case eBase16u:
			cpo2 = hexu_out_buf(cpi, cpo, in_byte_cnt);
			break;
		case eBase64:
			cpo2 = base64_out_buf(cpi, cpo, in_byte_cnt, 1);
			break;
		case eBase64_nte:
			cpo2 = base64_out_buf(cpi, cpo, in_byte_cnt, 0);
			break;
		case eBaseRaw:
			cpo2 = raw_out_buf(cpi, cpo, in_byte_cnt);
			break;
		case eUNK:
		default:
			exit(fprintf(stderr, "Error, unknown 'output' state found in large_hash_output function, in %s\n", curdat.dynamic_WHICH_TYPE_SIG));
	}
	return cpo2-cpo;
}

/********************************************************************
 ****  Here are the MD5 functions (Now using 'common' interface)
 *******************************************************************/
#ifdef MD5_SSE_PARA
#define MD5_LOOPS (MMX_COEF*MD5_SSE_PARA)
static const int MD5_inc = MD5_LOOPS;

static inline uint32_t DoMD5_FixBufferLen32(unsigned char *input_buf, int total_len) {
	uint32_t *p;
	uint32_t ret = (total_len / 64) + 1;
	if (total_len % 64 > 55)
		++ret;
	input_buf[total_len] = 0x80;
	p = (uint32_t *)&(input_buf[total_len+1]);
	while (*p && p < (uint32_t *)&input_buf[(ret<<6)])
		*p++ = 0;
	p = (uint32_t *)input_buf;
	p[(ret*16)-2] = (total_len<<3);
	return ret;
}
static void DoMD5_crypt_f_sse(void *in, int len[MD5_LOOPS], void *out) {
	ALIGN(16) ARCH_WORD_32 a[(16*MD5_LOOPS)/sizeof(ARCH_WORD_32)];
	unsigned int i, j, loops[MD5_LOOPS], bMore, cnt;
	unsigned char *cp = (unsigned char*)in;
	for (i = 0; i < MD5_LOOPS; ++i) {
		loops[i] = DoMD5_FixBufferLen32(cp, len[i]);
		cp += 256;
	}
	cp = (unsigned char*)in;
	bMore = 1;
	cnt = 1;
	while (bMore) {
		SSEmd5body(cp, a, a, SSEi_FLAT_IN|SSEi_4BUF_INPUT_FIRST_BLK|(cnt==1?0:SSEi_RELOAD));
		bMore = 0;
		for (i = 0; i < MD5_LOOPS; ++i) {
			if (cnt == loops[i]) {
				unsigned int offx = ((i>>2)*16)+(i&3);
				for (j = 0; j < 4; ++j) {
					((ARCH_WORD_32*)out)[(i<<2)+j] = a[(j<<2)+offx];
				}
			} else if (cnt < loops[i])
				bMore = 1;
		}
		cp += 64;
		++cnt;
	}
}
static void DoMD5_crypt_sse(void *in, int ilen[MD5_LOOPS], void *out[MD5_LOOPS], unsigned int *tot_len, int tid) {
	ALIGN(16) ARCH_WORD_32 a[(16*MD5_LOOPS)/sizeof(ARCH_WORD_32)];
	union yy { unsigned char u[16]; ARCH_WORD_32 a[16/sizeof(ARCH_WORD_32)]; } y;
	unsigned int i, j, loops[MD5_LOOPS], bMore, cnt;
	unsigned char *cp = (unsigned char*)in;
	for (i = 0; i < MD5_LOOPS; ++i) {
		loops[i] = DoMD5_FixBufferLen32(cp, ilen[i]);
		cp += 256;
	}
	cp = (unsigned char*)in;
	bMore = 1;
	cnt = 1;
	while (bMore) {
		SSEmd5body(cp, a, a, SSEi_FLAT_IN|SSEi_4BUF_INPUT_FIRST_BLK|(cnt==1?0:SSEi_RELOAD));
		bMore = 0;
		for (i = 0; i < MD5_LOOPS; ++i) {
			if (cnt == loops[i]) {
				unsigned int offx = ((i>>2)*16)+(i&3);
				for (j = 0; j < 4; ++j) {
					y.a[j] = a[(j<<2)+offx];
				}
				*(tot_len+i) += large_hash_output(y.u, &(((unsigned char*)out[i])[*(tot_len+i)]), 16, tid);
			} else if (cnt < loops[i])
				bMore = 1;
		}
		cp += 64;
		++cnt;
	}
}
#else

#define MD5_LOOPS 1
static const int MD5_inc = 1;

static void inline DoMD5_crypt_f(void *in, int len, void *out) {
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, in, len);
	MD5_Final((unsigned char*)out, &ctx);
}
static void inline DoMD5_crypt(void *in, int ilen, void *out, unsigned int *tot_len, int tid) {
	unsigned char crypt_out[16];
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, in, ilen);
	MD5_Final(crypt_out, &ctx);
	if (eLargeOut[0] == eBase16) {
		// since this is the usual, we avoid the extra overhead of large_hash_output, and go directly to the hex_out.
		hex_out_buf(crypt_out, &(((unsigned char*)out)[*tot_len]), 16);
		*tot_len += 32;
	} else
		*tot_len += large_hash_output(crypt_out, &(((unsigned char*)out)[*tot_len]), 16, tid);
}
#endif

void DynamicFunc__MD5_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD5_inc) {
#ifdef MD5_SSE_PARA
		int len[MD5_LOOPS], j;
		void *out[MD5_LOOPS];
		for (j = 0; j < MD5_LOOPS; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
		}
		DoMD5_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, &(total_len2_X86[i]), tid);
#else
		#if (MD5_X2)
		if (i & 1)
			DoMD5_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &(total_len2_X86[i]), tid);
		else
		#endif
		DoMD5_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &(total_len2_X86[i]), tid);
#endif
	}
}
void DynamicFunc__MD5_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD5_inc) {
#ifdef MD5_SSE_PARA
		int len[MD5_LOOPS], j;
		void *out[MD5_LOOPS];
		for (j = 0; j < MD5_LOOPS; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
		}
		DoMD5_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, &(total_len_X86[i]), tid);
#else
		#if (MD5_X2)
		if (i & 1)
			DoMD5_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &(total_len_X86[i]), tid);
		else
		#endif
		DoMD5_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &(total_len_X86[i]), tid);
#endif
	}
}

void DynamicFunc__MD5_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD5_inc) {
#ifdef MD5_SSE_PARA
		int len[MD5_LOOPS], j;
		unsigned int x[MD5_LOOPS];
		void *out[MD5_LOOPS];
		for (j = 0; j < MD5_LOOPS; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoMD5_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, x, tid);
		for (j = 0; j < MD5_LOOPS; ++j)
			total_len_X86[i+j] = 32;
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoMD5_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &x, tid);
		else
		#endif
		DoMD5_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &x, tid);
		total_len_X86[i] = x;
#endif
	}
}
void DynamicFunc__MD5_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD5_inc) {
#ifdef MD5_SSE_PARA
		int len[MD5_LOOPS], j;
		unsigned int x[MD5_LOOPS];
		void *out[MD5_LOOPS];
		for (j = 0; j < MD5_LOOPS; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoMD5_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, x, tid);
		for (j = 0; j < MD5_LOOPS; ++j)
			total_len2_X86[i+j] = 32;
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoMD5_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &x, tid);
		else
		#endif
		DoMD5_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &x, tid);
		total_len2_X86[i] = x;
#endif
	}
}
void DynamicFunc__MD5_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD5_inc) {
#ifdef MD5_SSE_PARA
		int len[MD5_LOOPS], j;
		unsigned int x[MD5_LOOPS];
		void *out[MD5_LOOPS];
		for (j = 0; j < MD5_LOOPS; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoMD5_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, x, tid);
		for (j = 0; j < MD5_LOOPS; ++j)
			total_len_X86[i+j] = 32;
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoMD5_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &x, tid);
		else
		#endif
		DoMD5_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &x, tid);
		total_len_X86[i] = x;
#endif
	}
}
void DynamicFunc__MD5_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD5_inc) {
#ifdef MD5_SSE_PARA
		int len[MD5_LOOPS], j;
		unsigned int x[MD5_LOOPS];
		void *out[MD5_LOOPS];
		for (j = 0; j < MD5_LOOPS; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoMD5_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, x, tid);
		for (j = 0; j < MD5_LOOPS; ++j)
			total_len2_X86[i+j] = 32;
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoMD5_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &x, tid);
		else
		#endif
		DoMD5_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &x, tid);
		total_len2_X86[i] = x;
#endif
	}
}
void DynamicFunc__MD5_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD5_inc) {
#ifdef MD5_SSE_PARA
	int len[MD5_LOOPS], j;
	for (j = 0; j < MD5_LOOPS; ++j)
		len[j] = total_len_X86[i+j];
	DoMD5_crypt_f_sse(input_buf_X86[i>>MD5_X2].x1.b, len, crypt_key_X86[i>>MD5_X2].x1.b);
#else
	#if (MD5_X2)
		if (i & 1)
			DoMD5_crypt_f(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], crypt_key_X86[i>>MD5_X2].x2.b2);
		else
	#endif
		DoMD5_crypt_f(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], crypt_key_X86[i>>MD5_X2].x1.b);
#endif
	}
}
void DynamicFunc__MD5_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD5_inc) {
#ifdef MD5_SSE_PARA
	int len[MD5_LOOPS], j;
	for (j = 0; j < MD5_LOOPS; ++j)
		len[j] = total_len2_X86[i+j];
	DoMD5_crypt_f_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, crypt_key_X86[i>>MD5_X2].x1.b);
#else
	#if (MD5_X2)
		if (i & 1)
			DoMD5_crypt_f(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], crypt_key_X86[i>>MD5_X2].x2.b2);
		else
	#endif
		DoMD5_crypt_f(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], crypt_key_X86[i>>MD5_X2].x1.b);
#endif
	}
}

/********************************************************************
 ****  Here are the MD4 functions (Now using 'common' interface)
 *******************************************************************/
#ifdef MD4_SSE_PARA
#define MD4_LOOPS (MMX_COEF*MD4_SSE_PARA)
static const int MD4_inc = MD4_LOOPS;

static inline uint32_t DoMD4_FixBufferLen32(unsigned char *input_buf, int total_len) {
	uint32_t *p;
	uint32_t ret = (total_len / 64) + 1;
	if (total_len % 64 > 55)
		++ret;
	input_buf[total_len] = 0x80;
	p = (uint32_t *)&(input_buf[total_len+1]);
	while (*p && p < (uint32_t *)&input_buf[(ret<<6)])
		*p++ = 0;
	p = (uint32_t *)input_buf;
	p[(ret*16)-1] = (total_len<<3);
	return ret;
}
static void DoMD4_crypt_f_sse(void *in, int len[MD4_LOOPS], void *out) {
	ALIGN(16) ARCH_WORD_32 a[(16*MD4_LOOPS)/sizeof(ARCH_WORD_32)];
	unsigned int i, j, loops[MD4_LOOPS], bMore, cnt;
	unsigned char *cp = (unsigned char*)in;
	for (i = 0; i < MD4_LOOPS; ++i) {
		loops[i] = DoMD4_FixBufferLen32(cp, len[i]);
		cp += 256;
	}
	cp = (unsigned char*)in;
	bMore = 1;
	cnt = 1;
	while (bMore) {
		SSEmd4body(cp, a, a, SSEi_FLAT_IN|SSEi_4BUF_INPUT_FIRST_BLK|(cnt==1?0:SSEi_RELOAD));
		bMore = 0;
		for (i = 0; i < MD4_LOOPS; ++i) {
			if (cnt == loops[i]) {
				unsigned int offx = ((i>>2)*16)+(i&3);
				for (j = 0; j < 4; ++j) {
					((ARCH_WORD_32*)out)[(i<<2)+j] = a[(j<<2)+offx];
				}
			} else if (cnt < loops[i])
				bMore = 1;
		}
		cp += 64;
		++cnt;
	}
}
static void DoMD4_crypt_sse(void *in, int ilen[MD4_LOOPS], void *out[MD4_LOOPS], unsigned int *tot_len, int tid) {
	ALIGN(16) ARCH_WORD_32 a[(16*MD4_LOOPS)/sizeof(ARCH_WORD_32)];
	union yy { unsigned char u[16]; ARCH_WORD_32 a[16/sizeof(ARCH_WORD_32)]; } y;
	unsigned int i, j, loops[MD4_LOOPS], bMore, cnt;
	unsigned char *cp = (unsigned char*)in;
	for (i = 0; i < MD4_LOOPS; ++i) {
		loops[i] = DoMD4_FixBufferLen32(cp, ilen[i]);
		cp += 256;
	}
	cp = (unsigned char*)in;
	bMore = 1;
	cnt = 1;
	while (bMore) {
		SSEmd4body(cp, a, a, SSEi_FLAT_IN|SSEi_4BUF_INPUT_FIRST_BLK|(cnt==1?0:SSEi_RELOAD));
		bMore = 0;
		for (i = 0; i < MD4_LOOPS; ++i) {
			if (cnt == loops[i]) {
				unsigned int offx = ((i>>2)*16)+(i&3);
				for (j = 0; j < 4; ++j) {
					y.a[j] = a[(j<<2)+offx];
				}
				*(tot_len+i) += large_hash_output(y.u, &(((unsigned char*)out[i])[*(tot_len+i)]), 16, tid);
			} else if (cnt < loops[i])
				bMore = 1;
		}
		cp += 64;
		++cnt;
	}
}
#else

#define MD4_LOOPS 1
static const int MD4_inc = 1;

static void DoMD4_crypt_f(void *in, int len, void *out) {
	MD4_CTX ctx;
	MD4_Init(&ctx);
	MD4_Update(&ctx, in, len);
	MD4_Final(out, &ctx);
}
static void DoMD4_crypt(void *in, int ilen, void *out, unsigned int *tot_len, int tid) {
	union xx { unsigned char u[16]; ARCH_WORD_32 a[16/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	MD4_CTX ctx;
	MD4_Init(&ctx);
	MD4_Update(&ctx, in, ilen);
	MD4_Final(crypt_out, &ctx);
	*tot_len += large_hash_output(crypt_out, &(((unsigned char*)out)[*tot_len]), 16, tid);
}
#endif

void DynamicFunc__MD4_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD4_inc) {
#ifdef MD4_SSE_PARA
		int len[MD4_LOOPS], j;
		void *out[MD4_LOOPS];
		for (j = 0; j < MD4_LOOPS; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
		}
		DoMD4_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, &(total_len2_X86[i]), tid);
#else
		#if (MD5_X2)
		if (i & 1)
			DoMD4_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &(total_len2_X86[i]), tid);
		else
		#endif
		DoMD4_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &(total_len2_X86[i]), tid);
#endif
	}
}
void DynamicFunc__MD4_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD4_inc) {
#ifdef MD4_SSE_PARA
		int len[MD4_LOOPS], j;
		void *out[MD4_LOOPS];
		for (j = 0; j < MD4_LOOPS; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
		}
		DoMD4_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, &(total_len_X86[i]), tid);
#else
		#if (MD5_X2)
		if (i & 1)
			DoMD4_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &(total_len_X86[i]), tid);
		else
		#endif
		DoMD4_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &(total_len_X86[i]), tid);
#endif
	}
}
void DynamicFunc__MD4_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD4_inc) {
#ifdef MD4_SSE_PARA
		int len[MD4_LOOPS], j;
		unsigned int x[MD4_LOOPS];
		void *out[MD4_LOOPS];
		for (j = 0; j < MD4_LOOPS; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoMD4_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, x, tid);
		for (j = 0; j < MD4_LOOPS; ++j)
			total_len_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoMD4_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &x, tid);
		else
		#endif
		DoMD4_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &x, tid);
		total_len_X86[i] = x;
#endif
	}
}
void DynamicFunc__MD4_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD4_inc) {
#ifdef MD4_SSE_PARA
		int len[MD4_LOOPS], j;
		unsigned int x[MD4_LOOPS];
		void *out[MD4_LOOPS];
		for (j = 0; j < MD4_LOOPS; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoMD4_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, x, tid);
		for (j = 0; j < MD4_LOOPS; ++j)
			total_len2_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoMD4_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &x, tid);
		else
		#endif
		DoMD4_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &x, tid);
		total_len2_X86[i] = x;
#endif
	}
}
void DynamicFunc__MD4_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD4_inc) {
#ifdef MD4_SSE_PARA
		int len[MD4_LOOPS], j;
		unsigned int x[MD4_LOOPS];
		void *out[MD4_LOOPS];
		for (j = 0; j < MD4_LOOPS; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoMD4_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, x, tid);
		for (j = 0; j < MD4_LOOPS; ++j)
			total_len_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoMD4_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &x, tid);
		else
		#endif
		DoMD4_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &x, tid);
		total_len_X86[i] = x;
#endif
	}
}
void DynamicFunc__MD4_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD4_inc) {
#ifdef MD4_SSE_PARA
		int len[MD4_LOOPS], j;
		unsigned int x[MD4_LOOPS];
		void *out[MD4_LOOPS];
		for (j = 0; j < MD4_LOOPS; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoMD4_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, x, tid);
		for (j = 0; j < MD4_LOOPS; ++j)
			total_len2_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoMD4_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &x, tid);
		else
		#endif
		DoMD4_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &x, tid);
		total_len2_X86[i] = x;
#endif
	}
}
void DynamicFunc__MD4_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD4_inc) {
#ifdef MD4_SSE_PARA
	int len[MD4_LOOPS], j;
	for (j = 0; j < MD4_LOOPS; ++j)
		len[j] = total_len_X86[i+j];
	DoMD4_crypt_f_sse(input_buf_X86[i>>MD5_X2].x1.b, len, crypt_key_X86[i>>MD5_X2].x1.b);
#else
	#if (MD5_X2)
		if (i & 1)
			DoMD4_crypt_f(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], crypt_key_X86[i>>MD5_X2].x2.b2);
		else
	#endif
		DoMD4_crypt_f(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], crypt_key_X86[i>>MD5_X2].x1.b);
#endif
	}
}
void DynamicFunc__MD4_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += MD4_inc) {
#ifdef MD4_SSE_PARA
	int len[MD4_LOOPS], j;
	for (j = 0; j < MD4_LOOPS; ++j)
		len[j] = total_len2_X86[i+j];
	DoMD4_crypt_f_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, crypt_key_X86[i>>MD5_X2].x1.b);
#else
	#if (MD5_X2)
		if (i & 1)
			DoMD4_crypt_f(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], crypt_key_X86[i>>MD5_X2].x2.b2);
		else
	#endif
		DoMD4_crypt_f(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], crypt_key_X86[i>>MD5_X2].x1.b);
#endif
	}
}

/********************************************************************
 ****  Here are the SHA1 functions (Now using 'common' interface)
 *******************************************************************/
#ifdef SHA1_SSE_PARA
#define SHA1_LOOPS (MMX_COEF*SHA1_SSE_PARA)
static const int sha1_inc = SHA1_LOOPS;

static inline uint32_t DoSHA1_FixBufferLen32(unsigned char *input_buf, int total_len) {
	uint32_t *p;
	uint32_t ret = (total_len / 64) + 1;
	if (total_len % 64 > 55)
		++ret;
	input_buf[total_len] = 0x80;
	p = (uint32_t *)&(input_buf[total_len+1]);
	while (*p && p < (uint32_t *)&input_buf[(ret<<6)-4])
		*p++ = 0;
	p = (uint32_t *)input_buf;
	p[(ret*16)-1] = JOHNSWAP(total_len<<3);
	return ret;
}
static void DoSHA1_crypt_f_sse(void *in, int len[SHA1_LOOPS], void *out) {
	ALIGN(16) ARCH_WORD_32 a[(20*SHA1_LOOPS)/sizeof(ARCH_WORD_32)];
	unsigned int i, j, loops[SHA1_LOOPS], bMore, cnt;
	unsigned char *cp = (unsigned char*)in;
	for (i = 0; i < SHA1_LOOPS; ++i) {
		loops[i] = DoSHA1_FixBufferLen32(cp, len[i]);
		cp += 256;
	}
	cp = (unsigned char*)in;
	bMore = 1;
	cnt = 1;
	while (bMore) {
		SSESHA1body(cp, a, a, SSEi_FLAT_IN|SSEi_4BUF_INPUT_FIRST_BLK|(cnt==1?0:SSEi_RELOAD));
		bMore = 0;
		for (i = 0; i < SHA1_LOOPS; ++i) {
			if (cnt == loops[i]) {
				unsigned int offx = ((i>>2)*20)+(i&3);
				for (j = 0; j < 4; ++j) {
					((ARCH_WORD_32*)out)[(i<<2)+j] = JOHNSWAP(a[(j<<2)+offx]);
				}
			} else if (cnt < loops[i])
				bMore = 1;
		}
		cp += 64;
		++cnt;
	}
}
static void DoSHA1_crypt_sse(void *in, int ilen[SHA1_LOOPS], void *out[SHA1_LOOPS], unsigned int *tot_len, int tid) {
	ALIGN(16) ARCH_WORD_32 a[(20*SHA1_LOOPS)/sizeof(ARCH_WORD_32)];
	union yy { unsigned char u[20]; ARCH_WORD_32 a[20/sizeof(ARCH_WORD_32)]; } y;
	unsigned int i, j, loops[SHA1_LOOPS], bMore, cnt;
	unsigned char *cp = (unsigned char*)in;
	for (i = 0; i < SHA1_LOOPS; ++i) {
		loops[i] = DoSHA1_FixBufferLen32(cp, ilen[i]);
		cp += 256;
	}
	cp = (unsigned char*)in;
	bMore = 1;
	cnt = 1;
	while (bMore) {
		SSESHA1body(cp, a, a, SSEi_FLAT_IN|SSEi_4BUF_INPUT_FIRST_BLK|(cnt==1?0:SSEi_RELOAD));
		bMore = 0;
		for (i = 0; i < SHA1_LOOPS; ++i) {
			if (cnt == loops[i]) {
				unsigned int offx = ((i>>2)*20)+(i&3);
				for (j = 0; j < 5; ++j) {
					y.a[j] =JOHNSWAP(a[(j<<2)+offx]);
				}
				*(tot_len+i) += large_hash_output(y.u, &(((unsigned char*)out[i])[*(tot_len+i)]), 20, tid);
			} else if (cnt < loops[i])
				bMore = 1;
		}
		cp += 64;
		++cnt;
	}
}
#else

#define SHA1_LOOPS 1
static const int sha1_inc = 1;

static void DoSHA1_crypt_f(void *in, int len, void *out) {
	union xx { unsigned char u[20]; ARCH_WORD_32 a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, in, len);
	SHA1_Final(crypt_out, &ctx);
	memcpy(out, crypt_out, 16);
}
static void DoSHA1_crypt(void *in, int ilen, void *out, unsigned int *tot_len, int tid) {
	union xx { unsigned char u[20]; ARCH_WORD_32 a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, in, ilen);
	SHA1_Final(crypt_out, &ctx);
	*tot_len += large_hash_output(crypt_out, &(((unsigned char*)out)[*tot_len]), 20, tid);
}
#endif

void DynamicFunc__SHA1_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha1_inc) {
#ifdef SHA1_SSE_PARA
		int len[SHA1_LOOPS], j;
		void *out[SHA1_LOOPS];
		for (j = 0; j < SHA1_LOOPS; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
		}
		DoSHA1_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, &(total_len2_X86[i]), tid);
#else
		#if (MD5_X2)
		if (i & 1)
			DoSHA1_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &(total_len2_X86[i]), tid);
		else
		#endif
		DoSHA1_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &(total_len2_X86[i]), tid);
#endif
	}
}
void DynamicFunc__SHA1_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha1_inc) {
#ifdef SHA1_SSE_PARA
		int len[SHA1_LOOPS], j;
		void *out[SHA1_LOOPS];
		for (j = 0; j < SHA1_LOOPS; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
		}
		DoSHA1_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, &(total_len_X86[i]), tid);
#else
		#if (MD5_X2)
		if (i & 1)
			DoSHA1_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &(total_len_X86[i]), tid);
		else
		#endif
		DoSHA1_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &(total_len_X86[i]), tid);
#endif
	}
}
void DynamicFunc__SHA1_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha1_inc) {
#ifdef SHA1_SSE_PARA
		int len[SHA1_LOOPS], j;
		unsigned int x[SHA1_LOOPS];
		void *out[SHA1_LOOPS];
		for (j = 0; j < SHA1_LOOPS; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoSHA1_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, x, tid);
		for (j = 0; j < SHA1_LOOPS; ++j)
			total_len_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoSHA1_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &x, tid);
		else
		#endif
		DoSHA1_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &x, tid);
		total_len_X86[i] = x;
#endif
	}
}
void DynamicFunc__SHA1_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha1_inc) {
#ifdef SHA1_SSE_PARA
		int len[SHA1_LOOPS], j;
		unsigned int x[SHA1_LOOPS];
		void *out[SHA1_LOOPS];
		for (j = 0; j < SHA1_LOOPS; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoSHA1_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, x, tid);
		for (j = 0; j < SHA1_LOOPS; ++j)
			total_len2_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoSHA1_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &x, tid);
		else
		#endif
		DoSHA1_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &x, tid);
		total_len2_X86[i] = x;
#endif
	}
}
void DynamicFunc__SHA1_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha1_inc) {
#ifdef SHA1_SSE_PARA
		int len[SHA1_LOOPS], j;
		unsigned int x[SHA1_LOOPS];
		void *out[SHA1_LOOPS];
		for (j = 0; j < SHA1_LOOPS; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoSHA1_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, x, tid);
		for (j = 0; j < SHA1_LOOPS; ++j)
			total_len_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoSHA1_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &x, tid);
		else
		#endif
		DoSHA1_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &x, tid);
		total_len_X86[i] = x;
#endif
	}
}
void DynamicFunc__SHA1_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha1_inc) {
#ifdef SHA1_SSE_PARA
		int len[SHA1_LOOPS], j;
		unsigned int x[SHA1_LOOPS];
		void *out[SHA1_LOOPS];
		for (j = 0; j < SHA1_LOOPS; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoSHA1_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, x, tid);
		for (j = 0; j < SHA1_LOOPS; ++j)
			total_len2_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoSHA1_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &x, tid);
		else
		#endif
		DoSHA1_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &x, tid);
		total_len2_X86[i] = x;
#endif
	}
}
void DynamicFunc__SHA1_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha1_inc) {
#ifdef SHA1_SSE_PARA
	int len[SHA1_LOOPS], j;
	for (j = 0; j < SHA1_LOOPS; ++j)
		len[j] = total_len_X86[i+j];
	DoSHA1_crypt_f_sse(input_buf_X86[i>>MD5_X2].x1.b, len, crypt_key_X86[i>>MD5_X2].x1.b);
#else
	#if (MD5_X2)
		if (i & 1)
			DoSHA1_crypt_f(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], crypt_key_X86[i>>MD5_X2].x2.b2);
		else
	#endif
		DoSHA1_crypt_f(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], crypt_key_X86[i>>MD5_X2].x1.b);
#endif
	}
}
void DynamicFunc__SHA1_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha1_inc) {
#ifdef SHA1_SSE_PARA
	int len[SHA1_LOOPS], j;
	for (j = 0; j < SHA1_LOOPS; ++j)
		len[j] = total_len2_X86[i+j];
	DoSHA1_crypt_f_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, crypt_key_X86[i>>MD5_X2].x1.b);
#else
	#if (MD5_X2)
		if (i & 1)
			DoSHA1_crypt_f(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], crypt_key_X86[i>>MD5_X2].x2.b2);
		else
	#endif
		DoSHA1_crypt_f(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], crypt_key_X86[i>>MD5_X2].x1.b);
#endif
	}
}

/********************************************************************
 ****  Here are the SHA224 and SHA256 functions!!!
 *******************************************************************/
#ifdef MMX_COEF_SHA256

static const int sha256_inc = MMX_COEF_SHA256;

static inline uint32_t DoSHA256_FixBufferLen32(unsigned char *input_buf, int total_len) {
	uint32_t *p;
	uint32_t ret = (total_len / 64) + 1;
	if (total_len % 64 > 55)
		++ret;
	input_buf[total_len] = 0x80;
	p = (uint32_t *)&(input_buf[total_len+1]);
	while (*p && p < (uint32_t *)&input_buf[(ret<<6)-4])
		*p++ = 0;
	p = (uint32_t *)input_buf;
	p[(ret*16)-1] = JOHNSWAP(total_len<<3);
	return ret;
}
static void DoSHA256_crypt_f_sse(void *in, int len[MMX_COEF_SHA256], void *out, int isSHA256) {
	ALIGN(16) ARCH_WORD_32 a[(32*MMX_COEF_SHA256)/sizeof(ARCH_WORD_32)];
	unsigned int i, j, loops[MMX_COEF_SHA256], bMore, cnt;
	unsigned char *cp = (unsigned char*)in;
	for (i = 0; i < MMX_COEF_SHA256; ++i) {
		loops[i] = DoSHA256_FixBufferLen32(cp, len[i]);
		cp += 256;
	}
	cp = (unsigned char*)in;
	bMore = 1;
	cnt = 1;
	while (bMore) {
		SSESHA256body(cp, a, a, SSEi_FLAT_IN|(isSHA256?0:SSEi_CRYPT_SHA224)|SSEi_4BUF_INPUT_FIRST_BLK|(cnt==1?0:SSEi_RELOAD));
		bMore = 0;
		for (i = 0; i < MMX_COEF_SHA256; ++i) {
			if (cnt == loops[i]) {
				for (j = 0; j < 4; ++j) {
					((ARCH_WORD_32*)out)[(i<<2)+j] = JOHNSWAP(a[(j<<2)+i]);
				}
			} else if (cnt < loops[i])
				bMore = 1;
		}
		cp += 64;
		++cnt;
	}
}
static void DoSHA256_crypt_sse(void *in, int ilen[MMX_COEF_SHA256], void *out[MMX_COEF_SHA256], unsigned int *tot_len, int isSHA256, int tid) {
	ALIGN(16) ARCH_WORD_32 a[(32*MMX_COEF_SHA256)/sizeof(ARCH_WORD_32)];
	union yy { unsigned char u[32]; ARCH_WORD_32 a[32/sizeof(ARCH_WORD_32)]; } y;
	unsigned int i, j, loops[MMX_COEF_SHA256], bMore, cnt;
	unsigned char *cp = (unsigned char*)in;
	for (i = 0; i < MMX_COEF_SHA256; ++i) {
		loops[i] = DoSHA256_FixBufferLen32(cp, ilen[i]);
		cp += 256;
	}
	cp = (unsigned char*)in;
	bMore = 1;
	cnt = 1;
	while (bMore) {
		SSESHA256body(cp, a, a, SSEi_FLAT_IN|(isSHA256?0:SSEi_CRYPT_SHA224)|SSEi_4BUF_INPUT_FIRST_BLK|(cnt==1?0:SSEi_RELOAD));
		bMore = 0;
		for (i = 0; i < MMX_COEF_SHA256; ++i) {
			if (cnt == loops[i]) {
				for (j = 0; j < 8; ++j) {
					y.a[j] =JOHNSWAP(a[(j<<2)+i]);
				}
				*(tot_len+i) += large_hash_output(y.u, &(((unsigned char*)out[i])[*(tot_len+i)]), isSHA256?32:28, tid);
			} else if (cnt < loops[i])
				bMore = 1;
		}
		cp += 64;
		++cnt;
	}
}
#else

static const int sha256_inc = 1;

static void DoSHA256_crypt_f(void *in, int len, void *out, int isSHA256) {
	union xx { unsigned char u[32]; ARCH_WORD_32 a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	SHA256_CTX ctx;
	if (isSHA256)
		SHA256_Init(&ctx);
	else
		SHA224_Init(&ctx);
	SHA256_Update(&ctx, in, len);
	SHA256_Final(crypt_out, &ctx);
	memcpy(out, crypt_out, 16);
}
static void DoSHA256_crypt(void *in, int ilen, void *out, unsigned int *tot_len, int isSHA256, int tid) {
	union xx { unsigned char u[32]; ARCH_WORD_32 a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	SHA256_CTX ctx;
	if (isSHA256)
		SHA256_Init(&ctx);
	else
		SHA224_Init(&ctx);
	SHA256_Update(&ctx, in, ilen);
	SHA256_Final(crypt_out, &ctx);
	*tot_len += large_hash_output(crypt_out, &(((unsigned char*)out)[*tot_len]), isSHA256?32:28, tid);
}
#endif

void DynamicFunc__SHA224_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
		int len[MMX_COEF_SHA256], j;
		void *out[MMX_COEF_SHA256];
		for (j = 0; j < MMX_COEF_SHA256; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
		}
		DoSHA256_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, &(total_len2_X86[i]), 0, tid);
#else
		#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &(total_len2_X86[i]), 0, tid);
		else
		#endif
		DoSHA256_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &(total_len2_X86[i]), 0, tid);
#endif
	}
}
void DynamicFunc__SHA256_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
		int len[MMX_COEF_SHA256], j;
		void *out[MMX_COEF_SHA256];
		for (j = 0; j < MMX_COEF_SHA256; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
		}
		DoSHA256_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, &(total_len2_X86[i]), 1, tid);
#else
		#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &(total_len2_X86[i]), 1, tid);
		else
		#endif
		DoSHA256_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &(total_len2_X86[i]), 1, tid);
#endif
	}
}
void DynamicFunc__SHA224_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
		int len[MMX_COEF_SHA256], j;
		void *out[MMX_COEF_SHA256];
		for (j = 0; j < MMX_COEF_SHA256; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
		}
		DoSHA256_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, &(total_len_X86[i]), 0, tid);
#else
		#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &(total_len_X86[i]), 0, tid);
		else
		#endif
		DoSHA256_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &(total_len_X86[i]), 0, tid);
#endif
	}
}
void DynamicFunc__SHA256_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
		int len[MMX_COEF_SHA256], j;
		void *out[MMX_COEF_SHA256];
		for (j = 0; j < MMX_COEF_SHA256; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
		}
		DoSHA256_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, &(total_len_X86[i]), 1, tid);
#else
		#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &(total_len_X86[i]), 1, tid);
		else
		#endif
		DoSHA256_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &(total_len_X86[i]), 1, tid);
#endif
	}
}
void DynamicFunc__SHA224_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
		int len[MMX_COEF_SHA256], j;
		unsigned int x[MMX_COEF_SHA256];
		void *out[MMX_COEF_SHA256];
		for (j = 0; j < MMX_COEF_SHA256; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoSHA256_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, x, 0, tid);
		for (j = 0; j < MMX_COEF_SHA256; ++j)
			total_len_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &x, 0, tid);
		else
		#endif
		DoSHA256_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &x, 0, tid);
		total_len_X86[i] = x;
#endif
	}
}
void DynamicFunc__SHA256_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
		int len[MMX_COEF_SHA256], j;
		unsigned int x[MMX_COEF_SHA256];
		void *out[MMX_COEF_SHA256];
		for (j = 0; j < MMX_COEF_SHA256; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoSHA256_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, x, 1, tid);
		for (j = 0; j < MMX_COEF_SHA256; ++j)
			total_len_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &x, 1, tid);
		else
		#endif
		DoSHA256_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &x, 1, tid);
		total_len_X86[i] = x;
#endif
	}
}
void DynamicFunc__SHA224_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
		int len[MMX_COEF_SHA256], j;
		unsigned int x[MMX_COEF_SHA256];
		void *out[MMX_COEF_SHA256];
		for (j = 0; j < MMX_COEF_SHA256; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoSHA256_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, x, 0, tid);
		for (j = 0; j < MMX_COEF_SHA256; ++j)
			total_len2_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &x, 0, tid);
		else
		#endif
		DoSHA256_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &x, 0, tid);
		total_len2_X86[i] = x;
#endif
	}
}
void DynamicFunc__SHA256_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til;i += sha256_inc) {
#ifdef MMX_COEF_SHA256
		int len[MMX_COEF_SHA256], j;
		unsigned int x[MMX_COEF_SHA256];
		void *out[MMX_COEF_SHA256];
		for (j = 0; j < MMX_COEF_SHA256; ++j) {
			len[j] = total_len_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoSHA256_crypt_sse(input_buf_X86[i>>MD5_X2].x1.b, len, out, x, 1, tid);
		for (j = 0; j < MMX_COEF_SHA256; ++j)
			total_len2_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &x, 1, tid);
		else
		#endif
		DoSHA256_crypt(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &x, 1, tid);
		total_len2_X86[i] = x;
#endif
	}
}
void DynamicFunc__SHA224_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
		int len[MMX_COEF_SHA256], j;
		unsigned int x[MMX_COEF_SHA256];
		void *out[MMX_COEF_SHA256];
		for (j = 0; j < MMX_COEF_SHA256; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoSHA256_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, x, 0, tid);
		for (j = 0; j < MMX_COEF_SHA256; ++j)
			total_len_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &x, 0, tid);
		else
		#endif
		DoSHA256_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &x, 0, tid);
		total_len_X86[i] = x;
#endif
	}
}
void DynamicFunc__SHA256_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
		int len[MMX_COEF_SHA256], j;
		unsigned int x[MMX_COEF_SHA256];
		void *out[MMX_COEF_SHA256];
		for (j = 0; j < MMX_COEF_SHA256; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoSHA256_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, x, 1, tid);
		for (j = 0; j < MMX_COEF_SHA256; ++j)
			total_len_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x2.b2, &x, 1, tid);
		else
		#endif
		DoSHA256_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf_X86[i>>MD5_X2].x1.b, &x, 1, tid);
		total_len_X86[i] = x;
#endif
	}
}
void DynamicFunc__SHA224_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
		int len[MMX_COEF_SHA256], j;
		unsigned int x[MMX_COEF_SHA256];
		void *out[MMX_COEF_SHA256];
		for (j = 0; j < MMX_COEF_SHA256; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoSHA256_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, x, 0, tid);
		for (j = 0; j < MMX_COEF_SHA256; ++j)
			total_len2_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &x, 0, tid);
		else
		#endif
		DoSHA256_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &x, 0, tid);
		total_len2_X86[i] = x;
#endif
	}
}
void DynamicFunc__SHA256_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
		int len[MMX_COEF_SHA256], j;
		unsigned int x[MMX_COEF_SHA256];
		void *out[MMX_COEF_SHA256];
		for (j = 0; j < MMX_COEF_SHA256; ++j) {
			len[j] = total_len2_X86[i+j];
			#if (MD5_X2)
			if (j&1)
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x2.b2;
			else
			#endif
				out[j] = input_buf2_X86[(i+j)>>MD5_X2].x1.b;
			x[j] = 0;
		}
		DoSHA256_crypt_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, out, x, 1, tid);
		for (j = 0; j < MMX_COEF_SHA256; ++j)
			total_len2_X86[i+j] = x[j];
#else
		unsigned int x = 0;
		#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], input_buf2_X86[i>>MD5_X2].x2.b2, &x, 1, tid);
		else
		#endif
		DoSHA256_crypt(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], input_buf2_X86[i>>MD5_X2].x1.b, &x, 1, tid);
		total_len2_X86[i] = x;
#endif
	}
}
void DynamicFunc__SHA224_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
	int len[MMX_COEF_SHA256], j;
	for (j = 0; j < MMX_COEF_SHA256; ++j)
		len[j] = total_len_X86[i+j];
	DoSHA256_crypt_f_sse(input_buf_X86[i>>MD5_X2].x1.b, len, crypt_key_X86[i>>MD5_X2].x1.b, 0);
#else
	#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt_f(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], crypt_key_X86[i>>MD5_X2].x2.b2, 0);
		else
	#endif
		DoSHA256_crypt_f(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], crypt_key_X86[i>>MD5_X2].x1.b, 0);
#endif
	}
}
void DynamicFunc__SHA256_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
	int len[MMX_COEF_SHA256], j;
	for (j = 0; j < MMX_COEF_SHA256; ++j)
		len[j] = total_len_X86[i+j];
	DoSHA256_crypt_f_sse(input_buf_X86[i>>MD5_X2].x1.b, len, crypt_key_X86[i>>MD5_X2].x1.b, 1);
#else
	#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt_f(input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i], crypt_key_X86[i>>MD5_X2].x2.b2, 1);
		else
	#endif
		DoSHA256_crypt_f(input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i], crypt_key_X86[i>>MD5_X2].x1.b, 1);
#endif
	}
}
void DynamicFunc__SHA224_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til;  i += sha256_inc) {
#ifdef MMX_COEF_SHA256
	int len[MMX_COEF_SHA256], j;
	for (j = 0; j < MMX_COEF_SHA256; ++j)
		len[j] = total_len2_X86[i+j];
	DoSHA256_crypt_f_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, crypt_key_X86[i>>MD5_X2].x1.b, 0);
#else
	#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt_f(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], crypt_key_X86[i>>MD5_X2].x2.b2, 0);
		else
	#endif
		DoSHA256_crypt_f(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], crypt_key_X86[i>>MD5_X2].x1.b, 0);
#endif
	}
}
void DynamicFunc__SHA256_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS){
	int i, til;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; i += sha256_inc) {
#ifdef MMX_COEF_SHA256
	int len[MMX_COEF_SHA256], j;
	for (j = 0; j < MMX_COEF_SHA256; ++j)
		len[j] = total_len2_X86[i+j];
	DoSHA256_crypt_f_sse(input_buf2_X86[i>>MD5_X2].x1.b, len, crypt_key_X86[i>>MD5_X2].x1.b, 1);
#else
	#if (MD5_X2)
		if (i & 1)
			DoSHA256_crypt_f(input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i], crypt_key_X86[i>>MD5_X2].x2.b2, 1);
		else
	#endif
		DoSHA256_crypt_f(input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i], crypt_key_X86[i>>MD5_X2].x1.b, 1);
#endif
	}
}

/********************************************************************
 ****  Here are the SHA384 and SHA512 functions!!!
 *******************************************************************/
void DynamicFunc__SHA384_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
		}
		SHA384_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 48, tid);
	}
}
void DynamicFunc__SHA512_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
		}
		SHA512_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 64, tid);
	}
}
void DynamicFunc__SHA384_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x2.B2[total_len_X86[i]]);
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x1.B[total_len_X86[i]]);
		}
		SHA384_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 48, tid);
	}
}
void DynamicFunc__SHA512_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x2.B2[total_len_X86[i]]);
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x1.B[total_len_X86[i]]);
		}
		SHA512_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 64, tid);
	}
}
void DynamicFunc__SHA384_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		SHA384_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 48, tid);
	}
}
void DynamicFunc__SHA512_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		SHA512_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 64, tid);
	}
}
void DynamicFunc__SHA384_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		SHA384_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 48, tid);
	}
}
void DynamicFunc__SHA512_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		SHA512_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 64, tid);
	}
}
void DynamicFunc__SHA384_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		SHA384_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 48, tid);
	}
}
void DynamicFunc__SHA512_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		SHA512_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 64, tid);
	}
}
void DynamicFunc__SHA384_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS){
	union xx { unsigned char u[56]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		SHA384_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 48, tid);
	}
}
void DynamicFunc__SHA512_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		SHA512_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 64, tid);
	}
}
void DynamicFunc__SHA384_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
		else
#endif
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
		SHA384_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 28 bytes.  Thus we do not have
		// the entire SHA384. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA384 hash (vs the whole 384 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 28).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}
void DynamicFunc__SHA512_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
		else
#endif
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
		SHA512_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire SHA512. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA512 hash (vs the whole 512 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 32).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}
void DynamicFunc__SHA384_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
		else
#endif
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
		SHA384_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 28 bytes.  Thus we do not have
		// the entire SHA384. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA384 hash (vs the whole 384 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 28).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}
void DynamicFunc__SHA512_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	SHA512_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
		else
#endif
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
		SHA512_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire SHA512. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA512 hash (vs the whole 512 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 32).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}

/**************************************************************
 ** GOST functions for dynamic
 *************************************************************/

void DynamicFunc__GOST_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	gost_ctx ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
		}
		john_gost_final(&ctx, crypt_out);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__GOST_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	gost_ctx ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x2.B2[total_len_X86[i]]);
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x1.B[total_len_X86[i]]);
		}
		john_gost_final(&ctx, crypt_out);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__GOST_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	gost_ctx ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		john_gost_final(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__GOST_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	gost_ctx ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		john_gost_final(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__GOST_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	gost_ctx ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		john_gost_final(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__GOST_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	gost_ctx ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		john_gost_final(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__GOST_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	gost_ctx ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
		else
#endif
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
		john_gost_final(&ctx, crypt_out);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire GOST. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of GOST hash (vs the whole 256 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 32).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}
void DynamicFunc__GOST_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	gost_ctx ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
		else
#endif
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
		john_gost_final(&ctx, crypt_out);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire GOST. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of GOST hash (vs the whole 256 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 32).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}


/**************************************************************
 ** WHIRLPOOL functions for dynamic
 *************************************************************/
void DynamicFunc__WHIRLPOOL_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	WHIRLPOOL_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 64, tid);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	WHIRLPOOL_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x2.B2[total_len_X86[i]]);
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x1.B[total_len_X86[i]]);
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 64, tid);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	WHIRLPOOL_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 64, tid);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	WHIRLPOOL_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 64, tid);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	WHIRLPOOL_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 64, tid);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	WHIRLPOOL_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 64, tid);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	WHIRLPOOL_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
		else
#endif
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
		WHIRLPOOL_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 64 bytes.  Thus we do not have
		// the entire WHIRLPOOL. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of WHIRLPOOL hash (vs the whole 512 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 64).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	WHIRLPOOL_CTX ctx;

#ifdef _OPENMP
	til = last;
	i = first;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
		else
#endif
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
		WHIRLPOOL_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 64 bytes.  Thus we do not have
		// the entire WHIRLPOOL. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of WHIRLPOOL hash (vs the whole 512 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 64).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}



/**************************************************************
 ** Tiger functions for dynamic
 *************************************************************/
void DynamicFunc__Tiger_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[24]; ARCH_WORD a[24/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_tiger_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_tiger_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_tiger(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			sph_tiger(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
		}
		sph_tiger_close(&ctx, crypt_out);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 24, tid);
	}
}
void DynamicFunc__Tiger_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[24]; ARCH_WORD a[24/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_tiger_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_tiger_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_tiger(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x2.B2[total_len_X86[i]]);
		}
		else
#endif
		{
			sph_tiger(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x1.B[total_len_X86[i]]);
		}
		sph_tiger_close(&ctx, crypt_out);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 24, tid);
	}
}
void DynamicFunc__Tiger_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[24]; ARCH_WORD a[24/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_tiger_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_tiger_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_tiger(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_tiger(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		sph_tiger_close(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 24, tid);
	}
}
void DynamicFunc__Tiger_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[24]; ARCH_WORD a[24/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_tiger_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_tiger_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_tiger(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_tiger(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		sph_tiger_close(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 24, tid);
	}
}
void DynamicFunc__Tiger_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[24]; ARCH_WORD a[24/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_tiger_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_tiger_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_tiger(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_tiger(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		sph_tiger_close(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 24, tid);
	}
}
void DynamicFunc__Tiger_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[24]; ARCH_WORD a[24/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_tiger_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_tiger_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_tiger(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_tiger(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		sph_tiger_close(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 24, tid);
	}
}
void DynamicFunc__Tiger_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[24]; ARCH_WORD a[24/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	sph_tiger_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_tiger_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			sph_tiger(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
		else
#endif
			sph_tiger(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
		sph_tiger_close(&ctx, crypt_out);

		// Only copies the first 16 out of 24 bytes.  Thus we do not have
		// the entire Tiger. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of Tiger hash (vs the whole 192 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 24).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}
void DynamicFunc__Tiger_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[24]; ARCH_WORD a[24/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	sph_tiger_context ctx;

#ifdef _OPENMP
	til = last;
	i = first;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_tiger_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			sph_tiger(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
		else
#endif
			sph_tiger(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
		sph_tiger_close(&ctx, crypt_out);

		// Only copies the first 16 out of 24 bytes.  Thus we do not have
		// the entire Tiger. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of Tiger hash (vs the whole 192 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 24).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}


/**************************************************************
 ** RIPEMD128 functions for dynamic
 *************************************************************/
void DynamicFunc__RIPEMD128_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[16]; ARCH_WORD a[16/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd128_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd128_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd128(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			sph_ripemd128(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
		}
		sph_ripemd128_close(&ctx, crypt_out);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 16, tid);
	}
}
void DynamicFunc__RIPEMD128_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[16]; ARCH_WORD a[16/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd128_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd128_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd128(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x2.B2[total_len_X86[i]]);
		}
		else
#endif
		{
			sph_ripemd128(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x1.B[total_len_X86[i]]);
		}
		sph_ripemd128_close(&ctx, crypt_out);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 16, tid);
	}
}
void DynamicFunc__RIPEMD128_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[16]; ARCH_WORD a[16/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd128_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd128_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd128(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd128(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd128_close(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 16, tid);
	}
}
void DynamicFunc__RIPEMD128_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[16]; ARCH_WORD a[16/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd128_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd128_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd128(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd128(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd128_close(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 16, tid);
	}
}
void DynamicFunc__RIPEMD128_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[16]; ARCH_WORD a[16/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd128_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd128_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd128(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd128(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd128_close(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 16, tid);
	}
}
void DynamicFunc__RIPEMD128_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[16]; ARCH_WORD a[16/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd128_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd128_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd128(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd128(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd128_close(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 16, tid);
	}
}
// since this hash is only 128 bits also, the output 'fits' properly into
// the crypt_key array, without using an intermediate buffer.
void DynamicFunc__RIPEMD128_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS) {
//	union xx { unsigned char u[16]; ARCH_WORD a[16/sizeof(ARCH_WORD)]; } u;
//	unsigned char *crypt_out=u.u;
	int i, til;
	sph_ripemd128_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd128_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			sph_ripemd128(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
		else
#endif
			sph_ripemd128(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
//		sph_ripemd128_close(&ctx, crypt_out);

#if (MD5_X2)
		if (i & 1)
//			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
			sph_ripemd128_close(&ctx, crypt_key_X86[i>>MD5_X2].x2.B2);
		else
#endif
//			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
			sph_ripemd128_close(&ctx, crypt_key_X86[i>>MD5_X2].x1.B);
	}
}
// since this hash is only 128 bits also, the output 'fits' properly into
// the crypt_key array, without using an intermediate buffer.
void DynamicFunc__RIPEMD128_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS) {
//	union xx { unsigned char u[16]; ARCH_WORD a[16/sizeof(ARCH_WORD)]; } u;
//	unsigned char *crypt_out=u.u;
	int i, til;
	sph_ripemd128_context ctx;

#ifdef _OPENMP
	til = last;
	i = first;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd128_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			sph_ripemd128(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
		else
#endif
			sph_ripemd128(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
//		sph_ripemd128_close(&ctx, crypt_out);

#if (MD5_X2)
		if (i & 1)
//			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		sph_ripemd128_close(&ctx, crypt_key_X86[i>>MD5_X2].x2.B2);
		else
#endif
			//memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
			sph_ripemd128_close(&ctx, crypt_key_X86[i>>MD5_X2].x1.B);
	}
}


/**************************************************************
 ** RIPEMD160 functions for dynamic
 *************************************************************/
void DynamicFunc__RIPEMD160_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd160_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd160_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd160(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			sph_ripemd160(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
		}
		sph_ripemd160_close(&ctx, crypt_out);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 20, tid);
	}
}
void DynamicFunc__RIPEMD160_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd160_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd160_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd160(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x2.B2[total_len_X86[i]]);
		}
		else
#endif
		{
			sph_ripemd160(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x1.B[total_len_X86[i]]);
		}
		sph_ripemd160_close(&ctx, crypt_out);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 20, tid);
	}
}
void DynamicFunc__RIPEMD160_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd160_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd160_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd160(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd160(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd160_close(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 20, tid);
	}
}
void DynamicFunc__RIPEMD160_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd160_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd160_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd160(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd160(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd160_close(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 20, tid);
	}
}
void DynamicFunc__RIPEMD160_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd160_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd160_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd160(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd160(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd160_close(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 20, tid);
	}
}
void DynamicFunc__RIPEMD160_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd160_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd160_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd160(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd160(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd160_close(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 20, tid);
	}
}
void DynamicFunc__RIPEMD160_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	sph_ripemd160_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd160_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			sph_ripemd160(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
		else
#endif
			sph_ripemd160(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
		sph_ripemd160_close(&ctx, crypt_out);

		// Only copies the first 16 out of 20 bytes.  Thus we do not have
		// the entire RIPEMD160. It would NOT be valid to continue from here. However
		// it is valid (and 160 bit safe), to simply check the first 160 bits
		// of RIPEMD160 hash (vs the whole 192 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 20).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}
void DynamicFunc__RIPEMD160_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	sph_ripemd160_context ctx;

#ifdef _OPENMP
	til = last;
	i = first;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd160_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			sph_ripemd160(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
		else
#endif
			sph_ripemd160(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
		sph_ripemd160_close(&ctx, crypt_out);

		// Only copies the first 16 out of 20 bytes.  Thus we do not have
		// the entire RIPEMD160. It would NOT be valid to continue from here. However
		// it is valid (and 160 bit safe), to simply check the first 160 bits
		// of RIPEMD160 hash (vs the whole 192 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 20).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}

/**************************************************************
 ** RIPEMD256 functions for dynamic
 *************************************************************/
void DynamicFunc__RIPEMD256_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd256_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd256_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd256(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			sph_ripemd256(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
		}
		sph_ripemd256_close(&ctx, crypt_out);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__RIPEMD256_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd256_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd256_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd256(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x2.B2[total_len_X86[i]]);
		}
		else
#endif
		{
			sph_ripemd256(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x1.B[total_len_X86[i]]);
		}
		sph_ripemd256_close(&ctx, crypt_out);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__RIPEMD256_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd256_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd256_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd256(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd256(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd256_close(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__RIPEMD256_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd256_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd256_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd256(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd256(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd256_close(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__RIPEMD256_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd256_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd256_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd256(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd256(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd256_close(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__RIPEMD256_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd256_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd256_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd256(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd256(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd256_close(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__RIPEMD256_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	sph_ripemd256_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd256_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			sph_ripemd256(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
		else
#endif
			sph_ripemd256(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
		sph_ripemd256_close(&ctx, crypt_out);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire RIPEMD256. It would NOT be valid to continue from here. However
		// it is valid (and 256 bit safe), to simply check the first 256 bits
		// of RIPEMD256 hash (vs the whole 192 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 32).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}
void DynamicFunc__RIPEMD256_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	sph_ripemd256_context ctx;

#ifdef _OPENMP
	til = last;
	i = first;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd256_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			sph_ripemd256(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
		else
#endif
			sph_ripemd256(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
		sph_ripemd256_close(&ctx, crypt_out);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire RIPEMD256. It would NOT be valid to continue from here. However
		// it is valid (and 256 bit safe), to simply check the first 256 bits
		// of RIPEMD256 hash (vs the whole 192 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 32).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}

/**************************************************************
 ** RIPEMD320 functions for dynamic
 *************************************************************/
void DynamicFunc__RIPEMD320_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[40]; ARCH_WORD a[40/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd320_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd320_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd320(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			sph_ripemd320(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
		}
		sph_ripemd320_close(&ctx, crypt_out);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 40, tid);
	}
}
void DynamicFunc__RIPEMD320_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[40]; ARCH_WORD a[40/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd320_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd320_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd320(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x2.B2[total_len_X86[i]]);
		}
		else
#endif
		{
			sph_ripemd320(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = &(input_buf_X86[i>>MD5_X2].x1.B[total_len_X86[i]]);
		}
		sph_ripemd320_close(&ctx, crypt_out);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 40, tid);
	}
}
void DynamicFunc__RIPEMD320_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[40]; ARCH_WORD a[40/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd320_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd320_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd320(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd320(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd320_close(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 40, tid);
	}
}
void DynamicFunc__RIPEMD320_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[40]; ARCH_WORD a[40/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd320_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd320_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd320(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd320(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd320_close(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 40, tid);
	}
}
void DynamicFunc__RIPEMD320_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[40]; ARCH_WORD a[40/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd320_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd320_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd320(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd320(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = input_buf2_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd320_close(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output(crypt_out, cpo, 40, tid);
	}
}
void DynamicFunc__RIPEMD320_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[40]; ARCH_WORD a[40/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	sph_ripemd320_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd320_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			sph_ripemd320(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x2.B2;
		}
		else
#endif
		{
			sph_ripemd320(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = input_buf_X86[i>>MD5_X2].x1.B;
		}
		sph_ripemd320_close(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output(crypt_out, cpo, 40, tid);
	}
}
void DynamicFunc__RIPEMD320_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[40]; ARCH_WORD a[40/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	sph_ripemd320_context ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd320_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			sph_ripemd320(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
		else
#endif
			sph_ripemd320(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
		sph_ripemd320_close(&ctx, crypt_out);

		// Only copies the first 16 out of 40 bytes.  Thus we do not have
		// the entire RIPEMD320. It would NOT be valid to continue from here. However
		// it is valid (and 320 bit safe), to simply check the first 320 bits
		// of RIPEMD320 hash (vs the whole 192 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 40).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}
void DynamicFunc__RIPEMD320_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[40]; ARCH_WORD a[40/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	sph_ripemd320_context ctx;

#ifdef _OPENMP
	til = last;
	i = first;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		sph_ripemd320_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			sph_ripemd320(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
		else
#endif
			sph_ripemd320(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
		sph_ripemd320_close(&ctx, crypt_out);

		// Only copies the first 16 out of 40 bytes.  Thus we do not have
		// the entire RIPEMD320. It would NOT be valid to continue from here. However
		// it is valid (and 320 bit safe), to simply check the first 320 bits
		// of RIPEMD320 hash (vs the whole 192 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 40).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}

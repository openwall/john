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
#if defined (MMX_COEF) && MMX_COEF==2 && defined (_OPENMP)
// NO thread support for MMX.  Only OpenSSL (CTX model), or SSE intrinsics have
// thread support.  The older md5_mmx.S/sha1_mmx.S files are NOT thread safe.
#undef _OPENMP
#define WAS_MMX_OPENMP
#endif
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "dynamic.h"
#include "sha2.h"
#include "gost.h"
// this one is going to be harder.  only haval_256_5 is implemented in CPAN perl, making genation of test cases harder.
// Also, there are 15 different hashes in this 'family'.
#include "sph_haval.h"

#include "sph_ripemd.h"
#include "sph_tiger.h"
#include "sph_whirlpool.h"

#include "johnswap.h"

#if OPENSSL_VERSION_NUMBER >= 0x10000000
#define USING_OSSL_WHRLP
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
// NOTE, cpo must be at least in_byte_cnt*2+1 bytes of buffer
static inline unsigned char *hex_out_buf(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	int j;
	for (j = 0; j < in_byte_cnt; ++j) {
		*cpo++ = dynamic_itoa16[*cpi>>4];
		*cpo++ = dynamic_itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return cpo; // returns pointer TO the null byte, not past it.
}
// NOTE, cpo must be at least in_byte_cnt*2 bytes of buffer
static inline unsigned char *hex_out_buf_no_null(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	int j;
	for (j = 0; j < in_byte_cnt; ++j) {
		*cpo++ = dynamic_itoa16[*cpi>>4];
		*cpo++ = dynamic_itoa16[*cpi&0xF];
		++cpi;
	}
	return cpo;
}
// NOTE, cpo must be at least in_byte_cnt*2 bytes of buffer
static inline unsigned char *hexu_out_buf_no_null(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	int j;
	for (j = 0; j < in_byte_cnt; ++j) {
		//*cpo++ = dynamic_itoa16[*cpi>>4];
		//*cpo++ = dynamic_itoa16[*cpi&0xF];
		*cpo++ = itoa16u[*cpi>>4];
		*cpo++ = itoa16u[*cpi&0xF];
		++cpi;
	}
	return cpo;
}
// NOTE, cpo must be at least in_byte_cnt*2+1 bytes of buffer
static inline unsigned char *hexu_out_buf(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	cpo = hexu_out_buf_no_null(cpi, cpo, in_byte_cnt);
	*cpo = 0;
	return cpo; // returns pointer TO the null byte, not past it.
}

// NOTE, cpo must be at least in_byte_cnt bytes of buffer
static inline unsigned char *raw_out_buf(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	int j;
	for (j = 0; j < in_byte_cnt; ++j) {
		*cpo++ = *cpi++;
	}
	return cpo;
}

// compatible 'standard' MIME base-64 encoding.
static inline unsigned char *base64_out_buf_no_null(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt, int add_eq) {
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

// NOTE, cpo must be at least in_byte_cnt*2+1 bytes of buffer
static inline unsigned char *base64_out_buf(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt, int add_eq) {
	cpo = base64_out_buf_no_null(cpi, cpo, in_byte_cnt, add_eq);
	*cpo = 0;
	return cpo; // returns pointer TO the null byte, not past it.
}
#if 0
void TEST_MIME_crap() {
	SHA_CTX ctx1;
	MD5_CTX ctx;
	SHA256_CTX ctx256;
	SHA512_CTX ctx512;
	unsigned char Data[64], Res[128];
	char *pw="password";

	printf ("pw = %s\n", pw);

	SHA384_Init(&ctx512); 	SHA384_Update(&ctx512, pw, strlen(pw)); 	SHA384_Final(Data, &ctx512);
	hex_out_buf(Data, Res, 48);
	printf ("\nSHA384 data:\nb16=%s\n", Res);
	base64_out_buf(Data, Res, 48);
	printf ("b64=%s\n", Res);

	SHA224_Init(&ctx256); 	SHA224_Update(&ctx256, pw, strlen(pw)); 	SHA224_Final(Data, &ctx256);
	hex_out_buf(Data, Res, 28);
	printf ("\nSHA224 data:\nb16=%s\n", Res);
	base64_out_buf(Data, Res, 28);
	printf ("b64=%s\n", Res);

	SHA1_Init(&ctx1); 	SHA1_Update(&ctx1, pw, strlen(pw)); 	SHA1_Final(Data, &ctx1);
	hex_out_buf(Data, Res, 20);
	printf ("\nSHA1 data:\nb16=%s\n", Res);
	base64_out_buf(Data, Res, 20);
	printf ("b64=%s\n", Res);

	MD5_Init(&ctx); 	MD5_Update(&ctx, pw, strlen(pw)); 	MD5_Final(Data, &ctx);
	hex_out_buf(Data, Res, 16);
	printf ("\nMD5 data:\nb16=%s\n", Res);
	base64_out_buf(Data, Res, 16);
	printf ("b64=%s\n", Res);

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
int large_hash_output_no_null(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt, int tid) {
	unsigned char *cpo2=cpo;
	switch(eLargeOut_get(tid)) {
		case eBase16:
			cpo2 = hex_out_buf_no_null(cpi, cpo, in_byte_cnt);
			break;
		case eBase16u:
			cpo2 = hexu_out_buf_no_null(cpi, cpo, in_byte_cnt);
			break;
		case eBase64:
			cpo2 = base64_out_buf_no_null(cpi, cpo, in_byte_cnt, 1);
			break;
		case eBase64_nte:
			cpo2 = base64_out_buf_no_null(cpi, cpo, in_byte_cnt, 0);
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
 ****  Here are the SHA224 and SHA256 functions!!!
 *******************************************************************/
void DynamicFunc__SHA224_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.b2[total_len2_X86[i]]);
		}
		else
#endif
		{
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.b[total_len2_X86[i]]);
		}
		SHA224_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 28, tid);
	}
}
void DynamicFunc__SHA256_crypt_input1_append_input2(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.b2[total_len2_X86[i]]);
		}
		else
#endif
		{
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.b[total_len2_X86[i]]);
		}
		SHA256_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__SHA224_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
		}
		SHA224_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 28, tid);
	}
}
void DynamicFunc__SHA256_crypt_input2_append_input1(DYNA_OMP_PARAMS) {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
		}
		SHA256_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__SHA224_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA224_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 28, tid);
	}
}
void DynamicFunc__SHA256_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA256_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__SHA224_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA224_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 28, tid);
	}
}
void DynamicFunc__SHA256_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA256_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__SHA224_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA224_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 28, tid);
	}
}
void DynamicFunc__SHA256_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA256_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__SHA224_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA224_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 28, tid);
	}
}
void DynamicFunc__SHA256_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	int tid=0;
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA256_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 32, tid);
	}
}
void DynamicFunc__SHA224_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
		else
#endif
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
		SHA224_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 28 bytes.  Thus we do not have
		// the entire SHA224. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA224 hash (vs the whole 224 bits), with cmp_all/cmp_one, and if it
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
void DynamicFunc__SHA256_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
		else
#endif
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
		SHA256_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire SHA256. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA256 hash (vs the whole 256 bits), with cmp_all/cmp_one, and if it
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
void DynamicFunc__SHA224_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
		else
#endif
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
		SHA224_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 28 bytes.  Thus we do not have
		// the entire SHA224. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA224 hash (vs the whole 224 bits), with cmp_all/cmp_one, and if it
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
void DynamicFunc__SHA256_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i, til;
	SHA256_CTX ctx;

#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
	for (; i < til; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
		else
#endif
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
		SHA256_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire SHA256. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA256 hash (vs the whole 256 bits), with cmp_all/cmp_one, and if it
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
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.b2[total_len2_X86[i]]);
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.b[total_len2_X86[i]]);
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
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.b2[total_len2_X86[i]]);
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.b[total_len2_X86[i]]);
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
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
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
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
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
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA384_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 48, tid);
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
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA512_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 64, tid);
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
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA384_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 48, tid);
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
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA512_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 64, tid);
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
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA384_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 48, tid);
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
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA512_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 64, tid);
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
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA384_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 48, tid);
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
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA512_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 64, tid);
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
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
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
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
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
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		john_gost_final(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 32, tid);
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
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		john_gost_final(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 32, tid);
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
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		john_gost_final(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 32, tid);
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
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		john_gost_final(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 32, tid);
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
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
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
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
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
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 64, tid);
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
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 64, tid);
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
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 64, tid);
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
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 64, tid);
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
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			sph_tiger(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
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
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			sph_tiger(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
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
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			sph_tiger(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		sph_tiger_close(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 24, tid);
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
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			sph_tiger(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		sph_tiger_close(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 24, tid);
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
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			sph_tiger(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		sph_tiger_close(&ctx, crypt_out);
		total_len2_X86[i] = large_hash_output_no_null(crypt_out, cpo, 24, tid);
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
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			sph_tiger(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		sph_tiger_close(&ctx, crypt_out);
		total_len_X86[i] = large_hash_output_no_null(crypt_out, cpo, 24, tid);
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
